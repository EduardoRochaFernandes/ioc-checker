"""
tests/test_ioc_checker.py
--------------------------
Unit tests for ioc_checker.py.

Covers IOC classification, defanging, MITRE inference, verdict logic,
caching, and report rendering — without making any real API calls.

Run:
    pip install pytest
    pytest tests/ -v
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Make sure the parent directory is on the path when running from /tests
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import ioc_checker as ic


# =============================================================================
# IOC classification
# =============================================================================

class TestDetectIocType:
    def test_ipv4(self):
        assert ic.detect_ioc_type("185.220.101.45") == "ip"

    def test_ipv6(self):
        assert ic.detect_ioc_type("2001:db8::1") == "ip"

    def test_domain(self):
        assert ic.detect_ioc_type("malicious-domain.com") == "domain"

    def test_subdomain(self):
        assert ic.detect_ioc_type("cdn.evil.io") == "domain"

    def test_url_http(self):
        assert ic.detect_ioc_type("http://phishing.example/login") == "url"

    def test_url_https(self):
        assert ic.detect_ioc_type("https://phishing.example/login") == "url"

    def test_md5(self):
        assert ic.detect_ioc_type("44d88612fea8a8f36de82e1278abb02f") == "hash_md5"

    def test_sha1(self):
        assert ic.detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash_sha1"

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert ic.detect_ioc_type(h) == "hash_sha256"

    def test_garbage_returns_unknown(self):
        assert ic.detect_ioc_type("not-an-ioc!!!") == "unknown"

    def test_strips_whitespace(self):
        assert ic.detect_ioc_type("  8.8.8.8  ") == "ip"


# =============================================================================
# Defanging
# =============================================================================

class TestDefang:
    def test_ip(self):
        assert ic.defang("1.2.3.4") == "1[.]2[.]3[.]4"

    def test_url(self):
        result = ic.defang("http://evil.com/payload")
        assert result == "hxxp://evil[.]com/payload"

    def test_domain(self):
        assert ic.defang("malicious.example.com") == "malicious[.]example[.]com"

    def test_already_defanged_is_idempotent(self):
        # Running defang twice should not double-replace
        defanged = ic.defang("http://evil.com")
        assert ic.defang(defanged) == defanged


# =============================================================================
# MITRE inference
# =============================================================================

class TestInferMitre:
    def test_ransomware_detected(self):
        detections = ["CrowdStrike: Win/Ransomware.BadStuff", "Kaspersky: Trojan.Generic"]
        result = ic.infer_mitre(detections)
        assert result is not None
        assert "T1486" in result["technique"]

    def test_trojan_fallback(self):
        detections = ["ESET: Trojan.Agent"]
        result = ic.infer_mitre(detections)
        assert result is not None
        assert "T1059" in result["technique"]

    def test_no_match_returns_none(self):
        detections = ["Vendor: SomeRandomDetectionName"]
        assert ic.infer_mitre(detections) is None

    def test_empty_list_returns_none(self):
        assert ic.infer_mitre([]) is None

    def test_case_insensitive(self):
        detections = ["Vendor: RANSOMWARE.Locky"]
        result = ic.infer_mitre(detections)
        assert result is not None


# =============================================================================
# Verdict logic
# =============================================================================

class TestCalculateVerdict:

    def _vt(self, malicious=0, suspicious=0, total=90):
        return {"malicious": malicious, "suspicious": suspicious,
                "harmless": total - malicious - suspicious, "total": total}

    def _abuse(self, score=0, is_tor=False):
        return {"abuse_confidence_score": score, "is_tor": is_tor,
                "total_reports": 0, "isp": "Test ISP", "usage_type": "N/A",
                "last_reported": "N/A", "country_code": "XX"}

    # True Positive cases
    def test_tp_on_high_vt_detections(self):
        verdict, _ = ic.calculate_verdict(self._vt(malicious=10))
        assert verdict == ic.VERDICT_TP

    def test_tp_on_high_abuse_score(self):
        verdict, _ = ic.calculate_verdict(self._vt(), self._abuse(score=80))
        assert verdict == ic.VERDICT_TP

    def test_tp_on_tor_node(self):
        verdict, _ = ic.calculate_verdict(self._vt(), self._abuse(is_tor=True))
        assert verdict == ic.VERDICT_TP

    # Suspicious cases
    def test_suspicious_on_one_vt_detection(self):
        verdict, _ = ic.calculate_verdict(self._vt(malicious=1))
        assert verdict == ic.VERDICT_SUSPICIOUS

    def test_suspicious_on_moderate_abuse_score(self):
        verdict, _ = ic.calculate_verdict(self._vt(), self._abuse(score=50))
        assert verdict == ic.VERDICT_SUSPICIOUS

    def test_suspicious_on_many_suspicious_vendors(self):
        verdict, _ = ic.calculate_verdict(self._vt(suspicious=5))
        assert verdict == ic.VERDICT_SUSPICIOUS

    # Benign cases
    def test_benign_on_clean_ioc(self):
        verdict, _ = ic.calculate_verdict(self._vt(), self._abuse(score=0))
        assert verdict == ic.VERDICT_BENIGN

    def test_benign_without_abuse_data(self):
        verdict, _ = ic.calculate_verdict(self._vt())
        assert verdict == ic.VERDICT_BENIGN

    # Error cases
    def test_unknown_on_vt_error(self):
        verdict, reason = ic.calculate_verdict({"error": "VT_API_KEY not configured"})
        assert verdict == ic.VERDICT_UNKNOWN
        assert "VT_API_KEY" in reason

    def test_abuse_error_does_not_block_verdict(self):
        # An AbuseIPDB error should not override a valid VT result
        verdict, _ = ic.calculate_verdict(self._vt(malicious=10), {"error": "timeout"})
        assert verdict == ic.VERDICT_TP


# =============================================================================
# Cache
# =============================================================================

class TestCache:
    def test_cache_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ic, "CACHE_FILE", tmp_path / "test_cache.json")
        data = {"vt": {"malicious": 5}, "abuse": None}
        ic.cache_set("1.2.3.4", data)
        result = ic.cache_get("1.2.3.4")
        assert result == data

    def test_expired_cache_returns_none(self, tmp_path, monkeypatch):
        from datetime import timedelta
        monkeypatch.setattr(ic, "CACHE_FILE", tmp_path / "test_cache.json")
        monkeypatch.setattr(ic, "CACHE_TTL_HOURS", 0)  # expire immediately

        ic.cache_set("1.2.3.4", {"vt": {}, "abuse": None})
        # TTL is 0 hours — any cached entry is already expired
        result = ic.cache_get("1.2.3.4")
        assert result is None

    def test_missing_key_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ic, "CACHE_FILE", tmp_path / "test_cache.json")
        assert ic.cache_get("not-in-cache") is None

    def test_corrupt_cache_returns_empty(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "test_cache.json"
        cache_path.write_text("{ this is not json }", encoding="utf-8")
        monkeypatch.setattr(ic, "CACHE_FILE", cache_path)
        result = ic._load_cache()
        assert result == {}


# =============================================================================
# API mocking — integration-style tests without real HTTP calls
# =============================================================================

class TestVtCheckIp:
    def _mock_vt_response(self):
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3, "suspicious": 1,
                        "harmless": 80, "undetected": 6,
                    },
                    "country": "DE",
                    "asn": 12345,
                    "as_owner": "Some ISP",
                    "reputation": -10,
                    "categories": {},
                    "tags": ["proxy"],
                }
            }
        }

    @patch("ioc_checker._vt_get")
    def test_returns_normalised_dict(self, mock_get):
        mock_get.return_value = self._mock_vt_response()
        result = ic.vt_check_ip("1.2.3.4")
        assert result["malicious"] == 3
        assert result["country"] == "DE"
        assert result["total"] == 90

    @patch("ioc_checker._vt_get")
    def test_propagates_error(self, mock_get):
        mock_get.return_value = {"error": "not found"}
        result = ic.vt_check_ip("1.2.3.4")
        assert "error" in result


class TestAbuseipdbCheck:
    def _mock_response(self):
        return {
            "data": {
                "abuseConfidenceScore": 95,
                "totalReports": 200,
                "countryCode": "RU",
                "isp": "Evil Corp",
                "domain": "evil.ru",
                "isTor": True,
                "isPublic": True,
                "usageType": "Data Center/Web Hosting/Transit",
                "lastReportedAt": "2025-03-01T12:00:00+00:00",
            }
        }

    @patch("ioc_checker.requests.get")
    def test_returns_normalised_dict(self, mock_get):
        mock_response         = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = self._mock_response()
        mock_get.return_value = mock_response

        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test-key"}):
            ic.ABUSEIPDB_API_KEY = "test-key"
            result = ic.abuseipdb_check("1.2.3.4")

        assert result["abuse_confidence_score"] == 95
        assert result["is_tor"] is True

    def test_missing_key_returns_error(self):
        original = ic.ABUSEIPDB_API_KEY
        ic.ABUSEIPDB_API_KEY = ""
        result = ic.abuseipdb_check("1.2.3.4")
        ic.ABUSEIPDB_API_KEY = original
        assert "error" in result


# =============================================================================
# ASCII bar helper
# =============================================================================

class TestBar:
    def test_zero_score(self):
        assert ic._bar(0)  == "░" * 10

    def test_full_score(self):
        assert ic._bar(100) == "█" * 10

    def test_half_score(self):
        result = ic._bar(50)
        assert "█" in result and "░" in result
        assert len(result) == 10
