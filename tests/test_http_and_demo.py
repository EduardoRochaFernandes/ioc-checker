"""
Tests for the HTTP layer (mocked `requests.get`, never real network),
the VirusTotal rate limiter, hash parsing, verdict boundaries, and the
offline --demo mode.
"""

import json
from unittest.mock import MagicMock

import pytest
import requests

import ioc_checker as ic
import ioc_checker_demo as demo


def _resp(status=200, payload=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload or {}
    if status >= 400 and status != 404:
        r.raise_for_status.side_effect = requests.exceptions.HTTPError(response=r)
    return r


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Keep every test away from the real cache, real keys and real sleeps."""
    monkeypatch.setattr(ic, "CACHE_FILE", tmp_path / "cache.json")
    monkeypatch.setattr(ic, "DEMO_MODE", False)
    monkeypatch.setattr(ic, "VT_API_KEY", "test-vt-key")
    monkeypatch.setattr(ic, "ABUSEIPDB_API_KEY", "test-abuse-key")
    monkeypatch.setattr(ic, "_last_vt_call", 0.0)
    monkeypatch.setattr(ic.time, "sleep", lambda s: None)


# -- VirusTotal HTTP behaviour -------------------------------------------------

class TestVtGet:
    def test_missing_key(self, monkeypatch):
        monkeypatch.setattr(ic, "VT_API_KEY", "")
        assert "VT_API_KEY" in ic._vt_get("ip_addresses/1.2.3.4")["error"]

    def test_success_sends_api_key_header(self, monkeypatch):
        get = MagicMock(return_value=_resp(200, {"data": {}}))
        monkeypatch.setattr(ic.requests, "get", get)
        assert ic._vt_get("ip_addresses/1.2.3.4") == {"data": {}}
        assert get.call_args.kwargs["headers"]["x-apikey"] == "test-vt-key"

    def test_404_is_reported_not_raised(self, monkeypatch):
        monkeypatch.setattr(ic.requests, "get", MagicMock(return_value=_resp(404)))
        assert "not found" in ic._vt_get("files/abc")["error"]

    def test_429_retries_once_after_sleep(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(ic.time, "sleep", sleeps.append)
        get = MagicMock(side_effect=[_resp(429), _resp(200, {"ok": 1})])
        monkeypatch.setattr(ic.requests, "get", get)
        assert ic._vt_get("domains/example.com") == {"ok": 1}
        assert get.call_count == 2
        assert 60 in sleeps

    def test_http_error(self, monkeypatch):
        monkeypatch.setattr(ic.requests, "get", MagicMock(return_value=_resp(500)))
        assert "HTTP 500" in ic._vt_get("domains/example.com")["error"]

    def test_timeout(self, monkeypatch):
        monkeypatch.setattr(ic.requests, "get", MagicMock(side_effect=requests.exceptions.Timeout()))
        assert "timed out" in ic._vt_get("domains/example.com")["error"]

    def test_connection_error(self, monkeypatch):
        monkeypatch.setattr(ic.requests, "get", MagicMock(side_effect=requests.exceptions.ConnectionError()))
        assert "Could not reach" in ic._vt_get("domains/example.com")["error"]

    def test_rate_limit_waits_between_calls(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(ic.time, "sleep", sleeps.append)
        monkeypatch.setattr(ic.requests, "get", MagicMock(return_value=_resp(200, {})))
        ic._vt_get("domains/a.example.com")
        ic._vt_get("domains/b.example.com")
        # the second call follows immediately, so it must wait close to the full interval
        assert sleeps and ic.VT_RATE_LIMIT_SECS - 1 <= sleeps[-1] <= ic.VT_RATE_LIMIT_SECS


class TestAbuseHttp:
    def test_429_reports_daily_limit(self, monkeypatch):
        monkeypatch.setattr(ic.requests, "get", MagicMock(return_value=_resp(429)))
        assert "daily limit" in ic.abuseipdb_check("1.2.3.4")["error"]

    def test_timeout(self, monkeypatch):
        monkeypatch.setattr(ic.requests, "get", MagicMock(side_effect=requests.exceptions.Timeout()))
        assert "timed out" in ic.abuseipdb_check("1.2.3.4")["error"]


# -- Hash / URL parsing --------------------------------------------------------

def test_vt_check_hash_extracts_detections_and_mitre(monkeypatch):
    payload = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 2, "undetected": 3},
        "type_description": "Win32 EXE", "size": 10, "sha256": "ff",
        "last_analysis_results": {
            "A": {"category": "malicious", "result": "Win32/Evil.Ransomware"},
            "B": {"category": "undetected", "result": None},
        },
    }}}
    monkeypatch.setattr(ic, "_vt_get", lambda endpoint: payload)
    out = ic.vt_check_hash("a" * 64)
    assert out["top_detections"] == ["A: Win32/Evil.Ransomware"]
    assert out["mitre_context"]["tactic"] == "Impact"
    assert out["total"] == 5


def test_vt_check_url_uses_unpadded_base64url(monkeypatch):
    seen = []
    monkeypatch.setattr(ic, "_vt_get", lambda endpoint: seen.append(endpoint) or {"error": "x"})
    ic.vt_check_url("https://a.example/")
    assert seen[0].startswith("urls/") and "=" not in seen[0]


# -- Verdict boundaries (the thresholds documented in the README) --------------

@pytest.mark.parametrize("vt,abuse,expected", [
    ({"malicious": 5}, None, ic.VERDICT_TP),
    ({"malicious": 4}, None, ic.VERDICT_SUSPICIOUS),
    ({"malicious": 0, "suspicious": 3}, None, ic.VERDICT_SUSPICIOUS),
    ({"malicious": 0, "suspicious": 2}, None, ic.VERDICT_BENIGN),
    ({"malicious": 0}, {"abuse_confidence_score": 75}, ic.VERDICT_TP),
    ({"malicious": 0}, {"abuse_confidence_score": 74}, ic.VERDICT_SUSPICIOUS),
    ({"malicious": 0}, {"abuse_confidence_score": 25}, ic.VERDICT_SUSPICIOUS),
    ({"malicious": 0}, {"abuse_confidence_score": 24}, ic.VERDICT_BENIGN),
    ({"malicious": 0}, {"abuse_confidence_score": 0, "is_tor": True}, ic.VERDICT_TP),
    ({"error": "boom"}, None, ic.VERDICT_UNKNOWN),
])
def test_verdict_boundaries(vt, abuse, expected):
    assert ic.calculate_verdict(vt, abuse)[0] == expected


def test_abuse_error_does_not_change_vt_verdict():
    verdict, _ = ic.calculate_verdict({"malicious": 0}, {"error": "limit"})
    assert verdict == ic.VERDICT_BENIGN


# -- Demo mode -----------------------------------------------------------------

class TestDemo:
    @pytest.fixture(autouse=True)
    def demo_on(self, monkeypatch):
        monkeypatch.setattr(ic, "DEMO_MODE", True)
        monkeypatch.setattr(ic, "VT_API_KEY", "")
        monkeypatch.setattr(ic, "ABUSEIPDB_API_KEY", "")
        # Any real HTTP call in demo mode is a bug.
        monkeypatch.setattr(ic.requests, "get", MagicMock(side_effect=AssertionError("network used")))

    def test_every_demo_ioc_gets_a_verdict_without_network(self):
        verdicts = set()
        for ioc in demo.DEMO_IOCS:
            vt, abuse, from_cache = ic._fetch_all(ioc, ic.detect_ioc_type(ioc))
            assert from_cache is False
            verdicts.add(ic.calculate_verdict(vt, abuse)[0])
        assert verdicts == {ic.VERDICT_TP, ic.VERDICT_SUSPICIOUS, ic.VERDICT_BENIGN, ic.VERDICT_UNKNOWN}

    def test_demo_does_not_write_cache(self):
        ic._fetch_all("203.0.113.66", "ip")
        assert not ic.CACHE_FILE.exists()

    def test_demo_json_output(self, capsys):
        ic.triage_ioc("203.0.113.66", json_output=True)
        report = json.loads(capsys.readouterr().out)
        assert report["verdict"] == ic.VERDICT_TP
        assert report["abuseipdb"]["is_tor"] is True

    def test_cli_demo_flag(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["ioc_checker", "--demo"])
        ic.main()
        captured = capsys.readouterr()
        assert "IOC TRIAGE REPORT" in captured.out
        assert "DEMO MODE" in captured.err  # banner goes to stderr so --json stays pipeable
