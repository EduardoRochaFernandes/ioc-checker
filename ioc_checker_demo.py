"""
ioc_checker_demo.py — canned sample data for ``ioc_checker --demo``
====================================================================
Lets anyone try the tool with no API keys and no network access.

IMPORTANT: everything here is *synthetic*. The payloads mimic the shape of
the real VirusTotal v3 / AbuseIPDB v2 JSON responses so the real parsing,
verdict and report code runs unchanged, but the numbers, vendor names and
detection names are invented for illustration. They are NOT live threat
intelligence. IPs use RFC 5737 documentation ranges and domains use
reserved example names.
"""

import base64

# IOCs triaged when you run ``ioc_checker --demo`` without -i / -f.
DEMO_IOCS = [
    "203.0.113.66",
    "198.51.100.23",
    "8.8.8.8",
    "login-update.example.com",
    "https://docs.example.org/shared/invoice.html",
    "a2d5038b5a27ee54fe05bef590a3e9e2ed52e5e4c7bf2f82192d725f126fb3d0",
    "never-seen.example.net",
]


def _url_id(url: str) -> str:
    """VirusTotal identifies a URL by its unpadded base64url form."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _stats(malicious: int, suspicious: int, harmless: int, undetected: int) -> dict:
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
    }


def _wrap(attributes: dict) -> dict:
    return {"data": {"attributes": attributes}}


# Keyed by the VT endpoint the tool would call (same strings as _vt_get).
DEMO_VT: dict[str, dict] = {
    "ip_addresses/203.0.113.66": _wrap({
        "last_analysis_stats": _stats(14, 2, 55, 20),
        "country": "NL", "asn": 64500, "as_owner": "Example Hosting B.V. (demo)",
        "reputation": -62, "categories": {}, "tags": ["tor"],
    }),
    "ip_addresses/198.51.100.23": _wrap({
        "last_analysis_stats": _stats(2, 1, 70, 18),
        "country": "DE", "asn": 64501, "as_owner": "Example Cloud GmbH (demo)",
        "reputation": -4, "categories": {}, "tags": [],
    }),
    "ip_addresses/8.8.8.8": _wrap({
        "last_analysis_stats": _stats(0, 0, 70, 22),
        "country": "US", "asn": 15169, "as_owner": "Google LLC",
        "reputation": 500, "categories": {}, "tags": [],
    }),
    "domains/login-update.example.com": _wrap({
        "last_analysis_stats": _stats(7, 2, 60, 22),
        "reputation": -25, "registrar": "Example Registrar (demo)",
        "creation_date": 1767225600,
        "categories": {"Vendor A": "phishing", "Vendor B": "malicious"},
        "tags": [],
    }),
    f"urls/{_url_id('https://docs.example.org/shared/invoice.html')}": _wrap({
        "last_analysis_stats": _stats(0, 3, 75, 14),
        "last_final_url": "https://docs.example.org/shared/invoice.html",
        "title": "Shared invoice",
        "categories": {"Vendor A": "suspicious content"}, "tags": [],
    }),
    "files/a2d5038b5a27ee54fe05bef590a3e9e2ed52e5e4c7bf2f82192d725f126fb3d0": _wrap({
        "last_analysis_stats": _stats(9, 1, 0, 50),
        "type_description": "Win32 EXE", "size": 482304,
        "meaningful_name": "invoice_viewer.exe",
        "sha256": "a2d5038b5a27ee54fe05bef590a3e9e2ed52e5e4c7bf2f82192d725f126fb3d0",
        "last_analysis_results": {
            "VendorA": {"category": "malicious", "result": "Ransom.Demo.Gen"},
            "VendorB": {"category": "malicious", "result": "Trojan.Demo.Agent"},
            "VendorC": {"category": "malicious", "result": "Win32/Demo.Ransomware.A"},
            "VendorD": {"category": "undetected", "result": None},
        },
        "tags": ["peexe"],
    }),
}

# Keyed by IP address. Mirrors the "data" object of AbuseIPDB's /check.
DEMO_ABUSEIPDB: dict[str, dict] = {
    "203.0.113.66": {
        "abuseConfidenceScore": 100, "totalReports": 312, "countryCode": "NL",
        "isp": "Example Hosting B.V. (demo)", "domain": "example.com",
        "isTor": True, "isPublic": True, "usageType": "Data Center/Web Hosting/Transit",
        "lastReportedAt": "2026-01-15T09:30:00+00:00",
    },
    "198.51.100.23": {
        "abuseConfidenceScore": 40, "totalReports": 9, "countryCode": "DE",
        "isp": "Example Cloud GmbH (demo)", "domain": "example.net",
        "isTor": False, "isPublic": True, "usageType": "Data Center/Web Hosting/Transit",
        "lastReportedAt": "2026-01-10T18:02:00+00:00",
    },
    "8.8.8.8": {
        "abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "US",
        "isp": "Google LLC", "domain": "google.com",
        "isTor": False, "isPublic": True, "usageType": "Data Center/Web Hosting/Transit",
        "lastReportedAt": None,
    },
}
