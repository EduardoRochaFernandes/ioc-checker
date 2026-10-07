#!/usr/bin/env python3
"""
ioc_checker.py — IOC Triage Tool
=================================
A command-line tool for SOC analysts to quickly triage Indicators of
Compromise (IOCs) against public threat intelligence APIs.

Supported IOC types:
    IP addresses, domains, URLs, and file hashes (MD5 / SHA1 / SHA256)

APIs:
    VirusTotal  — detection stats, file metadata, categories, tags
    AbuseIPDB   — IP abuse confidence score, Tor node detection (IPs only)

Key features:
    - Auto-detects IOC type from input
    - Rate-limit aware: enforces a 16s delay between VT requests on free tier
    - Local JSON cache to avoid redundant API calls (default TTL: 24h)
    - Persistent audit log of every triage session
    - Structured verdict with analyst next steps (SOC L1/L2 aligned)
    - JSON output mode for piping into other tools
    - Bulk mode: read a list of IOCs from a file
    - --demo mode: canned, synthetic API responses (no keys, no network)

Usage:
    python ioc_checker.py -i 185.220.101.45
    python ioc_checker.py -i malicious-domain.com
    python ioc_checker.py -i https://phishing.example/login
    python ioc_checker.py -i 44d88612fea8a8f36de82e1278abb02f
    python ioc_checker.py -f iocs.txt
    python ioc_checker.py -i 8.8.8.8 --json | jq .
    python ioc_checker.py --demo          # no API keys, no network

Setup:
    pip install -e .
    Create a .env file:
        VT_API_KEY=<your_key>          # https://www.virustotal.com/gui/my-apikey
        ABUSEIPDB_API_KEY=<your_key>   # https://www.abuseipdb.com/account/api

Author  : Eduardo Fernandes
Version : 2.0.0
License : MIT
"""

# ── Standard library ──────────────────────────────────────────────────────────
import argparse
import base64
import ipaddress
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Third-party ───────────────────────────────────────────────────────────────
try:
    import requests
    from requests.exceptions import ConnectionError, HTTPError, Timeout
except ImportError:
    sys.exit("[!] Missing dependency — run: pip install requests")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # .env support is optional; falls back to environment variables

# ── Configuration ─────────────────────────────────────────────────────────────
VT_API_KEY        = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

VT_BASE           = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE    = "https://api.abuseipdb.com/api/v2"

# Free VT tier: 4 requests/minute. 16s between calls keeps us safely under.
VT_RATE_LIMIT_SECS = 16

# Cache and audit log live next to the script (the repo folder when you use
# `pip install -e .`). Set IOC_CHECKER_HOME to store them somewhere else.
DATA_DIR = Path(os.getenv("IOC_CHECKER_HOME") or Path(__file__).parent)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Cache entries expire after 24 hours by default.
CACHE_FILE      = DATA_DIR / ".ioc_cache.json"
CACHE_TTL_HOURS = 24

# Audit log — one line per triage run, appended indefinitely.
LOG_FILE = DATA_DIR / "ioc_checker.log"

# Demo mode (--demo): serve canned responses instead of calling the APIs.
DEMO_MODE = False

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level    = logging.INFO,
    format   = "%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt  = "%Y-%m-%d %H:%M:%S",
    handlers = [
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        # Terminal output is managed manually for cleaner formatting.
    ],
)
log = logging.getLogger(__name__)

# ── MITRE ATT&CK — keyword to tactic/technique mapping ───────────────────────
# Inferred from vendor detection names returned by VirusTotal.
# Based on SOC L1/L2 malware classification and threat hunting knowledge.
# Order matters: more specific terms first to avoid early generic matches.
MITRE_CONTEXT: dict[str, dict[str, str]] = {
    "ransomware":     {"tactic": "Impact",            "technique": "T1486 – Data Encrypted for Impact"},
    "keylogger":      {"tactic": "Collection",        "technique": "T1056 – Input Capture"},
    "stealer":        {"tactic": "Collection",        "technique": "T1056 – Input Capture"},
    "rootkit":        {"tactic": "Defense Evasion",   "technique": "T1014 – Rootkit"},
    "backdoor":       {"tactic": "Persistence",       "technique": "T1543 – Create or Modify System Process"},
    "rat":            {"tactic": "Command & Control", "technique": "T1219 – Remote Access Software"},
    "c2":             {"tactic": "Command & Control", "technique": "T1071 – Application Layer Protocol"},
    "worm":           {"tactic": "Lateral Movement",  "technique": "T1570 – Lateral Tool Transfer"},
    "dropper":        {"tactic": "Execution",         "technique": "T1105 – Ingress Tool Transfer"},
    "trojan":         {"tactic": "Execution",         "technique": "T1059 – Command and Scripting Interpreter"},
    "phishing":       {"tactic": "Initial Access",    "technique": "T1566 – Phishing"},
    "exfil":          {"tactic": "Exfiltration",      "technique": "T1041 – Exfiltration Over C2 Channel"},
    "miner":          {"tactic": "Impact",            "technique": "T1496 – Resource Hijacking"},
    "reconnaissance": {"tactic": "Reconnaissance",    "technique": "T1595 – Active Scanning"},
    "malware":        {"tactic": "Execution",         "technique": "T1204 – User Execution"},
}

# ── Verdict constants ─────────────────────────────────────────────────────────
VERDICT_TP         = "TRUE POSITIVE ⚠"
VERDICT_SUSPICIOUS = "SUSPICIOUS 🔍"
VERDICT_BENIGN     = "LIKELY BENIGN ✓"
VERDICT_UNKNOWN    = "UNKNOWN ?"

# ── Visual helpers ────────────────────────────────────────────────────────────
SEP  = "─" * 62
SEP2 = "═" * 62


# =============================================================================
# Cache
# =============================================================================

def _load_cache() -> dict:
    """Load the on-disk cache, returning an empty dict if missing or corrupt.

    Returns:
        Dictionary of cached results keyed by IOC string.
    """
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Corrupt or unreadable cache — start fresh rather than crashing.
        return {}


def _save_cache(cache: dict) -> None:
    """Persist the cache dictionary to disk.

    Args:
        cache: The full cache dictionary to write.
    """
    try:
        CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except OSError as exc:
        log.warning("Could not write cache: %s", exc)


def cache_get(ioc: str) -> dict | None:
    """Return a cached result for an IOC if it exists and has not expired.

    Args:
        ioc: The raw IOC string used as the cache key.

    Returns:
        Cached result dict, or None if the entry is missing or expired.
    """
    entry = _load_cache().get(ioc)
    if not entry:
        return None
    cached_at = datetime.fromisoformat(entry.get("cached_at", "2000-01-01T00:00:00+00:00"))
    if datetime.now(timezone.utc) - cached_at > timedelta(hours=CACHE_TTL_HOURS):
        return None
    return entry.get("data")


def cache_set(ioc: str, data: dict) -> None:
    """Store a triage result in the cache with a current UTC timestamp.

    Args:
        ioc:  The IOC string used as the cache key.
        data: The result dictionary to cache.
    """
    cache = _load_cache()
    cache[ioc] = {
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    _save_cache(cache)


# =============================================================================
# IOC classification
# =============================================================================

def defang(ioc: str) -> str:
    """Return a defanged IOC string safe for use in reports and tickets.

    Replaces dots with [.] and http with hxxp to prevent accidental
    hyperlinking or execution in mail clients and ticketing systems.

    Args:
        ioc: Raw IOC string (IP, domain, or URL).

    Returns:
        Defanged string.

    Example:
        >>> defang("http://malicious.com/payload")
        'hxxp://malicious[.]com/payload'
    """
    # Guard against double-defanging: skip if already defanged.
    if "[.]" in ioc and "hxxp" in ioc:
        return ioc
    return ioc.replace(".", "[.]").replace("http", "hxxp")


def detect_ioc_type(ioc: str) -> str:
    """Classify an IOC string by type.

    Detection order: hashes first (fixed length + hex charset), then URLs
    (have a scheme), then IPs (parseable by ipaddress), then domains.

    Args:
        ioc: Raw input string.

    Returns:
        One of: 'hash_md5', 'hash_sha1', 'hash_sha256',
                'url', 'ip', 'domain', or 'unknown'.
    """
    ioc = ioc.strip()

    if re.fullmatch(r"[0-9a-fA-F]{32}", ioc):
        return "hash_md5"
    if re.fullmatch(r"[0-9a-fA-F]{40}", ioc):
        return "hash_sha1"
    if re.fullmatch(r"[0-9a-fA-F]{64}", ioc):
        return "hash_sha256"

    if re.match(r"https?://", ioc, re.IGNORECASE):
        return "url"

    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass

    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", ioc):
        return "domain"

    return "unknown"


def infer_mitre(detections: list[str]) -> dict | None:
    """Infer the most likely MITRE ATT&CK mapping from VT detection names.

    Iterates MITRE_CONTEXT in definition order and returns the first
    keyword match found in the combined detection string.

    Args:
        detections: List of 'Vendor: DetectionName' strings from VT.

    Returns:
        Dict with 'tactic' and 'technique' keys, or None if no match.
    """
    combined = " ".join(detections).lower()
    for keyword, context in MITRE_CONTEXT.items():
        if keyword in combined:
            return context
    return None


# =============================================================================
# VirusTotal API
# =============================================================================

_last_vt_call: float = 0.0  # module-level timestamp used for rate limiting


def _vt_get(endpoint: str) -> dict:
    """Make a rate-limited GET request to the VirusTotal v3 API.

    Enforces VT_RATE_LIMIT_SECS between calls to stay within the free
    tier quota. On a 429 response, waits 60 seconds and retries once.

    Args:
        endpoint: Path appended to VT_BASE (e.g. 'ip_addresses/1.2.3.4').

    Returns:
        Parsed JSON response dict, or {'error': <message>} on failure.
    """
    global _last_vt_call

    if DEMO_MODE:
        from ioc_checker_demo import DEMO_VT
        return DEMO_VT.get(endpoint, {"error": "IOC not found in VirusTotal database"})

    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured — add it to your .env file"}

    elapsed = time.time() - _last_vt_call
    if elapsed < VT_RATE_LIMIT_SECS:
        wait = VT_RATE_LIMIT_SECS - elapsed
        log.info("VT rate limit: waiting %.1fs before next request", wait)
        time.sleep(wait)

    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
    url     = f"{VT_BASE}/{endpoint}"

    try:
        response = requests.get(url, headers=headers, timeout=12)
        _last_vt_call = time.time()

        if response.status_code == 404:
            return {"error": "IOC not found in VirusTotal database"}

        if response.status_code == 429:
            log.warning("VT 429 received — sleeping 60s and retrying once")
            time.sleep(60)
            response = requests.get(url, headers=headers, timeout=12)
            _last_vt_call = time.time()

        response.raise_for_status()
        return response.json()

    except Timeout:
        return {"error": "VirusTotal request timed out after 12s"}
    except ConnectionError:
        return {"error": "Could not reach VirusTotal — check your network connection"}
    except HTTPError as exc:
        return {"error": f"VirusTotal returned HTTP {exc.response.status_code}"}


def _parse_vt_stats(attrs: dict) -> dict:
    """Extract and normalise last_analysis_stats from a VT attributes dict.

    Args:
        attrs: The 'attributes' sub-dict from a VT API response.

    Returns:
        Dict with keys: malicious, suspicious, harmless, undetected, total.
    """
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total":      sum(stats.values()) or 1,
    }


def vt_check_ip(ip: str) -> dict:
    """Query VirusTotal for an IP address.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        Normalised result dict, or {'error': ...} on failure.
    """
    raw = _vt_get(f"ip_addresses/{ip}")
    if "error" in raw:
        return raw
    attrs  = raw.get("data", {}).get("attributes", {})
    result = _parse_vt_stats(attrs)
    result.update({
        "country":    attrs.get("country", "N/A"),
        "asn":        attrs.get("asn", "N/A"),
        "as_owner":   attrs.get("as_owner", "N/A"),
        "reputation": attrs.get("reputation", 0),
        "categories": attrs.get("categories", {}),
        "tags":       attrs.get("tags", []),
    })
    return result


def vt_check_domain(domain: str) -> dict:
    """Query VirusTotal for a domain name.

    Args:
        domain: Fully-qualified domain name.

    Returns:
        Normalised result dict, or {'error': ...} on failure.
    """
    raw = _vt_get(f"domains/{domain}")
    if "error" in raw:
        return raw
    attrs  = raw.get("data", {}).get("attributes", {})
    result = _parse_vt_stats(attrs)
    result.update({
        "reputation":    attrs.get("reputation", 0),
        "registrar":     attrs.get("registrar", "N/A"),
        "creation_date": attrs.get("creation_date", "N/A"),
        "categories":    attrs.get("categories", {}),
        "tags":          attrs.get("tags", []),
    })
    return result


def vt_check_url(url: str) -> dict:
    """Query VirusTotal for a URL.

    VT identifies URLs by their base64url-encoded form (without padding).

    Args:
        url: Full URL including scheme.

    Returns:
        Normalised result dict, or {'error': ...} on failure.
    """
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    raw    = _vt_get(f"urls/{url_id}")
    if "error" in raw:
        return raw
    attrs  = raw.get("data", {}).get("attributes", {})
    result = _parse_vt_stats(attrs)
    result.update({
        "final_url":  attrs.get("last_final_url", url),
        "title":      attrs.get("title", "N/A"),
        "categories": attrs.get("categories", {}),
        "tags":       attrs.get("tags", []),
    })
    return result


def vt_check_hash(file_hash: str) -> dict:
    """Query VirusTotal for a file hash (MD5, SHA1, or SHA256).

    Also extracts the top malicious vendor detections and infers a MITRE
    ATT&CK mapping from those detection names.

    Args:
        file_hash: Hex-encoded file hash string.

    Returns:
        Normalised result dict including detections and MITRE context,
        or {'error': ...} on failure.
    """
    raw = _vt_get(f"files/{file_hash}")
    if "error" in raw:
        return raw
    attrs      = raw.get("data", {}).get("attributes", {})
    result     = _parse_vt_stats(attrs)
    vt_results = attrs.get("last_analysis_results", {})

    detections = [
        f"{vendor}: {r['result']}"
        for vendor, r in vt_results.items()
        if r.get("category") == "malicious" and r.get("result")
    ]

    result.update({
        "file_type":      attrs.get("type_description", "N/A"),
        "file_size":      attrs.get("size", "N/A"),
        "name":           attrs.get("meaningful_name", "N/A"),
        "md5":            attrs.get("md5", "N/A"),
        "sha1":           attrs.get("sha1", "N/A"),
        "sha256":         attrs.get("sha256", "N/A"),
        "top_detections": detections[:6],
        "mitre_context":  infer_mitre(detections),
        "tags":           attrs.get("tags", []),
    })
    return result


# =============================================================================
# AbuseIPDB API
# =============================================================================

def _parse_abuseipdb(d: dict) -> dict:
    """Normalise the 'data' object of an AbuseIPDB /check response.

    Args:
        d: The 'data' sub-dict from the AbuseIPDB API response.

    Returns:
        Dict with the fields the report and verdict logic use.
    """
    return {
        "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
        "total_reports":          d.get("totalReports", 0),
        "country_code":           d.get("countryCode", "N/A"),
        "isp":                    d.get("isp", "N/A"),
        "domain":                 d.get("domain", "N/A"),
        "is_tor":                 d.get("isTor", False),
        "is_public":              d.get("isPublic", True),
        "usage_type":             d.get("usageType", "N/A"),
        "last_reported":          d.get("lastReportedAt", "N/A"),
    }


def abuseipdb_check(ip: str) -> dict:
    """Query AbuseIPDB for IP abuse history over the last 90 days.

    The confidence score (0–100) represents the percentage of reporters
    who confirmed the IP as abusive. Tor exit node status is also returned.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        Normalised result dict, or {'error': ...} on failure.
    """
    if DEMO_MODE:
        from ioc_checker_demo import DEMO_ABUSEIPDB
        if ip not in DEMO_ABUSEIPDB:
            return {"error": "No canned AbuseIPDB data for this IP (demo mode)"}
        return _parse_abuseipdb(DEMO_ABUSEIPDB[ip])

    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not configured — add it to your .env file"}

    try:
        response = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=12,
        )
        if response.status_code == 429:
            return {"error": "AbuseIPDB daily limit reached (1000 req/day on free tier)"}
        response.raise_for_status()
        return _parse_abuseipdb(response.json().get("data", {}))
    except Timeout:
        return {"error": "AbuseIPDB request timed out after 12s"}
    except ConnectionError:
        return {"error": "Could not reach AbuseIPDB — check your network connection"}
    except HTTPError as exc:
        return {"error": f"AbuseIPDB returned HTTP {exc.response.status_code}"}


# =============================================================================
# Verdict logic
# =============================================================================

def calculate_verdict(vt: dict, abuse: dict | None = None) -> tuple[str, str]:
    """Determine the triage verdict from VirusTotal and AbuseIPDB results.

    Thresholds are intentionally conservative: prefer flagging for manual
    review over silently clearing a potentially malicious IOC.

    Verdict hierarchy:
        TRUE POSITIVE  — high confidence malicious
        SUSPICIOUS     — low detections or moderate abuse score
        LIKELY BENIGN  — no detections, low abuse score
        UNKNOWN        — data unavailable or insufficient

    Args:
        vt:    Normalised VirusTotal result dict.
        abuse: Normalised AbuseIPDB result dict, or None if not applicable.

    Returns:
        Tuple of (verdict_constant, human_readable_reason).
    """
    if "error" in vt:
        return VERDICT_UNKNOWN, f"Data unavailable: {vt['error']}"

    mal   = vt.get("malicious", 0)
    sus   = vt.get("suspicious", 0)
    total = vt.get("total", 1) or 1

    abuse_score = 0
    is_tor      = False
    if abuse and "error" not in abuse:
        abuse_score = abuse.get("abuse_confidence_score", 0)
        is_tor      = abuse.get("is_tor", False)

    # ── TRUE POSITIVE ─────────────────────────────────────────────────────────
    tp_reasons = []
    if mal >= 5:
        tp_reasons.append(f"{mal}/{total} VT vendors flagged malicious")
    if abuse_score >= 75:
        tp_reasons.append(f"AbuseIPDB confidence {abuse_score}/100")
    if is_tor:
        tp_reasons.append("confirmed Tor exit node")
    if tp_reasons:
        return VERDICT_TP, " | ".join(tp_reasons)

    # ── SUSPICIOUS ────────────────────────────────────────────────────────────
    sus_reasons = []
    if mal >= 1:
        sus_reasons.append(f"{mal} VT vendor(s) flagged malicious")
    if sus >= 3:
        sus_reasons.append(f"{sus} VT vendors flagged suspicious")
    if 25 <= abuse_score < 75:
        sus_reasons.append(f"AbuseIPDB confidence {abuse_score}/100 — moderate risk")
    if sus_reasons:
        return VERDICT_SUSPICIOUS, " | ".join(sus_reasons)

    # ── LIKELY BENIGN ─────────────────────────────────────────────────────────
    if mal == 0 and sus <= 2 and abuse_score < 25:
        return VERDICT_BENIGN, f"No malicious detections | AbuseIPDB score {abuse_score}/100"

    return VERDICT_UNKNOWN, "Insufficient data — manual review required"


# =============================================================================
# Report rendering
# =============================================================================

def _bar(score: int, width: int = 10) -> str:
    """Render a simple ASCII progress bar for a 0-100 score.

    Args:
        score: Integer between 0 and 100.
        width: Total number of bar segments.

    Returns:
        ASCII bar string, e.g. '████░░░░░░'.
    """
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def _print_header(ioc: str, ioc_type: str, from_cache: bool) -> None:
    """Print the report header block.

    Args:
        ioc:        Raw IOC string.
        ioc_type:   Classified IOC type string.
        from_cache: Whether this result came from the local cache.
    """
    cache_tag = "  [CACHED]" if from_cache else ""
    cache_tag += "  [DEMO - canned sample data]" if DEMO_MODE else ""
    print(f"\n{SEP2}")
    print(f"  IOC TRIAGE REPORT{cache_tag}")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(SEP2)
    print(f"  IOC   :  {defang(ioc)}")
    print(f"  Type  :  {ioc_type.replace('hash_', '').upper()}")
    print(SEP)


def _print_virustotal(ioc_type: str, vt: dict) -> None:
    """Print the VirusTotal section of the report.

    Args:
        ioc_type: Classified IOC type (ip, domain, url, hash_*).
        vt:       Normalised VirusTotal result dict.
    """
    print("\n[ VirusTotal ]")
    if "error" in vt:
        print(f"  !  {vt['error']}")
        return

    mal   = vt.get("malicious", 0)
    sus   = vt.get("suspicious", 0)
    total = vt.get("total", 0)

    flag = "🔴" if mal >= 5 else "🟡" if mal >= 1 or sus >= 3 else "🟢"
    print(f"  Detections  :  {flag}  {mal} malicious  /  {sus} suspicious  /  {total} vendors")
    print(f"  Reputation  :  {vt.get('reputation', 'N/A')}")

    if ioc_type == "ip":
        print(f"  Country     :  {vt.get('country', 'N/A')}")
        print(f"  ASN         :  AS{vt.get('asn', 'N/A')}  —  {vt.get('as_owner', 'N/A')}")

    if ioc_type == "domain":
        print(f"  Registrar   :  {vt.get('registrar', 'N/A')}")
        created = vt.get("creation_date", "N/A")
        if isinstance(created, int):
            created = datetime.fromtimestamp(created, tz=timezone.utc).strftime("%Y-%m-%d")
        print(f"  Registered  :  {created}")

    if ioc_type == "url":
        final = vt.get("final_url", "")
        if final:
            print(f"  Final URL   :  {defang(final)}")
        print(f"  Page title  :  {vt.get('title', 'N/A')}")

    if ioc_type.startswith("hash"):
        print(f"  File name   :  {vt.get('name', 'N/A')}")
        print(f"  File type   :  {vt.get('file_type', 'N/A')}")
        size = vt.get("file_size")
        if size and size != "N/A":
            print(f"  File size   :  {size:,} bytes")
        print(f"  MD5         :  {vt.get('md5', 'N/A')}")
        print(f"  SHA1        :  {vt.get('sha1', 'N/A')}")
        print(f"  SHA256      :  {vt.get('sha256', 'N/A')}")

        detections = vt.get("top_detections", [])
        if detections:
            print("  Detections  :")
            for d in detections:
                print(f"    •  {d}")

        mitre = vt.get("mitre_context")
        if mitre:
            print("\n  MITRE ATT&CK  (inferred from detection names)")
            print(f"    Tactic     :  {mitre['tactic']}")
            print(f"    Technique  :  {mitre['technique']}")

    cats = list(set(vt.get("categories", {}).values()))[:4]
    if cats:
        print(f"  Categories  :  {', '.join(cats)}")

    tags = vt.get("tags", [])
    if tags:
        print(f"  Tags        :  {', '.join(tags[:6])}")


def _print_abuseipdb(abuse: dict) -> None:
    """Print the AbuseIPDB section of the report.

    Args:
        abuse: Normalised AbuseIPDB result dict.
    """
    print("\n[ AbuseIPDB ]")
    if "error" in abuse:
        print(f"  !  {abuse['error']}")
        return

    score = abuse.get("abuse_confidence_score", 0)
    print(f"  Confidence  :  {score}/100  [{_bar(score)}]")
    print(f"  Reports     :  {abuse.get('total_reports', 0)}  (last 90 days)")
    print(f"  ISP         :  {abuse.get('isp', 'N/A')}")
    print(f"  Usage type  :  {abuse.get('usage_type', 'N/A')}")
    print(f"  Tor node    :  {'YES  ⚠' if abuse.get('is_tor') else 'No'}")

    last = abuse.get("last_reported", "")
    if last and last != "N/A":
        print(f"  Last report :  {last}")


def _print_verdict(verdict: str, reason: str) -> None:
    """Print the verdict block.

    Args:
        verdict: One of the VERDICT_* constants.
        reason:  Human-readable explanation.
    """
    print(f"\n{SEP}")
    print(f"  VERDICT  :  {verdict}")
    print(f"  REASON   :  {reason}")
    print(SEP)


def _print_next_steps(ioc_type: str, verdict: str) -> None:
    """Print analyst next steps based on verdict and IOC type.

    Steps follow the SOC L1/L2 triage workflow:
    document → search → contain → escalate → close.

    Args:
        ioc_type: Classified IOC type string.
        verdict:  One of the VERDICT_* constants.
    """
    print("\n[ Analyst Next Steps ]")

    if verdict == VERDICT_TP:
        print("  1.  Document all findings now — before escalation to L2")
        print("  2.  Search SIEM for this IOC across all hosts (last 30 days)")
        print("  3.  Check for lateral movement — are other hosts involved?")
        print("  4.  Block at firewall / proxy / EDR and raise a ticket")
        if ioc_type == "ip":
            print("  5.  Cross-reference with Talos Intelligence for added context")
            print("  6.  Review netflow — check volume, frequency, and ports")
        if ioc_type == "domain":
            print("  5.  Check DNS logs — which hosts resolved this and when?")
            print("  6.  Review HTTP proxy logs for URI patterns and POST bodies")
        if ioc_type == "url":
            print("  5.  Screenshot via URLScan.io — never visit directly")
            print("  6.  Check proxy logs for other hosts that requested this URL")
        if ioc_type.startswith("hash"):
            print("  5.  Isolate the affected endpoint immediately")
            print("  6.  Submit to Any.Run or Hybrid Analysis for behaviour report")
            print("  7.  Extract network IOCs from sandbox and re-run ioc_checker")

    elif verdict == VERDICT_SUSPICIOUS:
        print("  1.  Do not block yet — gather context before taking action")
        print("  2.  Search SIEM: which hosts? Which users? What time window?")
        print("  3.  Cross-check with Talos Intelligence and URLScan.io")
        print("  4.  Check asset criticality — is this host high-value?")
        print("  5.  Confirmed malicious → treat as True Positive and escalate")
        print("  6.  Confirmed benign → document the reasoning and close")

    else:  # BENIGN or UNKNOWN
        print("  1.  Document the investigation — note why this IOC was cleared")
        print("  2.  Verify against your org's internal allowlist before closing")
        print("  3.  If surrounding context is still suspicious → escalate anyway")
        print("      A clean score does not automatically clear a suspicious alert.")

    print()


# =============================================================================
# Triage orchestration
# =============================================================================

def _fetch_all(ioc: str, ioc_type: str) -> tuple[dict, dict | None, bool]:
    """Fetch VirusTotal and AbuseIPDB data for an IOC, using cache when possible.

    Args:
        ioc:      Raw IOC string.
        ioc_type: Pre-classified IOC type.

    Returns:
        Tuple of (vt_result, abuseipdb_result_or_None, from_cache).
    """
    # Demo data is never cached (it must not mask real results later).
    cached = None if DEMO_MODE else cache_get(ioc)
    if cached:
        log.info("Cache hit: %s", ioc)
        return cached.get("vt", {}), cached.get("abuse"), True

    vt:    dict           = {}
    abuse: dict | None    = None

    if ioc_type == "ip":
        vt    = vt_check_ip(ioc)
        abuse = abuseipdb_check(ioc)
    elif ioc_type == "domain":
        vt = vt_check_domain(ioc)
    elif ioc_type == "url":
        vt = vt_check_url(ioc)
    elif ioc_type.startswith("hash"):
        vt = vt_check_hash(ioc)

    if not DEMO_MODE:
        cache_set(ioc, {"vt": vt, "abuse": abuse})
    return vt, abuse, False


def triage_ioc(ioc: str, json_output: bool = False) -> None:
    """Run a full triage on a single IOC and print the report.

    Detects IOC type, fetches intelligence data (from cache or APIs),
    calculates a verdict, and renders the appropriate output format.

    Args:
        ioc:         Raw IOC string from the analyst or input file.
        json_output: If True, prints JSON instead of the human-readable
                     report. Useful for piping into jq or other tooling.
    """
    ioc      = ioc.strip()
    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "unknown":
        print(f"[!] Could not classify '{ioc}' — skipping")
        log.warning("Unclassified IOC skipped: %s", ioc)
        return

    vt, abuse, from_cache   = _fetch_all(ioc, ioc_type)
    verdict, reason         = calculate_verdict(vt, abuse)

    log.info("Triage | IOC: %-45s | Type: %-12s | Verdict: %s", ioc, ioc_type, verdict)

    if json_output:
        report = {
            "ioc":          ioc,
            "ioc_defanged": defang(ioc),
            "ioc_type":     ioc_type,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "from_cache":   from_cache,
            "virustotal":   vt,
            "abuseipdb":    abuse,
            "verdict":      verdict,
            "reason":       reason,
        }
        print(json.dumps(report, indent=2, default=str))
        return

    _print_header(ioc, ioc_type, from_cache)
    _print_virustotal(ioc_type, vt)
    if abuse is not None:
        _print_abuseipdb(abuse)
    _print_verdict(verdict, reason)
    _print_next_steps(ioc_type, verdict)


def triage_bulk(filepath: str, json_output: bool = False) -> None:
    """Triage a list of IOCs read from a file.

    File format: one IOC per line. Lines starting with # are comments.
    Blank lines are skipped.

    Args:
        filepath:    Path to the IOC list file.
        json_output: Passed through to triage_ioc for each entry.
    """
    path = Path(filepath)
    if not path.exists():
        sys.exit(f"[!] File not found: {filepath}")

    lines = path.read_text(encoding="utf-8").splitlines()
    iocs  = [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]

    if not iocs:
        sys.exit("[!] No IOCs found in the file")

    print(f"[*] Loaded {len(iocs)} IOC(s) from {path.name}")
    log.info("Bulk triage started: %d IOCs from %s", len(iocs), filepath)

    for ioc in iocs:
        triage_ioc(ioc, json_output=json_output)


# =============================================================================
# CLI
# =============================================================================

def _check_api_keys() -> None:
    """Warn the analyst if any API keys are missing before triage starts."""
    missing = []
    if not VT_API_KEY:
        missing.append("VT_API_KEY       (VirusTotal — required for all IOC types)")
    if not ABUSEIPDB_API_KEY:
        missing.append("ABUSEIPDB_API_KEY (AbuseIPDB — required for IP analysis only)")
    if missing:
        print("[!] Missing API keys — results will be incomplete:")
        for key in missing:
            print(f"    •  {key}")
        print("    Add them to a .env file in this directory.\n")


def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate triage function."""
    parser = argparse.ArgumentParser(
        prog            = "ioc_checker",
        description     = "IOC Triage Tool — VirusTotal + AbuseIPDB",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog          = """
examples:
  %(prog)s -i 185.220.101.45
  %(prog)s -i malicious-domain.com
  %(prog)s -i https://phishing.example/login
  %(prog)s -i 44d88612fea8a8f36de82e1278abb02f
  %(prog)s -f iocs.txt
  %(prog)s -i 8.8.8.8 --json | jq .verdict
  %(prog)s -f iocs.txt --json > results.json
  %(prog)s --demo                       (no API keys needed)

ioc types (auto-detected):
  IP address  →  VirusTotal + AbuseIPDB
  Domain      →  VirusTotal
  URL         →  VirusTotal
  Hash        →  VirusTotal  (MD5 / SHA1 / SHA256)

free api tier limits:
  VirusTotal  — 4 requests/minute  (tool enforces 16s delay automatically)
  AbuseIPDB   — 1000 requests/day
        """,
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-i", "--ioc",
        metavar = "IOC",
        help    = "Single IOC to triage (IP, domain, URL, or hash)",
    )
    group.add_argument(
        "-f", "--file",
        metavar = "FILE",
        help    = "Path to a file with one IOC per line",
    )
    parser.add_argument(
        "--json",
        action = "store_true",
        help   = "Output as JSON (for piping into jq or other tools)",
    )
    parser.add_argument(
        "--demo",
        action = "store_true",
        help   = "Offline demo: canned synthetic responses, no API keys or network. "
                 "Runs the bundled sample IOCs unless -i / -f is given",
    )
    parser.add_argument(
        "--no-cache",
        action = "store_true",
        help   = "Bypass local cache and force fresh API calls",
    )

    args = parser.parse_args()

    # The report uses emoji and box-drawing characters; make sure legacy
    # Windows consoles (cp1252) do not crash on them.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    if not (args.ioc or args.file or args.demo):
        parser.error("one of the arguments -i/--ioc -f/--file --demo is required")

    global DEMO_MODE
    DEMO_MODE = args.demo

    if args.no_cache and not DEMO_MODE and CACHE_FILE.exists():
        CACHE_FILE.unlink()
        print("[*] Cache cleared\n")

    if DEMO_MODE:
        print("[*] DEMO MODE - synthetic canned data, no API keys or network used", file=sys.stderr)
    else:
        _check_api_keys()

    if args.ioc:
        triage_ioc(args.ioc, json_output=args.json)
    elif args.file:
        triage_bulk(args.file, json_output=args.json)
    else:
        from ioc_checker_demo import DEMO_IOCS
        for ioc in DEMO_IOCS:
            triage_ioc(ioc, json_output=args.json)


if __name__ == "__main__":
    main()
