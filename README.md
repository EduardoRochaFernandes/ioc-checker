# ioc-checker

A command-line triage tool for SOC analysts. Checks IPs, domains, URLs, and file hashes against **VirusTotal** and **AbuseIPDB**, and produces a structured report with verdict and analyst next steps.

Built as part of a SOC L1/L2 learning path (TryHackMe), reflecting the manual triage workflow from phishing analysis, alert triage, threat intel, and malware classification labs.

---

## Features

- Auto-detects IOC type (IP, domain, URL, MD5 / SHA1 / SHA256)
- Queries VirusTotal for detection stats, categories, tags, and file metadata
- Queries AbuseIPDB for IP abuse confidence score and Tor node detection
- Infers MITRE ATT&CK tactic and technique from hash detection names
- Verdicts: **True Positive / Suspicious / Likely Benign / Unknown**
- Analyst next steps tailored to IOC type and verdict (SOC L1/L2 aligned)
- Rate-limit aware — enforces 16s delay between VT requests on free tier
- Local JSON cache (24h TTL) to avoid redundant API calls
- Persistent audit log of every triage session
- JSON output mode for piping into other tools
- Bulk mode: read a list of IOCs from a file

---

## Setup

```bash
git clone https://github.com/<your-username>/ioc-checker.git
cd ioc-checker
pip install -r requirements.txt
cp .env.example .env   # then add your API keys
```

Free API keys:
- **VirusTotal** — https://www.virustotal.com/gui/my-apikey (4 req/min)
- **AbuseIPDB** — https://www.abuseipdb.com/account/api (1000 req/day)

---

## Usage

```bash
# Single IOC
python ioc_checker.py -i 185.220.101.45
python ioc_checker.py -i malicious-domain.com
python ioc_checker.py -i https://phishing.example/login
python ioc_checker.py -i 44d88612fea8a8f36de82e1278abb02f

# Bulk from file (see iocs.example.txt)
python ioc_checker.py -f iocs.txt

# JSON output (pipe to jq or save to file)
python ioc_checker.py -i 185.220.101.45 --json | jq .verdict
python ioc_checker.py -f iocs.txt --json > results.json

# Force fresh API call (bypass cache)
python ioc_checker.py -i 185.220.101.45 --no-cache
```

---

## Example output

```
══════════════════════════════════════════════════════════════
  IOC TRIAGE REPORT
  2025-03-01 14:32:11 UTC
══════════════════════════════════════════════════════════════
  IOC   :  185[.]220[.]101[.]45
  Type  :  IP
──────────────────────────────────────────────────────────────

[ VirusTotal ]
  Detections  :  🔴  12 malicious  /  2 suspicious  /  94 vendors
  Reputation  :  -80
  Country     :  DE
  ASN         :  AS205100  —  F3 Netze e.V.

[ AbuseIPDB ]
  Confidence  :  98/100  [█████████░]
  Reports     :  847  (last 90 days)
  ISP         :  F3 Netze e.V.
  Usage type  :  Tor Proxy
  Tor node    :  YES  ⚠

──────────────────────────────────────────────────────────────
  VERDICT  :  TRUE POSITIVE ⚠
  REASON   :  12/94 VT vendors flagged malicious | AbuseIPDB confidence 98/100 | confirmed Tor exit node
──────────────────────────────────────────────────────────────

[ Analyst Next Steps ]
  1.  Document all findings now — before escalation to L2
  2.  Search SIEM for this IOC across all hosts (last 30 days)
  3.  Check for lateral movement — are other hosts involved?
  4.  Block at firewall / proxy / EDR and raise a ticket
  5.  Cross-reference with Talos Intelligence for added context
  6.  Review netflow — check volume, frequency, and ports
```

---

## Verdict thresholds

| Verdict | Condition |
|---|---|
| True Positive ⚠ | ≥5 VT malicious detections, OR AbuseIPDB ≥75, OR Tor node |
| Suspicious 🔍 | 1–4 VT malicious, OR ≥3 suspicious, OR AbuseIPDB 25–74 |
| Likely Benign ✓ | 0 malicious, ≤2 suspicious, AbuseIPDB <25 |
| Unknown ? | API error or insufficient data |

---

## Running the tests

```bash
pip install pytest
pytest tests/ -v
```

41 unit tests covering IOC classification, defanging, MITRE inference, verdict logic, cache behaviour, and API response parsing — all without real HTTP calls.

---

## Project structure

```
ioc-checker/
├── ioc_checker.py       # Main tool
├── requirements.txt
├── .env.example         # API key template
├── iocs.example.txt     # Example IOC list
├── tests/
│   └── test_ioc_checker.py
└── README.md
```

---

## Context

Built as part of a SOC L1/L2 learning path. Reflects the triage workflow documented in:
- Phishing Analysis Tools lab (tool selection by investigation phase)
- SOC L1 Alert Triage lab (verdict classification and escalation logic)
- IP and Domain Threat Intel lab (VirusTotal, AbuseIPDB, Talos)
- Malware Classification lab (MITRE ATT&CK mapping from detection names)

---

## License

MIT
