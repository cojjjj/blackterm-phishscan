# 🛡️ BlackTerm PhishScan

> A modern phishing URL intelligence framework built for blue teamers, SOC analysts, and cybersecurity enthusiasts.

---

## 🚀 Overview

BlackTerm PhishScan is a command-line phishing intelligence framework that performs deep analysis against URLs and domains.

Instead of simply checking whether a website is online, BlackTerm gathers intelligence from multiple sources to provide a complete threat assessment.

The framework combines:

- 🌍 DNS Intelligence
- 🔒 SSL Certificate Inspection
- 🌐 WHOIS Analysis
- 🛰️ IP Intelligence
- 🛡️ VirusTotal Reputation
- 📸 Website Screenshot Capture
- 🧠 AI Threat Summaries
- 📄 HTML Reports
- 📁 JSON Reports
- 💻 Modern Rich Terminal Dashboard

---

# Features

## URL Validation

- URL format validation
- HTTPS detection
- Redirect handling
- Reachability checks

---

## VirusTotal Intelligence

- Malicious detections
- Suspicious detections
- Harmless verdicts
- Undetected engines

---

## WHOIS Intelligence

- Registrar
- Creation date
- Expiration date
- Domain age

---

## SSL Intelligence

- Certificate issuer
- Subject
- Validity dates
- Days remaining
- Certificate status

---

## DNS Intelligence

- A Records
- AAAA Records
- MX Records
- NS Records
- TXT Records

---

## IP Intelligence

- ASN lookup
- Network owner
- Hosting provider
- IP address

---

## Website Screenshot

Automatically captures a screenshot of the scanned website for visual verification.

---

## AI Threat Summary

Generates a human-readable summary using all collected intelligence.

Example:

> Target youtube.com was assessed as LOW risk. VirusTotal reported no malicious detections. The SSL certificate is valid, DNS records resolve successfully, and the domain is approximately 20 years old.

---

## Reports

Every scan generates:

- JSON Report
- HTML Report
- Website Screenshot

---

# Installation

Clone the repository

```bash
git clone https://github.com/cojjjj/blackterm_phishscan.git

cd blackterm_phishscan
```

Create a virtual environment

```bash
python -m venv .venv
```

Activate

Windows

```bash
.venv\Scripts\activate
```

Install requirements

```bash
pip install -r requirements.txt
```

Install the CLI

```bash
pip install -e .
```

---

# Usage

Scan a URL

```bash
blackterm scan youtube.com
```

Disable screenshots

```bash
blackterm scan youtube.com --no-screenshot
```

---

# Example Output

```
BLACKTERM PHISHSCAN

✓ URL Validation
✓ VirusTotal
✓ WHOIS
✓ SSL
✓ DNS
✓ IP
✓ Screenshot
✓ AI Summary

Risk Score : 0 / 100
Threat Level : LOW

```

---

# Technology Stack

- Python
- Rich
- Requests
- VirusTotal API
- python-whois
- dnspython
- ipwhois
- Playwright
- Colorama

---

# Roadmap

- [x] VirusTotal Integration
- [x] WHOIS Intelligence
- [x] SSL Intelligence
- [x] DNS Intelligence
- [x] IP Intelligence
- [x] Website Screenshot Capture
- [x] HTML Reporting
- [x] JSON Reporting
- [x] AI Threat Summary
- [x] Rich Terminal Dashboard

### Planned

- [ ] Batch URL Scanning
- [ ] PDF Reports
- [ ] Threat Feed Integration
- [ ] Passive DNS
- [ ] URLHaus Integration
- [ ] AbuseIPDB Integration
- [ ] Shodan Integration
- [ ] Docker Support
- [ ] GitHub Actions
- [ ] Unit Tests

---

# License

MIT License

---

# Author

**Tyler Deppa**

Cybersecurity Student

GitHub

https://github.com/cojjjj

---

If you found this project interesting, consider giving it a ⭐.
