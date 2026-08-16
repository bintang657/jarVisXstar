# jarVisXstar

**Version:** 2.0.0  
**Python:** 3.8+  
**License:** MIT  
**Status:** Production-Ready  

---

## Overview

jarVisXstar is a security library that provides Web Application Firewall (WAF) capabilities with AI‑based anomaly detection, distributed rate limiting, multi‑layer obfuscation decoding, and integrated threat intelligence. It is designed to protect web applications from common attacks such as SQL injection, XSS, RCE, SSRF, LFI, Log4J, and more.

---

## Features

| Module | Description |
|--------|-------------|
| AI WAF Engine | Isolation Forest + behavioral biometrics for anomaly detection. |
| Multi‑Layer Decoder | Decodes URL, Base64, Hex, Gzip encoding to reveal hidden payloads. |
| Context‑Aware Sanitizer | Parameterized SQL, XSS DOM purifier, command and path sanitization. |
| Distributed Rate Limiter | Sliding window rate limiting with Redis support. |
| JWT Guardian | HS512 token generation and Redis‑based blacklist. |
| GeoIP Blocker | Blocks high‑risk countries and detects proxies/hosting. |
| Honeypot | Fake endpoints to trap attackers. |
| Notifier | Sends alerts to Telegram and Slack. |
| Threat Intelligence | External IP reputation via AbuseIPDB and VirusTotal. |
| Static Code Scanner | Scans for hardcoded secrets and dangerous functions. |

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Redis (optional, for distributed rate limiting and JWT blacklist)
- Git (optional, for cloning the repository)

---

### Method 1: Install from Source (Recommended)

If you have the source code locally (e.g., downloaded or extracted from a ZIP), navigate to the project root directory and run:

```bash
cd /path/to/jarVisXstar
pip install .