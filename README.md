# 🛡️ jarVisXstar - Ultimate Web Security Library
**By SLATE ASI - Level: GOD TIER**

## Fitur
- **AI WAF Engine** - Deteksi SQLi, XSS, RCE, LFI, SSRF, NoSQLi dengan threat scoring (0-100)
- **Sanitasi Multi-Layer** - Bleach + regex + HTML entity + null byte removal
- **JWT Guard** - HS512 signing, automatic revocation via Redis, JTI tracking
- **Distributed Rate Limiter** - sliding window per IP (default 100 req/menit)
- **Honeypot AI** - Fake endpoints (/admin, /config, /backup) yang mencatat pelaku
- **Threat Intel** - Signature auto-update dari feed eksternal
- **Middleware** - Siap pakai untuk Flask, Django, FastAPI
- **CLI Scanner** - Scan kode untuk hardcoded secret, eval, exec
- **Crypto Armor** - Enkripsi data sensitif dengan AES-256-GCM

## Instalasi
```bash
pip install -r requirements.txt
pip install -e .