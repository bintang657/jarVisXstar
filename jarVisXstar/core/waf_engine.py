import re
import time
import hashlib
from collections import defaultdict
from typing import Dict, Any, Tuple, List, Optional

class ThreatSignature:
    """Database tanda tangan ancaman - paling update"""
    SQLI = [
        r"(?i)(\bSELECT\b.*\bFROM\b.*\bWHERE\b)", r"(?i)(\bUNION\b.*\bSELECT\b)",
        r"(?i)(\bINSERT\b.*\bINTO\b)", r"(?i)(\bDELETE\b.*\bFROM\b)",
        r"(?i)(\bDROP\b.*\bTABLE\b)", r"(?i)(\bEXEC\b.*\bXP_\w+)",
        r"(?i)('.*\bOR\b.*'.*'.*')", r"(?i)(\bSLEEP\b\s*\()",
        r"(?i)(\bBENCHMARK\b\s*\()", r"(?i)(\bWAITFOR\b.*\bDELAY\b)"
    ]
    XSS = [
        r"<script.*?>.*?</script>", r"(?i)javascript\s*:",
        r"(?i)on\w+\s*=", r"<iframe.*?>", r"<img.*?onerror=",
        r"<svg.*?onload=", r"(?i)eval\s*\(.*?\)",
        r"document\.cookie", r"window\.location", r"alert\s*\("
    ]
    RCE = [
        r"(?i);\s*(wget|curl|bash|sh|python|nc|rm|chmod|whoami|id)",
        r"\$\{.*?\}", r"`.*?`", r"(?i)\|\s*sh", r"(?i)&\s*whoami",
        r"(?i)system\s*\(", r"(?i)popen\s*\(", r"(?i)exec\s*\("
    ]
    LFI = [
        r"\.\./\.\./", r"/etc/passwd", r"/var/log/",
        r"php://filter", r"file://", r"expect://"
    ]
    SSRF = [
        r"http://169.254.169.254", r"http://metadata.google",
        r"http://127.0.0.1", r"http://localhost", r"http://0.0.0.0"
    ]
    NO_SQLI = [
        r"(?i)\{\s*\$gt\s*:", r"(?i)\{\s*\$ne\s*:", r"(?i)\{\s*\$where\s*:",
        r"(?i)\{\s*\$regex\s*:"
    ]

class WAFEngine:
    def __init__(self):
        self.signatures = ThreatSignature()
        self.ip_blacklist = set()
        self.ip_request_count = defaultdict(list)
        self.anomaly_scores = defaultdict(int)
        self.total_blocks = 0

    def inspect(self, payload: Any, client_ip: str) -> Tuple[bool, Dict]:
        report = {
            "blocked": False,
            "score": 0,
            "triggers": [],
            "action": "ALLOW"
        }
        if not payload:
            return True, report

        raw = str(payload).lower()
        score = 0

        # 1. SQLi
        for p in self.signatures.SQLI:
            if re.search(p, raw):
                score += 25
                report["triggers"].append(f"SQLi: {p}")

        # 2. XSS
        for p in self.signatures.XSS:
            if re.search(p, raw):
                score += 20
                report["triggers"].append(f"XSS: {p}")

        # 3. RCE
        for p in self.signatures.RCE:
            if re.search(p, raw):
                score += 30
                report["triggers"].append(f"RCE: {p}")

        # 4. LFI
        for p in self.signatures.LFI:
            if re.search(p, raw):
                score += 20
                report["triggers"].append(f"LFI: {p}")

        # 5. SSRF
        for p in self.signatures.SSRF:
            if re.search(p, raw):
                score += 20
                report["triggers"].append(f"SSRF: {p}")

        # 6. NoSQLi
        for p in self.signatures.NO_SQLI:
            if re.search(p, raw):
                score += 25
                report["triggers"].append(f"NoSQLi: {p}")

        # 7. Obfuskasi (base64/hex ganda)
        if re.search(r"(%[0-9a-f]{2}){5,}", raw) or re.search(r"([0-9a-f]{20,})", raw):
            score += 15
            report["triggers"].append("OBFUSCATION")

        # 8. Panjang ekstrem
        if len(raw) > 8000:
            score += 10
            report["triggers"].append("PAYLOAD_OVERFLOW")

        # 9. Rate limiting
        now = time.time()
        self.ip_request_count[client_ip].append(now)
        self.ip_request_count[client_ip] = [t for t in self.ip_request_count[client_ip] if now - t < 60]
        if len(self.ip_request_count[client_ip]) > 120:
            score += 20
            report["triggers"].append("RATE_LIMIT")

        # 10. Anomali kumulatif
        self.anomaly_scores[client_ip] += score // 10
        if self.anomaly_scores[client_ip] > 60:
            self.ip_blacklist.add(client_ip)
            report["triggers"].append("BLACKLISTED")
            score = 100

        report["score"] = min(score, 100)

        if report["score"] >= 55 or client_ip in self.ip_blacklist:
            report["blocked"] = True
            report["action"] = "BLOCK"
            self.total_blocks += 1
        else:
            report["action"] = "LOG_ONLY"

        return (not report["blocked"]), report