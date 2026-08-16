import re
import time
from collections import defaultdict
from typing import Dict, Any, Tuple, List

class ThreatSignature:
    """Database tanda tangan ancaman - Update V1.1"""
    SQLI = [
        r"(?i)(\bSELECT\b.*\bFROM\b.*\bWHERE\b)", r"(?i)(\bUNION\b.*\bSELECT\b)",
        r"(?i)(\bINSERT\b.*\bINTO\b)", r"(?i)(\bDELETE\b.*\bFROM\b)",
        r"(?i)(\bDROP\b.*\bTABLE\b)", r"(?i)(\bEXEC\b.*\bXP_\w+)",
        r"(?i)('.*\bOR\b.*'.*'.*')", r"(?i)(\bSLEEP\b\s*\()",
        r"(?i)(''\s*OR\s*[0-9]+=[0-9]+)", r"(?i)(''\s*AND\s*[0-9]+=[0-9]+)",
        r"(?i)(--\s*$)"
    ]
    XSS = [
        r"<script.*?>.*?</script>", r"(?i)javascript\s*:",
        r"(?i)on\w+\s*=", r"<iframe.*?>", r"<img.*?onerror=",
        r"<svg.*?onload=", r"(?i)eval\s*\(.*?\)",
        r"document\.cookie", r"alert\s*\("
    ]
    RCE = [
        r"(?i);\s*(wget|curl|bash|sh|python|nc|rm|chmod|whoami|id)",
        r"\$\{.*?\}", r"`.*?`", r"(?i)\|\s*sh", r"(?i)&\s*whoami",
        r"(?i)system\s*\(", r"(?i)popen\s*\(", r"(?i)exec\s*\("
    ]
    LFI = [
        r"\.\./\.\./", r"/etc/passwd", r"/var/log/", r"php://filter",
        r"file://", r"expect://"
    ]
    SSRF = [
        r"http://169.254.169.254", r"http://metadata.google",
        r"http://127.0.0.1", r"http://localhost"
    ]
    # ========== UPDATE V1.1 : ANCAMAN MODERN ==========
    LOG4J = [
        r"(?i)\$\{jndi\s*[:=]\s*(ldap|rmi|dns|iiop)://", 
        r"(?i)jndi\s*[:=]\s*(ldap|rmi|dns)://",
        r"\$\{env\:.*?\}", r"\$\{sys\:.*?\}"
    ]
    SSTI = [
        r"\{\{.*?\}\}", r"\{\%.*?\%\}", r"\$\{.*?\}\}"
    ]
    GRAPHQL = [
        r"(?i)__typename", r"(?i)__schema", r"(?i)__type",
        r"\{\s*__typename\s*\{"
    ]
    OBFUSCATION = [
        r"echo\s+.*?\|.*?base64", r"powershell\s+.*?\-enc",
        r"\$\{IFS\}", r"\$\{PATH\}"
    ]
    HEADER_INJECT = [
        r"\%0d\%0a", r"\%0a\%0d", r"\r\n"
    ]

class WAFEngine:
    def __init__(self):
        self.signatures = ThreatSignature()
        self.ip_blacklist = set()
        self.ip_request_count = defaultdict(list)
        self.anomaly_scores = defaultdict(int)

    def inspect(self, payload: Any, client_ip: str) -> Tuple[bool, Dict]:
        report = {"blocked": False, "score": 0, "triggers": [], "action": "ALLOW"}
        if not payload:
            return True, report

        raw = str(payload).lower()
        score = 0

        # Deteksi semua kategori
        detection_map = [
            (self.signatures.SQLI, "SQLi", 25),
            (self.signatures.XSS, "XSS", 20),
            (self.signatures.RCE, "RCE", 30),
            (self.signatures.LFI, "LFI", 20),
            (self.signatures.SSRF, "SSRF", 20),
            # ========== UPDATE V1.1 ==========
            (self.signatures.LOG4J, "Log4J", 35),  # Skor tinggi!
            (self.signatures.SSTI, "SSTI", 30),
            (self.signatures.GRAPHQL, "GraphQL", 25),
            (self.signatures.OBFUSCATION, "OBFUSCATION", 30),
            (self.signatures.HEADER_INJECT, "HEADER_INJECT", 30)
        ]

        for patterns, name, base_score in detection_map:
            for p in patterns:
                if re.search(p, raw):
                    score += base_score
                    report["triggers"].append(f"{name}: {p}")

        # Deteksi panjang ekstrem
        if len(raw) > 8000:
            score += 15
            report["triggers"].append("PAYLOAD_OVERFLOW")

        # Rate limiting
        now = time.time()
        self.ip_request_count[client_ip].append(now)
        self.ip_request_count[client_ip] = [t for t in self.ip_request_count[client_ip] if now - t < 60]
        if len(self.ip_request_count[client_ip]) > 120:
            score += 20
            report["triggers"].append("RATE_LIMIT")

        # Anomali
        self.anomaly_scores[client_ip] += score // 10
        if self.anomaly_scores[client_ip] > 60:
            self.ip_blacklist.add(client_ip)
            report["triggers"].append("BLACKLISTED")
            score = 100

        report["score"] = min(score, 100)
        if report["score"] >= 25 or client_ip in self.ip_blacklist:
            report["blocked"] = True
            report["action"] = "BLOCK"

        return (not report["blocked"]), report