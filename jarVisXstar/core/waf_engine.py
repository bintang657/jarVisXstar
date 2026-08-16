import re
import time
import hashlib
import json
import base64
import urllib.parse
import zlib
from collections import defaultdict, deque
from typing import Dict, Any, Tuple, List, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

class ThreatSignature:
    SQLI = [
        r"(?i)(\bSELECT\b.*\bFROM\b)",
        r"(?i)(\bSELECT\b.*\bFROM\b.*\bWHERE\b)",
        r"(?i)(\bUNION\b.*\bSELECT\b)",
        r"(?i)(\bINSERT\b.*\bINTO\b)",
        r"(?i)(\bDELETE\b.*\bFROM\b)",
        r"(?i)(\bDROP\b.*\bTABLE\b)",
        r"(?i)(\bEXEC\b.*\bXP_\w+)",
        r"(?i)('.*\bOR\b.*'.*'.*')",
        r"(?i)(\bSLEEP\b\s*\()",
        r"(?i)(''\s*OR\s*[0-9]+=[0-9]+)",
        r"(?i)(''\s*AND\s*[0-9]+=[0-9]+)",
        r"(?i)(--\s*$)"
    ]
    XSS = [
        r"<script.*?>.*?</script>", r"(?i)javascript\s*:",
        r"(?i)on\w+\s*=", r"<iframe.*?>", r"<img.*?onerror=",
        r"<svg.*?onload=", r"(?i)eval\s*\(.*?\)", r"alert\s*\("
    ]
    RCE = [
        r"(?i);\s*(wget|curl|bash|sh|python|nc|rm|chmod|whoami|id)",
        r"\$\{.*?\}", r"`.*?`", r"(?i)\|\s*sh", r"(?i)&\s*whoami",
        r"(?i)system\s*\(", r"(?i)popen\s*\(", r"(?i)exec\s*\("
    ]
    LFI = [r"\.\./\.\./", r"/etc/passwd", r"/var/log/", r"php://filter", r"file://"]
    SSRF = [r"http://169.254.169.254", r"http://metadata.google", r"http://127.0.0.1"]
    LOG4J = [
        r"(?i)\$\{jndi\s*[:=]\s*(ldap|rmi|dns)://", r"\$\{env\:.*?\}", r"\$\{sys\:.*?\}"
    ]
    SSTI = [r"\{\{.*?\}\}", r"\{\%.*?\%\}", r"\$\{.*?\}"]
    GRAPHQL = [r"(?i)__typename", r"(?i)__schema", r"\{\s*__typename\s*\{"]
    HEADER_INJECT = [r"\%0d\%0a", r"\%0a\%0d", r"\r\n"]

class WAFEngine:
    def __init__(self, config: Optional[Dict] = None):
        self.signatures = ThreatSignature()
        self.ip_blacklist = set()
        self.ip_request_count = defaultdict(deque)
        self.ip_behavior = defaultdict(lambda: {'scanning': 0, 'bruteforce': 0, 'slow_attack': 0})
        self.anomaly_scores = defaultdict(int)
        self.total_blocks = 0
        self.config = config or {}
        self.threshold = self.config.get('threshold', 25)
        self.adaptive = self.config.get('adaptive_threshold', True)
        self.webhook_url = self.config.get('webhook_url', None)
        self.redis = None
        self.redis_enabled = False
        self._ip_paths = defaultdict(lambda: deque(maxlen=50))
        if 'redis_host' in self.config:
            try:
                import redis
                self.redis = redis.Redis(
                    host=self.config['redis_host'],
                    port=self.config.get('redis_port', 6379),
                    decode_responses=True,
                    socket_timeout=1
                )
                self.redis.ping()
                self.redis_enabled = True
                self._sync_blacklist()
            except:
                print("[WARN] Redis tidak tersedia, blacklist sharing dinonaktifkan.")

    def _sync_blacklist(self):
        if self.redis_enabled:
            keys = self.redis.keys("waf:blacklist:*")
            for key in keys:
                ip = key.split(":")[-1]
                self.ip_blacklist.add(ip)

    def _share_blacklist(self, ip: str):
        if self.redis_enabled:
            self.redis.setex(f"waf:blacklist:{ip}", 3600, "blocked")

    def _decode_payload(self, raw: str) -> str:
        decoded = raw
        try:
            decoded = urllib.parse.unquote_plus(decoded)
        except:
            pass
        try:
            decoded_base64 = base64.b64decode(decoded, validate=True).decode('utf-8', errors='ignore')
            if decoded_base64:
                decoded = decoded_base64
        except:
            pass
        try:
            if re.match(r'^[0-9a-fA-F]+$', decoded):
                decoded_hex = bytes.fromhex(decoded).decode('utf-8', errors='ignore')
                if decoded_hex:
                    decoded = decoded_hex
        except:
            pass
        try:
            if decoded.startswith('\x1f\x8b'):
                decoded_gzip = zlib.decompress(decoded.encode(), 16+zlib.MAX_WBITS).decode('utf-8', errors='ignore')
                if decoded_gzip:
                    decoded = decoded_gzip
        except:
            pass
        return decoded

    def _behavioral_analysis(self, ip: str, method: str, path: str, status: int):
        self._ip_paths[ip].append((time.time(), path))
        recent = [p for t, p in self._ip_paths[ip] if time.time() - t < 10]
        if len(set(recent)) > 15:
            self.ip_behavior[ip]['scanning'] += 1
        if status >= 400:
            self.ip_behavior[ip]['bruteforce'] += 1
            if self.ip_behavior[ip]['bruteforce'] > 10:
                self.ip_behavior[ip]['bruteforce'] = 10
        if 'sleep' in str(path).lower() or 'delay' in str(path).lower():
            self.ip_behavior[ip]['slow_attack'] += 1

    def inspect(self, payload: Any, client_ip: str, method: str = 'GET', path: str = '/', headers: Optional[Dict] = None) -> Tuple[bool, Dict]:
        report = {
            "blocked": False,
            "score": 0,
            "triggers": [],
            "action": "ALLOW",
            "behavior": {},
            "decoded_payload": None,
            "honeypot_triggered": False,
            "honeypot_response": None
        }

        honeypot_paths = ['/admin', '/config', '/backup', '/.env', '/wp-admin', '/phpmyadmin']
        if path in honeypot_paths:
            report['honeypot_triggered'] = True
            report['honeypot_response'] = self._generate_honeypot_response()
            self.total_blocks += 1

        if not payload:
            return True, report

        raw = str(payload)
        decoded = self._decode_payload(raw)
        report['decoded_payload'] = decoded[:500]

        score = 0
        to_check = decoded.lower()

        detection_map = [
            (self.signatures.SQLI, "SQLi", 25),
            (self.signatures.XSS, "XSS", 20),
            (self.signatures.RCE, "RCE", 30),
            (self.signatures.LFI, "LFI", 20),
            (self.signatures.SSRF, "SSRF", 20),
            (self.signatures.LOG4J, "Log4J", 35),
            (self.signatures.SSTI, "SSTI", 30),
            (self.signatures.GRAPHQL, "GraphQL", 25),
            (self.signatures.HEADER_INJECT, "HEADER_INJECT", 30)
        ]
        for patterns, name, base_score in detection_map:
            for pattern in patterns:
                if re.search(pattern, to_check):
                    score += base_score
                    report["triggers"].append(f"{name}: {pattern}")

        if raw != decoded and len(raw) > len(decoded) * 1.5:
            score += 20
            report["triggers"].append("HEAVY_OBFUSCATION")

        if len(raw) > 8000:
            score += 15
            report["triggers"].append("PAYLOAD_OVERFLOW")

        now = time.time()
        self.ip_request_count[client_ip].append(now)
        self.ip_request_count[client_ip] = deque([t for t in self.ip_request_count[client_ip] if now - t < 60], maxlen=200)
        req_count = len(self.ip_request_count[client_ip])
        if self.ip_behavior[client_ip]['scanning'] >= 5 or self.ip_behavior[client_ip]['bruteforce'] >= 5:
            limit = 30
        elif self.ip_behavior[client_ip]['slow_attack'] >= 2:
            limit = 10
        else:
            limit = 100
        if req_count > limit:
            score += 20
            report["triggers"].append(f"RATE_LIMIT_DYNAMIC (limit={limit})")

        behavior_score = 0
        if self.ip_behavior[client_ip]['scanning'] > 2:
            behavior_score += 10
        if self.ip_behavior[client_ip]['bruteforce'] > 3:
            behavior_score += 15
        if self.ip_behavior[client_ip]['slow_attack'] > 1:
            behavior_score += 20
        if behavior_score > 0:
            score += behavior_score
            report["behavior"] = dict(self.ip_behavior[client_ip])

        self.anomaly_scores[client_ip] += score // 10
        if self.anomaly_scores[client_ip] > 60:
            self.ip_blacklist.add(client_ip)
            self._share_blacklist(client_ip)
            report["triggers"].append("BLACKLISTED_GLOBAL")
            score = 100

        effective_threshold = self.threshold
        if self.adaptive and client_ip in self.ip_blacklist:
            effective_threshold = 15

        report["score"] = min(score, 100)

        if report["score"] >= effective_threshold or client_ip in self.ip_blacklist:
            report["blocked"] = True
            report["action"] = "BLOCK"
            self.total_blocks += 1
            if report["score"] >= 80:
                self.ip_blacklist.add(client_ip)
                self._share_blacklist(client_ip)
                report["triggers"].append("PERMABLOCK")
            if self.webhook_url and REQUESTS_AVAILABLE and self.total_blocks % 5 == 0:
                self._send_webhook(client_ip, report)

        status = 403 if report["blocked"] else 200
        self._behavioral_analysis(client_ip, method, path, status)

        return (not report["blocked"]), report

    def _generate_honeypot_response(self) -> Dict:
        response_type = self.config.get('honeypot_response_type', 'fake_admin')
        if response_type == 'fake_admin':
            return {
                'status': 200,
                'headers': {'Content-Type': 'text/html'},
                'body': '<html><head><title>Admin Panel</title></head><body><h1>Welcome Admin</h1><p>Database: mysql://localhost:3306/root:pass123</p></body></html>'
            }
        elif response_type == 'fake_error':
            return {
                'status': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Internal Server Error', 'trace': 'SQL syntax error near "UNION SELECT"'})
            }
        elif response_type == 'fake_db':
            return {
                'status': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'users': [{'username': 'admin', 'password': 'admin123'}, {'username': 'root', 'password': 'toor'}]})
            }
        return {'status': 403, 'headers': {}, 'body': 'Forbidden'}

    def _send_webhook(self, ip: str, report: Dict):
        try:
            if not REQUESTS_AVAILABLE:
                return
            payload = {
                'ip': ip,
                'timestamp': time.time(),
                'score': report['score'],
                'triggers': report['triggers'],
                'total_blocks': self.total_blocks
            }
            requests.post(self.webhook_url, json=payload, timeout=2)
        except:
            pass

    def get_stats(self) -> Dict:
        return {
            'total_blocks': self.total_blocks,
            'blacklist_size': len(self.ip_blacklist),
            'anomaly_scores': dict(self.anomaly_scores),
            'ip_behavior': dict(self.ip_behavior)
        }