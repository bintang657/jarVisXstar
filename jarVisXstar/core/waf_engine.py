import re
import json
import numpy as np
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import redis

class GodWAFEngine:
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.model = IsolationForest(contamination=0.01, random_state=42)
        self.scaler = StandardScaler()
        self.feature_cache = defaultdict(lambda: defaultdict(int))
        self.is_trained = False
        self.signatures = self._load_god_signatures()
        self.obfuscation_patterns = self._compile_deep_regex()

    def _load_god_signatures(self):
        return {
            'sqli': re.compile(r'(union\s+select|select\s+.*\s+from|sleep\(|benchmark\(|0x[0-9a-f]+|into\s+(outfile|dumpfile)|load_file)', re.I),
            'xss': re.compile(r'(<script|javascript:|on\w+\s*=|alert\(|prompt\(|confirm\(|eval\(|document\.|window\.|location\.)', re.I),
            'rce': re.compile(r'(system\(|exec\(|passthru\(|shell_exec\(|popen\(|proc_open\(|`[^`]+`|\$\(\(|\|{2}|&&|;\s*\w+\s*\()', re.I),
            'lfi': re.compile(r'(\.\./|\.\.\\|/etc/passwd|/proc/self/environ|/var/log|boot\.ini|C:\\\\)', re.I),
            'ssrf': re.compile(r'(http://169.254|http://127\.0\.0|http://localhost|http://10\.|http://172\.16|http://192\.168|gopher://|dict://|file://)', re.I),
            'log4j': re.compile(r'\$\{jndi:(ldap|rmi|dns)://[^}]+}', re.I),
            'ssti': re.compile(r'(\{\{.*\}\}|<%.*%>|\${.*}|{{.*}}|\{\%.*\%\})'),
            'graphql': re.compile(r'(__typename|__schema|__type|query\s*\{|mutation\s*\{)'),
            'header_inject': re.compile(r'(\r\n|%0a|%0d|\\r\\n)'),
        }

    def _compile_deep_regex(self):
        return {
            'url_encoded': re.compile(r'(%[0-9a-f]{2})', re.I),
            'double_encoded': re.compile(r'(%25[0-9a-f]{2})', re.I),
            'unicode_encoded': re.compile(r'(\\u[0-9a-f]{4})', re.I),
            'hex_encoded': re.compile(r'(0x[0-9a-f]+)', re.I),
            'base64': re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$'),
            'gzip': re.compile(b'\x1f\x8b'),
        }

    def deep_decode(self, payload):
        decoded = payload
        for _ in range(3):
            try:
                decoded = re.sub(self.obfuscation_patterns['url_encoded'], lambda m: bytes.fromhex(m.group(1)[1:]).decode('utf-8'), decoded)
            except:
                break
        try:
            if '0x' in decoded:
                hex_parts = re.findall(r'0x([0-9a-f]{2})', decoded)
                if hex_parts:
                    decoded = bytes.fromhex(''.join(hex_parts)).decode('utf-8', errors='ignore')
        except:
            pass
        if re.match(r'^[A-Za-z0-9+/]{10,}={0,2}$', decoded):
            try:
                decoded = __import__('base64').b64decode(decoded).decode('utf-8', errors='ignore')
            except:
                pass
        if b'\x1f\x8b' in decoded.encode():
            try:
                import gzip
                decoded = gzip.decompress(decoded.encode()).decode('utf-8', errors='ignore')
            except:
                pass
        return decoded

    def extract_features(self, request):
        features = {}
        path = request.get('path', '')
        query = request.get('query', '')
        body = request.get('body', '')
        headers = json.dumps(request.get('headers', {}))
        ip = request.get('ip', '')
        user_agent = request.get('user_agent', '')
        combined = f"{path} {query} {body} {headers}"
        decoded = self.deep_decode(combined)
        features['length'] = len(combined)
        features['entropy'] = self._shannon_entropy(combined)
        features['num_special'] = sum(1 for c in combined if not c.isalnum() and not c.isspace())
        features['num_digits'] = sum(1 for c in combined if c.isdigit())
        features['num_uppercase'] = sum(1 for c in combined if c.isupper())
        features['num_path_segments'] = path.count('/')
        features['num_query_params'] = query.count('&') + 1 if query else 0
        features['has_sql_keywords'] = 1 if any(k in combined.lower() for k in ['select', 'union', 'where', 'from', 'insert', 'update', 'delete', 'drop', 'exec']) else 0
        features['has_xss_keywords'] = 1 if any(k in combined.lower() for k in ['script', 'javascript', 'onerror', 'alert', 'prompt', 'confirm', 'eval']) else 0
        features['has_rce_keywords'] = 1 if any(k in combined for k in ['$', '`', '|', '&', ';', 'system', 'exec', 'passthru']) else 0
        features['ip_reputation'] = self._get_ip_reputation(ip)
        features['ua_known_bot'] = 1 if any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider', 'scanner', 'nmap', 'sqlmap']) else 0
        features['request_rate'] = self._get_request_rate(ip)
        return features

    def _shannon_entropy(self, data):
        if not data:
            return 0
        prob = [float(data.count(c)) / len(data) for c in set(data)]
        return -sum(p * __import__('math').log2(p) for p in prob)

    def _get_ip_reputation(self, ip):
        if self.redis:
            rep = self.redis.get(f"rep:{ip}")
            if rep:
                return float(rep)
        return 0.0

    def _get_request_rate(self, ip):
        if self.redis:
            key = f"rate:{ip}"
            count = self.redis.incr(key)
            if count == 1:
                self.redis.expire(key, 10)
            return count / 10.0
        return 0.0

    def train_anomaly_model(self, historical_requests):
        feature_vectors = []
        for req in historical_requests:
            feat = self.extract_features(req)
            feature_vectors.append([feat[k] for k in sorted(feat.keys())])
        if len(feature_vectors) > 100:
            X = np.array(feature_vectors, dtype=np.float32)
            X_scaled = self.scaler.fit_transform(X)
            self.model.fit(X_scaled)
            self.is_trained = True

    def predict(self, request):
        features = self.extract_features(request)
        vec = np.array([[features[k] for k in sorted(features.keys())]], dtype=np.float32)
        if self.is_trained:
            vec_scaled = self.scaler.transform(vec)
            anomaly_score = self.model.decision_function(vec_scaled)[0]
            is_anomaly = self.model.predict(vec_scaled)[0] == -1
        else:
            anomaly_score = 0.0
            is_anomaly = False
        combined = f"{request.get('path','')} {request.get('query','')} {request.get('body','')} {json.dumps(request.get('headers',{}))}"
        decoded = self.deep_decode(combined)
        max_risk = 0
        matched_rules = []
        for name, pattern in self.signatures.items():
            if pattern.search(decoded):
                risk = 0.8 if name in ['sqli', 'rce', 'ssrf', 'log4j'] else 0.6
                max_risk = max(max_risk, risk)
                matched_rules.append(name)
        behavioral_score = min(1.0, features['request_rate'] / 5.0 + features['ip_reputation'])
        final_risk = max(max_risk, abs(anomaly_score) if anomaly_score < 0 else 0.0, behavioral_score)
        final_risk = min(1.0, final_risk)
        return {
            'blocked': final_risk > 0.75,
            'risk_score': final_risk,
            'matched_rules': matched_rules,
            'anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'decoded_payload': decoded[:200],
            'features': features
        }