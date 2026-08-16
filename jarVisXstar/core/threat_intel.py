import redis
import json
import time
import requests
from collections import defaultdict

class GodThreatIntel:
    def __init__(self, redis_client=None, api_key=None):
        self.redis = redis_client
        self.api_key = api_key
        self.cache = defaultdict(lambda: {'score': 0, 'updated': 0})
        self.cache_ttl = 3600
        self.external_sources = [
            'https://api.abuseipdb.com/api/v2/check',
            'https://api.virustotal.com/v3/ip_addresses/',
        ]

    def get_ip_reputation(self, ip):
        cache_key = f"intel:{ip}"
        if self.redis:
            cached = self.redis.get(cache_key)
            if cached:
                data = json.loads(cached)
                if time.time() - data['updated'] < self.cache_ttl:
                    return data['score']
        if ip in self.cache and time.time() - self.cache[ip]['updated'] < self.cache_ttl:
            return self.cache[ip]['score']
        score = 0.0
        if self.api_key:
            for source in self.external_sources:
                try:
                    if 'abuseipdb' in source:
                        headers = {'Key': self.api_key, 'Accept': 'application/json'}
                        resp = requests.get(f"{source}?ipAddress={ip}", headers=headers, timeout=5)
                        if resp.status_code == 200:
                            data = resp.json()
                            score = max(score, data.get('data', {}).get('abuseConfidenceScore', 0) / 100.0)
                    elif 'virustotal' in source:
                        headers = {'x-apikey': self.api_key}
                        resp = requests.get(f"{source}{ip}", headers=headers, timeout=5)
                        if resp.status_code == 200:
                            data = resp.json()
                            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                            malicious = stats.get('malicious', 0)
                            total = sum(stats.values()) or 1
                            score = max(score, malicious / total)
                except:
                    pass
        if self.redis:
            self.redis.setex(cache_key, self.cache_ttl, json.dumps({'score': score, 'updated': time.time()}))
        self.cache[ip] = {'score': score, 'updated': time.time()}
        return score

    def get_blocklist(self):
        if self.redis:
            blocklist = self.redis.smembers("global_blocklist")
            return [ip.decode() for ip in blocklist]
        return []

    def add_to_blocklist(self, ip, reason='manual'):
        if self.redis:
            self.redis.sadd("global_blocklist", ip)
            self.redis.setex(f"block_reason:{ip}", 86400, reason)

    def remove_from_blocklist(self, ip):
        if self.redis:
            self.redis.srem("global_blocklist", ip)
            self.redis.delete(f"block_reason:{ip}")