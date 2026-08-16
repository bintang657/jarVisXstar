import requests
import json
import time
import redis
import os
from collections import defaultdict

class GodGeoIP:
    def __init__(self, redis_client=None, use_local_db=False, db_path='/var/lib/GeoIP/GeoLite2-City.mmdb'):
        self.redis = redis_client
        self.use_local_db = use_local_db
        self.db_path = db_path
        self.cache = {}
        self.cache_ttl = 3600
        self.blocked_countries = {'RU', 'CN', 'KP', 'IR', 'SY', 'VN', 'BY', 'CU', 'VE'}

    def _get_ip_info_local(self, ip):
        if not self.use_local_db:
            return None
        try:
            import maxminddb
            reader = maxminddb.open_database(self.db_path)
            data = reader.get(ip)
            reader.close()
            return data
        except:
            return None

    def _get_ip_info_remote(self, ip):
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp,proxy,hosting", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    return data
            return None
        except:
            return None

    def get_ip_info(self, ip):
        cache_key = f"geo:{ip}"
        if self.redis:
            cached = self.redis.get(cache_key)
            if cached:
                return json.loads(cached)
        if ip in self.cache and time.time() - self.cache[ip]['timestamp'] < self.cache_ttl:
            return self.cache[ip]['data']
        data = self._get_ip_info_local(ip) or self._get_ip_info_remote(ip)
        if data:
            info = {'country': data.get('countryCode') or data.get('country', {}).get('iso_code', 'XX'),
                    'isp': data.get('isp', ''),
                    'proxy': data.get('proxy', False),
                    'hosting': data.get('hosting', False)}
            if self.redis:
                self.redis.setex(cache_key, self.cache_ttl, json.dumps(info))
            self.cache[ip] = {'data': info, 'timestamp': time.time()}
            return info
        return None

    def is_blocked(self, ip):
        info = self.get_ip_info(ip)
        if not info:
            return False
        if info.get('country') in self.blocked_countries:
            return True
        if info.get('proxy') or info.get('hosting'):
            return True
        return False