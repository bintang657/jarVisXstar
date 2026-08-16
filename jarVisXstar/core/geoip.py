import requests
import json
import time
from typing import Dict, Optional, List

class GeoIPBlocker:
    def __init__(self, blocked_countries: List[str] = None, cache_ttl: int = 3600):
        self.blocked_countries = blocked_countries or ["RU", "CN", "KP", "IR", "SY"]
        self.cache = {}
        self.cache_ttl = cache_ttl
        self.api_url = "http://ip-api.com/json/"

    def get_country(self, ip: str) -> Optional[str]:
        """Cek negara dari IP, dengan cache"""
        if ip in self.cache:
            data, timestamp = self.cache[ip]
            if time.time() - timestamp < self.cache_ttl:
                return data.get("countryCode")
            else:
                del self.cache[ip]
        try:
            resp = requests.get(f"{self.api_url}{ip}", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    self.cache[ip] = (data, time.time())
                    return data.get("countryCode")
        except:
            pass
        return None

    def should_block(self, ip: str) -> tuple[bool, str]:
        """Returns (is_blocked, country_code)"""
        country = self.get_country(ip)
        if country and country in self.blocked_countries:
            return True, country
        return False, country