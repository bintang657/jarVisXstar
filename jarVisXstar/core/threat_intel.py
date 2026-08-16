import requests
import json
import os
from typing import List

class ThreatIntel:
    def __init__(self, cache_file: str = "signature_cache.json"):
        self.cache_file = cache_file
        self.signatures = self._load_cache()
        if not self.signatures:
            self.signatures = [
                "SQLi: select.*from",
                "XSS: <script>",
                "RCE: ; wget",
                "LFI: ../",
                "SSRF: 169.254.169.254"
            ]
            self._save_cache()

    def update(self):
        try:
            urls = [
                "https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules",
                "https://raw.githubusercontent.com/SpiderLabs/owasp-modsecurity-crs/v3.3.4/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"
            ]
            new_sigs = []
            for url in urls:
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code == 200:
                        lines = resp.text.split("\n")
                        for line in lines:
                            if "alert" in line and "sid" in line:
                                new_sigs.append(line[:200])
                except:
                    continue
            if new_sigs:
                self.signatures = list(set(self.signatures + new_sigs))[:500]
                self._save_cache()
        except:
            pass

    def _load_cache(self) -> List[str]:
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r") as f:
                    return json.load(f)
            except:
                return []
        return []

    def _save_cache(self):
        with open(self.cache_file, "w") as f:
            json.dump(self.signatures, f)