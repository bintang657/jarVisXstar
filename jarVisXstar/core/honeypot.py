import time
import json
from datetime import datetime
from typing import Dict

class Honeypot:
    def __init__(self, log_file: str = "honeypot_log.json"):
        self.fake_endpoints = [
            "/admin", "/config", "/backup", "/db_dump", "/shell",
            "/.git", "/.env", "/wp-admin", "/phpmyadmin"
        ]
        self.log_file = log_file
        self.captured = []

    def is_honeypot(self, path: str) -> bool:
        return path in self.fake_endpoints

    def capture(self, request_data: Dict):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "path": request_data.get("path"),
            "method": request_data.get("method"),
            "ip": request_data.get("ip"),
            "headers": request_data.get("headers", {}),
            "payload": request_data.get("payload")
        }
        self.captured.append(entry)
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")