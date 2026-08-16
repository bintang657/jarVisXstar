import json
import time
from datetime import datetime

class JSONLogger:
    @staticmethod
    def log(level: str, message: str, extra: dict = None):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            "extra": extra or {}
        }
        print(json.dumps(entry))