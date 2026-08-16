import requests
import json
from datetime import datetime

class Notifier:
    def __init__(self, telegram_bot_token: str = None, telegram_chat_id: str = None):
        self.telegram_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id

    def send_alert(self, message: str, ip: str = None, payload: str = None):
        """Kirim alert ke semua channel yang dikonfigurasi"""
        if not self.telegram_token or not self.telegram_chat_id:
            print("[INFO] Telegram not configured, skipping alert.")
            return

        text = f"🚨 *jarVisXstar ALERT* 🚨\nTime: {datetime.utcnow().isoformat()}\n{message}"
        if ip:
            text += f"\nIP: `{ip}`"
        if payload:
            text += f"\nPayload: `{payload[:200]}`"

        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        try:
            requests.post(url, json={"chat_id": self.telegram_chat_id, "text": text, "parse_mode": "Markdown"}, timeout=5)
        except:
            pass