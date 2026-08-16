import requests
import json
import time
from threading import Thread

class GodNotifier:
    def __init__(self, telegram_bot_token=None, telegram_chat_id=None, slack_webhook=None):
        self.telegram_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id
        self.slack_webhook = slack_webhook
        self.queue = []
        self.thread = None
        self.running = False

    def send_alert(self, message, level='info', ip=None, path=None, details=None):
        payload = {
            'message': message,
            'level': level,
            'timestamp': time.time(),
            'ip': ip,
            'path': path,
            'details': details
        }
        self.queue.append(payload)
        if not self.running:
            self._start_worker()

    def _start_worker(self):
        self.running = True
        self.thread = Thread(target=self._worker, daemon=True)
        self.thread.start()

    def _worker(self):
        while self.running and self.queue:
            payload = self.queue.pop(0)
            self._send_telegram(payload)
            self._send_slack(payload)
            time.sleep(1)
        self.running = False

    def _send_telegram(self, payload):
        if not self.telegram_token or not self.telegram_chat_id:
            return
        text = f"🚨 {payload['level'].upper()}: {payload['message']}\nIP: {payload['ip']}\nPath: {payload['path']}\nDetails: {json.dumps(payload['details'], indent=2)}"
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        try:
            requests.post(url, json={'chat_id': self.telegram_chat_id, 'text': text, 'parse_mode': 'HTML'}, timeout=5)
        except:
            pass

    def _send_slack(self, payload):
        if not self.slack_webhook:
            return
        color = {'info': '#36a64f', 'warning': '#ffcc00', 'critical': '#ff0000'}.get(payload['level'], '#808080')
        text = f"*{payload['level'].upper()}*: {payload['message']}\nIP: {payload['ip']}\nPath: {payload['path']}"
        try:
            requests.post(self.slack_webhook, json={'attachments': [{'color': color, 'text': text, 'fields': [{'title': 'Details', 'value': json.dumps(payload['details'], indent=2), 'short': False}]}]}, timeout=5)
        except:
            pass