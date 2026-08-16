import json
import time
import random
import redis
from collections import defaultdict

class GodHoneypot:
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.fake_endpoints = [
            '/admin', '/config', '/.env', '/backup', '/wp-admin', '/phpmyadmin',
            '/cpanel', '/webmail', '/mysql', '/db', '/shell', '/cmd', '/exec',
            '/system', '/debug', '/test', '/hidden', '/secret', '/private'
        ]
        self.fake_responses = {
            '/admin': {'status': 403, 'body': 'Access Denied'},
            '/config': {'status': 200, 'body': 'DB_HOST=localhost\nDB_USER=root\nDB_PASS=password123'},
            '/.env': {'status': 200, 'body': 'APP_SECRET=supersecret\nDATABASE_URL=mysql://root:root@localhost/db'},
            '/backup': {'status': 200, 'body': 'Backup file: db_2024.sql.gz (1.2GB)'},
            '/wp-admin': {'status': 302, 'headers': {'Location': 'https://wordpress.com/login'}},
            '/phpmyadmin': {'status': 200, 'body': 'phpMyAdmin 5.1.3 - setup page'},
            '/shell': {'status': 200, 'body': 'sh-4.2$ whoami\nroot\nsh-4.2$'},
        }
        self.tracker = defaultdict(lambda: {'count': 0, 'first_seen': time.time()})

    def is_honeypot(self, path):
        for endpoint in self.fake_endpoints:
            if path.startswith(endpoint) or path == endpoint:
                return True
        return False

    def get_response(self, path):
        base_path = path.split('?')[0]
        for endpoint in self.fake_endpoints:
            if base_path.startswith(endpoint) or base_path == endpoint:
                response = self.fake_responses.get(endpoint, {'status': 404, 'body': 'Not Found'})
                if self.redis:
                    self.redis.incr(f"honeypot_hit:{endpoint}")
                return response
        return {'status': 404, 'body': 'Not Found'}

    def get_hit_stats(self, endpoint=None):
        if self.redis:
            if endpoint:
                count = self.redis.get(f"honeypot_hit:{endpoint}")
                return int(count) if count else 0
            else:
                stats = {}
                for key in self.redis.scan_iter("honeypot_hit:*"):
                    endpoint_name = key.decode().split(':')[1]
                    stats[endpoint_name] = int(self.redis.get(key) or 0)
                return stats
        else:
            if endpoint:
                return self.tracker[endpoint]['count']
            return {k: v['count'] for k, v in self.tracker.items()}

    def increment_hit(self, path):
        base_path = path.split('?')[0]
        for endpoint in self.fake_endpoints:
            if base_path.startswith(endpoint) or base_path == endpoint:
                if self.redis:
                    self.redis.incr(f"honeypot_hit:{endpoint}")
                else:
                    self.tracker[endpoint]['count'] += 1
                break