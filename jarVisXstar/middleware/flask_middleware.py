from flask import request, g, jsonify, abort
import time
import json
from jarVisXstar.core.waf_engine import GodWAFEngine
from jarVisXstar.core.rate_limiter import GodRateLimiter
from jarVisXstar.core.sanitizer import GodSanitizer
from jarVisXstar.core.geoip import GodGeoIP
from jarVisXstar.core.honeypot import GodHoneypot
from jarVisXstar.core.notifier import GodNotifier
from jarVisXstar.core.threat_intel import GodThreatIntel

class GodFlaskMiddleware:
    def __init__(self, app=None, redis_client=None, secret_key=None, telegram_token=None, telegram_chat_id=None):
        self.app = app
        self.waf = GodWAFEngine(redis_client)
        self.rate_limiter = GodRateLimiter(redis_client)
        self.sanitizer = GodSanitizer()
        self.geo = GodGeoIP(redis_client)
        self.honeypot = GodHoneypot(redis_client)
        self.notifier = GodNotifier(telegram_token, telegram_chat_id)
        self.threat = GodThreatIntel(redis_client)
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        app.errorhandler(403)(self.forbidden_handler)

    def before_request(self):
        ip = request.remote_addr
        path = request.path
        method = request.method
        headers = dict(request.headers)
        user_agent = request.headers.get('User-Agent', '')
        query = request.query_string.decode('utf-8')
        body = request.get_data(as_text=True) or request.form.to_dict() or {}
        if isinstance(body, dict):
            body = json.dumps(body)
        req_data = {
            'ip': ip,
            'path': path,
            'query': query,
            'body': body,
            'headers': headers,
            'user_agent': user_agent,
            'method': method
        }
        if self.geo.is_blocked(ip):
            self.notifier.send_alert(f"Geo-blocked IP {ip}", 'critical', ip, path)
            abort(403)
        if self.honeypot.is_honeypot(path):
            self.honeypot.increment_hit(path)
            self.notifier.send_alert(f"Honeypot hit from {ip} on {path}", 'critical', ip, path)
            abort(403)
        if not self.rate_limiter.is_allowed(f"rate:{ip}"):
            self.notifier.send_alert(f"Rate limit exceeded for {ip}", 'warning', ip, path)
            abort(429)
        prediction = self.waf.predict(req_data)
        if prediction['blocked']:
            self.threat.add_to_blocklist(ip, reason=f"WAF: {','.join(prediction['matched_rules'])}")
            self.notifier.send_alert(f"WAF blocked request from {ip} on {path}", 'critical', ip, path, prediction)
            abort(403)
        g.clean_args = self.sanitizer.xss_deep_clean(query)
        g.clean_form = {k: self.sanitizer.xss_deep_clean(v) for k, v in (request.form or {}).items()}
        try:
            g.clean_json = {k: self.sanitizer.xss_deep_clean(str(v)) for k, v in (request.get_json() or {}).items()}
        except:
            g.clean_json = {}
        g.waf_prediction = prediction

    def after_request(self, response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return response

    def forbidden_handler(self, e):
        return jsonify({'error': 'Access denied'}), 403