from flask import request, jsonify, g
from jarVisXstar.core.waf_engine import WAFEngine
from jarVisXstar.core.sanitizer import SuperSanitizer
from jarVisXstar.core.rate_limiter import SlidingWindowRateLimiter

class JarVisXstarFlask:
    def __init__(self, app=None):
        self.waf = WAFEngine()
        self.rate = SlidingWindowRateLimiter()
        if app:
            self.init_app(app)

    def init_app(self, app):
        app.before_request(self._before)
        app.after_request(self._after)

    def _before(self):
        ip = request.remote_addr
        if not self.rate.allow(ip):
            return jsonify({"error": "Rate limit", "code": 429}), 429

        all_input = {
            "args": dict(request.args),
            "form": dict(request.form),
            "json": request.get_json(silent=True) or {},
            "cookies": dict(request.cookies),
            "headers": dict(request.headers)
        }
        safe, report = self.waf.inspect(all_input, ip)
        if not safe:
            return jsonify({"error": "Blocked by WAF", "triggers": report["triggers"], "score": report["score"]}), 403

        g.clean_args = SuperSanitizer.xss_clean(dict(request.args))
        g.clean_form = SuperSanitizer.xss_clean(dict(request.form))
        g.clean_json = SuperSanitizer.xss_clean(request.get_json(silent=True) or {})

    def _after(self, response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response