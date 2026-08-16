from fastapi import Request, Response
from fastapi.responses import JSONResponse
import json
from jarVisXstar.core.waf_engine import GodWAFEngine
from jarVisXstar.core.rate_limiter import GodRateLimiter
from jarVisXstar.core.sanitizer import GodSanitizer
from jarVisXstar.core.geoip import GodGeoIP
from jarVisXstar.core.honeypot import GodHoneypot
from jarVisXstar.core.notifier import GodNotifier
from jarVisXstar.core.threat_intel import GodThreatIntel

class GodFastAPIMiddleware:
    def __init__(self):
        self.waf = GodWAFEngine(None)
        self.rate_limiter = GodRateLimiter(None)
        self.sanitizer = GodSanitizer()
        self.geo = GodGeoIP(None)
        self.honeypot = GodHoneypot(None)
        self.notifier = GodNotifier()
        self.threat = GodThreatIntel(None)

    async def __call__(self, request: Request, call_next):
        ip = request.client.host if request.client else '0.0.0.0'
        path = request.url.path
        query = str(request.query_params)
        body = await request.body()
        body_str = body.decode('utf-8') if body else ''
        headers = dict(request.headers)
        user_agent = headers.get('user-agent', '')
        method = request.method
        req_data = {'ip': ip, 'path': path, 'query': query, 'body': body_str, 'headers': headers, 'user_agent': user_agent, 'method': method}
        if self.geo.is_blocked(ip):
            self.notifier.send_alert(f"Geo-blocked IP {ip}", 'critical', ip, path)
            return JSONResponse({'error': 'Access denied'}, status_code=403)
        if self.honeypot.is_honeypot(path):
            self.honeypot.increment_hit(path)
            self.notifier.send_alert(f"Honeypot hit from {ip} on {path}", 'critical', ip, path)
            return JSONResponse({'error': 'Access denied'}, status_code=403)
        if not self.rate_limiter.is_allowed(f"rate:{ip}"):
            self.notifier.send_alert(f"Rate limit exceeded for {ip}", 'warning', ip, path)
            return JSONResponse({'error': 'Too many requests'}, status_code=429)
        prediction = self.waf.predict(req_data)
        if prediction['blocked']:
            self.threat.add_to_blocklist(ip, reason=f"WAF: {','.join(prediction['matched_rules'])}")
            self.notifier.send_alert(f"WAF blocked request from {ip} on {path}", 'critical', ip, path, prediction)
            return JSONResponse({'error': 'Access denied'}, status_code=403)
        request.state.clean_args = self.sanitizer.xss_deep_clean(query)
        request.state.clean_form = {}
        try:
            json_data = await request.json()
            request.state.clean_json = {k: self.sanitizer.xss_deep_clean(str(v)) for k, v in json_data.items()}
        except:
            request.state.clean_json = {}
        request.state.waf_prediction = prediction
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return response