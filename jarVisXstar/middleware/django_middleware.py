from django.http import JsonResponse
from django.core.exceptions import PermissionDenied
import json
from jarVisXstar.core.waf_engine import GodWAFEngine
from jarVisXstar.core.rate_limiter import GodRateLimiter
from jarVisXstar.core.sanitizer import GodSanitizer
from jarVisXstar.core.geoip import GodGeoIP
from jarVisXstar.core.honeypot import GodHoneypot
from jarVisXstar.core.notifier import GodNotifier
from jarVisXstar.core.threat_intel import GodThreatIntel

class GodDjangoMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.waf = GodWAFEngine(None)
        self.rate_limiter = GodRateLimiter(None)
        self.sanitizer = GodSanitizer()
        self.geo = GodGeoIP(None)
        self.honeypot = GodHoneypot(None)
        self.notifier = GodNotifier()
        self.threat = GodThreatIntel(None)

    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        path = request.path
        method = request.method
        headers = {k: v for k, v in request.META.items() if k.startswith('HTTP_')}
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        query = request.GET.urlencode()
        body = request.body.decode('utf-8') or json.dumps(request.POST.dict()) or ''
        req_data = {'ip': ip, 'path': path, 'query': query, 'body': body, 'headers': headers, 'user_agent': user_agent, 'method': method}
        if self.geo.is_blocked(ip):
            self.notifier.send_alert(f"Geo-blocked IP {ip}", 'critical', ip, path)
            raise PermissionDenied
        if self.honeypot.is_honeypot(path):
            self.honeypot.increment_hit(path)
            self.notifier.send_alert(f"Honeypot hit from {ip} on {path}", 'critical', ip, path)
            raise PermissionDenied
        if not self.rate_limiter.is_allowed(f"rate:{ip}"):
            self.notifier.send_alert(f"Rate limit exceeded for {ip}", 'warning', ip, path)
            raise PermissionDenied
        prediction = self.waf.predict(req_data)
        if prediction['blocked']:
            self.threat.add_to_blocklist(ip, reason=f"WAF: {','.join(prediction['matched_rules'])}")
            self.notifier.send_alert(f"WAF blocked request from {ip} on {path}", 'critical', ip, path, prediction)
            raise PermissionDenied
        request.clean_args = self.sanitizer.xss_deep_clean(query)
        request.clean_form = {k: self.sanitizer.xss_deep_clean(v) for k, v in request.POST.items()}
        try:
            request.clean_json = {k: self.sanitizer.xss_deep_clean(str(v)) for k, v in json.loads(request.body).items()}
        except:
            request.clean_json = {}
        request.waf_prediction = prediction
        response = self.get_response(request)
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return response