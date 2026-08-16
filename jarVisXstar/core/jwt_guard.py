import jwt
import time
import hashlib
import os
from datetime import datetime, timedelta
from typing import Optional, Dict

class JWTGuard:
    def __init__(self, secret_key: str, redis_host: str = 'localhost', redis_port: int = 6379):
        if len(secret_key) < 32:
            secret_key = hashlib.sha256(secret_key.encode()).hexdigest()
        self.secret = secret_key
        self.redis_enabled = False
        self.redis = None
        try:
            import redis
            self.redis = redis.Redis(host=redis_host, port=redis_port, decode_responses=True, socket_timeout=1)
            self.redis.ping()
            self.redis_enabled = True
        except:
            pass
        self.blacklist_prefix = "jvx:bl:"

    def generate(self, user_id: str, extra: Optional[Dict] = None) -> str:
        payload = {
            "sub": user_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1),
            "jti": self._jti(user_id),
            "iss": "jarVisXstar"
        }
        if extra:
            payload.update(extra)
        return jwt.encode(payload, self.secret, algorithm="HS512")

    def verify(self, token: str) -> Optional[Dict]:
        try:
            payload = jwt.decode(token, self.secret, algorithms=["HS512"], issuer="jarVisXstar")
            if self.redis_enabled and self.redis:
                jti = payload.get("jti")
                if self.redis.exists(f"{self.blacklist_prefix}{jti}"):
                    return None
            return payload
        except:
            return None

    def revoke(self, token: str):
        if not self.redis_enabled:
            return
        try:
            payload = jwt.decode(token, self.secret, algorithms=["HS512"], options={"verify_exp": False})
            jti = payload.get("jti")
            exp = payload.get("exp")
            if exp and jti:
                ttl = max(int(exp) - int(time.time()), 1)
                self.redis.setex(f"{self.blacklist_prefix}{jti}", ttl, "revoked")
        except:
            pass

    def _jti(self, user_id: str) -> str:
        return hashlib.sha256(f"{user_id}{time.time()}{os.urandom(16)}".encode()).hexdigest()