import jwt
import time
import hashlib
import redis
from datetime import datetime, timedelta

class GodJWTGuard:
    def __init__(self, secret_key, redis_client=None, algorithm='HS512'):
        self.secret_key = secret_key if len(secret_key) >= 32 else hashlib.sha256(secret_key.encode()).hexdigest()
        self.redis = redis_client
        self.algorithm = algorithm

    def generate_token(self, user_id, payload=None, expires_in=3600):
        if payload is None:
            payload = {}
        payload['user_id'] = user_id
        payload['exp'] = time.time() + expires_in
        payload['iat'] = time.time()
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token

    def verify_token(self, token):
        try:
            decoded = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            if self.redis:
                blacklist_key = f"jwt_blacklist:{token}"
                if self.redis.exists(blacklist_key):
                    return None
            return decoded
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def revoke_token(self, token):
        if self.redis:
            decoded = jwt.decode(token, self.secret_key, algorithms=[self.algorithm], options={'verify_exp': False})
            exp = decoded.get('exp', time.time() + 3600)
            ttl = max(0, int(exp - time.time()))
            self.redis.setex(f"jwt_blacklist:{token}", ttl, 'revoked')

    def refresh_token(self, token):
        decoded = self.verify_token(token)
        if not decoded:
            return None
        user_id = decoded.get('user_id')
        new_payload = {k: v for k, v in decoded.items() if k not in ['exp', 'iat', 'nbf']}
        if self.redis:
            self.revoke_token(token)
        return self.generate_token(user_id, new_payload, expires_in=3600)