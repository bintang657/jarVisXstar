import time
import redis
import hashlib
from collections import defaultdict
import threading

class GodRateLimiter:
    def __init__(self, redis_client=None, default_limit=100, default_window=60):
        self.redis = redis_client
        self.default_limit = default_limit
        self.default_window = default_window
        self.local_cache = defaultdict(list)
        self.lock = threading.Lock()

    def is_allowed(self, key, limit=None, window=None):
        limit = limit or self.default_limit
        window = window or self.default_window
        now = time.time()
        if self.redis:
            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(key, 0, now - window)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, window + 10)
            results = pipe.execute()
            count = results[2]
            if count <= limit:
                return True
            return False
        else:
            with self.lock:
                timestamps = self.local_cache[key]
                timestamps = [t for t in timestamps if t > now - window]
                if len(timestamps) < limit:
                    timestamps.append(now)
                    self.local_cache[key] = timestamps
                    return True
                return False

    def get_remaining(self, key, limit=None, window=None):
        limit = limit or self.default_limit
        window = window or self.default_window
        now = time.time()
        if self.redis:
            count = self.redis.zcount(key, now - window, now)
            return max(0, limit - count)
        else:
            with self.lock:
                timestamps = self.local_cache.get(key, [])
                timestamps = [t for t in timestamps if t > now - window]
                return max(0, limit - len(timestamps))

    def reset(self, key):
        if self.redis:
            self.redis.delete(key)
        else:
            with self.lock:
                if key in self.local_cache:
                    del self.local_cache[key]