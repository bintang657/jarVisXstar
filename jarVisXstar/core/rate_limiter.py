import time
from collections import defaultdict, deque
from threading import Lock

class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_req = max_requests
        self.window = window_seconds
        self.records = defaultdict(deque)
        self.lock = Lock()

    def allow(self, client_ip: str) -> bool:
        with self.lock:
            now = time.time()
            dq = self.records[client_ip]
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if len(dq) < self.max_req:
                dq.append(now)
                return True
            return False