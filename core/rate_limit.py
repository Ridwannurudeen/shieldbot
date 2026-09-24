"""Per-caller rate limiters for the API's routes and the RPC proxy."""

import random
import time
from collections import defaultdict
from typing import Dict


class RateLimiter:
    """In-memory sliding window rate limiter per IP."""

    def __init__(self, requests_per_minute: int = 30, burst: int = 10):
        self.rpm = requests_per_minute
        self.burst = burst
        self.window = 60.0  # seconds
        self._hits: Dict[str, list] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]

        # Prune expired entries
        cutoff = now - self.window
        while hits and hits[0] < cutoff:
            hits.pop(0)

        if len(hits) >= self.rpm:
            return False

        # Burst check: no more than `burst` requests in 5 seconds
        burst_cutoff = now - 5.0
        recent = sum(1 for t in hits if t >= burst_cutoff)
        if recent >= self.burst:
            return False

        hits.append(now)

        # Probabilistic cleanup to prevent unbounded memory growth
        if random.random() < 0.01:
            self.cleanup()

        return True

    def cleanup(self):
        """Remove stale IPs (call periodically if needed)."""
        now = time.monotonic()
        cutoff = now - self.window * 2
        stale = [k for k, v in self._hits.items() if not v or v[-1] < cutoff]
        for k in stale:
            del self._hits[k]
