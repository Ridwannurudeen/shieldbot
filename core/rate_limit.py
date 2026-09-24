"""Per-caller rate limiters for the API's routes and the RPC proxy.

Each limiter keeps a sliding window of hits per caller, in process memory by default. With
RATE_LIMIT_BACKEND=redis the API's lifespan moves every limiter to Redis (use_redis), so every API
process shares one count per caller and a restart forgets nothing:

- A limiter keeps each caller's hits in a sorted set at shieldbot:ratelimit:<limiter>:<caller>,
  scored by the time of the hit, and every write renews the key's TTL to the window, so an idle
  caller's key expires.
- A check is one MULTI/EXEC transaction: drop the hits older than the window, add this one, count
  the window and the burst window. A hit over the limit is then taken back out, so, as in memory,
  only allowed requests count. Two checks racing for the last slot can both be refused, never both
  allowed.
- Hit times come from the host clock (time.time()): monotonic clocks are not comparable between
  processes on different hosts.

When Redis cannot answer (the client gives up after TIMEOUT_SECONDS), a limiter bound with
fail_open=True counts the request in this process's memory instead, as with the memory backend, so
a Redis outage neither takes the scan API down nor lifts its limits; any other limiter refuses the
request. Both log an error. api.py's lifespan sets the policy of each limiter.
"""

import logging
import math
import random
import time
import uuid
from collections import defaultdict
from typing import Dict, NamedTuple, Optional

import redis.asyncio as aioredis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

KEY_PREFIX = "shieldbot:ratelimit:"
# Seconds the client waits to connect or for a reply. A Redis slower than this counts as down: the
# request falls to its limiter's failure policy instead of waiting.
TIMEOUT_SECONDS = 0.5
# RateLimiter allows at most `burst` hits in this many seconds.
BURST_SECONDS = 5.0


def connect(redis_url: str) -> aioredis.Redis:
    """A Redis client for the limiters. It connects on first use and again after a failure."""
    return aioredis.from_url(
        redis_url,
        socket_connect_timeout=TIMEOUT_SECONDS,
        socket_timeout=TIMEOUT_SECONDS,
    )


class Hit(NamedTuple):
    """One request's hit in a caller's Redis window, and the window as the hit found it."""

    key: str
    member: str
    count: int  # hits in the window, this one included
    recent: int  # hits in the last BURST_SECONDS, this one included
    oldest: float  # time of the oldest hit in the window


class RedisWindow:
    """One limiter's per-caller sliding windows in Redis.

    `edge_counts` says whether a hit exactly `window` seconds old is still in the window, as in
    RateLimiter's memory window; AuthManager's memory window has already dropped it.
    """

    def __init__(self, client: aioredis.Redis, name: str, window: float, edge_counts: bool = True):
        self.name = name
        self._client = client
        self._prefix = f"{KEY_PREFIX}{name}:"
        self._window = window
        self._edge_counts = edge_counts

    async def add(self, caller: str, now: float) -> Hit:
        """Add a hit at `now` to the caller's window and count it, in one transaction.

        Raises RedisError when Redis cannot answer.
        """
        key = self._prefix + caller
        member = uuid.uuid4().hex
        pipe = self._client.pipeline(transaction=True)
        cutoff = now - self._window
        pipe.zremrangebyscore(key, "-inf", f"({cutoff}" if self._edge_counts else cutoff)
        pipe.zadd(key, {member: now})
        pipe.zcard(key)
        pipe.zcount(key, now - BURST_SECONDS, "+inf")
        pipe.zrange(key, 0, 0, withscores=True)
        pipe.expire(key, math.ceil(self._window))
        _, _, count, recent, oldest, _ = await pipe.execute()
        return Hit(key, member, count, recent, oldest[0][1])

    async def remove(self, hit: Hit) -> None:
        """Take a refused hit back out of its window.

        If Redis fails here the hit stays until it ages out of the window, which only makes the
        caller's limit stricter until then. The failure is logged.
        """
        try:
            await self._client.zrem(hit.key, hit.member)
        except RedisError as e:
            logger.error(
                "Rate limiter %s: could not take back a refused hit: %s",
                self.name,
                type(e).__name__,
            )


class RateLimiter:
    """Sliding window rate limiter per caller: `requests_per_minute` hits per 60 seconds and at most
    `burst` of them in BURST_SECONDS. In process memory until use_redis()."""

    def __init__(self, requests_per_minute: int = 30, burst: int = 10):
        self.rpm = requests_per_minute
        self.burst = burst
        self.window = 60.0  # seconds
        self._hits: Dict[str, list] = defaultdict(list)
        self._redis: Optional[RedisWindow] = None
        self._fail_open = False

    def use_redis(self, client: aioredis.Redis, name: str, fail_open: bool) -> None:
        """Keep this limiter's windows in Redis under `name`.

        When Redis cannot answer, the request is counted in this process's memory if fail_open,
        else refused.
        """
        self._redis = RedisWindow(client, name, self.window)
        self._fail_open = fail_open

    async def is_allowed(self, key: str) -> bool:
        if self._redis is not None:
            try:
                hit = await self._redis.add(key, time.time())
            except RedisError as e:
                logger.error(
                    "Rate limiter %s: Redis unavailable (%s), request %s",
                    self._redis.name,
                    type(e).__name__,
                    "counted in this process's memory" if self._fail_open else "refused",
                )
                if not self._fail_open:
                    return False
            else:
                if hit.count > self.rpm or hit.recent > self.burst:
                    await self._redis.remove(hit)
                    return False
                return True
        now = time.monotonic()
        hits = self._hits[key]

        # Prune expired entries
        cutoff = now - self.window
        while hits and hits[0] < cutoff:
            hits.pop(0)

        if len(hits) >= self.rpm:
            return False

        # Burst check: no more than `burst` requests in 5 seconds
        burst_cutoff = now - BURST_SECONDS
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
