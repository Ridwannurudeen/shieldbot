"""Redis-backed cache service for verdict caching and rate limiting.

Degrades gracefully to no-op when Redis is unavailable (fail-open).
"""

import json
import logging
from typing import Dict, Optional

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)


class CacheService:
    """Async Redis cache for verdict results and rate limiting."""

    def __init__(self, redis_url: str, ttl: int = 300):
        self._redis_url = redis_url
        self._ttl = ttl
        self._redis: Optional[aioredis.Redis] = None
        self._available = False

    async def connect(self) -> None:
        """Connect to Redis. Fails silently if unavailable."""
        try:
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=False,
                socket_connect_timeout=3,
            )
            await self._redis.ping()
            self._available = True
            logger.info("Redis cache connected at %s", self._redis_url)
        except Exception as exc:
            self._available = False
            self._redis = None
            logger.warning("Redis unavailable, cache disabled: %s", exc)

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._redis is not None:
            try:
                await self._redis.close()
            except Exception:
                pass
            self._redis = None
            self._available = False

    # ── Verdict caching ─────────────────────────────────────────────

    async def get_verdict(
        self, address: str, chain_id: int
    ) -> Optional[Dict]:
        """Retrieve a cached verdict. Returns None on miss or if disabled."""
        if not self._available:
            return None
        try:
            key = f"verdict:{address.lower()}:{chain_id}"
            raw = await self._redis.get(key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as exc:
            logger.debug("Cache get failed for %s:%s: %s", address, chain_id, exc)
            return None

    async def set_verdict(
        self,
        address: str,
        chain_id: int,
        verdict: Dict,
        ttl: Optional[int] = None,
    ) -> None:
        """Store a verdict in the cache with a TTL (seconds)."""
        if not self._available:
            return
        try:
            key = f"verdict:{address.lower()}:{chain_id}"
            value = json.dumps(verdict)
            await self._redis.set(key, value, ex=ttl or self._ttl)
        except Exception as exc:
            logger.debug("Cache set failed for %s:%s: %s", address, chain_id, exc)

    # ── Rate limiting ───────────────────────────────────────────────

    async def check_rate_limit(
        self, key: str, limit: int, window: int = 60
    ) -> bool:
        """Atomically increment a counter and return True if under the limit.

        Uses an atomic INCR-first pattern to avoid TOCTOU races.
        INCR creates the key starting at 1 if it doesn't exist.
        Returns True (allowed) when Redis is unavailable (fail-open).
        """
        if not self._available:
            return True
        try:
            rate_key = f"rate:{key}"
            pipe = self._redis.pipeline()
            pipe.incr(rate_key)
            pipe.expire(rate_key, window)
            results = await pipe.execute()
            current = results[0]  # INCR returns the new value
            return current <= limit
        except Exception as exc:
            logger.debug("Rate limit check failed for %s: %s", key, exc)
            return True
