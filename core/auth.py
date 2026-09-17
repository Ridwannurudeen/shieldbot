"""API key authentication and metering."""

import asyncio
import contextvars
import hashlib
import math
import secrets
import time
import uuid
import logging
from contextlib import contextmanager
from typing import Dict, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Tier-based rate limits
TIER_LIMITS = {
    "free": {"rpm": 60, "daily": 1000},
    "pro": {"rpm": 300, "daily": 50000},
}

KEY_PREFIX = "sb_"

# Seconds a refused caller should wait when the daily quota store cannot be read or written.
QUOTA_UNAVAILABLE_RETRY_AFTER = 60

# key_id -> (allowed, quota) for rate-limit checks already made while serving the current request.
_request_checks: contextvars.ContextVar[Optional[Dict[str, Tuple[bool, Dict]]]] = contextvars.ContextVar(
    "request_checks", default=None
)


def generate_api_key() -> str:
    """Generate a new API key with sb_ prefix."""
    return KEY_PREFIX + secrets.token_hex(16)


def hash_key(key: str) -> str:
    """SHA-256 hash of the full key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


@contextmanager
def request_quota_scope() -> Iterator[None]:
    """Count a key at most once per request: repeated checks inside the scope reuse the first result."""
    token = _request_checks.set({})
    try:
        yield
    finally:
        _request_checks.reset(token)


def rate_limit_headers(key_info: Dict) -> Dict[str, str]:
    """Daily quota headers for a key checked by check_rate_limit; empty if it was not checked."""
    quota = key_info.get("quota")
    if quota is None:
        return {}
    headers = {"X-RateLimit-Limit": str(quota["daily_limit"])}
    if quota["remaining"] is not None:
        headers["X-RateLimit-Remaining"] = str(quota["remaining"])
    headers["X-RateLimit-Reset"] = str(quota["resets_at"])
    if quota["retry_after"] is not None:
        headers["Retry-After"] = str(quota["retry_after"])
    return headers


def _quota(daily_limit: int, used: Optional[int], day: int) -> Dict:
    """Quota state for a UTC day number; unknown usage stays None."""
    return {
        "daily_limit": daily_limit,
        "used_today": used,
        "remaining": None if used is None else max(daily_limit - used, 0),
        "resets_at": (day + 1) * 86400,
    }


class AuthManager:
    """API key validation and per-key rate limiting."""

    def __init__(self, db):
        self.db = db
        # In-memory per-minute windows: key_id -> hit timestamps. Daily counts are in api_daily_usage.
        self._minute_hits: Dict[str, List[float]] = {}
        self._check_lock = asyncio.Lock()

    async def create_key(self, owner: str, tier: str = "free") -> Dict:
        """Create a new API key and store hash in DB."""
        if tier not in TIER_LIMITS:
            raise ValueError(f"Invalid tier: {tier}")

        raw_key = generate_api_key()
        key_hash = hash_key(raw_key)
        key_id = str(uuid.uuid4())
        limits = TIER_LIMITS[tier]

        async with self.db._db.execute("BEGIN IMMEDIATE"):
            await self.db._db.execute("""
                INSERT INTO api_keys (key_id, key_hash, owner, tier, rpm_limit, daily_limit, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            """, (key_id, key_hash, owner, tier, limits["rpm"], limits["daily"], time.time()))
            await self.db._db.commit()

        return {"key": raw_key, "key_id": key_id, "owner": owner, "tier": tier}

    async def validate_key(self, raw_key: str) -> Optional[Dict]:
        """Validate an API key. Returns key info dict or None."""
        if not raw_key or not raw_key.startswith(KEY_PREFIX):
            return None

        key_hash = hash_key(raw_key)
        cursor = await self.db._db.execute("""
            SELECT key_id, owner, tier, rpm_limit, daily_limit, is_active
            FROM api_keys WHERE key_hash = ?
        """, (key_hash,))
        row = await cursor.fetchone()
        if not row or not row[5]:  # not active
            return None

        return {
            "key_id": row[0],
            "owner": row[1],
            "tier": row[2],
            "rpm_limit": row[3],
            "daily_limit": row[4],
        }

    async def check_rate_limit(self, key_info: Dict) -> bool:
        """Check if the key is within rate limits. Returns True if allowed.

        The per-minute window is in memory. The daily quota is a durable counter for the UTC
        calendar day: an allowed request is counted and committed before it is served, so the
        count survives a restart and each allowed request is counted once. If the counter cannot
        be read or written the request is refused. The key's quota state, including the
        Retry-After seconds of a refusal, is stored in key_info["quota"].
        """
        key_id = key_info["key_id"]
        checks = _request_checks.get()
        if checks is not None and key_id in checks:
            allowed, key_info["quota"] = checks[key_id]
            return allowed

        async with self._check_lock:
            now = time.time()
            day = int(now // 86400)
            hits = [t for t in self._minute_hits.get(key_id, []) if t > now - 60]
            self._minute_hits[key_id] = hits
            try:
                if len(hits) >= key_info["rpm_limit"]:
                    allowed = False
                    used = await self._used_on_day(key_id, day)
                    retry_after = math.ceil(hits[0] + 60 - now)
                else:
                    allowed, used = await self._count_request(key_id, day, key_info["daily_limit"])
                    retry_after = None if allowed else math.ceil((day + 1) * 86400 - now)
            except Exception as e:
                logger.error("API quota store unavailable: %s", type(e).__name__)
                allowed, used, retry_after = False, None, QUOTA_UNAVAILABLE_RETRY_AFTER
            if allowed:
                hits.append(now)

        quota = {**_quota(key_info["daily_limit"], used, day), "retry_after": retry_after}
        key_info["quota"] = quota
        if checks is not None:
            checks[key_id] = (allowed, quota)
        return allowed

    async def _count_request(self, key_id: str, day: int, daily_limit: int) -> Tuple[bool, int]:
        """Count one request for the UTC day if the key is under its daily limit, and commit.

        Returns whether the request was counted and the day's count after it.
        """
        await self.db._db.execute(
            "INSERT OR IGNORE INTO api_daily_usage (key_id, utc_day, used) VALUES (?, ?, 0)",
            (key_id, day),
        )
        used = await self._used_on_day(key_id, day)
        cursor = await self.db._db.execute(
            "UPDATE api_daily_usage SET used = used + 1 WHERE key_id = ? AND utc_day = ? AND used < ?",
            (key_id, day, daily_limit),
        )
        counted = cursor.rowcount == 1
        await self.db._db.commit()
        return counted, used + 1 if counted else used

    async def _used_on_day(self, key_id: str, day: int) -> int:
        cursor = await self.db._db.execute(
            "SELECT used FROM api_daily_usage WHERE key_id = ? AND utc_day = ?", (key_id, day)
        )
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def get_quota(self, key_info: Dict) -> Dict:
        """Daily quota state for the current UTC day."""
        day = int(time.time() // 86400)
        used = await self._used_on_day(key_info["key_id"], day)
        return _quota(key_info["daily_limit"], used, day)

    async def record_usage(self, key_id: str, endpoint: str):
        """Record API usage for billing/analytics."""
        await self.db._db.execute("""
            INSERT INTO api_usage (key_id, endpoint, created_at) VALUES (?, ?, ?)
        """, (key_id, endpoint, time.time()))
        await self.db._db.commit()

    async def get_usage(self, key_id: str, days: int = 30) -> Dict:
        """Get usage stats for a key."""
        cutoff = time.time() - (days * 86400)
        cursor = await self.db._db.execute("""
            SELECT COUNT(*), endpoint FROM api_usage
            WHERE key_id = ? AND created_at > ?
            GROUP BY endpoint
        """, (key_id, cutoff))
        rows = await cursor.fetchall()
        total = sum(r[0] for r in rows)
        by_endpoint = {r[1]: r[0] for r in rows}
        return {"total": total, "by_endpoint": by_endpoint, "days": days}

    async def deactivate_key(self, key_id: str):
        """Deactivate an API key."""
        await self.db._db.execute(
            "UPDATE api_keys SET is_active = 0 WHERE key_id = ?", (key_id,)
        )
        await self.db._db.commit()
