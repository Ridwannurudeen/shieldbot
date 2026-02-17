"""API key authentication and metering."""

import hashlib
import secrets
import time
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Tier-based rate limits
TIER_LIMITS = {
    "free": {"rpm": 60, "daily": 1000},
    "pro": {"rpm": 300, "daily": 50000},
}

KEY_PREFIX = "sb_"


def generate_api_key() -> str:
    """Generate a new API key with sb_ prefix."""
    return KEY_PREFIX + secrets.token_hex(16)


def hash_key(key: str) -> str:
    """SHA-256 hash of the full key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


class AuthManager:
    """API key validation and per-key rate limiting."""

    def __init__(self, db):
        self.db = db
        # In-memory rate tracking: key_hash -> {minute_hits: [...], day_count: int, day_start: float}
        self._rate_state: Dict[str, Dict] = {}

    async def create_key(self, owner: str, tier: str = "free") -> Dict:
        """Create a new API key and store hash in DB."""
        if tier not in TIER_LIMITS:
            raise ValueError(f"Invalid tier: {tier}")

        raw_key = generate_api_key()
        key_hash = hash_key(raw_key)
        limits = TIER_LIMITS[tier]

        await self.db._db.execute("""
            INSERT INTO api_keys (key_id, key_hash, owner, tier, rpm_limit, daily_limit, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        """, (raw_key[:12], key_hash, owner, tier, limits["rpm"], limits["daily"], time.time()))
        await self.db._db.commit()

        return {"key": raw_key, "key_id": raw_key[:12], "owner": owner, "tier": tier}

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
        """Check if the key is within rate limits. Returns True if allowed."""
        key_id = key_info["key_id"]
        now = time.time()

        state = self._rate_state.get(key_id)
        if not state:
            state = {"minute_hits": [], "day_count": 0, "day_start": now}
            self._rate_state[key_id] = state

        # Reset daily counter if new day
        if now - state["day_start"] >= 86400:
            state["day_count"] = 0
            state["day_start"] = now

        # Prune minute hits
        cutoff = now - 60
        state["minute_hits"] = [t for t in state["minute_hits"] if t > cutoff]

        # Check limits
        if len(state["minute_hits"]) >= key_info["rpm_limit"]:
            return False
        if state["day_count"] >= key_info["daily_limit"]:
            return False

        # Record hit
        state["minute_hits"].append(now)
        state["day_count"] += 1
        return True

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
