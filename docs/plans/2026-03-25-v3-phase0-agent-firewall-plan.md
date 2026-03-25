# ShieldBot V3.0: Agent Transaction Firewall — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an Agent Transaction Firewall API so AI agents can check transactions before signing, with Redis verdict caching, a threshold-based policy engine, and a Python SDK.

**Architecture:** New modules are additive — no changes to existing endpoints. Agent firewall sits alongside the human `/api/firewall` path. Redis provides verdict caching and rate limiting for the hot plane. The policy engine uses threshold-based scoring (auto-allow below X, auto-block above Y, ask owner in between).

**Tech Stack:** FastAPI (existing), Redis (new — `redis[hiredis]`), aiosqlite (existing), pytest (existing)

**Existing patterns to follow:**
- Services go in `services/`, registered in `core/container.py`
- DB tables added to `Database._create_tables()` in `core/database.py`
- Config via `Settings` in `core/config.py` (env vars)
- Auth via `AuthManager` in `core/auth.py` (API key tiers)
- Tests in `tests/`, use fixtures from `tests/conftest.py`
- Agents in `agent/`, thin wrappers in `agent/tools.py`

**File paths are relative to:** `C:\Users\GUDMAN\Desktop\Github files\shieldbot\`

---

## Task 1: Add Redis dependency and cache service

**Files:**
- Modify: `requirements.txt`
- Create: `services/cache.py`
- Create: `tests/test_cache.py`
- Modify: `core/config.py` (add redis_url setting)

**Step 1: Add redis dependency to requirements.txt**

Add this line to `requirements.txt`:
```
redis[hiredis]==5.2.1
```

**Step 2: Add Redis config to Settings**

In `core/config.py`, add to the `Settings` class after the `database_path` field:

```python
# Redis (verdict caching + rate limiting)
redis_url: str = "redis://localhost:6379/0"
```

**Step 3: Write failing tests for CacheService**

Create `tests/test_cache.py`:

```python
"""Tests for Redis-backed verdict cache."""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    r = AsyncMock()
    r.get = AsyncMock(return_value=None)
    r.setex = AsyncMock()
    r.close = AsyncMock()
    r.ping = AsyncMock()
    return r


@pytest.fixture
def cache_service(mock_redis):
    from services.cache import CacheService
    svc = CacheService.__new__(CacheService)
    svc._redis = mock_redis
    svc._enabled = True
    svc._ttl = 300
    return svc


@pytest.mark.asyncio
async def test_get_verdict_cache_miss(cache_service, mock_redis):
    """Cache miss returns None."""
    mock_redis.get = AsyncMock(return_value=None)
    result = await cache_service.get_verdict("0xabc", 56)
    assert result is None
    mock_redis.get.assert_called_once_with("verdict:0xabc:56")


@pytest.mark.asyncio
async def test_get_verdict_cache_hit(cache_service, mock_redis):
    """Cache hit returns the stored verdict dict."""
    stored = {"verdict": "BLOCK", "score": 89, "flags": ["honeypot"]}
    mock_redis.get = AsyncMock(return_value=json.dumps(stored).encode())
    result = await cache_service.get_verdict("0xabc", 56)
    assert result["verdict"] == "BLOCK"
    assert result["score"] == 89


@pytest.mark.asyncio
async def test_set_verdict(cache_service, mock_redis):
    """set_verdict stores JSON with TTL."""
    verdict = {"verdict": "ALLOW", "score": 12}
    await cache_service.set_verdict("0xabc", 56, verdict)
    mock_redis.setex.assert_called_once()
    call_args = mock_redis.setex.call_args
    assert call_args[0][0] == "verdict:0xabc:56"
    assert call_args[0][1] == 300
    assert json.loads(call_args[0][2])["verdict"] == "ALLOW"


@pytest.mark.asyncio
async def test_cache_disabled_returns_none():
    """When Redis is unavailable, all ops return None/no-op."""
    from services.cache import CacheService
    svc = CacheService.__new__(CacheService)
    svc._redis = None
    svc._enabled = False
    svc._ttl = 300
    assert await svc.get_verdict("0xabc", 56) is None
    await svc.set_verdict("0xabc", 56, {"verdict": "ALLOW"})  # no error


@pytest.mark.asyncio
async def test_rate_limit_check(cache_service, mock_redis):
    """Rate limiter increments counter and checks limit."""
    mock_redis.get = AsyncMock(return_value=b"5")
    mock_redis.incr = AsyncMock(return_value=6)
    mock_redis.expire = AsyncMock()
    allowed = await cache_service.check_rate_limit("agent:123", 500)
    assert allowed is True


@pytest.mark.asyncio
async def test_rate_limit_exceeded(cache_service, mock_redis):
    """Rate limiter blocks when over limit."""
    mock_redis.get = AsyncMock(return_value=b"500")
    allowed = await cache_service.check_rate_limit("agent:123", 500)
    assert allowed is False
```

**Step 4: Run tests to verify they fail**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest tests/test_cache.py -v`
Expected: FAIL (ModuleNotFoundError: services.cache)

**Step 5: Implement CacheService**

Create `services/cache.py`:

```python
"""Redis-backed verdict cache and rate limiting for the hot plane."""

import json
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class CacheService:
    """Thin async wrapper around Redis for verdict caching and rate limiting.

    Gracefully degrades to no-op when Redis is unavailable.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0", ttl: int = 300):
        self._redis = None
        self._enabled = False
        self._ttl = ttl
        self._redis_url = redis_url

    async def connect(self):
        """Connect to Redis. Fails silently if unavailable."""
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=False,
                socket_connect_timeout=3,
            )
            await self._redis.ping()
            self._enabled = True
            logger.info("Redis cache connected")
        except Exception as e:
            logger.warning(f"Redis unavailable, caching disabled: {e}")
            self._redis = None
            self._enabled = False

    async def close(self):
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()

    # --- Verdict Cache ---

    async def get_verdict(self, address: str, chain_id: int) -> Optional[Dict]:
        """Get cached verdict for address+chain. Returns None on miss or disabled."""
        if not self._enabled:
            return None
        try:
            key = f"verdict:{address.lower()}:{chain_id}"
            raw = await self._redis.get(key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as e:
            logger.debug(f"Cache get error: {e}")
            return None

    async def set_verdict(self, address: str, chain_id: int, verdict: Dict, ttl: int = None):
        """Cache a verdict with TTL."""
        if not self._enabled:
            return
        try:
            key = f"verdict:{address.lower()}:{chain_id}"
            await self._redis.setex(key, ttl or self._ttl, json.dumps(verdict))
        except Exception as e:
            logger.debug(f"Cache set error: {e}")

    # --- Rate Limiting ---

    async def check_rate_limit(self, key: str, limit: int, window: int = 60) -> bool:
        """Check if key is within rate limit. Returns True if allowed."""
        if not self._enabled:
            return True  # fail-open when Redis down
        try:
            rate_key = f"rate:{key}"
            current = await self._redis.get(rate_key)
            if current is not None and int(current) >= limit:
                return False
            pipe = self._redis.pipeline()
            pipe.incr(rate_key)
            pipe.expire(rate_key, window)
            await pipe.execute()
            return True
        except Exception as e:
            logger.debug(f"Rate limit check error: {e}")
            return True  # fail-open
```

**Step 6: Run tests to verify they pass**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest tests/test_cache.py -v`
Expected: All 6 tests PASS

**Step 7: Commit**

```bash
git add requirements.txt services/cache.py tests/test_cache.py core/config.py
git commit -m "feat(v3): add Redis cache service with verdict caching and rate limiting"
```

---

## Task 2: Add agent_policies database table and CRUD methods

**Files:**
- Modify: `core/database.py` (add table + methods)
- Create: `tests/test_agent_policies.py`

**Step 1: Write failing tests**

Create `tests/test_agent_policies.py`:

```python
"""Tests for agent policy CRUD in the database."""

import pytest
import json
from core.database import Database


@pytest.fixture
async def db(tmp_path):
    d = Database(str(tmp_path / "test.db"))
    await d.initialize()
    yield d
    await d.close()


@pytest.mark.asyncio
async def test_upsert_and_get_agent_policy(db):
    """Insert a policy and retrieve it."""
    policy = {
        "mode": "threshold",
        "auto_allow_below": 25,
        "auto_block_above": 70,
        "max_spend_per_tx_usd": 500,
        "max_spend_daily_usd": 5000,
        "max_slippage": 0.05,
        "always_allow": ["0xPancakeRouter"],
        "always_block": [],
        "active_hours": "00:00-23:59",
        "timeout_action": "block",
        "owner_response_timeout": 60,
        "fail_mode": "cached_then_block",
    }
    await db.upsert_agent_policy(
        agent_id="erc8004:31253",
        owner_address="0xOwner",
        owner_telegram="@owner",
        tier="agent",
        policy=policy,
    )
    result = await db.get_agent_policy("erc8004:31253")
    assert result is not None
    assert result["agent_id"] == "erc8004:31253"
    assert result["owner_address"] == "0xOwner"
    assert result["tier"] == "agent"
    assert result["policy"]["auto_allow_below"] == 25
    assert result["policy"]["auto_block_above"] == 70
    assert "0xPancakeRouter" in result["policy"]["always_allow"]


@pytest.mark.asyncio
async def test_get_missing_policy(db):
    """Returns None for unregistered agent."""
    result = await db.get_agent_policy("nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_update_policy(db):
    """Upsert overwrites existing policy."""
    policy_v1 = {"mode": "threshold", "auto_allow_below": 25, "auto_block_above": 70}
    await db.upsert_agent_policy("agent:1", "0xOwner", tier="free", policy=policy_v1)

    policy_v2 = {"mode": "threshold", "auto_allow_below": 15, "auto_block_above": 80}
    await db.upsert_agent_policy("agent:1", "0xOwner", tier="pro", policy=policy_v2)

    result = await db.get_agent_policy("agent:1")
    assert result["tier"] == "pro"
    assert result["policy"]["auto_allow_below"] == 15


@pytest.mark.asyncio
async def test_record_and_check_daily_spend(db):
    """Daily spend tracking increments and resets."""
    await db.upsert_agent_policy("agent:1", "0xOwner", tier="agent",
                                  policy={"max_spend_daily_usd": 5000})
    await db.record_agent_spend("agent:1", 100.0)
    await db.record_agent_spend("agent:1", 250.0)
    spend = await db.get_agent_daily_spend("agent:1")
    assert spend == 350.0


@pytest.mark.asyncio
async def test_get_agent_history(db):
    """Agent firewall history records are stored and retrievable."""
    await db.record_agent_firewall_event(
        agent_id="agent:1", chain_id=56,
        tx_to="0xTarget", tx_value="1000",
        verdict="BLOCK", score=91,
        flags=["honeypot"], evidence="test evidence",
    )
    history = await db.get_agent_firewall_history("agent:1", limit=10)
    assert len(history) == 1
    assert history[0]["verdict"] == "BLOCK"
    assert history[0]["score"] == 91
```

**Step 2: Run tests to verify they fail**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest tests/test_agent_policies.py -v`
Expected: FAIL (AttributeError: Database has no method upsert_agent_policy)

**Step 3: Add tables and methods to database.py**

In `core/database.py`, add to the end of `_create_tables()` (before the final `await self._db.commit()`):

```python
            CREATE TABLE IF NOT EXISTS agent_policies (
                agent_id TEXT PRIMARY KEY,
                owner_address TEXT NOT NULL,
                owner_telegram TEXT,
                owner_webhook TEXT,
                tier TEXT NOT NULL DEFAULT 'free',
                policy TEXT NOT NULL DEFAULT '{}',
                daily_spend_used_usd REAL DEFAULT 0,
                daily_spend_reset_at REAL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_firewall_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                tx_to TEXT,
                tx_value TEXT,
                verdict TEXT NOT NULL,
                score REAL,
                flags TEXT,
                evidence TEXT,
                policy_result TEXT,
                latency_ms REAL,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_agent_fw_history
                ON agent_firewall_history(agent_id, created_at DESC);
```

Then add these methods to the `Database` class:

```python
    # --- Agent Policies ---

    async def upsert_agent_policy(
        self,
        agent_id: str,
        owner_address: str,
        owner_telegram: str = None,
        owner_webhook: str = None,
        tier: str = "free",
        policy: dict = None,
    ):
        """Insert or update an agent's firewall policy."""
        now = time.time()
        policy_json = json.dumps(policy or {})
        await self._db.execute("""
            INSERT INTO agent_policies
                (agent_id, owner_address, owner_telegram, owner_webhook,
                 tier, policy, daily_spend_used_usd, daily_spend_reset_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                owner_address = excluded.owner_address,
                owner_telegram = COALESCE(excluded.owner_telegram, agent_policies.owner_telegram),
                owner_webhook = COALESCE(excluded.owner_webhook, agent_policies.owner_webhook),
                tier = excluded.tier,
                policy = excluded.policy,
                updated_at = excluded.updated_at
        """, (agent_id, owner_address.lower(), owner_telegram, owner_webhook,
              tier, policy_json, now, now, now))
        await self._db.commit()

    async def get_agent_policy(self, agent_id: str) -> Optional[Dict]:
        """Get an agent's policy. Returns None if not registered."""
        cursor = await self._db.execute("""
            SELECT agent_id, owner_address, owner_telegram, owner_webhook,
                   tier, policy, daily_spend_used_usd, daily_spend_reset_at,
                   created_at, updated_at
            FROM agent_policies WHERE agent_id = ?
        """, (agent_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "agent_id": row[0],
            "owner_address": row[1],
            "owner_telegram": row[2],
            "owner_webhook": row[3],
            "tier": row[4],
            "policy": json.loads(row[5]) if row[5] else {},
            "daily_spend_used_usd": row[6] or 0,
            "daily_spend_reset_at": row[7],
            "created_at": row[8],
            "updated_at": row[9],
        }

    async def record_agent_spend(self, agent_id: str, amount_usd: float):
        """Increment an agent's daily spend. Resets if a new day."""
        now = time.time()
        cursor = await self._db.execute(
            "SELECT daily_spend_reset_at FROM agent_policies WHERE agent_id = ?",
            (agent_id,),
        )
        row = await cursor.fetchone()
        if row and row[0] and (now - row[0]) >= 86400:
            # New day — reset
            await self._db.execute("""
                UPDATE agent_policies
                SET daily_spend_used_usd = ?, daily_spend_reset_at = ?
                WHERE agent_id = ?
            """, (amount_usd, now, agent_id))
        else:
            await self._db.execute("""
                UPDATE agent_policies
                SET daily_spend_used_usd = daily_spend_used_usd + ?
                WHERE agent_id = ?
            """, (amount_usd, agent_id))
            if row and not row[0]:
                await self._db.execute("""
                    UPDATE agent_policies SET daily_spend_reset_at = ? WHERE agent_id = ?
                """, (now, agent_id))
        await self._db.commit()

    async def get_agent_daily_spend(self, agent_id: str) -> float:
        """Get current daily spend for an agent."""
        cursor = await self._db.execute(
            "SELECT daily_spend_used_usd, daily_spend_reset_at FROM agent_policies WHERE agent_id = ?",
            (agent_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return 0.0
        # Check if reset needed
        if row[1] and (time.time() - row[1]) >= 86400:
            return 0.0
        return row[0] or 0.0

    # --- Agent Firewall History ---

    async def record_agent_firewall_event(
        self,
        agent_id: str,
        chain_id: int,
        tx_to: str = None,
        tx_value: str = None,
        verdict: str = "ALLOW",
        score: float = None,
        flags: list = None,
        evidence: str = None,
        policy_result: dict = None,
        latency_ms: float = None,
    ):
        """Record an agent firewall check result."""
        now = time.time()
        flags_json = json.dumps(flags) if flags else None
        policy_json = json.dumps(policy_result) if policy_result else None
        await self._db.execute("""
            INSERT INTO agent_firewall_history
                (agent_id, chain_id, tx_to, tx_value, verdict, score,
                 flags, evidence, policy_result, latency_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (agent_id, chain_id, tx_to, tx_value, verdict, score,
              flags_json, evidence, policy_json, latency_ms, now))
        await self._db.commit()

    async def get_agent_firewall_history(
        self, agent_id: str, limit: int = 50
    ) -> List[Dict]:
        """Get firewall history for an agent, newest first."""
        cursor = await self._db.execute("""
            SELECT id, chain_id, tx_to, tx_value, verdict, score,
                   flags, evidence, policy_result, latency_ms, created_at
            FROM agent_firewall_history
            WHERE agent_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        """, (agent_id, limit))
        rows = await cursor.fetchall()
        results = []
        for r in rows:
            flags_val = json.loads(r[6]) if r[6] else []
            policy_val = json.loads(r[8]) if r[8] else None
            results.append({
                "id": r[0], "chain_id": r[1], "tx_to": r[2],
                "tx_value": r[3], "verdict": r[4], "score": r[5],
                "flags": flags_val, "evidence": r[7],
                "policy_result": policy_val, "latency_ms": r[9],
                "created_at": r[10],
            })
        return results
```

**Step 4: Run tests to verify they pass**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest tests/test_agent_policies.py -v`
Expected: All 5 tests PASS

**Step 5: Run all existing tests to verify no regressions**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest --tb=short -q`
Expected: 262+ passed (257 existing + 5 new)

**Step 6: Commit**

```bash
git add core/database.py tests/test_agent_policies.py
git commit -m "feat(v3): add agent_policies and agent_firewall_history tables with CRUD"
```

---

## Task 3: Build the policy engine (threshold model)

**Files:**
- Create: `agent/policy_engine.py`
- Create: `tests/test_agent_policy_engine.py`

**Step 1: Write failing tests**

Create `tests/test_agent_policy_engine.py`:

```python
"""Tests for the agent threshold-based policy engine."""

import pytest
from agent.policy_engine import AgentPolicyEngine, PolicyVerdict


@pytest.fixture
def engine():
    return AgentPolicyEngine()


@pytest.fixture
def default_policy():
    return {
        "mode": "threshold",
        "auto_allow_below": 25,
        "auto_block_above": 70,
        "max_spend_per_tx_usd": 500,
        "max_spend_daily_usd": 5000,
        "max_slippage": 0.05,
        "always_allow": ["0x10ed43c718714eb63d5aa57b78b54704e256024e"],
        "always_block": ["0xscammer"],
        "active_hours": "00:00-23:59",
        "timeout_action": "block",
        "fail_mode": "cached_then_block",
    }


def test_auto_allow_below_threshold(engine, default_policy):
    """Score below auto_allow → ALLOW, all checks pass."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=12,
        target_address="0xsometoken",
        tx_value_usd=100,
        daily_spend_usd=0,
        simulated_slippage=0.01,
    )
    assert result.verdict == "ALLOW"
    assert result.all_passed is True


def test_auto_block_above_threshold(engine, default_policy):
    """Score above auto_block → BLOCK."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=85,
        target_address="0xsometoken",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    assert result.verdict == "BLOCK"
    assert "risk_threshold" in result.failed_checks


def test_middle_range_asks_owner(engine, default_policy):
    """Score in middle range → WARN (ask owner)."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=45,
        target_address="0xsometoken",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    assert result.verdict == "WARN"
    assert result.needs_owner_approval is True


def test_always_allow_overrides(engine, default_policy):
    """Address in always_allow passes regardless of score."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=90,
        target_address="0x10ed43c718714eb63d5aa57b78b54704e256024e",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    assert result.verdict == "ALLOW"
    assert "allowlist" in result.checks["contract_list"]


def test_always_block_overrides(engine, default_policy):
    """Address in always_block blocks regardless of score."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=5,
        target_address="0xscammer",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    assert result.verdict == "BLOCK"
    assert "blocklist" in result.checks["contract_list"]


def test_spending_limit_exceeded(engine, default_policy):
    """Tx value exceeding per-tx limit → BLOCK."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=10,
        target_address="0xsafe",
        tx_value_usd=600,
        daily_spend_usd=0,
    )
    assert result.verdict == "BLOCK"
    assert "spending_limit" in result.failed_checks


def test_daily_spend_exceeded(engine, default_policy):
    """Daily spend exceeded → BLOCK."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=10,
        target_address="0xsafe",
        tx_value_usd=100,
        daily_spend_usd=4950,
    )
    assert result.verdict == "BLOCK"
    assert "daily_limit" in result.failed_checks


def test_slippage_exceeded(engine, default_policy):
    """Simulated slippage over max → BLOCK."""
    result = engine.evaluate(
        policy=default_policy,
        risk_score=10,
        target_address="0xsafe",
        tx_value_usd=100,
        daily_spend_usd=0,
        simulated_slippage=0.12,
    )
    assert result.verdict == "BLOCK"
    assert "slippage_cap" in result.failed_checks


def test_empty_policy_defaults(engine):
    """Empty policy uses safe defaults."""
    result = engine.evaluate(
        policy={},
        risk_score=50,
        target_address="0xsafe",
        tx_value_usd=100,
        daily_spend_usd=0,
    )
    # Default thresholds: allow < 25, block > 70, so 50 = WARN
    assert result.verdict == "WARN"
```

**Step 2: Run tests to verify they fail**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest tests/test_agent_policy_engine.py -v`
Expected: FAIL (ModuleNotFoundError: agent.policy_engine)

**Step 3: Implement AgentPolicyEngine**

Create `agent/policy_engine.py`:

```python
"""Threshold-based policy engine for agent transaction firewall."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PolicyVerdict:
    """Result of evaluating an agent's policy against a transaction."""
    verdict: str  # "ALLOW" | "WARN" | "BLOCK"
    checks: Dict[str, str] = field(default_factory=dict)
    failed_checks: List[str] = field(default_factory=list)
    needs_owner_approval: bool = False
    all_passed: bool = False


# Safe defaults when policy fields are missing
DEFAULTS = {
    "mode": "threshold",
    "auto_allow_below": 25,
    "auto_block_above": 70,
    "max_spend_per_tx_usd": 1000,
    "max_spend_daily_usd": 10000,
    "max_slippage": 0.10,
    "always_allow": [],
    "always_block": [],
    "timeout_action": "block",
    "fail_mode": "cached_then_block",
}


class AgentPolicyEngine:
    """Evaluates agent policies using a threshold model.

    - auto_allow_below: transactions scoring below this pass automatically.
    - auto_block_above: transactions scoring above this are blocked.
    - Middle range: asks the owner for approval.
    - Explicit allowlist/blocklist override everything.
    - Spending limits and slippage caps are hard gates.
    """

    def _get(self, policy: dict, key: str):
        """Get policy value with fallback to defaults."""
        return policy.get(key, DEFAULTS.get(key))

    def evaluate(
        self,
        policy: Dict,
        risk_score: float,
        target_address: str,
        tx_value_usd: float = 0,
        daily_spend_usd: float = 0,
        simulated_slippage: float = None,
    ) -> PolicyVerdict:
        """Evaluate a transaction against an agent's policy."""
        checks = {}
        failed = []
        target_lower = target_address.lower()

        # 1. Explicit lists (highest priority)
        always_allow = [a.lower() for a in (self._get(policy, "always_allow") or [])]
        always_block = [a.lower() for a in (self._get(policy, "always_block") or [])]

        if target_lower in always_block:
            checks["contract_list"] = f"fail — blocklist match"
            return PolicyVerdict(
                verdict="BLOCK", checks=checks,
                failed_checks=["contract_list"],
            )

        if target_lower in always_allow:
            checks["contract_list"] = f"pass — allowlist match"
            return PolicyVerdict(
                verdict="ALLOW", checks=checks, all_passed=True,
            )

        checks["contract_list"] = "pass — no list match"

        # 2. Spending limits (hard gates)
        max_per_tx = self._get(policy, "max_spend_per_tx_usd")
        if tx_value_usd > max_per_tx:
            checks["spending_limit"] = f"fail — ${tx_value_usd:.2f} > ${max_per_tx:.2f} limit"
            failed.append("spending_limit")

        else:
            checks["spending_limit"] = f"pass — ${tx_value_usd:.2f} <= ${max_per_tx:.2f}"

        max_daily = self._get(policy, "max_spend_daily_usd")
        if (daily_spend_usd + tx_value_usd) > max_daily:
            checks["daily_limit"] = f"fail — ${daily_spend_usd + tx_value_usd:.2f} > ${max_daily:.2f} daily limit"
            failed.append("daily_limit")
        else:
            checks["daily_limit"] = f"pass — ${daily_spend_usd + tx_value_usd:.2f} <= ${max_daily:.2f}"

        # 3. Slippage cap
        max_slip = self._get(policy, "max_slippage")
        if simulated_slippage is not None and simulated_slippage > max_slip:
            checks["slippage_cap"] = f"fail — {simulated_slippage:.1%} > {max_slip:.1%}"
            failed.append("slippage_cap")
        elif simulated_slippage is not None:
            checks["slippage_cap"] = f"pass — {simulated_slippage:.1%} <= {max_slip:.1%}"
        else:
            checks["slippage_cap"] = "skip — no simulation data"

        # Hard gate failures → BLOCK regardless of score
        if failed:
            checks["risk_threshold"] = "skip — hard gate failed"
            return PolicyVerdict(
                verdict="BLOCK", checks=checks, failed_checks=failed,
            )

        # 4. Risk threshold
        allow_below = self._get(policy, "auto_allow_below")
        block_above = self._get(policy, "auto_block_above")

        if risk_score < allow_below:
            checks["risk_threshold"] = f"pass — score {risk_score} < {allow_below}"
            return PolicyVerdict(
                verdict="ALLOW", checks=checks, all_passed=True,
            )

        if risk_score > block_above:
            checks["risk_threshold"] = f"fail — score {risk_score} > {block_above}"
            failed.append("risk_threshold")
            return PolicyVerdict(
                verdict="BLOCK", checks=checks, failed_checks=failed,
            )

        # Middle range → ask owner
        checks["risk_threshold"] = f"warn — score {risk_score} in [{allow_below}, {block_above}]"
        return PolicyVerdict(
            verdict="WARN", checks=checks,
            needs_owner_approval=True,
        )
```

**Step 4: Run tests to verify they pass**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest tests/test_agent_policy_engine.py -v`
Expected: All 10 tests PASS

**Step 5: Commit**

```bash
git add agent/policy_engine.py tests/test_agent_policy_engine.py
git commit -m "feat(v3): add threshold-based agent policy engine"
```

---

## Task 4: Build the agent firewall API endpoints

**Files:**
- Create: `agent/firewall.py` (route handler module)
- Create: `tests/test_agent_firewall_api.py`
- Modify: `api.py` (mount the new routes)
- Modify: `core/container.py` (add CacheService + AgentPolicyEngine)

**Step 1: Write failing tests for the API**

Create `tests/test_agent_firewall_api.py`:

```python
"""Tests for the agent firewall API endpoints."""

import pytest
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


@pytest.fixture
def mock_container():
    """Mock ServiceContainer with agent firewall dependencies."""
    c = MagicMock()
    c.db = MagicMock()
    c.db.get_agent_policy = AsyncMock(return_value={
        "agent_id": "agent:1",
        "owner_address": "0xowner",
        "owner_telegram": "@owner",
        "tier": "agent",
        "policy": {
            "mode": "threshold",
            "auto_allow_below": 25,
            "auto_block_above": 70,
            "max_spend_per_tx_usd": 500,
            "max_spend_daily_usd": 5000,
            "max_slippage": 0.05,
            "always_allow": [],
            "always_block": [],
        },
        "daily_spend_used_usd": 0,
    })
    c.db.get_agent_daily_spend = AsyncMock(return_value=0)
    c.db.record_agent_firewall_event = AsyncMock()
    c.db.record_agent_spend = AsyncMock()
    c.db.upsert_agent_policy = AsyncMock()
    c.db.get_agent_firewall_history = AsyncMock(return_value=[])
    c.db.get_contract_score = AsyncMock(return_value=None)
    c.db.upsert_contract_score = AsyncMock()

    c.cache = MagicMock()
    c.cache.get_verdict = AsyncMock(return_value=None)
    c.cache.set_verdict = AsyncMock()
    c.cache.check_rate_limit = AsyncMock(return_value=True)

    c.registry = MagicMock()
    c.registry.run_all = AsyncMock(return_value=[])

    c.risk_engine = MagicMock()
    c.risk_engine.compute_from_results = MagicMock(return_value={
        "risk_score": 12, "risk_level": "LOW", "flags": [],
        "category_scores": {}, "confidence": 0.9,
    })

    c.auth_manager = MagicMock()
    c.auth_manager.validate_key = AsyncMock(return_value={
        "key_id": "k1", "owner": "test", "tier": "agent", "rpm_limit": 500, "daily_limit": 50000,
    })
    c.auth_manager.check_rate_limit = AsyncMock(return_value=True)
    c.auth_manager.record_usage = AsyncMock()

    c.web3_client = MagicMock()
    c.web3_client.is_valid_address = MagicMock(return_value=True)
    c.web3_client.is_contract = AsyncMock(return_value=True)
    c.web3_client.is_token_contract = AsyncMock(return_value=True)

    c.tenderly_simulator = MagicMock()
    c.tenderly_simulator.is_enabled = MagicMock(return_value=False)

    c.calldata_decoder = MagicMock()
    c.calldata_decoder.decode = MagicMock(return_value={
        "selector": "0x38ed1739", "function_name": "swapExactTokensForTokens",
        "category": "swap", "risk": "low", "params": {},
        "is_approval": False, "is_unlimited_approval": False,
    })

    return c


@pytest.fixture
def client(mock_container):
    """Create test client with mocked container."""
    from agent.firewall import create_agent_firewall_router
    from fastapi import FastAPI

    app = FastAPI()
    router = create_agent_firewall_router(mock_container)
    app.include_router(router, prefix="/api/agent")
    return TestClient(app)


def test_agent_firewall_allow(client, mock_container):
    """Transaction to safe contract returns ALLOW."""
    mock_container.risk_engine.compute_from_results.return_value = {
        "risk_score": 12, "risk_level": "LOW", "flags": [],
        "category_scores": {}, "confidence": 0.9,
    }
    resp = client.post("/api/agent/firewall", json={
        "agent_id": "agent:1",
        "transaction": {
            "from": "0xAgentWallet",
            "to": "0xSafeContract",
            "data": "0x38ed1739",
            "value": "0",
            "chain_id": 56,
        },
    }, headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "ALLOW"
    assert body["score"] == 12


def test_agent_firewall_block(client, mock_container):
    """Transaction to high-risk contract returns BLOCK."""
    mock_container.risk_engine.compute_from_results.return_value = {
        "risk_score": 91, "risk_level": "HIGH", "flags": ["honeypot"],
        "category_scores": {}, "confidence": 0.95,
    }
    resp = client.post("/api/agent/firewall", json={
        "agent_id": "agent:1",
        "transaction": {
            "from": "0xAgentWallet",
            "to": "0xScamContract",
            "data": "0x",
            "value": "1000000000000000000",
            "chain_id": 56,
        },
    }, headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "BLOCK"
    assert body["score"] == 91


def test_agent_firewall_no_api_key(client):
    """Request without API key returns 401."""
    resp = client.post("/api/agent/firewall", json={
        "agent_id": "agent:1",
        "transaction": {"from": "0x1", "to": "0x2", "chain_id": 56},
    })
    assert resp.status_code == 401


def test_agent_firewall_unregistered_agent(client, mock_container):
    """Request from unregistered agent returns 404."""
    mock_container.db.get_agent_policy = AsyncMock(return_value=None)
    resp = client.post("/api/agent/firewall", json={
        "agent_id": "unknown_agent",
        "transaction": {"from": "0x1", "to": "0x2", "chain_id": 56},
    }, headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 404


def test_agent_register(client, mock_container):
    """Register a new agent with a policy."""
    resp = client.post("/api/agent/register", json={
        "agent_id": "new_agent",
        "owner_address": "0xOwner",
        "owner_telegram": "@owner",
        "policy": {
            "auto_allow_below": 20,
            "auto_block_above": 75,
            "max_spend_per_tx_usd": 1000,
        },
    }, headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == "new_agent"
    mock_container.db.upsert_agent_policy.assert_called_once()


def test_agent_history(client, mock_container):
    """Get agent firewall history."""
    mock_container.db.get_agent_firewall_history = AsyncMock(return_value=[
        {"id": 1, "verdict": "ALLOW", "score": 12, "created_at": time.time()},
    ])
    resp = client.get("/api/agent/history?agent_id=agent:1",
                      headers={"X-API-Key": "sb_testkey"})
    assert resp.status_code == 200
    assert len(resp.json()) == 1
```

**Step 2: Run tests to verify they fail**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest tests/test_agent_firewall_api.py -v`
Expected: FAIL (ModuleNotFoundError: agent.firewall)

**Step 3: Implement the agent firewall router**

Create `agent/firewall.py`:

```python
"""Agent Transaction Firewall API — hot plane endpoints."""

import time
import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field

from agent.policy_engine import AgentPolicyEngine
from core.analyzer import AnalysisContext

logger = logging.getLogger(__name__)


# --- Request/Response Models ---

class TransactionData(BaseModel):
    sender: str = Field(alias="from")
    to: str
    data: str = "0x"
    value: str = "0"
    chain_id: int = Field(default=56, alias="chain_id")

    class Config:
        populate_by_name = True


class AgentFirewallRequest(BaseModel):
    agent_id: str
    transaction: TransactionData
    context: Optional[Dict] = None


class AgentRegisterRequest(BaseModel):
    agent_id: str
    owner_address: str
    owner_telegram: Optional[str] = None
    owner_webhook: Optional[str] = None
    policy: Optional[Dict] = None


class AgentPolicyUpdateRequest(BaseModel):
    agent_id: str
    policy: Dict


# --- Router Factory ---

def create_agent_firewall_router(container) -> APIRouter:
    """Create the agent firewall router with injected dependencies."""
    router = APIRouter(tags=["Agent Firewall"])
    policy_engine = AgentPolicyEngine()

    async def _require_api_key(request: Request) -> Dict:
        """Validate API key from header."""
        raw_key = request.headers.get("X-API-Key", "")
        if not raw_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        key_info = await container.auth_manager.validate_key(raw_key)
        if not key_info:
            raise HTTPException(status_code=401, detail="Invalid API key")
        if not await container.auth_manager.check_rate_limit(key_info):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        return key_info

    @router.post("/firewall")
    async def agent_firewall(req: AgentFirewallRequest, request: Request):
        """Check a transaction against the agent's policy and risk scoring."""
        start_ms = time.time() * 1000
        key_info = await _require_api_key(request)

        # Load agent policy
        agent_policy = await container.db.get_agent_policy(req.agent_id)
        if not agent_policy:
            raise HTTPException(status_code=404, detail=f"Agent {req.agent_id} not registered. Call /api/agent/register first.")

        tx = req.transaction
        to_addr = tx.to.lower()
        chain_id = tx.chain_id

        # 1. Check Redis verdict cache
        cached = await container.cache.get_verdict(to_addr, chain_id)
        if cached:
            # Still run policy check against cached score
            daily_spend = await container.db.get_agent_daily_spend(req.agent_id)
            tx_value_usd = _estimate_value_usd(tx.value)
            policy_result = policy_engine.evaluate(
                policy=agent_policy.get("policy", {}),
                risk_score=cached["score"],
                target_address=to_addr,
                tx_value_usd=tx_value_usd,
                daily_spend_usd=daily_spend,
            )
            verdict = policy_result.verdict
            latency = time.time() * 1000 - start_ms
            await container.db.record_agent_firewall_event(
                agent_id=req.agent_id, chain_id=chain_id,
                tx_to=to_addr, tx_value=tx.value,
                verdict=verdict, score=cached["score"],
                flags=cached.get("flags", []),
                policy_result=policy_result.checks,
                latency_ms=latency,
            )
            return {
                "verdict": verdict,
                "score": cached["score"],
                "flags": cached.get("flags", []),
                "policy_check": {
                    "passed": policy_result.all_passed,
                    "checks": policy_result.checks,
                    "failed": policy_result.failed_checks,
                    "needs_owner_approval": policy_result.needs_owner_approval,
                },
                "cached": True,
                "latency_ms": round(latency, 1),
            }

        # 2. Check SQLite score cache
        db_cached = await container.db.get_contract_score(to_addr, chain_id, max_age_seconds=300)

        if db_cached:
            risk_score = db_cached["risk_score"]
            flags = db_cached.get("flags", [])
        else:
            # 3. Run analyzer pipeline
            is_token = await container.web3_client.is_token_contract(to_addr, chain_id)
            ctx = AnalysisContext(
                address=to_addr,
                chain_id=chain_id,
                from_address=tx.sender,
                is_token=is_token,
            )
            results = await container.registry.run_all(ctx)
            risk_output = container.risk_engine.compute_from_results(results, is_token)
            risk_score = risk_output["risk_score"]
            flags = risk_output.get("flags", [])

            # Cache in DB
            await container.db.upsert_contract_score(
                address=to_addr, chain_id=chain_id,
                risk_score=risk_score,
                risk_level=risk_output.get("risk_level", "UNKNOWN"),
                category_scores=risk_output.get("category_scores"),
                flags=flags,
                confidence=risk_output.get("confidence"),
            )

        # Cache in Redis for next hit
        await container.cache.set_verdict(to_addr, chain_id, {
            "score": risk_score, "flags": flags,
        })

        # 4. Policy check
        daily_spend = await container.db.get_agent_daily_spend(req.agent_id)
        tx_value_usd = _estimate_value_usd(tx.value)
        policy_result = policy_engine.evaluate(
            policy=agent_policy.get("policy", {}),
            risk_score=risk_score,
            target_address=to_addr,
            tx_value_usd=tx_value_usd,
            daily_spend_usd=daily_spend,
        )
        verdict = policy_result.verdict

        latency = time.time() * 1000 - start_ms

        # Record event
        await container.db.record_agent_firewall_event(
            agent_id=req.agent_id, chain_id=chain_id,
            tx_to=to_addr, tx_value=tx.value,
            verdict=verdict, score=risk_score, flags=flags,
            policy_result=policy_result.checks,
            latency_ms=latency,
        )

        # Track spending if allowed
        if verdict == "ALLOW" and tx_value_usd > 0:
            await container.db.record_agent_spend(req.agent_id, tx_value_usd)

        return {
            "verdict": verdict,
            "score": risk_score,
            "flags": flags,
            "policy_check": {
                "passed": policy_result.all_passed,
                "checks": policy_result.checks,
                "failed": policy_result.failed_checks,
                "needs_owner_approval": policy_result.needs_owner_approval,
            },
            "cached": False,
            "latency_ms": round(latency, 1),
        }

    @router.post("/register")
    async def register_agent(req: AgentRegisterRequest, request: Request):
        """Register an agent with a firewall policy."""
        key_info = await _require_api_key(request)
        await container.db.upsert_agent_policy(
            agent_id=req.agent_id,
            owner_address=req.owner_address,
            owner_telegram=req.owner_telegram,
            owner_webhook=req.owner_webhook,
            tier=key_info.get("tier", "free"),
            policy=req.policy or {},
        )
        return {
            "agent_id": req.agent_id,
            "status": "registered",
            "tier": key_info.get("tier", "free"),
        }

    @router.put("/policy")
    async def update_policy(req: AgentPolicyUpdateRequest, request: Request):
        """Update an agent's firewall policy."""
        key_info = await _require_api_key(request)
        existing = await container.db.get_agent_policy(req.agent_id)
        if not existing:
            raise HTTPException(status_code=404, detail=f"Agent {req.agent_id} not registered")
        await container.db.upsert_agent_policy(
            agent_id=req.agent_id,
            owner_address=existing["owner_address"],
            tier=existing["tier"],
            policy=req.policy,
        )
        return {"agent_id": req.agent_id, "status": "updated"}

    @router.get("/policy")
    async def get_policy(agent_id: str, request: Request):
        """Get an agent's current policy."""
        await _require_api_key(request)
        policy = await container.db.get_agent_policy(agent_id)
        if not policy:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not registered")
        return policy

    @router.get("/history")
    async def get_history(agent_id: str, request: Request, limit: int = 50):
        """Get an agent's firewall check history."""
        await _require_api_key(request)
        return await container.db.get_agent_firewall_history(agent_id, limit=limit)

    return router


def _estimate_value_usd(value_wei: str) -> float:
    """Rough BNB→USD estimate. Replace with oracle in production."""
    try:
        wei = int(value_wei) if value_wei else 0
        bnb = wei / 1e18
        return bnb * 600  # ~$600/BNB estimate — replace with price feed
    except (ValueError, TypeError):
        return 0.0
```

**Step 4: Wire CacheService into container and mount router in api.py**

In `core/container.py`, add import and init:

After the existing imports at the top, add:
```python
from services.cache import CacheService
from agent.policy_engine import AgentPolicyEngine
```

In `ServiceContainer.__init__`, after `self.tenderly_simulator = TenderlySimulator()`, add:
```python
        # Redis cache (verdict caching + rate limiting)
        self.cache = CacheService(
            redis_url=settings.redis_url,
            ttl=settings.cache_duration,
        )
```

In `ServiceContainer.startup()`, before the final logger.info lines, add:
```python
        await self.cache.connect()
```

In `ServiceContainer.shutdown()`, before `logger.info("ServiceContainer shut down")`, add:
```python
        await self.cache.close()
```

In `api.py`, mount the agent firewall router. Find where routes are defined (after app creation) and add:
```python
from agent.firewall import create_agent_firewall_router

# Mount agent firewall routes (V3)
agent_firewall_router = create_agent_firewall_router(container)
app.include_router(agent_firewall_router, prefix="/api/agent")
```

Note: The exact location in `api.py` depends on where `container` is accessible. It should be inside the `lifespan` context or after the container is bound to globals. Follow the existing pattern of how `container` is used in other endpoint handlers.

**Step 5: Run tests to verify they pass**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest tests/test_agent_firewall_api.py -v`
Expected: All 6 tests PASS

**Step 6: Run full test suite**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest --tb=short -q`
Expected: 278+ passed (no regressions)

**Step 7: Commit**

```bash
git add agent/firewall.py agent/policy_engine.py tests/test_agent_firewall_api.py core/container.py api.py services/cache.py
git commit -m "feat(v3): add agent transaction firewall API with policy engine and Redis caching"
```

---

## Task 5: Build the Python SDK package scaffold

**Files:**
- Create: `sdk/python/shieldbot/__init__.py`
- Create: `sdk/python/shieldbot/client.py`
- Create: `sdk/python/shieldbot/models.py`
- Create: `sdk/python/setup.py`
- Create: `sdk/python/tests/test_client.py`

**Step 1: Write failing tests for the SDK client**

Create `sdk/python/tests/__init__.py` (empty) and `sdk/python/tests/test_client.py`:

```python
"""Tests for the ShieldBot Python SDK client."""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from shieldbot.client import ShieldBot
from shieldbot.models import Verdict


@pytest.fixture
def sb():
    return ShieldBot(api_key="sb_test", agent_id="agent:1", base_url="http://localhost:8000")


@pytest.mark.asyncio
async def test_check_returns_verdict(sb):
    """check() returns a Verdict object."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "verdict": "ALLOW", "score": 12, "flags": [],
        "policy_check": {"passed": True, "checks": {}, "failed": [], "needs_owner_approval": False},
        "cached": False, "latency_ms": 100,
    }
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        verdict = await sb.check({
            "from": "0xAgent", "to": "0xTarget", "chain_id": 56,
        })
    assert isinstance(verdict, Verdict)
    assert verdict.allowed is True
    assert verdict.score == 12
    assert verdict.verdict == "ALLOW"


@pytest.mark.asyncio
async def test_check_block_verdict(sb):
    """BLOCK verdict sets allowed=False."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "verdict": "BLOCK", "score": 91, "flags": ["honeypot"],
        "policy_check": {"passed": False, "checks": {}, "failed": ["risk_threshold"], "needs_owner_approval": False},
        "cached": False, "latency_ms": 380,
    }
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        verdict = await sb.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert verdict.allowed is False
    assert verdict.blocked is True
    assert "honeypot" in verdict.flags


@pytest.mark.asyncio
async def test_local_cache_hit(sb):
    """Second check for same address uses local cache."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "verdict": "ALLOW", "score": 5, "flags": [],
        "policy_check": {"passed": True, "checks": {}, "failed": [], "needs_owner_approval": False},
        "cached": False, "latency_ms": 100,
    }
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp) as mock_post:
        await sb.check({"from": "0xA", "to": "0xSame", "chain_id": 56})
        v2 = await sb.check({"from": "0xA", "to": "0xSame", "chain_id": 56})
    # Only 1 HTTP call — second was cached
    assert mock_post.call_count == 1
    assert v2.score == 5


def test_verdict_properties():
    """Verdict model properties work correctly."""
    v = Verdict(verdict="ALLOW", score=12, flags=[], evidence=None,
                policy_check={}, cached=False, latency_ms=100)
    assert v.allowed is True
    assert v.blocked is False

    v2 = Verdict(verdict="BLOCK", score=91, flags=["honeypot"], evidence="scam",
                 policy_check={}, cached=False, latency_ms=380)
    assert v2.allowed is False
    assert v2.blocked is True
```

**Step 2: Run tests to verify they fail**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot/sdk/python" && python -m pytest tests/test_client.py -v`
Expected: FAIL (ModuleNotFoundError)

**Step 3: Create SDK models**

Create `sdk/python/shieldbot/__init__.py`:
```python
from shieldbot.client import ShieldBot
from shieldbot.models import Verdict

__all__ = ["ShieldBot", "Verdict"]
__version__ = "0.1.0"
```

Create `sdk/python/shieldbot/models.py`:
```python
"""Data models for the ShieldBot SDK."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Verdict:
    """Result of a ShieldBot transaction check."""
    verdict: str  # "ALLOW" | "WARN" | "BLOCK"
    score: float
    flags: List[str] = field(default_factory=list)
    evidence: Optional[str] = None
    policy_check: Optional[Dict] = None
    cached: bool = False
    latency_ms: float = 0

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    @property
    def blocked(self) -> bool:
        return self.verdict == "BLOCK"
```

**Step 4: Create SDK client**

Create `sdk/python/shieldbot/client.py`:
```python
"""ShieldBot Python SDK — async client with local verdict caching."""

import time
import logging
from typing import Dict, Optional
from collections import OrderedDict

import httpx

from shieldbot.models import Verdict

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.shieldbotsecurity.online"


class ShieldBot:
    """Async ShieldBot client with local verdict cache and fail-cached mode."""

    def __init__(
        self,
        api_key: str,
        agent_id: str,
        base_url: str = DEFAULT_BASE_URL,
        cache_size: int = 10000,
        cache_ttl: int = 86400,
        fail_mode: str = "cached",
        timeout: float = 10.0,
    ):
        self.api_key = api_key
        self.agent_id = agent_id
        self.base_url = base_url.rstrip("/")
        self._cache_size = cache_size
        self._cache_ttl = cache_ttl
        self._fail_mode = fail_mode
        self._timeout = timeout
        self._cache: OrderedDict = OrderedDict()
        self._http: Optional[httpx.AsyncClient] = None

    def _get_http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=self.base_url,
                headers={"X-API-Key": self.api_key},
                timeout=self._timeout,
            )
        return self._http

    def _cache_key(self, to: str, chain_id: int) -> str:
        return f"{to.lower()}:{chain_id}"

    def _get_cached(self, key: str) -> Optional[Verdict]:
        if key in self._cache:
            entry = self._cache[key]
            if time.time() - entry["ts"] < self._cache_ttl:
                self._cache.move_to_end(key)
                return entry["verdict"]
            else:
                del self._cache[key]
        return None

    def _set_cached(self, key: str, verdict: Verdict):
        self._cache[key] = {"verdict": verdict, "ts": time.time()}
        if len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)

    async def check(self, transaction: Dict) -> Verdict:
        """Check a transaction against the agent firewall.

        Args:
            transaction: Dict with keys: from, to, data (optional), value (optional), chain_id.

        Returns:
            Verdict with allowed/blocked status, score, flags, and evidence.
        """
        to_addr = transaction.get("to", "")
        chain_id = transaction.get("chain_id", 56)
        cache_key = self._cache_key(to_addr, chain_id)

        # Check local cache
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        # Call API
        try:
            http = self._get_http()
            resp = await http.post("/api/agent/firewall", json={
                "agent_id": self.agent_id,
                "transaction": transaction,
            })
            if resp.status_code == 200:
                data = resp.json()
                verdict = Verdict(
                    verdict=data["verdict"],
                    score=data["score"],
                    flags=data.get("flags", []),
                    evidence=data.get("evidence"),
                    policy_check=data.get("policy_check"),
                    cached=data.get("cached", False),
                    latency_ms=data.get("latency_ms", 0),
                )
                self._set_cached(cache_key, verdict)
                return verdict
            else:
                logger.warning(f"ShieldBot API returned {resp.status_code}: {resp.text}")
                raise httpx.HTTPStatusError(
                    f"API error: {resp.status_code}",
                    request=resp.request, response=resp,
                )
        except Exception as e:
            # Fail-cached mode
            if self._fail_mode == "cached":
                cached = self._get_cached(cache_key)
                if cached is not None:
                    logger.info(f"Using cached verdict for {to_addr} (API unavailable)")
                    return cached
            logger.error(f"ShieldBot API error: {e}")
            # Fail-open or fail-closed based on config
            if self._fail_mode in ("open", "cached"):
                return Verdict(verdict="ALLOW", score=0, flags=["api_unavailable"])
            else:
                return Verdict(verdict="BLOCK", score=100, flags=["api_unavailable"])

    async def close(self):
        """Close the HTTP client."""
        if self._http:
            await self._http.aclose()
```

**Step 5: Create setup.py**

Create `sdk/python/setup.py`:
```python
from setuptools import setup, find_packages

setup(
    name="shieldbot",
    version="0.1.0",
    description="ShieldBot SDK — AI agent transaction firewall for BNB Chain",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.24.0",
    ],
)
```

**Step 6: Run tests**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot/sdk/python" && pip install -e . && python -m pytest tests/test_client.py -v`
Expected: All 4 tests PASS

**Step 7: Commit**

```bash
git add sdk/
git commit -m "feat(v3): add Python SDK with async client, local caching, and fail-cached mode"
```

---

## Task 6: Integration test — full pipeline end-to-end

**Files:**
- Create: `tests/test_agent_firewall_integration.py`

**Step 1: Write integration test**

Create `tests/test_agent_firewall_integration.py`:

```python
"""Integration test: agent registers → checks transaction → gets verdict → history recorded."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


@pytest.fixture
def full_client():
    """Test client with real DB, mocked external services."""
    import tempfile
    import os
    from core.database import Database
    from core.auth import AuthManager
    from services.cache import CacheService
    from agent.firewall import create_agent_firewall_router
    from fastapi import FastAPI

    db_path = os.path.join(tempfile.mkdtemp(), "test.db")

    class FakeContainer:
        pass

    container = FakeContainer()
    container.db = Database(db_path)

    # Mock external services
    container.cache = MagicMock()
    container.cache.get_verdict = AsyncMock(return_value=None)
    container.cache.set_verdict = AsyncMock()
    container.cache.check_rate_limit = AsyncMock(return_value=True)

    container.auth_manager = MagicMock()
    container.auth_manager.validate_key = AsyncMock(return_value={
        "key_id": "k1", "owner": "test", "tier": "agent",
        "rpm_limit": 500, "daily_limit": 50000,
    })
    container.auth_manager.check_rate_limit = AsyncMock(return_value=True)
    container.auth_manager.record_usage = AsyncMock()

    container.registry = MagicMock()
    container.registry.run_all = AsyncMock(return_value=[])

    container.risk_engine = MagicMock()
    container.risk_engine.compute_from_results = MagicMock(return_value={
        "risk_score": 15, "risk_level": "LOW", "flags": [],
        "category_scores": {}, "confidence": 0.9,
    })

    container.web3_client = MagicMock()
    container.web3_client.is_valid_address = MagicMock(return_value=True)
    container.web3_client.is_contract = AsyncMock(return_value=True)
    container.web3_client.is_token_contract = AsyncMock(return_value=True)

    container.tenderly_simulator = MagicMock()
    container.tenderly_simulator.is_enabled = MagicMock(return_value=False)

    container.calldata_decoder = MagicMock()
    container.calldata_decoder.decode = MagicMock(return_value={
        "selector": "0x38ed1739", "function_name": "swapExactTokensForTokens",
        "category": "swap", "risk": "low", "params": {},
        "is_approval": False, "is_unlimited_approval": False,
    })

    # Init DB synchronously for test
    import asyncio
    asyncio.get_event_loop().run_until_complete(container.db.initialize())

    app = FastAPI()
    router = create_agent_firewall_router(container)
    app.include_router(router, prefix="/api/agent")

    yield TestClient(app), container

    asyncio.get_event_loop().run_until_complete(container.db.close())


def test_full_agent_lifecycle(full_client):
    """Register agent → check transaction → verify history."""
    client, container = full_client
    headers = {"X-API-Key": "sb_testkey"}

    # 1. Register
    resp = client.post("/api/agent/register", json={
        "agent_id": "lifecycle_agent",
        "owner_address": "0xOwner",
        "policy": {
            "auto_allow_below": 25,
            "auto_block_above": 70,
            "max_spend_per_tx_usd": 500,
        },
    }, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "registered"

    # 2. Check a safe transaction
    resp = client.post("/api/agent/firewall", json={
        "agent_id": "lifecycle_agent",
        "transaction": {
            "from": "0xAgentWallet",
            "to": "0xSafeToken",
            "data": "0x",
            "value": "0",
            "chain_id": 56,
        },
    }, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "ALLOW"
    assert body["score"] == 15

    # 3. Check history is recorded
    resp = client.get("/api/agent/history?agent_id=lifecycle_agent", headers=headers)
    assert resp.status_code == 200
    history = resp.json()
    assert len(history) == 1
    assert history[0]["verdict"] == "ALLOW"

    # 4. Check a high-risk transaction
    container.risk_engine.compute_from_results.return_value = {
        "risk_score": 91, "risk_level": "HIGH", "flags": ["honeypot"],
        "category_scores": {}, "confidence": 0.95,
    }
    container.cache.get_verdict = AsyncMock(return_value=None)  # no cache

    resp = client.post("/api/agent/firewall", json={
        "agent_id": "lifecycle_agent",
        "transaction": {
            "from": "0xAgentWallet",
            "to": "0xScamToken",
            "data": "0x",
            "value": "1000000000000000000",
            "chain_id": 56,
        },
    }, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "BLOCK"
    assert body["score"] == 91

    # 5. History now has 2 entries
    resp = client.get("/api/agent/history?agent_id=lifecycle_agent", headers=headers)
    assert len(resp.json()) == 2
```

**Step 2: Run integration test**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest tests/test_agent_firewall_integration.py -v`
Expected: PASS

**Step 3: Run full test suite — final check**

Run: `cd "C:/Users/GUDMAN/Desktop/Github files/shieldbot" && python -m pytest --tb=short -q`
Expected: 285+ passed (all existing + all new)

**Step 4: Commit**

```bash
git add tests/test_agent_firewall_integration.py
git commit -m "test(v3): add agent firewall integration test — full lifecycle"
```

---

## Task 7: Install Redis on VPS and deploy

**Step 1: Install Redis on VPS**

```bash
ssh root@75.119.153.252 "apt update && apt install -y redis-server && systemctl enable redis-server && systemctl start redis-server && redis-cli ping"
```
Expected: `PONG`

**Step 2: Add REDIS_URL to .env on VPS**

```bash
ssh root@75.119.153.252 "echo 'REDIS_URL=redis://localhost:6379/0' >> /opt/shieldbot/.env"
```

**Step 3: Install new Python dependency**

```bash
ssh root@75.119.153.252 "cd /opt/shieldbot && pip install 'redis[hiredis]==5.2.1'"
```

**Step 4: Deploy via git pull + restart**

```bash
ssh root@75.119.153.252 "cd /opt/shieldbot && git clean -fd landing/ && git pull origin main && systemctl restart shieldbot-api"
```

**Step 5: Verify health**

```bash
curl https://api.shieldbotsecurity.online/api/health
```
Expected: `{"status": "ok"}`

**Step 6: Smoke test the agent firewall endpoint**

```bash
# Create an API key (via admin endpoint or directly)
# Then test the agent registration
curl -X POST https://api.shieldbotsecurity.online/api/agent/register \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sb_<your_key>" \
  -d '{"agent_id": "test:1", "owner_address": "0x0000000000000000000000000000000000000000", "policy": {"auto_allow_below": 25, "auto_block_above": 70}}'
```
Expected: `{"agent_id": "test:1", "status": "registered", "tier": "..."}`

---

## Summary

| Task | What it builds | New tests |
|------|---------------|-----------|
| 1 | Redis CacheService | 6 |
| 2 | agent_policies DB table + CRUD | 5 |
| 3 | Threshold policy engine | 10 |
| 4 | Agent firewall API endpoints | 6 |
| 5 | Python SDK package | 4 |
| 6 | Integration test (full lifecycle) | 1 |
| 7 | VPS deployment | 0 (manual) |
| **Total** | | **32 new tests** |

After all tasks: ~289+ tests passing, agent firewall API live, Python SDK ready for `pip install`.
