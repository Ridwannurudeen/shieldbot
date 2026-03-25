"""Tests for agent policy CRUD in the database."""

import pytest
import pytest_asyncio
import json
from core.database import Database


@pytest_asyncio.fixture
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
    assert result["owner_address"] == "0xowner"
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
