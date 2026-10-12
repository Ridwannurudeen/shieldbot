"""Tests for agent policy CRUD in the database."""

import pytest
import pytest_asyncio
from argparse import Namespace
from unittest.mock import AsyncMock, MagicMock

from core.auth import AuthManager
from core.database import Database
from scripts import manage_agents


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
async def test_list_unowned_agent_policies_returns_unowned_and_inactive_key_rows(db):
    """The migration listing surfaces unowned rows and rows stranded by inactive keys."""
    auth = AuthManager(db)
    active_key = await auth.create_key(owner="active")
    inactive_key = await auth.create_key(owner="inactive")
    await auth.deactivate_key(inactive_key["key_id"])
    await db.upsert_agent_policy(
        "null-key", "0xOwner", owner_telegram="@null", owner_webhook="https://null.example", policy={},
    )
    await db.upsert_agent_policy("empty-key", "0xOwner", policy={}, registered_by_key="")
    await db.upsert_agent_policy(
        "owned", "0xOwner", policy={}, registered_by_key=active_key["key_id"],
    )
    await db.upsert_agent_policy(
        "inactive-key", "0xOwner", owner_telegram="@inactive", owner_webhook="https://inactive.example",
        policy={}, registered_by_key=inactive_key["key_id"],
    )

    rows = await db.list_unowned_agent_policies()

    assert {row["agent_id"] for row in rows} == {"null-key", "empty-key", "inactive-key"}
    null_key = next(row for row in rows if row["agent_id"] == "null-key")
    assert null_key["owner_address"] == "0xowner"
    assert null_key["owner_telegram"] == "@null"
    assert null_key["owner_webhook"] == "https://null.example"
    assert isinstance(null_key["created_at"], float)


@pytest.mark.asyncio
async def test_claim_unowned_agent_policy_requires_an_active_key(db):
    """A claim is available only to an active API key and only once."""
    auth = AuthManager(db)
    active_key = await auth.create_key(owner="active")
    inactive_key = await auth.create_key(owner="inactive")
    await auth.deactivate_key(inactive_key["key_id"])
    await db.upsert_agent_policy("unowned", "0xOwner", policy={})
    await db.upsert_agent_policy(
        "owned", "0xOwner", policy={}, registered_by_key=active_key["key_id"],
    )
    await db.upsert_agent_policy("missing-key", "0xOwner", policy={})
    await db.upsert_agent_policy("inactive-key", "0xOwner", policy={})

    assert await db.claim_unowned_agent_policy("unowned", active_key["key_id"])
    assert not await db.claim_unowned_agent_policy("owned", active_key["key_id"])
    assert not await db.claim_unowned_agent_policy("missing-key", "no-such-key")
    assert not await db.claim_unowned_agent_policy("inactive-key", inactive_key["key_id"])
    assert (await db.get_agent_policy("unowned"))["registered_by_key"] == active_key["key_id"]
    assert (await db.get_agent_policy("inactive-key"))["registered_by_key"] is None


@pytest.mark.asyncio
async def test_get_agent_policy_claim_refusal_reports_every_cause_and_retry_state(db):
    """Claim diagnostics distinguish durable refusals from a concurrent state change."""
    auth = AuthManager(db)
    active_key = await auth.create_key(owner="active")
    inactive_key = await auth.create_key(owner="inactive")
    await auth.deactivate_key(inactive_key["key_id"])
    await db.upsert_agent_policy(
        "owned", "0xOwner", policy={}, registered_by_key=active_key["key_id"],
    )
    await db.upsert_agent_policy("unowned", "0xOwner", policy={})

    assert await db.get_agent_policy_claim_refusal("missing", active_key["key_id"]) == "agent_missing"
    assert await db.get_agent_policy_claim_refusal("owned", active_key["key_id"]) == "agent_owned"
    assert await db.get_agent_policy_claim_refusal("unowned", inactive_key["key_id"]) == "key_inactive"
    assert await db.get_agent_policy_claim_refusal("unowned", active_key["key_id"]) is None


@pytest.mark.asyncio
async def test_release_agent_policy_clears_ownership_and_reports_refusals(db):
    """Only an owned policy can be released; missing and already-unowned rows are distinct."""
    auth = AuthManager(db)
    key = await auth.create_key(owner="owner")
    await db.upsert_agent_policy("owned", "0xOwner", policy={}, registered_by_key=key["key_id"])
    await db.upsert_agent_policy("unowned", "0xOwner", policy={})

    assert await db.release_agent_policy("owned")
    assert (await db.get_agent_policy("owned"))["registered_by_key"] is None
    assert not await db.release_agent_policy("missing")
    assert await db.get_agent_policy_release_refusal("missing") == "agent_missing"
    assert not await db.release_agent_policy("unowned")
    assert await db.get_agent_policy_release_refusal("unowned") == "agent_unowned"


@pytest.mark.asyncio
async def test_manage_agents_lists_contact_fields(capsys):
    """The operator listing prints the legacy attribution leads used for migration."""
    db = MagicMock()
    db.list_unowned_agent_policies = AsyncMock(return_value=[{
        "agent_id": "agent:legacy",
        "owner_address": "0xowner",
        "owner_telegram": "@owner",
        "owner_webhook": "https://owner.example",
        "created_at": 123.0,
    }])

    await manage_agents.cmd_list_unowned(Namespace(), db)

    output = capsys.readouterr().out
    assert "Telegram" in output
    assert "Webhook" in output
    assert "@owner" in output
    assert "https://owner.example" in output


@pytest.mark.asyncio
async def test_manage_agents_release_requires_confirmation(capsys):
    """Release does not make a row claimable until the operator confirms it."""
    db = MagicMock()
    db.release_agent_policy = AsyncMock()

    await manage_agents.cmd_release(Namespace(agent_id="agent:owned", confirm=False), db)

    assert capsys.readouterr().out == (
        "Release refused: rerun with --confirm to make agent agent:owned claimable.\n"
    )
    db.release_agent_policy.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("released", "refusal", "expected"),
    [
        (True, None, "Agent agent:owned released and ready to be claimed.\n"),
        (False, "agent_missing", "Release refused: agent agent:owned does not exist.\n"),
        (False, "agent_unowned", "Release refused: agent agent:owned is already unowned.\n"),
        (False, None, "Release refused: policy state changed; retry the release.\n"),
    ],
)
async def test_manage_agents_release_reports_result(capsys, released, refusal, expected):
    """Release reports success, durable refusals, and its concurrent-change fallback."""
    db = MagicMock()
    db.release_agent_policy = AsyncMock(return_value=released)
    db.get_agent_policy_release_refusal = AsyncMock(return_value=refusal)

    await manage_agents.cmd_release(Namespace(agent_id="agent:owned", confirm=True), db)

    assert capsys.readouterr().out == expected
    db.release_agent_policy.assert_awaited_once_with("agent:owned")
    if released:
        db.get_agent_policy_release_refusal.assert_not_awaited()
    else:
        db.get_agent_policy_release_refusal.assert_awaited_once_with("agent:owned")


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
