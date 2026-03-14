"""Tests for agent.sentinel — event-driven feedback loop."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from agent.sentinel import Sentinel


@pytest.fixture
def sentinel():
    tools = MagicMock()
    tools.auto_watch_deployer = AsyncMock()
    tools.scan_contract = AsyncMock(
        return_value={"risk_score": 90, "risk_level": "HIGH", "flags": ["unverified"]}
    )

    db = MagicMock()
    db.insert_agent_finding = AsyncMock()

    ai = MagicMock()
    ai.client = None  # disabled for most tests

    return Sentinel(tools=tools, db=db, ai_analyzer=ai)


# --- on_scan_blocked ---


@pytest.mark.asyncio
async def test_on_scan_blocked_watches_deployer(sentinel):
    """High-risk block with a known deployer should auto-watch and log finding."""
    await sentinel.on_scan_blocked(
        address="0xabc",
        deployer="0xdead",
        chain_id=56,
        risk_score=85,
    )

    sentinel.tools.auto_watch_deployer.assert_awaited_once_with(
        "0xdead",
        reason="auto: blocked 0xabc (score=85)",
        chain_id=56,
    )
    sentinel.db.insert_agent_finding.assert_awaited_once()
    call_kwargs = sentinel.db.insert_agent_finding.call_args.kwargs
    assert call_kwargs["finding_type"] == "sentinel_event"
    assert call_kwargs["address"] == "0xabc"
    assert call_kwargs["deployer"] == "0xdead"
    assert call_kwargs["action_taken"] == "watched"
    assert call_kwargs["risk_score"] == 85


@pytest.mark.asyncio
async def test_on_scan_blocked_skips_low_risk(sentinel):
    """Score below 71 should skip entirely."""
    await sentinel.on_scan_blocked(
        address="0xabc",
        deployer="0xdead",
        chain_id=56,
        risk_score=50,
    )

    sentinel.tools.auto_watch_deployer.assert_not_awaited()
    sentinel.db.insert_agent_finding.assert_not_awaited()


@pytest.mark.asyncio
async def test_on_scan_blocked_skips_no_deployer(sentinel):
    """No deployer should skip entirely."""
    await sentinel.on_scan_blocked(
        address="0xabc",
        deployer=None,
        chain_id=56,
        risk_score=85,
    )

    sentinel.tools.auto_watch_deployer.assert_not_awaited()
    sentinel.db.insert_agent_finding.assert_not_awaited()


@pytest.mark.asyncio
async def test_on_scan_blocked_never_crashes(sentinel):
    """Even if auto_watch raises, the caller must not see an exception."""
    sentinel.tools.auto_watch_deployer = AsyncMock(
        side_effect=RuntimeError("boom")
    )

    # Should NOT raise
    await sentinel.on_scan_blocked(
        address="0xabc",
        deployer="0xdead",
        chain_id=56,
        risk_score=90,
    )


# --- on_deployer_flagged ---


@pytest.mark.asyncio
async def test_on_deployer_flagged_high_risk(sentinel):
    """Scan returns risk >= 71 → finding with action_taken='blocked'."""
    sentinel.tools.scan_contract = AsyncMock(
        return_value={"risk_score": 90, "risk_level": "HIGH", "flags": ["unverified"]}
    )

    await sentinel.on_deployer_flagged(
        deployer="0xdead",
        new_contract="0xnew",
        chain_id=56,
    )

    sentinel.tools.scan_contract.assert_awaited_once_with("0xnew", 56)
    call_kwargs = sentinel.db.insert_agent_finding.call_args.kwargs
    assert call_kwargs["action_taken"] == "blocked"
    assert call_kwargs["risk_score"] == 90


@pytest.mark.asyncio
async def test_on_deployer_flagged_low_risk(sentinel):
    """Scan returns risk < 71 → finding with action_taken='watched'."""
    sentinel.tools.scan_contract = AsyncMock(
        return_value={"risk_score": 40, "risk_level": "LOW", "flags": []}
    )

    await sentinel.on_deployer_flagged(
        deployer="0xdead",
        new_contract="0xnew",
        chain_id=56,
    )

    sentinel.tools.scan_contract.assert_awaited_once_with("0xnew", 56)
    call_kwargs = sentinel.db.insert_agent_finding.call_args.kwargs
    assert call_kwargs["action_taken"] == "watched"
    assert call_kwargs["risk_score"] == 40
