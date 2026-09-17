"""Tests for agent.sentinel — event-driven feedback loop."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from agent.sentinel import Sentinel


def scan_result(score, complete=True):
    """Shape of RiskEngine.compute_from_results: the score is rug_probability."""
    return {
        "rug_probability": score,
        "risk_level": "LOW" if score <= 30 else "HIGH",
        "risk_archetype": "unknown",
        "critical_flags": [],
        "confidence_level": 80,
        "category_scores": {},
        "status": "ok" if complete else "unknown",
        "coverage": {"structural": 1, "honeypot": 1 if complete else 0},
        "coverage_reasons": {} if complete else {"honeypot": "Honeypot simulation unavailable"},
    }


@pytest.fixture
def sentinel():
    tools = MagicMock()
    tools.auto_watch_deployer = AsyncMock()
    tools.scan_contract = AsyncMock(return_value=scan_result(90))

    db = MagicMock()
    db.insert_agent_finding = AsyncMock()

    ai = MagicMock()
    ai.is_available = MagicMock(return_value=False)

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
    """A complete scan scoring >= 71 → finding with action_taken='blocked'."""
    sentinel.tools.scan_contract = AsyncMock(return_value=scan_result(90))

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
    """A complete scan scoring < 71 → finding with action_taken='watched'."""
    sentinel.tools.scan_contract = AsyncMock(return_value=scan_result(40))

    await sentinel.on_deployer_flagged(
        deployer="0xdead",
        new_contract="0xnew",
        chain_id=56,
    )

    sentinel.tools.scan_contract.assert_awaited_once_with("0xnew", 56)
    call_kwargs = sentinel.db.insert_agent_finding.call_args.kwargs
    assert call_kwargs["action_taken"] == "watched"
    assert call_kwargs["risk_score"] == 40


@pytest.mark.asyncio
async def test_on_deployer_flagged_blocks_a_high_score_from_the_engine(sentinel):
    """The engine reports rug_probability, and a high one must be blocked."""
    sentinel.tools.scan_contract = AsyncMock(return_value=scan_result(95, complete=False))

    await sentinel.on_deployer_flagged(deployer="0xdead", new_contract="0xnew", chain_id=4663)

    call_kwargs = sentinel.db.insert_agent_finding.call_args.kwargs
    assert call_kwargs["action_taken"] == "blocked"
    assert call_kwargs["risk_score"] == 95
    assert call_kwargs["chain_id"] == 4663


@pytest.mark.asyncio
@pytest.mark.parametrize("result", [
    scan_result(5, complete=False),
    {**scan_result(5), "partial": True},
    {key: value for key, value in scan_result(5).items() if key != "rug_probability"},
])
async def test_on_deployer_flagged_never_records_an_incomplete_scan_as_watched(sentinel, result):
    """An incomplete scan is recorded as unknown, with the score the engine gave."""
    sentinel.tools.scan_contract = AsyncMock(return_value=result)

    await sentinel.on_deployer_flagged(deployer="0xdead", new_contract="0xnew", chain_id=56)

    call_kwargs = sentinel.db.insert_agent_finding.call_args.kwargs
    assert call_kwargs["action_taken"] == "unknown"
    assert call_kwargs["risk_score"] == result.get("rug_probability")
