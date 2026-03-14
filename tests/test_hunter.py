"""Tests for agent.hunter — scheduled threat sweep loop."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.hunter import Hunter


@pytest.fixture
def tools():
    t = MagicMock()
    t.scan_contract = AsyncMock(
        return_value={"risk_score": 80, "risk_level": "HIGH", "flags": ["unverified"]}
    )
    t.auto_watch_deployer = AsyncMock()
    return t


@pytest.fixture
def db():
    d = MagicMock()
    d.get_watched_deployers = AsyncMock(return_value=[])
    d.get_tracked_pairs = AsyncMock(return_value=[])
    d.update_tracked_pair_status = AsyncMock()
    d.insert_agent_finding = AsyncMock()
    return d


@pytest.fixture
def ai():
    a = MagicMock()
    a.client = None  # disabled by default
    return a


@pytest.fixture
def sentinel():
    return MagicMock()


@pytest.fixture
def hunter(tools, db, ai, sentinel):
    return Hunter(tools=tools, db=db, ai_analyzer=ai, sentinel=sentinel)


# --- sweep orchestration ---


@pytest.mark.asyncio
async def test_sweep_runs_all_phases(hunter):
    """sweep() should call all three sub-methods."""
    hunter._check_watched_deployers = AsyncMock(return_value=[])
    hunter._recheck_warn_contracts = AsyncMock(return_value=[])
    hunter._scan_new_pairs = AsyncMock(return_value=[])

    result = await hunter.sweep()

    hunter._check_watched_deployers.assert_awaited_once()
    hunter._recheck_warn_contracts.assert_awaited_once()
    hunter._scan_new_pairs.assert_awaited_once()
    assert result == []


@pytest.mark.asyncio
async def test_sweep_aggregates_flagged(hunter):
    """sweep() should combine flagged results from all phases."""
    hunter._check_watched_deployers = AsyncMock(return_value=["0xaaa"])
    hunter._recheck_warn_contracts = AsyncMock(return_value=["0xbbb"])
    hunter._scan_new_pairs = AsyncMock(return_value=[])

    result = await hunter.sweep()
    assert result == ["0xaaa", "0xbbb"]


# --- _check_watched_deployers ---


@pytest.mark.asyncio
async def test_check_watched_deployers_returns_list(hunter, db):
    """Should return an empty list when deployers exist but no new contracts found."""
    db.get_watched_deployers = AsyncMock(return_value=[
        {"deployer_address": "0xdead", "chain_id": 56, "watch_reason": "test"},
    ])

    result = await hunter._check_watched_deployers("sweep-1")
    assert isinstance(result, list)
    assert result == []


@pytest.mark.asyncio
async def test_check_watched_deployers_empty(hunter, db):
    """Should return empty list when no deployers are watched."""
    db.get_watched_deployers = AsyncMock(return_value=[])

    result = await hunter._check_watched_deployers("sweep-1")
    assert result == []


# --- _recheck_warn_contracts ---


@pytest.mark.asyncio
async def test_recheck_upgrades_to_blocked(hunter, tools, db):
    """A pair with rescan score >= 71 should be blocked and deployer auto-watched."""
    db.get_tracked_pairs = AsyncMock(return_value=[{
        "pair_address": "0xpair1",
        "token_address": "0xtoken1",
        "deployer": "0xdeploy1",
    }])
    tools.scan_contract = AsyncMock(
        return_value={"risk_score": 85, "risk_level": "HIGH", "flags": ["rug"]}
    )

    result = await hunter._recheck_warn_contracts("sweep-1")

    assert "0xtoken1" in result
    db.update_tracked_pair_status.assert_awaited_once_with("0xpair1", "blocked")
    tools.auto_watch_deployer.assert_awaited_once()
    db.insert_agent_finding.assert_awaited_once()


@pytest.mark.asyncio
async def test_recheck_clears_low_score(hunter, tools, db):
    """A pair with rescan score <= 30 should be cleared."""
    db.get_tracked_pairs = AsyncMock(return_value=[{
        "pair_address": "0xpair2",
        "token_address": "0xtoken2",
        "deployer": "0xdeploy2",
    }])
    tools.scan_contract = AsyncMock(
        return_value={"risk_score": 20, "risk_level": "LOW", "flags": []}
    )

    result = await hunter._recheck_warn_contracts("sweep-1")

    assert result == []
    db.update_tracked_pair_status.assert_awaited_once_with("0xpair2", "cleared")
    # No finding logged for cleared contracts
    db.insert_agent_finding.assert_not_awaited()


@pytest.mark.asyncio
async def test_recheck_leaves_warn_alone(hunter, tools, db):
    """A pair with rescan score 31-70 should stay in watching status."""
    db.get_tracked_pairs = AsyncMock(return_value=[{
        "pair_address": "0xpair3",
        "token_address": "0xtoken3",
        "deployer": "0xdeploy3",
    }])
    tools.scan_contract = AsyncMock(
        return_value={"risk_score": 50, "risk_level": "MEDIUM", "flags": ["warn"]}
    )

    result = await hunter._recheck_warn_contracts("sweep-1")

    assert result == []
    db.update_tracked_pair_status.assert_not_awaited()
    db.insert_agent_finding.assert_not_awaited()


# --- _scan_new_pairs ---


@pytest.mark.asyncio
async def test_scan_new_pairs_placeholder(hunter):
    """Placeholder should return an empty list."""
    result = await hunter._scan_new_pairs("sweep-1")
    assert result == []


# --- start / stop ---


@pytest.mark.asyncio
async def test_start_and_stop(hunter):
    """start() should create a background task; stop() should cancel it."""
    await hunter.start(interval_seconds=3600)

    assert hunter.is_running is True
    assert hunter._task is not None
    assert not hunter._task.done()

    await hunter.stop()

    assert hunter.is_running is False
    assert hunter._task.done()


@pytest.mark.asyncio
async def test_stop_when_not_started(hunter):
    """stop() before start() should not raise."""
    await hunter.stop()
    assert hunter.is_running is False


# --- error handling ---


@pytest.mark.asyncio
async def test_sweep_exception_doesnt_crash(hunter):
    """Errors in sub-methods should not propagate from sweep()."""
    hunter._check_watched_deployers = AsyncMock(side_effect=RuntimeError("boom"))
    hunter._recheck_warn_contracts = AsyncMock(return_value=[])
    hunter._scan_new_pairs = AsyncMock(return_value=[])

    # Should NOT raise — the sweep catches sub-method exceptions
    result = await hunter.sweep()
    # sweep itself should still return whatever it collected before the error
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_recheck_individual_error_doesnt_stop_others(hunter, tools, db):
    """If one pair recheck fails, others should still be processed."""
    db.get_tracked_pairs = AsyncMock(return_value=[
        {"pair_address": "0xpairA", "token_address": "0xtokenA", "deployer": "0xdA"},
        {"pair_address": "0xpairB", "token_address": "0xtokenB", "deployer": "0xdB"},
    ])
    # First call raises, second succeeds with high score
    tools.scan_contract = AsyncMock(
        side_effect=[
            RuntimeError("rpc failure"),
            {"risk_score": 90, "risk_level": "HIGH", "flags": ["rug"]},
        ]
    )

    result = await hunter._recheck_warn_contracts("sweep-1")

    # Second pair should still be flagged
    assert "0xtokenB" in result
    db.update_tracked_pair_status.assert_awaited_once_with("0xpairB", "blocked")


# --- _log_finding ---


@pytest.mark.asyncio
async def test_log_finding_stores_in_db(hunter, db):
    """_log_finding should insert a finding into the database."""
    await hunter._log_finding(
        investigation_id="sweep-1",
        address="0xtoken1",
        deployer="0xdeploy1",
        risk_score=85,
        evidence={"risk_score": 85, "flags": ["rug"]},
        action="blocked",
    )

    db.insert_agent_finding.assert_awaited_once()
    call_kwargs = db.insert_agent_finding.call_args.kwargs
    assert call_kwargs["finding_type"] == "hunter_sweep"
    assert call_kwargs["investigation_id"] == "sweep-1"
    assert call_kwargs["address"] == "0xtoken1"
    assert call_kwargs["deployer"] == "0xdeploy1"
    assert call_kwargs["risk_score"] == 85
    assert call_kwargs["action_taken"] == "blocked"
    assert call_kwargs["narrative"] is None  # AI disabled


@pytest.mark.asyncio
async def test_log_finding_with_ai_narrative(hunter, db, ai):
    """When AI is available, _log_finding should generate a narrative."""
    # Set up AI mock to be available
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="  This contract is dangerous.  ")]
    ai.client = MagicMock()
    ai.client.messages.create = AsyncMock(return_value=mock_message)

    await hunter._log_finding(
        investigation_id="sweep-2",
        address="0xbad",
        deployer="0xevil",
        risk_score=95,
        evidence={"risk_score": 95},
        action="blocked",
    )

    db.insert_agent_finding.assert_awaited_once()
    call_kwargs = db.insert_agent_finding.call_args.kwargs
    assert call_kwargs["narrative"] == "This contract is dangerous."


@pytest.mark.asyncio
async def test_log_finding_ai_failure_still_stores(hunter, db, ai):
    """If AI narrative fails, the finding should still be stored without narrative."""
    ai.client = MagicMock()
    ai.client.messages.create = AsyncMock(side_effect=RuntimeError("API down"))

    await hunter._log_finding(
        investigation_id="sweep-3",
        address="0xbad",
        deployer="0xevil",
        risk_score=80,
        evidence={"risk_score": 80},
        action="blocked",
    )

    db.insert_agent_finding.assert_awaited_once()
    call_kwargs = db.insert_agent_finding.call_args.kwargs
    assert call_kwargs["narrative"] is None
