"""Tests for agent.hunter — scheduled threat sweep loop."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from agent.hunter import (
    LAUNCH_SCANS_PER_SWEEP,
    RECHECK_MIN_INTERVAL_SECONDS,
    RECHECK_PAIRS_PER_SWEEP,
    SCAN_INTERVAL_SECONDS,
    Hunter,
)
from core.database import Database
from services.launch_discovery import LaunchDiscoveryError


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
    d.get_recheck_chains = AsyncMock(return_value=[])
    d.get_recheck_pairs = AsyncMock(return_value=[])
    d.mark_tracked_pair_checked = AsyncMock()
    d.update_tracked_pair_status = AsyncMock()
    d.insert_agent_finding = AsyncMock()
    return d


def watching_pairs(db, rows):
    """Serve rows to the recheck phase the way the database does, grouped by chain."""
    db.get_recheck_chains = AsyncMock(return_value=sorted({row.get("chain_id", 56) for row in rows}))

    async def recheck_pairs(status, chain_id, limit, checked_before):
        return [row for row in rows if row.get("chain_id", 56) == chain_id][:limit]

    db.get_recheck_pairs = AsyncMock(side_effect=recheck_pairs)


@pytest.fixture
def ai():
    a = MagicMock()
    a.is_available = MagicMock(return_value=False)
    return a


@pytest.fixture
def sentinel():
    return MagicMock()


@pytest.fixture(autouse=True)
def unpaced_scans():
    """Scan pacing is asserted on its own; every other test runs without the wait."""
    with patch("agent.hunter.SCAN_INTERVAL_SECONDS", 0):
        yield


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
    watching_pairs(db, [{
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
    watching_pairs(db, [{
        "pair_address": "0xpair2",
        "token_address": "0xtoken2",
        "deployer": "0xdeploy2",
    }])
    tools.scan_contract = AsyncMock(
        return_value={
            "risk_score": 20, "risk_level": "LOW", "flags": [],
            "status": "ok", "coverage": {"structural": 1, "honeypot": 1},
        }
    )

    result = await hunter._recheck_warn_contracts("sweep-1")

    assert result == []
    db.update_tracked_pair_status.assert_awaited_once_with("0xpair2", "cleared")
    # No finding logged for cleared contracts
    db.insert_agent_finding.assert_not_awaited()


@pytest.mark.asyncio
async def test_recheck_leaves_warn_alone(hunter, tools, db):
    """A pair with rescan score 31-70 should stay in watching status."""
    watching_pairs(db, [{
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
    watching_pairs(db, [
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
    ai.is_available = MagicMock(return_value=True)
    ai.chat = AsyncMock(return_value="  This contract is dangerous.  ")

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
    ai.is_available = MagicMock(return_value=True)
    ai.chat = AsyncMock(side_effect=RuntimeError("API down"))

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


# --- chain propagation and incomplete scans ---

ROBINHOOD_TOKEN = "0xcde854116e1be8d52612c03d099e2415dc921e18"


def scan_result(score, complete=True):
    """Shape of RiskEngine.compute_from_results: the score is rug_probability."""
    return {
        "rug_probability": score,
        "risk_level": "LOW" if score <= 30 else "HIGH",
        "critical_flags": [],
        "status": "ok" if complete else "unknown",
        "coverage": {"structural": 1, "honeypot": 1 if complete else 0},
        "coverage_reasons": {} if complete else {"honeypot": "Honeypot simulation unavailable"},
    }


@pytest.mark.asyncio
async def test_recheck_rescans_and_logs_a_robinhood_pair_on_its_own_chain(hunter, tools, db):
    watching_pairs(db, [{
        "pair_address": ROBINHOOD_TOKEN,
        "token_address": ROBINHOOD_TOKEN,
        "deployer": None,
        "chain_id": 4663,
    }])
    tools.scan_contract = AsyncMock(return_value=scan_result(90))

    result = await hunter._recheck_warn_contracts("sweep-1")

    assert result == [ROBINHOOD_TOKEN]
    tools.scan_contract.assert_awaited_once_with(ROBINHOOD_TOKEN, chain_id=4663)
    db.update_tracked_pair_status.assert_awaited_once_with(ROBINHOOD_TOKEN, "blocked")
    assert db.insert_agent_finding.call_args.kwargs["chain_id"] == 4663
    tools.auto_watch_deployer.assert_not_awaited()


@pytest.mark.asyncio
async def test_recheck_keeps_bsc_rows_on_bsc(hunter, tools, db):
    watching_pairs(db, [{
        "pair_address": "0xpair1",
        "token_address": "0xtoken1",
        "deployer": "0xdeploy1",
        "chain_id": 56,
    }])
    tools.scan_contract = AsyncMock(
        return_value={"risk_score": 85, "risk_level": "HIGH", "flags": ["rug"]}
    )

    await hunter._recheck_warn_contracts("sweep-1")

    tools.scan_contract.assert_awaited_once_with("0xtoken1", chain_id=56)
    assert db.insert_agent_finding.call_args.kwargs["chain_id"] == 56
    tools.auto_watch_deployer.assert_awaited_once_with(
        "0xdeploy1", reason="auto: recheck upgrade 0xtoken1 (score=85)"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("result", [
    scan_result(10, complete=False),
    {"risk_score": 20, "risk_level": "LOW", "flags": []},
    {**scan_result(10), "partial": True},
    {key: value for key, value in scan_result(10).items() if key != "rug_probability"},
])
async def test_recheck_incomplete_scan_never_clears(hunter, tools, db, result):
    watching_pairs(db, [{
        "pair_address": "0xpair2", "token_address": "0xtoken2", "deployer": "0xdeploy2", "chain_id": 4663,
    }])
    tools.scan_contract = AsyncMock(return_value=result)

    assert await hunter._recheck_warn_contracts("sweep-1") == []
    db.update_tracked_pair_status.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("score,status", [(10, "cleared"), (85, "blocked")])
async def test_recheck_reads_the_score_scan_contract_returns(hunter, tools, db, score, status):
    watching_pairs(db, [{
        "pair_address": "0xpair4", "token_address": "0xtoken4", "deployer": None, "chain_id": 56,
    }])
    tools.scan_contract = AsyncMock(return_value=scan_result(score))

    await hunter._recheck_warn_contracts("sweep-1")

    db.update_tracked_pair_status.assert_awaited_once_with("0xpair4", status)


# --- _scan_new_pairs: Robinhood Chain launches ---


@pytest_asyncio.fixture
async def real_db(tmp_path):
    database = Database(str(tmp_path / "hunter.db"))
    await database.initialize()
    yield database
    await database.close()


def launch(index):
    return {
        "token_address": "0x" + f"{index + 1:040x}",
        "source": "uniswap_v4",
        "launchpad": "Uniswap v4",
        "source_rank": 2,
        "pool_id": None,
        "block_number": 65_000_000 + index,
        "tx_hash": "0x" + f"{index + 1:064x}",
        "block_timestamp": 1_789_000_000 + index,
    }


async def scan_statuses(database):
    cursor = await database._db.execute(
        "SELECT token_address, scan_status FROM discovered_launches WHERE chain_id = 4663"
    )
    return dict(await cursor.fetchall())


@pytest.mark.asyncio
async def test_scan_new_pairs_discovers_then_scans_newest_launches_up_to_the_cap(tools, ai, sentinel, real_db):
    count = LAUNCH_SCANS_PER_SWEEP + 5
    await real_db.upsert_discovered_launches(4663, [launch(index) for index in range(count)])
    order = []
    discovery = MagicMock()
    discovery.run = AsyncMock(side_effect=lambda: order.append("discover"))

    async def scan(token, chain_id):
        order.append(token)
        return scan_result(10)

    tools.scan_contract = AsyncMock(side_effect=scan)
    hunter = Hunter(tools=tools, db=real_db, ai_analyzer=ai, sentinel=sentinel, discovery=discovery)

    assert await hunter._scan_new_pairs("sweep-1") == []

    newest = [launch(index)["token_address"] for index in reversed(range(count))]
    assert order == ["discover", *newest[:LAUNCH_SCANS_PER_SWEEP]]
    assert all(call.kwargs == {"chain_id": 4663} for call in tools.scan_contract.await_args_list)
    remaining = await real_db.get_unscanned_launches(4663, limit=100)
    assert [row["token_address"] for row in remaining] == newest[LAUNCH_SCANS_PER_SWEEP:]


@pytest.mark.asyncio
async def test_scan_new_pairs_records_each_outcome_and_never_clears_an_incomplete_scan(
    tools, ai, sentinel, real_db
):
    outcomes = {
        "blocked": scan_result(85, complete=False),
        "unknown": scan_result(5, complete=False),
        "watching": scan_result(50),
        "cleared": scan_result(5),
        "error": RuntimeError("provider unavailable"),
    }
    tokens = {status: launch(index)["token_address"] for index, status in enumerate(outcomes)}
    await real_db.upsert_discovered_launches(4663, [launch(index) for index in range(len(outcomes))])
    by_token = {tokens[status]: outcome for status, outcome in outcomes.items()}

    async def scan(token, chain_id):
        if isinstance(by_token[token], Exception):
            raise by_token[token]
        return by_token[token]

    tools.scan_contract = AsyncMock(side_effect=scan)
    discovery = MagicMock(run=AsyncMock(return_value={}))
    hunter = Hunter(tools=tools, db=real_db, ai_analyzer=ai, sentinel=sentinel, discovery=discovery)

    assert await hunter._scan_new_pairs("sweep-1") == [tokens["blocked"]]

    assert await scan_statuses(real_db) == {token: status for status, token in tokens.items()}
    findings = await real_db.get_agent_findings()
    assert [(f["address"], f["chain_id"], f["action_taken"]) for f in findings] == [
        (tokens["blocked"], 4663, "blocked")
    ]
    watching = await real_db.get_tracked_pairs(status="watching")
    assert {(row["token_address"], row["chain_id"]) for row in watching} == {
        (tokens["unknown"], 4663), (tokens["watching"], 4663), (tokens["error"], 4663),
    }
    tools.auto_watch_deployer.assert_not_awaited()


@pytest.mark.asyncio
async def test_scan_new_pairs_still_scans_known_launches_when_discovery_fails(tools, ai, sentinel, real_db):
    await real_db.upsert_discovered_launches(4663, [launch(0)])
    discovery = MagicMock(run=AsyncMock(side_effect=LaunchDiscoveryError("RPC unavailable")))
    tools.scan_contract = AsyncMock(return_value=scan_result(5, complete=False))
    hunter = Hunter(tools=tools, db=real_db, ai_analyzer=ai, sentinel=sentinel, discovery=discovery)

    assert await hunter._scan_new_pairs("sweep-1") == []

    tools.scan_contract.assert_awaited_once_with(launch(0)["token_address"], chain_id=4663)
    assert await scan_statuses(real_db) == {launch(0)["token_address"]: "unknown"}


@pytest.mark.asyncio
async def test_discovered_launch_is_rechecked_and_logged_on_robinhood_chain(tools, ai, sentinel, real_db):
    token = launch(0)["token_address"]
    await real_db.upsert_discovered_launches(4663, [launch(0)])
    hunter = Hunter(
        tools=tools, db=real_db, ai_analyzer=ai, sentinel=sentinel,
        discovery=MagicMock(run=AsyncMock(return_value={})),
    )
    tools.scan_contract = AsyncMock(return_value=scan_result(10, complete=False))
    await hunter._scan_new_pairs("sweep-1")

    # Six hours later the launch is due a recheck, which an incomplete scan does not clear.
    await backdate(real_db, token, RECHECK_MIN_INTERVAL_SECONDS + 60)
    await hunter._recheck_warn_contracts("sweep-2")
    assert [row["token_address"] for row in await real_db.get_tracked_pairs(status="watching")] == [token]

    await backdate(real_db, token, RECHECK_MIN_INTERVAL_SECONDS + 60)
    tools.scan_contract = AsyncMock(return_value=scan_result(95))
    assert await hunter._recheck_warn_contracts("sweep-3") == [token]

    tools.scan_contract.assert_awaited_once_with(token, chain_id=4663)
    assert [row["chain_id"] for row in await real_db.get_tracked_pairs(status="blocked")] == [4663]
    findings = await real_db.get_agent_findings()
    assert [(f["address"], f["chain_id"], f["investigation_id"]) for f in findings] == [(token, 4663, "sweep-3")]


# --- recheck fairness, rotation and interval ---

DAY = 24 * 3600


async def backdate(database, pair_address, checked_ago):
    """Move a pair's last check checked_ago seconds into the past (None: never checked)."""
    checked = None if checked_ago is None else time.time() - checked_ago
    await database._db.execute(
        "UPDATE tracked_pairs SET last_checked = ? WHERE pair_address = ?", (checked, pair_address)
    )
    await database._db.commit()


async def watching_row(database, pair_address, chain_id, checked_ago):
    """Insert a watching pair whose last check was checked_ago seconds ago (None: never)."""
    await database.upsert_tracked_pair(pair_address, token_address=pair_address, chain_id=chain_id)
    await backdate(database, pair_address, checked_ago)


async def sweep_scans(hunter, tools):
    """Run one recheck phase and return the (token, chain) pairs it scanned."""
    tools.scan_contract.reset_mock()
    await hunter._recheck_warn_contracts("sweep")
    return [(call.args[0], call.kwargs["chain_id"]) for call in tools.scan_contract.await_args_list]


@pytest.mark.asyncio
async def test_recheck_gives_every_chain_a_turn(tools, ai, sentinel, real_db):
    await watching_row(real_db, "0xbsc1", 56, 3 * DAY)
    for index in range(25):
        await watching_row(real_db, launch(index)["token_address"], 4663, DAY + index)
    tools.scan_contract = AsyncMock(return_value=scan_result(10, complete=False))
    hunter = Hunter(tools=tools, db=real_db, ai_analyzer=ai, sentinel=sentinel)

    scanned = await sweep_scans(hunter, tools)

    assert ("0xbsc1", 56) in scanned
    assert len(scanned) <= RECHECK_PAIRS_PER_SWEEP
    assert sum(1 for _, chain in scanned if chain == 4663) <= RECHECK_PAIRS_PER_SWEEP // 2


@pytest.mark.asyncio
async def test_recheck_rotates_the_least_recently_checked_rows(tools, ai, sentinel, real_db):
    await watching_row(real_db, "0xnever", 4663, None)
    await watching_row(real_db, "0xoldest", 4663, 3 * DAY)
    await watching_row(real_db, "0xmiddle", 4663, 2 * DAY)
    await watching_row(real_db, "0xnewest", 4663, DAY)
    tools.scan_contract = AsyncMock(return_value=scan_result(10, complete=False))
    hunter = Hunter(tools=tools, db=real_db, ai_analyzer=ai, sentinel=sentinel)

    with patch("agent.hunter.RECHECK_PAIRS_PER_SWEEP", 2):
        first = await sweep_scans(hunter, tools)
        second = await sweep_scans(hunter, tools)
        third = await sweep_scans(hunter, tools)

    assert [token for token, _ in first] == ["0xnever", "0xoldest"]
    assert [token for token, _ in second] == ["0xmiddle", "0xnewest"]
    assert third == []


@pytest.mark.asyncio
async def test_recheck_skips_a_row_checked_within_the_minimum_interval(tools, ai, sentinel, real_db):
    await watching_row(real_db, "0xfresh", 4663, RECHECK_MIN_INTERVAL_SECONDS / 2)
    tools.scan_contract = AsyncMock(return_value=scan_result(10, complete=False))
    hunter = Hunter(tools=tools, db=real_db, ai_analyzer=ai, sentinel=sentinel)

    assert await sweep_scans(hunter, tools) == []

    await watching_row(real_db, "0xfresh", 4663, RECHECK_MIN_INTERVAL_SECONDS + 60)

    assert await sweep_scans(hunter, tools) == [("0xfresh", 4663)]
    # The attempt is recorded even though an incomplete scan leaves the row watching.
    row = (await real_db.get_recheck_pairs("watching", 4663, 10, time.time()))[0]
    assert row["last_checked"] > time.time() - 60
    assert await sweep_scans(hunter, tools) == []


@pytest.mark.asyncio
async def test_recheck_scans_at_most_the_sweep_budget(tools, ai, sentinel, real_db):
    for index in range(RECHECK_PAIRS_PER_SWEEP + 10):
        await watching_row(real_db, launch(index)["token_address"], 4663, DAY + index)
    tools.scan_contract = AsyncMock(return_value=scan_result(10, complete=False))
    hunter = Hunter(tools=tools, db=real_db, ai_analyzer=ai, sentinel=sentinel)

    assert len(await sweep_scans(hunter, tools)) == RECHECK_PAIRS_PER_SWEEP


# --- scan pacing and pair address reuse ---


@pytest.mark.asyncio
async def test_recheck_waits_between_scans(tools, ai, sentinel, real_db):
    for index in range(3):
        await watching_row(real_db, launch(index)["token_address"], 4663, DAY + index)
    tools.scan_contract = AsyncMock(return_value=scan_result(10, complete=False))
    hunter = Hunter(tools=tools, db=real_db, ai_analyzer=ai, sentinel=sentinel)

    with (
        patch("agent.hunter.SCAN_INTERVAL_SECONDS", 1.5),
        patch("agent.hunter.asyncio.sleep", new_callable=AsyncMock) as sleep,
    ):
        await hunter._recheck_warn_contracts("sweep")

    assert tools.scan_contract.await_count == 3
    assert [call.args[0] for call in sleep.await_args_list] == [1.5, 1.5]
    assert SCAN_INTERVAL_SECONDS > 0


@pytest.mark.asyncio
async def test_launch_scans_wait_between_scans(tools, ai, sentinel, real_db):
    await real_db.upsert_discovered_launches(4663, [launch(index) for index in range(3)])
    tools.scan_contract = AsyncMock(return_value=scan_result(10, complete=False))
    hunter = Hunter(
        tools=tools, db=real_db, ai_analyzer=ai, sentinel=sentinel,
        discovery=MagicMock(run=AsyncMock(return_value=None)),
    )

    with (
        patch("agent.hunter.SCAN_INTERVAL_SECONDS", 1.5),
        patch("agent.hunter.asyncio.sleep", new_callable=AsyncMock) as sleep,
    ):
        await hunter._scan_new_pairs("sweep")

    assert tools.scan_contract.await_count == 3
    assert [call.args[0] for call in sleep.await_args_list] == [1.5, 1.5]


@pytest.mark.asyncio
async def test_a_reused_pair_address_moves_to_its_new_chain(tools, ai, sentinel, real_db):
    await real_db.upsert_tracked_pair("0xshared", token_address="0xbsctoken", chain_id=56)
    await real_db.upsert_tracked_pair("0xshared", token_address=ROBINHOOD_TOKEN, chain_id=4663)

    rows = await real_db.get_tracked_pairs(status="watching")
    assert [(row["pair_address"], row["token_address"], row["chain_id"]) for row in rows] == [
        ("0xshared", ROBINHOOD_TOKEN, 4663)
    ]

    await backdate(real_db, "0xshared", DAY)
    tools.scan_contract = AsyncMock(return_value=scan_result(10, complete=False))
    hunter = Hunter(tools=tools, db=real_db, ai_analyzer=ai, sentinel=sentinel)

    assert await sweep_scans(hunter, tools) == [(ROBINHOOD_TOKEN, 4663)]
