"""Guard rescans across the real watch, hunter, evidence store and publisher drain."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from eth_abi import decode
from eth_utils import keccak

import agent.hunter as hunter_module
import services.verdict_publisher as vp
from agent.hunter import SCAN_REQUEST_COST
from core.database import Database
from services.rpc_guard import BreakerOpenError, OPEN, RpcGuard
from tests.test_launch_watch import Polls, launch, make_watch, pool, scanned, token


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "guard.db"))
    await database.initialize()
    yield database
    await database.close()


@pytest.fixture
def now(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(hunter_module.time, "time", lambda: clock[0])
    monkeypatch.setattr(vp, "RECEIPT_DELAY_SECONDS", 0)
    return clock


def measurement(observed_at, complete=True):
    return {
        "observed_at": observed_at,
        "rug_probability": 10,
        "risk_level": "LOW",
        "status": "ok" if complete else "unknown",
        "coverage": {"structural": 1, "honeypot": 1 if complete else 0},
        "coverage_reasons": {} if complete else {"honeypot": "Unavailable"},
        "honeypot_data": {"observed_at": observed_at, "simulation_block": int(observed_at)},
    }


def publisher_for(db):
    return vp.VerdictPublisher(db, rpc_url="https://rpc.invalid", registry_address="0x" + "aa" * 20)


async def confirmed(db, publisher, subject, observed_at):
    result = await publisher.publish(4663, subject, measurement(observed_at))
    await db.update_verdict_onchain(result["evidence_id"], "confirmed")
    return result


@pytest.mark.asyncio
async def test_oldest_measurement_first_without_tracking_cleared_pairs(db, now):
    publisher = publisher_for(db)
    for index, timestamp in enumerate((650, 500, 600)):
        await confirmed(db, publisher, token(index), timestamp)
    watch = make_watch(db, scan=lambda *args, **kwargs: measurement(now[0]))
    watch.hunter.verdict_publisher = publisher

    await watch.cycle()

    assert scanned(watch) == [token(1), token(2), token(0)]
    assert await db.get_tracked_pairs() == []
    assert await watch.hunter.due_guard_subjects() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["exception", "incomplete", "cached", "missing", "future", "publisher"])
async def test_failed_measurement_retries_promptly_without_consuming_interval(db, now, failure):
    publisher = publisher_for(db)
    await confirmed(db, publisher, token(0), 600)
    watch = make_watch(db)
    watch.hunter.verdict_publisher = publisher
    if failure == "exception":
        watch.hunter.tools.scan_contract.side_effect = RuntimeError("provider failed")
    else:
        value = {"cached": 600, "missing": None, "future": 1001}.get(failure, 1000)
        watch.hunter.tools.scan_contract.return_value = measurement(value, failure != "incomplete") if value else {
            **measurement(1000), "observed_at": None,
        }
        if failure == "publisher":
            publisher.publish = AsyncMock(return_value=None)

    await watch.cycle()
    [subject] = await db.get_guard_subjects(4663)
    assert subject["last_observed_at"] == 600
    assert await watch.hunter.due_guard_subjects() == []
    now[0] += hunter_module.GUARD_RESCAN_RETRY_SECONDS
    assert [row["subject"] for row in await watch.hunter.due_guard_subjects()] == [token(0)]
    assert now[0] - 1000 < hunter_module.GUARD_RESCAN_INTERVAL_SECONDS
    if failure == "incomplete":
        assert (await db.get_latest_verdict_evidence(4663, token(0)))["verdict"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_open_breaker_leaves_guard_subject_due_without_scanning(db, now):
    publisher = publisher_for(db)
    await confirmed(db, publisher, token(0), 600)
    guard = RpcGuard("test")
    guard.state = OPEN
    watch = make_watch(db, guard=guard)
    watch.hunter.verdict_publisher = publisher
    [subject] = await watch.hunter.due_guard_subjects()
    with pytest.raises(BreakerOpenError):
        await watch.hunter.rescan_guard_subject(subject)
    watch.hunter.tools.scan_contract.assert_not_awaited()
    assert (await db.get_guard_subjects(4663))[0]["retry_after"] == 0


@pytest.mark.asyncio
async def test_disabled_publisher_does_not_spend_guard_scan_budget(db, now):
    await confirmed(db, publisher_for(db), token(0), 600)
    watch = make_watch(db)
    watch.hunter.verdict_publisher = vp.VerdictPublisher(db, registry_address="")
    await watch.cycle()
    watch.hunter.tools.scan_contract.assert_not_awaited()
    assert await watch.hunter.due_guard_subjects() == []


@pytest.mark.asyncio
async def test_unregister_during_budget_wait_cancels_queued_rescan(db, now):
    publisher = publisher_for(db)
    await confirmed(db, publisher, token(0), 600)
    guard = RpcGuard("test")
    guard.acquire = AsyncMock()
    watch = make_watch(db, guard=guard)
    watch.hunter.verdict_publisher = publisher
    [subject] = await watch.hunter.due_guard_subjects()

    async def remove(cost):
        await db.unregister_guard_subject(4663, token(0))

    guard.acquire.side_effect = remove
    await watch.hunter.rescan_guard_subject(subject)
    watch.hunter.tools.scan_contract.assert_not_awaited()
    assert await db.get_guard_subjects(4663) == []


@pytest.mark.asyncio
async def test_failing_guards_do_not_starve_existing_general_rechecks(db, now):
    publisher = publisher_for(db)
    for index in range(4):
        await confirmed(db, publisher, token(index + 20), 500 + index)
    await db.upsert_discovered_launches(4663, [launch(index) for index in range(20)])
    await db.upsert_tracked_pair(token(50), token_address=token(50), chain_id=4663)

    async def scan(*args, **kwargs):
        now[0] += 45
        return measurement(now[0], complete=False)

    watch = make_watch(db, Polls({pool(i): 1 for i in range(20)}), scan=scan, clock=lambda: now[0])
    watch.hunter.verdict_publisher = publisher
    watch.queue_rechecks(await db.get_tracked_pairs())
    for _ in range(10):
        await watch.cycle()
    assert token(50) in scanned(watch)


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["incomplete", "exception", "high"])
async def test_guard_rescan_supersedes_cleared_launch_feed(db, now, outcome):
    publisher = publisher_for(db)
    await db.upsert_discovered_launches(4663, [launch(0)])
    await db.record_launch_scan(4663, token(0), "cleared", 10)
    await confirmed(db, publisher, token(0), 600)
    watch = make_watch(db)
    watch.hunter.verdict_publisher = publisher
    if outcome == "exception":
        watch.hunter.tools.scan_contract.side_effect = RuntimeError("unavailable")
    else:
        result = measurement(now[0], outcome != "incomplete")
        if outcome == "high":
            result.update(rug_probability=90, risk_level="HIGH")
        watch.hunter.tools.scan_contract.return_value = result
    await watch.cycle()
    [item], _ = await db.get_launch_feed(4663, 10)
    assert item["scan"]["outcome"] == ("blocked" if outcome == "high" else "unknown")
    assert item["scan"]["status"] == ("ok" if outcome == "high" else "unknown")
    assert item["scan"]["risk_score"] == (90 if outcome == "high" else None)
    assert await db.get_tracked_pairs() == []


@pytest.mark.asyncio
async def test_tight_budget_keeps_discovery_and_launch_scans_moving(db, now, monkeypatch):
    publisher = publisher_for(db)
    for index in range(4):
        await confirmed(db, publisher, token(index + 20), 500 + index)
    await db.upsert_discovered_launches(4663, [launch(index) for index in range(12)])
    guard = RpcGuard("test", clock=lambda: now[0])
    reservations = []
    acquire = guard.acquire

    async def reserve(cost, probe=False):
        reservations.append(cost)
        await acquire(cost, probe)

    async def advance(delay):
        now[0] += delay

    monkeypatch.setattr(guard, "acquire", reserve)
    monkeypatch.setattr("services.rpc_guard.asyncio.sleep", advance)
    polls = []

    async def poll(pools=()):
        polls.append(now[0])
        await guard.acquire(3)
        return {"target": launch(0)["block_number"] + 100, "swaps": {pool(i): 1 for i in range(12)}}

    watch = make_watch(db, guard=guard, clock=lambda: now[0], scan=lambda *a, **k: measurement(now[0]))
    watch.hunter.verdict_publisher = publisher
    watch.hunter.discovery.poll = AsyncMock(side_effect=poll)
    for _ in range(8):
        await watch.cycle()

    order = scanned(watch)
    assert len(polls) == 8
    assert max(b - a for a, b in zip(polls, polls[1:])) <= 2 * SCAN_REQUEST_COST + 3
    guarded = {token(index + 20) for index in range(4)}
    assert guarded.issubset(order)
    assert sum(subject not in guarded for subject in order) >= sum(subject in guarded for subject in order)
    assert all(a not in guarded or b not in guarded for a, b in zip(order, order[1:]))
    assert reservations.count(SCAN_REQUEST_COST) == len(order)


@pytest.mark.asyncio
async def test_failing_oldest_subject_does_not_monopolize_guard_slots(db, now):
    publisher = publisher_for(db)
    for index in range(3):
        await confirmed(db, publisher, token(index), 500 + index)

    async def scan(*args, **kwargs):
        now[0] += 45
        raise RuntimeError("failed")

    watch = make_watch(db, scan=scan, clock=lambda: now[0])
    watch.hunter.verdict_publisher = publisher
    for _ in range(3):
        await watch.cycle()
    assert scanned(watch) == [token(0), token(1), token(2)]


@pytest.mark.asyncio
async def test_low_launch_really_refreshes_through_publisher_drain_without_signing(db, now, monkeypatch):
    publisher = publisher_for(db)
    publisher._account = MagicMock()
    recorded = []

    async def prepare(session, row, transactions, data):
        # Calldata bytes stand in for the signed envelope only at the transport boundary.
        return "send", bytes.fromhex(data[2:]), len(recorded), 1

    async def rpc(session, calls, row=None):
        responses = []
        for method, params in calls:
            if method == "eth_sendRawTransaction":
                raw = bytes.fromhex(params[0][2:])
                assert raw[:4] == vp.RECORD_SELECTOR
                subject, verdict, evidence_hash, observed_block = decode(
                    ["address", "uint8", "bytes32", "uint64"], raw[4:]
                )
                recorded.append((subject, verdict, "0x" + evidence_hash.hex(), observed_block, now[0]))
                responses.append("0x" + keccak(raw).hex())
            else:
                assert method == "eth_getTransactionReceipt"
                responses.append({"status": "0x1"})
        return responses

    monkeypatch.setattr(publisher, "_prepare", prepare)
    monkeypatch.setattr(publisher, "_rpc", rpc)
    await db.upsert_discovered_launches(4663, [launch(0)])
    watch = make_watch(db, Polls({pool(0): 1}), scan=lambda *a, **k: measurement(now[0]))
    watch.hunter.verdict_publisher = publisher
    await watch.cycle()
    assert await db.get_guard_subjects(4663) == []
    assert await publisher.drain_once() == "done"
    assert await db.get_tracked_pairs() == []
    assert len(await db.get_guard_subjects(4663)) == 1
    first = await db.get_latest_verdict_evidence(4663, token(0))

    now[0] += vp.VERDICT_REFRESH_SECONDS - 1
    await watch.cycle()
    assert len(recorded) == 1
    assert scanned(watch) == [token(0)]
    now[0] += 1
    await watch.cycle()
    assert await publisher.drain_once() == "done"
    second = await db.get_latest_verdict_evidence(4663, token(0))

    assert first["onchain_status"] == second["onchain_status"] == "confirmed"
    assert first["id"] != second["id"] and first["tx_hash"] != second["tx_hash"]
    assert [row[1] for row in recorded] == [int(vp.Verdict.LOW)] * 2
    assert [row[3] for row in recorded] == [1000, 1300]
    assert [row[4] for row in recorded] == [1000, 1300]
    assert recorded[0][2] != recorded[1][2]
    assert json.loads(second["canonical"])["observed_at"] == 1300
    publisher._account.sign_transaction.assert_not_called()


@pytest.mark.asyncio
async def test_stats_show_ages_due_subjects_and_budget_pressure(db, now):
    publisher = publisher_for(db)
    await confirmed(db, publisher, token(0), 600)
    guard = RpcGuard("test", clock=lambda: now[0])
    await guard.acquire(SCAN_REQUEST_COST)
    watch = make_watch(db, guard=guard)
    watch.hunter.verdict_publisher = publisher
    snapshot = await watch.hunter.guard_watch_stats()
    assert snapshot["subjects"][0]["measurement_age_seconds"] == 400
    assert snapshot["due_count"] == 1
    assert snapshot["rpc_budget"]["wait_seconds"] == SCAN_REQUEST_COST
    assert snapshot["rpc_budget"]["saturated"] is True
