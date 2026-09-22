"""Observation provenance and queue eligibility across the real evidence store and fake RPC."""

import json
from unittest.mock import AsyncMock

import pytest

import services.verdict_publisher as vp
from core.verdict_evidence import build_evidence
from tests.test_verdict_publisher import (
    COMPLETE,
    TOKEN,
    FakeChain,
    decode_record,
    drain_all,
    make_publisher,
    rpc_node,
    sender,
)
from tests.test_verdict_publisher import db as db


@pytest.fixture(autouse=True)
def observation_clock(monkeypatch):
    monkeypatch.setattr(vp.time, "time", lambda: 1000)
    monkeypatch.setattr(vp, "RECEIPT_DELAY_SECONDS", 0)


def scan(observed_at=990, level="LOW"):
    return {**COMPLETE, "observed_at": observed_at, "risk_level": level}


def test_evidence_uses_oldest_measurement_instead_of_enqueue_time():
    payload = build_evidence(
        4663, TOKEN, scan(990), {"observed_at": 950, "simulation_block": 123}, 1000
    )
    assert payload["observed_at"] == payload["scanned_at"] == 950
    assert payload["observed_block"] == 123


def test_separate_unstamped_simulation_cannot_inherit_the_scan_time():
    payload = build_evidence(4663, TOKEN, scan(990), {"simulation_block": 123})
    assert payload["observed_at"] == payload["scanned_at"] == 0


@pytest.mark.asyncio
async def test_freshness_is_checked_after_the_supersession_lookup(db, monkeypatch):
    publisher = sender(db)
    summary = await publisher.publish(4663, TOKEN, scan(700))
    row = await db.claim_next_pending_verdict(4663)
    newest = db.get_newest_verdict_observation

    async def slow_lookup(*args):
        result = await newest(*args)
        monkeypatch.setattr(vp.time, "time", lambda: 1001)
        return result

    monkeypatch.setattr(db, "get_newest_verdict_observation", slow_lookup)
    assert await publisher._drop_ineligible(row)
    assert (await db.get_verdict_evidence(summary["evidence_id"]))["onchain_error"] == "StaleObservation"


@pytest.mark.asyncio
async def test_publish_preserves_measurement_time(db):
    await make_publisher(db).publish(4663, TOKEN, scan(950))
    payload = json.loads((await db.get_latest_verdict_evidence(4663, TOKEN))["canonical"])
    assert payload["observed_at"] == payload["scanned_at"] == 950


@pytest.mark.asyncio
@pytest.mark.parametrize("observed_at,reason", [
    (699, "StaleObservation"),
    (None, "MissingObservationTime"),
    (True, "MissingObservationTime"),
    (1001, "FutureObservation"),
])
async def test_ineligible_pending_evidence_is_dropped_before_preparation(db, observed_at, reason):
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, scan(observed_at))
    publisher._prepare = AsyncMock(side_effect=AssertionError("must not prepare"))
    with rpc_node(FakeChain()):
        assert await publisher.drain_once() == "done"
    row = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (row["onchain_status"], row["onchain_error"]) == ("dropped", reason)
    publisher._prepare.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("first_time,first_level,second_time,second_level,expected", [
    (980, "LOW", 990, "HIGH", "HIGH"),
    (990, "HIGH", 980, "LOW", "HIGH"),
    (990, "HIGH", 990, "LOW", "HIGH"),
    (990, "LOW", 990, "UNKNOWN", "UNKNOWN"),
    (980, "HIGH", 990, "LOW", "LOW"),
])
async def test_supersession_uses_observation_order_and_denial_wins_ties(
    db, first_time, first_level, second_time, second_level, expected
):
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, scan(first_time, first_level))
    await publisher.publish(4663, TOKEN, scan(second_time, second_level))
    chain = FakeChain()
    with rpc_node(chain):
        assert await drain_all(publisher) == ["done", "done", "idle"]
    assert [decode_record(raw)["verdict"] for raw in chain.sent] == [int(vp.Verdict[expected])]
    cursor = await db._db.execute(
        "SELECT onchain_status, onchain_error FROM verdict_evidence WHERE onchain_status = 'dropped'"
    )
    assert await cursor.fetchall() == [("dropped", "SupersededObservation")]


@pytest.mark.asyncio
async def test_unchanged_healthy_verdict_refreshes_only_after_observation_threshold(db, monkeypatch):
    publisher = make_publisher(db)
    first = await publisher.publish(4663, TOKEN, scan(1000))
    await db.update_verdict_onchain(first["evidence_id"], "confirmed")
    monkeypatch.setattr(vp.time, "time", lambda: 1299)
    unchanged = await publisher.publish(4663, TOKEN, scan(1299))
    assert unchanged["onchain_status"] == "deduplicated"
    monkeypatch.setattr(vp.time, "time", lambda: 1300)
    refreshed = await publisher.publish(4663, TOKEN, scan(1300))
    assert refreshed["evidence_id"] != first["evidence_id"]
    # Reusing the old measurement never refreshes freshness.
    assert vp._repeats(await db.get_latest_verdict_evidence(4663, TOKEN),
                       build_evidence(4663, TOKEN, scan(1300), None, 1600))


@pytest.mark.asyncio
async def test_evidence_that_expires_during_preparation_is_never_broadcast(db, monkeypatch):
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, scan(700))
    prepare = publisher._prepare

    async def expire(*args):
        result = await prepare(*args)
        monkeypatch.setattr(vp.time, "time", lambda: 1001)
        return result

    monkeypatch.setattr(publisher, "_prepare", expire)
    chain = FakeChain()
    with rpc_node(chain):
        assert await publisher.drain_once() == "done"
    assert chain.sent == []
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_error"] == "StaleObservation"


@pytest.mark.asyncio
async def test_a_new_denial_arriving_during_preparation_stops_the_permission(db, monkeypatch):
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, scan(980))
    prepare = publisher._prepare

    async def supersede(*args):
        result = await prepare(*args)
        await publisher.publish(4663, TOKEN, scan(990, "HIGH"))
        return result

    monkeypatch.setattr(publisher, "_prepare", supersede)
    chain = FakeChain()
    with rpc_node(chain):
        assert await publisher.drain_once() == "done"
    assert chain.sent == []


@pytest.mark.asyncio
async def test_deduplicated_denial_still_supersedes_an_older_permission(db):
    publisher = sender(db)
    first = await publisher.publish(4663, TOKEN, scan(980, "HIGH"))
    await db.update_verdict_onchain(first["evidence_id"], "confirmed")
    await publisher.publish(4663, TOKEN, scan(990, "HIGH"))
    await publisher.publish(4663, TOKEN, scan(985))
    chain = FakeChain()
    with rpc_node(chain):
        await drain_all(publisher)
    assert chain.sent == []
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_error"] == "SupersededObservation"


@pytest.mark.asyncio
async def test_continuous_remeasurement_does_not_postpone_refresh(db, monkeypatch):
    publisher = make_publisher(db)
    first = await publisher.publish(4663, TOKEN, scan(1000))
    await db.update_verdict_onchain(first["evidence_id"], "confirmed")
    for observed_at in (1100, 1200, 1299):
        monkeypatch.setattr(vp.time, "time", lambda: observed_at)
        repeated = await publisher.publish(4663, TOKEN, scan(observed_at))
        assert repeated["onchain_status"] == "deduplicated"
    monkeypatch.setattr(vp.time, "time", lambda: 1300)
    refreshed = await publisher.publish(4663, TOKEN, scan(1300))
    assert refreshed["onchain_status"] == "pending"


@pytest.mark.asyncio
async def test_newer_unchanged_pending_measurement_replaces_old_pending_row(db):
    publisher = sender(db)
    first = await publisher.publish(4663, TOKEN, scan(980))
    newer = await publisher.publish(4663, TOKEN, scan(990))
    chain = FakeChain()
    with rpc_node(chain):
        await drain_all(publisher)
    assert len(chain.sent) == 1
    assert decode_record(chain.sent[0])["evidence_hash"] == newer["evidence_hash"]
    assert (await db.get_verdict_evidence(first["evidence_id"]))["onchain_error"] == "SupersededObservation"


@pytest.mark.asyncio
async def test_stale_backlog_does_not_use_broadcast_capacity(db, monkeypatch):
    publisher = sender(db)
    monkeypatch.setattr(vp, "MAX_RECORDS_PER_HOUR", 1)
    await publisher.publish(4663, TOKEN, scan(600))
    await publisher.publish(4663, TOKEN, scan(990, "HIGH"))
    chain = FakeChain()
    with rpc_node(chain):
        assert await drain_all(publisher) == ["done", "done", "idle"]
    assert len(chain.sent) == 1


@pytest.mark.asyncio
async def test_expiry_during_broadcast_backoff_prevents_retry(db, monkeypatch):
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, scan(700))
    chain = FakeChain()
    post = chain.post

    def rate_limit_broadcast(url, json):
        if isinstance(json, dict) and json["method"] == "eth_sendRawTransaction":
            chain.http_statuses.append(429)
        return post(url, json)

    async def expire_on_backoff(seconds):
        if seconds:
            monkeypatch.setattr(vp.time, "time", lambda: 1001)

    monkeypatch.setattr(chain, "post", rate_limit_broadcast)
    monkeypatch.setattr(vp.asyncio, "sleep", expire_on_backoff)
    with rpc_node(chain):
        assert await publisher.drain_once() == "done"
    assert chain.sent == []
    assert chain.methods().count(["eth_sendRawTransaction"]) == 1
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_error"] == "StaleObservation"


@pytest.mark.asyncio
async def test_dropped_transaction_is_reconciled_without_being_resent(db, monkeypatch):
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, scan(700))
    chain = FakeChain()
    chain.mine = False
    monkeypatch.setattr(vp, "RECONCILE_AFTER_SECONDS", -1)
    with rpc_node(chain):
        assert await publisher.drain_once() == "done"
        assert await publisher._reconcile() == 1
        monkeypatch.setattr(vp.time, "time", lambda: 1001)
        assert await publisher.drain_once() == "done"
        assert await publisher._reconcile() == 0
        dropped = await db.get_latest_verdict_evidence(4663, TOKEN)
        assert dropped["onchain_status"] == "dropped"
        chain.receipts[dropped["tx_hash"]] = {"status": "0x1"}
        assert await publisher._reconcile() == 0
    row = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (row["onchain_status"], row["onchain_error"]) == ("confirmed", "StaleObservation")
    assert len(chain.sent) == 1
