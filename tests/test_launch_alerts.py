"""Launch alert subscriptions and the durable outbox the Telegram bot polls (no Telegram needed)."""

from types import SimpleNamespace

import pytest
import pytest_asyncio

import core.database
from core.database import Database


CHAIN = 4663
TOKENS = ["0x" + f"{index:040x}" for index in range(1, 9)]
CHAT_A, CHAT_B = 111, -100222
EVIDENCE = {
    "rug_probability": 80,
    "risk_level": "HIGH",
    "critical_flags": ["Honeypot detected", "Cannot sell token"],
    "coverage": {"structural": 1.0, "honeypot": 0.8},
    "coverage_reasons": {"honeypot": "sell tax unmeasured"},
    "status": "unknown",
}


def _launch(token, block):
    return {
        "token_address": token,
        "source": "long",
        "launchpad": "LONG",
        "source_rank": 5,
        "pool_id": None,
        "block_number": block,
        "tx_hash": "0x" + f"{block:064x}",
        "block_timestamp": 1_758_000_000 + block,
    }


async def _open(path):
    database = Database(path)
    await database.initialize()
    return database


@pytest_asyncio.fixture
async def db(tmp_path):
    database = await _open(str(tmp_path / "alerts.db"))
    yield database
    await database.close()


async def _subscribe(db, chat_id, mode, at):
    await db.subscribe_launch_alerts(chat_id, CHAIN, mode)
    await db._db.execute(
        "UPDATE launch_alert_subscriptions SET created_at = ? WHERE chat_id = ? AND chain_id = ?",
        (at, chat_id, CHAIN),
    )
    await db._db.commit()


async def _scan(db, token, status, score, at, block=100):
    await db.upsert_discovered_launches(CHAIN, [_launch(token, block)])
    await db.record_launch_scan(CHAIN, token, status, score)
    await db._db.execute(
        "UPDATE discovered_launches SET scanned_at = ? WHERE chain_id = ? AND token_address = ?",
        (at, CHAIN, token),
    )
    await db._db.commit()


async def _outbox(db):
    cursor = await db._db.execute(
        "SELECT chat_id, token_address, outcome, state FROM launch_alert_outbox"
        " ORDER BY token_address, outcome, chat_id"
    )
    return [tuple(row) for row in await cursor.fetchall()]


async def _subscriptions(db):
    cursor = await db._db.execute(
        "SELECT chat_id, chain_id, mode, created_at FROM launch_alert_subscriptions ORDER BY chat_id"
    )
    return [tuple(row) for row in await cursor.fetchall()]


# --- subscriptions ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_subscription_persists_and_a_mode_change_keeps_its_start(tmp_path):
    path = str(tmp_path / "subs.db")
    db = await _open(path)
    await _subscribe(db, CHAT_A, "blocked", at=500.0)
    await db.subscribe_launch_alerts(CHAT_A, CHAIN, "all")
    await db.close()

    reopened = await _open(path)
    try:
        assert await _subscriptions(reopened) == [(CHAT_A, CHAIN, "all", 500.0)]
    finally:
        await reopened.close()


@pytest.mark.asyncio
async def test_subscription_rejects_an_unknown_mode(db):
    with pytest.raises(Exception, match="CHECK constraint failed"):
        await db.subscribe_launch_alerts(CHAT_A, CHAIN, "everything")


@pytest.mark.asyncio
async def test_unsubscribe_removes_the_chat_and_cancels_its_queue(db):
    await _subscribe(db, CHAT_A, "all", at=500.0)
    await _subscribe(db, CHAT_B, "all", at=500.0)
    await _scan(db, TOKENS[0], "unknown", None, at=1000.0)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)

    assert await db.unsubscribe_launch_alerts(CHAT_A, CHAIN) is True
    assert await db.unsubscribe_launch_alerts(CHAT_A, CHAIN) is False

    assert [row[0] for row in await _subscriptions(db)] == [CHAT_B]
    assert await _outbox(db) == [
        (CHAT_B, TOKENS[0], "unknown", "pending"),
        (CHAT_A, TOKENS[0], "unknown", "cancelled"),
    ]


@pytest.mark.asyncio
async def test_a_migrated_chat_keeps_its_subscription_and_queue(db):
    await _subscribe(db, CHAT_A, "all", at=500.0)
    for index, token in enumerate(TOKENS[:3]):
        await _scan(db, token, "blocked", 90, at=1000.0 + index, block=100 + index)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)
    sent, *_ = await db.get_pending_launch_alerts(now=1000.0, max_age=3600, per_chat=5, limit=5)
    await db.claim_launch_alert(sent["id"])
    await db.set_launch_alert_state(sent["id"], "sent")

    await db.move_launch_alert_chat(CHAT_A, -100999, CHAIN)

    assert await _subscriptions(db) == [(-100999, CHAIN, "all", 500.0)]
    assert await _outbox(db) == [
        (CHAT_A, TOKENS[0], "blocked", "sent"),
        (-100999, TOKENS[1], "blocked", "pending"),
        (-100999, TOKENS[2], "blocked", "pending"),
    ]


@pytest.mark.asyncio
async def test_a_chat_migrating_into_a_subscribed_chat_keeps_that_subscription_and_queue(db):
    await _subscribe(db, CHAT_A, "all", at=500.0)
    await _subscribe(db, CHAT_B, "blocked", at=700.0)
    await _scan(db, TOKENS[0], "blocked", 90, at=1000.0)
    await _scan(db, TOKENS[1], "unknown", None, at=1001.0, block=101)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)

    await db.move_launch_alert_chat(CHAT_A, CHAT_B, CHAIN)

    assert await _subscriptions(db) == [(CHAT_B, CHAIN, "blocked", 700.0)]
    assert await _outbox(db) == [
        (CHAT_B, TOKENS[0], "blocked", "pending"),
        (CHAT_A, TOKENS[0], "blocked", "cancelled"),
        (CHAT_A, TOKENS[1], "unknown", "cancelled"),
    ]


# --- enqueue ----------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_mode_queues_only_blocked_and_all_mode_queues_every_outcome(db):
    await _subscribe(db, CHAT_A, "blocked", at=500.0)
    await _subscribe(db, CHAT_B, "all", at=500.0)
    for token, status in zip(TOKENS, ("blocked", "unknown", "watching", "cleared", "error")):
        await _scan(db, token, status, 50, at=1000.0)
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[5], 101)])

    await db.enqueue_launch_alerts(CHAIN, since=900.0)

    assert await _outbox(db) == [
        (CHAT_B, TOKENS[0], "blocked", "pending"),
        (CHAT_A, TOKENS[0], "blocked", "pending"),
        (CHAT_B, TOKENS[1], "unknown", "pending"),
        (CHAT_B, TOKENS[2], "watching", "pending"),
        (CHAT_B, TOKENS[3], "cleared", "pending"),
        (CHAT_B, TOKENS[4], "unknown", "pending"),
    ]


@pytest.mark.asyncio
async def test_payload_is_the_feed_item(db):
    await _subscribe(db, CHAT_A, "blocked", at=500.0)
    await _scan(db, TOKENS[0], "blocked", 80, at=1000.0)
    await db.insert_agent_finding(
        finding_type="hunter_sweep",
        address=TOKENS[0],
        chain_id=CHAIN,
        risk_score=80,
        evidence=EVIDENCE,
        action_taken="blocked",
    )
    feed, _ = await db.get_launch_feed(CHAIN, 10)

    await db.enqueue_launch_alerts(CHAIN, since=900.0)

    (alert,) = await db.get_pending_launch_alerts(now=1000.0, max_age=3600, per_chat=5, limit=5)
    assert alert["payload"] == feed[0]
    assert alert["payload"]["scan"]["status"] == "unknown"
    assert (alert["chat_id"], alert["chain_id"], alert["token_address"], alert["outcome"]) == (
        CHAT_A,
        CHAIN,
        TOKENS[0],
        "blocked",
    )


@pytest.mark.asyncio
async def test_outcomes_outside_the_window_or_before_subscribing_are_not_queued(db):
    await _subscribe(db, CHAT_A, "all", at=1500.0)
    await _scan(db, TOKENS[0], "blocked", 90, at=800.0)
    await _scan(db, TOKENS[1], "blocked", 90, at=1200.0)
    await _scan(db, TOKENS[2], "blocked", 90, at=1600.0)
    await db.upsert_discovered_launches(CHAIN, [_launch(TOKENS[3], 101)])

    await db.enqueue_launch_alerts(CHAIN, since=900.0)

    assert await _outbox(db) == [(CHAT_A, TOKENS[2], "blocked", "pending")]


@pytest.mark.asyncio
async def test_repeated_passes_and_a_restart_queue_nothing_twice(tmp_path):
    path = str(tmp_path / "restart.db")
    db = await _open(path)
    await _subscribe(db, CHAT_A, "all", at=500.0)
    await _scan(db, TOKENS[0], "blocked", 90, at=1000.0)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)
    await db.close()

    reopened = await _open(path)
    try:
        await reopened.enqueue_launch_alerts(CHAIN, since=0.0)
        assert await _outbox(reopened) == [(CHAT_A, TOKENS[0], "blocked", "pending")]
    finally:
        await reopened.close()


async def _recheck_blocked(db, token, at):
    await db.upsert_tracked_pair(token, token_address=token, chain_id=CHAIN)
    await db._db.execute(
        "UPDATE tracked_pairs SET status = 'blocked', last_checked = ? WHERE pair_address = ?",
        (at, token),
    )
    await db._db.commit()


@pytest.mark.asyncio
async def test_a_rechecked_block_waits_for_its_evidence_before_queueing(db, monkeypatch):
    await _subscribe(db, CHAT_A, "blocked", at=500.0)
    await _scan(db, TOKENS[0], "unknown", 20, at=1000.0)
    await _recheck_blocked(db, TOKENS[0], at=2000.0)
    monkeypatch.setattr(core.database, "time", SimpleNamespace(time=lambda: 2010.0))

    held = await db.enqueue_launch_alerts(CHAIN, since=1990.0)
    assert held == 2000.0
    assert await _outbox(db) == []

    await db.insert_agent_finding(
        finding_type="hunter_sweep", address=TOKENS[0], chain_id=CHAIN,
        risk_score=85, evidence=EVIDENCE, action_taken="blocked",
    )
    assert await db.enqueue_launch_alerts(CHAIN, since=held) is None

    (alert,) = await db.get_pending_launch_alerts(now=2010.0, max_age=3600, per_chat=5, limit=5)
    assert alert["outcome"] == "blocked"
    assert alert["payload"]["scan"]["coverage"] == EVIDENCE["coverage"]
    assert alert["payload"]["scan"]["flags"] == EVIDENCE["critical_flags"]
    assert alert["payload"]["scan"]["risk_score"] == 85


@pytest.mark.asyncio
async def test_a_block_whose_evidence_never_arrives_is_queued_after_the_wait_without_it(db, monkeypatch):
    await _subscribe(db, CHAT_A, "blocked", at=500.0)
    await _scan(db, TOKENS[0], "unknown", 20, at=1000.0)
    await _recheck_blocked(db, TOKENS[0], at=2000.0)
    monkeypatch.setattr(core.database, "time", SimpleNamespace(time=lambda: 2301.0))

    assert await db.enqueue_launch_alerts(CHAIN, since=1990.0) is None

    (alert,) = await db.get_pending_launch_alerts(now=2301.0, max_age=3600, per_chat=5, limit=5)
    assert alert["payload"]["scan"]["status"] == "unknown"
    assert alert["payload"]["scan"]["coverage_reasons"] == {
        "scan": "Coverage details were not recorded for this scan"
    }


@pytest.mark.asyncio
async def test_a_recheck_that_blocks_a_launch_is_a_new_alert(db):
    await _subscribe(db, CHAT_A, "blocked", at=500.0)
    await _subscribe(db, CHAT_B, "all", at=500.0)
    await _scan(db, TOKENS[0], "unknown", 20, at=1000.0)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)
    await db.upsert_tracked_pair(TOKENS[0], token_address=TOKENS[0], chain_id=CHAIN)
    await db._db.execute(
        "UPDATE tracked_pairs SET status = 'blocked', last_checked = 2000.0 WHERE pair_address = ?",
        (TOKENS[0],),
    )
    await db._db.commit()

    await db.enqueue_launch_alerts(CHAIN, since=1900.0)

    assert await _outbox(db) == [
        (CHAT_B, TOKENS[0], "blocked", "pending"),
        (CHAT_A, TOKENS[0], "blocked", "pending"),
        (CHAT_B, TOKENS[0], "unknown", "pending"),
    ]


@pytest.mark.asyncio
async def test_enqueue_without_subscribers_queues_nothing(db):
    await _scan(db, TOKENS[0], "blocked", 90, at=1000.0)

    await db.enqueue_launch_alerts(CHAIN, since=900.0)

    assert await _outbox(db) == []


# --- delivery bookkeeping -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pending_alerts_are_capped_per_chat_and_in_total_oldest_first(db):
    await _subscribe(db, CHAT_A, "all", at=500.0)
    await _subscribe(db, CHAT_B, "all", at=500.0)
    for index, token in enumerate(TOKENS[:4]):
        await _scan(db, token, "blocked", 90, at=1000.0 + index, block=100 + index)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)

    capped = await db.get_pending_launch_alerts(now=1010.0, max_age=3600, per_chat=2, limit=10)
    total = await db.get_pending_launch_alerts(now=1010.0, max_age=3600, per_chat=2, limit=3)

    assert [(alert["chat_id"], alert["token_address"]) for alert in capped] == [
        (CHAT_B, TOKENS[0]),
        (CHAT_A, TOKENS[0]),
        (CHAT_B, TOKENS[1]),
        (CHAT_A, TOKENS[1]),
    ]
    assert [alert["id"] for alert in total] == [alert["id"] for alert in capped[:3]]


@pytest.mark.asyncio
async def test_stale_pending_alerts_expire_instead_of_sending(db):
    await _subscribe(db, CHAT_A, "all", at=500.0)
    await _scan(db, TOKENS[0], "blocked", 90, at=1000.0)
    await _scan(db, TOKENS[1], "blocked", 90, at=3000.0, block=101)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)

    pending = await db.get_pending_launch_alerts(now=4700.0, max_age=3600, per_chat=5, limit=5)

    assert [alert["token_address"] for alert in pending] == [TOKENS[1]]
    assert await _outbox(db) == [
        (CHAT_A, TOKENS[0], "blocked", "expired"),
        (CHAT_A, TOKENS[1], "blocked", "pending"),
    ]


@pytest.mark.asyncio
async def test_an_alert_is_claimed_once_and_a_claimed_alert_is_never_pending_again(tmp_path):
    path = str(tmp_path / "claim.db")
    db = await _open(path)
    await _subscribe(db, CHAT_A, "all", at=500.0)
    await _scan(db, TOKENS[0], "blocked", 90, at=1000.0)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)
    (alert,) = await db.get_pending_launch_alerts(now=1000.0, max_age=3600, per_chat=5, limit=5)

    assert await db.claim_launch_alert(alert["id"]) is True
    assert await db.claim_launch_alert(alert["id"]) is False
    await db.close()

    reopened = await _open(path)
    try:
        await reopened.enqueue_launch_alerts(CHAIN, since=0.0)
        assert (
            await reopened.get_pending_launch_alerts(now=1000.0, max_age=3600, per_chat=5, limit=5)
            == []
        )
        assert await _outbox(reopened) == [(CHAT_A, TOKENS[0], "blocked", "sending")]
    finally:
        await reopened.close()


@pytest.mark.asyncio
async def test_an_alert_left_sending_by_a_dead_pass_becomes_unconfirmed_and_is_never_resent(db):
    await _subscribe(db, CHAT_A, "all", at=500.0)
    await _scan(db, TOKENS[0], "blocked", 90, at=1000.0)
    await _scan(db, TOKENS[1], "blocked", 90, at=1000.0, block=101)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)
    stale, recent = await db.get_pending_launch_alerts(now=1000.0, max_age=3600, per_chat=5, limit=5)
    await db.claim_launch_alert(stale["id"])
    await db.claim_launch_alert(recent["id"])
    await db._db.execute("UPDATE launch_alert_outbox SET updated_at = 1000.0 WHERE id = ?", (stale["id"],))
    await db._db.execute("UPDATE launch_alert_outbox SET updated_at = 1200.0 WHERE id = ?", (recent["id"],))
    await db._db.commit()

    pending = await db.get_pending_launch_alerts(now=1301.0, max_age=3600, per_chat=5, limit=5)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)

    assert pending == []
    assert await db.get_pending_launch_alerts(now=1301.0, max_age=3600, per_chat=5, limit=5) == []
    cursor = await db._db.execute("SELECT id, state, error FROM launch_alert_outbox ORDER BY id")
    assert [tuple(row) for row in await cursor.fetchall()] == [
        (stale["id"], "unconfirmed", "Interrupted"),
        (recent["id"], "sending", None),
    ]


@pytest.mark.asyncio
async def test_alert_state_records_the_outcome_and_a_released_alert_is_pending_again(db):
    await _subscribe(db, CHAT_A, "all", at=500.0)
    await _scan(db, TOKENS[0], "blocked", 90, at=1000.0)
    await _scan(db, TOKENS[1], "blocked", 90, at=1000.0, block=101)
    await db.enqueue_launch_alerts(CHAIN, since=900.0)
    first, second = await db.get_pending_launch_alerts(
        now=1000.0, max_age=3600, per_chat=5, limit=5
    )
    await db.claim_launch_alert(first["id"])
    await db.claim_launch_alert(second["id"])

    await db.set_launch_alert_state(first["id"], "failed", "Forbidden")
    await db.set_launch_alert_state(second["id"], "pending")

    cursor = await db._db.execute("SELECT id, state, error FROM launch_alert_outbox ORDER BY id")
    assert [tuple(row) for row in await cursor.fetchall()] == [
        (first["id"], "failed", "Forbidden"),
        (second["id"], "pending", None),
    ]
