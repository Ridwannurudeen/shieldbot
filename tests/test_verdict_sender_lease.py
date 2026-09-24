"""The sender lease: of all the verdict drains on one database, only the lease holder stores and broadcasts.

A second drain can start by mistake: a second workers.py, or an API still running the drain after
BACKGROUND_WORKERS=external was set. Two drains on one recorder account would race for its nonces. The fake
node and the dummy key come from tests/test_verdict_publisher.py; no test touches the network.
"""

import asyncio
import logging
import sqlite3
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

import services.verdict_publisher as vp
from core.database import Database
from services.verdict_publisher import VerdictPublisher
from tests.test_verdict_publisher import (
    KEY,
    REGISTRY,
    RPC,
    TOKEN,
    FakeChain,
    gate_method,
    rpc_node,
    sends_settled,
    until,
)
from eth_account import Account

from tests.test_verdict_storage import insert

TOKENS = ["0x" + f"{n:040x}" for n in range(1, 4)]
RPC_A = "https://rpc-a.invalid/4663"
RPC_B = "https://rpc-b.invalid/4663"
DRAIN_TASKS = ("VerdictPublisher._drain_under_lease", "VerdictPublisher._drain_loop")


def scan():
    """A complete scan observed now: the drain drops observations older than five minutes."""
    return {
        "observed_at": int(time.time()),
        "status": "ok",
        "risk_level": "LOW",
        "rug_probability": 5.0,
        "coverage": {"structural": 1, "honeypot": 1},
        "coverage_reasons": {},
    }


@pytest.fixture
def short_lease(monkeypatch):
    monkeypatch.setattr(vp, "LEASE_SECONDS", 0.3)
    monkeypatch.setattr(vp, "LEASE_RENEW_SECONDS", 0.05)
    monkeypatch.setattr(vp, "DB_LOCK_WAIT_SECONDS", 0.05)
    # A send goes ahead only under a lease with a lock wait and a broadcast phase still to run.
    monkeypatch.setattr(vp, "PHASE_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(vp, "RECEIPT_DELAY_SECONDS", 0)


@pytest_asyncio.fixture
async def two_processes(tmp_path):
    """Two processes' connections to one database file."""
    path = str(tmp_path / "shieldbot.db")
    first, second = Database(path), Database(path)
    await first.initialize()
    await second.initialize()
    yield first, second
    await first.close()
    await second.close()


def publisher_on(db, rpc_url=RPC):
    return VerdictPublisher(db, rpc_url=rpc_url, registry_address=REGISTRY)


async def lease(db):
    return await lease_row(db, vp.LEASE_NAME)


async def lease_row(db, name):
    cursor = await db._db.execute("SELECT holder, expires_at FROM sender_leases WHERE name = ?", (name,))
    return await cursor.fetchone()


async def holds(db, publisher):
    row = await lease(db)
    return row is not None and row[0] == publisher._lease_holder


async def confirmed(db, subject):
    stored = await db.get_latest_verdict_evidence(4663, subject)
    return stored is not None and stored["onchain_status"] == "confirmed"


async def queued(db, subject):
    stored = await db.get_latest_verdict_evidence(4663, subject)
    return stored is not None and stored["onchain_status"] == "pending"


def running_drains():
    return [task for task in asyncio.all_tasks() if task.get_coro().__qualname__ in DRAIN_TASKS]


def watch_broadcasts(chain, gated_url=None, on_broadcast=None):
    """Note the RPC URL of every eth_sendRawTransaction; hold those sent to gated_url until the event is set."""
    gate = asyncio.Event()
    broadcasts = []
    original = chain.post

    def post(url, json):
        rows = json if isinstance(json, list) else [json]
        broadcast = any(row["method"] == "eth_sendRawTransaction" for row in rows)
        if broadcast:
            broadcasts.append(url)
            if on_broadcast is not None:
                on_broadcast(url)
        response = original(url, json)
        if broadcast and url == gated_url:
            response._gate = gate
        return response

    chain.post = post
    return broadcasts, gate


def hold_calls(chain, url, method):
    """Hold the node's answer to `method` from `url` until the returned event is set."""
    gate = asyncio.Event()
    original = chain.post

    def post(posted_url, json):
        response = original(posted_url, json)
        rows = json if isinstance(json, list) else [json]
        if posted_url == url and any(row["method"] == method for row in rows):
            response._gate = gate
        return response

    chain.post = post
    return gate


def methods_posted_to(chain, url):
    return [
        row["method"]
        for posted_url, body in chain.posts
        if posted_url == url
        for row in (body if isinstance(body, list) else [body])
    ]


# ---------------------------------------------------------------------------
# The lease in the database
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_lease_has_one_holder_until_it_expires_unrenewed(two_processes, monkeypatch):
    first_db, second_db = two_processes
    clock = SimpleNamespace(now=1_790_000_000.0)
    monkeypatch.setattr("core.database.time", SimpleNamespace(time=lambda: clock.now))

    assert await first_db.take_sender_lease("drain", "host-a:1:aa", 60) == (
        "host-a:1:aa",
        clock.now + 60,
    )
    assert await second_db.take_sender_lease("drain", "host-b:2:bb", 60) == (
        "host-a:1:aa",
        clock.now + 60,
    )
    clock.now += 45
    # The holder renews; the other still cannot take it.
    assert await first_db.take_sender_lease("drain", "host-a:1:aa", 60) == (
        "host-a:1:aa",
        clock.now + 60,
    )
    clock.now += 59
    assert (await second_db.take_sender_lease("drain", "host-b:2:bb", 60))[0] == "host-a:1:aa"
    # Unrenewed for its whole period, the lease goes to the next process that asks.
    clock.now += 1
    assert await second_db.take_sender_lease("drain", "host-b:2:bb", 60) == (
        "host-b:2:bb",
        clock.now + 60,
    )
    # Only the holder can release it.
    await first_db.release_sender_lease("drain", "host-a:1:aa")
    assert (await first_db.take_sender_lease("drain", "host-a:1:aa", 60))[0] == "host-b:2:bb"
    await second_db.release_sender_lease("drain", "host-b:2:bb")
    assert (await first_db.take_sender_lease("drain", "host-a:1:aa", 60))[0] == "host-a:1:aa"


@pytest.mark.asyncio
async def test_processes_asking_at_once_get_one_holder(tmp_path):
    path = str(tmp_path / "shieldbot.db")
    processes = [Database(path) for _ in range(4)]
    for db in processes:
        await db.initialize()
    try:
        answers = await asyncio.gather(
            *(db.take_sender_lease("drain", f"host:{n}:aa", 90) for n, db in enumerate(processes))
        )
        holders = {holder for holder, _ in answers}
        assert len(holders) == 1 and holders <= {f"host:{n}:aa" for n in range(4)}
    finally:
        for db in processes:
            await db.close()


@pytest.mark.asyncio
async def test_lease_writes_never_commit_or_roll_back_the_drains_transaction(tmp_path):
    db = Database(str(tmp_path / "shieldbot.db"))
    await db.initialize()
    try:
        evidence_id = await insert(db, onchain_status="pending")
        outbox = await db._outbox()
        # The drain is part way through a transaction of its own.
        await outbox.execute(
            "UPDATE verdict_evidence SET onchain_status = 'sending' WHERE id = ?", (evidence_id,)
        )
        renewal = asyncio.create_task(db.take_sender_lease("drain", "host:1:aa", 90))
        await asyncio.sleep(0.05)
        # The drain undoes its own write; a lease renewal must not have committed it.
        await outbox.rollback()
        assert (await renewal)[0] == "host:1:aa"
        assert (await db.get_verdict_evidence(evidence_id))["onchain_status"] == "pending"
        assert db._lease_db is not None
        assert db._lease_db is not db._drain_db and db._lease_db is not db._db
    finally:
        await db.close()
    assert db._lease_db is None


@pytest.mark.asyncio
async def test_a_failed_renewal_never_rolls_back_a_take_running_beside_it(two_processes):
    db, other_process = two_processes
    await db.take_sender_lease("drain", "host:1:aa", 90)
    _, old_expiry = await lease_row(db, "drain")
    # A lock wait shorter than production's, so the renewal below gives up quickly.
    await (await db._lease()).execute("PRAGMA busy_timeout=200")
    # Another connection holds the write lock for longer than that.
    await other_process._db.execute("BEGIN IMMEDIATE")
    renewal = asyncio.create_task(db.take_sender_lease("drain", "host:1:aa", 90))
    await asyncio.sleep(0.05)
    # The check at a send asks while the renewal is still waiting for the lock.
    fence = asyncio.create_task(db.take_sender_lease("drain", "host:1:aa", 90))
    await asyncio.sleep(0.25)
    await other_process._db.rollback()
    renewed, fenced = await asyncio.gather(renewal, fence, return_exceptions=True)
    assert isinstance(renewed, sqlite3.OperationalError)
    # The failed renewal's rollback did not undo the fence's take: it got the fresh expiry, or it refused.
    assert isinstance(fenced, Exception) or fenced[1] > old_expiry
    if not isinstance(fenced, Exception):
        assert await lease_row(db, "drain") == fenced


@pytest.mark.asyncio
async def test_a_lease_released_between_the_take_and_its_read_is_not_held(tmp_path):
    db = Database(str(tmp_path / "shieldbot.db"))
    await db.initialize()
    try:
        # Another process releases the lease the moment this take writes it.
        await (await db._lease()).execute(
            "CREATE TEMP TRIGGER released AFTER INSERT ON sender_leases BEGIN DELETE FROM sender_leases; END"
        )
        holder, expires_at = await db.take_sender_lease("drain", "host:1:aa", 90)
        assert holder is None and expires_at <= time.time()
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_close_closes_every_connection_when_one_fails_to_close(tmp_path):
    db = Database(str(tmp_path / "shieldbot.db"))
    await db.initialize()
    drain, lease_connection, shared = await db._outbox(), await db._lease(), db._db
    close_drain = drain.close

    async def fails():
        raise sqlite3.OperationalError("disk I/O error")

    drain.close = fails
    with pytest.raises(sqlite3.OperationalError):
        await db.close()
    for connection in (lease_connection, shared):
        with pytest.raises(ValueError):
            await connection.execute("SELECT 1")
    await close_drain()


@pytest.mark.asyncio
async def test_a_lease_call_after_close_never_reopens_its_connection(tmp_path):
    db = Database(str(tmp_path / "shieldbot.db"))
    await db.initialize()
    await db.take_sender_lease("drain", "host:1:aa", 90)
    await db.close()
    with pytest.raises(AttributeError):
        await db.take_sender_lease("drain", "host:1:aa", 90)
    assert db._lease_db is None


# ---------------------------------------------------------------------------
# Drains
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_of_two_drains_on_one_database_only_the_lease_holder_sends(
    two_processes, short_lease, caplog
):
    caplog.set_level(logging.INFO, logger="services.verdict_publisher")
    first_db, second_db = two_processes
    first, second = publisher_on(first_db), publisher_on(second_db)
    second._rpc = AsyncMock(side_effect=AssertionError("only the lease holder may contact the RPC"))
    chain = FakeChain()
    with rpc_node(chain):
        first.start(recorder_key=KEY)
        await until(lambda: holds(first_db, first))
        second.start(recorder_key=KEY)
        # Several lease periods: the holder keeps renewing, so the waiting drain never takes over.
        await asyncio.sleep(1.0)
        assert await holds(first_db, first)
        for token in TOKENS:
            await first.publish(4663, token, scan())
        for token in TOKENS:
            await until(lambda token=token: confirmed(first_db, token))
        await second.stop()
        await first.stop()
    assert len(chain.sent) == len(TOKENS)
    second._rpc.assert_not_called()
    assert f"sending as recorder {first.recorder}" in caplog.text
    assert f"not sending, {first._lease_holder} holds the sender lease" in caplog.text


@pytest.mark.asyncio
async def test_a_dead_holders_lease_expires_and_the_waiting_drain_takes_over(
    two_processes, short_lease
):
    first_db, second_db = two_processes
    first, second = publisher_on(first_db), publisher_on(second_db)
    chain = FakeChain()
    with rpc_node(chain):
        first.start(recorder_key=KEY)
        await until(lambda: holds(first_db, first))
        second.start(recorder_key=KEY)
        await asyncio.sleep(0.1)
        # The holder dies without releasing the lease, and its connection closes with it.
        first._drain_task.cancel()
        await asyncio.gather(first._drain_task, return_exceptions=True)
        await first_db.close()
        # The lease stays with the dead process until it expires, then the waiting drain takes it.
        assert (await lease(second_db))[0] == first._lease_holder
        await until(lambda: holds(second_db, second))
        await second.publish(4663, TOKEN, scan())
        await until(lambda: confirmed(second_db, TOKEN))
        await second.stop()
    assert len(chain.sent) == 1


@pytest.mark.asyncio
async def test_a_waiting_drain_asks_again_when_the_lease_expires_not_a_whole_period_later(
    two_processes, short_lease, monkeypatch
):
    monkeypatch.setattr(vp, "LEASE_SECONDS", 60.0)
    first_db, second_db = two_processes
    first, second = publisher_on(first_db), publisher_on(second_db)
    with rpc_node(FakeChain()):
        first.start(recorder_key=KEY)
        await until(lambda: holds(first_db, first))
        # The holder dies with its lease a moment from expiring.
        first._drain_task.cancel()
        await asyncio.gather(first._drain_task, return_exceptions=True)
        await first_db.close()
        await second_db._db.execute("UPDATE sender_leases SET expires_at = ?", (time.time() + 0.3,))
        await second_db._db.commit()
        second.start(recorder_key=KEY)
        await until(lambda: holds(second_db, second))
        await second.stop()


@pytest.mark.asyncio
async def test_a_holder_that_finds_another_holder_stops_sending_until_it_can_take_the_lease_again(
    two_processes, short_lease, caplog
):
    db, other_process = two_processes
    publisher = publisher_on(db)
    chain = FakeChain()
    with rpc_node(chain):
        publisher.start(recorder_key=KEY)
        await until(lambda: holds(db, publisher))
        # Another drain holds it now, as it may once this one has gone a whole lease period unrenewed.
        await other_process._db.execute(
            "UPDATE sender_leases SET holder = 'other-host:1:ab', expires_at = ?",
            (time.time() + 3600,),
        )
        await other_process._db.commit()
        await until(lambda: asyncio.sleep(0, "stopped sending" in caplog.text))
        await publisher.publish(4663, TOKEN, scan())
        await asyncio.sleep(0.5)
        assert chain.sent == []
        # Once the other drain's lease is gone, this one takes it at its next try and sends.
        await other_process._db.execute("DELETE FROM sender_leases")
        await other_process._db.commit()
        await until(lambda: confirmed(db, TOKEN))
        await publisher.stop()
    assert len(chain.sent) == 1


@pytest.mark.asyncio
async def test_a_holder_whose_renewals_hang_then_fail_stops_while_its_lease_is_still_live(
    two_processes, monkeypatch, caplog
):
    monkeypatch.setattr(vp, "LEASE_SECONDS", 2.0)
    monkeypatch.setattr(vp, "LEASE_RENEW_SECONDS", 0.2)
    monkeypatch.setattr(vp, "DB_LOCK_WAIT_SECONDS", 0.5)
    db, other_process = two_processes
    publisher = publisher_on(db)

    async def locked(*args):
        # "database is locked" arrives only once the busy timeout has passed.
        await asyncio.sleep(vp.DB_LOCK_WAIT_SECONDS)
        raise sqlite3.OperationalError("database is locked")

    with rpc_node(FakeChain()):
        publisher.start(recorder_key=KEY)
        await until(lambda: holds(db, publisher))
        monkeypatch.setattr(db, "take_sender_lease", locked)
        await until(lambda: asyncio.sleep(0, "stopped sending" in caplog.text), tries=400)
        # No other drain could have taken the lease yet: the drain stopped before it lapsed.
        holder, expires_at = await lease(other_process)
        assert holder == publisher._lease_holder and expires_at > time.time()
        assert "OperationalError" in caplog.text
        await publisher.stop()


@pytest.mark.asyncio
async def test_renewal_is_not_attempted_when_waiting_out_the_lock_could_run_the_lease_out(monkeypatch):
    # The production timings: a 90 s lease renewed every 15 s, and a lock wait of 5 s before a renewal fails.
    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(vp.time, "time", lambda: clock.now)
    publisher = publisher_on(None)
    attempts = []

    async def locked():
        attempts.append(clock.now)
        clock.now += vp.DB_LOCK_WAIT_SECONDS
        raise sqlite3.OperationalError("database is locked")

    async def sleep(seconds):
        clock.now += seconds

    publisher._take_lease = locked
    with patch("services.verdict_publisher.asyncio.sleep", new=sleep):
        await publisher._keep_lease(1000.0 + vp.LEASE_SECONDS)
    # Each attempt could wait out the lock and still leave a renewal period of the lease; the next one could not.
    assert attempts == [1015.0, 1035.0, 1055.0]
    assert clock.now == 1075.0


@pytest.mark.asyncio
async def test_a_drain_that_lost_the_lease_neither_stores_nor_broadcasts_what_it_signed(
    two_processes, monkeypatch, caplog
):
    monkeypatch.setattr(vp, "LEASE_SECONDS", 1.0)
    monkeypatch.setattr(vp, "LEASE_RENEW_SECONDS", 0.1)
    monkeypatch.setattr(vp, "DB_LOCK_WAIT_SECONDS", 0.05)
    monkeypatch.setattr(vp, "PHASE_TIMEOUT_SECONDS", 0.8)
    monkeypatch.setattr(vp, "DRAIN_POLL_SECONDS", 3600)
    monkeypatch.setattr(vp, "RECEIPT_DELAY_SECONDS", 0)
    first_db, second_db = two_processes
    first, second = publisher_on(first_db, RPC_A), publisher_on(second_db, RPC_B)

    async def never_renews(held_until):
        await asyncio.Event().wait()

    # The first drain's renewal loop never runs: only the check at the send can stop it.
    first._keep_lease = never_renews
    chain = FakeChain()
    broadcasts, _ = watch_broadcasts(chain)
    reads = hold_calls(chain, RPC_A, "eth_getTransactionCount")
    with rpc_node(chain):
        first.start(recorder_key=KEY)
        await until(lambda: holds(first_db, first))
        second.start(recorder_key=KEY)
        # Shortly before the first drain's lease runs out unrenewed, it claims a row while it still holds the
        # lease, and its reads before signing are held up.
        _, expires_at = await lease(first_db)
        await asyncio.sleep(max(0.0, expires_at - 0.3 - time.time()))
        await first.publish(4663, TOKEN, scan())
        await until(
            lambda: asyncio.sleep(0, "eth_getTransactionCount" in methods_posted_to(chain, RPC_A))
        )
        # Meanwhile its lease runs out unrenewed and the second drain takes it.
        await until(lambda: holds(second_db, second))
        reads.set()
        await until(
            lambda: asyncio.sleep(0, f"not sending, {second._lease_holder} holds" in caplog.text)
        )
        # The first drain claimed the row and signed, then found the lease gone: the row goes back to the queue
        # with nothing stored or broadcast.
        await until(lambda: queued(first_db, TOKEN))
        assert "eth_getTransactionCount" in methods_posted_to(chain, RPC_A)
        assert RPC_A not in broadcasts
        evidence_id = (await first_db.get_latest_verdict_evidence(4663, TOKEN))["id"]
        assert await first_db.get_verdict_transactions([evidence_id]) == {evidence_id: []}
        second._wake.set()
        await until(lambda: confirmed(second_db, TOKEN))
        await first.stop()
        await second.stop()
    assert broadcasts == [RPC_B]
    assert len(chain.sent) == 1


@pytest.mark.asyncio
async def test_a_new_holder_never_broadcasts_while_the_old_holders_broadcast_is_open(
    two_processes, monkeypatch
):
    monkeypatch.setattr(vp, "LEASE_SECONDS", 2.0)
    monkeypatch.setattr(vp, "LEASE_RENEW_SECONDS", 0.2)
    monkeypatch.setattr(vp, "DB_LOCK_WAIT_SECONDS", 0.05)
    # The broadcast phase is shorter than the lease, as PHASE_TIMEOUT_SECONDS is shorter than LEASE_SECONDS.
    monkeypatch.setattr(vp, "PHASE_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(vp, "DRAIN_POLL_SECONDS", 0.05)
    monkeypatch.setattr(vp, "RECEIPT_DELAY_SECONDS", 0)
    first_db, second_db = two_processes
    first, second = publisher_on(first_db, RPC_A), publisher_on(second_db, RPC_B)
    chain = FakeChain()
    open_sends_at_second_broadcast = []

    def on_broadcast(url):
        if url == RPC_B:
            open_sends_at_second_broadcast.append(len(first._tasks))

    # The first drain's broadcast hangs until its phase timeout.
    broadcasts, _ = watch_broadcasts(chain, gated_url=RPC_A, on_broadcast=on_broadcast)
    with rpc_node(chain):
        first.start(recorder_key=KEY)
        await until(lambda: holds(first_db, first))
        second.start(recorder_key=KEY)
        await first.publish(4663, TOKEN, scan())
        await until(lambda: asyncio.sleep(0, RPC_A in broadcasts))
        # Then its renewals break, so its lease runs out and the second drain takes over.
        monkeypatch.setattr(
            first_db, "take_sender_lease", AsyncMock(side_effect=RuntimeError("database is locked"))
        )
        await until(lambda: holds(second_db, second))
        await second.publish(4663, TOKENS[0], scan())
        await until(lambda: confirmed(second_db, TOKENS[0]))
        await first.stop()
        await second.stop()
    assert broadcasts == [RPC_A, RPC_B]
    assert open_sends_at_second_broadcast == [0]


@pytest.mark.asyncio
async def test_a_send_that_cannot_renew_the_lease_is_not_broadcast_so_a_new_holder_never_overlaps_it(
    two_processes, monkeypatch
):
    monkeypatch.setattr(vp, "LEASE_SECONDS", 2.0)
    monkeypatch.setattr(vp, "LEASE_RENEW_SECONDS", 0.2)
    monkeypatch.setattr(vp, "DB_LOCK_WAIT_SECONDS", 0.05)
    monkeypatch.setattr(vp, "PHASE_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(vp, "DRAIN_POLL_SECONDS", 0.05)
    monkeypatch.setattr(vp, "RECEIPT_DELAY_SECONDS", 0)
    first_db, second_db = two_processes
    first, second = publisher_on(first_db, RPC_A), publisher_on(second_db, RPC_B)
    chain = FakeChain()
    open_sends_at_second_broadcast = []

    def on_broadcast(url):
        if url == RPC_B:
            open_sends_at_second_broadcast.append(len(first._tasks))

    broadcasts, _ = watch_broadcasts(chain, gated_url=RPC_A, on_broadcast=on_broadcast)
    with rpc_node(chain):
        first.start(recorder_key=KEY)
        await until(lambda: holds(first_db, first))
        second.start(recorder_key=KEY)
        # The first drain's renewals break; its lease now runs out at a fixed time.
        monkeypatch.setattr(
            first_db, "take_sender_lease", AsyncMock(side_effect=RuntimeError("database is locked"))
        )
        await asyncio.sleep(0.3)
        _, expires_at = await lease(second_db)
        # A row reaches the first drain half a second before the lease lapses: a broadcast started now would
        # still be open when the second drain takes over.
        await asyncio.sleep(max(0.0, expires_at - 0.5 - time.time()))
        await first.publish(4663, TOKEN, scan())
        await until(lambda: holds(second_db, second))
        await second.publish(4663, TOKENS[0], scan())
        await until(lambda: confirmed(second_db, TOKENS[0]))
        await until(lambda: confirmed(second_db, TOKEN))
        await first.stop()
        await second.stop()
    assert RPC_A not in broadcasts
    assert open_sends_at_second_broadcast == [0, 0]


def sending_publisher(db):
    """A publisher that holds the key, with its drain driven by the test."""
    publisher = publisher_on(db)
    publisher._account = Account.from_key(KEY)
    publisher.recorder = publisher._account.address
    return publisher


@pytest.mark.asyncio
async def test_a_send_under_a_lease_too_short_for_its_broadcast_is_not_made_and_stops_the_drain(
    two_processes, short_lease
):
    db, _ = two_processes
    publisher = sending_publisher(db)
    # The lease is still this process's, but it runs out before a lock wait and a broadcast phase could.
    publisher._take_lease = AsyncMock(return_value=(True, time.time() + vp.PHASE_TIMEOUT_SECONDS))
    chain = FakeChain()
    await publisher.publish(4663, TOKEN, scan())
    with rpc_node(chain):
        assert await publisher.drain_once() == "retry"
    assert chain.sent == []
    assert await queued(db, TOKEN)
    # The drain loop stops claiming; the lease is taken again before anything else is sent.
    assert publisher._lease_lost


@pytest.mark.asyncio
async def test_the_check_at_a_send_comes_before_the_last_freshness_check(two_processes, short_lease):
    db, _ = two_processes
    publisher = sending_publisher(db)
    steps = []
    take, drop_ineligible = publisher._take_lease, publisher._drop_ineligible

    async def noted_take():
        steps.append("take lease")
        return await take()

    async def noted_drop(row):
        steps.append("freshness")
        return await drop_ineligible(row)

    store = db.set_verdict_tx_hash

    async def noted_store(*args, **kwargs):
        steps.append("store")
        return await store(*args, **kwargs)

    publisher._take_lease, publisher._drop_ineligible = noted_take, noted_drop
    db.set_verdict_tx_hash = noted_store
    await publisher.publish(4663, TOKEN, scan())
    with rpc_node(FakeChain()):
        assert await publisher.drain_once() == "done"
    # No write of the lease's runs between the last freshness check and storing the transaction.
    stored = steps.index("store")
    assert steps[stored - 2 : stored] == ["take lease", "freshness"]


@pytest.mark.asyncio
async def test_a_drain_stopped_by_the_check_at_a_send_takes_the_lease_again_and_sends(
    two_processes, short_lease, monkeypatch, caplog
):
    db, _ = two_processes
    publisher = publisher_on(db)
    chain = FakeChain()
    take = publisher._take_lease
    short = []

    async def never_renews(held_until):
        await asyncio.Event().wait()

    # Only the start and the check at a send take the lease in this test.
    publisher._keep_lease = never_renews
    monkeypatch.setattr(vp, "DRAIN_BACKOFF_SECONDS", 0.05)

    async def one_short_take():
        # Decided when the call starts, so a take already under way is never the one cut short.
        shortened = bool(short)
        short.clear()
        held, expires_at = await take()
        return held, time.time() if shortened else expires_at

    publisher._take_lease = one_short_take
    with rpc_node(chain):
        publisher.start(recorder_key=KEY)
        await until(lambda: holds(db, publisher))
        short.append(True)
        await publisher.publish(4663, TOKEN, scan())
        await until(lambda: confirmed(db, TOKEN))
        await publisher.stop()
    assert "expires too soon" in caplog.text
    assert len(chain.sent) == 1


@pytest.mark.asyncio
async def test_a_stop_releases_a_lease_the_database_still_names_this_process_for(
    two_processes, short_lease, monkeypatch
):
    db, _ = two_processes
    publisher = publisher_on(db)
    take = db.take_sender_lease

    async def answer_never_arrives(*args):
        await take(*args)
        await asyncio.Event().wait()

    # The lease is taken, but the stop comes before this process learns it holds it.
    monkeypatch.setattr(db, "take_sender_lease", answer_never_arrives)
    with rpc_node(FakeChain()):
        publisher.start(recorder_key=KEY)
        await until(lambda: holds(db, publisher))
        await publisher.stop()
    assert await lease(db) is None


@pytest.mark.asyncio
async def test_a_clean_stop_releases_the_lease(two_processes, short_lease):
    db, _ = two_processes
    publisher = publisher_on(db)
    with rpc_node(FakeChain()):
        publisher.start(recorder_key=KEY)
        await until(lambda: holds(db, publisher))
        await publisher.stop()
    assert await lease(db) is None


@pytest.mark.asyncio
async def test_a_stop_releases_the_lease_only_once_the_drain_has_ended(
    two_processes, short_lease, monkeypatch
):
    db, _ = two_processes
    publisher = publisher_on(db)
    drains_at_release = []
    release = db.release_sender_lease

    async def noted_release(*args):
        drains_at_release.extend(running_drains())
        return await release(*args)

    monkeypatch.setattr(db, "release_sender_lease", noted_release)
    with rpc_node(FakeChain()):
        publisher.start(recorder_key=KEY)
        await until(lambda: holds(db, publisher))
        await publisher.stop()
    assert drains_at_release == []
    assert await lease(db) is None


@pytest.mark.asyncio
async def test_a_stop_with_a_send_still_under_way_leaves_the_lease_to_expire(
    two_processes, short_lease, monkeypatch
):
    monkeypatch.setattr(vp, "STOP_TIMEOUT_SECONDS", 0.05)
    db, _ = two_processes
    publisher = publisher_on(db)
    chain = FakeChain()
    gate = gate_method(chain, "eth_getTransactionReceipt")
    with rpc_node(chain):
        publisher.start(recorder_key=KEY)
        await until(lambda: holds(db, publisher))
        await publisher.publish(4663, TOKEN, scan())
        await until(lambda: asyncio.sleep(0, bool(chain.sent)))
        await publisher.stop()
        assert await holds(db, publisher)
        gate.set()
        await sends_settled(publisher)
