"""The sender lease: of all the verdict drains on one database, only the lease holder sends.

A second drain can start by mistake: a second workers.py, or an API still running the drain after
BACKGROUND_WORKERS=external was set. Two drains on one recorder account would race for its nonces. The fake
node and the dummy key come from tests/test_verdict_publisher.py; no test touches the network.
"""

import asyncio
import logging
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

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

TOKENS = ["0x" + f"{n:040x}" for n in range(1, 4)]


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


def publisher_on(db):
    return VerdictPublisher(db, rpc_url=RPC, registry_address=REGISTRY)


async def lease(db):
    cursor = await db._db.execute(
        "SELECT holder, expires_at FROM sender_leases WHERE name = ?", (vp.LEASE_NAME,)
    )
    return await cursor.fetchone()


async def holds(db, publisher):
    """The lease names the publisher, and the publisher knows it holds it."""
    row = await lease(db)
    return publisher._holds_lease and row is not None and row[0] == publisher._lease_holder


async def confirmed(db, subject):
    stored = await db.get_latest_verdict_evidence(4663, subject)
    return stored is not None and stored["onchain_status"] == "confirmed"


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
async def test_a_holder_that_cannot_renew_stops_sending_while_its_lease_is_still_live(
    two_processes, monkeypatch, caplog
):
    monkeypatch.setattr(vp, "LEASE_SECONDS", 1.0)
    monkeypatch.setattr(vp, "LEASE_RENEW_SECONDS", 0.2)
    db, other_process = two_processes
    publisher = publisher_on(db)
    with rpc_node(FakeChain()):
        publisher.start(recorder_key=KEY)
        await until(lambda: holds(db, publisher))
        monkeypatch.setattr(
            db, "take_sender_lease", AsyncMock(side_effect=RuntimeError("database is locked"))
        )
        await until(lambda: asyncio.sleep(0, "stopped sending" in caplog.text), tries=300)
        # No other drain could have taken the lease yet: the drain stopped a renewal period before it lapsed.
        holder, expires_at = await lease(other_process)
        assert holder == publisher._lease_holder and expires_at > time.time()
        assert "RuntimeError" in caplog.text
        await publisher.stop()


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
