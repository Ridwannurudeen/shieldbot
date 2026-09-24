"""After the registry address changes, records of the old registry never stand in for the new one.

Deduplication only compares evidence queued for the configured registry, the drain never sends a row to
a registry other than the one it was queued for, and only a confirmation on the configured registry admits
a subject to the guard watch.
"""

import asyncio

import pytest
import pytest_asyncio
from eth_account import Account
from eth_utils import to_checksum_address

import services.verdict_publisher as vp
from core.database import Database
from tests.test_verdict_publisher import (
    COMPLETE,
    INCOMPLETE,
    KEY,
    REGISTRY,
    TOKEN,
    FakeChain,
    decode_record,
    drain_all,
    lease_expired,
    make_publisher,
    record_once,
    rpc_node,
    sender,
)

NEW_REGISTRY = "0x" + "d1" * 20


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


@pytest.fixture
def reconcile_now(monkeypatch):
    """Reconciliation and claim recovery look at rows at once."""
    monkeypatch.setattr(vp, "RECONCILE_AFTER_SECONDS", -1)


@pytest.fixture(autouse=True)
def observation_clock(monkeypatch):
    monkeypatch.setattr(vp, "RECEIPT_DELAY_SECONDS", 0)
    monkeypatch.setattr(vp.time, "time", lambda: COMPLETE["observed_at"])


def new_sender(db):
    """The API process restarted with ROBINHOOD_VERDICT_REGISTRY set to a new address."""
    publisher = make_publisher(db, registry=NEW_REGISTRY)
    publisher._account = Account.from_key(KEY)
    publisher.recorder = publisher._account.address
    return publisher


@pytest.mark.asyncio
async def test_a_verdict_confirmed_on_the_old_registry_is_queued_again_for_the_new_one(db):
    first = await make_publisher(db).publish(4663, TOKEN, COMPLETE)
    await db.update_verdict_onchain(first["evidence_id"], "confirmed", registry=REGISTRY)

    again = await make_publisher(db, registry=NEW_REGISTRY).publish(4663, TOKEN, COMPLETE)

    assert again["evidence_id"] != first["evidence_id"]
    assert again["onchain_status"] == "pending"
    stored = await db.get_verdict_evidence(again["evidence_id"])
    assert stored["registry"] == to_checksum_address(NEW_REGISTRY)


@pytest.mark.asyncio
async def test_the_drain_never_sends_a_row_queued_for_another_registry(db):
    old = await make_publisher(db).publish(4663, TOKEN, COMPLETE)
    publisher = new_sender(db)
    chain = FakeChain()
    with rpc_node(chain):
        assert await drain_all(publisher) == ["done", "idle"]
    assert chain.posts == []
    stored = await db.get_verdict_evidence(old["evidence_id"])
    assert (stored["onchain_status"], stored["onchain_error"]) == ("dropped", "RegistryChanged")
    assert stored["registry"] == to_checksum_address(REGISTRY)


@pytest.mark.asyncio
async def test_every_sent_record_goes_to_the_registry_its_row_names(db):
    await make_publisher(db).publish(4663, TOKEN, COMPLETE)
    publisher = new_sender(db)
    fresh = await publisher.publish(4663, TOKEN, INCOMPLETE)
    chain = FakeChain()
    with rpc_node(chain):
        assert await drain_all(publisher) == ["done", "done", "idle"]
    [raw] = chain.sent
    stored = await db.get_verdict_evidence(fresh["evidence_id"])
    assert stored["onchain_status"] == "confirmed"
    assert decode_record(raw)["to"] == NEW_REGISTRY
    assert stored["registry"].lower() == NEW_REGISTRY


@pytest.mark.asyncio
async def test_only_a_confirmation_on_the_configured_registry_admits_a_guard_subject(
    db, reconcile_now
):
    chain = FakeChain()
    chain.receipt_status = None
    old = await record_once(db, chain, sender(db))
    assert old["onchain_status"] == "submitted"
    chain.catch_up()
    # The process restarted with the new registry, so the old one's sender lease has run out.
    await lease_expired(db)
    publisher = new_sender(db)
    with rpc_node(chain):
        assert await publisher._reconcile() == 0
    late = await db.get_verdict_evidence(old["id"])
    assert (late["onchain_status"], late["registry"]) == (
        "confirmed",
        to_checksum_address(REGISTRY),
    )
    assert decode_record(chain.sent[0])["to"] == REGISTRY
    assert await db.get_guard_subjects(4663) == []
    assert not await db.register_guard_subject(4663, TOKEN, NEW_REGISTRY)

    await publisher.publish(4663, TOKEN, INCOMPLETE)
    chain.receipt_status = "0x1"
    with rpc_node(chain):
        assert await drain_all(publisher) == ["done", "idle"]
    assert [row["subject"] for row in await db.get_guard_subjects(4663)] == [TOKEN]


@pytest.mark.asyncio
async def test_an_old_registry_row_is_dropped_on_requeue_and_its_late_receipt_still_confirms_it(
    db, reconcile_now
):
    chain = FakeChain()
    chain.lagging, chain.mine = True, False  # the node holds the old registry's transaction; not mined yet
    old = await record_once(db, chain, sender(db))
    assert old["onchain_status"] == "submitted"
    publisher = new_sender(db)
    with rpc_node(chain):
        assert await publisher._reconcile() == 1  # no receipt yet, so it is queued again
        assert await publisher.drain_once() == "done"  # claimed, then dropped instead of sent
    assert len(chain.sent) == 1
    dropped = await db.get_verdict_evidence(old["id"])
    assert (dropped["onchain_status"], dropped["onchain_error"], dropped["tx_hash"]) == (
        "dropped",
        "RegistryChanged",
        old["tx_hash"],
    )

    # The old registry's transaction lands after all.
    held = decode_record(chain.sent[0])
    chain.mined.append((held["nonce"], old["tx_hash"], held["evidence_hash"]))
    chain.catch_up()
    with rpc_node(chain):
        assert await publisher._reconcile() == 0
    late = await db.get_verdict_evidence(old["id"])
    assert (late["onchain_status"], late["onchain_error"], late["tx_hash"], late["registry"]) == (
        "confirmed",
        "RegistryChanged",
        old["tx_hash"],
        to_checksum_address(REGISTRY),
    )
    assert held["to"] == REGISTRY
    assert await db.get_guard_subjects(4663) == []


@pytest.mark.asyncio
async def test_a_claim_left_by_the_old_registry_is_recovered_and_dropped_unsent(db, reconcile_now):
    old = await make_publisher(db).publish(4663, TOKEN, COMPLETE)
    await db.claim_next_pending_verdict(4663)
    publisher = new_sender(db)
    chain = FakeChain()
    with rpc_node(chain):
        assert await publisher._recover_claims() == 1
        assert await drain_all(publisher) == ["done", "idle"]
    assert chain.posts == []
    stored = await db.get_verdict_evidence(old["evidence_id"])
    assert (stored["onchain_status"], stored["onchain_error"]) == ("dropped", "RegistryChanged")


@pytest.mark.asyncio
async def test_a_claim_the_old_registry_mined_is_recovered_as_confirmed_without_guard_admission(
    db, reconcile_now
):
    chain = FakeChain()
    chain.raise_on["eth_getTransactionReceipt"] = asyncio.CancelledError()  # killed after broadcasting
    await make_publisher(db).publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        with pytest.raises(asyncio.CancelledError):
            await sender(db).drain_once()
    chain.raise_on.clear()
    [(_, mined_hash, _)] = chain.mined
    publisher = new_sender(db)
    with rpc_node(chain):
        assert await publisher._recover_claims() == 0
        assert await publisher.drain_once() == "idle"
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"], stored["registry"]) == (
        "confirmed",
        mined_hash,
        to_checksum_address(REGISTRY),
    )
    assert len(chain.sent) == 1
    assert await db.get_guard_subjects(4663) == []


@pytest.mark.asyncio
async def test_a_confirmation_that_names_no_registry_never_admits_a_guard_subject(db):
    first = await make_publisher(db).publish(4663, TOKEN, COMPLETE)
    await db.update_verdict_onchain(first["evidence_id"], "confirmed")
    await db.update_verdict_onchain(first["evidence_id"], "confirmed", registry=None)
    assert await db.get_guard_subjects(4663) == []
    # The row itself qualifies once the registry it was queued for is named.
    assert await db.register_guard_subject(4663, TOKEN, REGISTRY)


@pytest.mark.asyncio
async def test_explicit_guard_registration_needs_a_confirmation_on_the_given_registry(db):
    first = await make_publisher(db).publish(4663, TOKEN, COMPLETE)
    await db.update_verdict_onchain(first["evidence_id"], "confirmed", registry=NEW_REGISTRY)
    assert await db.get_guard_subjects(4663) == []
    assert not await db.register_guard_subject(4663, TOKEN, NEW_REGISTRY)
    assert not await db.register_guard_subject(4663, TOKEN, None)
    assert await db.register_guard_subject(4663, TOKEN, REGISTRY.upper().replace("0X", "0x"))
    assert [row["subject"] for row in await db.get_guard_subjects(4663)] == [TOKEN]
