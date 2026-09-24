"""After the registry address changes, records of the old registry never stand in for the new one.

Deduplication only compares evidence queued for the configured registry, the drain never sends a row to
a registry other than the one it was queued for, and only a confirmation on the configured registry admits
a subject to the guard watch.
"""

import pytest
from eth_account import Account
from eth_utils import to_checksum_address

import services.verdict_publisher as vp
from tests.test_verdict_publisher import (
    COMPLETE,
    INCOMPLETE,
    KEY,
    REGISTRY,
    TOKEN,
    FakeChain,
    decode_record,
    drain_all,
    make_publisher,
    record_once,
    rpc_node,
    sender,
)
from tests.test_verdict_publisher import db as db
from tests.test_verdict_publisher import reconcile_now  # noqa: F401  (pytest fixture)

NEW_REGISTRY = "0x" + "d1" * 20


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
async def test_explicit_guard_registration_needs_a_confirmation_on_the_given_registry(db):
    first = await make_publisher(db).publish(4663, TOKEN, COMPLETE)
    await db.update_verdict_onchain(first["evidence_id"], "confirmed", registry=NEW_REGISTRY)
    assert await db.get_guard_subjects(4663) == []
    assert not await db.register_guard_subject(4663, TOKEN, NEW_REGISTRY)
    assert not await db.register_guard_subject(4663, TOKEN, None)
    assert await db.register_guard_subject(4663, TOKEN, REGISTRY.upper().replace("0X", "0x"))
    assert [row["subject"] for row in await db.get_guard_subjects(4663)] == [TOKEN]
