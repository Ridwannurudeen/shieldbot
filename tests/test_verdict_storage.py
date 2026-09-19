"""Storage of published verdict evidence, keyed by (chain_id, subject) with history."""

import asyncio
import time

import pytest
import pytest_asyncio

from core.database import Database

TOKEN = "0x" + "ab" * 20
OTHER = "0x" + "cd" * 20
HASH_A = "0x" + "11" * 32
HASH_B = "0x" + "22" * 32
TX_A = "0x" + "44" * 32
TX_B = "0x" + "55" * 32
REGISTRY = "0x" + "33" * 20


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


async def insert(
    db, subject=TOKEN, chain_id=4663, verdict="UNKNOWN", evidence_hash=HASH_A, **kwargs
):
    return await db.insert_verdict_evidence(
        chain_id=chain_id,
        subject=subject,
        verdict=verdict,
        evidence_hash=evidence_hash,
        canonical='{"verdict":"%s"}' % verdict,
        observed_block=kwargs.pop("observed_block", 0),
        onchain_status=kwargs.pop("onchain_status", "off"),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_never_published_subject_has_no_evidence(db):
    assert await db.get_latest_verdict_evidence(4663, TOKEN) is None


@pytest.mark.asyncio
async def test_insert_and_read_back_latest(db):
    evidence_id = await insert(
        db,
        verdict="HONEYPOT",
        observed_block=65704949,
        onchain_status="pending",
        registry=REGISTRY,
    )
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert stored["id"] == evidence_id
    assert stored["chain_id"] == 4663
    assert stored["subject"] == TOKEN
    assert stored["verdict"] == "HONEYPOT"
    assert stored["evidence_hash"] == HASH_A
    assert stored["canonical"] == '{"verdict":"HONEYPOT"}'
    assert stored["observed_block"] == 65704949
    assert stored["onchain_status"] == "pending"
    assert stored["registry"] == REGISTRY
    assert stored["tx_hash"] is None
    assert stored["onchain_error"] is None
    assert stored["created_at"] > 0


@pytest.mark.asyncio
async def test_history_is_kept_and_latest_wins(db):
    first = await insert(db, verdict="UNKNOWN", evidence_hash=HASH_A)
    second = await insert(db, verdict="HIGH", evidence_hash=HASH_B)
    assert second > first
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["id"], stored["verdict"], stored["evidence_hash"]) == (second, "HIGH", HASH_B)
    cursor = await db._db.execute(
        "SELECT verdict FROM verdict_evidence WHERE chain_id = ? AND subject = ? ORDER BY id",
        (4663, TOKEN),
    )
    assert [row[0] for row in await cursor.fetchall()] == ["UNKNOWN", "HIGH"]


@pytest.mark.asyncio
async def test_latest_is_scoped_by_chain_and_subject(db):
    await insert(db, verdict="LOW", chain_id=56)
    await insert(db, verdict="HIGH", subject=OTHER)
    assert await db.get_latest_verdict_evidence(4663, TOKEN) is None
    assert (await db.get_latest_verdict_evidence(56, TOKEN))["verdict"] == "LOW"
    assert (await db.get_latest_verdict_evidence(4663, OTHER))["verdict"] == "HIGH"


@pytest.mark.asyncio
async def test_onchain_outcome_is_recorded_against_the_evidence(db):
    sent = await insert(db, onchain_status="pending", registry=REGISTRY)
    await db.update_verdict_onchain(sent, "submitted", tx_hash="0x" + "44" * 32)
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"], stored["onchain_error"]) == (
        "submitted",
        "0x" + "44" * 32,
        None,
    )

    failed = await insert(db, subject=OTHER, onchain_status="pending", registry=REGISTRY)
    await db.update_verdict_onchain(failed, "failed", onchain_error="RateCapExceeded")
    stored = await db.get_latest_verdict_evidence(4663, OTHER)
    assert (stored["onchain_status"], stored["tx_hash"], stored["onchain_error"]) == (
        "failed",
        None,
        "RateCapExceeded",
    )
    # Updating one row leaves the other untouched.
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "submitted"


@pytest.mark.asyncio
async def test_table_creation_is_idempotent_and_keeps_rows(db):
    await insert(db)
    await db._create_tables()
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["evidence_hash"] == HASH_A


# ---------------------------------------------------------------------------
# On-chain outbox: claim before send
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_claim_takes_the_oldest_pending_robinhood_row(db):
    await insert(db, onchain_status="off")
    await insert(db, chain_id=56, onchain_status="pending")
    first = await insert(db, onchain_status="pending", evidence_hash=HASH_A)
    second = await insert(db, subject=OTHER, onchain_status="pending", evidence_hash=HASH_B)

    claimed = await db.claim_next_pending_verdict(4663)
    assert claimed == {
        "id": first, "subject": TOKEN, "verdict": "UNKNOWN", "evidence_hash": HASH_A, "observed_block": 0,
        "tx_hash": None, "nonce": None, "attempts": 0,
    }
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "sending"
    assert (await db.claim_next_pending_verdict(4663))["id"] == second
    assert await db.claim_next_pending_verdict(4663) is None


@pytest.mark.asyncio
async def test_tx_hash_and_nonce_are_stored_on_the_claimed_row_before_broadcast(db):
    evidence_id = await insert(db, onchain_status="pending")
    await db.claim_next_pending_verdict(4663)
    await db.set_verdict_tx_hash(evidence_id, TX_A, 7)
    assert await db.get_claimed_verdicts(4663) == [
        {"id": evidence_id, "tx_hash": TX_A, "nonce": 7, "attempts": 1},
    ]


@pytest.mark.asyncio
async def test_a_released_claim_is_pending_again_and_keeps_its_last_transaction(db):
    evidence_id = await insert(db, onchain_status="pending")
    await db.claim_next_pending_verdict(4663)
    await db.set_verdict_tx_hash(evidence_id, TX_A, 7)
    await db.release_verdict_claim(evidence_id)
    assert await db.get_claimed_verdicts(4663) == []
    claimed = await db.claim_next_pending_verdict(4663)
    assert (claimed["id"], claimed["tx_hash"], claimed["nonce"], claimed["attempts"]) == (evidence_id, TX_A, 7, 1)


@pytest.mark.asyncio
async def test_release_and_tx_hash_only_touch_claimed_rows(db):
    evidence_id = await insert(db, onchain_status="pending")
    await db.set_verdict_tx_hash(evidence_id, TX_A, 7)
    await db.release_verdict_claim(evidence_id)
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"]) == ("pending", None)


async def signed_row(db, status, subject=TOKEN, tx_hash=TX_A):
    evidence_id = await insert(db, subject=subject, onchain_status="pending")
    await db.claim_next_pending_verdict(4663)
    await db.set_verdict_tx_hash(evidence_id, tx_hash, 7)
    await db.update_verdict_onchain(evidence_id, status, tx_hash=tx_hash)
    return evidence_id


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["submitted", "unconfirmed", "failed"])
async def test_unresolved_records_are_listed_and_can_be_requeued(db, status):
    evidence_id = await signed_row(db, status)
    later = time.time() + 1
    assert await db.get_unresolved_verdicts(4663, later, max_attempts=5, limit=10) == [
        {"id": evidence_id, "tx_hash": TX_A, "nonce": 7, "attempts": 1},
    ]
    await db.requeue_verdict(evidence_id)
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"]) == ("pending", TX_A)
    assert await db.get_unresolved_verdicts(4663, later, max_attempts=5, limit=10) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["confirmed", "reverted", "off", "pending", "sending"])
async def test_resolved_or_active_records_are_never_listed_or_requeued(db, status):
    evidence_id = await signed_row(db, status)
    assert await db.get_unresolved_verdicts(4663, time.time() + 1, max_attempts=5, limit=10) == []
    await db.requeue_verdict(evidence_id)
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == status


@pytest.mark.asyncio
async def test_unresolved_listing_honours_age_attempts_limit_and_order(db):
    first = await signed_row(db, "submitted")
    second = await signed_row(db, "unconfirmed", subject=OTHER, tx_hash=TX_B)
    assert await db.get_unresolved_verdicts(4663, time.time() - 60, max_attempts=5, limit=10) == []
    later = time.time() + 1
    assert [r["id"] for r in await db.get_unresolved_verdicts(4663, later, max_attempts=5, limit=10)] == [
        first, second,
    ]
    assert [r["id"] for r in await db.get_unresolved_verdicts(4663, later, max_attempts=5, limit=1)] == [first]
    assert await db.get_unresolved_verdicts(4663, later, max_attempts=1, limit=10) == []
    assert await db.get_unresolved_verdicts(56, later, max_attempts=5, limit=10) == []


@pytest.mark.asyncio
async def test_two_connections_never_claim_the_same_row(tmp_path):
    """Two processes sharing one SQLite file: every pending row is claimed exactly once."""
    path = str(tmp_path / "shared.db")
    first, second = Database(path), Database(path)
    await first.initialize()
    await second.initialize()
    try:
        ids = [await insert(first, subject="0x" + f"{n:040x}", onchain_status="pending") for n in range(1, 21)]
        claimed = []

        async def claimer(database):
            while (row := await database.claim_next_pending_verdict(4663)) is not None:
                claimed.append(row["id"])

        await asyncio.gather(claimer(first), claimer(second), claimer(first), claimer(second))
        assert sorted(claimed) == ids
    finally:
        await first.close()
        await second.close()


@pytest.mark.asyncio
async def test_the_claim_query_uses_the_outbox_index(db):
    cursor = await db._db.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_verdict_evidence_outbox'"
    )
    [sql] = await cursor.fetchone()
    assert "verdict_evidence(chain_id, onchain_status, id)" in " ".join(sql.split())
    cursor = await db._db.execute(
        "EXPLAIN QUERY PLAN SELECT id FROM verdict_evidence "
        "WHERE chain_id = ? AND onchain_status = 'pending' ORDER BY id LIMIT 1",
        (4663,),
    )
    plan = " ".join(row[-1] for row in await cursor.fetchall())
    assert "idx_verdict_evidence_outbox" in plan
