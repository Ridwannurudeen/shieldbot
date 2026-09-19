"""Storage of published verdict evidence, keyed by (chain_id, subject) with history."""

import pytest
import pytest_asyncio

from core.database import Database

TOKEN = "0x" + "ab" * 20
OTHER = "0x" + "cd" * 20
HASH_A = "0x" + "11" * 32
HASH_B = "0x" + "22" * 32
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
