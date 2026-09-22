"""Observation ordering remains independent of enqueue order and delivery outcome."""

import json

import pytest
import pytest_asyncio

from core.database import Database

TOKEN = "0x" + "ab" * 20
OTHER = "0x" + "cd" * 20


@pytest_asyncio.fixture
async def db(monkeypatch):
    monkeypatch.setattr("core.database.time.time", lambda: 1000)
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


async def insert(db, observed_at, verdict="LOW", status="pending", chain_id=4663, subject=TOKEN):
    return await db.insert_verdict_evidence(
        chain_id=chain_id,
        subject=subject,
        verdict=verdict,
        evidence_hash="0x" + "11" * 32,
        canonical=json.dumps({"observed_at": observed_at, "verdict": verdict}),
        observed_block=0,
        onchain_status=status,
    )


@pytest.mark.asyncio
async def test_evidence_by_id_preserves_the_existing_row_shape(db):
    first = await insert(db, 900)
    expected = await db.get_latest_verdict_evidence(4663, TOKEN)
    await insert(db, 950, "HIGH")
    assert await db.get_verdict_evidence(first) == expected
    assert await db.get_verdict_evidence(999) is None


@pytest.mark.asyncio
async def test_newest_observation_ignores_enqueue_order(db):
    newest = await insert(db, 950, "HONEYPOT")
    expected = await db.get_latest_verdict_evidence(4663, TOKEN)
    older = await insert(db, 900, "LOW")
    assert older > newest
    assert await db.get_newest_verdict_observation(4663, TOKEN) == expected
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["id"] == older


@pytest.mark.asyncio
@pytest.mark.parametrize("denial,permission", [
    ("HONEYPOT", "UNKNOWN"), ("UNKNOWN", "HIGH"), ("HIGH", "MEDIUM"), ("MEDIUM", "LOW"),
])
async def test_equal_observation_time_keeps_the_more_conservative_verdict(db, denial, permission):
    denied = await insert(db, 950, denial)
    await insert(db, 950, permission)
    assert (await db.get_newest_verdict_observation(4663, TOKEN))["id"] == denied


@pytest.mark.asyncio
async def test_equal_time_and_verdict_use_latest_row(db):
    await insert(db, 950)
    latest = await insert(db, 950)
    assert (await db.get_newest_verdict_observation(4663, TOKEN))["id"] == latest


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["dropped", "failed", "reverted", "off", "confirmed"])
async def test_delivery_outcome_does_not_erase_the_newest_denial(db, status):
    denied = await insert(db, 500, "HONEYPOT", status)
    await insert(db, 400)
    assert (await db.get_newest_verdict_observation(4663, TOKEN))["id"] == denied


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", [None, True, False, 0, -1, "990", "bad", [], {}, 1001, 990.0, 990.5])
async def test_invalid_or_future_times_do_not_supersede_measured_evidence(db, invalid):
    measured = await insert(db, 900)
    await insert(db, invalid, "HONEYPOT")
    assert (await db.get_newest_verdict_observation(4663, TOKEN))["id"] == measured


@pytest.mark.asyncio
async def test_missing_observation_time_has_no_watermark(db):
    await db.insert_verdict_evidence(4663, TOKEN, "LOW", "hash", "{}", 0, "pending")
    assert await db.get_newest_verdict_observation(4663, TOKEN) is None


@pytest.mark.asyncio
async def test_observation_lookup_is_scoped_by_chain_and_subject(db):
    await insert(db, 950, chain_id=56)
    await insert(db, 950, subject=OTHER)
    assert await db.get_newest_verdict_observation(4663, TOKEN) is None


@pytest.mark.asyncio
async def test_newer_permission_can_follow_an_older_denial(db):
    await insert(db, 900, "HONEYPOT")
    allowed = await insert(db, 950)
    assert (await db.get_newest_verdict_observation(4663, TOKEN))["id"] == allowed


@pytest.mark.asyncio
async def test_deduplicated_observation_advances_watermark_without_replacing_refresh_anchor(db):
    anchor = await insert(db, 900, "HONEYPOT", "confirmed")
    measured = await insert(db, 950, "HONEYPOT", "deduplicated")
    assert (await db.get_newest_verdict_observation(4663, TOKEN))["id"] == measured
    stored = await db.get_newest_verdict_observation(4663, TOKEN, include_deduplicated=False)
    assert stored["id"] == anchor
    assert json.loads(stored["canonical"])["observed_at"] == 900


@pytest.mark.asyncio
async def test_anchor_lookup_does_not_skip_an_intervening_unresolved_verdict(db):
    await insert(db, 900, "LOW", "confirmed")
    unresolved = await insert(db, 930, "HIGH", "unconfirmed")
    await insert(db, 950, "LOW", "deduplicated")
    stored = await db.get_newest_verdict_observation(4663, TOKEN, include_deduplicated=False)
    assert stored["id"] == unresolved


@pytest.mark.asyncio
async def test_signed_dropped_rows_remain_receipt_candidates_but_cannot_be_requeued(db):
    evidence_id = await insert(db, 950)
    await db.claim_next_pending_verdict(4663)
    tx_hash = "0x" + "44" * 32
    await db.set_verdict_tx_hash(evidence_id, tx_hash, 7, "02aa", 112_000_000)
    await db.update_verdict_onchain(
        evidence_id, "dropped", tx_hash=tx_hash, onchain_error="StaleObservation"
    )
    await insert(db, 950, status="dropped", subject=OTHER)
    assert await db.get_unresolved_verdicts(4663, 1001, 10) == [
        {"id": evidence_id, "tx_hash": tx_hash, "nonce": 7, "attempts": 1},
    ]
    await db.requeue_verdict(evidence_id)
    stored = await db.get_verdict_evidence(evidence_id)
    assert stored["onchain_status"] == "dropped"
    assert stored["onchain_error"] == "StaleObservation"
    assert await db.claim_next_pending_verdict(4663) is None
