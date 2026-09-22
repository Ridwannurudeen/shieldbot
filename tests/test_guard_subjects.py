"""Durable, bounded guard subscriptions follow confirmed verdict evidence."""

import asyncio
import json
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from core.database import Database

TOKEN = "0x" + "ab" * 20
OTHER = "0x" + "cd" * 20
REGISTRY = "0x" + "33" * 20


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr("core.database.time.time", lambda: 1000)
    database = Database(str(tmp_path / "guard.db"))
    await database.initialize()
    yield database
    await database.close()


async def insert(db, subject=TOKEN, observed_at=900, chain_id=4663,
                 status="pending", registry=REGISTRY, complete=True):
    return await db.insert_verdict_evidence(
        chain_id, subject, "LOW" if complete else "UNKNOWN", "hash",
        json.dumps({"observed_at": observed_at, "status": "ok" if complete else "unknown",
                    "coverage": {"honeypot": 1 if complete else 0}}),
        0, status, registry=registry,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["off", "pending", "sending", "submitted", "failed"])
async def test_only_confirmed_subjects_can_enter(db, status):
    evidence_id = await insert(db)
    await db.update_verdict_onchain(evidence_id, status)
    assert await db.get_guard_subjects(4663) == []
    assert not await db.register_guard_subject(4663, TOKEN)


@pytest.mark.asyncio
async def test_confirmation_registers_and_explicit_registration_is_idempotent(db):
    evidence_id = await insert(db)
    await db.update_verdict_onchain(evidence_id, "confirmed")
    assert await db.get_guard_subjects(4663) == [
        {"chain_id": 4663, "subject": TOKEN, "last_observed_at": 900, "retry_after": 0},
    ]
    assert await db.register_guard_subject(4663, TOKEN.upper())
    assert len(await db.get_guard_subjects(4663)) == 1


@pytest.mark.asyncio
async def test_leaving_survives_late_confirmation_and_restart_but_allows_explicit_reentry(db):
    evidence_id = await insert(db)
    await db.unregister_guard_subject(4663, TOKEN.upper())
    await db.update_verdict_onchain(evidence_id, "confirmed")
    await db.close()
    await db.initialize()
    assert await db.get_guard_subjects(4663) == []
    assert await db.register_guard_subject(4663, TOKEN)
    assert len(await db.get_guard_subjects(4663)) == 1
    await db.unregister_guard_subject(4663, TOKEN)
    assert await db.get_guard_subjects(4663) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id,registry,observed_at", [
    (56, REGISTRY, 900), (4663, None, 900), (4663, "", 900),
    (4663, REGISTRY, None), (4663, REGISTRY, True), (4663, REGISTRY, 0),
    (4663, REGISTRY, 1001), (4663, REGISTRY, "900"),
])
async def test_unqualified_confirmation_does_not_admit(db, chain_id, registry, observed_at):
    evidence_id = await insert(db, chain_id=chain_id, registry=registry, observed_at=observed_at)
    await db.update_verdict_onchain(evidence_id, "confirmed")
    assert await db.get_guard_subjects(chain_id) == []
    assert not await db.register_guard_subject(chain_id, TOKEN)


@pytest.mark.asyncio
async def test_cap_applies_to_admission_and_explicit_reentry(db, monkeypatch):
    monkeypatch.setattr("core.database.GUARD_WATCH_MAX_SUBJECTS", 1)
    first = await insert(db)
    second = await insert(db, subject=OTHER)
    await db.update_verdict_onchain(first, "confirmed")
    await db.update_verdict_onchain(second, "confirmed")
    assert not await db.register_guard_subject(4663, OTHER)
    await db.unregister_guard_subject(4663, TOKEN)
    assert await db.register_guard_subject(4663, OTHER)
    assert not await db.register_guard_subject(4663, TOKEN)
    assert [row["subject"] for row in await db.get_guard_subjects(4663)] == [OTHER]


@pytest.mark.asyncio
async def test_concurrent_confirmations_across_connections_obey_cap(db, monkeypatch):
    monkeypatch.setattr("core.database.GUARD_WATCH_MAX_SUBJECTS", 1)
    first = await insert(db)
    second = await insert(db, subject=OTHER)
    peer = Database(db.db_path)
    await peer.initialize()
    try:
        await asyncio.gather(db.update_verdict_onchain(first, "confirmed"),
                             peer.update_verdict_onchain(second, "confirmed"))
        assert len(await db.get_guard_subjects(4663)) == 1
        await db.unregister_guard_subject(4663, TOKEN)
        await db.unregister_guard_subject(4663, OTHER)
        admitted = await asyncio.gather(db.register_guard_subject(4663, TOKEN),
                                        peer.register_guard_subject(4663, OTHER))
        assert sorted(admitted) == [False, True]
    finally:
        await peer.close()


@pytest.mark.asyncio
async def test_oldest_complete_measurement_first_and_unknown_before_complete(db):
    for subject, observed, complete in [(TOKEN, 950, True), (OTHER, 900, True), ("unknown", 990, False)]:
        evidence_id = await insert(db, subject=subject, observed_at=observed, complete=complete)
        await db.update_verdict_onchain(evidence_id, "confirmed")
    rows = await db.get_guard_subjects(4663)
    assert [row["subject"] for row in rows] == ["unknown", OTHER, TOKEN]
    assert rows[0]["last_observed_at"] is None


@pytest.mark.asyncio
async def test_failed_measurement_and_late_old_confirmation_never_advance_or_regress_time(db):
    evidence_id = await insert(db)
    await db.update_verdict_onchain(evidence_id, "confirmed")
    await db.update_guard_subject_measurement(4663, TOKEN, 950, 0)
    await db.update_guard_subject_measurement(4663, TOKEN, None, 1020)
    await db.update_verdict_onchain(evidence_id, "confirmed")
    assert (await db.get_guard_subjects(4663))[0] == {
        "chain_id": 4663, "subject": TOKEN, "last_observed_at": 950, "retry_after": 1020,
    }
    incomplete = await insert(db, observed_at=990, complete=False)
    await db.update_verdict_onchain(incomplete, "confirmed")
    assert (await db.get_guard_subjects(4663))[0]["last_observed_at"] == 950


@pytest.mark.asyncio
async def test_measurement_updates_never_reactivate_unregistered_subject(db):
    await db.unregister_guard_subject(4663, TOKEN)
    await db.update_guard_subject_measurement(4663, TOKEN, 950, 0)
    assert await db.get_guard_subjects(4663) == []


@pytest.mark.asyncio
async def test_reduced_cap_is_enforced_on_restart_and_zero_disables(db, monkeypatch):
    for subject in (TOKEN, OTHER):
        evidence_id = await insert(db, subject=subject)
        await db.update_verdict_onchain(evidence_id, "confirmed")
    monkeypatch.setattr("core.database.GUARD_WATCH_MAX_SUBJECTS", 1)
    await db.close()
    await db.initialize()
    assert len(await db.get_guard_subjects(4663)) == 1
    cursor = await db._db.execute("SELECT COUNT(*) FROM guard_subjects WHERE enabled = 1")
    assert (await cursor.fetchone())[0] == 1
    monkeypatch.setattr("core.database.GUARD_WATCH_MAX_SUBJECTS", 0)
    await db.close()
    await db.initialize()
    assert await db.get_guard_subjects(4663) == []
    assert not await db.register_guard_subject(4663, TOKEN)


@pytest.mark.asyncio
async def test_admission_failure_does_not_leave_a_partial_confirmation(db, monkeypatch):
    evidence_id = await insert(db)
    monkeypatch.setattr(db, "_admit_guard_subject", AsyncMock(side_effect=RuntimeError("disk failure")))
    with pytest.raises(RuntimeError, match="disk failure"):
        await db.update_verdict_onchain(evidence_id, "confirmed")
    await db.touch_verdict(evidence_id)
    assert (await db.get_verdict_evidence(evidence_id))["onchain_status"] == "pending"
    assert await db.get_guard_subjects(4663) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("coverage", [{}, {"honeypot": None}, {"honeypot": 0.5}])
async def test_ok_status_with_incomplete_coverage_has_no_successful_measurement(db, coverage):
    evidence_id = await db.insert_verdict_evidence(
        4663, TOKEN, "UNKNOWN", "hash",
        json.dumps({"observed_at": 900, "status": "ok", "coverage": coverage}),
        0, "pending", registry=REGISTRY,
    )
    await db.update_verdict_onchain(evidence_id, "confirmed")
    assert (await db.get_guard_subjects(4663))[0]["last_observed_at"] is None
