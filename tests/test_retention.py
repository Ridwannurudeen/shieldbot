"""Retention deletes old usage, scan evidence, eligible verdict evidence and never-scanned launches."""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from agent.hunter import Hunter
from core.auth import AuthManager
from core.database import (
    LAUNCH_RETENTION_DAYS,
    SCAN_EVIDENCE_RETENTION_DAYS,
    USAGE_RETENTION_DAYS,
    VERDICT_EVIDENCE_RETENTION_DAYS,
    _PRUNE_LAUNCHES_SQL,
    _PRUNE_VERDICT_EVIDENCE_SQL,
    Database,
)


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "retention.db"))
    await database.initialize()
    yield database
    await database.close()


async def rows(db, sql, parameters=()):
    cursor = await db._db.execute(sql, parameters)
    return await cursor.fetchall()


async def insert_verdict_evidence(db, subject, status, created_at, tx_hash=None):
    cursor = await db._db.execute(
        """
        INSERT INTO verdict_evidence
            (chain_id, subject, verdict, evidence_hash, canonical, observed_block, created_at,
             onchain_status, tx_hash, updated_at)
        VALUES (4663, ?, 'LOW', ?, '{}', 0, ?, ?, ?, ?)
        """,
        (subject, f"{subject}-{status}", created_at, status, tx_hash, created_at),
    )
    return cursor.lastrowid


async def seed(db, now):
    """Rows either side of the retention line, plus today's, in every pruned table."""
    today = int(now // 86400)
    for created_at in (
        now - (USAGE_RETENTION_DAYS + 1) * 86400,
        now - (USAGE_RETENTION_DAYS - 1) * 86400,
        now,
    ):
        await db._db.execute(
            "INSERT INTO api_usage (key_id, endpoint, created_at) VALUES ('key', '/api/firewall', ?)",
            (created_at,),
        )
    for day, used in (
        (today - USAGE_RETENTION_DAYS - 1, 7),
        (today - USAGE_RETENTION_DAYS + 1, 8),
        (today, 3),
    ):
        await db._db.execute(
            "INSERT INTO api_daily_usage (key_id, utc_day, used) VALUES ('key', ?, ?)", (day, used)
        )
        await db._db.execute(
            "INSERT INTO ai_token_usage (utc_day, tokens) VALUES (?, ?)", (day, used * 100)
        )
    for label, created_at in (
        ("expired", now - (SCAN_EVIDENCE_RETENTION_DAYS + 1) * 86400),
        ("kept", now - (SCAN_EVIDENCE_RETENTION_DAYS - 1) * 86400),
        ("new", now),
    ):
        await db._db.execute(
            "INSERT INTO scan_evidence (evidence_hash, canonical, created_at) VALUES (?, '{}', ?)",
            (label, created_at),
        )
    await insert_verdict_evidence(
        db, "retention-subject", "off", now - (VERDICT_EVIDENCE_RETENTION_DAYS + 1) * 86400
    )
    await insert_verdict_evidence(
        db, "retention-subject", "off", now - (VERDICT_EVIDENCE_RETENTION_DAYS - 1) * 86400
    )
    old_launch_time = int(now) - (LAUNCH_RETENTION_DAYS + 1) * 86400
    await db._db.execute(
        """
        INSERT INTO discovered_launches
            (chain_id, token_address, source, launchpad, source_rank, block_number, tx_hash,
             block_timestamp, discovered_at)
        VALUES (4663, 'retention-launch', 'seed', 'seed', 1, 1, 'tx-retention', ?, ?)
        """,
        (old_launch_time, now),
    )
    await db._db.commit()
    # Adding a request deletes the expired ones first, so the expired row goes in last.
    assert await db.add_free_key_request("new@example.com", "pending", now + 1800)
    assert await db.add_free_key_request("old@example.com", "expired", now - 1)


@pytest.mark.asyncio
async def test_the_usage_prune_searches_an_index_rather_than_scanning_the_table(db):
    plan = await rows(db, "EXPLAIN QUERY PLAN DELETE FROM api_usage WHERE created_at < 0")
    assert any("USING INDEX idx_api_usage_created_at" in row[-1] for row in plan), plan
    plan = await rows(db, "EXPLAIN QUERY PLAN DELETE FROM scan_evidence WHERE created_at < 0")
    assert any("USING INDEX idx_scan_evidence_created_at" in row[-1] for row in plan), plan
    plan = await rows(
        db,
        "EXPLAIN QUERY PLAN " + _PRUNE_VERDICT_EVIDENCE_SQL,
        (0,),
    )
    assert any("USING INDEX idx_verdict_evidence_created_at" in row[-1] for row in plan), plan
    plan = await rows(
        db,
        "EXPLAIN QUERY PLAN " + _PRUNE_LAUNCHES_SQL,
        (0,),
    )
    assert any("USING INDEX idx_discovered_launches_retention" in row[-1] for row in plan), plan


@pytest.mark.asyncio
async def test_prune_deletes_only_rows_past_their_retention(db):
    now = time.time()
    await seed(db, now)
    today = int(now // 86400)

    assert await db.prune_retention() == {
        "api_usage": 1,
        "api_daily_usage": 1,
        "ai_token_usage": 1,
        "free_key_requests": 1,
        "scan_evidence": 1,
        "verdict_evidence": 1,
        "discovered_launches": 0,
    }
    assert len(await rows(db, "SELECT id FROM api_usage")) == 2
    assert await rows(db, "SELECT utc_day FROM api_daily_usage ORDER BY utc_day") == [
        (today - USAGE_RETENTION_DAYS + 1,),
        (today,),
    ]
    assert await rows(db, "SELECT utc_day FROM ai_token_usage ORDER BY utc_day") == [
        (today - USAGE_RETENTION_DAYS + 1,),
        (today,),
    ]
    assert await rows(db, "SELECT email FROM free_key_requests") == [("new@example.com",)]
    assert await rows(db, "SELECT evidence_hash FROM scan_evidence ORDER BY created_at") == [
        ("kept",),
        ("new",),
    ]
    assert await rows(db, "SELECT chain_id, block_number FROM discovered_launches") == [(4663, 1)]
    assert await db.prune_retention() == {
        "api_usage": 0,
        "api_daily_usage": 0,
        "ai_token_usage": 0,
        "free_key_requests": 0,
        "scan_evidence": 0,
        "verdict_evidence": 0,
        "discovered_launches": 0,
    }


@pytest.mark.asyncio
async def test_prune_keeps_onchain_and_newest_verdict_evidence(db):
    now = time.time()
    old = now - (VERDICT_EVIDENCE_RETENTION_DAYS + 1) * 86400
    young = now - (VERDICT_EVIDENCE_RETENTION_DAYS - 1) * 86400
    newer_young = now - (VERDICT_EVIDENCE_RETENTION_DAYS - 2) * 86400
    cases = [
        ("off-subject", "off", old, None),
        ("off-subject", "off", old, None),
        ("deduplicated-subject", "deduplicated", old, None),
        ("deduplicated-subject", "off", old, None),
        ("dropped-no-hash-subject", "dropped", old, None),
        ("dropped-no-hash-subject", "off", old, None),
        ("dropped-hash-subject", "dropped", old, "tx-dropped"),
        ("dropped-hash-subject", "off", old, None),
        ("confirmed-subject", "confirmed", old, "tx-confirmed"),
        ("confirmed-subject", "off", old, None),
        ("reverted-subject", "reverted", old, "tx-reverted"),
        ("reverted-subject", "off", old, None),
        ("pending-subject", "pending", old, None),
        ("pending-subject", "off", old, None),
        ("young-subject", "off", young, None),
        ("young-subject", "off", newer_young, None),
        ("off-hash-subject", "off", old, "tx-off"),
        ("off-hash-subject", "off", old, None),
        ("sending-subject", "sending", old, None),
        ("sending-subject", "off", old + 1, None),
        ("submitted-subject", "submitted", old, None),
        ("submitted-subject", "off", old + 1, None),
        ("unconfirmed-subject", "unconfirmed", old, None),
        ("unconfirmed-subject", "off", old + 1, None),
        ("failed-subject", "failed", old, None),
        ("failed-subject", "off", old + 1, None),
    ]
    ids = [
        await insert_verdict_evidence(db, subject, status, created_at, tx_hash)
        for subject, status, created_at, tx_hash in cases
    ]
    await db._db.commit()

    await db.prune_retention()

    assert [row[0] for row in await rows(db, "SELECT id FROM verdict_evidence ORDER BY id")] == [
        ids[1], ids[3], ids[5], ids[6], ids[7], ids[8], ids[9], ids[10], ids[11], ids[12],
        ids[13], ids[14], ids[15], ids[16], ids[17], *ids[18:26],
    ]


@pytest.mark.asyncio
async def test_prune_deletes_only_old_never_scanned_launches(db):
    now = time.time()
    old = int(now) - (LAUNCH_RETENTION_DAYS + 1) * 86400
    young = int(now) - (LAUNCH_RETENTION_DAYS - 1) * 86400
    launches = (
        (4663, "old-unscanned", old, None, 1),
        (4663, "young-unscanned", young, None, 2),
        (4663, "old-scanned", old, now - (LAUNCH_RETENTION_DAYS + 1) * 86400, 3),
        (4664, "only-old-unscanned", old, None, 1),
    )
    for chain_id, token, block_timestamp, scanned_at, block_number in launches:
        await db._db.execute(
            """
            INSERT INTO discovered_launches
                (chain_id, token_address, source, launchpad, source_rank, block_number, tx_hash,
                 block_timestamp, discovered_at, scanned_at)
            VALUES (?, ?, 'seed', 'seed', 1, ?, 'tx-launch', ?, ?, ?)
            """,
            (chain_id, token, block_number, block_timestamp, now, scanned_at),
        )
    await db._db.commit()

    deleted = await db.prune_retention()

    assert deleted["discovered_launches"] == 1
    assert await rows(
        db, "SELECT chain_id, token_address FROM discovered_launches ORDER BY chain_id, token_address"
    ) == [
        (4663, "old-scanned"),
        (4663, "young-unscanned"),
        (4664, "only-old-unscanned"),
    ]
    assert (await db.get_launch_discovery_status(4664))["last_discovered_block"] == 1


@pytest.mark.asyncio
async def test_quotas_and_the_ai_budget_read_the_same_after_a_prune(db):
    now = time.time()
    await seed(db, now)
    auth = AuthManager(db)
    key_info = {"key_id": "key", "rpm_limit": 60, "daily_limit": 1000}
    before = (
        await auth.get_quota(key_info),
        await auth.get_usage("key"),
        await db.get_ai_tokens_used(int(now // 86400)),
    )
    await db.prune_retention()
    after = (
        await auth.get_quota(key_info),
        await auth.get_usage("key"),
        await db.get_ai_tokens_used(int(now // 86400)),
    )
    assert after == before
    assert before[0]["used_today"] == 3
    assert before[2] == 300
    assert await auth.check_rate_limit(key_info)
    assert key_info["quota"]["used_today"] == 4


def hunter_with(db):
    hunter = Hunter(tools=MagicMock(), db=db, ai_analyzer=MagicMock(), sentinel=MagicMock())
    hunter._check_watched_deployers = AsyncMock(return_value=[])
    hunter._recheck_warn_contracts = AsyncMock(return_value=[])
    hunter._scan_new_pairs = AsyncMock(return_value=[])
    return hunter


@pytest.mark.asyncio
async def test_every_hunter_sweep_prunes_chats_and_usage_records(db):
    now = time.time()
    await seed(db, now)
    await db.insert_chat_message("user", "user", "hello")
    await db._db.execute("UPDATE chat_history SET created_at = ?", (now - 2 * 86400,))
    await db._db.commit()

    await hunter_with(db).sweep()

    assert await rows(db, "SELECT id FROM chat_history") == []
    assert len(await rows(db, "SELECT id FROM api_usage")) == 2
    assert await rows(db, "SELECT email FROM free_key_requests") == [("new@example.com",)]
    assert len(await rows(db, "SELECT evidence_hash FROM scan_evidence")) == 2


@pytest.mark.asyncio
async def test_a_failed_chat_prune_does_not_skip_the_usage_prune():
    db = MagicMock()
    db.prune_old_chats = AsyncMock(side_effect=RuntimeError("database is locked"))
    db.prune_retention = AsyncMock()
    await hunter_with(db).sweep()
    db.prune_retention.assert_awaited_once()
