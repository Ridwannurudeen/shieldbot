"""Usage records are kept USAGE_RETENTION_DAYS; expired free key link requests are deleted."""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from agent.hunter import Hunter
from core.auth import AuthManager
from core.database import USAGE_RETENTION_DAYS, Database


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "retention.db"))
    await database.initialize()
    yield database
    await database.close()


async def rows(db, sql):
    cursor = await db._db.execute(sql)
    return await cursor.fetchall()


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
    await db._db.commit()
    # Adding a request deletes the expired ones first, so the expired row goes in last.
    assert await db.add_free_key_request("new@example.com", "pending", now + 1800)
    assert await db.add_free_key_request("old@example.com", "expired", now - 1)


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
    assert await db.prune_retention() == {
        "api_usage": 0,
        "api_daily_usage": 0,
        "ai_token_usage": 0,
        "free_key_requests": 0,
    }


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


@pytest.mark.asyncio
async def test_a_failed_chat_prune_does_not_skip_the_usage_prune():
    db = MagicMock()
    db.prune_old_chats = AsyncMock(side_effect=RuntimeError("database is locked"))
    db.prune_retention = AsyncMock()
    await hunter_with(db).sweep()
    db.prune_retention.assert_awaited_once()
