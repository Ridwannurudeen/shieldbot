"""The shared connection commits each statement on its own, so a failed write never leaves it inside a transaction.

On 2026-09-28 one launch discovery write on the shared connection failed on a locked database and left it in the
implicit transaction the write had opened. The next read pinned a WAL snapshot inside that transaction, other
connections kept committing, and every later write on the shared connection failed with "database is locked" until a
restart fifteen hours later.
"""

import asyncio
import sqlite3
from unittest.mock import patch

import aiosqlite
import pytest
import pytest_asyncio

from core.database import Database
from tests.test_database import LEGACY_FUNDER_SCHEMA


CHAIN = 4663
CONTRACT = "0x" + "c" * 40


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "shieldbot.db"))
    await database.initialize()
    # Production waits 5 s for a lock; the tests give up sooner.
    await database._db.execute("PRAGMA busy_timeout=100")
    yield database
    await database.close()


@pytest_asyncio.fixture
async def other(db):
    """Another connection to the file, as transaction()'s, the drain's, the lease's and the bot's are."""
    connection = await aiosqlite.connect(db.db_path, isolation_level=None)
    await connection.execute("PRAGMA busy_timeout=100")
    yield connection
    await connection.close()


async def _count(connection, table):
    cursor = await connection.execute(f"SELECT COUNT(*) FROM {table}")
    return (await cursor.fetchone())[0]


@pytest.mark.asyncio
async def test_a_write_that_failed_on_a_locked_database_does_not_stop_later_writes_while_others_commit(
    db, other
):
    await other.execute("BEGIN IMMEDIATE")
    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        await db.set_launch_confirmed_head(CHAIN, 100)
    await other.execute("COMMIT")

    # The launch watch's next cycles: a read on the shared connection, a commit on another, then the write.
    for head in (101, 102):
        await db.get_launch_cursor(CHAIN, "uniswap_v4")
        await other.execute(
            "INSERT OR REPLACE INTO launch_discovery_cursors (chain_id, source, last_block, updated_at) "
            "VALUES (1, 'probe', ?, 0)",
            (head,),
        )
        await db.set_launch_confirmed_head(CHAIN, head)

    assert (await db.get_launch_discovery_status(CHAIN))["confirmed_head"] == 102
    assert not db._db.in_transaction


@pytest.mark.asyncio
async def test_a_failed_write_never_discards_another_coroutines_write(db, other):
    paused, resume = asyncio.Event(), asyncio.Event()
    commit = db._db.commit

    async def paused_commit():
        paused.set()
        await resume.wait()
        await commit()

    with patch.object(db._db, "commit", paused_commit):
        recording = asyncio.create_task(db.record_outcome(CONTRACT, 56, 80.0, "block"))
        await asyncio.wait_for(paused.wait(), 5)
        # record_outcome has run its INSERT and waits before its commit: the row is already committed, so a
        # write failing meanwhile, here on another connection's lock, has nothing of it to take back.
        assert await _count(other, "outcome_events") == 1
        await other.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError, match="database is locked"):
            await db.set_launch_confirmed_head(CHAIN, 100)
        await other.execute("ROLLBACK")
        resume.set()
        await asyncio.wait_for(recording, 5)

    assert await _count(other, "outcome_events") == 1
    assert (await db.get_launch_discovery_status(CHAIN))["confirmed_head"] is None
    assert not db._db.in_transaction


@pytest.mark.asyncio
async def test_a_migration_on_the_shared_connection_still_rolls_back_whole(db, other):
    # The migrations run their statements inside an explicit BEGIN IMMEDIATE on the shared connection.
    await db._db.execute("DROP TABLE funder_links")
    await db._db.executescript(LEGACY_FUNDER_SCHEMA)
    await db._db.execute("INSERT INTO funder_links VALUES ('0xdeployer', 56, '0xfunder', 123, 500)")
    execute = db._db.execute

    async def fail_rename(sql, parameters=None):
        if "RENAME TO funder_links" in sql:
            raise aiosqlite.OperationalError("injected migration failure")
        return await execute(sql, parameters)

    with patch.object(db._db, "execute", fail_rename):
        with pytest.raises(aiosqlite.OperationalError, match="injected migration failure"):
            await db._create_tables()

    assert not db._db.in_transaction
    cursor = await other.execute("PRAGMA table_info(funder_links)")
    assert (await cursor.fetchall())[3][2] == "INTEGER"
    cursor = await other.execute("SELECT * FROM funder_links")
    assert await cursor.fetchall() == [("0xdeployer", 56, "0xfunder", 123, 500.0)]
    cursor = await other.execute("SELECT name FROM sqlite_master WHERE name = 'funder_links_new'")
    assert await cursor.fetchall() == []
