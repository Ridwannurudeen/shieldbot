"""Database.transaction(): a multi-statement write commits whole or not at all, whatever the shared connection does.

The shared connection keeps a write in an implicit transaction until the next commit, and any coroutine's commit
publishes it. A write inside transaction() runs on a connection of its own, so a failure between its statements
rolls all of them back while other coroutines keep writing and committing on the shared one.
"""

import asyncio
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import aiosqlite
import pytest
import pytest_asyncio

from core.database import Database
from core.indexer import DeployerIndexer


CHAIN = 4663
DEPLOYER = "0x" + "d" * 40
FUNDER = "0x" + "f" * 40
CONTRACT = "0x" + "c" * 40
CHAT_A, CHAT_B = 111, -100222


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "shieldbot.db"))
    await database.initialize()
    yield database
    await database.close()


def _locked_at(fragment):
    """aiosqlite's execute, patched on the class, failing the statement that contains ``fragment`` on any connection."""
    execute = aiosqlite.Connection.execute

    async def locked(self, sql, parameters=None):
        if fragment in sql:
            raise sqlite3.OperationalError("database is locked")
        return await execute(self, sql, parameters)

    return patch.object(aiosqlite.Connection, "execute", locked)


async def _count(db, table):
    cursor = await db._db.execute(f"SELECT COUNT(*) FROM {table}")
    return (await cursor.fetchone())[0]


# --- a write cut short -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_deployment_alert_cut_short_leaves_no_row_while_another_write_commits(db):
    await db.add_watched_deployer(DEPLOYER, 56)

    with _locked_at("UPDATE watched_deployers"):
        logged, recorded = await asyncio.gather(
            db.log_deployment_alert(DEPLOYER, 56, CONTRACT),
            db.record_outcome(CONTRACT, 56, 80.0, "blocked"),
            return_exceptions=True,
        )
    await db._db.commit()

    assert isinstance(logged, sqlite3.OperationalError) and recorded is None
    assert await _count(db, "deployment_alerts") == 0
    assert (await db.is_watched_deployer(DEPLOYER, 56))["alert_count"] == 0
    assert await _count(db, "outcome_events") == 1


@pytest.mark.asyncio
async def test_an_indexed_contract_whose_funder_link_fails_leaves_no_deployer_row(db):
    web3 = MagicMock()
    web3._get_adapter.return_value = SimpleNamespace(chain_id=56)
    web3.get_contract_creation_info = AsyncMock(return_value={"creator": DEPLOYER, "tx_hash": "0xabc"})
    indexer = DeployerIndexer(web3, db)
    indexer._fetch_funder = AsyncMock(return_value={"funder": FUNDER, "value": 10**18})

    with _locked_at("INSERT OR IGNORE INTO funder_links"):
        # The indexer logs the failure; another coroutine's write commits meanwhile.
        await asyncio.gather(
            indexer._index_contract(CONTRACT, 56),
            db.record_outcome(CONTRACT, 56, 80.0, "blocked"),
        )
    await db._db.commit()

    cursor = await db._db.execute("SELECT COUNT(*) FROM deployers WHERE contract_address = ?", (CONTRACT,))
    assert (await cursor.fetchone())[0] == 0
    assert await _count(db, "funder_links") == 0
    assert await _count(db, "outcome_events") == 1


# --- load and nesting --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_transactions_interleave_with_shared_connection_writes_without_a_lock_error(db):
    await db.add_watched_deployer(DEPLOYER, 56)
    chats = list(range(1, 6))
    for chat_id in chats:
        await db.subscribe_launch_alerts(chat_id, CHAIN, "all")
    addresses = ["0x" + f"{index:040x}" for index in range(1, 21)]
    writes = []
    for index, address in enumerate(addresses):
        writes += [
            db.upsert_contract_score(address, 56, 10.0, "LOW"),
            db.record_outcome(address, 56, 10.0, "proceed"),
            db.log_deployment_alert(DEPLOYER, 56, address),
        ]
        if index < len(chats):
            writes.append(db.unsubscribe_launch_alerts(chats[index], CHAIN))

    results = await asyncio.gather(*writes, return_exceptions=True)

    assert [result for result in results if isinstance(result, BaseException)] == []
    assert await _count(db, "contract_scores") == 20
    assert await _count(db, "outcome_events") == 20
    assert await _count(db, "deployment_alerts") == 20
    assert (await db.is_watched_deployer(DEPLOYER, 56))["alert_count"] == 20
    assert await _count(db, "launch_alert_subscriptions") == 0
    assert not db._db.in_transaction
    assert not db._txn_db.in_transaction


@pytest.mark.asyncio
async def test_a_chat_move_unsubscribes_inside_its_own_transaction_without_waiting_for_itself(db):
    await db.subscribe_launch_alerts(CHAT_A, CHAIN, "all")

    await asyncio.wait_for(db.move_launch_alert_chat(CHAT_A, CHAT_B, CHAIN), 5)

    cursor = await db._db.execute("SELECT chat_id FROM launch_alert_subscriptions")
    assert [row[0] for row in await cursor.fetchall()] == [CHAT_B]


# --- lifecycle ---------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_transaction_connection_opens_on_first_use_and_never_after_close(db):
    assert db._txn_db is None
    async with db.transaction() as connection:
        assert connection is db._txn_db and connection is not db._db
    assert db._txn_db is not None

    await db.close()

    assert db._txn_db is None
    with pytest.raises(ValueError):
        async with db.transaction():
            pass
    assert db._txn_db is None


@pytest.mark.asyncio
async def test_close_closes_the_shared_connection_when_the_transaction_connection_fails_to_close(db):
    async with db.transaction():
        pass
    txn, shared = db._txn_db, db._db
    close_txn = txn.close

    async def fails():
        raise sqlite3.OperationalError("disk I/O error")

    txn.close = fails
    try:
        with pytest.raises(sqlite3.OperationalError):
            await db.close()
        with pytest.raises(ValueError):
            await shared.execute("SELECT 1")
    finally:
        await close_txn()


@pytest.mark.asyncio
async def test_an_in_memory_database_runs_its_transactions_on_the_shared_connection():
    db = Database(":memory:")
    await db.initialize()
    try:
        with pytest.raises(RuntimeError, match="cut short"):
            async with db.transaction() as connection:
                assert connection is db._db
                await connection.execute(
                    "INSERT INTO outcome_events (address, chain_id, created_at) VALUES (?, ?, ?)",
                    (CONTRACT, 56, 0.0),
                )
                raise RuntimeError("cut short")
        assert db._txn_db is None
        assert await _count(db, "outcome_events") == 0
    finally:
        await db.close()
