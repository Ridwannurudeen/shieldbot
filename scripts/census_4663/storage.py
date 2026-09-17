"""Durable, atomic census snapshots outside the application checkout."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import aiosqlite


def data_directory(path, create=True):
    directory = Path(path).expanduser().resolve()
    repo = Path(__file__).resolve().parents[2]
    if directory == repo or repo in directory.parents:
        raise ValueError("Census data directory must be outside the repository")
    if any((parent / ".git").exists() for parent in (directory, *directory.parents)):
        raise ValueError("Census data directory must be outside any repository")
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    return directory


async def initialize(db):
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA busy_timeout=5000")
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS blocks (
            number INTEGER PRIMARY KEY, hash TEXT NOT NULL, timestamp INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS pools (
            pool_key TEXT PRIMARY KEY, source TEXT NOT NULL, token0 TEXT NOT NULL,
            token1 TEXT NOT NULL, block_number INTEGER NOT NULL, timestamp INTEGER NOT NULL,
            tx_hash TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (
            source TEXT NOT NULL, pool_key TEXT NOT NULL, name TEXT NOT NULL,
            block_number INTEGER NOT NULL, timestamp INTEGER NOT NULL, tx_hash TEXT NOT NULL,
            log_index INTEGER NOT NULL, ingested_at REAL NOT NULL, data TEXT NOT NULL,
            PRIMARY KEY(tx_hash, log_index));
        CREATE INDEX IF NOT EXISTS events_pool ON events(pool_key, block_number);
        CREATE TABLE IF NOT EXISTS evidence (
            tx_hash TEXT PRIMARY KEY, block_number INTEGER NOT NULL, data TEXT NOT NULL);
    """)
    await db.commit()


async def load_data(data_dir):
    path = data_directory(data_dir) / "census.sqlite3"
    if not path.is_file():
        raise ValueError("No census database; run the collector first")
    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("BEGIN")
        result = {}
        for table, statement in (
            ("pools", "SELECT * FROM pools"),
            ("events", "SELECT * FROM events"),
            ("evidence", "SELECT * FROM evidence"),
            ("blocks", "SELECT * FROM blocks"),
            ("meta", "SELECT * FROM meta"),
        ):
            async with db.execute(statement) as cursor:
                result[table] = [dict(row) for row in await cursor.fetchall()]
            for row in result[table]:
                if "data" in row:
                    row["data"] = json.loads(row["data"])
        result["meta"] = {row["key"]: row["value"] for row in result["meta"]}
        if result["meta"].get("chain_id") != "4663":
            raise ValueError("Census database is not bound to chain 4663")
        return result


class CensusSnapshot:
    """Stream report inputs from one snapshot without loading events or evidence."""

    def __init__(self, connection):
        self.connection = connection
        self.meta = {
            row["key"]: row["value"]
            for row in connection.execute("SELECT key, value FROM meta")
        }
        connection.execute(
            "CREATE TEMP TABLE token_pools "
            "(position INTEGER PRIMARY KEY, pool_key TEXT NOT NULL)"
        )

    def coverage(self):
        return tuple(
            self.connection.execute(
                "SELECT MIN(timestamp), MAX(timestamp) FROM blocks"
            ).fetchone()
        )

    def pools(self):
        for row in self.connection.execute("SELECT * FROM pools ORDER BY rowid"):
            yield {**dict(row), "data": json.loads(row["data"])}

    def token_events(self, pools, first_seen, deadline, end):
        """Yield events from first_seen to deadline in log order, then later swaps.

        Metrics use events after the deadline only as swap directions, so those
        need no ordering. Sorting only the first window keeps SQLite's sorter
        small for tokens paired in thousands of pools.
        """
        self.connection.execute("DELETE FROM temp.token_pools")
        self.connection.executemany(
            "INSERT INTO temp.token_pools VALUES (?, ?)",
            enumerate(pool["pool_key"] for pool in pools),
        )
        early = self.connection.execute(
            "SELECT e.pool_key, e.name, e.timestamp, e.data "
            "FROM temp.token_pools AS p CROSS JOIN events AS e "
            "ON e.pool_key = p.pool_key "
            "WHERE e.timestamp >= ? AND e.timestamp <= ? "
            "ORDER BY e.block_number, e.log_index, p.position, e.rowid",
            (first_seen, deadline),
        )
        for row in early:
            yield {**dict(row), "data": json.loads(row["data"])}
        late = self.connection.execute(
            "SELECT e.pool_key, e.name, e.timestamp, e.data "
            "FROM temp.token_pools AS p CROSS JOIN events AS e "
            "ON e.pool_key = p.pool_key "
            "WHERE e.name = 'Swap' AND e.timestamp > ? AND e.timestamp <= ?",
            (deadline, end),
        )
        for row in late:
            yield {**dict(row), "data": json.loads(row["data"])}

    def creation_events(self):
        return self.connection.execute(
            "SELECT pool_key, timestamp, ingested_at FROM events "
            "WHERE name IN ('Initialize', 'PairCreated', 'PoolCreated')"
        )

    def evidence(self):
        rows = self.connection.execute(
            "SELECT tx_hash, data FROM evidence ORDER BY rowid"
        )
        for row in rows:
            yield {"tx_hash": row["tx_hash"], "data": json.loads(row["data"])}


@contextmanager
def read_snapshot(data_dir):
    path = data_directory(data_dir, create=False) / "census.sqlite3"
    if not path.is_file():
        raise ValueError("No census database; run the collector first")
    # A read-only connection never takes a write lock. One deferred transaction
    # pins a single WAL snapshot while the collector keeps committing.
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        snapshot = CensusSnapshot(connection)
        if snapshot.meta.get("chain_id") != "4663":
            raise ValueError("Census database is not bound to chain 4663")
        yield snapshot
    finally:
        connection.close()
