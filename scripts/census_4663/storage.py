"""Durable, atomic census snapshots outside the application checkout."""

import json
from pathlib import Path

import aiosqlite


def data_directory(path):
    directory = Path(path).expanduser().resolve()
    repo = Path(__file__).resolve().parents[2]
    if directory == repo or repo in directory.parents:
        raise ValueError("Census data directory must be outside the repository")
    if any((parent / ".git").exists() for parent in (directory, *directory.parents)):
        raise ValueError("Census data directory must be outside any repository")
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
