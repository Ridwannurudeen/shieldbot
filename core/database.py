"""Database layer — SQLite with WAL mode for contract reputation and outcome tracking."""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator, Dict, List, Optional, Tuple

import aiosqlite

from core.extension_formatter import is_scan_incomplete
from core.verdicts import CAUTION_MIN, HIGH, THREAT_CONDITION, stored_level

logger = logging.getLogger(__name__)

# Chain 4663 shares 1 rps; discovery uses ~0.27. Four subjects at 23 requests
# every 300s use 0.307 rps, leaving ~0.42 rps for launches and other work.
GUARD_WATCH_MAX_SUBJECTS = max(0, int(os.getenv("GUARD_WATCH_MAX_SUBJECTS", "4")))

# Eighteen digits keep a cursor block inside SQLite's signed 64-bit integers.
_LAUNCH_CURSOR = re.compile(r"(\d{1,18}):(0x[0-9a-f]{40})")
_NO_SCAN_DETAIL = "Coverage details were not recorded for this scan"
# The hunter stores the finding holding a blocked launch's evidence, after any AI narrative,
# before it marks the launch blocked, so an alert normally finds that evidence already there.
# This is how long an alert still waits when the evidence is missing anyway, for example a
# finding whose store failed, before it is queued without it.
_BLOCKED_EVIDENCE_WAIT_SECONDS = 300
# A Telegram send times out within seconds, so an alert still marked sending after this long
# belongs to a pass that died between claiming it and recording the result.
_LAUNCH_ALERT_SEND_TIMEOUT_SECONDS = 300
# Days of API key usage rows and daily AI token counts kept. Quotas and the AI budget read only the
# current UTC day, and /api/usage reads the last 30 days.
USAGE_RETENTION_DAYS = 90
# Days an /api/firewall or /api/scan evidence document (core/scan_evidence.py) stays retrievable.
SCAN_EVIDENCE_RETENTION_DAYS = 90

# One row per discovered launch with its latest outcome. A recheck records blocked or cleared on
# the launch's tracked pair (keyed by the token), and a newer one supersedes the launch scan. A
# watching pair has only been queued for a recheck, so it changes nothing.
_LAUNCH_SELECT = """
    SELECT token_address, source, launchpad, pool_id, block_number, tx_hash, block_timestamp,
           discovered_at,
           CASE WHEN rechecked THEN recheck_status ELSE scan_status END,
           CASE WHEN rechecked THEN NULL ELSE risk_score END,
           CASE WHEN rechecked THEN recheck_at ELSE scanned_at END AS outcome_at,
           impostor_check
    FROM (
        SELECT l.*, p.status AS recheck_status, p.last_checked AS recheck_at,
               COALESCE(p.status IN ('blocked', 'cleared') AND p.last_checked >= l.scanned_at, 0)
                   AS rechecked
        FROM discovered_launches l
        LEFT JOIN tracked_pairs p ON p.pair_address = l.token_address AND p.chain_id = l.chain_id
"""
_LAUNCH_ROWS = _LAUNCH_SELECT + """
        WHERE l.chain_id = ?
    )
"""
_LAUNCH_FEED_FIRST_PAGE = _LAUNCH_ROWS + """
    ORDER BY block_number DESC, token_address DESC
    LIMIT ?
"""
_LAUNCH_FEED_NEXT_PAGE = _LAUNCH_ROWS + """
    WHERE (block_number, token_address) < (?, ?)
    ORDER BY block_number DESC, token_address DESC
    LIMIT ?
"""
# Launches whose latest outcome was recorded at or after a time, found through the scan-time
# index and the rechecked pairs rather than a scan of every discovered launch. It repeats
# _LAUNCH_SELECT as one literal because its filter holds a subquery.
_LAUNCH_OUTCOMES_SINCE = """
    SELECT token_address, source, launchpad, pool_id, block_number, tx_hash, block_timestamp,
           discovered_at,
           CASE WHEN rechecked THEN recheck_status ELSE scan_status END,
           CASE WHEN rechecked THEN NULL ELSE risk_score END,
           CASE WHEN rechecked THEN recheck_at ELSE scanned_at END AS outcome_at,
           impostor_check
    FROM (
        SELECT l.*, p.status AS recheck_status, p.last_checked AS recheck_at,
               COALESCE(p.status IN ('blocked', 'cleared') AND p.last_checked >= l.scanned_at, 0)
                   AS rechecked
        FROM discovered_launches l
        LEFT JOIN tracked_pairs p ON p.pair_address = l.token_address AND p.chain_id = l.chain_id
        WHERE (l.chain_id = ? AND l.scanned_at >= ?) OR (l.chain_id = ? AND l.token_address IN (
            SELECT pair_address FROM tracked_pairs
            WHERE chain_id = ? AND status IN ('blocked', 'cleared') AND last_checked >= ?
        ))
    )
    WHERE outcome_at >= ?
    ORDER BY outcome_at, token_address
"""


def reporter_hash(secret: str, client_ip: str) -> Optional[str]:
    """A community report's reporter_id: HMAC-SHA256 of the client IP under REPORTER_HASH_SECRET,
    as 32 hex characters, or None when no secret is set. Neither the IP nor the secret is stored."""
    if not secret:
        return None
    return hmac.new(secret.encode(), client_ip.encode(), hashlib.sha256).hexdigest()[:32]


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _lift_scan_metadata(score: Dict) -> Dict:
    """Expose stored scan coverage at the top level while keeping it in category_scores.

    Rows written before coverage tracking carry no metadata and are reported as unknown.
    """
    metadata = score['category_scores'].get('_scan_metadata')
    if not metadata:
        score['status'] = 'unknown'
        score['coverage_reasons'] = {'coverage': 'Score predates coverage tracking'}
        return score
    for key in ('status', 'coverage', 'coverage_reasons'):
        if key in metadata:
            score[key] = metadata[key]
    return score


def _launch_outcome(stored_status, scanned_at) -> str:
    """Name a launch's latest outcome; any status the feed does not know is unknown."""
    if scanned_at is None:
        return "not_scanned"
    return stored_status if stored_status in ("blocked", "watching", "cleared") else "unknown"


def _launch_scan(stored_status, risk_score, scanned_at, finding) -> Dict:
    """Describe a launch's latest outcome; ``status`` is the authoritative completeness field.

    The hunter records watching and cleared only for complete scans, and a recheck clears only
    a complete scan, so both are complete. A blocked launch takes its detail, including
    per-field coverage, from the hunter's finding evidence and is not shown as complete without
    it; no other outcome has per-field coverage recorded. An unknown scan's partial score is
    withheld so that it cannot read as a verdict.
    """
    outcome = _launch_outcome(stored_status, scanned_at)
    scan = {
        "outcome": outcome,
        "status": "unknown",
        "risk_level": None,
        "risk_score": None,
        "coverage": None,
        "coverage_reasons": {"scan": "Scan incomplete; coverage details were not recorded"},
        "flags": [],
        "scanned_at": scanned_at,
    }
    if outcome == "not_scanned":
        scan["coverage_reasons"] = {"scan": "Not scanned yet"}
    elif outcome in ("watching", "cleared"):
        scan.update(status="ok", risk_score=risk_score, coverage_reasons={})
    elif outcome == "blocked":
        finding_score, evidence = finding
        scan["risk_score"] = risk_score if risk_score is not None else finding_score
        if evidence is None:
            scan["coverage_reasons"] = {"scan": _NO_SCAN_DETAIL}
        else:
            incomplete = is_scan_incomplete(evidence)
            scan.update(
                status="unknown" if incomplete else "ok",
                risk_level=evidence.get("risk_level"),
                coverage=evidence.get("coverage"),
                coverage_reasons=evidence.get("coverage_reasons") or ({"scan": _NO_SCAN_DETAIL} if incomplete else {}),
                flags=evidence.get("critical_flags") or [],
            )
    elif stored_status == "error":
        scan["coverage_reasons"] = {"scan": "Scan failed before completing"}
    return scan


# How decided a launch's impostor check is: under the same rules, a stored check is only replaced by one
# at least as decided.
_IMPOSTOR_CHECK_RANK = {"unknown": 0, "none": 1, "collision": 2, "impostor": 3, "official": 3}
_STORED_IMPOSTOR_CHECK_RANK = "CASE json_extract(impostor_check, '$.status') " + " ".join(
    f"WHEN '{status}' THEN {rank}" for status, rank in _IMPOSTOR_CHECK_RANK.items()
) + " END"


def _impostor_check(stored) -> Optional[Dict]:
    return json.loads(stored) if stored else None


def _launch_item(chain_id: int, row, finding) -> Dict:
    (token, source, launchpad, pool_id, block_number, tx_hash, block_timestamp,
     discovered_at, stored_status, risk_score, outcome_at, impostor_check) = row
    return {
        "chain_id": chain_id,
        "token_address": token,
        "launchpad": launchpad,
        "source": source,
        "pool_id": pool_id,
        "tx_hash": tx_hash,
        "block_number": block_number,
        "block_timestamp": block_timestamp,
        "discovered_at": discovered_at,
        "scan": _launch_scan(stored_status, risk_score, outcome_at, finding),
        "impostor_check": _impostor_check(impostor_check),
        "verdict_url": f"/api/verdict/{chain_id}/{token}",
    }


class Database:
    """Async SQLite database for contract scores and outcome events."""

    def __init__(self, db_path: str = "shieldbot.db"):
        self.db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None
        # The verdict drain's own connection: one aiosqlite connection carries one implicit transaction,
        # so a rollback on the shared one would undo whatever else was being written at the time.
        self._drain_db: Optional[aiosqlite.Connection] = None
        self._drain_lock = asyncio.Lock()
        # The sender lease's own connection: its commits and rollbacks run beside the drain's, never inside a
        # transaction the drain has open.
        self._lease_db: Optional[aiosqlite.Connection] = None
        self._lease_lock = asyncio.Lock()
        # One lease call at a time on that connection: calls that overlap share its implicit transaction, so one
        # call's rollback would undo another's upsert.
        self._lease_calls = asyncio.Lock()
        # transaction()'s own connection, in autocommit mode: each write transaction is an explicit BEGIN IMMEDIATE
        # ... COMMIT, so no other coroutine's commit publishes half of it.
        self._txn_db: Optional[aiosqlite.Connection] = None
        self._txn_open = asyncio.Lock()
        # One transaction at a time on that connection.
        self._txn_lock = asyncio.Lock()

    async def initialize(self):
        """Open connection and create tables."""
        self._db = await aiosqlite.connect(self.db_path)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA busy_timeout=5000")
        await self._create_tables()
        logger.info(f"Database initialized at {self.db_path}")

    async def _outbox(self) -> aiosqlite.Connection:
        """The connection the verdict drain writes on, so its rollback never reaches another coroutine's work.

        Opened on first use: only the process that drains ever holds it, and a write after close() never
        reopens one. An in-memory database keeps the shared connection, because a second connection to
        ":memory:" would be a different database.
        """
        if self._drain_db is None and self._db is not None and self.db_path != ":memory:":
            async with self._drain_lock:
                if self._drain_db is None:
                    self._drain_db = await self._second_connection()
        return self._drain_db or self._db

    async def _lease(self) -> aiosqlite.Connection:
        """The sender lease's connection, opened on first use like the drain's; an in-memory database keeps the
        shared one, as the drain's does."""
        if self._lease_db is None and self._db is not None and self.db_path != ":memory:":
            async with self._lease_lock:
                if self._lease_db is None:
                    self._lease_db = await self._second_connection()
        return self._lease_db or self._db

    async def _transaction_connection(self) -> aiosqlite.Connection:
        """transaction()'s connection, opened on first use like the drain's; an in-memory database keeps the shared
        one, as the drain's does. After close() it raises ValueError and never reopens one."""
        if self._txn_db is None and self._db is not None and self.db_path != ":memory:":
            async with self._txn_open:
                if self._txn_db is None:
                    self._txn_db = await self._second_connection(autocommit=True)
        connection = self._txn_db or self._db
        if connection is None:
            raise ValueError("Connection closed")
        return connection

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        """One write transaction, BEGIN IMMEDIATE ... COMMIT, rolled back on any exception, one at a time.

        Await nothing but the yielded connection inside the block: a write on the shared connection would
        wait for this transaction's lock, and a nested transaction() would wait for itself.
        """
        connection = await self._transaction_connection()
        async with self._txn_lock:
            try:
                if connection is not self._db:
                    await connection.execute("BEGIN IMMEDIATE")
                yield connection
                await connection.commit()
            except BaseException:
                try:
                    await connection.rollback()
                except Exception as e:   # a rollback on a connection closed underneath must not hide the cause
                    logger.warning("Transaction rollback failed: %s", type(e).__name__)
                raise

    async def _second_connection(self, autocommit: bool = False) -> Optional[aiosqlite.Connection]:
        """Another connection to the database file, or None if close() ran while it was opening.

        An autocommit connection opens no implicit transaction, so it writes in one only after an explicit BEGIN.
        """
        if autocommit:
            opened = await aiosqlite.connect(self.db_path, isolation_level=None)
        else:
            opened = await aiosqlite.connect(self.db_path)
        await opened.execute("PRAGMA busy_timeout=5000")
        # Checked after the last await, so the caller stores the connection before close() can run again.
        if self._db is None:
            # close() ran while this connection was opening; leaving it open would
            # keep aiosqlite's non-daemon worker thread alive past shutdown.
            await opened.close()
            return None
        return opened

    async def close(self):
        """Close the database connection.

        Every handle is detached first: a write landing while a close is awaited must fail, not
        reopen the drain's, the lease's or transaction()'s connection behind us.
        """
        drain, lease, txn, shared = self._drain_db, self._lease_db, self._txn_db, self._db
        self._drain_db = self._lease_db = self._txn_db = self._db = None
        # A connection that fails to close must not leave the others open.
        try:
            if drain:
                await drain.close()
        finally:
            try:
                if lease:
                    await lease.close()
            finally:
                try:
                    if txn:
                        await txn.close()
                finally:
                    if shared:
                        await shared.close()

    async def _create_tables(self):
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS contract_scores (
                address TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                archetype TEXT,
                category_scores TEXT,
                flags TEXT,
                confidence REAL,
                first_seen_at REAL NOT NULL,
                last_scanned_at REAL NOT NULL,
                scan_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (address, chain_id)
            );

            CREATE TABLE IF NOT EXISTS outcome_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                chain_id INTEGER NOT NULL DEFAULT 56,
                risk_score_at_scan REAL,
                user_decision TEXT,
                outcome TEXT,
                tx_hash TEXT,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_outcome_address
                ON outcome_events(address, chain_id);

            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                key_hash TEXT NOT NULL UNIQUE,
                owner TEXT NOT NULL,
                tier TEXT NOT NULL DEFAULT 'free',
                rpm_limit INTEGER NOT NULL DEFAULT 60,
                daily_limit INTEGER NOT NULL DEFAULT 1000,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_api_usage_key
                ON api_usage(key_id, created_at);
            -- The retention prune deletes by time alone.
            CREATE INDEX IF NOT EXISTS idx_api_usage_created_at
                ON api_usage(created_at);

            CREATE TABLE IF NOT EXISTS api_daily_usage (
                key_id TEXT NOT NULL,
                utc_day INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (key_id, utc_day)
            );

            CREATE TABLE IF NOT EXISTS deployers (
                contract_address TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                deployer_address TEXT NOT NULL,
                deploy_tx_hash TEXT,
                indexed_at REAL NOT NULL,
                PRIMARY KEY (contract_address, chain_id)
            );

            CREATE TABLE IF NOT EXISTS funder_links (
                deployer_address TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                funder_address TEXT NOT NULL,
                funding_value_wei TEXT DEFAULT '0',
                indexed_at REAL NOT NULL,
                PRIMARY KEY (deployer_address, chain_id)
            );

            CREATE INDEX IF NOT EXISTS idx_deployer_address
                ON deployers(deployer_address);
            CREATE INDEX IF NOT EXISTS idx_funder_address
                ON funder_links(funder_address);

            CREATE TABLE IF NOT EXISTS community_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                chain_id INTEGER NOT NULL DEFAULT 56,
                report_type TEXT NOT NULL,
                reporter_id TEXT,
                reason TEXT,
                risk_score_at_report REAL,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_community_reports_address
                ON community_reports(address, chain_id);

            CREATE TABLE IF NOT EXISTS beta_signups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                signed_up_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS watched_deployers (
                deployer_address TEXT NOT NULL,
                chain_id INTEGER NOT NULL DEFAULT 0,
                watch_reason TEXT NOT NULL,
                risk_severity TEXT NOT NULL DEFAULT 'HIGH',
                contract_count INTEGER DEFAULT 0,
                high_risk_count INTEGER DEFAULT 0,
                alert_count INTEGER NOT NULL DEFAULT 0,
                last_alert_at REAL,
                created_at REAL NOT NULL,
                PRIMARY KEY (deployer_address, chain_id)
            );

            CREATE TABLE IF NOT EXISTS deployment_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                deployer_address TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                new_contract_address TEXT NOT NULL,
                watch_reason TEXT,
                telegram_sent INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_deployment_alerts_deployer
                ON deployment_alerts(deployer_address, created_at);

            CREATE TABLE IF NOT EXISTS agent_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_type TEXT NOT NULL,
                investigation_id TEXT,
                address TEXT,
                deployer TEXT,
                chain_id INTEGER NOT NULL DEFAULT 56,
                risk_score INTEGER,
                narrative TEXT,
                evidence TEXT,
                action_taken TEXT,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_agent_findings_type
                ON agent_findings(finding_type, created_at);
            CREATE INDEX IF NOT EXISTS idx_agent_findings_address
                ON agent_findings(address);

            CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                message TEXT NOT NULL,
                tools_used TEXT,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chat_history_user
                ON chat_history(user_id, created_at);

            CREATE TABLE IF NOT EXISTS tracked_pairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pair_address TEXT UNIQUE NOT NULL,
                token_address TEXT,
                deployer TEXT,
                liquidity_usd REAL,
                first_seen REAL NOT NULL,
                last_checked REAL,
                status TEXT NOT NULL DEFAULT 'watching'
            );

            CREATE INDEX IF NOT EXISTS idx_tracked_pairs_status
                ON tracked_pairs(status);

            CREATE TABLE IF NOT EXISTS agent_policies (
                agent_id TEXT PRIMARY KEY,
                owner_address TEXT NOT NULL,
                owner_telegram TEXT,
                owner_webhook TEXT,
                tier TEXT NOT NULL DEFAULT 'free',
                policy TEXT NOT NULL DEFAULT '{}',
                registered_by_key TEXT,
                daily_spend_used_usd REAL DEFAULT 0,
                daily_spend_reset_at REAL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_firewall_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                tx_to TEXT,
                tx_value TEXT,
                verdict TEXT NOT NULL,
                score REAL,
                flags TEXT,
                evidence TEXT,
                policy_result TEXT,
                latency_ms REAL,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_agent_fw_history
                ON agent_firewall_history(agent_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS threat_graph_edges (
                source_address TEXT NOT NULL,
                target_address TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                relationship TEXT NOT NULL,
                evidence TEXT,
                confidence REAL DEFAULT 0.5,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                PRIMARY KEY (source_address, target_address, chain_id, relationship)
            );
            CREATE INDEX IF NOT EXISTS idx_graph_source
                ON threat_graph_edges(source_address, chain_id);
            CREATE INDEX IF NOT EXISTS idx_graph_target
                ON threat_graph_edges(target_address, chain_id);

            CREATE TABLE IF NOT EXISTS threat_graph_clusters (
                cluster_id TEXT NOT NULL,
                address TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                role TEXT,
                confidence REAL DEFAULT 0.5,
                updated_at REAL NOT NULL,
                PRIMARY KEY (cluster_id, address, chain_id)
            );
            CREATE INDEX IF NOT EXISTS idx_cluster_address
                ON threat_graph_clusters(address, chain_id);

            CREATE TABLE IF NOT EXISTS guardian_wallets (
                wallet_address TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                owner_id TEXT NOT NULL,
                is_agent_wallet INTEGER DEFAULT 0,
                health_score REAL DEFAULT 100,
                last_scan_at REAL,
                last_event_at REAL,
                created_at REAL NOT NULL,
                PRIMARY KEY (wallet_address, chain_id)
            );
            CREATE INDEX IF NOT EXISTS idx_guardian_wallets_owner
                ON guardian_wallets(owner_id);

            CREATE TABLE IF NOT EXISTS guardian_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_address TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                details TEXT,
                acknowledged INTEGER DEFAULT 0,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_guardian_alerts_wallet
                ON guardian_alerts(wallet_address, chain_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS anomaly_baselines (
                agent_id TEXT PRIMARY KEY,
                baseline_data TEXT NOT NULL,
                baseline_started_at REAL,
                baseline_ready INTEGER DEFAULT 0,
                last_updated REAL
            );

            CREATE TABLE IF NOT EXISTS reputation_cache (
                agent_id TEXT NOT NULL,
                registry TEXT NOT NULL,
                trust_score REAL,
                total_jobs INTEGER DEFAULT 0,
                disputed_jobs INTEGER DEFAULT 0,
                raw_data TEXT,
                last_fetched REAL,
                PRIMARY KEY (agent_id, registry)
            );
        """)
        await self._db.commit()
        await self._migrate_funding_value_wei()
        await self._migrate_tracked_pairs_chain_id()
        await self._migrate_outcome_source()
        await self._migrate_reporter_ips()
        await self._migrate_contract_score_levels()
        await self._create_launch_discovery_tables()
        await self._create_launch_feed_tables()
        await self._create_launch_alert_tables()
        await self._create_verdict_evidence_tables()
        await self._create_scan_evidence_tables()
        await self._create_ai_usage_tables()
        await self._create_free_key_tables()
        await self._create_scam_blacklist_table()

        # Migrate: add registered_by_key column for existing DBs
        try:
            await self._db.execute(
                "ALTER TABLE agent_policies ADD COLUMN registered_by_key TEXT"
            )
            await self._db.commit()
        except Exception:
            pass  # Column already exists

    async def _migrate_funding_value_wei(self):
        """Store integer wei as decimal text without losing rows or precision."""
        await self._db.execute("BEGIN IMMEDIATE")
        try:
            cursor = await self._db.execute("PRAGMA table_info(funder_links)")
            columns = await cursor.fetchall()
            funding_column = next(c for c in columns if c[1] == "funding_value_wei")
            if funding_column[2].upper() == "TEXT":
                await self._db.commit()
                return

            cursor = await self._db.execute("""
                SELECT 1 FROM funder_links
                WHERE typeof(funding_value_wei) NOT IN ('integer', 'text', 'null')
                LIMIT 1
            """)
            if await cursor.fetchone():
                raise ValueError("Cannot perform lossless funding-value migration: non-integer values exist")

            cursor = await self._db.execute("""
                SELECT sql FROM sqlite_master
                WHERE tbl_name = 'funder_links'
                    AND type IN ('index', 'trigger') AND sql IS NOT NULL
            """)
            schema_objects = await cursor.fetchall()
            await self._db.execute("""
                CREATE TABLE funder_links_new (
                    deployer_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    funder_address TEXT NOT NULL,
                    funding_value_wei TEXT DEFAULT '0',
                    indexed_at REAL NOT NULL,
                    PRIMARY KEY (deployer_address, chain_id)
                )
            """)
            await self._db.execute("""
                INSERT INTO funder_links_new
                    (rowid, deployer_address, chain_id, funder_address, funding_value_wei, indexed_at)
                SELECT rowid, deployer_address, chain_id, funder_address,
                    CAST(funding_value_wei AS TEXT), indexed_at
                FROM funder_links
            """)
            await self._db.execute("DROP TABLE funder_links")
            await self._db.execute("ALTER TABLE funder_links_new RENAME TO funder_links")
            for (sql,) in schema_objects:
                await self._db.execute(sql)
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise

    async def _migrate_tracked_pairs_chain_id(self):
        """Tag tracked pairs with their chain; rows from before chain tracking are BSC."""
        await self._db.execute("BEGIN IMMEDIATE")
        try:
            cursor = await self._db.execute("PRAGMA table_info(tracked_pairs)")
            if not any(column[1] == "chain_id" for column in await cursor.fetchall()):
                await self._db.execute(
                    "ALTER TABLE tracked_pairs ADD COLUMN chain_id INTEGER NOT NULL DEFAULT 56"
                )
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise

    async def _migrate_outcome_source(self):
        """Record who sent each outcome event. Rows from before this column came from a route anyone
        can call, so they are 'client' rows."""
        await self._db.execute("BEGIN IMMEDIATE")
        try:
            cursor = await self._db.execute("PRAGMA table_info(outcome_events)")
            if not any(column[1] == "source" for column in await cursor.fetchall()):
                await self._db.execute(
                    "ALTER TABLE outcome_events ADD COLUMN source TEXT NOT NULL DEFAULT 'client'"
                )
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise

    async def _migrate_reporter_ips(self):
        """Clear every community report reporter_id that is a raw client IP, stored before reporters
        were hashed, in one transaction. Rows already cleared or hashed are left as they are."""
        await self._db.execute("BEGIN IMMEDIATE")
        try:
            cursor = await self._db.execute(
                "SELECT id, reporter_id FROM community_reports WHERE reporter_id IS NOT NULL"
            )
            ips = [(row_id,) for row_id, reporter in await cursor.fetchall() if _is_ip_address(reporter)]
            await self._db.executemany(
                "UPDATE community_reports SET reporter_id = NULL WHERE id = ?", ips
            )
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise

    async def _migrate_contract_score_levels(self):
        """Raise every stored level below the band of its stored score, in one transaction. Rows
        written before the level followed the final score keep the level of the unboosted or unfloored
        score. A level is never lowered, so an incomplete scan's MEDIUM stays MEDIUM."""
        await self._db.execute("BEGIN IMMEDIATE")
        try:
            cursor = await self._db.execute(
                "SELECT address, chain_id, risk_score, risk_level FROM contract_scores WHERE risk_score >= ?",
                (CAUTION_MIN,),
            )
            raised = []
            for address, chain_id, score, level in await cursor.fetchall():
                level_for_score = stored_level(score, level)
                if level_for_score != level:
                    raised.append((level_for_score, address, chain_id))
            await self._db.executemany(
                "UPDATE contract_scores SET risk_level = ? WHERE address = ? AND chain_id = ?", raised
            )
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise

    # --- Contract Scores ---

    async def upsert_contract_score(
        self,
        address: str,
        chain_id: int,
        risk_score: float,
        risk_level: str,
        archetype: str = None,
        category_scores: Dict = None,
        flags: List[str] = None,
        confidence: float = None,
    ):
        """Insert or update a contract score record."""
        now = time.time()
        cat_json = json.dumps(category_scores) if category_scores else None
        flags_json = json.dumps(flags) if flags else None

        await self._db.execute("""
            INSERT INTO contract_scores
                (address, chain_id, risk_score, risk_level, archetype,
                 category_scores, flags, confidence, first_seen_at, last_scanned_at, scan_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(address, chain_id) DO UPDATE SET
                risk_score = excluded.risk_score,
                risk_level = excluded.risk_level,
                archetype = excluded.archetype,
                category_scores = excluded.category_scores,
                flags = excluded.flags,
                confidence = excluded.confidence,
                last_scanned_at = excluded.last_scanned_at,
                scan_count = scan_count + 1
        """, (
            address.lower(), chain_id, risk_score, risk_level, archetype,
            cat_json, flags_json, confidence, now, now,
        ))
        await self._db.commit()

    async def get_contract_score(
        self, address: str, chain_id: int, max_age_seconds: float = 300
    ) -> Optional[Dict]:
        """Get cached contract score if fresh enough."""
        cursor = await self._db.execute("""
            SELECT risk_score, risk_level, archetype, category_scores, flags,
                   confidence, first_seen_at, last_scanned_at, scan_count
            FROM contract_scores
            WHERE address = ? AND chain_id = ?
        """, (address.lower(), chain_id))
        row = await cursor.fetchone()
        if not row:
            return None

        last_scanned = row[7]
        if (time.time() - last_scanned) > max_age_seconds:
            return None

        return _lift_scan_metadata({
            'risk_score': row[0],
            'risk_level': row[1],
            'archetype': row[2],
            'category_scores': json.loads(row[3]) if row[3] else {},
            'flags': json.loads(row[4]) if row[4] else [],
            'confidence': row[5],
            'first_seen_at': row[6],
            'last_scanned_at': row[7],
            'scan_count': row[8],
            'cached': True,
        })

    async def get_all_scored_contracts(
        self, min_risk_score: int = 50, limit: int = 500
    ) -> List[Dict]:
        """Get all scored contracts above a risk threshold for graph seeding."""
        cursor = await self._db.execute("""
            SELECT address, chain_id, risk_score, risk_level, archetype,
                   category_scores, flags, confidence
            FROM contract_scores
            WHERE risk_score >= ?
            ORDER BY risk_score DESC
            LIMIT ?
        """, (min_risk_score, limit))
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            results.append(_lift_scan_metadata({
                "address": row[0],
                "chain_id": row[1],
                "risk_score": row[2],
                "risk_level": row[3],
                "archetype": row[4],
                "category_scores": json.loads(row[5]) if row[5] else {},
                "flags": json.loads(row[6]) if row[6] else [],
                "confidence": row[7],
            }))
        return results

    # --- Outcome Events ---

    async def record_outcome(
        self,
        address: str,
        chain_id: int = 56,
        risk_score_at_scan: float = None,
        user_decision: str = None,
        outcome: str = None,
        tx_hash: str = None,
        source: str = "client",
    ):
        """Record a user decision or outcome event.

        source is 'key:<key_id>' when a valid API key sent it, otherwise 'client'.
        """
        now = time.time()
        await self._db.execute("""
            INSERT INTO outcome_events
                (address, chain_id, risk_score_at_scan, user_decision, outcome, tx_hash, source, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (address.lower(), chain_id, risk_score_at_scan, user_decision, outcome, tx_hash, source, now))
        await self._db.commit()

    # --- Community Reports ---

    async def record_community_report(
        self,
        address: str,
        chain_id: int = 56,
        report_type: str = "false_positive",
        reporter_id: str = None,
        reason: str = None,
        risk_score_at_report: float = None,
    ):
        """Record a community report (false positive/negative)."""
        now = time.time()
        await self._db.execute("""
            INSERT INTO community_reports
                (address, chain_id, report_type, reporter_id, reason, risk_score_at_report, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (address.lower(), chain_id, report_type, reporter_id, reason, risk_score_at_report, now))
        await self._db.commit()

    async def get_reports(self, address: str, chain_id: int = 56, limit: int = 50) -> List[Dict]:
        """Get community reports for an address."""
        cursor = await self._db.execute("""
            SELECT report_type, reporter_id, reason, risk_score_at_report, created_at
            FROM community_reports
            WHERE address = ? AND chain_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        """, (address.lower(), chain_id, limit))
        rows = await cursor.fetchall()
        return [
            {
                'report_type': r[0],
                'reporter_id': r[1],
                'reason': r[2],
                'risk_score_at_report': r[3],
                'created_at': r[4],
            }
            for r in rows
        ]

    async def get_all_reports(self, limit: int = 200) -> List[Dict]:
        """Get all community reports."""
        cursor = await self._db.execute("""
            SELECT address, chain_id, report_type, reporter_id, reason, risk_score_at_report, created_at
            FROM community_reports
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        return [
            {
                'address': r[0],
                'chain_id': r[1],
                'report_type': r[2],
                'reporter_id': r[3],
                'reason': r[4],
                'risk_score_at_report': r[5],
                'created_at': r[6],
            }
            for r in rows
        ]

    # --- Outcome Events ---

    async def get_campaign_graph(self, address: str, chain_id: int = None) -> Dict:
        """Get deployer/funder links for an address (as contract or as deployer)."""
        addr = address.lower()

        # Find contracts deployed by this address
        if chain_id:
            cursor = await self._db.execute(
                "SELECT contract_address, deploy_tx_hash FROM deployers WHERE deployer_address = ? AND chain_id = ?",
                (addr, chain_id),
            )
        else:
            cursor = await self._db.execute(
                "SELECT contract_address, deploy_tx_hash FROM deployers WHERE deployer_address = ?",
                (addr,),
            )
        deployed_contracts = [
            {'contract': r[0], 'tx_hash': r[1]} for r in await cursor.fetchall()
        ]

        # Find deployer of this address (if it's a contract)
        if chain_id:
            cursor = await self._db.execute(
                "SELECT deployer_address, deploy_tx_hash FROM deployers WHERE contract_address = ? AND chain_id = ?",
                (addr, chain_id),
            )
        else:
            cursor = await self._db.execute(
                "SELECT deployer_address, deploy_tx_hash FROM deployers WHERE contract_address = ?",
                (addr,),
            )
        deployer_row = await cursor.fetchone()
        deployer = deployer_row[0] if deployer_row else None

        # Find funder of the deployer
        funder = None
        funder_value = 0
        lookup_deployer = deployer or addr
        if chain_id:
            cursor = await self._db.execute(
                "SELECT funder_address, funding_value_wei FROM funder_links WHERE deployer_address = ? AND chain_id = ?",
                (lookup_deployer, chain_id),
            )
        else:
            cursor = await self._db.execute(
                "SELECT funder_address, funding_value_wei FROM funder_links WHERE deployer_address = ?",
                (lookup_deployer,),
            )
        funder_row = await cursor.fetchone()
        if funder_row:
            funder = funder_row[0]
            funder_value = funder_row[1]

        return {
            'address': addr,
            'deployer': deployer,
            'funder': funder,
            'funder_value_wei': str(funder_value),
            'contracts_deployed': deployed_contracts,
            'total_deployed': len(deployed_contracts),
        }

    # --- Beta Signups ---

    async def add_beta_signup(self, email: str) -> bool:
        """Add a beta signup email. Returns True if new, False if duplicate."""
        try:
            await self._db.execute(
                "INSERT INTO beta_signups (email) VALUES (?)",
                (email.lower().strip(),),
            )
            await self._db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False

    async def get_beta_signups(self) -> List[Dict]:
        """Return all beta signup entries."""
        cursor = await self._db.execute(
            "SELECT id, email, signed_up_at FROM beta_signups ORDER BY id DESC"
        )
        rows = await cursor.fetchall()
        return [
            {"id": r[0], "email": r[1], "signed_up_at": r[2]}
            for r in rows
        ]

    async def get_platform_stats(self) -> Dict:
        """Aggregate platform metrics for reporting and grant applications."""
        now = time.time()
        windows = {
            "last_24h": now - 86400,
            "last_7d":  now - 7 * 86400,
            "last_30d": now - 30 * 86400,
        }

        # --- All-time aggregates ---
        cur = await self._db.execute(
            "SELECT COUNT(*), COALESCE(SUM(scan_count), 0) FROM contract_scores"
        )
        row = await cur.fetchone()
        unique_contracts = row[0] or 0
        total_scan_events = int(row[1] or 0)

        # The threat feed (api.py) lists the same rows. The interpolated value is the code constant
        # verdicts.THREAT_CONDITION, never user input.
        cur = await self._db.execute(
            f"SELECT COUNT(*) FROM contract_scores WHERE {THREAT_CONDITION}"  # nosec B608
        )
        threats_detected = (await cur.fetchone())[0] or 0

        cur = await self._db.execute(
            "SELECT COUNT(*) FROM outcome_events WHERE user_decision = 'block'"
        )
        total_blocks = (await cur.fetchone())[0] or 0

        cur = await self._db.execute(
            "SELECT COUNT(*) FROM outcome_events WHERE user_decision = 'proceed'"
        )
        total_proceeds = (await cur.fetchone())[0] or 0

        cur = await self._db.execute(
            "SELECT COUNT(*) FROM deployers"
        )
        deployers_indexed = (await cur.fetchone())[0] or 0

        cur = await self._db.execute(
            "SELECT COUNT(*) FROM community_reports"
        )
        community_reports = (await cur.fetchone())[0] or 0

        cur = await self._db.execute(
            "SELECT COUNT(*) FROM beta_signups"
        )
        beta_signups = (await cur.fetchone())[0] or 0

        # Risk level breakdown
        cur = await self._db.execute(
            "SELECT risk_level, COUNT(*) FROM contract_scores GROUP BY risk_level"
        )
        by_risk_level = {row[0]: row[1] for row in await cur.fetchall()}

        # By chain
        cur = await self._db.execute(
            "SELECT chain_id, COUNT(*), COALESCE(SUM(scan_count), 0) FROM contract_scores GROUP BY chain_id"
        )
        by_chain = {
            str(row[0]): {"contracts": row[1], "scans": int(row[2])}
            for row in await cur.fetchall()
        }

        # --- Time-windowed aggregates ---
        windowed = {}
        for label, cutoff in windows.items():
            cur = await self._db.execute(
                "SELECT COUNT(*) FROM contract_scores WHERE last_scanned_at > ?", (cutoff,)
            )
            scans = (await cur.fetchone())[0] or 0

            # The interpolated value is the code constant verdicts.THREAT_CONDITION, never user input.
            cur = await self._db.execute(
                f"SELECT COUNT(*) FROM contract_scores WHERE last_scanned_at > ? AND {THREAT_CONDITION}",  # nosec B608
                (cutoff,)
            )
            threats = (await cur.fetchone())[0] or 0

            cur = await self._db.execute(
                "SELECT COUNT(*) FROM outcome_events WHERE created_at > ? AND user_decision = 'block'",
                (cutoff,)
            )
            blocks = (await cur.fetchone())[0] or 0

            windowed[label] = {
                "scans": scans,
                "threats_detected": threats,
                "transactions_blocked": blocks,
            }

        return {
            "all_time": {
                "unique_contracts_scanned": unique_contracts,
                "total_scan_events": total_scan_events,
                "threats_detected": threats_detected,
                "transactions_blocked": total_blocks,
                "transactions_proceeded_past_warning": total_proceeds,
                "deployers_indexed": deployers_indexed,
                "community_reports": community_reports,
                "beta_signups": beta_signups,
                "by_risk_level": by_risk_level,
                "by_chain": by_chain,
            },
            **windowed,
        }

    async def get_outcomes(self, address: str, chain_id: int = 56, limit: int = 50) -> List[Dict]:
        """Get outcome events for an address."""
        cursor = await self._db.execute("""
            SELECT risk_score_at_scan, user_decision, outcome, tx_hash, source, created_at
            FROM outcome_events
            WHERE address = ? AND chain_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        """, (address.lower(), chain_id, limit))
        rows = await cursor.fetchall()
        return [
            {
                'risk_score_at_scan': r[0],
                'user_decision': r[1],
                'outcome': r[2],
                'tx_hash': r[3],
                'source': r[4],
                'created_at': r[5],
            }
            for r in rows
        ]

    # --- Deployer Risk Summary ---

    async def get_deployer_risk_summary(self, contract_address: str, chain_id: int) -> Optional[Dict]:
        """Look up who deployed contract_address, then count their HIGH-risk contracts.

        Returns dict with deployer_address, total_contracts, high_risk_contracts or None
        if the contract's deployer is not yet indexed.
        """
        cursor = await self._db.execute(
            "SELECT deployer_address FROM deployers WHERE contract_address = ? AND chain_id = ?",
            (contract_address.lower(), chain_id),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        deployer = row[0]

        # The interpolated value is the code constant verdicts.HIGH, never user input.
        cursor = await self._db.execute(f"""
            SELECT
                COUNT(DISTINCT d.contract_address),
                COALESCE(SUM(CASE WHEN cs.risk_level = '{HIGH}' THEN 1 ELSE 0 END), 0)
            FROM deployers d
            LEFT JOIN contract_scores cs
                ON cs.address = d.contract_address AND cs.chain_id = d.chain_id
            WHERE d.deployer_address = ?
        """, (deployer,))  # nosec B608
        stats = await cursor.fetchone()
        return {
            "deployer_address": deployer,
            "total_contracts": stats[0] or 0,
            "high_risk_contracts": int(stats[1] or 0),
        }

    # --- Watched Deployers ---

    async def add_watched_deployer(
        self,
        address: str,
        chain_id: int = 0,
        reason: str = "MANUAL",
        severity: str = "HIGH",
        contract_count: int = 0,
        high_risk_count: int = 0,
    ):
        """Add or update a deployer in the watch list."""
        now = time.time()
        await self._db.execute("""
            INSERT INTO watched_deployers
                (deployer_address, chain_id, watch_reason, risk_severity,
                 contract_count, high_risk_count, alert_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(deployer_address, chain_id) DO UPDATE SET
                watch_reason = excluded.watch_reason,
                risk_severity = excluded.risk_severity,
                contract_count = excluded.contract_count,
                high_risk_count = excluded.high_risk_count
        """, (address.lower(), chain_id, reason, severity, contract_count, high_risk_count, now))
        await self._db.commit()

    async def remove_watched_deployer(self, address: str, chain_id: int = 0):
        """Remove a deployer from the watch list."""
        await self._db.execute(
            "DELETE FROM watched_deployers WHERE deployer_address = ? AND chain_id = ?",
            (address.lower(), chain_id),
        )
        await self._db.commit()

    async def get_watched_deployers(self) -> List[Dict]:
        """Return all watched deployers."""
        cursor = await self._db.execute("""
            SELECT deployer_address, chain_id, watch_reason, risk_severity,
                   contract_count, high_risk_count, alert_count, last_alert_at, created_at
            FROM watched_deployers
            ORDER BY created_at DESC
        """)
        rows = await cursor.fetchall()
        return [
            {
                "deployer_address": r[0],
                "chain_id": r[1],
                "watch_reason": r[2],
                "risk_severity": r[3],
                "contract_count": r[4],
                "high_risk_count": r[5],
                "alert_count": r[6],
                "last_alert_at": r[7],
                "created_at": r[8],
            }
            for r in rows
        ]

    async def is_watched_deployer(self, address: str, chain_id: int = 0) -> Optional[Dict]:
        """Return the watch record for a deployer, or None if not watched.

        Checks both the exact chain_id and chain_id=0 (all-chains wildcard).
        """
        cursor = await self._db.execute("""
            SELECT deployer_address, chain_id, watch_reason, risk_severity,
                   contract_count, high_risk_count, alert_count, last_alert_at, created_at
            FROM watched_deployers
            WHERE deployer_address = ? AND (chain_id = ? OR chain_id = 0)
            ORDER BY chain_id DESC
            LIMIT 1
        """, (address.lower(), chain_id))
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "deployer_address": row[0],
            "chain_id": row[1],
            "watch_reason": row[2],
            "risk_severity": row[3],
            "contract_count": row[4],
            "high_risk_count": row[5],
            "alert_count": row[6],
            "last_alert_at": row[7],
            "created_at": row[8],
        }

    # --- Deployment Alerts ---

    async def log_deployment_alert(
        self,
        deployer: str,
        chain_id: int,
        contract_address: str,
        reason: str = None,
        telegram_sent: int = 0,
    ) -> int:
        """Log an alert for a watched deployer deploying a new contract. Returns the new row id."""
        now = time.time()
        async with self.transaction() as connection:
            cursor = await connection.execute("""
                INSERT INTO deployment_alerts
                    (deployer_address, chain_id, new_contract_address, watch_reason, telegram_sent, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (deployer.lower(), chain_id, contract_address.lower(), reason, telegram_sent, now))
            await connection.execute("""
                UPDATE watched_deployers
                SET alert_count = alert_count + 1, last_alert_at = ?
                WHERE deployer_address = ? AND (chain_id = ? OR chain_id = 0)
            """, (now, deployer.lower(), chain_id))
        return cursor.lastrowid

    async def get_deployment_alerts(self, limit: int = 50) -> List[Dict]:
        """Return recent deployment alerts, newest first."""
        cursor = await self._db.execute("""
            SELECT id, deployer_address, chain_id, new_contract_address,
                   watch_reason, telegram_sent, created_at
            FROM deployment_alerts
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        return [
            {
                "id": r[0],
                "deployer_address": r[1],
                "chain_id": r[2],
                "new_contract_address": r[3],
                "watch_reason": r[4],
                "telegram_sent": bool(r[5]),
                "created_at": r[6],
            }
            for r in rows
        ]

    # --- Agent Findings ---

    async def insert_agent_finding(
        self,
        finding_type: str,
        address: str = None,
        deployer: str = None,
        chain_id: int = 56,
        risk_score: int = None,
        narrative: str = None,
        evidence=None,
        action_taken: str = None,
        investigation_id: str = None,
    ):
        """Insert a threat finding discovered by the AI agent."""
        now = time.time()
        evidence_json = json.dumps(evidence) if isinstance(evidence, (dict, list)) else evidence
        await self._db.execute("""
            INSERT INTO agent_findings
                (finding_type, investigation_id, address, deployer, chain_id,
                 risk_score, narrative, evidence, action_taken, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (finding_type, investigation_id, address, deployer, chain_id,
              risk_score, narrative, evidence_json, action_taken, now))
        await self._db.commit()

    async def get_agent_findings(
        self, limit: int = 50, finding_type: str = None
    ) -> List[Dict]:
        """Get agent findings, optionally filtered by type, newest first."""
        if finding_type:
            cursor = await self._db.execute("""
                SELECT id, finding_type, investigation_id, address, deployer,
                       chain_id, risk_score, narrative, evidence, action_taken, created_at
                FROM agent_findings
                WHERE finding_type = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
            """, (finding_type, limit))
        else:
            cursor = await self._db.execute("""
                SELECT id, finding_type, investigation_id, address, deployer,
                       chain_id, risk_score, narrative, evidence, action_taken, created_at
                FROM agent_findings
                ORDER BY created_at DESC, id DESC
                LIMIT ?
            """, (limit,))
        rows = await cursor.fetchall()
        results = []
        for r in rows:
            evidence_val = r[8]
            if evidence_val:
                try:
                    evidence_val = json.loads(evidence_val)
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append({
                "id": r[0],
                "finding_type": r[1],
                "investigation_id": r[2],
                "address": r[3],
                "deployer": r[4],
                "chain_id": r[5],
                "risk_score": r[6],
                "narrative": r[7],
                "evidence": evidence_val,
                "action_taken": r[9],
                "created_at": r[10],
            })
        return results

    # --- Chat History ---

    async def insert_chat_message(
        self,
        user_id: str,
        role: str,
        message: str,
        tools_used=None,
        max_per_user: int = 50,
    ):
        """Insert a chat message for a user, capping at max_per_user messages."""
        now = time.time()
        tools_json = json.dumps(tools_used) if isinstance(tools_used, (list, dict)) else tools_used
        await self._db.execute("""
            INSERT INTO chat_history (user_id, role, message, tools_used, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, role, message, tools_json, now))
        # Evict oldest messages beyond the per-user cap
        await self._db.execute("""
            DELETE FROM chat_history WHERE id IN (
                SELECT id FROM chat_history
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT -1 OFFSET ?
            )
        """, (user_id, max_per_user))
        await self._db.commit()

    async def get_chat_history(self, user_id: str, limit: int = 10) -> List[Dict]:
        """Get the last N messages for a user, ordered oldest-first (for LLM context)."""
        cursor = await self._db.execute("""
            SELECT id, role, message, tools_used, created_at
            FROM chat_history
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        """, (user_id, limit))
        rows = await cursor.fetchall()
        # Reverse so oldest is first (LLM context order)
        rows = list(reversed(rows))
        results = []
        for r in rows:
            tools_val = r[3]
            if tools_val:
                try:
                    tools_val = json.loads(tools_val)
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append({
                "id": r[0],
                "user_id": user_id,
                "role": r[1],
                "message": r[2],
                "tools_used": tools_val,
                "created_at": r[4],
            })
        return results

    async def prune_old_chats(self, max_age_seconds: int = 86400) -> int:
        """Delete chat messages older than max_age_seconds. Returns count deleted."""
        cutoff = time.time() - max_age_seconds
        cursor = await self._db.execute(
            "DELETE FROM chat_history WHERE created_at < ?", (cutoff,)
        )
        await self._db.commit()
        return cursor.rowcount

    async def prune_retention(self) -> Dict[str, int]:
        """Delete usage records older than USAGE_RETENTION_DAYS, scan evidence documents older than
        SCAN_EVIDENCE_RETENTION_DAYS and expired free key link requests.

        Returns the rows deleted per table.
        """
        now = time.time()
        oldest_day = int(now // 86400) - USAGE_RETENTION_DAYS
        deleted = {}
        for table, sql, cutoff in (
            ("api_usage", "DELETE FROM api_usage WHERE created_at < ?", now - USAGE_RETENTION_DAYS * 86400),
            ("api_daily_usage", "DELETE FROM api_daily_usage WHERE utc_day < ?", oldest_day),
            ("ai_token_usage", "DELETE FROM ai_token_usage WHERE utc_day < ?", oldest_day),
            ("free_key_requests", "DELETE FROM free_key_requests WHERE expires_at <= ?", now),
            (
                "scan_evidence", "DELETE FROM scan_evidence WHERE created_at < ?",
                now - SCAN_EVIDENCE_RETENTION_DAYS * 86400,
            ),
        ):
            cursor = await self._db.execute(sql, (cutoff,))
            deleted[table] = cursor.rowcount
        await self._db.commit()
        return deleted

    # --- AI Token Usage ---

    async def _create_ai_usage_tables(self):
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS ai_token_usage (
                utc_day INTEGER PRIMARY KEY,
                tokens INTEGER NOT NULL
            );
        """)
        await self._db.commit()

    async def get_ai_tokens_used(self, utc_day: int) -> int:
        """Tokens the advisor's AI calls used on a UTC day number."""
        cursor = await self._db.execute(
            "SELECT tokens FROM ai_token_usage WHERE utc_day = ?", (utc_day,)
        )
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def add_ai_tokens_used(self, utc_day: int, tokens: int):
        """Add tokens to a UTC day's count and commit."""
        await self._db.execute("""
            INSERT INTO ai_token_usage (utc_day, tokens) VALUES (?, ?)
            ON CONFLICT(utc_day) DO UPDATE SET tokens = tokens + excluded.tokens
        """, (utc_day, tokens))
        await self._db.commit()

    # --- Scam Blacklist ---

    async def _create_scam_blacklist_table(self):
        """The local scam blacklist. chain_id NULL covers every chain, expires_at NULL never expires.
        source is 'community' (users reported the address) or 'admin' (an admin confirmed it); one
        entry per address and chain."""
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS scam_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id INTEGER,
                address TEXT NOT NULL,
                source TEXT NOT NULL CHECK (source IN ('community', 'admin')),
                reason TEXT,
                reports INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                expires_at REAL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_scam_blacklist_entry
                ON scam_blacklist(address, COALESCE(chain_id, 0));
        """)
        await self._db.commit()

    async def add_community_blacklist(
        self, address: str, chain_id: Optional[int], reports: int, expires_at: float,
    ):
        """Add or renew a community entry. An admin entry for the same address and chain is left as it is."""
        await self._db.execute("""
            INSERT INTO scam_blacklist (chain_id, address, source, reports, created_at, expires_at)
            VALUES (?, ?, 'community', ?, ?, ?)
            ON CONFLICT (address, COALESCE(chain_id, 0)) DO UPDATE SET
                reports = excluded.reports,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at
            WHERE scam_blacklist.source = 'community'
        """, (chain_id, address.lower(), reports, time.time(), expires_at))
        await self._db.commit()

    async def confirm_blacklist(self, address: str, chain_id: Optional[int], reason: Optional[str]):
        """Make an address an admin entry that never expires, confirming a community entry in place
        (its report count is kept)."""
        await self._db.execute("""
            INSERT INTO scam_blacklist (chain_id, address, source, reason, created_at, expires_at)
            VALUES (?, ?, 'admin', ?, ?, NULL)
            ON CONFLICT (address, COALESCE(chain_id, 0)) DO UPDATE SET
                source = 'admin',
                reason = COALESCE(excluded.reason, scam_blacklist.reason),
                expires_at = NULL
        """, (chain_id, address.lower(), reason, time.time()))
        await self._db.commit()

    async def remove_blacklist(self, address: str, chain_id: Optional[int]) -> bool:
        """Delete the entry for an address on a chain (NULL: the every-chain entry). True if one was deleted."""
        cursor = await self._db.execute(
            "DELETE FROM scam_blacklist WHERE address = ? AND COALESCE(chain_id, 0) = COALESCE(?, 0)",
            (address.lower(), chain_id),
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def get_active_blacklist(self, now: float) -> List[Dict]:
        """Every blacklist entry that has not expired at `now`."""
        cursor = await self._db.execute("""
            SELECT chain_id, address, source, reason, reports, created_at, expires_at
            FROM scam_blacklist
            WHERE expires_at IS NULL OR expires_at > ?
        """, (now,))
        return [
            {
                'chain_id': r[0], 'address': r[1], 'source': r[2], 'reason': r[3],
                'reports': r[4], 'created_at': r[5], 'expires_at': r[6],
            }
            for r in await cursor.fetchall()
        ]

    async def prune_scam_blacklist(self, now: float) -> int:
        """Delete the entries that have expired at `now`. Returns how many were deleted."""
        cursor = await self._db.execute(
            "DELETE FROM scam_blacklist WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,)
        )
        await self._db.commit()
        return cursor.rowcount

    # --- Self-Serve Free Keys ---

    async def _create_free_key_tables(self):
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS free_key_requests (
                token_hash TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                used_at REAL
            );

            CREATE INDEX IF NOT EXISTS idx_free_key_requests_email
                ON free_key_requests(email);
        """)
        await self._db.commit()

    async def add_free_key_request(self, email: str, token_hash: str, expires_at: float) -> bool:
        """Store an emailed link's token hash unless the address already has an unused, unexpired one.

        Expired requests are deleted first. Returns whether the request was stored.
        """
        now = time.time()
        await self._db.execute("DELETE FROM free_key_requests WHERE expires_at <= ?", (now,))
        cursor = await self._db.execute("""
            INSERT INTO free_key_requests (token_hash, email, created_at, expires_at)
            SELECT ?, ?, ?, ? WHERE NOT EXISTS (
                SELECT 1 FROM free_key_requests WHERE email = ? AND used_at IS NULL
            )
        """, (token_hash, email, now, expires_at, email))
        await self._db.commit()
        return cursor.rowcount == 1

    async def delete_free_key_request(self, token_hash: str):
        await self._db.execute("DELETE FROM free_key_requests WHERE token_hash = ?", (token_hash,))
        await self._db.commit()

    async def claim_free_key_request(self, token_hash: str) -> Optional[str]:
        """Mark an unused, unexpired request used and return its email; None if there is none."""
        cursor = await self._db.execute(
            "SELECT email FROM free_key_requests WHERE token_hash = ?", (token_hash,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        now = time.time()
        cursor = await self._db.execute("""
            UPDATE free_key_requests SET used_at = ?
            WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
        """, (now, token_hash, now))
        await self._db.commit()
        return row[0] if cursor.rowcount == 1 else None

    # --- Tracked Pairs ---

    async def upsert_tracked_pair(
        self,
        pair_address: str,
        token_address: str = None,
        deployer: str = None,
        liquidity_usd: float = None,
        status: str = "watching",
        chain_id: int = 56,
    ):
        """Insert or update a tracked pair."""
        now = time.time()
        await self._db.execute("""
            INSERT INTO tracked_pairs
                (pair_address, token_address, deployer, liquidity_usd, first_seen, last_checked, status, chain_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(pair_address) DO UPDATE SET
                token_address = COALESCE(excluded.token_address, tracked_pairs.token_address),
                deployer = COALESCE(excluded.deployer, tracked_pairs.deployer),
                liquidity_usd = COALESCE(excluded.liquidity_usd, tracked_pairs.liquidity_usd),
                last_checked = excluded.last_checked,
                status = excluded.status,
                chain_id = excluded.chain_id
        """, (pair_address, token_address, deployer, liquidity_usd, now, now, status, chain_id))
        await self._db.commit()

    async def get_tracked_pairs(
        self, status: str = None, limit: int = 100
    ) -> List[Dict]:
        """Get tracked pairs, optionally filtered by status."""
        if status:
            cursor = await self._db.execute("""
                SELECT id, pair_address, token_address, deployer, liquidity_usd,
                       first_seen, last_checked, status, chain_id
                FROM tracked_pairs
                WHERE status = ?
                ORDER BY first_seen DESC
                LIMIT ?
            """, (status, limit))
        else:
            cursor = await self._db.execute("""
                SELECT id, pair_address, token_address, deployer, liquidity_usd,
                       first_seen, last_checked, status, chain_id
                FROM tracked_pairs
                ORDER BY first_seen DESC
                LIMIT ?
            """, (limit,))
        rows = await cursor.fetchall()
        return [
            {
                "id": r[0],
                "pair_address": r[1],
                "token_address": r[2],
                "deployer": r[3],
                "liquidity_usd": r[4],
                "first_seen": r[5],
                "last_checked": r[6],
                "status": r[7],
                "chain_id": r[8],
            }
            for r in rows
        ]

    async def get_recheck_chains(self, status: str) -> List[int]:
        """Return the chains that have tracked pairs in this status."""
        cursor = await self._db.execute(
            "SELECT DISTINCT chain_id FROM tracked_pairs WHERE status = ? ORDER BY chain_id",
            (status,),
        )
        return [row[0] for row in await cursor.fetchall()]

    async def get_recheck_pairs(
        self, status: str, chain_id: int, limit: int, checked_before: float
    ) -> List[Dict]:
        """Get one chain's pairs that are due a recheck, least recently checked first.

        A pair that has never been checked sorts first.
        """
        cursor = await self._db.execute("""
            SELECT id, pair_address, token_address, deployer, liquidity_usd,
                   first_seen, last_checked, status, chain_id
            FROM tracked_pairs
            WHERE status = ? AND chain_id = ? AND COALESCE(last_checked, 0) <= ?
            ORDER BY COALESCE(last_checked, 0), id
            LIMIT ?
        """, (status, chain_id, checked_before, limit))
        rows = await cursor.fetchall()
        return [
            {
                "id": r[0],
                "pair_address": r[1],
                "token_address": r[2],
                "deployer": r[3],
                "liquidity_usd": r[4],
                "first_seen": r[5],
                "last_checked": r[6],
                "status": r[7],
                "chain_id": r[8],
            }
            for r in rows
        ]

    async def mark_tracked_pair_checked(self, pair_address: str):
        """Record a recheck attempt without changing the pair's status."""
        await self._db.execute(
            "UPDATE tracked_pairs SET last_checked = ? WHERE pair_address = ?",
            (time.time(), pair_address),
        )
        await self._db.commit()

    async def update_tracked_pair_status(self, pair_address: str, status: str):
        """Update a tracked pair's status and last_checked timestamp."""
        now = time.time()
        await self._db.execute("""
            UPDATE tracked_pairs
            SET status = ?, last_checked = ?
            WHERE pair_address = ?
        """, (status, now, pair_address))
        await self._db.commit()

    # --- Agent Policies ---

    async def upsert_agent_policy(
        self,
        agent_id: str,
        owner_address: str,
        owner_telegram: str = None,
        owner_webhook: str = None,
        tier: str = "free",
        policy: dict = None,
        registered_by_key: str = None,
    ):
        """Insert or update an agent's firewall policy."""
        now = time.time()
        policy_json = json.dumps(policy or {})
        await self._db.execute("""
            INSERT INTO agent_policies
                (agent_id, owner_address, owner_telegram, owner_webhook,
                 tier, policy, registered_by_key, daily_spend_used_usd,
                 daily_spend_reset_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                owner_address = excluded.owner_address,
                owner_telegram = COALESCE(excluded.owner_telegram, agent_policies.owner_telegram),
                owner_webhook = COALESCE(excluded.owner_webhook, agent_policies.owner_webhook),
                tier = excluded.tier,
                policy = excluded.policy,
                registered_by_key = COALESCE(agent_policies.registered_by_key, excluded.registered_by_key),
                updated_at = excluded.updated_at
        """, (agent_id, owner_address.lower(), owner_telegram, owner_webhook,
              tier, policy_json, registered_by_key, now, now, now))
        await self._db.commit()

    async def get_agent_policy(self, agent_id: str) -> Optional[Dict]:
        """Get an agent's policy. Returns None if not registered."""
        cursor = await self._db.execute("""
            SELECT agent_id, owner_address, owner_telegram, owner_webhook,
                   tier, policy, registered_by_key, daily_spend_used_usd,
                   daily_spend_reset_at, created_at, updated_at
            FROM agent_policies WHERE agent_id = ?
        """, (agent_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        try:
            policy = json.loads(row[5]) if row[5] else {}
        except (json.JSONDecodeError, TypeError):
            policy = {}
        return {
            "agent_id": row[0],
            "owner_address": row[1],
            "owner_telegram": row[2],
            "owner_webhook": row[3],
            "tier": row[4],
            "policy": policy,
            "registered_by_key": row[6],
            "daily_spend_used_usd": row[7] or 0,
            "daily_spend_reset_at": row[8],
            "created_at": row[9],
            "updated_at": row[10],
        }

    async def record_agent_spend(self, agent_id: str, amount_usd: float):
        """Increment an agent's daily spend atomically. Resets if a new day."""
        now = time.time()
        await self._db.execute("""
            UPDATE agent_policies SET
                daily_spend_used_usd = CASE
                    WHEN daily_spend_reset_at IS NOT NULL
                         AND (? - daily_spend_reset_at) >= 86400
                    THEN ?
                    ELSE daily_spend_used_usd + ?
                END,
                daily_spend_reset_at = CASE
                    WHEN daily_spend_reset_at IS NULL
                         OR (? - daily_spend_reset_at) >= 86400
                    THEN ?
                    ELSE daily_spend_reset_at
                END
            WHERE agent_id = ?
        """, (now, amount_usd, amount_usd, now, now, agent_id))
        await self._db.commit()

    async def get_agent_daily_spend(self, agent_id: str) -> float:
        """Get current daily spend for an agent."""
        cursor = await self._db.execute(
            "SELECT daily_spend_used_usd, daily_spend_reset_at FROM agent_policies WHERE agent_id = ?",
            (agent_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return 0.0
        # Check if reset needed
        if row[1] and (time.time() - row[1]) >= 86400:
            return 0.0
        return row[0] or 0.0

    # --- Agent Firewall History ---

    async def record_agent_firewall_event(
        self,
        agent_id: str,
        chain_id: int,
        tx_to: str = None,
        tx_value: str = None,
        verdict: str = "ALLOW",
        score: float = None,
        flags: list = None,
        evidence: str = None,
        policy_result: dict = None,
        latency_ms: float = None,
    ):
        """Record an agent firewall check result."""
        now = time.time()
        flags_json = json.dumps(flags) if flags else None
        policy_json = json.dumps(policy_result) if policy_result else None
        await self._db.execute("""
            INSERT INTO agent_firewall_history
                (agent_id, chain_id, tx_to, tx_value, verdict, score,
                 flags, evidence, policy_result, latency_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (agent_id, chain_id, tx_to, tx_value, verdict, score,
              flags_json, evidence, policy_json, latency_ms, now))
        await self._db.commit()

    async def get_agent_firewall_history(
        self, agent_id: str, limit: int = 50
    ) -> List[Dict]:
        """Get firewall history for an agent, newest first."""
        cursor = await self._db.execute("""
            SELECT id, chain_id, tx_to, tx_value, verdict, score,
                   flags, evidence, policy_result, latency_ms, created_at
            FROM agent_firewall_history
            WHERE agent_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        """, (agent_id, limit))
        rows = await cursor.fetchall()
        results = []
        for r in rows:
            try:
                flags_val = json.loads(r[6]) if r[6] else []
            except (json.JSONDecodeError, TypeError):
                flags_val = []
            try:
                policy_val = json.loads(r[8]) if r[8] else None
            except (json.JSONDecodeError, TypeError):
                policy_val = None
            results.append({
                "id": r[0], "chain_id": r[1], "tx_to": r[2],
                "tx_value": r[3], "verdict": r[4], "score": r[5],
                "flags": flags_val, "evidence": r[7],
                "policy_result": policy_val, "latency_ms": r[9],
                "created_at": r[10],
            })
        return results

    # --- Threat Graph ---

    async def add_threat_graph_edge(
        self,
        source: str,
        target: str,
        chain_id: int,
        relationship: str,
        evidence: Dict = None,
        confidence: float = 0.5,
    ):
        """Insert or update a threat graph edge."""
        now = time.time()
        evidence_json = json.dumps(evidence) if evidence else None
        await self._db.execute("""
            INSERT INTO threat_graph_edges
                (source_address, target_address, chain_id, relationship,
                 evidence, confidence, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_address, target_address, chain_id, relationship) DO UPDATE SET
                evidence = COALESCE(excluded.evidence, threat_graph_edges.evidence),
                confidence = MAX(threat_graph_edges.confidence, excluded.confidence),
                last_seen = excluded.last_seen
        """, (source.lower(), target.lower(), chain_id, relationship,
              evidence_json, confidence, now, now))
        await self._db.commit()

    async def get_edges_from(self, address: str, chain_id: int) -> List[Dict]:
        """Get all outgoing edges from an address."""
        cursor = await self._db.execute("""
            SELECT source_address, target_address, chain_id, relationship,
                   evidence, confidence, first_seen, last_seen
            FROM threat_graph_edges
            WHERE source_address = ? AND chain_id = ?
        """, (address.lower(), chain_id))
        rows = await cursor.fetchall()
        results = []
        for r in rows:
            ev = r[4]
            if ev:
                try:
                    ev = json.loads(ev)
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append({
                "source_address": r[0],
                "target_address": r[1],
                "chain_id": r[2],
                "relationship": r[3],
                "evidence": ev,
                "confidence": r[5],
                "first_seen": r[6],
                "last_seen": r[7],
            })
        return results

    async def get_edges_to(self, address: str, chain_id: int) -> List[Dict]:
        """Get all incoming edges to an address."""
        cursor = await self._db.execute("""
            SELECT source_address, target_address, chain_id, relationship,
                   evidence, confidence, first_seen, last_seen
            FROM threat_graph_edges
            WHERE target_address = ? AND chain_id = ?
        """, (address.lower(), chain_id))
        rows = await cursor.fetchall()
        results = []
        for r in rows:
            ev = r[4]
            if ev:
                try:
                    ev = json.loads(ev)
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append({
                "source_address": r[0],
                "target_address": r[1],
                "chain_id": r[2],
                "relationship": r[3],
                "evidence": ev,
                "confidence": r[5],
                "first_seen": r[6],
                "last_seen": r[7],
            })
        return results

    async def get_cluster_for_address(
        self, address: str, chain_id: int
    ) -> Optional[Dict]:
        """Get cluster membership for an address, or None."""
        cursor = await self._db.execute("""
            SELECT cluster_id, address, chain_id, role, confidence, updated_at
            FROM threat_graph_clusters
            WHERE address = ? AND chain_id = ?
            LIMIT 1
        """, (address.lower(), chain_id))
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "cluster_id": row[0],
            "address": row[1],
            "chain_id": row[2],
            "role": row[3],
            "confidence": row[4],
            "updated_at": row[5],
        }

    async def get_cluster_members(self, cluster_id: str) -> List[Dict]:
        """Get all members of a cluster."""
        cursor = await self._db.execute("""
            SELECT cluster_id, address, chain_id, role, confidence, updated_at
            FROM threat_graph_clusters
            WHERE cluster_id = ?
        """, (cluster_id,))
        rows = await cursor.fetchall()
        return [
            {
                "cluster_id": r[0],
                "address": r[1],
                "chain_id": r[2],
                "role": r[3],
                "confidence": r[4],
                "updated_at": r[5],
            }
            for r in rows
        ]

    async def upsert_cluster_member(
        self,
        cluster_id: str,
        address: str,
        chain_id: int,
        role: str = "member",
        confidence: float = 0.5,
    ):
        """Insert or update a cluster member."""
        now = time.time()
        await self._db.execute("""
            INSERT INTO threat_graph_clusters
                (cluster_id, address, chain_id, role, confidence, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(cluster_id, address, chain_id) DO UPDATE SET
                role = excluded.role,
                confidence = excluded.confidence,
                updated_at = excluded.updated_at
        """, (cluster_id, address.lower(), chain_id, role, confidence, now))
        await self._db.commit()

    async def get_graph_stats(self) -> Dict:
        """Get aggregate threat graph statistics."""
        cur = await self._db.execute(
            "SELECT COUNT(*) FROM threat_graph_edges"
        )
        total_edges = (await cur.fetchone())[0] or 0

        cur = await self._db.execute(
            "SELECT COUNT(DISTINCT cluster_id) FROM threat_graph_clusters"
        )
        total_clusters = (await cur.fetchone())[0] or 0

        cur = await self._db.execute("""
            SELECT COUNT(*) FROM (
                SELECT source_address AS addr FROM threat_graph_edges
                UNION
                SELECT target_address AS addr FROM threat_graph_edges
            )
        """)
        total_addresses = (await cur.fetchone())[0] or 0

        return {
            "total_edges": total_edges,
            "total_clusters": total_clusters,
            "total_addresses": total_addresses,
        }

    async def get_top_clusters(self, limit: int = 10) -> List[Dict]:
        """Get the most active clusters by member count."""
        cursor = await self._db.execute("""
            SELECT cluster_id, COUNT(*) as member_count
            FROM threat_graph_clusters
            GROUP BY cluster_id
            ORDER BY member_count DESC
            LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        return [
            {"cluster_id": r[0], "member_count": r[1]}
            for r in rows
        ]

    # --- Guardian Wallets ---

    async def register_guardian_wallet(
        self, wallet_address: str, chain_id: int, owner_id: str, is_agent: bool = False
    ) -> Dict:
        """Register a wallet for guardian monitoring."""
        now = time.time()
        wallet_address = wallet_address.lower()
        await self._db.execute("""
            INSERT INTO guardian_wallets (wallet_address, chain_id, owner_id, is_agent_wallet, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(wallet_address, chain_id) DO UPDATE SET
                owner_id = excluded.owner_id,
                is_agent_wallet = excluded.is_agent_wallet
        """, (wallet_address, chain_id, owner_id, int(is_agent), now))
        await self._db.commit()
        return {"wallet_address": wallet_address, "chain_id": chain_id, "owner_id": owner_id, "created_at": now}

    async def get_guardian_wallets(self, owner_id: str) -> List[Dict]:
        """List monitored wallets for an owner."""
        cursor = await self._db.execute(
            "SELECT wallet_address, chain_id, is_agent_wallet, health_score, last_scan_at, created_at "
            "FROM guardian_wallets WHERE owner_id = ? ORDER BY created_at DESC",
            (owner_id,),
        )
        rows = await cursor.fetchall()
        return [
            {
                "wallet_address": r[0], "chain_id": r[1], "is_agent_wallet": bool(r[2]),
                "health_score": r[3], "last_scan_at": r[4], "created_at": r[5],
            }
            for r in rows
        ]

    async def get_guardian_wallet(self, wallet_address: str, chain_id: int) -> Optional[Dict]:
        """Get a single guardian wallet."""
        cursor = await self._db.execute(
            "SELECT wallet_address, chain_id, owner_id, is_agent_wallet, health_score, last_scan_at, created_at "
            "FROM guardian_wallets WHERE wallet_address = ? AND chain_id = ?",
            (wallet_address.lower(), chain_id),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "wallet_address": row[0], "chain_id": row[1], "owner_id": row[2],
            "is_agent_wallet": bool(row[3]), "health_score": row[4],
            "last_scan_at": row[5], "created_at": row[6],
        }

    async def update_guardian_health(self, wallet_address: str, chain_id: int, health_score: float):
        """Update wallet health score."""
        now = time.time()
        await self._db.execute(
            "UPDATE guardian_wallets SET health_score = ?, last_scan_at = ? WHERE wallet_address = ? AND chain_id = ?",
            (health_score, now, wallet_address.lower(), chain_id),
        )
        await self._db.commit()

    async def create_guardian_alert(
        self, wallet_address: str, chain_id: int, alert_type: str,
        severity: str, title: str, details: Dict = None,
    ) -> int:
        """Create a guardian alert. Returns alert ID."""
        now = time.time()
        details_json = json.dumps(details) if details else None
        cursor = await self._db.execute(
            "INSERT INTO guardian_alerts (wallet_address, chain_id, alert_type, severity, title, details, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (wallet_address.lower(), chain_id, alert_type, severity, title, details_json, now),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_guardian_alerts(self, wallet_address: str = None, limit: int = 50) -> List[Dict]:
        """Get recent guardian alerts."""
        if wallet_address:
            cursor = await self._db.execute(
                "SELECT id, wallet_address, chain_id, alert_type, severity, title, details, acknowledged, created_at "
                "FROM guardian_alerts WHERE wallet_address = ? ORDER BY created_at DESC LIMIT ?",
                (wallet_address.lower(), limit),
            )
        else:
            cursor = await self._db.execute(
                "SELECT id, wallet_address, chain_id, alert_type, severity, title, details, acknowledged, created_at "
                "FROM guardian_alerts ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        results = []
        for r in rows:
            details = None
            if r[6]:
                try:
                    details = json.loads(r[6])
                except (json.JSONDecodeError, TypeError):
                    details = r[6]
            results.append({
                "id": r[0], "wallet_address": r[1], "chain_id": r[2], "alert_type": r[3],
                "severity": r[4], "title": r[5], "details": details,
                "acknowledged": bool(r[7]), "created_at": r[8],
            })
        return results

    async def acknowledge_guardian_alert(self, alert_id: int) -> bool:
        """Mark alert as acknowledged. Returns True if found."""
        cursor = await self._db.execute(
            "UPDATE guardian_alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
        )
        await self._db.commit()
        return cursor.rowcount > 0

    # --- Anomaly Baselines ---

    async def upsert_anomaly_baseline(self, agent_id: str, baseline_data: str, is_ready: bool):
        """Insert or update anomaly baseline."""
        now = time.time()
        await self._db.execute("""
            INSERT INTO anomaly_baselines (agent_id, baseline_data, baseline_started_at, baseline_ready, last_updated)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                baseline_data = excluded.baseline_data,
                baseline_ready = excluded.baseline_ready,
                last_updated = excluded.last_updated
        """, (agent_id, baseline_data, now, int(is_ready), now))
        await self._db.commit()

    async def get_anomaly_baseline(self, agent_id: str) -> Optional[Dict]:
        """Get anomaly baseline for an agent."""
        cursor = await self._db.execute(
            "SELECT agent_id, baseline_data, baseline_started_at, baseline_ready, last_updated "
            "FROM anomaly_baselines WHERE agent_id = ?",
            (agent_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "agent_id": row[0], "baseline_data": row[1],
            "baseline_started_at": row[2], "baseline_ready": bool(row[3]),
            "last_updated": row[4],
        }

    async def get_all_ready_baselines(self) -> List[Dict]:
        """Get all agents with ready baselines."""
        cursor = await self._db.execute(
            "SELECT agent_id, baseline_data, baseline_started_at, last_updated "
            "FROM anomaly_baselines WHERE baseline_ready = 1"
        )
        rows = await cursor.fetchall()
        return [
            {"agent_id": r[0], "baseline_data": r[1], "baseline_started_at": r[2], "last_updated": r[3]}
            for r in rows
        ]

    # --- Reputation Cache ---

    async def upsert_reputation_cache(self, agent_id: str, data: Dict):
        """Store composite reputation score."""
        now = time.time()
        raw_json = json.dumps(data)
        composite = data.get("composite_score", 0)
        await self._db.execute("""
            INSERT INTO reputation_cache (agent_id, registry, trust_score, raw_data, last_fetched)
            VALUES (?, 'composite', ?, ?, ?)
            ON CONFLICT(agent_id, registry) DO UPDATE SET
                trust_score = excluded.trust_score,
                raw_data = excluded.raw_data,
                last_fetched = excluded.last_fetched
        """, (agent_id, composite, raw_json, now))
        await self._db.commit()

    async def get_reputation_cache(self, agent_id: str) -> Optional[Dict]:
        """Get cached composite reputation score."""
        cursor = await self._db.execute(
            "SELECT raw_data, last_fetched FROM reputation_cache WHERE agent_id = ? AND registry = 'composite'",
            (agent_id,),
        )
        row = await cursor.fetchone()
        if not row or not row[0]:
            return None
        try:
            data = json.loads(row[0])
            data["last_fetched"] = row[1]
            return data
        except (json.JSONDecodeError, TypeError):
            return None

    async def get_reputation_cache_by_registry(self, agent_id: str, registry: str) -> Optional[Dict]:
        """Get cached score for a specific registry."""
        cursor = await self._db.execute(
            "SELECT trust_score, raw_data, last_fetched FROM reputation_cache WHERE agent_id = ? AND registry = ?",
            (agent_id, registry),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {"trust_score": row[0], "raw_data": row[1], "last_fetched": row[2]}

    async def invalidate_reputation_cache(self, agent_id: str):
        """Invalidate reputation cache by setting last_fetched to 0."""
        await self._db.execute(
            "UPDATE reputation_cache SET last_fetched = 0 WHERE agent_id = ?", (agent_id,)
        )
        await self._db.commit()

    async def get_reputation_leaderboard(self, limit: int = 50) -> List[Dict]:
        """Get top agents by composite trust score."""
        cursor = await self._db.execute(
            "SELECT agent_id, trust_score, raw_data FROM reputation_cache "
            "WHERE registry = 'composite' AND trust_score IS NOT NULL "
            "ORDER BY trust_score DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        results = []
        for r in rows:
            entry = {"agent_id": r[0], "composite_score": r[1]}
            if r[2]:
                try:
                    data = json.loads(r[2])
                    entry["breakdown"] = data.get("breakdown", {})
                    entry["verified"] = data.get("verified", False)
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(entry)
        return results

    # --- Launch Discovery ---

    async def _create_launch_discovery_tables(self):
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS launch_discovery_cursors (
                chain_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                last_block INTEGER NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (chain_id, source)
            );

            CREATE TABLE IF NOT EXISTS discovered_launches (
                chain_id INTEGER NOT NULL,
                token_address TEXT NOT NULL,
                source TEXT NOT NULL,
                launchpad TEXT NOT NULL,
                source_rank INTEGER NOT NULL,
                pool_id TEXT,
                block_number INTEGER NOT NULL,
                tx_hash TEXT NOT NULL,
                block_timestamp INTEGER NOT NULL,
                discovered_at REAL NOT NULL,
                scan_status TEXT,
                risk_score REAL,
                scanned_at REAL,
                impostor_check TEXT,
                PRIMARY KEY (chain_id, token_address)
            );

            CREATE INDEX IF NOT EXISTS idx_discovered_launches_unscanned
                ON discovered_launches(chain_id, scanned_at, block_number);
        """)
        await self._db.commit()
        await self._migrate_launch_impostor_check()

    async def _migrate_launch_impostor_check(self):
        """Add the impostor check to launch tables created before it; earlier launches have none."""
        await self._db.execute("BEGIN IMMEDIATE")
        try:
            cursor = await self._db.execute("PRAGMA table_info(discovered_launches)")
            if not any(column[1] == "impostor_check" for column in await cursor.fetchall()):
                await self._db.execute("ALTER TABLE discovered_launches ADD COLUMN impostor_check TEXT")
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise

    async def get_launch_cursor(self, chain_id: int, source: str) -> Optional[int]:
        """Return the last block processed for a launch source, or None before its first sweep."""
        cursor = await self._db.execute(
            "SELECT last_block FROM launch_discovery_cursors WHERE chain_id = ? AND source = ?",
            (chain_id, source),
        )
        row = await cursor.fetchone()
        return row[0] if row else None

    async def set_launch_cursor(self, chain_id: int, source: str, last_block: int):
        """Store the last block processed for a launch source."""
        await self._db.execute("""
            INSERT INTO launch_discovery_cursors (chain_id, source, last_block, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(chain_id, source) DO UPDATE SET
                last_block = excluded.last_block,
                updated_at = excluded.updated_at
        """, (chain_id, source, last_block, time.time()))
        await self._db.commit()

    async def get_launch_discovery_status(self, chain_id: int) -> Dict:
        """Report how far launch discovery has read, from its stored cursors and launches.

        ``cursor`` is the lowest source cursor, the block through which every source has been
        read; ``last_sweep_at`` is when a sweep last moved a cursor; ``last_discovered_block`` is
        the newest launch recorded. Each is None until discovery has stored one.
        """
        cursor = await self._db.execute(
            "SELECT MIN(last_block), MAX(updated_at) FROM launch_discovery_cursors WHERE chain_id = ?",
            (chain_id,),
        )
        lowest, last_sweep_at = await cursor.fetchone()
        cursor = await self._db.execute(
            "SELECT MAX(block_number) FROM discovered_launches WHERE chain_id = ?", (chain_id,)
        )
        newest = (await cursor.fetchone())[0]
        return {"cursor": lowest, "last_sweep_at": last_sweep_at, "last_discovered_block": newest}

    async def upsert_discovered_launches(self, chain_id: int, launches: List[Dict]):
        """Record launches idempotently, one row per token.

        On conflict the higher-ranked source keeps the label, the first known pool is kept,
        and the earliest block with its transaction and timestamp wins. Scan outcomes are kept.
        """
        now = time.time()
        await self._db.executemany("""
            INSERT INTO discovered_launches
                (chain_id, token_address, source, launchpad, source_rank, pool_id,
                 block_number, tx_hash, block_timestamp, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(chain_id, token_address) DO UPDATE SET
                source = CASE WHEN excluded.source_rank > discovered_launches.source_rank
                    THEN excluded.source ELSE discovered_launches.source END,
                launchpad = CASE WHEN excluded.source_rank > discovered_launches.source_rank
                    THEN excluded.launchpad ELSE discovered_launches.launchpad END,
                source_rank = MAX(excluded.source_rank, discovered_launches.source_rank),
                pool_id = COALESCE(discovered_launches.pool_id, excluded.pool_id),
                tx_hash = CASE WHEN excluded.block_number < discovered_launches.block_number
                    THEN excluded.tx_hash ELSE discovered_launches.tx_hash END,
                block_timestamp = CASE WHEN excluded.block_number < discovered_launches.block_number
                    THEN excluded.block_timestamp ELSE discovered_launches.block_timestamp END,
                block_number = MIN(excluded.block_number, discovered_launches.block_number)
        """, [
            (
                chain_id, launch["token_address"], launch["source"], launch["launchpad"],
                launch["source_rank"], launch["pool_id"], launch["block_number"], launch["tx_hash"],
                launch["block_timestamp"], now,
            )
            for launch in launches
        ])
        await self._db.commit()

    async def get_unscanned_launches(self, chain_id: int, limit: int) -> List[Dict]:
        """Return launches that have not been scanned, newest first."""
        cursor = await self._db.execute("""
            SELECT token_address, source, launchpad, pool_id, block_number, tx_hash, block_timestamp
            FROM discovered_launches
            WHERE chain_id = ? AND scanned_at IS NULL
            ORDER BY block_number DESC, token_address
            LIMIT ?
        """, (chain_id, limit))
        rows = await cursor.fetchall()
        return [
            {
                "token_address": r[0],
                "source": r[1],
                "launchpad": r[2],
                "pool_id": r[3],
                "block_number": r[4],
                "tx_hash": r[5],
                "block_timestamp": r[6],
            }
            for r in rows
        ]

    async def record_launch_scan(
        self, chain_id: int, token_address: str, scan_status: str, risk_score: Optional[float]
    ):
        """Record the outcome of scanning a discovered launch."""
        await self._db.execute("""
            UPDATE discovered_launches
            SET scan_status = ?, risk_score = ?, scanned_at = ?
            WHERE chain_id = ? AND token_address = ?
        """, (scan_status, risk_score, time.time(), chain_id, token_address))
        await self._db.commit()

    async def record_launch_impostor_check(self, chain_id: int, token_address: str, check: Dict):
        """Store a launch's check against the official Robinhood tokens (services.robinhood_assets).

        A check made under newer rules replaces the stored one outright, so a corrected rule corrects the
        stored labels on the next scan; checks stored before rule versions count as rules 1. Under the
        same rules a check never replaces a more decided one (_IMPOSTOR_CHECK_RANK), so a failed read
        cannot turn an impostor, official or collision finding into none or unknown, and an official
        finding is not replaced by a check made from a shorter list. One UPDATE decides and writes.
        """
        # The interpolated value is the code constant _STORED_IMPOSTOR_CHECK_RANK, never user input.
        await self._db.execute(f"""
            UPDATE discovered_launches SET impostor_check = :check
            WHERE chain_id = :chain_id AND token_address = :token AND (
                impostor_check IS NULL
                OR COALESCE(json_extract(impostor_check, '$.rules'), 1) < :rules
                OR (
                    COALESCE(json_extract(impostor_check, '$.rules'), 1) = :rules
                    AND {_STORED_IMPOSTOR_CHECK_RANK} <= :rank
                    AND NOT (
                        json_extract(impostor_check, '$.status') = 'official'
                        AND :list_size < json_extract(impostor_check, '$.list_size')
                    )
                )
            )
        """, {  # nosec B608
            "check": json.dumps(check), "chain_id": chain_id, "token": token_address, "rules": check["rules"],
            "rank": _IMPOSTOR_CHECK_RANK[check["status"]], "list_size": check["list_size"],
        })
        await self._db.commit()

    # --- Launch Feed ---

    async def _create_launch_feed_tables(self):
        await self._db.executescript("""
            CREATE INDEX IF NOT EXISTS idx_discovered_launches_feed
                ON discovered_launches(chain_id, block_number DESC, token_address DESC);
            CREATE INDEX IF NOT EXISTS idx_discovered_launches_scan_share
                ON discovered_launches(chain_id, block_timestamp, scanned_at);
        """)
        await self._db.commit()

    async def get_launch_scan_share(self, chain_id: int, since: float) -> Dict:
        """Count the launches whose block is at or after ``since`` and how many of them were scanned.

        A launch counts as scanned once any scan outcome was recorded for it, including an
        incomplete or failed one.
        """
        cursor = await self._db.execute("""
            SELECT COUNT(*), COUNT(scanned_at) FROM discovered_launches
            WHERE chain_id = ? AND block_timestamp >= ?
        """, (chain_id, since))
        launches, scanned = await cursor.fetchone()
        return {"launches": launches, "scanned": scanned}

    async def get_launch_feed(
        self, chain_id: int, limit: int, cursor: Optional[str] = None
    ) -> Tuple[List[Dict], Optional[str]]:
        """Return a page of discovered launches, newest first, each with its latest outcome.

        Each launch's ``scan.status`` is authoritative: "ok" only for a complete scan. Its
        ``impostor_check`` is its check against the official Robinhood tokens
        (record_launch_impostor_check), or None if it was never checked. ``cursor``
        is the ``next_cursor`` of the previous page ("block:token"). The next cursor is None on
        the last page. A malformed cursor raises ValueError.
        """
        if cursor is None:
            result = await self._db.execute(_LAUNCH_FEED_FIRST_PAGE, (chain_id, limit + 1))
        else:
            match = _LAUNCH_CURSOR.fullmatch(cursor) if isinstance(cursor, str) else None
            if match is None:
                raise ValueError("Invalid cursor")
            result = await self._db.execute(
                _LAUNCH_FEED_NEXT_PAGE, (chain_id, int(match.group(1)), match.group(2), limit + 1)
            )
        rows = await result.fetchall()
        next_cursor = f"{rows[limit - 1][4]}:{rows[limit - 1][0]}" if len(rows) > limit else None
        items = [_launch_item(chain_id, row, await self._launch_finding(chain_id, row)) for row in rows[:limit]]
        return items, next_cursor

    async def _launch_finding(self, chain_id: int, row):
        """Return the hunter finding behind a blocked launch, or (None, None) for other outcomes."""
        if row[10] is not None and row[8] == "blocked":
            return await self._latest_hunter_finding(chain_id, row[0])
        return None, None

    async def _latest_hunter_finding(self, chain_id: int, address: str):
        """Return the risk score and evidence of the hunter's latest finding for an address."""
        cursor = await self._db.execute("""
            SELECT risk_score, evidence FROM agent_findings
            WHERE finding_type = 'hunter_sweep' AND chain_id = ? AND address = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 1
        """, (chain_id, address))
        row = await cursor.fetchone()
        if row is None:
            return None, None
        try:
            evidence = json.loads(row[1]) if row[1] else None
        except (json.JSONDecodeError, TypeError):
            evidence = None
        return row[0], evidence if isinstance(evidence, dict) else None

    # --- Launch Alerts ---

    async def _create_launch_alert_tables(self):
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS launch_alert_subscriptions (
                chat_id INTEGER NOT NULL,
                chain_id INTEGER NOT NULL,
                mode TEXT NOT NULL CHECK (mode IN ('blocked', 'all')),
                created_at REAL NOT NULL,
                PRIMARY KEY (chat_id, chain_id)
            );

            CREATE TABLE IF NOT EXISTS launch_alert_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                chain_id INTEGER NOT NULL,
                token_address TEXT NOT NULL,
                outcome TEXT NOT NULL,
                outcome_at REAL NOT NULL,
                payload TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending',
                error TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                UNIQUE (chat_id, chain_id, token_address, outcome)
            );

            CREATE INDEX IF NOT EXISTS idx_launch_alert_outbox_state
                ON launch_alert_outbox(state, chat_id, id);
        """)
        await self._db.commit()

    async def subscribe_launch_alerts(self, chat_id: int, chain_id: int, mode: str):
        """Subscribe a chat to a chain's launch alerts ("blocked" or "all"), or change its mode.

        A subscription covers outcomes recorded after it was first created.
        """
        await self._db.execute("""
            INSERT INTO launch_alert_subscriptions (chat_id, chain_id, mode, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(chat_id, chain_id) DO UPDATE SET mode = excluded.mode
        """, (chat_id, chain_id, mode, time.time()))
        await self._db.commit()

    async def unsubscribe_launch_alerts(self, chat_id: int, chain_id: int) -> bool:
        """Remove a chat's subscription and cancel its queued alerts; False if it had none."""
        async with self.transaction() as connection:
            unsubscribed = await self._unsubscribe_launch_alerts(connection, chat_id, chain_id)
        return unsubscribed

    async def _unsubscribe_launch_alerts(
        self, connection: aiosqlite.Connection, chat_id: int, chain_id: int
    ) -> bool:
        """The unsubscribe's two statements, inside the caller's transaction."""
        cursor = await connection.execute(
            "DELETE FROM launch_alert_subscriptions WHERE chat_id = ? AND chain_id = ?",
            (chat_id, chain_id),
        )
        await connection.execute("""
            UPDATE launch_alert_outbox SET state = 'cancelled', updated_at = ?
            WHERE chat_id = ? AND chain_id = ? AND state = 'pending'
        """, (time.time(), chat_id, chain_id))
        return cursor.rowcount == 1

    async def move_launch_alert_chat(self, chat_id: int, new_chat_id: int, chain_id: int):
        """Follow a group that became a supergroup: move its subscription and queued alerts.

        If the new id is already subscribed, that subscription stays and the old queue is
        cancelled.
        """
        # One transaction, running the unsubscribe's statements rather than the public method, which would
        # wait for this transaction's lock.
        async with self.transaction() as connection:
            cursor = await connection.execute(
                "UPDATE OR IGNORE launch_alert_subscriptions SET chat_id = ? WHERE chat_id = ? AND chain_id = ?",
                (new_chat_id, chat_id, chain_id),
            )
            if cursor.rowcount == 1:
                await connection.execute("""
                    UPDATE OR IGNORE launch_alert_outbox SET chat_id = ?, updated_at = ?
                    WHERE chat_id = ? AND chain_id = ? AND state = 'pending'
                """, (new_chat_id, time.time(), chat_id, chain_id))
            await self._unsubscribe_launch_alerts(connection, chat_id, chain_id)

    async def enqueue_launch_alerts(self, chain_id: int, since: float) -> Optional[float]:
        """Queue alerts for the launch outcomes recorded at or after ``since``.

        A chat gets outcomes recorded after it subscribed: every one in "all" mode, otherwise
        only blocked ones and those of impostors of an official Robinhood token. An impostor's
        outcomes other than blocked are all queued as "impostor", so a chat gets one impostor alert
        per launch besides the blocked one. A chat is queued at most one alert per launch and
        outcome, so passes over the same window, and passes after a restart, never queue an alert
        twice.

        A blocked launch whose evidence is not stored yet is held back for up to
        _BLOCKED_EVIDENCE_WAIT_SECONDS. Returns the outcome time of the oldest one held, which
        the caller keeps inside its next window, or None.
        """
        cursor = await self._db.execute(
            "SELECT chat_id, mode, created_at FROM launch_alert_subscriptions WHERE chain_id = ? ORDER BY chat_id",
            (chain_id,),
        )
        subscriptions = await cursor.fetchall()
        if not subscriptions:
            return None
        cursor = await self._db.execute(
            _LAUNCH_OUTCOMES_SINCE, (chain_id, since, chain_id, chain_id, since, since)
        )
        alerts = []
        held = None
        now = time.time()
        for row in await cursor.fetchall():
            token, stored_status, outcome_at = row[0], row[8], row[10]
            outcome = _launch_outcome(stored_status, outcome_at)
            impostor_check = _impostor_check(row[11])
            impostor = impostor_check is not None and impostor_check["status"] == "impostor"
            key = "impostor" if impostor and outcome != "blocked" else outcome
            chats = [
                chat_id for chat_id, mode, created_at in subscriptions
                if created_at <= outcome_at and (mode == "all" or outcome == "blocked" or impostor)
            ]
            if not chats:
                continue
            finding = await self._launch_finding(chain_id, row)
            if outcome == "blocked" and finding[1] is None and outcome_at > now - _BLOCKED_EVIDENCE_WAIT_SECONDS:
                held = outcome_at if held is None else min(held, outcome_at)
                continue
            payload = json.dumps(_launch_item(chain_id, row, finding))
            alerts += [(chat_id, chain_id, token, key, outcome_at, payload, now, now) for chat_id in chats]
        await self._db.executemany("""
            INSERT OR IGNORE INTO launch_alert_outbox
                (chat_id, chain_id, token_address, outcome, outcome_at, payload, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, alerts)
        await self._db.commit()
        return held

    async def get_pending_launch_alerts(
        self, now: float, max_age: float, per_chat: int, limit: int
    ) -> List[Dict]:
        """Expire pending alerts older than ``max_age``, then return the oldest pending ones.

        An alert left sending by a pass that died is marked unconfirmed and never resent. At
        most ``per_chat`` alerts per chat and ``limit`` in all are returned.
        """
        await self._db.execute("""
            UPDATE launch_alert_outbox SET state = 'expired', updated_at = ?
            WHERE state = 'pending' AND outcome_at < ?
        """, (now, now - max_age))
        await self._db.execute("""
            UPDATE launch_alert_outbox SET state = 'unconfirmed', error = 'Interrupted', updated_at = ?
            WHERE state = 'sending' AND updated_at < ?
        """, (now, now - _LAUNCH_ALERT_SEND_TIMEOUT_SECONDS))
        await self._db.commit()
        cursor = await self._db.execute("""
            SELECT id, chat_id, chain_id, token_address, outcome, payload FROM (
                SELECT *, ROW_NUMBER() OVER (PARTITION BY chat_id ORDER BY id) AS position
                FROM launch_alert_outbox
                WHERE state = 'pending'
            )
            WHERE position <= ?
            ORDER BY id
            LIMIT ?
        """, (per_chat, limit))
        return [
            {
                "id": r[0],
                "chat_id": r[1],
                "chain_id": r[2],
                "token_address": r[3],
                "outcome": r[4],
                "payload": json.loads(r[5]),
            }
            for r in await cursor.fetchall()
        ]

    async def claim_launch_alert(self, alert_id: int) -> bool:
        """Mark a pending alert as sending; False if it is no longer pending.

        A claimed alert may have reached the chat, so it is never pending again unless it is
        released because Telegram refused it.
        """
        cursor = await self._db.execute(
            "UPDATE launch_alert_outbox SET state = 'sending', updated_at = ? WHERE id = ? AND state = 'pending'",
            (time.time(), alert_id),
        )
        await self._db.commit()
        return cursor.rowcount == 1

    async def set_launch_alert_state(self, alert_id: int, state: str, error: Optional[str] = None):
        """Record what happened to an alert, with the error class if it was not sent."""
        await self._db.execute(
            "UPDATE launch_alert_outbox SET state = ?, error = ?, updated_at = ? WHERE id = ?",
            (state, error, time.time(), alert_id),
        )
        await self._db.commit()
    # --- Scan Evidence ---

    async def _create_scan_evidence_tables(self):
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS scan_evidence (
                evidence_hash TEXT PRIMARY KEY,
                canonical TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            -- The retention prune deletes by time alone.
            CREATE INDEX IF NOT EXISTS idx_scan_evidence_created_at
                ON scan_evidence(created_at);
        """)
        await self._db.commit()

    async def insert_scan_evidence(self, evidence_hash: str, canonical: str):
        """Store one /api/firewall or /api/scan evidence document under its hash.

        Equal bytes have an equal hash, so a document already stored is left as it is.
        """
        await self._db.execute(
            "INSERT OR IGNORE INTO scan_evidence (evidence_hash, canonical, created_at) VALUES (?, ?, ?)",
            (evidence_hash, canonical, time.time()),
        )
        await self._db.commit()

    async def get_scan_evidence(self, evidence_hash: str) -> Optional[Dict]:
        """The stored document and when it was stored, or None for a hash never stored or pruned."""
        cursor = await self._db.execute(
            "SELECT canonical, created_at FROM scan_evidence WHERE evidence_hash = ?", (evidence_hash,)
        )
        row = await cursor.fetchone()
        return None if row is None else {"canonical": row[0], "created_at": row[1]}

    # --- Verdict Evidence ---

    async def _create_verdict_evidence_tables(self):
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS verdict_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                verdict TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                canonical TEXT NOT NULL,
                observed_block INTEGER NOT NULL,
                created_at REAL NOT NULL,
                onchain_status TEXT NOT NULL,
                registry TEXT,
                tx_hash TEXT,
                nonce INTEGER,
                attempts INTEGER NOT NULL DEFAULT 0,
                onchain_error TEXT,
                updated_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_verdict_evidence_subject
                ON verdict_evidence(chain_id, subject, id);

            CREATE INDEX IF NOT EXISTS idx_verdict_evidence_outbox
                ON verdict_evidence(chain_id, onchain_status, id);

            CREATE TABLE IF NOT EXISTS verdict_transactions (
                evidence_id INTEGER NOT NULL,
                tx_hash TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                raw_tx TEXT,
                max_fee_per_gas INTEGER,
                created_at REAL NOT NULL,
                PRIMARY KEY (evidence_id, tx_hash)
            );

            CREATE TABLE IF NOT EXISTS guard_subjects (
                chain_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_observed_at INTEGER,
                retry_after REAL NOT NULL DEFAULT 0,
                PRIMARY KEY (chain_id, subject)
            );

            -- Which process may send (services.verdict_publisher), until expires_at unless it renews.
            CREATE TABLE IF NOT EXISTS sender_leases (
                name TEXT PRIMARY KEY,
                holder TEXT NOT NULL,
                expires_at REAL NOT NULL,
                renewed_at REAL NOT NULL
            );
        """)
        # Lowering the configured cap retires excess registrations deterministically.
        await self._db.execute("""
            UPDATE guard_subjects SET enabled = 0
            WHERE enabled = 1 AND rowid NOT IN (
                SELECT rowid FROM guard_subjects WHERE enabled = 1
                ORDER BY rowid LIMIT ?
            )
        """, (GUARD_WATCH_MAX_SUBJECTS,))
        await self._db.commit()
        await self._migrate_verdict_outbox_columns()

    async def _migrate_verdict_outbox_columns(self):
        """Add the outbox's columns to verdict tables created before them; a transaction's fee stays unknown."""
        await self._db.execute("BEGIN IMMEDIATE")
        try:
            cursor = await self._db.execute("PRAGMA table_info(verdict_evidence)")
            columns = {column[1] for column in await cursor.fetchall()}
            if "nonce" not in columns:
                await self._db.execute("ALTER TABLE verdict_evidence ADD COLUMN nonce INTEGER")
            if "attempts" not in columns:
                await self._db.execute(
                    "ALTER TABLE verdict_evidence ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"
                )
            cursor = await self._db.execute("PRAGMA table_info(verdict_transactions)")
            columns = {column[1] for column in await cursor.fetchall()}
            if "max_fee_per_gas" not in columns:
                await self._db.execute(
                    "ALTER TABLE verdict_transactions ADD COLUMN max_fee_per_gas INTEGER"
                )
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise

    async def insert_verdict_evidence(
        self, chain_id: int, subject: str, verdict: str, evidence_hash: str, canonical: str,
        observed_block: int, onchain_status: str, registry: Optional[str] = None,
        onchain_error: Optional[str] = None,
    ) -> int:
        """Store one published evidence document; earlier documents for the subject are kept."""
        now = time.time()
        cursor = await self._db.execute("""
            INSERT INTO verdict_evidence
                (chain_id, subject, verdict, evidence_hash, canonical, observed_block, created_at,
                 onchain_status, registry, onchain_error, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            chain_id, subject, verdict, evidence_hash, canonical, observed_block, now,
            onchain_status, registry, onchain_error, now,
        ))
        await self._db.commit()
        return cursor.lastrowid

    async def update_verdict_onchain(
        self, evidence_id: int, onchain_status: str, tx_hash: Optional[str] = None,
        onchain_error: Optional[str] = None, registry: Optional[str] = None,
    ):
        """Record the on-chain outcome for one stored evidence document.

        `registry` is the registry the caller records to: a confirmation admits its subject to the guard watch
        only when the row was queued for that registry.
        """
        outbox = await self._outbox()
        try:
            await outbox.execute("""
                UPDATE verdict_evidence
                SET onchain_status = ?, tx_hash = ?, onchain_error = ?, updated_at = ?
                WHERE id = ?
            """, (onchain_status, tx_hash, onchain_error, time.time(), evidence_id))
            if onchain_status == "confirmed":
                cursor = await outbox.execute("""
                    SELECT chain_id, subject, canonical FROM verdict_evidence
                    WHERE id = ? AND chain_id = 4663 AND lower(registry) = lower(?)
                """, (evidence_id, registry))
                row = await cursor.fetchone()
                if row is not None:
                    await self._admit_guard_subject(outbox, *row, reenable=False)
            await outbox.commit()
        except BaseException:
            await outbox.rollback()
            raise

    async def _admit_guard_subject(
        self, connection, chain_id: int, subject: str, canonical: str, reenable: bool
    ) -> bool:
        evidence = json.loads(canonical)
        observed_at = evidence.get("observed_at")
        if type(observed_at) is not int or not 0 < observed_at <= time.time():
            return False
        measured_at = None if is_scan_incomplete(evidence) else observed_at
        cursor = await connection.execute("""
            INSERT INTO guard_subjects (chain_id, subject, last_observed_at)
            SELECT ?, ?, ? WHERE ? > 0 AND (
                (SELECT COUNT(*) FROM guard_subjects WHERE enabled = 1) < ?
                OR EXISTS (
                    SELECT 1 FROM guard_subjects WHERE chain_id = ? AND subject = ? AND enabled = 1
                )
            )
            ON CONFLICT(chain_id, subject) DO UPDATE SET
                enabled = 1,
                last_observed_at = CASE
                    WHEN excluded.last_observed_at IS NULL THEN guard_subjects.last_observed_at
                    WHEN guard_subjects.last_observed_at IS NULL THEN excluded.last_observed_at
                    ELSE MAX(guard_subjects.last_observed_at, excluded.last_observed_at)
                END
            WHERE guard_subjects.enabled = 1 OR ?
        """, (
            chain_id, subject.lower(), measured_at, GUARD_WATCH_MAX_SUBJECTS,
            GUARD_WATCH_MAX_SUBJECTS, chain_id, subject.lower(), reenable,
        ))
        return cursor.rowcount == 1

    async def register_guard_subject(self, chain_id: int, subject: str, registry: Optional[str]) -> bool:
        """Explicitly watch a subject confirmed on `registry`, or reenable one, within the shared cap."""
        cursor = await self._db.execute("""
            SELECT chain_id, subject, canonical FROM verdict_evidence
            WHERE chain_id = ? AND chain_id = 4663 AND subject = ?
              AND onchain_status = 'confirmed' AND lower(registry) = lower(?)
              AND json_type(canonical, '$.observed_at') = 'integer'
              AND json_extract(canonical, '$.observed_at') > 0
              AND json_extract(canonical, '$.observed_at') <= ?
            ORDER BY json_extract(canonical, '$.observed_at') DESC, id DESC LIMIT 1
        """, (chain_id, subject.lower(), registry, time.time()))
        row = await cursor.fetchone()
        if row is None:
            return False
        admitted = await self._admit_guard_subject(self._db, *row, reenable=True)
        await self._db.commit()
        return admitted

    async def unregister_guard_subject(self, chain_id: int, subject: str):
        """Persist an opt-out even when a confirmation has not arrived yet."""
        await self._db.execute("""
            INSERT INTO guard_subjects (chain_id, subject, enabled) VALUES (?, ?, 0)
            ON CONFLICT(chain_id, subject) DO UPDATE SET enabled = 0
        """, (chain_id, subject.lower()))
        await self._db.commit()

    async def get_guard_subjects(self, chain_id: int) -> List[Dict]:
        """Active subjects ordered by their oldest successful measurement, unknown first."""
        cursor = await self._db.execute("""
            SELECT chain_id, subject, last_observed_at, retry_after FROM guard_subjects
            WHERE chain_id = ? AND enabled = 1
            ORDER BY last_observed_at, subject LIMIT ?
        """, (chain_id, GUARD_WATCH_MAX_SUBJECTS))
        return [
            {"chain_id": row[0], "subject": row[1], "last_observed_at": row[2], "retry_after": row[3]}
            for row in await cursor.fetchall()
        ]

    async def update_guard_subject_measurement(
        self, chain_id: int, subject: str, observed_at: Optional[int], retry_after: float
    ):
        """Advance complete measurement time; failures only set their short retry delay."""
        await self._db.execute("""
            UPDATE guard_subjects SET last_observed_at = CASE
                WHEN ? IS NULL THEN last_observed_at
                WHEN last_observed_at IS NULL THEN ?
                ELSE MAX(last_observed_at, ?)
            END, retry_after = ?
            WHERE chain_id = ? AND subject = ? AND enabled = 1
        """, (observed_at, observed_at, observed_at, retry_after, chain_id, subject.lower()))
        await self._db.commit()

    async def get_latest_verdict_evidence(self, chain_id: int, subject: str) -> Optional[Dict]:
        """Return the most recently published evidence for a subject, or None if never published."""
        cursor = await self._db.execute("""
            SELECT id, chain_id, subject, verdict, evidence_hash, canonical, observed_block, created_at,
                   onchain_status, registry, tx_hash, onchain_error, updated_at
            FROM verdict_evidence
            WHERE chain_id = ? AND subject = ?
            ORDER BY id DESC
            LIMIT 1
        """, (chain_id, subject))
        row = await cursor.fetchone()
        if row is None:
            return None
        keys = (
            "id", "chain_id", "subject", "verdict", "evidence_hash", "canonical", "observed_block",
            "created_at", "onchain_status", "registry", "tx_hash", "onchain_error", "updated_at",
        )
        return dict(zip(keys, row))

    async def get_verdict_evidence(self, evidence_id: int) -> Optional[Dict]:
        """Return one evidence document and its delivery outcome by row id."""
        cursor = await self._db.execute("""
            SELECT id, chain_id, subject, verdict, evidence_hash, canonical, observed_block, created_at,
                   onchain_status, registry, tx_hash, onchain_error, updated_at
            FROM verdict_evidence
            WHERE id = ?
        """, (evidence_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        keys = (
            "id", "chain_id", "subject", "verdict", "evidence_hash", "canonical", "observed_block",
            "created_at", "onchain_status", "registry", "tx_hash", "onchain_error", "updated_at",
        )
        return dict(zip(keys, row))

    async def get_verdict_evidence_counts(self) -> Dict[int, Dict[str, int]]:
        """Stored evidence documents per chain, and how many of them have a confirmed on-chain record."""
        cursor = await self._db.execute("""
            SELECT chain_id, COUNT(*), SUM(onchain_status = 'confirmed')
            FROM verdict_evidence
            GROUP BY chain_id
        """)
        return {
            chain_id: {"documents": documents, "confirmed": confirmed}
            for chain_id, documents, confirmed in await cursor.fetchall()
        }

    async def get_newest_verdict_observation(
        self, chain_id: int, subject: str, include_deduplicated: bool = True,
        registry: Optional[str] = None,
    ) -> Optional[Dict]:
        """Return the newest measured evidence, preferring denial at equal observation times.

        Delivery failures and dropped rows still supersede older measurements. Legacy evidence
        without observation provenance cannot establish an observation watermark. Excluding
        deduplicated rows finds the recording anchor whose observation determines refresh age.
        Given a registry, only evidence queued for it is considered, so a record on another
        registry never stands in for one on this registry.
        """
        cursor = await self._db.execute("""
            SELECT id FROM verdict_evidence
            WHERE chain_id = ? AND subject = ?
              AND (? OR onchain_status != 'deduplicated')
              AND (? IS NULL OR lower(registry) = lower(?))
              AND json_type(canonical, '$.observed_at') = 'integer'
              AND json_extract(canonical, '$.observed_at') > 0
              AND json_extract(canonical, '$.observed_at') <= ?
            ORDER BY json_extract(canonical, '$.observed_at') DESC,
                     CASE verdict WHEN 'HONEYPOT' THEN 4 WHEN 'UNKNOWN' THEN 3
                         WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 1 ELSE 0 END DESC,
                     id DESC
            LIMIT 1
        """, (chain_id, subject, include_deduplicated, registry, registry, time.time()))
        row = await cursor.fetchone()
        return await self.get_verdict_evidence(row[0]) if row else None

    async def claim_next_pending_verdict(self, chain_id: int) -> Optional[Dict]:
        """Claim the oldest row waiting to be recorded on-chain by moving it from pending to sending.

        The conditional UPDATE is atomic in SQLite, so two connections, even in two processes, never claim
        the same row.
        """
        outbox = await self._outbox()
        while True:
            cursor = await outbox.execute("""
                SELECT id, subject, verdict, evidence_hash, observed_block, tx_hash, nonce, attempts
                FROM verdict_evidence
                WHERE chain_id = ? AND onchain_status = 'pending'
                ORDER BY id
                LIMIT 1
            """, (chain_id,))
            row = await cursor.fetchone()
            if row is None:
                return None
            cursor = await outbox.execute("""
                UPDATE verdict_evidence SET onchain_status = 'sending', updated_at = ?
                WHERE id = ? AND onchain_status = 'pending'
            """, (time.time(), row[0]))
            await outbox.commit()
            if cursor.rowcount == 1:
                return dict(zip(
                    ("id", "subject", "verdict", "evidence_hash", "observed_block", "tx_hash", "nonce", "attempts"),
                    row,
                ))

    async def set_verdict_tx_hash(
        self, evidence_id: int, tx_hash: str, nonce: int, raw_tx: Optional[str] = None,
        max_fee_per_gas: Optional[int] = None,
    ) -> bool:
        """Record a transaction about to be broadcast for a claimed row; returns False if the row is not claimed.

        Every transaction a row has ever broadcast is kept in verdict_transactions, and the row's tx_hash and nonce
        show the latest one. Each new transaction counts one attempt; sending the same bytes again adds nothing.
        """
        outbox = await self._outbox()
        now = time.time()
        # One transaction: a failure must not leave the row update behind for a later commit to land alone.
        try:
            cursor = await outbox.execute("""
                UPDATE verdict_evidence SET tx_hash = ?, nonce = ?, updated_at = ?
                WHERE id = ? AND onchain_status = 'sending'
            """, (tx_hash, nonce, now, evidence_id))
            claimed = cursor.rowcount == 1
            if claimed:
                cursor = await outbox.execute("""
                    INSERT OR IGNORE INTO verdict_transactions
                        (evidence_id, tx_hash, nonce, raw_tx, max_fee_per_gas, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (evidence_id, tx_hash, nonce, raw_tx, max_fee_per_gas, now))
                if cursor.rowcount == 1:
                    await outbox.execute(
                        "UPDATE verdict_evidence SET attempts = attempts + 1 WHERE id = ?", (evidence_id,)
                    )
            await outbox.commit()
        except BaseException:
            await outbox.rollback()
            raise
        return claimed

    async def get_verdict_transactions(self, evidence_ids: List[int]) -> Dict[int, List[Dict]]:
        """Every transaction broadcast for each row, oldest first."""
        transactions: Dict[int, List[Dict]] = {}
        for evidence_id in evidence_ids:
            cursor = await self._db.execute("""
                SELECT tx_hash, nonce, raw_tx, max_fee_per_gas FROM verdict_transactions
                WHERE evidence_id = ?
                ORDER BY created_at, rowid
            """, (evidence_id,))
            transactions[evidence_id] = [
                {"tx_hash": r[0], "nonce": r[1], "raw_tx": r[2], "max_fee_per_gas": r[3]}
                for r in await cursor.fetchall()
            ]
        return transactions

    async def touch_verdict(self, evidence_id: int):
        """Mark a row as just looked at, so reconciliation looks at it again only after its delay."""
        outbox = await self._outbox()
        await outbox.execute(
            "UPDATE verdict_evidence SET updated_at = ? WHERE id = ?", (time.time(), evidence_id)
        )
        await outbox.commit()

    async def release_verdict_claim(self, evidence_id: int):
        """Return a claimed row to the pending queue.

        An earlier transaction's hash and nonce are kept, so the next attempt can check whether it may still land.
        """
        outbox = await self._outbox()
        await outbox.execute("""
            UPDATE verdict_evidence SET onchain_status = 'pending', updated_at = ?
            WHERE id = ? AND onchain_status = 'sending'
        """, (time.time(), evidence_id))
        await outbox.commit()

    async def take_sender_lease(self, name: str, holder: str, seconds: float) -> Tuple[Optional[str], float]:
        """Take or renew the named lease for `holder` for `seconds`, unless another holder's lease is still live.

        One conditional upsert, atomic in SQLite, so however many processes ask at once, one holds the lease.
        Returns the lease's holder and expiry (Unix time) after the attempt, or (None, now) if the lease was
        released before it could be read back. Runs on the lease's own connection, one call at a time, so it never
        commits or rolls back a transaction the drain or another lease call has open.
        """
        connection = await self._lease()
        async with self._lease_calls:
            now = time.time()
            # A failure or a cancellation between the upsert and its commit must not leave the write lock held.
            try:
                await connection.execute("""
                    INSERT INTO sender_leases (name, holder, expires_at, renewed_at) VALUES (?, ?, ?, ?)
                    ON CONFLICT (name) DO UPDATE SET
                        holder = excluded.holder, expires_at = excluded.expires_at, renewed_at = excluded.renewed_at
                    WHERE sender_leases.holder = excluded.holder OR sender_leases.expires_at <= excluded.renewed_at
                """, (name, holder, now + seconds, now))
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise
            cursor = await connection.execute(
                "SELECT holder, expires_at FROM sender_leases WHERE name = ?", (name,)
            )
            row = await cursor.fetchone()
        return (row[0], row[1]) if row else (None, now)

    async def release_sender_lease(self, name: str, holder: str):
        """Give up the named lease if `holder` holds it, on the lease's own connection."""
        connection = await self._lease()
        async with self._lease_calls:
            await connection.execute("DELETE FROM sender_leases WHERE name = ? AND holder = ?", (name, holder))
            await connection.commit()

    async def requeue_verdict(self, evidence_id: int):
        """Queue an unresolved record (submitted, unconfirmed or failed) for another attempt."""
        outbox = await self._outbox()
        await outbox.execute("""
            UPDATE verdict_evidence SET onchain_status = 'pending', updated_at = ?
            WHERE id = ? AND onchain_status IN ('submitted', 'unconfirmed', 'failed')
        """, (time.time(), evidence_id))
        await outbox.commit()

    async def get_unresolved_verdicts(self, chain_id: int, updated_before: float, limit: int) -> List[Dict]:
        """Signed records awaiting receipts, including dropped records that must never be resent."""
        cursor = await self._db.execute("""
            SELECT id, tx_hash, nonce, attempts FROM verdict_evidence
            WHERE chain_id = ? AND onchain_status IN ('submitted', 'unconfirmed', 'failed', 'dropped')
              AND tx_hash IS NOT NULL AND updated_at < ?
            ORDER BY updated_at, id
            LIMIT ?
        """, (chain_id, updated_before, limit))
        return [
            {"id": r[0], "tx_hash": r[1], "nonce": r[2], "attempts": r[3]} for r in await cursor.fetchall()
        ]

    async def get_claimed_verdicts(self, chain_id: int, claimed_before: Optional[float] = None) -> List[Dict]:
        """Rows claimed for sending whose outcome was never recorded, optionally only those untouched since then."""
        cursor = await self._db.execute("""
            SELECT id, tx_hash, nonce, attempts FROM verdict_evidence
            WHERE chain_id = ? AND onchain_status = 'sending' AND (? IS NULL OR updated_at < ?)
            ORDER BY id
        """, (chain_id, claimed_before, claimed_before))
        return [
            {"id": r[0], "tx_hash": r[1], "nonce": r[2], "attempts": r[3]} for r in await cursor.fetchall()
        ]
