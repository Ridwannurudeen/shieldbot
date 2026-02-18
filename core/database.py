"""Database layer — SQLite with WAL mode for contract reputation and outcome tracking."""

import json
import time
import logging
from typing import Dict, List, Optional

import aiosqlite

logger = logging.getLogger(__name__)


class Database:
    """Async SQLite database for contract scores and outcome events."""

    def __init__(self, db_path: str = "shieldbot.db"):
        self.db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None

    async def initialize(self):
        """Open connection and create tables."""
        self._db = await aiosqlite.connect(self.db_path)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA busy_timeout=5000")
        await self._create_tables()
        logger.info(f"Database initialized at {self.db_path}")

    async def close(self):
        """Close the database connection."""
        if self._db:
            await self._db.close()
            self._db = None

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
                funding_value_wei INTEGER DEFAULT 0,
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
        """)
        await self._db.commit()

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

        return {
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
        }

    # --- Outcome Events ---

    async def record_outcome(
        self,
        address: str,
        chain_id: int = 56,
        risk_score_at_scan: float = None,
        user_decision: str = None,
        outcome: str = None,
        tx_hash: str = None,
    ):
        """Record a user decision or outcome event."""
        now = time.time()
        await self._db.execute("""
            INSERT INTO outcome_events
                (address, chain_id, risk_score_at_scan, user_decision, outcome, tx_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (address.lower(), chain_id, risk_score_at_scan, user_decision, outcome, tx_hash, now))
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
            'funder_value_wei': funder_value,
            'contracts_deployed': deployed_contracts,
            'total_deployed': len(deployed_contracts),
        }

    async def get_outcomes(self, address: str, chain_id: int = 56, limit: int = 50) -> List[Dict]:
        """Get outcome events for an address."""
        cursor = await self._db.execute("""
            SELECT risk_score_at_scan, user_decision, outcome, tx_hash, created_at
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
                'created_at': r[4],
            }
            for r in rows
        ]
