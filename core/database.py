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

        cur = await self._db.execute(
            "SELECT COUNT(*) FROM contract_scores WHERE risk_score >= 71"
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

            cur = await self._db.execute(
                "SELECT COUNT(*) FROM contract_scores WHERE last_scanned_at > ? AND risk_score >= 71",
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

        cursor = await self._db.execute("""
            SELECT
                COUNT(DISTINCT d.contract_address),
                COALESCE(SUM(CASE WHEN cs.risk_level = 'HIGH' THEN 1 ELSE 0 END), 0)
            FROM deployers d
            LEFT JOIN contract_scores cs
                ON cs.address = d.contract_address AND cs.chain_id = d.chain_id
            WHERE d.deployer_address = ?
        """, (deployer,))
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
        cursor = await self._db.execute("""
            INSERT INTO deployment_alerts
                (deployer_address, chain_id, new_contract_address, watch_reason, telegram_sent, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (deployer.lower(), chain_id, contract_address.lower(), reason, telegram_sent, now))
        await self._db.execute("""
            UPDATE watched_deployers
            SET alert_count = alert_count + 1, last_alert_at = ?
            WHERE deployer_address = ? AND (chain_id = ? OR chain_id = 0)
        """, (now, deployer.lower(), chain_id))
        await self._db.commit()
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
                ORDER BY created_at DESC
                LIMIT ?
            """, (finding_type, limit))
        else:
            cursor = await self._db.execute("""
                SELECT id, finding_type, investigation_id, address, deployer,
                       chain_id, risk_score, narrative, evidence, action_taken, created_at
                FROM agent_findings
                ORDER BY created_at DESC
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
    ):
        """Insert a chat message for a user."""
        now = time.time()
        tools_json = json.dumps(tools_used) if isinstance(tools_used, (list, dict)) else tools_used
        await self._db.execute("""
            INSERT INTO chat_history (user_id, role, message, tools_used, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, role, message, tools_json, now))
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

    # --- Tracked Pairs ---

    async def upsert_tracked_pair(
        self,
        pair_address: str,
        token_address: str = None,
        deployer: str = None,
        liquidity_usd: float = None,
        status: str = "watching",
    ):
        """Insert or update a tracked PancakeSwap pair."""
        now = time.time()
        await self._db.execute("""
            INSERT INTO tracked_pairs
                (pair_address, token_address, deployer, liquidity_usd, first_seen, last_checked, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(pair_address) DO UPDATE SET
                token_address = COALESCE(excluded.token_address, tracked_pairs.token_address),
                deployer = COALESCE(excluded.deployer, tracked_pairs.deployer),
                liquidity_usd = COALESCE(excluded.liquidity_usd, tracked_pairs.liquidity_usd),
                last_checked = excluded.last_checked,
                status = excluded.status
        """, (pair_address, token_address, deployer, liquidity_usd, now, now, status))
        await self._db.commit()

    async def get_tracked_pairs(
        self, status: str = None, limit: int = 100
    ) -> List[Dict]:
        """Get tracked pairs, optionally filtered by status."""
        if status:
            cursor = await self._db.execute("""
                SELECT id, pair_address, token_address, deployer, liquidity_usd,
                       first_seen, last_checked, status
                FROM tracked_pairs
                WHERE status = ?
                ORDER BY first_seen DESC
                LIMIT ?
            """, (status, limit))
        else:
            cursor = await self._db.execute("""
                SELECT id, pair_address, token_address, deployer, liquidity_usd,
                       first_seen, last_checked, status
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
            }
            for r in rows
        ]

    async def update_tracked_pair_status(self, pair_address: str, status: str):
        """Update a tracked pair's status and last_checked timestamp."""
        now = time.time()
        await self._db.execute("""
            UPDATE tracked_pairs
            SET status = ?, last_checked = ?
            WHERE pair_address = ?
        """, (status, now, pair_address))
        await self._db.commit()
