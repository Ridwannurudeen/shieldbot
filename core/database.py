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

        # Migrate: add registered_by_key column for existing DBs
        try:
            await self._db.execute(
                "ALTER TABLE agent_policies ADD COLUMN registered_by_key TEXT"
            )
            await self._db.commit()
        except Exception:
            pass  # Column already exists

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
