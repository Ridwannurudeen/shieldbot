"""Hunter — scheduled proactive threat sweep loop for ShieldBot's AI agent.

Runs periodic sweeps that:
1. Check watched deployers for new contracts
2. Recheck contracts previously scored WARN (31-70)
3. Discover new Robinhood Chain launches and scan the newest ones

For any flagged contract: auto-watches the deployer, generates an AI threat
narrative (when available), and stores the finding.

Every public method is wrapped in try/except so it never crashes the caller.
"""

import asyncio
import json
import logging
import time
import traceback

from agent.prompts import HAIKU_MODEL, NARRATIVE_TEMPLATE
from core.extension_formatter import is_scan_incomplete
from services.launch_discovery import CHAIN_ID as LAUNCH_CHAIN_ID

logger = logging.getLogger(__name__)

# Each scan runs every analyzer, so only the newest launches are scanned per sweep.
LAUNCH_SCANS_PER_SWEEP = 10


class Hunter:
    """Proactive scheduled threat sweeps."""

    def __init__(self, tools, db, ai_analyzer, sentinel, discovery=None):
        self.tools = tools
        self.db = db
        self.ai = ai_analyzer
        self.sentinel = sentinel
        self.discovery = discovery
        self._task = None  # asyncio.Task for background loop
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, interval_seconds: int = 1800):
        """Start the background sweep loop (default: every 30 min)."""
        if self._running or (self._task and not self._task.done()):
            logger.warning("Hunter already running, ignoring duplicate start")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop(interval_seconds))
        logger.info("Hunter started (interval=%ds)", interval_seconds)

    async def stop(self):
        """Cancel the background task."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Hunter stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def _loop(self, interval: int):
        """Main loop: sweep then sleep."""
        while self._running:
            try:
                await self.sweep()
            except Exception as exc:
                logger.error(
                    "Hunter sweep failed: %s\n%s",
                    type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
                )
            await asyncio.sleep(interval)

    async def sweep(self):
        """One complete hunt cycle.

        Returns a list of flagged contract addresses.
        Never raises — sub-method exceptions are caught individually.
        """
        investigation_id = f"sweep-{int(time.time())}"
        logger.info("Hunter sweep started: %s", investigation_id)

        flagged = []

        # Phase 1: check watched deployers
        try:
            flagged += await self._check_watched_deployers(investigation_id)
        except Exception as exc:
            logger.error(
                "Hunter: _check_watched_deployers failed: %s\n%s",
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )

        # Phase 2: recheck WARN contracts
        try:
            flagged += await self._recheck_warn_contracts(investigation_id)
        except Exception as exc:
            logger.error(
                "Hunter: _recheck_warn_contracts failed: %s\n%s",
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )

        # Phase 3: discover and scan new Robinhood Chain launches
        try:
            flagged += await self._scan_new_pairs(investigation_id)
        except Exception as exc:
            logger.error(
                "Hunter: _scan_new_pairs failed: %s\n%s",
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )

        # Housekeeping: prune stale chat history (>24h)
        try:
            await self.db.prune_old_chats()
        except Exception as exc:
            logger.error(
                "Hunter: chat pruning failed: %s\n%s",
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )

        logger.info(
            "Hunter sweep %s complete: %d flagged", investigation_id, len(flagged)
        )
        return flagged

    # ------------------------------------------------------------------
    # Phase 1: Watched deployer check
    # ------------------------------------------------------------------

    async def _check_watched_deployers(self, investigation_id: str):
        """Check each watched deployer for new contracts not yet tracked.

        In a full implementation this would query BSCScan for recent
        deployer transactions. For now this is a hook point that
        iterates watched deployers without taking action.
        """
        flagged = []
        deployers = await self.db.get_watched_deployers()
        # Cap at 200 deployers per sweep to prevent resource exhaustion
        for d in deployers[:200]:
            try:
                # Future: query BSCScan for recent contract creations by this deployer
                # and scan any that aren't already tracked.
                pass
            except Exception as exc:
                logger.error(
                    "Hunter: error checking deployer %s: %s\n%s",
                    d.get("deployer_address"),
                    type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
                )
        return flagged

    # ------------------------------------------------------------------
    # Phase 2: Recheck WARN contracts
    # ------------------------------------------------------------------

    async def _recheck_warn_contracts(self, investigation_id: str):
        """Recheck contracts previously scored WARN (31-70). Cap at 20.

        Only a complete scan clears a contract; an incomplete one leaves it watching.
        """
        flagged = []
        pairs = await self.db.get_tracked_pairs(status="watching", limit=20)
        for pair in pairs:
            try:
                chain_id = pair.get("chain_id", 56)
                result = await self.tools.scan_contract(pair["token_address"], chain_id=chain_id)
                risk_score = result.get("risk_score", result.get("rug_probability"))

                if risk_score is not None and risk_score >= 71:
                    # Upgraded to BLOCK
                    await self.db.update_tracked_pair_status(
                        pair["pair_address"], "blocked"
                    )
                    if pair.get("deployer"):
                        await self.tools.auto_watch_deployer(
                            pair["deployer"],
                            reason=f"auto: recheck upgrade {pair['token_address']} (score={risk_score})",
                        )
                    await self._log_finding(
                        investigation_id,
                        pair["token_address"],
                        pair.get("deployer"),
                        risk_score,
                        result,
                        "blocked",
                        chain_id=chain_id,
                    )
                    flagged.append(pair["token_address"])
                elif risk_score is not None and risk_score <= 30 and not is_scan_incomplete(result):
                    # Cleared
                    await self.db.update_tracked_pair_status(
                        pair["pair_address"], "cleared"
                    )
                # else: still WARN, leave as watching
            except Exception as exc:
                logger.error(
                    "Hunter: error rechecking %s: %s\n%s", pair.get("token_address"),
                    type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
                )
        return flagged

    # ------------------------------------------------------------------
    # Phase 3: New Robinhood Chain launches
    # ------------------------------------------------------------------

    async def _scan_new_pairs(self, investigation_id: str):
        """Discover Robinhood Chain launches, then scan the newest unscanned ones.

        BSC pair monitoring is not implemented, and without a discovery service this
        phase does nothing. Launches that are not blocked or cleared by a complete scan
        are tracked as watching so the recheck phase revisits them on their own chain.
        """
        if self.discovery is None:
            return []
        try:
            await self.discovery.run()
        except Exception as exc:
            logger.error(
                "Hunter: launch discovery failed: %s\n%s",
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )

        flagged = []
        launches = await self.db.get_unscanned_launches(LAUNCH_CHAIN_ID, LAUNCH_SCANS_PER_SWEEP)
        for launch in launches:
            token = launch["token_address"]
            try:
                result = await self.tools.scan_contract(token, chain_id=LAUNCH_CHAIN_ID)
            except Exception as exc:
                logger.error(
                    "Hunter: error scanning launch %s: %s\n%s", token,
                    type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
                )
                await self.db.upsert_tracked_pair(token, token_address=token, chain_id=LAUNCH_CHAIN_ID)
                await self.db.record_launch_scan(LAUNCH_CHAIN_ID, token, "error", None)
                continue

            risk_score = result.get("risk_score", result.get("rug_probability"))
            if risk_score is not None and risk_score >= 71:
                status = "blocked"
                await self._log_finding(
                    investigation_id, token, None, risk_score, result, status, chain_id=LAUNCH_CHAIN_ID
                )
                flagged.append(token)
            elif risk_score is None or is_scan_incomplete(result):
                status = "unknown"
            elif risk_score <= 30:
                status = "cleared"
            else:
                status = "watching"
            if status in ("unknown", "watching"):
                await self.db.upsert_tracked_pair(token, token_address=token, chain_id=LAUNCH_CHAIN_ID)
            await self.db.record_launch_scan(LAUNCH_CHAIN_ID, token, status, risk_score)
        return flagged

    # ------------------------------------------------------------------
    # Finding logger
    # ------------------------------------------------------------------

    async def _log_finding(
        self, investigation_id, address, deployer, risk_score, evidence, action, chain_id=56
    ):
        """Store a finding and optionally generate AI narrative."""
        narrative = None
        if self.ai and self.ai.is_available():
            try:
                prompt = NARRATIVE_TEMPLATE.format(
                    data=json.dumps(evidence, default=str)
                )
                narrative = await self.ai.chat(
                    model=HAIKU_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=200,
                )
                narrative = narrative.strip()
            except Exception as exc:
                logger.warning(
                    "Hunter: AI narrative failed: %s\n%s",
                    type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
                )

        await self.db.insert_agent_finding(
            finding_type="hunter_sweep",
            investigation_id=investigation_id,
            address=address,
            deployer=deployer,
            chain_id=chain_id,
            risk_score=risk_score,
            narrative=narrative,
            evidence=evidence,
            action_taken=action,
        )
