"""Hunter — scheduled proactive threat sweep loop for ShieldBot's AI agent.

Runs periodic sweeps that:
1. Check watched deployers for new contracts
2. Recheck contracts previously scored WARN (31-70)
3. Scan new PancakeSwap pairs (placeholder for future implementation)

For any flagged contract: auto-watches the deployer, generates an AI threat
narrative (when available), and stores the finding.

Every public method is wrapped in try/except so it never crashes the caller.
"""

import asyncio
import json
import logging
import time

from agent.prompts import NARRATIVE_TEMPLATE

logger = logging.getLogger(__name__)


class Hunter:
    """Proactive scheduled threat sweeps."""

    def __init__(self, tools, db, ai_analyzer, sentinel):
        self.tools = tools
        self.db = db
        self.ai = ai_analyzer
        self.sentinel = sentinel
        self._task = None  # asyncio.Task for background loop
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, interval_seconds: int = 1800):
        """Start the background sweep loop (default: every 30 min)."""
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
            except Exception:
                logger.exception("Hunter sweep failed")
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
        except Exception:
            logger.exception("Hunter: _check_watched_deployers failed")

        # Phase 2: recheck WARN contracts
        try:
            flagged += await self._recheck_warn_contracts(investigation_id)
        except Exception:
            logger.exception("Hunter: _recheck_warn_contracts failed")

        # Phase 3: scan new PancakeSwap pairs (placeholder)
        try:
            flagged += await self._scan_new_pairs(investigation_id)
        except Exception:
            logger.exception("Hunter: _scan_new_pairs failed")

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
        for d in deployers:
            try:
                # Future: query BSCScan for recent contract creations by this deployer
                # and scan any that aren't already tracked.
                pass
            except Exception:
                logger.exception(
                    "Hunter: error checking deployer %s",
                    d.get("deployer_address"),
                )
        return flagged

    # ------------------------------------------------------------------
    # Phase 2: Recheck WARN contracts
    # ------------------------------------------------------------------

    async def _recheck_warn_contracts(self, investigation_id: str):
        """Recheck contracts previously scored WARN (31-70). Cap at 20."""
        flagged = []
        pairs = await self.db.get_tracked_pairs(status="watching", limit=20)
        for pair in pairs:
            try:
                result = await self.tools.scan_contract(pair["token_address"])
                risk_score = result.get("risk_score", 0)

                if risk_score >= 71:
                    # Upgraded to BLOCK
                    await self.db.update_tracked_pair_status(
                        pair["pair_address"], "blocked"
                    )
                    await self.tools.auto_watch_deployer(
                        pair.get("deployer", "unknown"),
                        reason=f"auto: recheck upgrade {pair['token_address']} (score={risk_score})",
                    )
                    await self._log_finding(
                        investigation_id,
                        pair["token_address"],
                        pair.get("deployer"),
                        risk_score,
                        result,
                        "blocked",
                    )
                    flagged.append(pair["token_address"])
                elif risk_score <= 30:
                    # Cleared
                    await self.db.update_tracked_pair_status(
                        pair["pair_address"], "cleared"
                    )
                # else: still WARN, leave as watching
            except Exception:
                logger.exception(
                    "Hunter: error rechecking %s", pair.get("token_address")
                )
        return flagged

    # ------------------------------------------------------------------
    # Phase 3: New PancakeSwap pairs (placeholder)
    # ------------------------------------------------------------------

    async def _scan_new_pairs(self, investigation_id: str):
        """Placeholder for PancakeSwap pair monitoring.

        Full implementation will watch PancakeSwap Factory PairCreated events.
        For now, returns empty list.
        """
        return []

    # ------------------------------------------------------------------
    # Finding logger
    # ------------------------------------------------------------------

    async def _log_finding(
        self, investigation_id, address, deployer, risk_score, evidence, action
    ):
        """Store a finding and optionally generate AI narrative."""
        narrative = None
        if self.ai and getattr(self.ai, "client", None) is not None:
            try:
                prompt = NARRATIVE_TEMPLATE.format(
                    data=json.dumps(evidence, default=str)
                )
                message = await self.ai.client.messages.create(
                    model="claude-3-haiku-20240307",
                    max_tokens=200,
                    messages=[{"role": "user", "content": prompt}],
                )
                narrative = message.content[0].text.strip()
            except Exception:
                logger.warning("Hunter: AI narrative failed", exc_info=True)

        await self.db.insert_agent_finding(
            finding_type="hunter_sweep",
            investigation_id=investigation_id,
            address=address,
            deployer=deployer,
            chain_id=56,
            risk_score=risk_score,
            narrative=narrative,
            evidence=evidence,
            action_taken=action,
        )
