"""Sentinel — event-driven feedback loop for ShieldBot's AI agent.

Listens for scan events (blocked contracts, mempool alerts, deployer flags)
and takes autonomous follow-up actions: auto-watching deployers, logging
findings, and generating threat narratives.

Every public method is wrapped in try/except so it never crashes the caller.
"""

import json
import logging
from typing import Optional

from agent.prompts import HAIKU_MODEL, NARRATIVE_TEMPLATE

logger = logging.getLogger(__name__)


class Sentinel:
    """Reactive event handlers that close the feedback loop."""

    def __init__(self, tools, db, ai_analyzer):
        self.tools = tools
        self.db = db
        self.ai = ai_analyzer

    # ------------------------------------------------------------------
    # Event: a user scan returned BLOCK
    # ------------------------------------------------------------------

    async def on_scan_blocked(
        self,
        address: str,
        deployer: Optional[str],
        chain_id: int,
        risk_score: float,
    ) -> None:
        """Auto-watch the deployer when a contract is blocked with high risk.

        Skips silently if risk_score < 71 or deployer is unknown.
        Never raises — all exceptions are caught and logged.
        """
        try:
            if risk_score < 71 or deployer is None:
                return

            await self.tools.auto_watch_deployer(
                deployer,
                reason=f"auto: blocked {address} (score={risk_score})",
                chain_id=chain_id,
            )

            await self.db.insert_agent_finding(
                finding_type="sentinel_event",
                address=address,
                deployer=deployer,
                chain_id=chain_id,
                risk_score=risk_score,
                action_taken="watched",
            )

            logger.info(
                "Sentinel: auto-watching deployer %s after blocking %s",
                deployer,
                address,
            )

        except Exception:
            logger.exception("Sentinel.on_scan_blocked failed (non-fatal)")

    # ------------------------------------------------------------------
    # Event: mempool monitor detected suspicious activity
    # ------------------------------------------------------------------

    async def on_mempool_alert(self, alert_data: dict) -> None:
        """Store a mempool alert as an agent finding, optionally with AI narrative."""
        try:
            narrative = None

            # Generate a short threat narrative via Haiku if AI is available
            if self.ai and getattr(self.ai, "client", None) is not None:
                try:
                    prompt = NARRATIVE_TEMPLATE.format(data=json.dumps(alert_data, default=str))
                    message = await self.ai.client.messages.create(
                        model=HAIKU_MODEL,
                        max_tokens=200,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    narrative = message.content[0].text.strip()
                except Exception:
                    logger.warning("Sentinel: AI narrative generation failed", exc_info=True)

            await self.db.insert_agent_finding(
                finding_type="mempool_alert",
                address=alert_data.get("address"),
                deployer=alert_data.get("deployer"),
                chain_id=alert_data.get("chain_id", 56),
                risk_score=alert_data.get("risk_score"),
                narrative=narrative,
                evidence=alert_data,
                action_taken=alert_data.get("action"),
            )

            logger.info("Sentinel: mempool alert logged for %s", alert_data.get("address"))

        except Exception:
            logger.exception("Sentinel.on_mempool_alert failed (non-fatal)")

    # ------------------------------------------------------------------
    # Event: a watched deployer deployed a new contract
    # ------------------------------------------------------------------

    async def on_deployer_flagged(
        self,
        deployer: str,
        new_contract: str,
        chain_id: int,
    ) -> None:
        """Scan a new contract from a watched deployer and log the result."""
        try:
            result = await self.tools.scan_contract(new_contract, chain_id)
            risk_score = result.get("risk_score", 0)
            action = "blocked" if risk_score >= 71 else "watched"

            await self.db.insert_agent_finding(
                finding_type="deployer_flagged",
                address=new_contract,
                deployer=deployer,
                chain_id=chain_id,
                risk_score=risk_score,
                action_taken=action,
                evidence=result,
            )

            logger.info(
                "Sentinel: deployer %s new contract %s scored %s → %s",
                deployer,
                new_contract,
                risk_score,
                action,
            )

        except Exception:
            logger.exception("Sentinel.on_deployer_flagged failed (non-fatal)")
