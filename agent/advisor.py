"""Advisor — conversational AI chat engine with intent routing.

Routes user messages to the appropriate tool pipeline, gathers context,
and streams responses through Claude for natural-language security analysis.
"""

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from agent.prompts import ADVISOR_SYSTEM_PROMPT, EXPLAIN_SCAN_TEMPLATE, HAIKU_MODEL, SONNET_MODEL

logger = logging.getLogger(__name__)

# Pre-compiled patterns for routing
_ADDRESS_RE = re.compile(r'0x[a-fA-F0-9]{40}')
_THREAT_RE = re.compile(
    r'\b(threat|alert|active|happening|danger|recent|found)\b',
    re.IGNORECASE,
)


class Advisor:
    """Intent-routing advisor backed by Claude for ShieldBot chat."""

    def __init__(self, tools, db, ai_analyzer):
        self.tools = tools
        self.db = db
        self.ai = ai_analyzer
        self.sonnet_model = SONNET_MODEL
        self.haiku_model = HAIKU_MODEL

    # ------------------------------------------------------------------
    # 1. Intent routing (sync, no LLM)
    # ------------------------------------------------------------------

    def route(self, message: str) -> Tuple[str, dict]:
        """Classify a user message into an intent + extracted data.

        Returns:
            ("CONTRACT_CHECK", {"address": "0x..."})
            ("THREAT_FEED", {})
            ("GENERAL", {})
        """
        addr_match = _ADDRESS_RE.search(message)
        if addr_match:
            return ("CONTRACT_CHECK", {"address": addr_match.group()})

        if _THREAT_RE.search(message):
            return ("THREAT_FEED", {})

        return ("GENERAL", {})

    # ------------------------------------------------------------------
    # 2. Context gathering (async, calls tools)
    # ------------------------------------------------------------------

    async def _gather_context(self, intent: str, data: dict, chain_id: int = 56):
        """Gather tool-sourced context based on the routed intent.

        Returns a dict or list depending on intent.
        """
        if intent == "CONTRACT_CHECK":
            addr = data["address"]
            scan, deployer, honeypot, market = await asyncio.gather(
                self.tools.scan_contract(addr, chain_id=chain_id),
                self.tools.check_deployer(addr, chain_id=chain_id),
                self.tools.check_honeypot(addr, chain_id=chain_id),
                self.tools.get_market_data(addr, chain_id=chain_id),
                return_exceptions=True,
            )
            if isinstance(scan, Exception):
                logger.warning("scan_contract failed: %s", scan)
                scan = {}
            if isinstance(deployer, Exception):
                logger.warning("check_deployer failed: %s", deployer)
                deployer = {}
            if isinstance(honeypot, Exception):
                logger.warning("check_honeypot failed: %s", honeypot)
                honeypot = {}
            if isinstance(market, Exception):
                logger.warning("get_market_data failed: %s", market)
                market = {}
            return {"scan": scan, "deployer": deployer, "honeypot": honeypot, "market": market}

        if intent == "THREAT_FEED":
            try:
                return await self.tools.get_agent_findings(limit=10)
            except Exception as e:
                logger.warning("get_agent_findings failed: %s", e)
                return []

        return {}

    # ------------------------------------------------------------------
    # 3. Chat (async, calls Claude)
    # ------------------------------------------------------------------

    async def chat(self, user_id: str, message: str, chain_id: int = 56) -> Dict[str, Any]:
        """Process a user chat message end-to-end.

        1. Route the message to an intent
        2. Load chat history
        3. Gather tool context
        4. Build messages list for Claude
        5. Call Claude Sonnet
        6. Save user + assistant messages
        7. Return {"text": str, "scan_data": optional dict}
        """
        intent, data = self.route(message)
        history = await self.db.get_chat_history(user_id, limit=10)
        context = await self._gather_context(intent, data, chain_id=chain_id)

        # Build the user content — inject context when available.
        # Wrap in XML delimiters to mitigate prompt injection via API data.
        if context:
            user_content = (
                "<tool_results>\n"
                f"{json.dumps(context, default=str)}\n"
                "</tool_results>\n\n"
                f"<user_message>{message}</user_message>"
            )
        else:
            user_content = f"<user_message>{message}</user_message>"

        # Build messages list from history + new message
        messages: List[Dict] = []
        for entry in history:
            messages.append({
                "role": entry["role"],
                "content": entry["message"],
            })
        messages.append({"role": "user", "content": user_content})

        # Call AI or return fallback
        if not self.ai.is_available():
            response_text = (
                "AI analysis is currently unavailable. "
                "Please try again later or check your API key configuration."
            )
        else:
            try:
                response_text = await asyncio.wait_for(
                    self.ai.chat(
                        model=self.sonnet_model,
                        messages=messages,
                        system=ADVISOR_SYSTEM_PROMPT,
                        max_tokens=500,
                    ),
                    timeout=30.0,
                )
            except asyncio.TimeoutError:
                logger.error("Advisor chat timed out after 30s")
                response_text = (
                    "The request timed out. Please try again."
                )
            except Exception as e:
                logger.error("Advisor chat failed: %s", e)
                response_text = (
                    "I encountered an error processing your request. "
                    "Please try again."
                )

        # Persist both sides of the conversation
        await self.db.insert_chat_message(user_id, "user", message)
        await self.db.insert_chat_message(user_id, "assistant", response_text)

        result: Dict[str, Any] = {"text": response_text}

        # Attach structured scan data for CONTRACT_CHECK intents
        if intent == "CONTRACT_CHECK" and isinstance(context, dict):
            scan = context.get("scan", {})
            if scan:
                result["scan_data"] = {
                    "address": data.get("address", ""),
                    "risk_score": scan.get("risk_score", scan.get("rug_probability")),
                    "risk_level": scan.get("risk_level"),
                    "archetype": scan.get("risk_archetype"),
                    "flags": scan.get("critical_flags", scan.get("flags", [])),
                    "confidence": scan.get("confidence"),
                    "honeypot": context.get("honeypot", {}),
                    "market": context.get("market", {}),
                }

        return result

    # ------------------------------------------------------------------
    # 4. Explain scan (async, calls Haiku)
    # ------------------------------------------------------------------

    async def explain_scan(self, scan_result: dict) -> str:
        """Generate a plain-English explanation of a scan result.

        Uses Haiku for speed. Falls back to rule-based if AI is disabled.
        """
        if not self.ai.is_available():
            return self._rule_based_explanation(scan_result)

        prompt = EXPLAIN_SCAN_TEMPLATE.format(
            data=json.dumps(scan_result, default=str)
        )

        try:
            return await self.ai.chat(
                model=self.haiku_model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300,
            )
        except Exception as e:
            logger.error("Advisor explain_scan failed: %s", e)
            return self._rule_based_explanation(scan_result)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rule_based_explanation(scan_result: dict) -> str:
        """Simple rule-based fallback when AI is unavailable."""
        score = scan_result.get("risk_score", 50)
        level = scan_result.get("risk_level", "UNKNOWN")

        if score >= 70:
            return (
                f"This contract has a high risk score of {score}/100 "
                f"(level: {level}). It shows dangerous patterns and "
                "interacting with it is not recommended."
            )
        if score >= 40:
            return (
                f"This contract has a moderate risk score of {score}/100 "
                f"(level: {level}). Exercise caution and verify details "
                "before interacting."
            )
        return (
            f"This contract has a low risk score of {score}/100 "
            f"(level: {level}). No major red flags were detected, "
            "but always do your own research."
        )
