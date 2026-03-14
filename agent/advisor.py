"""Advisor — conversational AI chat engine with intent routing.

Routes user messages to the appropriate tool pipeline, gathers context,
and streams responses through Claude for natural-language security analysis.
"""

import json
import logging
import re
from typing import Dict, List, Tuple

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

    async def _gather_context(self, intent: str, data: dict):
        """Gather tool-sourced context based on the routed intent.

        Returns a dict or list depending on intent.
        """
        if intent == "CONTRACT_CHECK":
            scan = await self.tools.scan_contract(data["address"])
            deployer = await self.tools.check_deployer(data["address"])
            return {"scan": scan, "deployer": deployer}

        if intent == "THREAT_FEED":
            return await self.tools.get_agent_findings(limit=10)

        return {}

    # ------------------------------------------------------------------
    # 3. Chat (async, calls Claude)
    # ------------------------------------------------------------------

    async def chat(self, user_id: str, message: str) -> str:
        """Process a user chat message end-to-end.

        1. Route the message to an intent
        2. Load chat history
        3. Gather tool context
        4. Build messages list for Claude
        5. Call Claude Sonnet
        6. Save user + assistant messages
        7. Return response text
        """
        intent, data = self.route(message)
        history = await self.db.get_chat_history(user_id, limit=10)
        context = await self._gather_context(intent, data)

        # Build the user content — inject context when available
        if context:
            user_content = (
                f"[ShieldBot Data]: {json.dumps(context, default=str)}\n\n"
                f"User question: {message}"
            )
        else:
            user_content = message

        # Build messages list from history + new message
        messages: List[Dict] = []
        for entry in history:
            messages.append({
                "role": entry["role"],
                "content": entry["message"],
            })
        messages.append({"role": "user", "content": user_content})

        # Call Claude or return fallback
        if self.ai.client is None:
            response_text = (
                "AI analysis is currently unavailable. "
                "Please try again later or check your API key configuration."
            )
        else:
            try:
                response = await self.ai.client.messages.create(
                    model=self.sonnet_model,
                    max_tokens=500,
                    system=ADVISOR_SYSTEM_PROMPT,
                    messages=messages,
                )
                response_text = response.content[0].text
            except Exception as e:
                logger.error(f"Advisor chat failed: {e}")
                response_text = (
                    "I encountered an error processing your request. "
                    "Please try again."
                )

        # Persist both sides of the conversation
        await self.db.insert_chat_message(user_id, "user", message)
        await self.db.insert_chat_message(user_id, "assistant", response_text)

        return response_text

    # ------------------------------------------------------------------
    # 4. Explain scan (async, calls Haiku)
    # ------------------------------------------------------------------

    async def explain_scan(self, scan_result: dict) -> str:
        """Generate a plain-English explanation of a scan result.

        Uses Haiku for speed. Falls back to rule-based if AI is disabled.
        """
        if self.ai.client is None:
            return self._rule_based_explanation(scan_result)

        prompt = EXPLAIN_SCAN_TEMPLATE.format(
            data=json.dumps(scan_result, default=str)
        )

        try:
            response = await self.ai.client.messages.create(
                model=self.haiku_model,
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Advisor explain_scan failed: {e}")
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
