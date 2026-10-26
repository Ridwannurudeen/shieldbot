"""Advisor — conversational AI chat engine with intent routing.

Routes user messages to the appropriate tool pipeline, gathers context,
and streams responses through Claude for natural-language security analysis.
"""

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List, Tuple

import anthropic

from utils.chain_info import get_chain_name
from utils.web3_client import UnsupportedChainError
from utils.ai_analyzer import AIEmptyResponse, AIRefused

from agent.prompts import ADVISOR_SYSTEM_PROMPT, EXPLAIN_SCAN_TEMPLATE, HAIKU_MODEL, SONNET_MODEL
from core.chat_coverage import readable_coverage_gaps, unknown_reply

logger = logging.getLogger(__name__)

# Pre-compiled patterns for routing
_ADDRESS_RE = re.compile(r'0x[a-fA-F0-9]{40}')
_THREAT_RE = re.compile(
    r'\b(threat|alert|active|happening|danger|recent|found)\b',
    re.IGNORECASE,
)

AI_CHAT_PAUSED = (
    "AI chat is paused for today because the daily AI budget is used up. "
    "It resumes at 00:00 UTC."
)

# A scan without a verdict still carries its partial reading as a score and a level. The prompt forbids citing
# them; the model's view of such a scan leaves them out, so a number it never saw it cannot cite.
_SCORE_FIELDS = ("rug_probability", "risk_score", "risk_level", "risk_archetype", "category_scores", "confidence_level")


def _untagged(text: str) -> str:
    """Text that cannot open or close the <tool_results> and <user_message> tags around it.

    Token names come from DexScreener and messages are pasted text, so < and > are written as the
    JSON escapes \\u003c and \\u003e, which JSON tool data decodes back to the same characters.
    """
    return text.replace("<", "\\u003c").replace(">", "\\u003e")


def _utc_day() -> int:
    return int(time.time() // 86400)


class Advisor:
    """Intent-routing advisor backed by Claude for ShieldBot chat."""

    def __init__(self, tools, db, ai_analyzer, daily_token_budget: int):
        self.tools = tools
        self.db = db
        self.ai = ai_analyzer
        self.daily_token_budget = daily_token_budget
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
        self.tools._container.web3_client.validate_chain_id(chain_id)
        if intent == "CONTRACT_CHECK":
            addr = data["address"]
            scan, deployer, honeypot, market = await asyncio.gather(
                self.tools.scan_contract(addr, chain_id=chain_id),
                self.tools.check_deployer(addr, chain_id=chain_id),
                self.tools.check_honeypot(addr, chain_id=chain_id),
                self.tools.get_market_data(addr, chain_id=chain_id),
                return_exceptions=True,
            )
            for result in (scan, deployer, honeypot, market):
                if isinstance(result, UnsupportedChainError):
                    raise result
            if isinstance(scan, Exception):
                logger.warning("scan_contract failed: %s", type(scan).__name__)
                scan = {
                    "status": "unknown", "coverage": {},
                    "coverage_reasons": {"scan": "Contract scan unavailable"},
                }
            if isinstance(deployer, Exception):
                logger.warning("check_deployer failed: %s", type(deployer).__name__)
                deployer = {}
            if isinstance(honeypot, Exception):
                logger.warning("check_honeypot failed: %s", type(honeypot).__name__)
                honeypot = {}
            if isinstance(market, Exception):
                logger.warning("get_market_data failed: %s", type(market).__name__)
                market = {}
            context = {"scan": scan, "deployer": deployer, "honeypot": honeypot, "market": market}
            coverage_gaps = readable_coverage_gaps(scan.get("coverage_reasons", {}))
            if coverage_gaps:
                context["coverage_gaps"] = coverage_gaps
            return context

        if intent == "THREAT_FEED":
            try:
                return await self.tools.get_agent_findings(limit=10)
            except UnsupportedChainError:
                raise
            except Exception as e:
                logger.warning("get_agent_findings failed: %s", type(e).__name__)
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
        self.tools._container.web3_client.validate_chain_id(chain_id)
        chain_name = get_chain_name(chain_id)
        intent, data = self.route(message)
        history = await self.db.get_chat_history(user_id, limit=10)
        context = await self._gather_context(intent, data, chain_id=chain_id)

        # A scan the engine left without a verdict (status unknown): the model sees it without its scores, and
        # history keeps the Unknown reply the user is shown (api.agent_chat shapes the response the same way),
        # so a later turn cannot quote a score or verdict the user never received.
        unknown_scan = intent == "CONTRACT_CHECK" and context["scan"].get("status") == "unknown"

        # Build the user content — inject context when available.
        # Wrap in XML delimiters to mitigate prompt injection via API data; nothing inside can close them.
        if context:
            shown = context
            if unknown_scan:
                shown = {
                    **context,
                    "scan": {key: value for key, value in context["scan"].items() if key not in _SCORE_FIELDS},
                }
            user_content = (
                "<tool_results>\n"
                f"{_untagged(json.dumps(shown, default=str))}\n"
                "</tool_results>\n\n"
                f"<user_message>{_untagged(message)}</user_message>"
            )
        else:
            user_content = f"<user_message>{_untagged(message)}</user_message>"

        # Build messages list from history + new message; stored messages cannot open the tags either.
        messages: List[Dict] = []
        for entry in history:
            messages.append({
                "role": entry["role"],
                "content": _untagged(entry["message"]),
            })
        messages.append({"role": "user", "content": user_content})

        # Call AI or return fallback
        model_response_available = False
        if not self.ai.is_available():
            response_text = (
                "AI analysis is currently unavailable. "
                "Please try again later or check your API key configuration."
            )
        elif await self._ai_budget_spent():
            response_text = AI_CHAT_PAUSED
        else:
            try:
                response_text, tokens = await asyncio.wait_for(
                    self.ai.chat_with_usage(
                        model=self.sonnet_model,
                        messages=messages,
                        system=(
                            ADVISOR_SYSTEM_PROMPT
                            + f"\nCurrent chain: {chain_name} (chain_id={chain_id})."
                        ),
                        max_tokens=2000,
                    ),
                    timeout=30.0,
                )
            except asyncio.TimeoutError:
                logger.error("Advisor chat timed out after 30s")
                response_text = (
                    "The request timed out. Please try again."
                )
            except UnsupportedChainError:
                raise
            except AIRefused as e:
                logger.error("Advisor chat failed: %s", type(e).__name__)
                response_text = "The assistant declined to answer this request."
            except (
                anthropic.AuthenticationError,
                anthropic.PermissionDeniedError,
                anthropic.NotFoundError,
                anthropic.BadRequestError,
            ) as e:
                logger.error("Advisor chat failed: %s", type(e).__name__)
                response_text = (
                    "The assistant is unavailable: this deployment has no working language model "
                    "configured. Scanning, the transaction firewall and the on-chain guard do not use "
                    "it and are unaffected."
                )
            except (anthropic.RateLimitError, anthropic.APIConnectionError, AIEmptyResponse) as e:
                logger.error("Advisor chat failed: %s", type(e).__name__)
                response_text = "I encountered an error processing your request. Please try again."
            except anthropic.APIStatusError as error:
                logger.error("Advisor chat failed: %s", type(error).__name__)
                response_text = "I encountered an error processing your request. Please try again."
            except Exception as e:
                name = type(e).__name__
                logger.error("Advisor chat failed: %s", name)
                response_text = "I encountered an error processing your request. Please try again."
            else:
                model_response_available = True
                try:
                    await self.db.add_ai_tokens_used(_utc_day(), tokens)
                except Exception as e:
                    logger.error("AI token usage record failed: %s", type(e).__name__)

        # Persist both sides of the conversation; a paused reply would only crowd tomorrow's history
        if response_text != AI_CHAT_PAUSED:
            stored = response_text
            if unknown_scan:
                stored = unknown_reply(
                    context["scan"].get("coverage_reasons", {}),
                    response_text if model_response_available else "",
                )
            await self.db.insert_chat_message(user_id, "user", message)
            await self.db.insert_chat_message(user_id, "assistant", stored)

        result: Dict[str, Any] = {"text": response_text, "model_response_available": model_response_available}

        # Attach structured scan data for CONTRACT_CHECK intents
        if intent == "CONTRACT_CHECK" and isinstance(context, dict):
            scan = context.get("scan", {})
            if scan:
                result["scan_data"] = {
                    "chain_id": chain_id,
                    "chain_name": chain_name,
                    "address": data.get("address", ""),
                    "risk_score": scan.get("risk_score", scan.get("rug_probability")),
                    "risk_level": scan.get("risk_level"),
                    "archetype": scan.get("risk_archetype"),
                    "flags": scan.get("critical_flags", scan.get("flags", [])),
                    "confidence": scan.get("confidence"),
                    "status": scan.get("status"),
                    "coverage": scan.get("coverage", {}),
                    "coverage_reasons": scan.get("coverage_reasons", {}),
                    "honeypot": context.get("honeypot", {}),
                    "market": context.get("market", {}),
                    "impostor_check": scan.get("impostor_check"),
                }

        return result

    # ------------------------------------------------------------------
    # 4. Explain scan (async, calls Haiku)
    # ------------------------------------------------------------------

    async def explain_scan(self, scan_result: dict) -> str:
        """Generate a plain-English explanation of a scan result.

        Uses Haiku for speed. Falls back to rule-based if AI is disabled, today's budget is spent
        or the budget store fails.
        """
        if not self.ai.is_available():
            return self._rule_based_explanation(scan_result)

        prompt = EXPLAIN_SCAN_TEMPLATE.format(
            data=json.dumps(scan_result, default=str)
        )

        try:
            if await self._ai_budget_spent():
                return self._rule_based_explanation(scan_result)
            explanation, tokens = await self.ai.chat_with_usage(
                model=self.haiku_model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300,
            )
            await self.db.add_ai_tokens_used(_utc_day(), tokens)
            return explanation
        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Advisor explain_scan failed: %s", type(e).__name__)
            return self._rule_based_explanation(scan_result)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _ai_budget_spent(self) -> bool:
        """Whether today's AI token budget, shared by chat and explanations, is used up."""
        return await self.db.get_ai_tokens_used(_utc_day()) >= self.daily_token_budget

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
