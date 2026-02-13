"""
AI-Powered Contract Analysis using Claude API
Provides structured risk scoring, source code analysis, and contextual recommendations
"""

import os
import json
import logging
import anthropic
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """Claude AI-powered contract analysis with structured scoring"""

    def __init__(self):
        self.api_key = os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            logger.warning("ANTHROPIC_API_KEY not set - AI analysis disabled")
            self.client = None
        else:
            self.client = anthropic.AsyncAnthropic(api_key=self.api_key)

        # Use model available on this API key
        self.model = "claude-3-haiku-20240307"

    async def compute_ai_risk_score(self, address: str, scan_data: Dict) -> Optional[Dict]:
        """
        Get structured AI risk assessment with numeric score.

        Returns:
            dict with keys: risk_score (0-100), confidence (0-100),
            risk_level (str), key_findings (list), recommendation (str)
        """
        if not self.client:
            return None

        try:
            context = self._format_scan_data(scan_data)

            prompt = f"""You are a blockchain security analyst scoring a BNB Chain smart contract.

Address: {address}
Scan Data:
{context}

Return ONLY a JSON object (no markdown, no explanation) with this exact schema:
{{
  "risk_score": <0-100 integer, 0=safe 100=critical>,
  "confidence": <0-100 integer, how confident you are>,
  "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "key_findings": ["<finding1>", "<finding2>", "<finding3>"],
  "recommendation": "<one sentence action item>"
}}

Base your score on: verification status, contract age, scam DB matches, bytecode patterns, source code issues, ownership, and taxes."""

            message = await self.client.messages.create(
                model=self.model,
                max_tokens=400,
                messages=[{"role": "user", "content": prompt}]
            )

            raw = message.content[0].text.strip()
            # Strip markdown code fences if present
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
                if raw.endswith("```"):
                    raw = raw[:-3]
                raw = raw.strip()

            result = json.loads(raw)
            # Clamp values
            result["risk_score"] = max(0, min(100, int(result.get("risk_score", 50))))
            result["confidence"] = max(0, min(100, int(result.get("confidence", 50))))

            logger.info(f"AI risk score for {address}: {result['risk_score']}/100 (confidence: {result['confidence']}%)")
            return result

        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"AI risk score parse error: {e}")
            return None
        except Exception as e:
            logger.error(f"AI risk score failed: {e}")
            return None

    async def analyze_verified_source(self, address: str, source_code: str) -> Optional[Dict]:
        """
        AI analysis of verified Solidity source code for dangerous patterns.

        Returns:
            dict with keys: dangerous_patterns (list of dicts), severity (str), summary (str)
        """
        if not self.client:
            return None

        try:
            # Truncate source for API limits (first 12KB)
            source_sample = source_code[:12000] if len(source_code) > 12000 else source_code

            prompt = f"""Analyze this BNB Chain smart contract source code for dangerous patterns.

Address: {address}
Source Code:
```solidity
{source_sample}
```

Return ONLY a JSON object (no markdown):
{{
  "dangerous_patterns": [
    {{"pattern": "<name>", "severity": "<critical|high|medium|low>", "detail": "<explanation>"}}
  ],
  "severity": "<SAFE|WARNING|DANGER>",
  "summary": "<2 sentence summary>"
}}

Look for: honeypot mechanisms (blacklists, trading pauses, max tx traps), hidden mint functions, proxy upgradability, owner-only sell restrictions, fee manipulation, hidden approvals, self-destruct, and delegatecall to unknown addresses."""

            message = await self.client.messages.create(
                model=self.model,
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}]
            )

            raw = message.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
                if raw.endswith("```"):
                    raw = raw[:-3]
                raw = raw.strip()

            result = json.loads(raw)
            logger.info(f"AI source analysis for {address}: {result.get('severity', 'unknown')}")
            return result

        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"AI source analysis parse error: {e}")
            return None
        except Exception as e:
            logger.error(f"AI source analysis failed: {e}")
            return None

    async def analyze_contract_bytecode(self, address: str, bytecode: str, scan_results: Dict) -> Optional[str]:
        """
        Use Claude to analyze contract bytecode and provide natural language explanation.
        """
        if not self.client:
            return None

        try:
            context = self._prepare_scan_context(address, scan_results)
            bytecode_sample = bytecode[:8000] if len(bytecode) > 8000 else bytecode

            prompt = f"""You are a blockchain security expert analyzing a smart contract on BNB Chain.

Contract Address: {address}
Bytecode Sample (first 4KB): {bytecode_sample}

Scan Results from automated tools:
{context}

Based on the bytecode patterns and scan results, provide:
1. A clear risk assessment (HIGH/MEDIUM/LOW)
2. Specific vulnerabilities or concerns you identify
3. Explanation in simple terms for non-technical users
4. Actionable recommendation (interact/avoid/proceed with caution)

Keep response under 200 words, focused and actionable."""

            message = await self.client.messages.create(
                model=self.model,
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )

            return message.content[0].text

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return None

    async def analyze_token_safety(self, address: str, token_info: Dict, safety_results: Dict) -> Optional[str]:
        """
        Use Claude to analyze token safety and provide contextual recommendations.
        """
        if not self.client:
            return None

        try:
            context = self._prepare_token_context(address, token_info, safety_results)

            prompt = f"""You are a DeFi security expert analyzing a token on BNB Chain.

Token: {token_info.get('name', 'Unknown')} ({token_info.get('symbol', 'N/A')})
Address: {address}

Safety Check Results:
{context}

Provide:
1. Clear safety verdict (SAFE/WARNING/DANGER)
2. Key risks identified (honeypot, taxes, ownership, etc.)
3. Trading advice in simple terms
4. What users should check before buying

Keep response under 200 words, actionable for traders."""

            message = await self.client.messages.create(
                model=self.model,
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )

            return message.content[0].text

        except Exception as e:
            logger.error(f"AI token analysis failed: {e}")
            return None

    async def explain_findings(self, user_question: str, scan_context: Dict) -> Optional[str]:
        """Answer user questions about scan results using Claude."""
        if not self.client:
            return None

        try:
            prompt = f"""You are helping a user understand a smart contract security scan.

Scan Context: {scan_context}

User Question: {user_question}

Provide a clear, helpful answer in 2-3 sentences. Use simple language."""

            message = await self.client.messages.create(
                model=self.model,
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}]
            )

            return message.content[0].text

        except Exception as e:
            logger.error(f"AI explanation failed: {e}")
            return None

    def _format_scan_data(self, scan_data: Dict) -> str:
        """Format scan data dict into readable context string."""
        lines = []
        for key, value in scan_data.items():
            if key in ('ai_analysis', 'ai_risk_score', 'source_code'):
                continue  # skip large/recursive fields
            lines.append(f"- {key}: {value}")
        return "\n".join(lines)

    def _prepare_scan_context(self, address: str, scan_results: Dict) -> str:
        """Format scan results for Claude context"""
        return f"""
- Verified: {scan_results.get('is_verified', False)}
- Risk Level: {scan_results.get('risk_level', 'unknown').upper()}
- Contract Age: {scan_results.get('contract_age_days', 'unknown')} days
- Scam Database Matches: {len(scan_results.get('scam_matches', []))}
- Warnings: {', '.join(scan_results.get('warnings', [])) if scan_results.get('warnings') else 'None'}
"""

    def _prepare_token_context(self, address: str, token_info: Dict, safety_results: Dict) -> str:
        """Format token safety results for Claude context"""
        return f"""
- Token: {token_info.get('name', 'Unknown')} ({token_info.get('symbol', 'N/A')})
- Is Honeypot: {safety_results.get('is_honeypot', False)}
- Can Buy: {safety_results.get('checks', {}).get('can_buy', 'unknown')}
- Can Sell: {safety_results.get('checks', {}).get('can_sell', 'unknown')}
- Ownership Renounced: {safety_results.get('checks', {}).get('ownership_renounced', 'unknown')}
- Buy Tax: {safety_results.get('buy_tax', 0)}%
- Sell Tax: {safety_results.get('sell_tax', 0)}%
- Safety Level: {safety_results.get('safety_level', 'unknown').upper()}
- Risks: {', '.join(safety_results.get('risks', [])) if safety_results.get('risks') else 'None'}
"""

    def is_available(self) -> bool:
        """Check if AI analysis is available"""
        return self.client is not None
