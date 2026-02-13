"""
AI-Powered Contract Analysis using Claude API
Provides structured risk scoring, source code analysis, and contextual recommendations
"""

import os
import json
import logging
import anthropic
from typing import Dict, Optional
from utils.firewall_prompt import FIREWALL_SYSTEM_PROMPT

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

    async def generate_forensic_report(self, address: str, scan_data: Dict, scan_type: str) -> Optional[str]:
        """
        Generate a unified ShieldAI forensic report from all scan data.
        Returns a pre-formatted Telegram-ready Markdown string, or None on failure.
        """
        if not self.client:
            return None

        try:
            context = self._build_forensic_context(address, scan_data, scan_type)

            system_prompt = """You are ShieldAI — an autonomous blockchain forensic intelligence agent deployed on BNB Chain.

Your mission: Analyze the provided on-chain scan data and produce a structured forensic security report. You speak with authority, precision, and zero fluff.

OUTPUT FORMAT — use Telegram Markdown (** for bold, ` for inline code). Follow this exact structure:

🛡️ **SHIELDAI FORENSIC REPORT**
━━━━━━━━━━━━━━━━━━━━

📍 **Target:** `<address>`
🔎 **Scan Type:** <Contract Security / Token Safety>
⏱️ **Status:** Complete

━━━━━━━━━━━━━━━━━━━━
🚨 **THREAT ASSESSMENT**

**Risk Score:** <X>/100 — <CRITICAL / HIGH / MODERATE / LOW>
**Confidence:** <X>%

<1-2 sentence threat summary based on the data>

━━━━━━━━━━━━━━━━━━━━
🔴 **CRITICAL SIGNALS**

<Bullet list of the most dangerous findings. If none, write "No critical signals detected.">

━━━━━━━━━━━━━━━━━━━━
💧 **LIQUIDITY & LP ANALYSIS**

<Liquidity lock status, percentage, rug pull risk. For contract scans without LP data, note "N/A — contract-level scan">

━━━━━━━━━━━━━━━━━━━━
📋 **CONTRACT GOVERNANCE**

<Verification status, ownership, proxy patterns, dangerous functions, contract age>

━━━━━━━━━━━━━━━━━━━━
💰 **TRADE SIMULATION**

<Buy/sell tax, honeypot status, transfer restrictions. For contract scans, note "N/A — use /token for trade analysis">

━━━━━━━━━━━━━━━━━━━━
🧠 **INVESTIGATOR'S NOTE**

<2-3 sentences of expert-level contextual analysis. Connect the dots between findings. Mention what a sophisticated attacker could exploit.>

━━━━━━━━━━━━━━━━━━━━
📊 **INVESTOR SUMMARY**

<1-2 sentences in plain language for non-technical users>

━━━━━━━━━━━━━━━━━━━━
⚖️ **FINAL VERDICT**

<One of: 🟢 CLEARED — Low risk | 🟡 CAUTION — Moderate risk, proceed carefully | 🔴 AVOID — High risk | 🚨 CRITICAL — Do not interact>

RULES:
- Use ONLY the data provided. Do not hallucinate findings.
- Risk score weights: scam DB match = critical, honeypot = critical, unverified + new = high, high taxes = moderate, ownership not renounced = moderate, suspicious bytecode = high
- Keep total output under 600 words
- No HTML tags — only Telegram Markdown"""

            user_message = f"""Scan data for forensic analysis:

{context}

Generate the ShieldAI forensic report now."""

            message = await self.client.messages.create(
                model=self.model,
                max_tokens=1200,
                messages=[
                    {"role": "user", "content": system_prompt + "\n\n" + user_message}
                ]
            )

            report = message.content[0].text.strip()
            logger.info(f"Forensic report generated for {address}")
            return report

        except Exception as e:
            logger.error(f"Forensic report generation failed: {e}")
            return None

    def _build_forensic_context(self, address: str, data: Dict, scan_type: str) -> str:
        """Build structured context string from scan data for the forensic prompt."""
        lines = [
            f"Address: {address}",
            f"Scan Type: {scan_type}",
            f"Risk Score (heuristic): {data.get('risk_score', 'N/A')}/100",
            f"Confidence: {data.get('confidence', 'N/A')}%",
            f"Risk Level: {data.get('risk_level', data.get('safety_level', 'unknown'))}",
        ]

        # Contract info
        if 'is_verified' in data:
            lines.append(f"Contract Verified: {data['is_verified']}")
        if 'is_contract' in data:
            lines.append(f"Is Contract: {data['is_contract']}")
        if 'contract_age_days' in data:
            lines.append(f"Contract Age: {data['contract_age_days']} days")

        # Token info
        if data.get('name'):
            lines.append(f"Token Name: {data['name']}")
        if data.get('symbol'):
            lines.append(f"Token Symbol: {data['symbol']}")
        if data.get('total_supply'):
            lines.append(f"Total Supply: {data['total_supply']}")

        # Honeypot & taxes
        if 'is_honeypot' in data:
            lines.append(f"Is Honeypot: {data['is_honeypot']}")
        if data.get('buy_tax') is not None:
            lines.append(f"Buy Tax: {data['buy_tax']}%")
        if data.get('sell_tax') is not None:
            lines.append(f"Sell Tax: {data['sell_tax']}%")

        # Checks
        checks = data.get('checks', {})
        if checks:
            lines.append("Security Checks:")
            for k, v in checks.items():
                status = "PASS" if v is True else ("FAIL" if v is False else "UNKNOWN")
                lines.append(f"  - {k.replace('_', ' ').title()}: {status}")

        # Warnings / risks
        warnings = data.get('warnings', [])
        if warnings:
            lines.append("Warnings:")
            for w in warnings:
                lines.append(f"  - {w}")

        risks = data.get('risks', [])
        if risks:
            lines.append("Risks:")
            for r in risks:
                lines.append(f"  - {r}")

        # Scam DB
        scam_matches = data.get('scam_matches', [])
        if scam_matches:
            lines.append(f"Scam Database Matches: {len(scam_matches)}")
            for m in scam_matches[:5]:
                lines.append(f"  - {m.get('type', 'unknown')}: {m.get('reason', 'N/A')}")
        else:
            lines.append("Scam Database Matches: 0")

        # Source code patterns
        patterns = data.get('source_code_patterns', [])
        if patterns:
            lines.append("Source Code Patterns Detected:")
            for p in patterns:
                lines.append(f"  - [{p['severity'].upper()}] {p['message']}")

        # Liquidity
        if 'liquidity_lock_percentage' in data:
            lines.append(f"Liquidity Lock: {data['liquidity_lock_percentage']}%")
        if 'owner' in data:
            lines.append(f"Contract Owner: {data['owner']}")

        return "\n".join(lines)

    async def generate_firewall_report(self, tx_data: Dict, contract_scan: Dict) -> Optional[Dict]:
        """
        Generate a firewall analysis report for the Chrome extension.
        Returns structured JSON (not markdown) for the extension to render.

        Args:
            tx_data: Transaction data including decoded calldata info
            contract_scan: Results from scanning the target contract

        Returns:
            dict matching the firewall response schema, or None on failure
        """
        if not self.client:
            return None

        try:
            context = self._build_firewall_context(tx_data, contract_scan)

            user_message = f"""Analyze this pending BNB Chain transaction:

{context}

Return the firewall analysis JSON now."""

            message = await self.client.messages.create(
                model=self.model,
                max_tokens=800,
                messages=[
                    {"role": "user", "content": FIREWALL_SYSTEM_PROMPT + "\n\n" + user_message}
                ]
            )

            raw = message.content[0].text.strip()
            # Strip markdown code fences if present
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
                if raw.endswith("```"):
                    raw = raw[:-3]
                raw = raw.strip()

            result = json.loads(raw)

            # Validate and clamp
            result["risk_score"] = max(0, min(100, int(result.get("risk_score", 50))))
            valid_classifications = {"BLOCK_RECOMMENDED", "HIGH_RISK", "CAUTION", "SAFE"}
            if result.get("classification") not in valid_classifications:
                result["classification"] = "CAUTION"
            if not isinstance(result.get("danger_signals"), list):
                result["danger_signals"] = []

            logger.info(
                f"Firewall report: {result['classification']} "
                f"(score {result['risk_score']}) for tx to {tx_data.get('to', 'unknown')}"
            )
            return result

        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Firewall report parse error: {e}")
            return None
        except Exception as e:
            logger.error(f"Firewall report failed: {e}")
            return None

    def _build_firewall_context(self, tx_data: Dict, contract_scan: Dict) -> str:
        """Build context string for the firewall prompt."""
        lines = [
            "=== TRANSACTION DATA ===",
            f"From: {tx_data.get('from', 'unknown')}",
            f"To: {tx_data.get('to', 'unknown')}",
            f"Value: {tx_data.get('value', '0')} wei",
            f"Chain ID: {tx_data.get('chainId', 56)}",
        ]

        # Decoded calldata
        decoded = tx_data.get("decoded_calldata", {})
        if decoded:
            lines.append(f"\n=== CALLDATA ANALYSIS ===")
            lines.append(f"Function: {decoded.get('function_name', 'unknown')}")
            lines.append(f"Signature: {decoded.get('signature', 'N/A')}")
            lines.append(f"Category: {decoded.get('category', 'unknown')}")
            lines.append(f"Is Approval: {decoded.get('is_approval', False)}")
            lines.append(f"Is Unlimited Approval: {decoded.get('is_unlimited_approval', False)}")
            if decoded.get("token_symbol"):
                lines.append(f"Token: {decoded.get('token_name', '')} ({decoded['token_symbol']})")
            if decoded.get("formatted_amount"):
                lines.append(f"Formatted Amount: {decoded['formatted_amount']}")
            if decoded.get("spender_label"):
                lines.append(f"Spender: {decoded['spender_label']}")
            if decoded.get("disguised_warning"):
                lines.append(f"DISGUISED CALL WARNING: {decoded['disguised_warning']}")
            params = decoded.get("params", {})
            if params:
                lines.append("Parameters:")
                for k, v in params.items():
                    lines.append(f"  {k}: {v}")

        # Whitelisted router
        router = tx_data.get("whitelisted_router")
        if router:
            lines.append(f"\nTarget is WHITELISTED ROUTER: {router}")

        # Contract scan results
        lines.append(f"\n=== CONTRACT SCAN ({tx_data.get('to', 'unknown')}) ===")
        lines.append(f"Is Contract: {contract_scan.get('is_contract', 'unknown')}")
        lines.append(f"Is Verified: {contract_scan.get('is_verified', False)}")
        lines.append(f"Contract Age: {contract_scan.get('contract_age_days', 'unknown')} days")
        lines.append(f"Scam DB Matches: {len(contract_scan.get('scam_matches', []))}")
        lines.append(f"Risk Score (heuristic): {contract_scan.get('risk_score', 'N/A')}/100")

        # Token-specific data
        if contract_scan.get('is_honeypot') is not None:
            lines.append(f"Is Honeypot: {contract_scan.get('is_honeypot', False)}")
        if contract_scan.get('buy_tax') is not None:
            lines.append(f"Buy Tax: {contract_scan.get('buy_tax', 0)}%")
        if contract_scan.get('sell_tax') is not None:
            lines.append(f"Sell Tax: {contract_scan.get('sell_tax', 0)}%")

        ownership = contract_scan.get('checks', {}).get('ownership_renounced')
        if ownership is not None:
            lines.append(f"Ownership Renounced: {ownership}")

        warnings = contract_scan.get('warnings', [])
        if warnings:
            lines.append("Warnings:")
            for w in warnings[:8]:
                lines.append(f"  - {w}")

        scam_matches = contract_scan.get('scam_matches', [])
        if scam_matches:
            lines.append("Scam Matches:")
            for m in scam_matches[:5]:
                lines.append(f"  - {m.get('type', 'unknown')}: {m.get('reason', 'N/A')}")

        return "\n".join(lines)

    def is_available(self) -> bool:
        """Check if AI analysis is available"""
        return self.client is not None
