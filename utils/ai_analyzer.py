"""
AI-Powered Contract Analysis using Claude API
Provides natural language risk explanations and contextual recommendations
"""

import os
import logging
import anthropic
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """Claude AI-powered contract analysis"""
    
    def __init__(self):
        self.api_key = os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            logger.warning("ANTHROPIC_API_KEY not set - AI analysis disabled")
            self.client = None
        else:
            self.client = anthropic.Anthropic(api_key=self.api_key)
    
    async def analyze_contract_bytecode(self, address: str, bytecode: str, scan_results: Dict) -> Optional[str]:
        """
        Use Claude to analyze contract bytecode and provide natural language explanation
        
        Args:
            address: Contract address
            bytecode: Contract bytecode (hex)
            scan_results: Results from traditional scanners
        
        Returns:
            Natural language risk analysis from Claude
        """
        if not self.client:
            return None
        
        try:
            # Prepare context for Claude
            context = self._prepare_scan_context(address, scan_results)
            
            # Truncate bytecode for API limits (first 4KB)
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

            message = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=500,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            ai_analysis = message.content[0].text
            logger.info(f"AI analysis generated for {address}")
            
            return ai_analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return None
    
    async def analyze_token_safety(self, address: str, token_info: Dict, safety_results: Dict) -> Optional[str]:
        """
        Use Claude to analyze token safety and provide contextual recommendations
        
        Args:
            address: Token address
            token_info: Token metadata (name, symbol, etc.)
            safety_results: Results from honeypot detection and safety checks
        
        Returns:
            Natural language safety analysis from Claude
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

            message = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=500,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            ai_analysis = message.content[0].text
            logger.info(f"AI token analysis generated for {address}")
            
            return ai_analysis
            
        except Exception as e:
            logger.error(f"AI token analysis failed: {e}")
            return None
    
    async def explain_findings(self, user_question: str, scan_context: Dict) -> Optional[str]:
        """
        Answer user questions about scan results using Claude
        
        Args:
            user_question: User's question about the scan
            scan_context: Full scan results context
        
        Returns:
            Natural language explanation from Claude
        """
        if not self.client:
            return None
        
        try:
            prompt = f"""You are helping a user understand a smart contract security scan.

Scan Context: {scan_context}

User Question: {user_question}

Provide a clear, helpful answer in 2-3 sentences. Use simple language."""

            message = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=300,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            explanation = message.content[0].text
            logger.info("AI explanation generated for user question")
            
            return explanation
            
        except Exception as e:
            logger.error(f"AI explanation failed: {e}")
            return None
    
    def _prepare_scan_context(self, address: str, scan_results: Dict) -> str:
        """Format scan results for Claude context"""
        context = f"""
- Verified: {scan_results.get('is_verified', False)}
- Risk Level: {scan_results.get('risk_level', 'unknown').upper()}
- Contract Age: {scan_results.get('contract_age_days', 'unknown')} days
- Scam Database Matches: {len(scan_results.get('scam_matches', []))}
- Warnings: {', '.join(scan_results.get('warnings', [])) if scan_results.get('warnings') else 'None'}
"""
        return context
    
    def _prepare_token_context(self, address: str, token_info: Dict, safety_results: Dict) -> str:
        """Format token safety results for Claude context"""
        context = f"""
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
        return context
    
    def is_available(self) -> bool:
        """Check if AI analysis is available"""
        return self.client is not None
