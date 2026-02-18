"""Signature/Permit Analyzer — detects dangerous EIP-712 typed data signatures."""

import logging
from typing import Dict, List, Optional

from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult

logger = logging.getLogger(__name__)

# Maximum uint256 — signals unlimited approval
MAX_UINT256 = (1 << 256) - 1
UNLIMITED_THRESHOLD = 10**30

# Far-future deadline: > 1 year from now (seconds)
FAR_FUTURE_SECONDS = 365 * 24 * 3600

# Known safe Permit2 spenders (Uniswap ecosystem)
KNOWN_PERMIT2_SPENDERS = {
    "0x000000000022d473030f116ddee9f6b43ac78ba3".lower(): "Uniswap Permit2",
    "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".lower(): "Uniswap Universal Router",
}


class SignaturePermitAnalyzer(Analyzer):
    """Analyzes EIP-712 typed data for dangerous permit/signature patterns.

    Parses typed data from ctx.extra['typed_data'] for:
    - EIP-2612 Permit: flags unlimited value, unknown spender, far-future deadline
    - Permit2 (PermitSingle/PermitBatch): amount/expiration/spender
    - Seaport OrderComponents: zero-price NFT listings
    """

    @property
    def name(self) -> str:
        return "signature"

    @property
    def weight(self) -> float:
        return 0.10

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        typed_data = ctx.extra.get('typed_data')
        sign_method = ctx.extra.get('sign_method', '')

        # No typed data — nothing to analyze
        if not typed_data:
            return AnalyzerResult(
                name=self.name, weight=self.weight, score=0,
                flags=[], data={'sign_method': sign_method, 'has_typed_data': False},
            )

        score = 0.0
        flags: List[str] = []
        sig_type = 'unknown'

        try:
            # Parse the typed data structure
            if isinstance(typed_data, str):
                import json
                typed_data = json.loads(typed_data)

            primary_type = typed_data.get('primaryType', '')
            domain = typed_data.get('domain', {})
            message = typed_data.get('message', {})

            # EIP-2612 Permit
            if primary_type == 'Permit':
                sig_type = 'eip2612_permit'
                s, f = self._check_permit(message, domain)
                score += s
                flags.extend(f)

            # Permit2 — PermitSingle or PermitBatch
            elif primary_type in ('PermitSingle', 'PermitBatch'):
                sig_type = 'permit2'
                s, f = self._check_permit2(message, primary_type)
                score += s
                flags.extend(f)

            # Seaport OrderComponents
            elif primary_type == 'OrderComponents':
                sig_type = 'seaport_order'
                s, f = self._check_seaport(message)
                score += s
                flags.extend(f)

            # personal_sign / eth_sign — generally benign
            elif sign_method in ('personal_sign', 'eth_sign'):
                sig_type = 'personal_sign'
                # personal_sign is typically harmless (login signatures)
                score = 0

            else:
                sig_type = primary_type or sign_method or 'unknown'

        except Exception as e:
            logger.error(f"Error analyzing typed data: {e}")
            flags.append('Failed to parse typed data')
            score = 15  # Mild suspicion on parse failure

        score = min(score, 100)

        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=score,
            flags=flags,
            data={
                'sign_method': sign_method,
                'has_typed_data': True,
                'sig_type': sig_type,
            },
        )

    def _check_permit(self, message: Dict, domain: Dict) -> tuple:
        """Check EIP-2612 Permit for dangerous patterns."""
        score = 0.0
        flags = []

        value = _parse_uint(message.get('value', 0))
        spender = (message.get('spender') or '').lower()
        deadline = _parse_uint(message.get('deadline', 0))

        # Unlimited value
        if value >= UNLIMITED_THRESHOLD:
            score += 30
            flags.append('Permit: unlimited token approval')

        # Unknown spender
        if spender and spender not in KNOWN_PERMIT2_SPENDERS:
            score += 25
            flags.append(f'Permit: approval to unknown spender {spender[:10]}...')
        elif not spender:
            score += 15
            flags.append('Permit: missing spender address')

        # Far-future deadline
        import time
        now = int(time.time())
        if deadline > 0 and (deadline - now) > FAR_FUTURE_SECONDS:
            score += 10
            flags.append('Permit: far-future deadline (>1 year)')

        return score, flags

    def _check_permit2(self, message: Dict, primary_type: str) -> tuple:
        """Check Uniswap Permit2 for dangerous patterns."""
        score = 0.0
        flags = []

        if primary_type == 'PermitSingle':
            details = message.get('details', {})
            spender = (message.get('spender') or '').lower()
            amount = _parse_uint(details.get('amount', 0))
            expiration = _parse_uint(details.get('expiration', 0))

            if amount >= UNLIMITED_THRESHOLD:
                score += 25
                flags.append('Permit2: unlimited amount')

            if spender not in KNOWN_PERMIT2_SPENDERS:
                score += 20
                flags.append(f'Permit2: unknown spender {spender[:10]}...')

            import time
            now = int(time.time())
            if expiration > 0 and (expiration - now) > FAR_FUTURE_SECONDS:
                score += 10
                flags.append('Permit2: far-future expiration')

        elif primary_type == 'PermitBatch':
            details_list = message.get('details', [])
            spender = (message.get('spender') or '').lower()

            if spender not in KNOWN_PERMIT2_SPENDERS:
                score += 25
                flags.append(f'Permit2 Batch: unknown spender {spender[:10]}...')

            for i, detail in enumerate(details_list):
                amount = _parse_uint(detail.get('amount', 0))
                if amount >= UNLIMITED_THRESHOLD:
                    score += 15
                    flags.append(f'Permit2 Batch: unlimited amount for token #{i+1}')

        return score, flags

    def _check_seaport(self, message: Dict) -> tuple:
        """Check Seaport OrderComponents for zero-price listings."""
        score = 0.0
        flags = []

        consideration = message.get('consideration', [])
        offer = message.get('offer', [])

        # Zero-price listing: offering NFT but receiving nothing meaningful
        total_consideration = sum(
            _parse_uint(c.get('startAmount', 0))
            for c in consideration
        )

        has_nft_offer = any(
            int(o.get('itemType', 0)) in (2, 3)  # ERC721 or ERC1155
            for o in offer
        )

        if has_nft_offer and total_consideration == 0:
            score += 50
            flags.append('Seaport: zero-price NFT listing (likely phishing)')
        elif has_nft_offer and total_consideration < 1000:
            score += 30
            flags.append('Seaport: suspiciously low consideration for NFT')

        return score, flags


def _parse_uint(value) -> int:
    """Parse a uint value from typed data (may be string, hex, or int)."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            if value.startswith('0x') or value.startswith('0X'):
                return int(value, 16)
            return int(value)
        except (ValueError, TypeError):
            return 0
    return 0
