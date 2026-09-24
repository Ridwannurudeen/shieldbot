"""Signature/Permit Analyzer — detects dangerous EIP-712 typed data signatures."""

import logging
from typing import Dict, List, Optional

from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult
from services.counterparty_service import UnavailableCounterparty, judge_spender
from utils.web3_client import UnsupportedChainError

logger = logging.getLogger(__name__)

# Maximum uint256 — signals unlimited approval
MAX_UINT256 = (1 << 256) - 1
UNLIMITED_THRESHOLD = 10**30

# Far-future deadline: > 1 year from now (seconds)
FAR_FUTURE_SECONDS = 365 * 24 * 3600

# Permit2 SignatureTransfer: the spender pulls the tokens as soon as it submits the signature.
SIGNATURE_TRANSFER_TYPES = (
    'PermitTransferFrom',
    'PermitBatchTransferFrom',
    'PermitWitnessTransferFrom',
    'PermitBatchWitnessTransferFrom',
)


class SignaturePermitAnalyzer(Analyzer):
    """Analyzes EIP-712 typed data for dangerous permit/signature patterns.

    Parses typed data from ctx.extra['typed_data'] for:
    - EIP-2612 Permit: flags unlimited value, unknown spender, far-future deadline
    - Permit2 AllowanceTransfer (PermitSingle/PermitBatch): amount/expiration/spender
    - Permit2 SignatureTransfer (PermitTransferFrom, its batch and witness forms): pull rights
    - Seaport OrderComponents: zero-price NFT listings

    Every permit's spender is judged like a calldata approval's: the chain adapter's routers and
    Permit2 are allowlisted, and any other spender's counterparty facts can set a hard floor.
    """

    def __init__(self, counterparty_service=None):
        self._counterparty = counterparty_service or UnavailableCounterparty()

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
        permit = None
        spender_data = {}
        floor = None

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
                permit = self._check_permit(message, domain)

            # Permit2 AllowanceTransfer — PermitSingle or PermitBatch
            elif primary_type in ('PermitSingle', 'PermitBatch'):
                sig_type = 'permit2'
                permit = self._check_permit2(message, primary_type)

            # Permit2 SignatureTransfer
            elif primary_type in SIGNATURE_TRANSFER_TYPES:
                sig_type = 'permit2_transfer'
                permit = self._check_permit2_transfer(message, primary_type)

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

            if permit:
                s, f, spender, unlimited = permit
                score += s
                flags.extend(f)
                s, f, floor, spender_data = await self._judge_spender(spender, unlimited, sig_type, ctx.chain_id)
                score += s
                flags = f + flags if floor else flags + f

        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Error analyzing typed data: %s", type(e).__name__)
            flags.append('Failed to parse typed data')
            score = 15  # Mild suspicion on parse failure

        # The signature-only path has no engine, so the floor is applied here as well as declared.
        score = min(max(score, floor or 0), 100)

        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=score,
            flags=flags,
            data={
                'sign_method': sign_method,
                'has_typed_data': True,
                'sig_type': sig_type,
                **spender_data,
                **({'floor': floor} if floor else {}),
            },
        )

    async def _judge_spender(self, spender: str, unlimited: bool, sig_type: str, chain_id: int) -> tuple:
        """Score a permit's spender: (points, flags, floor or None, result data)."""
        if not spender:
            return 15, ['Permit: missing spender address'], None, {}
        if self._counterparty.allowlisted_name(spender, chain_id):
            return 0, [], None, {}
        facts = await self._counterparty.fetch(spender, chain_id)
        floor, floor_flag, unknown = judge_spender(facts, unlimited)
        # A SignatureTransfer moves the tokens at once, so any spender outside the allowlist is
        # riskier than an allowance's.
        points = 30 if sig_type == 'permit2_transfer' else 25 if unknown else 10
        if floor:
            flags = [floor_flag] + ([facts['reason']] if unknown else [])
        elif unknown:
            flags = [f'Permit: approval to unknown spender {spender[:10]}...']
        else:
            flags = [f'Permit: spender {spender[:10]}... is not a known protocol (verified contract)']
        data = {
            'status': 'unknown' if unknown else 'ok',
            'coverage': {'counterparty': not unknown},
            'reason': facts['reason'] if unknown else None,
            'counterparty': facts,
        }
        return points, flags, floor, data

    def _check_permit(self, message: Dict, domain: Dict) -> tuple:
        """Check EIP-2612 Permit for dangerous patterns: (score, flags, spender, unlimited)."""
        score = 0.0
        flags = []

        value = _parse_uint(message.get('value', 0))
        spender = (message.get('spender') or '').lower()
        deadline = _parse_uint(message.get('deadline', 0))

        # Unlimited value
        if value >= UNLIMITED_THRESHOLD:
            score += 30
            flags.append('Permit: unlimited token approval')

        # Far-future deadline
        import time
        now = int(time.time())
        if deadline > 0 and (deadline - now) > FAR_FUTURE_SECONDS:
            score += 10
            flags.append('Permit: far-future deadline (>1 year)')

        return score, flags, spender, value >= UNLIMITED_THRESHOLD

    def _check_permit2(self, message: Dict, primary_type: str) -> tuple:
        """Check a Permit2 AllowanceTransfer: (score, flags, spender, unlimited)."""
        score = 0.0
        flags = []
        spender = (message.get('spender') or '').lower()

        if primary_type == 'PermitSingle':
            details = message.get('details', {})
            amount = _parse_uint(details.get('amount', 0))
            expiration = _parse_uint(details.get('expiration', 0))
            unlimited = amount >= UNLIMITED_THRESHOLD

            if unlimited:
                score += 25
                flags.append('Permit2: unlimited amount')

            import time
            now = int(time.time())
            if expiration > 0 and (expiration - now) > FAR_FUTURE_SECONDS:
                score += 10
                flags.append('Permit2: far-future expiration')

        else:
            details_list = message.get('details', [])
            unlimited = False

            for i, detail in enumerate(details_list):
                amount = _parse_uint(detail.get('amount', 0))
                if amount >= UNLIMITED_THRESHOLD:
                    unlimited = True
                    score += 15
                    flags.append(f'Permit2 Batch: unlimited amount for token #{i+1}')

        return score, flags, spender, unlimited

    def _check_permit2_transfer(self, message: Dict, primary_type: str) -> tuple:
        """Check a Permit2 SignatureTransfer: (score, flags, spender, unlimited)."""
        score = 0.0
        flags = []
        spender = (message.get('spender') or '').lower()
        permitted = message.get('permitted', [])
        if 'Batch' not in primary_type:
            permitted = [permitted]
        unlimited = any(_parse_uint(item.get('amount', 0)) >= UNLIMITED_THRESHOLD for item in permitted)
        deadline = _parse_uint(message.get('deadline', 0))

        if unlimited:
            score += 20
            flags.append('Permit2 transfer: unlimited amount')
        if len(permitted) >= 3:
            score += 15
            flags.append(f'Permit2 transfer: {len(permitted)} tokens in one signature')

        import time
        now = int(time.time())
        if deadline > 0 and (deadline - now) > FAR_FUTURE_SECONDS:
            score += 10
            flags.append('Permit2 transfer: far-future deadline (>1 year)')

        return score, flags, spender, unlimited

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
