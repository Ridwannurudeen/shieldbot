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
        # Why the typed data could not be read, if it could not.
        unreadable = None

        try:
            # Parse the typed data structure
            if isinstance(typed_data, str):
                import json
                typed_data = json.loads(typed_data)

            primary_type = typed_data.get('primaryType', '')
            message = typed_data.get('message', {})
            if not isinstance(message, dict):
                raise ValueError('typed data message is not an object')
            # Only the members the declared types name enter the digest a wallet signs, so the
            # permit checks read the message through them.
            types = typed_data.get('types')

            # EIP-2612 Permit
            if primary_type == 'Permit':
                sig_type = 'eip2612_permit'
                permit = self._check_permit(message, types)

            # Permit2 AllowanceTransfer — PermitSingle or PermitBatch
            elif primary_type in ('PermitSingle', 'PermitBatch'):
                sig_type = 'permit2'
                permit = self._check_permit2(message, primary_type, types)

            # Permit2 SignatureTransfer
            elif primary_type in SIGNATURE_TRANSFER_TYPES:
                sig_type = 'permit2_transfer'
                permit = self._check_permit2_transfer(message, primary_type, types)

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
                s, f, spender, unlimited, granted, readable = permit
                if not readable:
                    unreadable = 'Typed data type does not match its permit standard'
                score += s
                flags.extend(f)
                # A revoke gives the spender nothing, so there is no spender to judge.
                if granted:
                    s, f, floor, spender_data = await self._judge_spender(spender, unlimited, sig_type, ctx.chain_id)
                    score += s
                    flags = f + flags if floor else flags + f

        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Error analyzing typed data: %s", type(e).__name__)
            flags.append('Failed to parse typed data')
            score = 15  # Mild suspicion on parse failure
            unreadable = f'Typed data could not be analysed ({type(e).__name__})'

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
                # Typed data that could not be read leaves the signature unknown, so on the main
                # firewall path the risk engine cannot count it as covered and dilute it to SAFE.
                **({} if unreadable is None else {
                    'status': 'unknown',
                    'coverage': {**spender_data.get('coverage', {}), 'typed_data': False},
                    'reason': '; '.join(filter(None, (unreadable, spender_data.get('reason')))),
                }),
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

    def _check_permit(self, message: Dict, types) -> tuple:
        """Check EIP-2612 Permit for dangerous patterns: (score, flags, spender, unlimited, granted,
        whether its declared type could be read)."""
        score = 0.0
        flags = []

        members = _members(types, 'Permit') or {}
        spender = _declared_spender(message, members)
        deadline = _parse_uint(message.get('deadline', 0)) if 'deadline' in members else 0
        # The declared type picks the rule. value without allowed is EIP-2612: a value that reads as
        # 0 revokes, and one that cannot be read (a float, a negative, an object) is judged as the
        # largest grant. allowed without value is DAI's: only allowed false revokes. Any other type,
        # or one with no spender member, cannot be read and is judged as the largest grant.
        unreadable = False
        mismatch = 'spender' not in members or ('value' in members) == ('allowed' in members)
        if mismatch:
            granted = unlimited = True
        elif 'allowed' in members:
            granted = unlimited = message.get('allowed') is not False
        else:
            value = _parse_uint_or_none(message.get('value'))
            unreadable = value is None
            granted = value != 0
            unlimited = unreadable or value >= UNLIMITED_THRESHOLD

        # Unlimited value
        if mismatch:
            score += 30
            flags.append('Permit: type does not match EIP-2612 or DAI; treated as unlimited')
        elif unreadable:
            score += 30
            flags.append('Permit: amount could not be read; treated as unlimited')
        elif unlimited:
            score += 30
            flags.append('Permit: unlimited token approval')

        # Far-future deadline
        import time
        now = int(time.time())
        if deadline > 0 and (deadline - now) > FAR_FUTURE_SECONDS:
            score += 10
            flags.append('Permit: far-future deadline (>1 year)')

        return score, flags, spender, unlimited, granted, not mismatch

    def _check_permit2(self, message: Dict, primary_type: str, types) -> tuple:
        """Check a Permit2 AllowanceTransfer: (score, flags, spender, unlimited, granted, whether its
        declared type could be read)."""
        score = 0.0
        flags = []
        members = _members(types, primary_type) or {}
        spender = _declared_spender(message, members)
        detail_members = _referenced_members(types, members, 'details', primary_type == 'PermitBatch')
        if detail_members is None or 'amount' not in detail_members or 'spender' not in members:
            flags.append('Permit2: type does not match Permit2; treated as unlimited')
            return 25.0, flags, spender, True, True, False

        # An amount that reads as 0 revokes the spender's allowance; one that cannot be read is
        # judged as the largest grant.
        if primary_type == 'PermitSingle':
            details = message.get('details', {})
            amount = _parse_uint_or_none(details.get('amount'))
            expiration = _parse_uint(details.get('expiration', 0)) if 'expiration' in detail_members else 0
            granted = amount != 0
            unlimited = amount is None or amount >= UNLIMITED_THRESHOLD

            if amount is None:
                score += 25
                flags.append('Permit2: amount could not be read; treated as unlimited')
            elif unlimited:
                score += 25
                flags.append('Permit2: unlimited amount')

            import time
            now = int(time.time())
            if expiration > 0 and (expiration - now) > FAR_FUTURE_SECONDS:
                score += 10
                flags.append('Permit2: far-future expiration')

        else:
            amounts = [_parse_uint_or_none(detail.get('amount')) for detail in message.get('details', [])]
            # A batch revokes only when every amount reads as 0; an empty batch is judged anyway.
            granted = not amounts or any(amount != 0 for amount in amounts)
            unlimited = False

            for i, amount in enumerate(amounts):
                if amount is None:
                    unlimited = True
                    score += 15
                    flags.append(f'Permit2 Batch: amount for token #{i+1} could not be read; treated as unlimited')
                elif amount >= UNLIMITED_THRESHOLD:
                    unlimited = True
                    score += 15
                    flags.append(f'Permit2 Batch: unlimited amount for token #{i+1}')

        return score, flags, spender, unlimited, granted, True

    def _check_permit2_transfer(self, message: Dict, primary_type: str, types) -> tuple:
        """Check a Permit2 SignatureTransfer: (score, flags, spender, unlimited, granted, whether its
        declared type could be read)."""
        score = 0.0
        flags = []
        members = _members(types, primary_type) or {}
        spender = _declared_spender(message, members)
        token_members = _referenced_members(types, members, 'permitted', 'Batch' in primary_type)
        if token_members is None or 'amount' not in token_members or 'spender' not in members:
            flags.append('Permit2 transfer: type does not match Permit2; treated as unlimited')
            return 20.0, flags, spender, True, True, False
        permitted = message.get('permitted', [])
        if 'Batch' not in primary_type:
            permitted = [permitted]
        amounts = [_parse_uint_or_none(item.get('amount')) for item in permitted]
        unlimited = any(amount is None or amount >= UNLIMITED_THRESHOLD for amount in amounts)
        deadline = _parse_uint(message.get('deadline', 0)) if 'deadline' in members else 0

        if None in amounts:
            score += 20
            flags.append('Permit2 transfer: amount could not be read; treated as unlimited')
        elif unlimited:
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

        return score, flags, spender, unlimited, True, True

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


def _members(types, type_name: str) -> Optional[Dict[str, str]]:
    """The members an EIP-712 struct type declares, {name: type}, or None when `types` does not
    declare the type properly. A message key the type does not declare is not in the signed digest."""
    fields = types.get(type_name) if isinstance(types, dict) else None
    if not isinstance(fields, list) or not fields:
        return None
    members = {}
    for field in fields:
        if not (isinstance(field, dict) and isinstance(field.get('name'), str) and isinstance(field.get('type'), str)):
            return None
        members[field['name']] = field['type']
    return members


def _referenced_members(types, members: Dict[str, str], name: str, array: bool) -> Optional[Dict[str, str]]:
    """The members of the struct type that member `name` declares, a list of them when `array`;
    None when the member, its type or its shape is not what the permit's type declares."""
    declared = members.get(name, '')
    if declared.endswith('[]') != array:
        return None
    return _members(types, declared.removesuffix('[]'))


def _declared_spender(message: Dict, members: Dict[str, str]) -> str:
    spender = message.get('spender') if 'spender' in members else None
    return spender.lower() if isinstance(spender, str) else ''


def _parse_uint_or_none(value) -> Optional[int]:
    """A uint256 from typed data, or None when the value cannot be read as one.

    Only an int or a decimal or 0x-hex string holding a non-negative integer is readable: JSON
    numbers such as 1e30 arrive as floats, and bool counts as int in Python but not here. An amount
    that cannot be read must never read as 0, which would make it a revoke.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        try:
            number = int(value, 16) if value[:2] in ('0x', '0X') else int(value, 10)
        except ValueError:
            return None
        return number if number >= 0 else None
    return None


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
