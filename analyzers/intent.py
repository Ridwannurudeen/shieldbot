"""Intent Mismatch Analyzer — detects when tx behavior doesn't match user intent."""

import asyncio
import logging
import re
from typing import List, Optional

from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult
from services.counterparty_service import (
    UnavailableCounterparty, approval_grant, judge_delegate, judge_spender, within_timeout,
)
from utils.calldata_decoder import CalldataDecoder, UNLIMITED_THRESHOLD

logger = logging.getLogger(__name__)

_decoder = CalldataDecoder()


class IntentMismatchAnalyzer(Analyzer):
    """Detects mismatches between apparent and actual transaction intent.

    Checks:
    - Disguised selectors (benign name + dangerous selector)
    - Unlimited approval to non-whitelisted target
    - Native value sent on an approval call
    - Unknown selector on unverified contract
    - Hard floors: a grant to a wallet, a labelled address or an unverified or new contract,
      native value paid to claim() or to an unverified contract, and any EIP-7702 delegation
    """

    def __init__(self, web3_client, counterparty_service=None):
        self._web3_client = web3_client
        # Without a counterparty service the allowlist still holds; the spender's facts are unknown.
        self._counterparty = counterparty_service or UnavailableCounterparty(web3_client)

    @property
    def name(self) -> str:
        return "intent"

    @property
    def weight(self) -> float:
        return 0.15

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        score = 0.0
        flags: List[str] = []

        calldata = ctx.extra.get('calldata', '0x')
        payment = _parse_value(ctx.extra.get('value', '0'))

        # Decode calldata
        decoded = _decoder.decode(calldata)
        selector = decoded.get('selector')
        # An EIP-7702 authorization list hands the sender's account to each delegate's code.
        delegations = await self._delegations(ctx)

        if not selector and delegations is None:
            # Native transfer — no calldata to analyze
            return AnalyzerResult(
                name=self.name, weight=self.weight, score=0,
                flags=[], data={'intent': 'native_transfer'},
            )

        # 1. Disguised selector check
        disguised = decoded.get('disguised_warning')
        if disguised:
            score += 40
            flags.append(f'Disguised selector: {disguised}')

        # One allowlist for these points and the floors below: the scanned chain's routers and
        # Permit2, checked against the spender the call grants (a permit names the owner first).
        grant = approval_grant(decoded)
        whitelisted = self._counterparty.allowlisted_name(grant[0], ctx.chain_id) if grant else None
        # The spender's facts, looked up once: they name the spender below and set its floor in 5.
        counterparty = await self._counterparty.fetch(grant[0], ctx.chain_id) if grant and not whitelisted else None

        # 2. Unlimited approval to non-whitelisted target
        if decoded.get('is_unlimited_approval'):
            if not whitelisted:
                score += 35
                # A wallet (EIP-7702 delegated or not) is never called a contract; unknown code is neither.
                if counterparty and (counterparty['delegated'] or counterparty['is_contract'] is False):
                    spender = 'a wallet address'
                elif counterparty and counterparty['is_contract']:
                    spender = 'non-whitelisted contract'
                else:
                    spender = 'non-whitelisted address'
                flags.append(f'Unlimited approval to {spender}')
            else:
                # Even unlimited approval to a known router is lower risk but notable
                score += 5
                flags.append(f'Unlimited approval to {whitelisted}')

        # 3. Native value > 0 on an approval call
        if decoded.get('is_approval') and payment > 0:
            score += 30
            flags.append('Native value sent with approval call (unusual)')

        verification_unknown = False

        # 4. Unknown selector — skip entirely for verified/non-token contracts
        if decoded.get('category') == 'unknown':
            is_verified = ctx.extra.get('is_verified')
            if ctx.is_token is False or is_verified:
                # Verified contracts and non-token contracts (marketplaces,
                # bridges, governance) commonly have selectors outside our
                # known list — this is normal, not suspicious.  No penalty.
                pass
            elif is_verified is False:
                score += 20
                flags.append(f'Unknown function selector 0x{selector}')
            else:
                verification_unknown = True
                flags.append('Selector risk unknown: contract verification unavailable')

        # 5. Hard floors. A positive grant to a spender outside the allowlist is judged on the
        # spender's facts; native value paid with a call is judged on the target's.
        floors = []
        counterparty_known = None
        counterparty_reasons = []
        if counterparty is not None:
            floor, floor_flag, unknown = judge_spender(counterparty, grant[1])
            floors.append((floor, floor_flag))
            counterparty_known = not unknown
            if unknown:
                counterparty_reasons.append(counterparty['reason'])
        # On a router swap the value goes to the allowlisted router, not to the token scanned here.
        # A native send with no call pays a recipient, not a contract call.
        if payment > 0 and selector and not ctx.extra.get('whitelisted_router'):
            floor, floor_flag, reason = await self._payment_floor(ctx, decoded, payment)
            floors.append((floor, floor_flag))
            counterparty_known = counterparty_known is not False and reason is None
            if reason:
                counterparty_reasons.append(reason)
        delegate_known = None
        if delegations is not None:
            delegation_floors, delegate_known, delegate_reasons = delegations
            floors.extend(delegation_floors)
            counterparty_reasons.extend(delegate_reasons)
        floors = sorted((pair for pair in floors if pair[0]), reverse=True)
        floor = floors[0][0] if floors else None
        flags[:0] = [flag for _, flag in floors]
        flags.extend(counterparty_reasons)
        counterparty_reason = '; '.join(counterparty_reasons) or None

        score = min(score, 100)

        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=score,
            flags=flags,
            data={
                'status': 'unknown' if verification_unknown or False in (counterparty_known, delegate_known) else 'ok',
                'coverage': {
                    'selector_verification': not verification_unknown,
                    **({} if counterparty_known is None else {'counterparty': counterparty_known}),
                    **({} if delegate_known is None else {'delegate': delegate_known}),
                },
                'reason': (
                    'Contract verification unavailable for unknown selector' if verification_unknown
                    else counterparty_reason
                ),
                'selector': selector,
                'function_name': decoded.get('function_name'),
                'category': decoded.get('category'),
                'is_approval': decoded.get('is_approval', False),
                'is_unlimited': decoded.get('is_unlimited_approval', False),
                'disguised': disguised is not None,
                **({'floor': floor} if floor else {}),
                **({'counterparty': counterparty} if counterparty else {}),
            },
        )

    async def _delegations(self, ctx: AnalysisContext) -> Optional[tuple]:
        """For an EIP-7702 transaction: ([(floor, flag)] per delegate, whether every delegate's facts are
        known, the reasons they are not). None without an authorization list. One that is not a list
        (the RPC proxy passes the page's value as sent), is empty, or has an authorization whose delegate
        address cannot be read is judged as an unknown delegate."""
        authorizations = ctx.extra.get('authorization_list')
        if authorizations is None:
            return None
        items = authorizations if isinstance(authorizations, list) else [None]
        delegates = [item.get('address') if isinstance(item, dict) else None for item in items]
        if not delegates or not all(isinstance(d, str) and re.fullmatch(r'0x[0-9a-fA-F]{40}', d) for d in delegates):
            return [(100, 'EIP-7702 delegation to an address that cannot be read')], False, [
                'EIP-7702 delegate address unreadable'
            ]
        delegates = list(dict.fromkeys(d.lower() for d in delegates))
        # Each lookup is bounded by the provider timeout; together they take as long as the slowest.
        all_facts = await asyncio.gather(*(self._counterparty.fetch(d, ctx.chain_id) for d in delegates))
        floors, reasons = [], []
        for delegate, facts in zip(delegates, all_facts):
            floor, flag, unknown = judge_delegate(delegate, facts)
            floors.append((floor, flag))
            if unknown:
                reasons.append(facts['reason'] or f'EIP-7702 delegate {delegate}: facts unknown')
        return floors, not reasons, reasons

    async def _payment_floor(self, ctx: AnalysisContext, decoded: dict, payment: int) -> tuple:
        """(floor or None, its flag, the reason it is incomplete or None) for native value paid to
        the target with a call.

        Pay-to-claim and fake-mint pages take the victim's native coin through a call on an
        unverified contract; a verified contract taking payment is ordinary, except for claim(),
        where paying to claim is itself the phishing pattern.
        """
        if ctx.extra.get('is_contract') is False:
            # A wallet takes payments; there is no contract to judge, and an explorer calls every
            # wallet unverified.
            return None, None, None
        is_verified = ctx.extra.get('is_verified')
        claim = decoded.get('category') == 'claim'
        call = decoded.get('signature') or f"0x{decoded['selector']}"
        sends = f'{call} sends {payment / 1e18:g} native value to'
        if is_verified is None:
            reason = 'Contract verification unavailable for a call with native value'
            return 60, f'{sends} a contract of unknown verification', reason
        if is_verified is True:
            return (60, f'{sends} the contract', None) if claim else (None, None, None)
        if claim:
            return 85, f'{sends} an unverified contract', None
        creation = await within_timeout(
            self._web3_client.get_contract_creation_info(ctx.address, chain_id=ctx.chain_id), None
        )
        age = creation.get('age_days') if creation else None
        if age is None:
            # It may be a fresh deployment (85), but nothing says so: the older contract's floor
            # holds and the verdict stays unknown, as for an approval's spender.
            return 60, f'{sends} an unverified contract of unknown age', (
                'Contract age unavailable for a payment to an unverified contract'
            )
        if age >= 7:
            return 60, f'{sends} an unverified contract', None
        return 85, f'{sends} an unverified contract {age} days old', None


def _parse_value(value) -> int:
    """Parse hex or decimal value string to int."""
    if not value:
        return 0
    if isinstance(value, int):
        return value
    try:
        s = str(value)
        if s.startswith('0x') or s.startswith('0X'):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return 0
