"""Intent Mismatch Analyzer — detects when tx behavior doesn't match user intent."""

import logging
from typing import List

from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult
from services.counterparty_service import UnavailableCounterparty, approval_grant, judge_spender
from utils.calldata_decoder import CalldataDecoder, UNLIMITED_THRESHOLD

logger = logging.getLogger(__name__)

# Dangerous selectors that should never appear under benign names
DANGEROUS_SELECTORS = {"095ea7b3", "a22cb465", "23b872dd"}
# approve, setApprovalForAll, transferFrom

_decoder = CalldataDecoder()


class IntentMismatchAnalyzer(Analyzer):
    """Detects mismatches between apparent and actual transaction intent.

    Checks:
    - Disguised selectors (benign name + dangerous selector)
    - Unlimited approval to non-whitelisted target
    - Native value sent on an approval call
    - Unknown selector on unverified contract
    - Hard floors: a grant to a wallet, a labelled address or an unverified or new contract,
      and native value paid to claim()
    """

    def __init__(self, counterparty_service=None):
        self._counterparty = counterparty_service or UnavailableCounterparty()

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
        value = ctx.extra.get('value', '0')

        # Decode calldata
        decoded = _decoder.decode(calldata)
        selector = decoded.get('selector')

        if not selector:
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

        # 2. Unlimited approval to non-whitelisted target
        if decoded.get('is_unlimited_approval'):
            spender = decoded.get('params', {}).get('param_0', '')
            # Check if spender is whitelisted
            whitelisted = _decoder.is_whitelisted_target(spender, chain_id=ctx.chain_id)
            if not whitelisted:
                score += 35
                flags.append('Unlimited approval to non-whitelisted contract')
            else:
                # Even unlimited approval to a known router is lower risk but notable
                score += 5
                flags.append(f'Unlimited approval to {whitelisted}')

        # 3. Native value > 0 on an approval call
        if decoded.get('is_approval'):
            value_int = _parse_value(value)
            if value_int > 0:
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
        # spender's facts; native value paid to claim() is the pay-to-claim phishing pattern.
        floor = None
        counterparty = None
        counterparty_known = None
        counterparty_reason = None
        grant = approval_grant(decoded)
        if grant and not self._counterparty.allowlisted_name(grant[0], ctx.chain_id):
            counterparty = await self._counterparty.fetch(grant[0], ctx.chain_id)
            floor, floor_flag, unknown = judge_spender(counterparty, grant[1])
            counterparty_known = not unknown
            counterparty_reason = counterparty['reason'] if unknown else None
        elif decoded.get('category') == 'claim' and _parse_value(value) > 0:
            is_verified = ctx.extra.get('is_verified')
            floor = 85 if is_verified is False else 60
            target = {False: 'an unverified contract', True: 'the contract'}.get(
                is_verified, 'a contract of unknown verification'
            )
            floor_flag = f'claim() sends {_parse_value(value) / 1e18:g} native value to {target}'
            counterparty_known = is_verified is not None
            counterparty_reason = (
                None if counterparty_known else 'Contract verification unavailable for claim() with native value'
            )
        if floor:
            flags.insert(0, floor_flag)
        if counterparty_reason:
            flags.append(counterparty_reason)

        score = min(score, 100)

        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=score,
            flags=flags,
            data={
                'status': 'unknown' if verification_unknown or counterparty_known is False else 'ok',
                'coverage': {
                    'selector_verification': not verification_unknown,
                    **({} if counterparty_known is None else {'counterparty': counterparty_known}),
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
