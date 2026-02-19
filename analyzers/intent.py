"""Intent Mismatch Analyzer — detects when tx behavior doesn't match user intent."""

import logging
from typing import List

from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult
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
    - Approval to an EOA (spender is not a contract)
    """

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

        # 4. Unknown selector — skip entirely for verified/non-token contracts
        if decoded.get('category') == 'unknown':
            is_verified = ctx.extra.get('is_verified')
            if not ctx.is_token or is_verified:
                # Verified contracts and non-token contracts (marketplaces,
                # bridges, governance) commonly have selectors outside our
                # known list — this is normal, not suspicious.  No penalty.
                pass
            else:
                score += 20
                flags.append(f'Unknown function selector 0x{selector}')

        # 5. Approval to EOA — check via extra data if available
        if decoded.get('is_approval'):
            spender = decoded.get('params', {}).get('param_0', '')
            is_spender_contract = ctx.extra.get('spender_is_contract')
            if is_spender_contract is False:
                score += 35
                flags.append('Approval to an EOA (not a contract)')

        score = min(score, 100)

        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=score,
            flags=flags,
            data={
                'selector': selector,
                'function_name': decoded.get('function_name'),
                'category': decoded.get('category'),
                'is_approval': decoded.get('is_approval', False),
                'is_unlimited': decoded.get('is_unlimited_approval', False),
                'disguised': disguised is not None,
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
