"""Honeypot analyzer — wraps HoneypotService."""

import logging
from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult
from services.honeypot_service import SELL_TAX_EXTREME, SELL_TAX_HIGH
from services.robinhood_assets import official_asset_reason

logger = logging.getLogger(__name__)


class HoneypotAnalyzer(Analyzer):
    """Analyzes honeypot status and tax info.

    Canonical WETH and USDG are the simulator's funding assets, not tokens to sell. Official stocks
    are simulated when a supported route resolves; unresolved routes retain the explicit skip note.
    """

    def __init__(self, honeypot_service, robinhood_assets=None):
        self._service = honeypot_service
        self._assets = robinhood_assets

    @property
    def name(self) -> str:
        return "honeypot"

    @property
    def weight(self) -> float:
        return 0.15

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        # Honeypot simulation is only meaningful for ERC-20 tokens.
        # Non-token contracts (marketplaces, bridges, governance) will always
        # fail simulation or return nonsensical data — skip entirely.
        if ctx.is_token is False:
            return AnalyzerResult(
                name=self.name, weight=self.weight,
                score=0, flags=[], data={'skipped': True, 'reason': 'non-token contract'},
            )
        official = await self._assets.official(ctx.address, ctx.chain_id) if self._assets else None
        if official is not None and official.get('canonical') is True:
            reason = official_asset_reason(official, 'sell simulation does not apply')
            return AnalyzerResult(
                name=self.name, weight=self.weight,
                score=0, flags=[], data={'skipped': True, 'reason': reason, 'notes': [reason]},
            )

        data = await self._service.fetch_honeypot_data(ctx.address, chain_id=ctx.chain_id)
        data = dict(data)
        if (data.get('simulation_failed') or data.get('rpc_failed') or data.get('undecided')) \
                and data.get('can_sell') is True:
            data['can_sell'] = None
        # A failed run is missing evidence, so an official stock's sell check remains uncovered.
        if official is not None and not (data.get('rpc_failed') or data.get('simulation_failed')) and (
            data.get('is_honeypot') is None or data.get('can_sell') is None
        ):
            reason = official_asset_reason(official, 'sell simulation does not apply')
            return AnalyzerResult(
                name=self.name, weight=self.weight,
                score=0, flags=[], data={'skipped': True, 'reason': reason, 'notes': [reason]},
            )
        fields = ('is_honeypot', 'buy_tax', 'sell_tax', 'can_buy', 'can_sell')
        # A sell tax the service left uncovered (GoPlus's, for a sell ShieldBot's own simulation made at a
        # tax it could not measure) is scored below, but does not complete the answer.
        tax_uncovered = (data.get('coverage') or {}).get('sell_tax') is False
        data['coverage'] = {field: data.get(field) is not None for field in fields}
        if tax_uncovered:
            data['coverage']['sell_tax'] = False
        if data.get('simulation_failed'):
            data['coverage']['can_sell'] = False
            data['reason'] = data.get('reason') or 'Honeypot simulation failed (unresolved)'
        # ShieldBot's own simulation could not run: sellability stays unknown.
        if data.get('rpc_failed'):
            data['coverage']['can_sell'] = False
            data['reason'] = data.get('reason') or 'Honeypot simulation could not run (unresolved)'
        if data.get('undecided'):
            data['coverage']['can_sell'] = False
            data['reason'] = data.get('reason') or 'Own simulation left sellability undecided (unresolved)'
        data['status'] = 'unknown' if data.get('status') == 'unknown' or not all(data['coverage'].values()) else 'ok'
        if data['status'] == 'unknown':
            data['reason'] = data.get('reason') or 'Incomplete honeypot provider data'
        score, flags = self._compute(data)
        return AnalyzerResult(
            name=self.name, weight=self.weight,
            score=score, flags=flags, data=data,
        )

    def _compute(self, d: dict) -> tuple:
        score = 0
        flags = []
        if d.get('is_honeypot'):
            score += 80
            flags.append('Honeypot detected')
            # The doubt is explanation only: the simulated sell still failed, so the score stands.
            if d.get('likely_false_positive'):
                flags.append('Honeypot flag may be a false positive: the contract is verified and its taxes are normal')
        if d.get('can_sell') is False:
            score += 60
            flags.append('Cannot sell token')
        if d.get('cannot_buy') is True:
            score += 20
            flags.append('Cannot buy token')
        if d.get('cannot_sell_all') is True:
            score += 20
            flags.append('Cannot sell all tokens')
        if d.get('transfer_pausable') is True:
            score += 20
            flags.append('Token transfers can be paused')
        if d.get('can_sell') is None:
            flags.append(f"Sellability unknown: {d.get('reason') or 'no honeypot data for this chain'}")
        elif d.get('status') == 'unknown':
            flags.append(f"Honeypot coverage unknown: {d.get('reason') or 'incomplete provider data'}")
        sell_tax = d.get('sell_tax')
        buy_tax = d.get('buy_tax')
        if sell_tax is not None and sell_tax > SELL_TAX_EXTREME:
            score += 40
            flags.append(f'Extreme sell tax: {sell_tax}%')
        elif sell_tax is not None and sell_tax > SELL_TAX_HIGH:
            score += 20
        if buy_tax is not None and buy_tax > 20:
            score += 10
        return min(score, 100), flags
