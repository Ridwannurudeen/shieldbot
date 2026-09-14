"""Honeypot analyzer — wraps HoneypotService."""

import logging
from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult

logger = logging.getLogger(__name__)


class HoneypotAnalyzer(Analyzer):
    """Analyzes honeypot status and tax info."""

    def __init__(self, honeypot_service):
        self._service = honeypot_service

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
        if not ctx.is_token:
            return AnalyzerResult(
                name=self.name, weight=self.weight,
                score=0, flags=[], data={'skipped': True, 'reason': 'non-token contract'},
            )

        data = await self._service.fetch_honeypot_data(ctx.address, chain_id=ctx.chain_id)
        data = dict(data)
        if data.get('simulation_failed') and data.get('can_sell') is True:
            data['can_sell'] = None
        fields = ('is_honeypot', 'buy_tax', 'sell_tax', 'can_buy', 'can_sell')
        data['coverage'] = {field: data.get(field) is not None for field in fields}
        if data.get('simulation_failed'):
            data['coverage']['can_sell'] = False
            data['reason'] = data.get('reason') or 'Honeypot simulation failed (unresolved)'
        data['status'] = 'ok' if all(data['coverage'].values()) else 'unknown'
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
        if d.get('simulation_failed') and not d.get('is_honeypot'):
            score += 40
            flags.append('Honeypot simulation failed — treat as suspicious')
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
        if sell_tax is not None and sell_tax > 50:
            score += 40
            flags.append(f'Extreme sell tax: {sell_tax}%')
        elif sell_tax is not None and sell_tax > 20:
            score += 20
        if buy_tax is not None and buy_tax > 20:
            score += 10
        return min(score, 100), flags
