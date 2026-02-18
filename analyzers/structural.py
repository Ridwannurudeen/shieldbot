"""Structural analyzer — wraps ContractService."""

import logging
from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult

logger = logging.getLogger(__name__)


class StructuralAnalyzer(Analyzer):
    """Analyzes contract structure: verification, age, mint/proxy/pause/blacklist, scam DB."""

    def __init__(self, contract_service):
        self._service = contract_service

    @property
    def name(self) -> str:
        return "structural"

    @property
    def weight(self) -> float:
        return 0.40

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        data = await self._service.fetch_contract_data(ctx.address, chain_id=ctx.chain_id)
        score, flags = self._compute(data)
        return AnalyzerResult(
            name=self.name, weight=self.weight,
            score=score, flags=flags, data=data,
        )

    def _compute(self, d: dict) -> tuple:
        score = 0
        flags = []
        if d.get('is_contract') is False:
            score += 50
            flags.append('No contract bytecode at address (destroyed or EOA)')
        elif not d.get('is_verified'):
            score += 25
            flags.append('Contract not verified')
        age = d.get('contract_age_days')
        if age is not None and age < 7:
            score += 20
            flags.append(f'Contract age: {age} days')
        if d.get('has_mint'):
            score += 15
            flags.append('Mint function detected')
        if d.get('has_proxy'):
            score += 15
            flags.append('Proxy/upgradeable contract')
        if d.get('has_pause'):
            score += 10
        if d.get('has_blacklist'):
            score += 10
            flags.append('Blacklist function detected')
        if d.get('scam_matches'):
            score += 30
            flags.append(f'Scam DB match ({len(d["scam_matches"])} sources)')
        if d.get('ownership_renounced') is False:
            score += 5
        return min(score, 100), flags
