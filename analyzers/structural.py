"""Structural analyzer — wraps ContractService, with optional Token Sniffer fallback."""

import logging
from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult
from core.risk_engine import database_matches, medium_matches

logger = logging.getLogger(__name__)


class StructuralAnalyzer(Analyzer):
    """Analyzes contract structure: verification, age, mint/proxy/pause/blacklist, scam DB.

    When a contract is unverified, Token Sniffer is queried as a fallback to
    replace the flat unverified penalty with a data-driven score.
    """

    def __init__(self, contract_service, token_sniffer=None):
        self._service = contract_service
        self._sniffer = token_sniffer

    @property
    def name(self) -> str:
        return "structural"

    @property
    def weight(self) -> float:
        return 0.40

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        data = await self._service.fetch_contract_data(ctx.address, chain_id=ctx.chain_id)

        data = dict(data)
        data['coverage'] = dict(data.get('coverage', {}))
        # A confirmed EOA has no verification or age to observe.
        if data.get('is_contract') is not False:
            data['coverage']['is_verified'] = data.get('is_verified') is not None
            data['coverage']['contract_age_days'] = data.get('contract_age_days') is not None
        data['status'] = 'unknown' if data.get('status') == 'unknown' or not all(data['coverage'].values()) else 'ok'
        if data['status'] == 'unknown':
            missing = ', '.join(field for field, covered in data['coverage'].items() if not covered)
            data['reason'] = data.get('reason') or (
                f'Structural data unknown: {missing}' if missing else 'Structural provider data incomplete'
            )

        sniffer_data = {}
        if (
            self._sniffer
            and self._sniffer.is_enabled()
            and data.get("is_verified") is False
            and data.get("is_contract")
        ):
            sniffer_data = await self._sniffer.fetch(ctx.address, chain_id=ctx.chain_id)

        score, flags = self._compute(data, sniffer_data)
        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=score,
            flags=flags,
            data={**data, "token_sniffer": sniffer_data},
        )

    def _compute(self, d: dict, sniffer: dict) -> tuple:
        score = 0
        flags = []

        if d.get("is_contract") is False:
            score += 50
            flags.append("No contract bytecode at address (destroyed or EOA)")
        elif d.get("is_verified") is False:
            ts_score = sniffer.get("score")  # 0-100, 100 = safest
            if ts_score is not None:
                if ts_score <= 30:
                    score += 40
                    flags.append(f"Token Sniffer: High-risk unverified contract (score {ts_score}/100)")
                elif ts_score <= 60:
                    score += 25
                    flags.append(f"Token Sniffer: Suspicious unverified contract (score {ts_score}/100)")
                else:
                    score += 10
                    flags.append(f"Unverified contract — Token Sniffer score {ts_score}/100")
                if sniffer.get("is_flagged"):
                    score += 15
                    flags.append("Token Sniffer: Contract explicitly flagged")
            else:
                score += 25
                flags.append("Contract not verified")

        age = d.get("contract_age_days")
        if age is not None and age < 7:
            score += 20
            flags.append(f"Contract age: {age} days")
        if d.get("has_mint"):
            score += 15
            flags.append("Mint function detected")
        if d.get("has_proxy"):
            score += 15
            flags.append("Proxy/upgradeable contract")
        if d.get("has_pause"):
            score += 10
        if d.get("has_blacklist"):
            score += 10
            flags.append("Blacklist function detected")
        if d.get("has_destroy") and d.get("ownership_renounced") is not True:
            score += 15
            flags.append("destroy() function: the owner may be able to delete the contract")
        hard_matches = database_matches(d.get("scam_matches"))
        if hard_matches:
            score += 30
            flags.append(f"Scam DB match ({len(hard_matches)} sources)")
        if d.get("ownership_renounced") is False:
            score += 5
        # A community report adds no points: the risk engine holds its floor. Its reason leads, so the
        # extension, which shows three flags, always names it.
        flags[:0] = [match["reason"] for match in medium_matches(d.get("scam_matches"))]
        return min(score, 100), flags
