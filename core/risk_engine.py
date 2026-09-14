import logging
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from core.analyzer import AnalyzerResult

logger = logging.getLogger(__name__)

class _EmptyResult:
    """Sentinel for missing analyzer results."""
    name = ""
    weight = 0.0
    score = 0.0
    flags = []
    data = {}
    error = None

_EMPTY_RESULT = _EmptyResult()

RISK_ARCHETYPES = {
    'honeypot': 'Honeypot',
    'rug_pull': 'Rug Pull',
    'wash_traded': 'Wash Traded',
    'high_risk_contract': 'High-Risk Contract',
    'legitimate': 'Legitimate',
    'unknown': 'Unknown',
}

# Category weights
WEIGHT_STRUCTURAL = 0.40
WEIGHT_MARKET = 0.25
WEIGHT_BEHAVIORAL = 0.20
WEIGHT_HONEYPOT = 0.15


class RiskEngine:
    """Composite weighted risk scoring across all data sources."""

    def __init__(self, calibration=None):
        """Initialize with optional CalibrationConfig for data-driven thresholds."""
        self._calibration = calibration

    def compute_composite_risk(
        self,
        contract_data: dict,
        honeypot_data: dict,
        dex_data: dict,
        ethos_data: dict,
        is_token: bool = True,
    ) -> dict:
        critical_flags = []

        # --- Structural score (0-100) ---
        structural = 0
        if contract_data.get('is_verified') is False:
            structural += 25
            critical_flags.append('Contract not verified')
        age = contract_data.get('contract_age_days')
        if age is not None and age < 7:
            structural += 20
            critical_flags.append(f'Contract age: {age} days')
        if contract_data.get('has_mint'):
            structural += 15
            critical_flags.append('Mint function detected')
        if contract_data.get('has_proxy'):
            structural += 15
            critical_flags.append('Proxy/upgradeable contract')
        if contract_data.get('has_pause'):
            structural += 10
        if contract_data.get('has_blacklist'):
            structural += 10
            critical_flags.append('Blacklist function detected')
        if contract_data.get('scam_matches'):
            structural += 30
            critical_flags.append(f'Scam DB match ({len(contract_data["scam_matches"])} sources)')
        if contract_data.get('ownership_renounced') is False:
            structural += 5
        structural = min(structural, 100)

        # --- Market score (0-100) ---
        market = 0
        if dex_data.get('low_liquidity_flag'):
            market += 30
            critical_flags.append('Low liquidity (<$10k)')
        if dex_data.get('new_pair_flag'):
            market += 25
            critical_flags.append('New pair (<24h)')
        if dex_data.get('volatility_flag'):
            market += 20
            critical_flags.append('Extreme volatility (>200%)')
        if dex_data.get('wash_trade_flag'):
            market += 25
            critical_flags.append('Possible wash trading')

        # Volume/FDV anomaly - dead or manipulated token
        fdv = dex_data.get('fdv')
        volume_24h = dex_data.get('volume_24h')
        if fdv is not None and volume_24h is not None and fdv > 1_000_000 and volume_24h < 1000:
            market += 20
            volume_ratio = (volume_24h / fdv * 100) if fdv > 0 else 0
            critical_flags.append(f'Dead/Low activity (${fdv:,.0f} FDV, ${volume_24h:,.0f} volume, {volume_ratio:.4f}%)')

        market = min(market, 100)

        # --- Behavioral score (0-100) ---
        behavioral = 0
        if ethos_data.get('severe_reputation_flag'):
            behavioral += 50
            critical_flags.append('Severe reputation warning')
        elif ethos_data.get('low_reputation_flag'):
            behavioral += 30
            critical_flags.append('Low wallet reputation')
        if ethos_data.get('scam_flags'):
            behavioral += 40
            critical_flags.append('Ethos scam flags present')
        behavioral = min(behavioral, 100)

        # --- Honeypot score (0-100) ---
        honeypot_score = 0
        if honeypot_data.get('is_honeypot'):
            honeypot_score += 80
            critical_flags.append('Honeypot detected')
        if honeypot_data.get('simulation_failed') and not honeypot_data.get('is_honeypot'):
            honeypot_score += 40
            critical_flags.append('Honeypot simulation failed — treat as suspicious')
        if honeypot_data.get('can_sell') is False:
            honeypot_score += 60
            critical_flags.append('Cannot sell token')
        if honeypot_data.get('cannot_buy') is True:
            honeypot_score += 20
            critical_flags.append('Cannot buy token')
        if honeypot_data.get('cannot_sell_all') is True:
            honeypot_score += 20
            critical_flags.append('Cannot sell all tokens')
        if honeypot_data.get('transfer_pausable') is True:
            honeypot_score += 20
            critical_flags.append('Token transfers can be paused')
        sell_tax = honeypot_data.get('sell_tax')
        buy_tax = honeypot_data.get('buy_tax')
        if sell_tax is not None and sell_tax > 50:
            honeypot_score += 40
            critical_flags.append(f'Extreme sell tax: {sell_tax}%')
        elif sell_tax is not None and sell_tax > 20:
            honeypot_score += 20
        if buy_tax is not None and buy_tax > 20:
            honeypot_score += 10
        honeypot_score = min(honeypot_score, 100)

        # Unknown components do not dilute observed risks.
        from core.analyzer import AnalyzerResult

        component_results = [
            AnalyzerResult('structural', WEIGHT_STRUCTURAL, structural, data=contract_data),
            AnalyzerResult('market', WEIGHT_MARKET, market, data=dex_data),
            AnalyzerResult('behavioral', WEIGHT_BEHAVIORAL, behavioral, data=ethos_data),
            AnalyzerResult('honeypot', WEIGHT_HONEYPOT, honeypot_score, data=honeypot_data),
        ]
        composite, category_scores, coverage, coverage_reasons, covered_weight = self._covered_scores(component_results)
        required_unknown = is_token and coverage.get('honeypot', 0) < 1
        if required_unknown:
            critical_flags.append('Sellability unknown: ' + coverage_reasons.get('honeypot', 'Incomplete honeypot data'))

        # --- Escalation overrides (token-specific) ---
        has_mint = contract_data.get('has_mint', False)
        has_proxy = contract_data.get('has_proxy', False)
        ownership_renounced = contract_data.get('ownership_renounced', False)
        liquidity_info = dex_data.get('liquidity_usd')

        if is_token:
            if has_mint and has_proxy and ownership_renounced is False:
                composite = max(composite, 85)

            if not contract_data.get('is_contract') and honeypot_data.get('simulation_failed'):
                composite = max(composite, 80)

            if honeypot_data.get('is_honeypot'):
                sell_tax = honeypot_data.get('sell_tax')
                is_false_positive_candidate = liquidity_info is not None and sell_tax is not None and liquidity_info > 500_000 and sell_tax < 5
                is_proxy = contract_data.get('has_proxy', False)
                if not is_false_positive_candidate or (honeypot_data.get('low_tax_honeypot') and not is_proxy):
                    composite = max(composite, 80)

            if ethos_data.get('severe_reputation_flag'):
                pair_age = dex_data.get('pair_age_hours')
                if pair_age is not None and pair_age < 24:
                    composite = min(composite + 15, 100)

            if ownership_renounced and liquidity_info is not None and liquidity_info > 100_000 and honeypot_data.get('is_honeypot') is False and not required_unknown:
                composite = max(composite - 20, 0)

        rug_probability = round(min(max(composite, 0), 100), 1)

        # --- Risk level (uses calibration thresholds when available) ---
        high_t = self._calibration.high_threshold if self._calibration else 71
        med_t = self._calibration.medium_threshold if self._calibration else 31

        if rug_probability >= high_t:
            risk_level = 'HIGH'
        elif rug_probability >= med_t:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        if required_unknown and risk_level == 'LOW':
            risk_level = 'MEDIUM'

        # --- Risk archetype ---
        archetype = self._determine_archetype(
            contract_data, honeypot_data, dex_data, rug_probability,
            is_token=is_token,
        )

        if required_unknown and archetype == 'legitimate':
            archetype = 'unknown'

        # --- Confidence ---
        confidence = self._compute_confidence(contract_data, honeypot_data, dex_data, ethos_data)
        confidence = min(confidence, round(covered_weight * 100))

        # Deduplicate flags
        seen = set()
        unique_flags = []
        for f in critical_flags:
            if f not in seen:
                seen.add(f)
                unique_flags.append(f)

        return {
            'rug_probability': rug_probability,
            'risk_level': risk_level,
            'risk_archetype': archetype,
            'critical_flags': unique_flags,
            'confidence_level': confidence,
            'category_scores': category_scores,
            'coverage': coverage,
            'coverage_reasons': coverage_reasons,
            'status': 'unknown' if required_unknown or covered_weight < 1 - 1e-9 else 'ok',
        }

    def compute_from_results(self, results: List["AnalyzerResult"], is_token: bool = True) -> dict:
        """
        Compute composite risk from a list of AnalyzerResult objects.
        Produces identical output shape to compute_composite_risk().

        Args:
            results: List of AnalyzerResult from the registry pipeline.
            is_token: Whether the target contract is an ERC-20 token.
                      Non-token contracts (marketplaces, bridges, governance)
                      skip token-specific escalation rules.

        Expects pre-normalized weights (summing to 1.0).  The registry's
        run_all() handles normalization before results reach this method.
        """
        # Build lookup by analyzer name
        by_name = {r.name: r for r in results}

        # Extract underlying service data from each result
        contract_data = by_name.get("structural", _EMPTY_RESULT).data
        honeypot_data = by_name.get("honeypot", _EMPTY_RESULT).data
        dex_data = by_name.get("market", _EMPTY_RESULT).data
        ethos_data = by_name.get("behavioral", _EMPTY_RESULT).data

        composite, category_scores, coverage, coverage_reasons, covered_weight = self._covered_scores(results)
        required_unknown = is_token and coverage.get('honeypot', 0) < 1
        critical_flags = [flag for result in results for flag in result.flags]
        if required_unknown:
            critical_flags.append('Sellability unknown: ' + coverage_reasons.get('honeypot', 'No honeypot data'))

        # --- Escalation overrides ---
        # Token-specific escalation rules only apply to ERC-20 tokens.
        # Non-token contracts (marketplaces, bridges, governance) commonly
        # have proxy patterns, mint-like bytecode, and unrenounced ownership
        # as normal operational patterns — not rug indicators.
        has_mint = contract_data.get('has_mint', False)
        has_proxy = contract_data.get('has_proxy', False)
        ownership_renounced = contract_data.get('ownership_renounced', False)

        is_verified = contract_data.get('is_verified', True)
        has_blacklist = contract_data.get('has_blacklist', False)

        if is_token:
            if has_mint and has_proxy and ownership_renounced is False:
                composite = max(composite, 85)

            # Unverified contract with dangerous bytecode patterns — likely scam
            liquidity = dex_data.get('liquidity_usd')
            if not is_verified and (has_mint or has_blacklist) and ownership_renounced is False and liquidity is not None and liquidity < 100_000:
                composite = max(composite, 55)

            # No contract bytecode + honeypot simulation failed → destroyed scam token
            if not contract_data.get('is_contract') and honeypot_data.get('simulation_failed'):
                composite = max(composite, 80)

            # Honeypot escalation — floor at 80 if confirmed
            if honeypot_data.get('is_honeypot'):
                sell_tax = honeypot_data.get('sell_tax')
                is_false_positive_candidate = liquidity is not None and sell_tax is not None and liquidity > 500_000 and sell_tax < 5
                is_proxy = contract_data.get('has_proxy', False)
                if not is_false_positive_candidate or (honeypot_data.get('low_tax_honeypot') and not is_proxy):
                    composite = max(composite, 80)

            if ethos_data.get('severe_reputation_flag'):
                pair_age = dex_data.get('pair_age_hours')
                if pair_age is not None and pair_age < 24:
                    composite = min(composite + 15, 100)

            # Positive signals — reduce score for renounced ownership with high liquidity
            liquidity_info = dex_data.get('liquidity_usd')
            if ownership_renounced and liquidity_info is not None and liquidity_info > 100_000 and honeypot_data.get('is_honeypot') is False and not required_unknown:
                composite = max(composite - 20, 0)
        else:
            # Non-token: only escalate for verified scam matches or behavioral flags
            if contract_data.get('scam_matches'):
                composite = max(composite, 70)
            if ethos_data.get('severe_reputation_flag') and ethos_data.get('scam_flags'):
                composite = min(composite + 10, 100)

        rug_probability = round(min(max(composite, 0), 100), 1)

        high_t = self._calibration.high_threshold if self._calibration else 71
        med_t = self._calibration.medium_threshold if self._calibration else 31

        if rug_probability >= high_t:
            risk_level = 'HIGH'
        elif rug_probability >= med_t:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        if required_unknown and risk_level == 'LOW':
            risk_level = 'MEDIUM'

        archetype = self._determine_archetype(
            contract_data, honeypot_data, dex_data, rug_probability,
            is_token=is_token,
        )

        confidence = self._compute_confidence(contract_data, honeypot_data, dex_data, ethos_data)
        # Apply calibration confidence boost if available
        if self._calibration and self._calibration.confidence_boost:
            confidence = min(100, confidence + self._calibration.confidence_boost)
        confidence = min(confidence, round(covered_weight * 100))
        if required_unknown and archetype == 'legitimate':
            archetype = 'unknown'

        # Deduplicate flags
        seen = set()
        unique_flags = []
        for f in critical_flags:
            if f not in seen:
                seen.add(f)
                unique_flags.append(f)

        return {
            'rug_probability': rug_probability,
            'risk_level': risk_level,
            'risk_archetype': archetype,
            'critical_flags': unique_flags,
            'confidence_level': confidence,
            'category_scores': category_scores,
            'coverage': coverage,
            'coverage_reasons': coverage_reasons,
            'status': 'unknown' if required_unknown or covered_weight < 1 - 1e-9 else 'ok',
        }

    def _covered_scores(self, results):
        coverage = {}
        reasons = {}
        scores = {}
        included = []
        covered_weight = 0
        for result in results:
            data = result.data
            fields = data.get('coverage')
            simulation_failed = result.name == 'honeypot' and data.get('simulation_failed')
            if simulation_failed:
                fields = dict(fields) if isinstance(fields, dict) and fields else {
                    field: data.get(field) is not None
                    for field in ('is_honeypot', 'can_sell', 'buy_tax', 'sell_tax')
                }
                fields['can_sell'] = False
            if result.error:
                fraction = 0
            elif data.get('skipped'):
                fraction = 1
            elif isinstance(fields, dict) and fields:
                fraction = sum(value is True for value in fields.values()) / len(fields)
            elif result.name == 'honeypot':
                required = ('is_honeypot', 'can_sell', 'buy_tax', 'sell_tax')
                fraction = sum(data.get(key) is not None for key in required) / len(required)
            else:
                fraction = 1 if data and data.get('status') != 'unknown' else 0
            coverage[result.name] = fraction
            covered_weight += result.weight * fraction
            if fraction < 1:
                reasons[result.name] = result.error or (
                    'Honeypot simulation failed (unresolved)' if simulation_failed
                    else data.get('reason') or 'Provider data unavailable or incomplete'
                )
            # Known adverse evidence remains actionable even if other fields are unknown.
            if not result.error and (fraction == 1 or result.score > 0):
                included.append(result)
                scores[result.name] = round(result.score, 1)
            else:
                scores[result.name] = None
        weight = sum(result.weight for result in included)
        composite = sum(result.score * result.weight for result in included)
        if weight and abs(weight - 1) > 1e-9:
            composite /= weight
        return composite, scores, coverage, reasons, covered_weight

    def _determine_archetype(self, contract_data, honeypot_data, dex_data, rug_prob, is_token=True):
        # Token-specific archetypes only apply to ERC-20 tokens.
        # Non-token contracts should never be labelled honeypot/rug_pull
        # based on token-oriented heuristics.
        if is_token:
            if honeypot_data.get('is_honeypot') or honeypot_data.get('can_sell') is False:
                return 'honeypot'
            if dex_data.get('wash_trade_flag'):
                return 'wash_traded'
            if (contract_data.get('has_mint') and contract_data.get('has_proxy')
                    and not contract_data.get('ownership_renounced')):
                return 'rug_pull'
        if rug_prob >= 71:
            return 'high_risk_contract'
        return 'legitimate'

    def _compute_confidence(self, contract_data, honeypot_data, dex_data, ethos_data):
        score = 0
        total = 0

        # Contract data quality
        total += 30
        if contract_data.get('is_contract'):
            score += 10
        if contract_data.get('is_verified') is not None:
            score += 10
        if contract_data.get('contract_age_days') is not None:
            score += 10

        # Honeypot data
        total += 25
        if honeypot_data.get('is_honeypot') is not None:
            score += 15
        if honeypot_data.get('sell_tax') is not None and honeypot_data['sell_tax'] >= 0:
            score += 10

        # DEX data
        total += 25
        if dex_data.get('liquidity_usd') is not None and dex_data['liquidity_usd'] > 0:
            score += 15
        if dex_data.get('pair_age_hours') is not None:
            score += 10

        # Ethos data
        total += 20
        if ethos_data.get('reputation_score') is not None and ethos_data['reputation_score'] != 50:
            score += 20

        return round((score / total) * 100) if total else 50
