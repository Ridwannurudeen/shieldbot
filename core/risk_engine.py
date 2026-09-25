import logging
from typing import List, Optional, TYPE_CHECKING

from core.verdicts import BLOCK_MIN, HIGH, LOW, MEDIUM, level_from_score

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

# A scam match's severity sets what it does to a score. 'block' (GoPlus labels the token a scam, or
# an admin confirmed the address) floors it at 90; 'high', the default, is a scam database finding
# with the 70 floor. 'medium' is a crowd signal: a community blacklist entry, which anyone who can
# send reports can create. It raises a score to MEDIUM_MATCH_FLOOR, inside the CAUTION band, is shown
# by its reason, and is never counted as a scam database match.
MEDIUM_MATCH_FLOOR = 40
# A confirmed honeypot's floor on a token: deep liquidity and low taxes do not make a token that cannot
# be sold safe to buy.
HONEYPOT_FLOOR = 80


def _is_medium(match) -> bool:
    return isinstance(match, dict) and match.get('severity') == 'medium'


def database_matches(matches) -> list:
    """The matches that are scam database findings: every match except a medium-severity one."""
    return [match for match in matches or () if not _is_medium(match)]


def medium_matches(matches) -> list:
    """The medium-severity matches (community reports)."""
    return [match for match in matches or () if _is_medium(match)]


def scam_match_floor(matches) -> int:
    """The score floor a target's scam matches set, as the engine applies them: 90 for a
    block-severity match, 70 for any other scam database match, MEDIUM_MATCH_FLOOR for community
    reports alone, otherwise 0. The legacy scanner applies it in one step."""
    if any(isinstance(match, dict) and match.get('severity') == 'block' for match in matches or ()):
        return 90
    if database_matches(matches):
        return 70
    return MEDIUM_MATCH_FLOOR if medium_matches(matches) else 0


def apply_local_match(risk_output: dict, match: Optional[dict]) -> dict:
    """risk_output with the target's local blacklist match (ScamDatabase.local_match) applied as
    compute_from_results applies a scam match. The structural analyzer reports the match among its
    scam matches only when it returns, so one that failed or ran past the deadline would drop an
    admin entry's Block. Applying a match the analyzer did report changes nothing: the floor is a max.

    A block floor makes the level HIGH and is a hard floor. A community match holds the CAUTION band
    and is never HIGH on its own, and score_before_community_floor stays without it."""
    if not match:
        return risk_output
    floor = scam_match_floor([match])
    output = dict(risk_output)
    output['rug_probability'] = round(min(max(output['rug_probability'], floor), 100), 1)
    if database_matches([match]):
        output['score_before_community_floor'] = round(min(max(output['score_before_community_floor'], floor), 100), 1)
    # A scam match is never LOW, and a block floor is HIGH whatever the calibrated thresholds.
    if floor >= BLOCK_MIN:
        output['risk_level'] = HIGH
        output['transaction_floor'] = max(output['transaction_floor'] or 0, floor)
    elif output['risk_level'] == LOW:
        output['risk_level'] = MEDIUM
    # The match's reason leads, as a fired floor's does.
    if match['reason'] not in output['critical_flags']:
        output['critical_flags'] = [match['reason'], *output['critical_flags']]
    return output


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
        is_token: Optional[bool] = True,
    ) -> dict:
        scam_matches = contract_data.get('scam_matches')
        hard_matches = database_matches(scam_matches)
        # A community report's reason leads, so the extension, which shows three flags, always names it.
        critical_flags = [match['reason'] for match in medium_matches(scam_matches)]

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
        if contract_data.get('has_destroy') and contract_data.get('ownership_renounced') is not True:
            structural += 15
            critical_flags.append('destroy() function: the owner may be able to delete the contract')
        if hard_matches:
            structural += 30
            critical_flags.append(f'Scam DB match ({len(hard_matches)} sources)')
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
            # The doubt is explanation only: the simulated sell still failed, so the score stands.
            if honeypot_data.get('likely_false_positive'):
                critical_flags.append('Honeypot flag may be a false positive: the contract is verified and its taxes are normal')
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
        composite, category_scores, coverage, coverage_reasons, covered_weight, _ = self._covered_scores(component_results)
        required_unknown = is_token is not False and coverage.get('honeypot', 0) < 1
        incomplete = required_unknown or covered_weight < 1 - 1e-9 or any(fraction < 1 for fraction in coverage.values())
        if required_unknown:
            critical_flags.append('Sellability unknown: ' + coverage_reasons.get('honeypot', 'Incomplete honeypot data'))

        # --- Escalation overrides (token-specific) ---
        has_mint = contract_data.get('has_mint', False)
        has_proxy = contract_data.get('has_proxy', False)
        ownership_renounced = contract_data.get('ownership_renounced', False)
        liquidity_info = dex_data.get('liquidity_usd')

        if is_token is not False:
            if has_mint and has_proxy and ownership_renounced is False:
                composite = max(composite, 85)

            if contract_data.get('is_contract') is False and honeypot_data.get('simulation_failed'):
                composite = max(composite, 80)

            # A confirmed honeypot floors at HONEYPOT_FLOOR.
            if honeypot_data.get('is_honeypot'):
                composite = max(composite, HONEYPOT_FLOOR)

            if ethos_data.get('severe_reputation_flag'):
                pair_age = dex_data.get('pair_age_hours')
                if pair_age is not None and pair_age < 24:
                    composite = min(composite + 15, 100)

            # A failed scam lookup or bytecode scan is not a clean one, so it earns no positive signal.
            contract_coverage = contract_data.get('coverage', {})
            checks_covered = contract_coverage.get('scam_database', True) and contract_coverage.get('bytecode', True)
            # A community report does not withhold the discount: its only effect is its floor below.
            if ownership_renounced and liquidity_info is not None and liquidity_info > 100_000 and honeypot_data.get('is_honeypot') is False and not required_unknown and not hard_matches and checks_covered:
                composite = max(composite - 20, 0)

            if hard_matches:
                composite = max(composite, 70)

        # A block-severity scam match (GoPlus labels the token a scam, or an admin confirmed the
        # address) is a BLOCK on every target type. A community report holds the CAUTION band on every
        # target type and never adds more.
        floor = 90 if any(
            isinstance(match, dict) and match.get('severity') == 'block' for match in scam_matches or []
        ) else 0
        # The score without the community floor: the firewall's revert rule reads it, so a crowd
        # signal can neither cause that escalation nor mask it.
        score_before_community_floor = round(min(max(composite, floor, 0), 100), 1)
        # Not a hard floor: transaction_floor reports only those.
        community_floor = MEDIUM_MATCH_FLOOR if medium_matches(scam_matches) else 0
        composite = max(composite, floor, community_floor)

        rug_probability = round(min(max(composite, 0), 100), 1)

        # --- Risk level (uses calibration thresholds when available) ---
        risk_level = level_from_score(rug_probability, self._calibration)

        if incomplete and risk_level == LOW:
            risk_level = MEDIUM

        # A calibrated medium threshold can sit above the scam floor; a scam match is never LOW.
        if contract_data.get('scam_matches') and risk_level == LOW:
            risk_level = MEDIUM

        if floor >= BLOCK_MIN:
            risk_level = HIGH

        # --- Risk archetype ---
        archetype = self._determine_archetype(
            contract_data, honeypot_data, dex_data, rug_probability,
            is_token=is_token,
        )

        if incomplete and archetype == 'legitimate':
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
            'observed_at': min((r.data.get('observed_at', 0) for r in component_results if r.data and not r.data.get('skipped')), default=0),
            'rug_probability': rug_probability,
            'risk_level': risk_level,
            'risk_archetype': archetype,
            'critical_flags': unique_flags,
            'confidence_level': confidence,
            'category_scores': category_scores,
            'coverage': coverage,
            'coverage_reasons': coverage_reasons,
            'status': 'unknown' if incomplete else 'ok',
            'transaction_floor': floor or None,
            'score_before_community_floor': score_before_community_floor,
            'notes': [],
        }

    def compute_from_results(self, results: List["AnalyzerResult"], is_token: Optional[bool] = True) -> dict:
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

        composite, category_scores, coverage, coverage_reasons, covered_weight, tx_share = self._covered_scores(results)
        required_unknown = is_token is not False and coverage.get('honeypot', 0) < 1
        incomplete = required_unknown or covered_weight < 1 - 1e-9 or any(fraction < 1 for fraction in coverage.values())
        # A fired floor's reason leads: the extension overlay shows only the first three flags.
        ordered = sorted(results, key=lambda result: not (result.data.get('floor') and not result.error))
        critical_flags = [flag for result in ordered for flag in result.flags]
        if required_unknown:
            # A measured can_sell is known either way, so only the rest of the honeypot data is
            # unknown. The honeypot analyzer uses the same labels, and its flag already carries a reason.
            label = 'Honeypot coverage unknown: ' if honeypot_data.get('can_sell') is not None else 'Sellability unknown: '
            if not any(flag.startswith(label) for flag in critical_flags):
                critical_flags.append(label + coverage_reasons.get('honeypot', 'No honeypot data'))
        # An analyzer's notes name what an add-only signal could not measure (data['notes']). The gap
        # changes no score and no status, so it is information, not a danger signal: notes have their
        # own list and never enter critical_flags. Contract: only an analyzer writes data['notes']
        # (structural and market do); no provider's data carries that key, so every result's notes
        # are its analyzer's.
        notes = [note for result in results if not result.error for note in result.data.get('notes', ())]

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
        # A community report is not a scam database match: it takes no 70 floor, only its own below.
        hard_matches = database_matches(contract_data.get('scam_matches'))

        if is_token is not False:
            if has_mint and has_proxy and ownership_renounced is False:
                composite = max(composite, 85)

            # Unverified contract with dangerous bytecode patterns — likely scam
            liquidity = dex_data.get('liquidity_usd')
            if is_verified is False and (has_mint or has_blacklist) and ownership_renounced is False and liquidity is not None and liquidity < 100_000:
                composite = max(composite, 55)

            # No contract bytecode + honeypot simulation failed → destroyed scam token
            if contract_data.get('is_contract') is False and honeypot_data.get('simulation_failed'):
                composite = max(composite, 80)

            # Honeypot escalation — floor at HONEYPOT_FLOOR if confirmed.
            if honeypot_data.get('is_honeypot'):
                composite = max(composite, HONEYPOT_FLOOR)

            if ethos_data.get('severe_reputation_flag'):
                pair_age = dex_data.get('pair_age_hours')
                if pair_age is not None and pair_age < 24:
                    composite = min(composite + 15, 100)

            # Positive signals — reduce score for renounced ownership with high liquidity.
            # A failed scam lookup or bytecode scan is not a clean one, so it earns no positive signal.
            # The signal describes the token, so it never discounts the transaction's own share. A
            # community report does not withhold it: its only effect is its floor below.
            liquidity_info = dex_data.get('liquidity_usd')
            contract_coverage = contract_data.get('coverage', {})
            checks_covered = contract_coverage.get('scam_database', True) and contract_coverage.get('bytecode', True)
            if ownership_renounced and liquidity_info is not None and liquidity_info > 100_000 and honeypot_data.get('is_honeypot') is False and not required_unknown and not hard_matches and checks_covered:
                composite = max(composite - 20, tx_share)

            if hard_matches:
                composite = max(composite, 70)
        else:
            # Non-token: only escalate for verified scam matches or behavioral flags
            if hard_matches:
                composite = max(composite, 70)
            if ethos_data.get('severe_reputation_flag') and ethos_data.get('scam_flags'):
                composite = min(composite + 10, 100)

        # Hard floors: a rule an analyzer declares from evidence it owns (an approval to a wallet, a
        # pay-to-claim contract) holds whatever the weighted mean and the discount say, and so does
        # a block-severity scam match (GoPlus labels the token a scam, or an admin confirmed the
        # address). A community report holds the CAUTION band and never adds more.
        floor = max((result.data.get('floor') or 0 for result in results if not result.error), default=0)
        if any(
            isinstance(match, dict) and match.get('severity') == 'block' for match in contract_data.get('scam_matches') or []
        ):
            floor = max(floor, 90)
        # The score without the community floor: the firewall's revert rule reads it, so a crowd
        # signal can neither cause that escalation nor mask it.
        score_before_community_floor = round(min(max(composite, floor, 0), 100), 1)
        # Not a hard floor: transaction_floor reports only those.
        community_floor = MEDIUM_MATCH_FLOOR if medium_matches(contract_data.get('scam_matches')) else 0
        composite = max(composite, floor, community_floor)

        rug_probability = round(min(max(composite, 0), 100), 1)

        risk_level = level_from_score(rug_probability, self._calibration)

        if incomplete and risk_level == LOW:
            risk_level = MEDIUM

        # A calibrated medium threshold can sit above the scam floor; a scam match is never LOW.
        if contract_data.get('scam_matches') and risk_level == LOW:
            risk_level = MEDIUM

        # A fired floor is never LOW, and one at the extension's fixed BLOCK boundary is HIGH
        # whatever the calibrated thresholds, so the RPC proxy (which blocks on HIGH) agrees.
        if floor >= BLOCK_MIN:
            risk_level = HIGH
        elif floor and risk_level == LOW:
            risk_level = MEDIUM

        archetype = self._determine_archetype(
            contract_data, honeypot_data, dex_data, rug_probability,
            is_token=is_token,
        )

        confidence = self._compute_confidence(contract_data, honeypot_data, dex_data, ethos_data)
        # Apply calibration confidence boost if available
        if self._calibration and self._calibration.confidence_boost:
            confidence = min(100, confidence + self._calibration.confidence_boost)
        confidence = min(confidence, round(covered_weight * 100))
        if incomplete and archetype == 'legitimate':
            archetype = 'unknown'

        # Deduplicate flags
        seen = set()
        unique_flags = []
        for f in critical_flags:
            if f not in seen:
                seen.add(f)
                unique_flags.append(f)

        return {
            'observed_at': min((r.data.get('observed_at', 0) for r in results if r.data and not r.error and not r.data.get('skipped')), default=0),
            'rug_probability': rug_probability,
            'risk_level': risk_level,
            'risk_archetype': archetype,
            'critical_flags': unique_flags,
            'confidence_level': confidence,
            'category_scores': category_scores,
            'coverage': coverage,
            'coverage_reasons': coverage_reasons,
            'status': 'unknown' if incomplete else 'ok',
            'transaction_floor': floor or None,
            'score_before_community_floor': score_before_community_floor,
            'notes': notes,
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
            structural_missing = []
            if result.name == 'structural':
                fields = dict(fields) if isinstance(fields, dict) else {}
                for field in ('is_verified', 'contract_age_days') if data.get('is_contract') is not False else ():
                    fields[field] = data.get(field) is not None
                    if not fields[field]:
                        structural_missing.append(field)
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
            if fraction == 1 and data.get('status') == 'unknown':
                fraction = 0
            coverage[result.name] = fraction
            covered_weight += result.weight * fraction
            if fraction < 1:
                reasons[result.name] = result.error or (
                    'Honeypot simulation failed (unresolved)' if simulation_failed
                    else data.get('reason') or (
                        'Structural data unknown: ' + ', '.join(structural_missing)
                        if structural_missing else 'Provider data unavailable or incomplete'
                    )
                )
            # A skipped analyzer does not apply to this target (a non-token has no market and no
            # sellability): it is covered, but a zero from it would only dilute the others.
            if not result.error and data.get('skipped'):
                scores[result.name] = 0.0
            # Known adverse evidence remains actionable even if other fields are unknown.
            elif not result.error and (fraction == 1 or result.score > 0):
                included.append(result)
                scores[result.name] = round(result.score, 1)
            else:
                scores[result.name] = None
        weight = sum(result.weight for result in included)
        composite = sum(result.score * result.weight for result in included)
        # The part of the mean that describes the transaction (calldata, typed data), not the target.
        tx_share = sum(result.score * result.weight for result in included if result.name in ('intent', 'signature'))
        if weight and abs(weight - 1) > 1e-9:
            composite /= weight
            tx_share /= weight
        return composite, scores, coverage, reasons, covered_weight, tx_share

    def _determine_archetype(self, contract_data, honeypot_data, dex_data, rug_prob, is_token: Optional[bool] = True):
        # Token-specific archetypes only apply to ERC-20 tokens.
        # Non-token contracts should never be labelled honeypot/rug_pull
        # based on token-oriented heuristics.
        if is_token is not False:
            if honeypot_data.get('is_honeypot') or honeypot_data.get('can_sell') is False:
                return 'honeypot'
            if dex_data.get('wash_trade_flag'):
                return 'wash_traded'
            if (contract_data.get('has_mint') and contract_data.get('has_proxy')
                    and contract_data.get('ownership_renounced') is False):
                return 'rug_pull'
        if rug_prob >= BLOCK_MIN:
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
