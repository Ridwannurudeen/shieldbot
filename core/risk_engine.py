import logging

logger = logging.getLogger(__name__)

RISK_ARCHETYPES = {
    'honeypot': 'Honeypot',
    'rug_pull': 'Rug Pull',
    'wash_traded': 'Wash Traded',
    'high_risk_contract': 'High-Risk Contract',
    'legitimate': 'Legitimate',
}

# Category weights
WEIGHT_STRUCTURAL = 0.40
WEIGHT_MARKET = 0.25
WEIGHT_BEHAVIORAL = 0.20
WEIGHT_HONEYPOT = 0.15


class RiskEngine:
    """Composite weighted risk scoring across all data sources."""

    def compute_composite_risk(
        self,
        contract_data: dict,
        honeypot_data: dict,
        dex_data: dict,
        ethos_data: dict,
    ) -> dict:
        critical_flags = []

        # --- Structural score (0-100) ---
        structural = 0
        if not contract_data.get('is_verified'):
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
        fdv = dex_data.get('fdv', 0)
        volume_24h = dex_data.get('volume_24h', 0)
        if fdv > 1_000_000 and volume_24h < 1000:
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
        if not honeypot_data.get('can_sell'):
            honeypot_score += 60
            critical_flags.append('Cannot sell token')
        sell_tax = honeypot_data.get('sell_tax', 0)
        buy_tax = honeypot_data.get('buy_tax', 0)
        if sell_tax > 50:
            honeypot_score += 40
            critical_flags.append(f'Extreme sell tax: {sell_tax}%')
        elif sell_tax > 20:
            honeypot_score += 20
        if buy_tax > 20:
            honeypot_score += 10
        honeypot_score = min(honeypot_score, 100)

        # --- Composite weighted score ---
        composite = (
            structural * WEIGHT_STRUCTURAL
            + market * WEIGHT_MARKET
            + behavioral * WEIGHT_BEHAVIORAL
            + honeypot_score * WEIGHT_HONEYPOT
        )

        # --- Escalation overrides ---
        has_mint = contract_data.get('has_mint', False)
        has_proxy = contract_data.get('has_proxy', False)
        ownership_renounced = contract_data.get('ownership_renounced', False)

        # mint + proxy + ownership not renounced → likely rug
        if has_mint and has_proxy and ownership_renounced is False:
            composite = max(composite, 85)

        # honeypot confirmed → floor at 80
        if honeypot_data.get('is_honeypot'):
            composite = max(composite, 80)

        # severe reputation + new pair → escalate
        if ethos_data.get('severe_reputation_flag'):
            pair_age = dex_data.get('pair_age_hours')
            if pair_age is not None and pair_age < 24:
                composite = min(composite + 15, 100)

        # positive signals → reduce
        liquidity_info = dex_data.get('liquidity_usd', 0)
        if ownership_renounced and liquidity_info > 100_000:
            composite = max(composite - 20, 0)

        rug_probability = round(min(max(composite, 0), 100), 1)

        # --- Risk level ---
        if rug_probability >= 71:
            risk_level = 'HIGH'
        elif rug_probability >= 31:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        # --- Risk archetype ---
        archetype = self._determine_archetype(
            contract_data, honeypot_data, dex_data, rug_probability
        )

        # --- Confidence ---
        confidence = self._compute_confidence(contract_data, honeypot_data, dex_data, ethos_data)

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
            'category_scores': {
                'structural': round(structural, 1),
                'market': round(market, 1),
                'behavioral': round(behavioral, 1),
                'honeypot': round(honeypot_score, 1),
            },
        }

    def _determine_archetype(self, contract_data, honeypot_data, dex_data, rug_prob):
        if honeypot_data.get('is_honeypot') or not honeypot_data.get('can_sell', True):
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
        if honeypot_data.get('sell_tax', -1) >= 0:
            score += 10

        # DEX data
        total += 25
        if dex_data.get('liquidity_usd', 0) > 0:
            score += 15
        if dex_data.get('pair_age_hours') is not None:
            score += 10

        # Ethos data
        total += 20
        if ethos_data.get('reputation_score', 50) != 50:
            score += 20

        return round((score / total) * 100) if total else 50
