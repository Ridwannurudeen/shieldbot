"""Formats composite risk data into a full Telegram intelligence report."""


def format_full_report(
    risk_output: dict,
    contract_data: dict,
    dex_data: dict,
    ethos_data: dict,
    honeypot_data: dict = None,
    address: str = '',
    ai_analysis: str = None,
    token_info: dict = None,
) -> str:
    rug_prob = risk_output.get('rug_probability', 0)
    risk_level = risk_output.get('risk_level', 'UNKNOWN')
    archetype = risk_output.get('risk_archetype', 'unknown')
    confidence = risk_output.get('confidence_level', 0)
    flags = risk_output.get('critical_flags', [])
    scores = risk_output.get('category_scores', {})
    incomplete = risk_output.get('status') == 'unknown' or risk_level == 'UNKNOWN'
    coverage_reasons = risk_output.get('coverage_reasons', {})

    # Verdict emoji
    if rug_prob >= 71:
        verdict_icon = '\U0001F6A8'  # 🚨
    elif rug_prob >= 50:
        verdict_icon = '\U0001F534'  # 🔴
    elif rug_prob >= 31 or incomplete or risk_level in ('MEDIUM', 'HIGH'):
        verdict_icon = '\U0001F7E1'  # 🟡
    else:
        verdict_icon = '\U0001F7E2'  # 🟢

    lines = []

    # Header
    lines.append(f'{verdict_icon} *ShieldBot Intelligence Report*')
    lines.append('')

    # Target (with token name and symbol if available)
    if token_info and token_info.get('name') and token_info.get('symbol'):
        lines.append(f'*Token:* {token_info["name"]} ({token_info["symbol"]})')
        lines.append(f'*Address:* `{address}`')
    else:
        lines.append(f'*Target:* `{address}`')
    lines.append(f'*Risk Archetype:* {archetype.replace("_", " ").title()}')
    probability = 'Unknown (incomplete coverage)' if incomplete else f'{rug_prob}%'
    lines.append(f'*Rug Probability:* {probability}  |  *Risk Level:* {risk_level}')
    lines.append(f'*Confidence:* {confidence}%')
    lines.append('')

    # Critical flags
    if flags:
        lines.append('*\U000026A0 Critical Flags:*')
        for flag in flags:
            lines.append(f'  \u2022 {flag}')
        lines.append('')

    # Category scores
    lines.append('*Category Breakdown:*')
    for category in ('structural', 'market', 'behavioral', 'honeypot'):
        score = scores.get(category)
        value = f'{score}/100' if score is not None else 'Unknown'
        reason = coverage_reasons.get(category)
        if reason:
            value += f' ({reason})'
        lines.append(f'  {category.title()}: {value}')
    lines.append('')

    # Contract analysis
    lines.append('*\U0001F4DC Contract Analysis:*')
    verified_value = contract_data.get('is_verified')
    verified = 'Unknown' if verified_value is None else ('\u2705' if verified_value else '\u274C')
    lines.append(f'  Verified: {verified}')
    age = contract_data.get('contract_age_days')
    lines.append(f'  Age: {age} days' if age is not None else '  Age: Unknown')
    ownership = contract_data.get('ownership_renounced')
    renounced = 'Unknown' if ownership is None else ('\u2705' if ownership else '\u274C')
    lines.append(f'  Ownership Renounced: {renounced}')

    bytecode_warnings = contract_data.get('bytecode_warnings', [])
    if bytecode_warnings:
        lines.append(f'  Bytecode Warnings: {", ".join(bytecode_warnings)}')
    source_patterns = contract_data.get('source_code_patterns', [])
    if source_patterns:
        lines.append(f'  Source Patterns: {", ".join(source_patterns)}')
    scam_matches = contract_data.get('scam_matches', [])
    if scam_matches:
        lines.append(f'  Scam DB Hits: {len(scam_matches)}')
    lines.append('')

    # Market intelligence
    lines.append('*\U0001F4CA Market Intelligence:*')
    market_reason = dex_data.get('reason') or 'Provider data unavailable'
    for key, label in (('liquidity_usd', 'Liquidity'), ('volume_24h', '24h Volume'), ('fdv', 'FDV')):
        value = dex_data.get(key)
        rendered = f'${value:,.0f}' if value is not None else f'Unknown ({market_reason})'
        lines.append(f'  {label}: {rendered}')
    change = dex_data.get('price_change_24h')
    rendered_change = f'{change:+.1f}%' if change is not None else f'Unknown ({market_reason})'
    lines.append(f'  24h Price Change: {rendered_change}')
    pair_age = dex_data.get('pair_age_hours')
    lines.append(f'  Pair Age: {pair_age:.1f}h' if pair_age is not None else f'  Pair Age: Unknown ({market_reason})')

    dex_flags = []
    if dex_data.get('low_liquidity_flag'):
        dex_flags.append('Low Liquidity')
    if dex_data.get('wash_trade_flag'):
        dex_flags.append('Wash Trading')
    if dex_data.get('volatility_flag'):
        dex_flags.append('High Volatility')
    if dex_data.get('new_pair_flag'):
        dex_flags.append('New Pair')
    if dex_flags:
        lines.append(f'  Flags: {", ".join(dex_flags)}')
    lines.append('')

    # Wallet reputation
    lines.append('*\U0001F464 Wallet Reputation (Ethos):*')
    rep_score = ethos_data.get('reputation_score', 50)
    trust = ethos_data.get('trust_level', 'unknown')
    lines.append(f'  Score: {rep_score}  |  Trust: {trust}')
    ethos_flags = ethos_data.get('scam_flags', [])
    if ethos_flags:
        lines.append(f'  Scam Flags: {", ".join(str(f) for f in ethos_flags)}')
    linked = ethos_data.get('linked_wallets', [])
    if linked:
        lines.append(f'  Linked Wallets: {len(linked)}')
    lines.append('')

    # Trade simulation
    if honeypot_data is not None:
        lines.append('*\U0001F9EA Trade Simulation:*')
        reason = honeypot_data.get('reason') or honeypot_data.get('honeypot_reason') or 'Provider data unavailable'
        is_honeypot = honeypot_data.get('is_honeypot')
        if is_honeypot is None:
            hp = f'Unknown ({reason})'
        else:
            hp = '\u274C Honeypot' if is_honeypot else '\u2705 Not Honeypot'
        lines.append(f'  {hp}')
        for key, label in (('buy_tax', 'Buy Tax'), ('sell_tax', 'Sell Tax')):
            value = honeypot_data.get(key)
            rendered = f'{value}%' if value is not None else f'Unknown ({reason})'
            lines.append(f'  {label}: {rendered}')
        for key, label in (('can_buy', 'Buyability'), ('can_sell', 'Sellability')):
            value = honeypot_data.get(key)
            rendered = f'Unknown ({reason})' if value is None else ('Yes' if value else 'No')
            lines.append(f'  {label}: {rendered}')
        if reason and reason not in ('Unknown', 'None', ''):
            lines.append(f'  Reason: {reason}')
        lines.append('')

    # AI Analysis
    if ai_analysis:
        lines.append('*\U0001F9E0 AI Analysis:*')
        lines.append(ai_analysis)
        lines.append('')

    # Final verdict
    lines.append('*Final Verdict:*')
    if rug_prob >= 71:
        lines.append(f'{verdict_icon} DO NOT PROCEED — Rug probability {rug_prob}%')
    elif rug_prob >= 31 or incomplete or risk_level in ('MEDIUM', 'HIGH'):
        detail = 'Unknown risk: provider coverage incomplete' if incomplete else f'Moderate risk ({rug_prob}%)'
        lines.append(f'{verdict_icon} PROCEED WITH CAUTION — {detail}')
    else:
        lines.append(f'{verdict_icon} Generally Safe — Low risk ({rug_prob}%)')

    return '\n'.join(lines)
