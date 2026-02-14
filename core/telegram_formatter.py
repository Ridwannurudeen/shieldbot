"""Formats composite risk data into a full Telegram intelligence report."""


def format_full_report(
    risk_output: dict,
    contract_data: dict,
    dex_data: dict,
    ethos_data: dict,
    honeypot_data: dict = None,
    address: str = '',
    ai_analysis: str = None,
) -> str:
    rug_prob = risk_output.get('rug_probability', 0)
    risk_level = risk_output.get('risk_level', 'UNKNOWN')
    archetype = risk_output.get('risk_archetype', 'unknown')
    confidence = risk_output.get('confidence_level', 0)
    flags = risk_output.get('critical_flags', [])
    scores = risk_output.get('category_scores', {})

    # Verdict emoji
    if rug_prob >= 71:
        verdict_icon = '\U0001F6A8'  # 🚨
    elif rug_prob >= 50:
        verdict_icon = '\U0001F534'  # 🔴
    elif rug_prob >= 31:
        verdict_icon = '\U0001F7E1'  # 🟡
    else:
        verdict_icon = '\U0001F7E2'  # 🟢

    lines = []

    # Header
    lines.append(f'{verdict_icon} *ShieldBot Intelligence Report*')
    lines.append('')

    # Target
    lines.append(f'*Target:* `{address}`')
    lines.append(f'*Risk Archetype:* {archetype.replace("_", " ").title()}')
    lines.append(f'*Rug Probability:* {rug_prob}%  |  *Risk Level:* {risk_level}')
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
    lines.append(f'  Structural: {scores.get("structural", 0)}/100')
    lines.append(f'  Market: {scores.get("market", 0)}/100')
    lines.append(f'  Behavioral: {scores.get("behavioral", 0)}/100')
    lines.append(f'  Honeypot: {scores.get("honeypot", 0)}/100')
    lines.append('')

    # Contract analysis
    lines.append('*\U0001F4DC Contract Analysis:*')
    verified = '\u2705' if contract_data.get('is_verified') else '\u274C'
    lines.append(f'  Verified: {verified}')
    age = contract_data.get('contract_age_days')
    lines.append(f'  Age: {age} days' if age is not None else '  Age: Unknown')
    renounced = '\u2705' if contract_data.get('ownership_renounced') else '\u274C'
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
    liq = dex_data.get('liquidity_usd', 0)
    vol = dex_data.get('volume_24h', 0)
    change = dex_data.get('price_change_24h', 0)
    fdv = dex_data.get('fdv', 0)
    pair_age = dex_data.get('pair_age_hours')
    lines.append(f'  Liquidity: ${liq:,.0f}')
    lines.append(f'  24h Volume: ${vol:,.0f}')
    lines.append(f'  24h Price Change: {change:+.1f}%')
    lines.append(f'  FDV: ${fdv:,.0f}')
    if pair_age is not None:
        lines.append(f'  Pair Age: {pair_age:.1f}h')

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
    if honeypot_data:
        lines.append('*\U0001F9EA Trade Simulation:*')
        hp = '\u274C Honeypot' if honeypot_data.get('is_honeypot') else '\u2705 Not Honeypot'
        lines.append(f'  {hp}')
        bt = honeypot_data.get('buy_tax', 0)
        st = honeypot_data.get('sell_tax', 0)
        lines.append(f'  Buy Tax: {bt}%  |  Sell Tax: {st}%')
        can_buy = '\u2705' if honeypot_data.get('can_buy') else '\u274C'
        can_sell = '\u2705' if honeypot_data.get('can_sell') else '\u274C'
        lines.append(f'  Can Buy: {can_buy}  |  Can Sell: {can_sell}')
        reason = honeypot_data.get('honeypot_reason')
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
    elif rug_prob >= 31:
        lines.append(f'{verdict_icon} PROCEED WITH CAUTION — Moderate risk ({rug_prob}%)')
    else:
        lines.append(f'{verdict_icon} Generally Safe — Low risk ({rug_prob}%)')

    return '\n'.join(lines)
