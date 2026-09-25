"""Formats composite risk data into a full Telegram intelligence report."""

import re
import sys
import unicodedata

from core.extension_formatter import is_scan_incomplete
from core.risk_engine import database_matches, medium_matches
from core.verdicts import BLOCK_RECOMMENDED, CAUTION, HIGH, HIGH_RISK, MEDIUM, SAFE, UNKNOWN, classify

# Replies are sent with Telegram's legacy Markdown, where these characters start an entity.
_MARKUP = re.compile(r'([_*`\[])')
# Token names are the token's own text, and flags and reasons can carry its revert strings, so
# control characters, line separators, and the invisible, filler and bidirectional characters that can
# hide or reorder text are blanked before they reach a message.
CONTROL_CHARACTERS = re.compile(
    r'[\x00-\x1f\x7f-\x9f\xad\u061c\u115f\u1160\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069'
    r'\u3164\ufeff\uffa0]'
)


def _combining_marks() -> str:
    """The body of a regex character class matching every combining mark (Unicode category M)."""
    ranges = []
    for code in range(sys.maxunicode + 1):
        if unicodedata.category(chr(code)).startswith('M'):
            if ranges and ranges[-1][1] == code - 1:
                ranges[-1][1] = code
            else:
                ranges.append([code, code])
    return ''.join(f'{re.escape(chr(low))}-{re.escape(chr(high))}' for low, high in ranges)


# Telegram turns a bare domain, a URI with a scheme, an @mention and a /command into a link in any
# message, plain text or escaped Markdown alike, so untrusted text shows the character that starts one
# as a look-alike: a dot (or an ideographic or fullwidth dot, which Telegram also reads as one) between
# a word character and a letter, where a domain's next label starts, as ONE DOT LEADER; the colon of
# any scheme:// (tg, ton, http, even with a dotless host) as RATIO; and an @ or / starting a word as
# FULLWIDTH COMMERCIAL AT or DIVISION SLASH. A dot before a digit and a colon not followed by // are
# left alone, so numbers, versions and times (12.5%, $0.0023, v1.2, 12:30) read and copy as written.
# Text is composed (NFC) first, and a combining mark before a dot counts as the end of a label as the
# letter under it does, so an accent written as a separate mark (l + U+0301) cannot keep a domain whole.
_LINK_STARTS = re.compile(
    rf'(?<=[\w{_combining_marks()}])[.\u3002\uff0e\uff61](?=[^\W\d_])'
    r'|(?<=[\w+.\-]):(?=//)|(?<!\w)@(?=\w)|(?<![\w/<>])/(?=\w)'
)
_LINK_LOOKALIKES = {'@': '\N{FULLWIDTH COMMERCIAL AT}', '/': '\N{DIVISION SLASH}', ':': '\N{RATIO}'}
# How a collision's symbol or name pointed at the official token.
_POINTED_BY = {'ticker': 'same ticker', 'affix': 'ticker with an affix', 'company': 'same company name'}
_ADDRESS = re.compile(r'0x[0-9a-fA-F]{40}')


def unlinked(value) -> str:
    """An untrusted value as one line of text Telegram cannot turn into a link, a mention or a command,
    with the characters that could hide or reorder it blanked."""
    text = unicodedata.normalize('NFC', CONTROL_CHARACTERS.sub(' ', str(value)))
    return _LINK_STARTS.sub(lambda match: _LINK_LOOKALIKES.get(match.group(), '\N{ONE DOT LEADER}'), text)


def escape_markdown(value) -> str:
    """Show a value literally in a legacy Markdown message, with no markup or line breaks.

    Legacy Markdown has no escape for a backslash, and one ending a value would escape the markup
    after it, so a backslash is shown as the look-alike SET MINUS. Links stay tappable, as the
    operator's own alerts need; text from a token, a provider, a user or the model goes through
    escape_untrusted instead.
    """
    text = CONTROL_CHARACTERS.sub(' ', str(value)).replace('\\', '\N{SET MINUS}')
    return _MARKUP.sub(r'\\\1', text)


def escape_untrusted(value) -> str:
    """escape_markdown for text from a token, a provider, a user or the model, which is also unlinked."""
    return escape_markdown(unlinked(value))


def escape_markdown_lines(text: str) -> str:
    """Escape multi-line AI text line by line, keeping its line breaks.

    The model is asked for ** bold, which legacy Markdown renders as nothing, and ` code spans, so
    both are dropped rather than shown as markup characters.
    """
    return '\n'.join(
        escape_untrusted(line) for line in text.replace('**', '').replace('`', '').split('\n')
    )


def describe_impostor_check(check: dict) -> str:
    """A check against the official Robinhood Chain tokens (services.robinhood_assets), in plain words.

    A check queued for an alert under older rules lacks the newer fields, so those are read with get.
    """
    status, symbol, contract = check['status'], check['symbol'], check['official_address']
    pointed_by = _POINTED_BY.get(check.get('pointer'), 'same ticker or name')
    if status == 'unknown':
        return f"Unknown ({check['reason']})"
    if status == 'none':
        return 'No match among official Robinhood Chain tokens'
    if check.get('canonical'):
        if status == 'official':
            return f'The canonical {symbol} of Robinhood Chain'
        if status == 'impostor':
            text = f'Impersonates the canonical {symbol} of Robinhood Chain; canonical contract {contract}'
        else:
            text = (
                f"Not the canonical {symbol} of Robinhood Chain ({pointed_by}); "
                f'canonical contract {contract}'
            )
    elif status == 'official':
        return f'Official {symbol} token (Robinhood)'
    elif status == 'impostor':
        text = f'Impersonates official {symbol} token (Robinhood-issued); official contract {contract}'
    elif check.get('third_party'):
        text = (
            f"{symbol} token in another issuer's convention ({check['third_party']}), not Robinhood's {symbol}; "
            f'official contract {contract}'
        )
    else:
        text = f"Not the official {symbol} token ({pointed_by}); official contract {contract}"
    also = check.get('also')
    if also:
        text += f"; also resembles official {also['symbol']} token, contract {also['official_address']}"
    return text


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
    risk_level = risk_output.get('risk_level', UNKNOWN)
    archetype = risk_output.get('risk_archetype', 'unknown')
    confidence = risk_output.get('confidence_level', 0)
    flags = risk_output.get('critical_flags', [])
    notes = risk_output.get('notes', [])
    scores = risk_output.get('category_scores', {})
    incomplete = is_scan_incomplete(risk_output) or bool(
        honeypot_data and honeypot_data.get('simulation_failed')
    )
    # An incomplete scan's level is not known either: the engine raises missing data to a MEDIUM floor,
    # and its band still sets the icon and the final verdict.
    if incomplete:
        risk_level = UNKNOWN
    coverage_reasons = risk_output.get('coverage_reasons', {})
    impostor_check = risk_output.get('impostor_check')
    impostor = impostor_check is not None and impostor_check['status'] == 'impostor'

    # Verdict emoji
    band = classify(rug_prob)
    if impostor or band == BLOCK_RECOMMENDED:
        verdict_icon = '\U0001F6A8'  # 🚨
    elif band == HIGH_RISK:
        verdict_icon = '\U0001F534'  # 🔴
    elif band == CAUTION or incomplete or risk_level in (MEDIUM, HIGH):
        verdict_icon = '\U0001F7E1'  # 🟡
    else:
        verdict_icon = '\U0001F7E2'  # 🟢

    lines = []

    # Header
    lines.append(f'{verdict_icon} *ShieldBot Intelligence Report*')
    lines.append('')

    # Target (with token name and symbol if available)
    if token_info and token_info.get('name') and token_info.get('symbol'):
        lines.append(f'*Token:* {escape_untrusted(token_info["name"])} ({escape_untrusted(token_info["symbol"])})')
        lines.append(f'*Address:* `{address}`')
    else:
        lines.append(f'*Target:* `{address}`')
    # A wallet has no token to check. The check reads the token's symbol and name itself, so it is stated
    # whether or not the report has them.
    if impostor_check and contract_data.get('is_contract') is not False:
        detail = escape_untrusted(describe_impostor_check(impostor_check))
        # A contract goes in a code span, which a tap copies; a valid address holds nothing to escape.
        for contract in {impostor_check['official_address'], (impostor_check.get('also') or {}).get('official_address')}:
            if contract and _ADDRESS.fullmatch(contract):
                detail = detail.replace(contract, f'`{contract}`')
        warning = '\U000026A0 ' if impostor else ''
        lines.append(f'*Official Token Check:* {warning}{detail}')
    lines.append(f'*Risk Archetype:* {archetype.replace("_", " ").title()}')
    probability = 'Unknown (incomplete coverage)' if incomplete else f'{rug_prob}%'
    lines.append(f'*Rug Probability:* {probability}  |  *Risk Level:* {risk_level}')
    lines.append(f'*Confidence:* {confidence}%')
    lines.append('')

    # Critical flags
    if flags:
        lines.append('*\U000026A0 Critical Flags:*')
        for flag in flags:
            lines.append(f'  \u2022 {escape_untrusted(flag)}')
        lines.append('')

    # Notes name a check that could not run and only adds risk: information, not a danger signal.
    if notes:
        lines.append('*\u2139 Notes:*')
        for note in notes:
            lines.append(f'  \u2022 {escape_untrusted(note)}')
        lines.append('')

    # Category scores
    lines.append('*Category Breakdown:*')
    for category in ('structural', 'market', 'behavioral', 'honeypot'):
        score = scores.get(category)
        value = f'{score}/100' if score is not None else 'Unknown'
        reason = coverage_reasons.get(category)
        if reason:
            value += f' ({escape_untrusted(reason)})'
        lines.append(f'  {category.title()}: {value}')
    lines.append('')

    # Contract analysis
    lines.append('*\U0001F4DC Contract Analysis:*')
    verified_value = contract_data.get('is_verified')
    if contract_data.get('is_contract') is False:
        verified = 'Not applicable (wallet or destroyed contract)'
    else:
        verified = 'Unknown' if verified_value is None else ('\u2705' if verified_value else '\u274C')
    lines.append(f'  Verified: {verified}')
    age = contract_data.get('contract_age_days')
    lines.append(f'  Age: {age} days' if age is not None else '  Age: Unknown')
    ownership = contract_data.get('ownership_renounced')
    renounced = 'Unknown' if ownership is None else ('\u2705' if ownership else '\u274C')
    lines.append(f'  Ownership Renounced: {renounced}')

    bytecode_warnings = contract_data.get('bytecode_warnings', [])
    if bytecode_warnings:
        lines.append(f'  Bytecode Warnings: {escape_untrusted(", ".join(bytecode_warnings))}')
    source_patterns = contract_data.get('source_code_patterns', [])
    if source_patterns:
        lines.append(f'  Source Patterns: {escape_untrusted(", ".join(source_patterns))}')
    scam_matches = database_matches(contract_data.get('scam_matches'))
    if scam_matches:
        lines.append(f'  Scam DB Hits: {len(scam_matches)}')
    elif contract_data.get('coverage', {}).get('scam_database') is False:
        lines.append('  Scam DB Hits: Unknown')
    # A community report is not a scam database hit; it is named on its own.
    for match in medium_matches(contract_data.get('scam_matches')):
        lines.append(f'  {escape_untrusted(match["reason"])}')
    lines.append('')

    # Market intelligence
    lines.append('*\U0001F4CA Market Intelligence:*')
    market_reason = escape_untrusted(dex_data.get('reason') or 'Provider data unavailable')
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
    # A failed lookup, or an address Ethos has no score for, has no reputation to show, not a neutral one.
    if ethos_data.get('status') == 'unknown' or ethos_data.get('ethos_raw_score') is None:
        reason = ethos_data.get('reason')
        lines.append('  Score: Unknown  |  Trust: Unknown' + (f' ({escape_untrusted(reason)})' if reason else ''))
    else:
        trust = escape_untrusted(ethos_data['trust_level'])
        lines.append(f"  Score: {ethos_data['reputation_score']}  |  Trust: {trust}")
    ethos_flags = ethos_data.get('scam_flags', [])
    if ethos_flags:
        lines.append(f'  Scam Flags: {escape_untrusted(", ".join(str(f) for f in ethos_flags))}')
    linked = ethos_data.get('linked_wallets', [])
    if linked:
        lines.append(f'  Linked Wallets: {len(linked)}')
    lines.append('')

    # Trade simulation
    if honeypot_data is not None:
        lines.append('*\U0001F9EA Trade Simulation:*')
        reason = escape_untrusted(
            honeypot_data.get('reason') or honeypot_data.get('honeypot_reason') or 'Provider data unavailable'
        )
        is_honeypot = honeypot_data.get('is_honeypot')
        if is_honeypot is None or (honeypot_data.get('simulation_failed') and is_honeypot is False):
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
            if key == 'can_sell' and honeypot_data.get('simulation_failed'):
                value = None
            rendered = f'Unknown ({reason})' if value is None else ('Yes' if value else 'No')
            lines.append(f'  {label}: {rendered}')
        if reason and reason not in ('Unknown', 'None', ''):
            lines.append(f'  Reason: {reason}')
        lines.append('')

    # AI Analysis
    if ai_analysis and not incomplete:
        lines.append('*\U0001F9E0 AI Analysis:*')
        lines.append(escape_markdown_lines(ai_analysis))
        lines.append('')

    # Final verdict
    lines.append('*Final Verdict:*')
    if impostor:
        claimed = 'the canonical' if impostor_check['canonical'] else 'official'
        caveat = '; unknown risk: provider coverage incomplete' if incomplete else ''
        lines.append(
            f'{verdict_icon} Impersonates {claimed} {escape_untrusted(impostor_check["symbol"])}: '
            f'do not treat as the real token{caveat}'
        )
    elif band == BLOCK_RECOMMENDED:
        detail = 'Unknown risk: provider coverage incomplete' if incomplete else f'Rug probability {rug_prob}%'
        lines.append(f'{verdict_icon} DO NOT PROCEED — {detail}')
    elif band != SAFE or incomplete or risk_level in (MEDIUM, HIGH):
        detail = 'Unknown risk: provider coverage incomplete' if incomplete else f'Moderate risk ({rug_prob}%)'
        lines.append(f'{verdict_icon} PROCEED WITH CAUTION — {detail}')
    else:
        lines.append(f'{verdict_icon} Generally Safe — Low risk ({rug_prob}%)')

    return '\n'.join(lines)
