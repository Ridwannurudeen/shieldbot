"""Formats composite risk data into a compact JSON dict for the Chrome extension."""

from core.verdicts import BLOCK_RECOMMENDED, CAUTION, HIGH, HIGH_RISK, MEDIUM, SAFE, UNKNOWN, classify


def is_scan_incomplete(risk_output: dict) -> bool:
    coverage = risk_output.get('coverage')
    return (
        risk_output.get('status') != 'ok'
        or risk_output.get('partial') is True
        or str(risk_output.get('risk_level', '')).upper() == UNKNOWN
        or bool(risk_output.get('simulation_failed'))
        or not coverage
        or any(value is None or value < 1 for value in coverage.values())
    )


def format_extension_alert(risk_output: dict) -> dict:
    rug_prob = risk_output.get('rug_probability', 0)
    risk_level = risk_output.get('risk_level', UNKNOWN)
    archetype = risk_output.get('risk_archetype', 'unknown')
    confidence = risk_output.get('confidence_level', 0)
    flags = risk_output.get('critical_flags', [])
    incomplete = is_scan_incomplete(risk_output)
    reasons = risk_output.get('coverage_reasons', {})

    # Classification mapping
    band = classify(rug_prob)
    classification = band
    if band == BLOCK_RECOMMENDED:
        action = 'Do not proceed with this transaction.'
    elif band == HIGH_RISK:
        action = 'High risk detected. Avoid unless you fully understand the risks.'
    elif band == CAUTION:
        action = 'Proceed with caution. Review the flagged concerns.'
    elif incomplete or risk_level in (MEDIUM, HIGH):
        classification = CAUTION
        reason = '; '.join(dict.fromkeys(reasons.values())) or 'Provider data unavailable or incomplete'
        action = f'Unknown: {reason}. Review the missing data before proceeding.'
    else:
        action = 'No major risks detected. Standard precautions apply.'

    if incomplete and band != SAFE:
        reason = '; '.join(dict.fromkeys(reasons.values())) or 'Provider data unavailable or incomplete'
        action += f' Unknown: {reason}.'

    return {
        'risk_classification': classification,
        'rug_probability': rug_prob,
        'risk_display': 'Unknown (incomplete provider coverage)' if incomplete else f'{rug_prob}%',
        'top_flags': flags[:3],
        'recommended_action': action,
        'risk_archetype': archetype.replace('_', ' ').title(),
        'confidence': confidence,
        'status': 'unknown' if incomplete else 'ok',
        'coverage': risk_output.get('coverage', {}),
        'coverage_reasons': reasons,
    }
