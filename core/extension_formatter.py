"""Formats composite risk data into a compact JSON dict for the Chrome extension."""


def format_extension_alert(risk_output: dict) -> dict:
    rug_prob = risk_output.get('rug_probability', 0)
    risk_level = risk_output.get('risk_level', 'UNKNOWN')
    archetype = risk_output.get('risk_archetype', 'unknown')
    confidence = risk_output.get('confidence_level', 0)
    flags = risk_output.get('critical_flags', [])

    # Classification mapping
    if rug_prob >= 71:
        classification = 'BLOCK_RECOMMENDED'
        action = 'Do not proceed with this transaction.'
    elif rug_prob >= 50:
        classification = 'HIGH_RISK'
        action = 'High risk detected. Avoid unless you fully understand the risks.'
    elif rug_prob >= 31:
        classification = 'CAUTION'
        action = 'Proceed with caution. Review the flagged concerns.'
    else:
        classification = 'SAFE'
        action = 'No major risks detected. Standard precautions apply.'

    return {
        'risk_classification': classification,
        'rug_probability': rug_prob,
        'top_flags': flags[:3],
        'recommended_action': action,
        'risk_archetype': archetype.replace('_', ' ').title(),
        'confidence': confidence,
    }
