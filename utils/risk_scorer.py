"""
Risk Scoring Engine
Calculates blended risk scores (heuristic + AI) with confidence levels
"""

import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Severity weights for heuristic scoring
SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
    "info": 0
}

# Blending ratio: 60% heuristic, 40% AI (when AI is available)
HEURISTIC_WEIGHT = 0.60
AI_WEIGHT = 0.40


def calculate_risk_score(findings: List[Dict]) -> Tuple[int, str, str]:
    """
    Calculate heuristic risk score from security findings.

    Args:
        findings: List of dicts with 'severity' and 'message' keys

    Returns:
        tuple: (risk_score 0-100, risk_level str, recommendation str)
    """
    total_risk = 0
    for finding in findings:
        severity = finding.get("severity", "info")
        total_risk += SEVERITY_WEIGHTS.get(severity, 0)

    risk_score = min(total_risk, 100)

    if risk_score >= 71:
        risk_level = "HIGH"
        recommendation = "DO NOT PROCEED - Critical security issues detected."
    elif risk_score >= 31:
        risk_level = "MEDIUM"
        recommendation = "Proceed with extreme caution. Verify all details carefully."
    else:
        risk_level = "LOW"
        recommendation = "Generally safe, but always verify independently."

    return risk_score, risk_level, recommendation


def blend_scores(heuristic_score: int, ai_score: Optional[int]) -> int:
    """
    Blend heuristic and AI risk scores.
    Falls back to 100% heuristic when AI is unavailable.

    Args:
        heuristic_score: 0-100 from heuristic analysis
        ai_score: 0-100 from AI analysis, or None

    Returns:
        Blended score 0-100
    """
    if ai_score is None:
        return heuristic_score

    blended = (HEURISTIC_WEIGHT * heuristic_score) + (AI_WEIGHT * ai_score)
    return max(0, min(100, round(blended)))


def compute_confidence(data_sources: Dict[str, bool]) -> int:
    """
    Compute confidence percentage based on how many data sources responded.

    Args:
        data_sources: dict mapping source name to whether it responded successfully
            e.g. {"bscscan": True, "honeypot_api": True, "scam_db": False, "ai": True}

    Returns:
        Confidence percentage 0-100
    """
    if not data_sources:
        return 0

    # Weight each source by importance
    source_weights = {
        "bscscan": 20,
        "bytecode": 15,
        "scam_db": 15,
        "honeypot_api": 20,
        "contract_age": 10,
        "ai": 15,
        "source_code": 5,
    }

    total_weight = 0
    achieved_weight = 0

    for source, responded in data_sources.items():
        weight = source_weights.get(source, 10)
        total_weight += weight
        if responded:
            achieved_weight += weight

    if total_weight == 0:
        return 0

    return max(0, min(100, round((achieved_weight / total_weight) * 100)))


def score_level_from_int(score: int) -> str:
    """Convert numeric score to risk level string."""
    if score >= 71:
        return "HIGH"
    elif score >= 31:
        return "MEDIUM"
    return "LOW"


def recommendation_from_score(score: int) -> str:
    """Get recommendation text from numeric score."""
    if score >= 71:
        return "DO NOT PROCEED - Critical security issues detected."
    elif score >= 31:
        return "Proceed with extreme caution. Verify all details carefully."
    return "Generally safe, but always verify independently."


def findings_from_scan_result(result: Dict) -> List[Dict]:
    """
    Convert a scan result dict (from TransactionScanner or TokenScanner)
    into a list of severity-tagged findings for scoring.
    """
    findings = []

    # Scam DB matches = critical
    for match in result.get('scam_matches', []):
        findings.append({
            "severity": "critical",
            "message": f"Scam DB match: {match.get('type', 'unknown')} - {match.get('reason', '')}"
        })

    # Honeypot = critical
    if result.get('is_honeypot'):
        findings.append({"severity": "critical", "message": "Honeypot detected"})

    # Unverified = high
    if result.get('is_verified') is False:
        findings.append({"severity": "high", "message": "Contract not verified on BscScan"})

    # Very new contract = high
    age = result.get('contract_age_days')
    if age is not None and age < 7:
        severity = "high" if age < 1 else "medium"
        findings.append({"severity": severity, "message": f"Contract is only {age} days old"})

    # Suspicious patterns from checks
    if result.get('checks', {}).get('no_suspicious_patterns') is False:
        findings.append({"severity": "high", "message": "Suspicious bytecode patterns detected"})

    # Ownership not renounced
    if result.get('checks', {}).get('ownership_renounced') is False:
        findings.append({"severity": "medium", "message": "Ownership not renounced"})

    # Liquidity not locked
    if result.get('checks', {}).get('liquidity_locked') is False:
        findings.append({"severity": "medium", "message": "Liquidity not locked"})

    # High taxes
    buy_tax = result.get('buy_tax', 0) or 0
    sell_tax = result.get('sell_tax', 0) or 0
    if sell_tax > 50:
        findings.append({"severity": "critical", "message": f"Extremely high sell tax: {sell_tax}%"})
    elif sell_tax > 10:
        findings.append({"severity": "medium", "message": f"High sell tax: {sell_tax}%"})
    if buy_tax > 10:
        findings.append({"severity": "medium", "message": f"High buy tax: {buy_tax}%"})

    # Can't sell
    if result.get('checks', {}).get('can_sell') is False:
        findings.append({"severity": "critical", "message": "Cannot sell token"})

    # Source code dangerous patterns (from AI source analysis)
    for pattern in result.get('source_analysis', {}).get('dangerous_patterns', []):
        findings.append({
            "severity": pattern.get("severity", "medium"),
            "message": f"Source: {pattern.get('pattern', 'unknown')} - {pattern.get('detail', '')}"
        })

    return findings


def format_risk_report(analysis: dict) -> str:
    """Format analysis results into human-readable Markdown report."""
    findings = analysis.get("findings", [])
    risk_score, risk_level, recommendation = calculate_risk_score(findings)

    report = f"*Security Analysis Report*\n\n"
    report += f"*Risk Level:* {risk_level}\n"
    report += f"*Risk Score:* {risk_score}/100\n\n"

    if findings:
        report += "*Findings:*\n"
        for finding in findings:
            severity = finding.get("severity", "info").upper()
            message = finding.get("message", "Unknown issue")
            report += f"  [{severity}] {message}\n"
        report += "\n"

    report += f"*Recommendation:*\n{recommendation}\n"

    return report
