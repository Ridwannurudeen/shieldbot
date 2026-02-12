"""
Risk Scoring Engine
Calculates overall risk scores based on various factors
"""

def calculate_risk_score(findings: list) -> tuple:
    """
    Calculate risk score from security findings
    
    Args:
        findings: List of security findings, each with severity level
    
    Returns:
        tuple: (risk_score, risk_level, recommendation)
    """
    # Risk weights
    SEVERITY_WEIGHTS = {
        "critical": 40,
        "high": 25,
        "medium": 15,
        "low": 5,
        "info": 0
    }
    
    # Calculate total risk
    total_risk = 0
    for finding in findings:
        severity = finding.get("severity", "info")
        total_risk += SEVERITY_WEIGHTS.get(severity, 0)
    
    # Cap at 100
    risk_score = min(total_risk, 100)
    
    # Determine risk level
    if risk_score >= 71:
        risk_level = "🔴 HIGH RISK"
        recommendation = "❌ DO NOT PROCEED! This transaction/token shows critical security issues."
    elif risk_score >= 31:
        risk_level = "🟡 MEDIUM RISK"
        recommendation = "⚠️ Proceed with extreme caution. Verify all details carefully."
    else:
        risk_level = "🟢 LOW RISK"
        recommendation = "✅ Generally safe, but always verify independently."
    
    return risk_score, risk_level, recommendation

def format_risk_report(analysis: dict) -> str:
    """
    Format analysis results into human-readable report
    
    Args:
        analysis: Analysis results dictionary
    
    Returns:
        str: Formatted report text (Markdown)
    """
    findings = analysis.get("findings", [])
    risk_score, risk_level, recommendation = calculate_risk_score(findings)
    
    report = f"🛡️ *Security Analysis Report*\n\n"
    report += f"*Risk Level:* {risk_level}\n"
    report += f"*Risk Score:* {risk_score}/100\n\n"
    
    if findings:
        report += "*Findings:*\n"
        for finding in findings:
            severity = finding.get("severity", "info").upper()
            message = finding.get("message", "Unknown issue")
            report += f"• [{severity}] {message}\n"
        report += "\n"
    
    report += f"*Recommendation:*\n{recommendation}\n"
    
    return report
