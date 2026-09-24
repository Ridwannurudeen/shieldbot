"""Tests for utils/risk_scorer.py — scoring logic, confidence."""

import pytest
from utils.risk_scorer import (
    calculate_risk_score,
    compute_confidence,
    score_level_from_int,
)


# --- calculate_risk_score ---

class TestCalculateRiskScore:
    def test_empty_findings_returns_zero(self):
        score, level, _ = calculate_risk_score([])
        assert score == 0
        assert level == "LOW"

    def test_single_critical_finding(self):
        findings = [{"severity": "critical", "message": "Scam DB match"}]
        score, level, _ = calculate_risk_score(findings)
        assert score == 40
        assert level == "MEDIUM"

    def test_multiple_criticals_cap_at_100(self):
        findings = [{"severity": "critical", "message": f"issue {i}"} for i in range(5)]
        score, _, _ = calculate_risk_score(findings)
        assert score == 100

    def test_high_severity(self):
        findings = [{"severity": "high", "message": "Unverified"}]
        score, _, _ = calculate_risk_score(findings)
        assert score == 25

    def test_medium_severity(self):
        findings = [{"severity": "medium", "message": "Ownership not renounced"}]
        score, _, _ = calculate_risk_score(findings)
        assert score == 15

    def test_info_severity_is_zero_weight(self):
        findings = [{"severity": "info", "message": "Standard transfer"}]
        score, _, _ = calculate_risk_score(findings)
        assert score == 0

    def test_mixed_severities(self):
        findings = [
            {"severity": "critical", "message": "Honeypot"},
            {"severity": "high", "message": "Unverified"},
            {"severity": "medium", "message": "New contract"},
            {"severity": "info", "message": "Transfer function"},
        ]
        score, _, _ = calculate_risk_score(findings)
        # 40 + 25 + 15 + 0 = 80
        assert score == 80
        assert score >= 71  # HIGH threshold

    def test_high_threshold_boundary(self):
        # 71 should be HIGH
        findings = [
            {"severity": "critical", "message": "a"},
            {"severity": "high", "message": "b"},
            {"severity": "low", "message": "c"},
            {"severity": "low", "message": "d"},
        ]
        score, level, _ = calculate_risk_score(findings)
        # 40 + 25 + 5 + 5 = 75
        assert level == "HIGH"

    def test_medium_threshold_boundary(self):
        # 31 should be MEDIUM
        findings = [
            {"severity": "high", "message": "a"},
            {"severity": "low", "message": "b"},
            {"severity": "low", "message": "c"},
        ]
        score, level, _ = calculate_risk_score(findings)
        # 25 + 5 + 5 = 35
        assert level == "MEDIUM"


# --- compute_confidence ---

class TestComputeConfidence:
    def test_empty_sources(self):
        assert compute_confidence({}) == 0

    def test_all_sources_responded(self):
        sources = {
            "bscscan": True,
            "bytecode": True,
            "scam_db": True,
            "honeypot_api": True,
            "contract_age": True,
            "source_code": True,
        }
        assert compute_confidence(sources) == 100

    def test_no_sources_responded(self):
        sources = {
            "bscscan": False,
            "bytecode": False,
            "scam_db": False,
        }
        assert compute_confidence(sources) == 0

    def test_partial_sources(self):
        sources = {
            "bscscan": True,
            "bytecode": True,
            "scam_db": False,
        }
        # bscscan(20) + bytecode(15) responded, scam_db(15) didn't
        # achieved=35, total=50
        assert compute_confidence(sources) == 70


# --- score_level_from_int ---

class TestScoreLevelFromInt:
    def test_low_at_30(self):
        assert score_level_from_int(30) == "LOW"

    def test_medium_at_31(self):
        assert score_level_from_int(31) == "MEDIUM"

    def test_medium_at_70(self):
        assert score_level_from_int(70) == "MEDIUM"

    def test_high_at_71(self):
        assert score_level_from_int(71) == "HIGH"

    def test_high_at_100(self):
        assert score_level_from_int(100) == "HIGH"

    def test_low_at_0(self):
        assert score_level_from_int(0) == "LOW"
