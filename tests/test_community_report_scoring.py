"""A community blacklist entry is a crowd signal anyone can manufacture: it raises a score to the
CAUTION band and says "Reported by N users", but never counts as a scam database match and never
reaches BLOCK on its own. An entry an admin confirmed is a full, block-severity scam match."""

from unittest.mock import AsyncMock

import pytest

from analyzers.structural import StructuralAnalyzer
from core.analyzer import AnalyzerResult
from core.calibration import CalibrationConfig
from core.extension_formatter import format_extension_alert
from core.risk_engine import RiskEngine
from core.telegram_formatter import format_full_report
from scanner.transaction_scanner import TransactionScanner
from utils.ai_analyzer import AIAnalyzer
from utils.ai_analyzer import _scam_match_count as ai_scam_match_count
from utils.scam_db import ScamMatches


ADDRESS = "0x1111111111111111111111111111111111111111"
COMMUNITY = {
    "type": "community_reports",
    "reason": "Reported by 3 users",
    "source": "ShieldBot",
    "severity": "medium",
    "reports": 3,
}
ADMIN = {
    "type": "Local Blacklist",
    "reason": "Confirmed scam address",
    "source": "ShieldBot",
    "severity": "block",
}
GOPLUS_HIGH = {
    "type": "GoPlus Security",
    "reason": "Honeypot (GoPlus)",
    "source": "gopluslabs.io",
    "severity": "high",
}
CONTRACT = {
    "is_contract": True,
    "is_verified": True,
    "contract_age_days": 400,
    "ownership_renounced": None,
}
HONEYPOT = {"is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0}
MARKET = {"liquidity_usd": 50000, "pair_age_hours": 100}
ETHOS = {"reputation_score": 80}
SKIPPED = {"skipped": True, "reason": "non-token contract"}


def _risk(
    entrypoint, is_token, scam_matches, contract=CONTRACT, scores=(0, 0, 0), calibration=None
):
    contract = {**contract, "scam_matches": scam_matches}
    engine = RiskEngine(calibration=calibration)
    if entrypoint == "direct":
        return engine.compute_composite_risk(contract, HONEYPOT, MARKET, ETHOS, is_token=is_token)
    structural, flags = StructuralAnalyzer(None)._compute(contract, {})
    market, behavioral, honeypot = scores
    return engine.compute_from_results(
        [
            AnalyzerResult("structural", 0.4, structural, flags=flags, data=contract),
            AnalyzerResult("market", 0.25, market, data=MARKET if is_token else SKIPPED),
            AnalyzerResult("behavioral", 0.2, behavioral, data=ETHOS),
            AnalyzerResult("honeypot", 0.15, honeypot, data=HONEYPOT if is_token else SKIPPED),
        ],
        is_token=is_token,
    )


TARGETS = [("direct", True), ("direct", False), ("registry", True), ("registry", False)]


@pytest.mark.parametrize("entrypoint, is_token", TARGETS)
def test_community_report_raises_a_clean_target_to_caution(entrypoint, is_token):
    risk = _risk(entrypoint, is_token, [COMMUNITY])
    alert = format_extension_alert(risk)
    assert risk["status"] == "ok"
    assert risk["rug_probability"] == 40
    assert risk["risk_level"] == "MEDIUM"
    assert alert["risk_classification"] == "CAUTION"
    assert alert["top_flags"][0] == "Reported by 3 users"
    assert not any(flag.startswith("Scam DB match") for flag in risk["critical_flags"])


@pytest.mark.parametrize("entrypoint, is_token", TARGETS)
def test_community_report_cannot_block_alone(entrypoint, is_token):
    many = {**COMMUNITY, "reason": "Reported by 500 users", "reports": 500}
    for calibration in (None, CalibrationConfig(high_threshold=90.0, medium_threshold=80.0)):
        risk = _risk(entrypoint, is_token, [many], calibration=calibration)
        assert risk["rug_probability"] < 50
        assert risk["risk_level"] == "MEDIUM"
        assert format_extension_alert(risk)["risk_classification"] == "CAUTION"


def test_community_report_adds_nothing_above_its_floor():
    risky = {**CONTRACT, "is_verified": False, "contract_age_days": 3}
    without = _risk("registry", True, [], contract=risky, scores=(100, 0, 100))
    with_reports = _risk("registry", True, [COMMUNITY], contract=risky, scores=(100, 0, 100))
    assert without["rug_probability"] == with_reports["rug_probability"] == 58
    assert "Reported by 3 users" in with_reports["critical_flags"]


@pytest.mark.parametrize("entrypoint, is_token", TARGETS)
def test_the_score_before_the_community_floor_is_exposed(entrypoint, is_token):
    reported = _risk(entrypoint, is_token, [COMMUNITY])
    assert (reported["rug_probability"], reported["score_before_community_floor"]) == (40, 0)
    risky = {**CONTRACT, "is_verified": False, "contract_age_days": 3}
    unreported = _risk(entrypoint, is_token, [], contract=risky)
    assert unreported["score_before_community_floor"] == unreported["rug_probability"]
    # A block-severity match is not a crowd signal: its floor is in the score before the community floor.
    confirmed = _risk(entrypoint, is_token, [ADMIN, COMMUNITY])
    assert confirmed["score_before_community_floor"] == confirmed["rug_probability"] >= 90


@pytest.mark.parametrize("entrypoint, is_token", TARGETS)
def test_admin_confirmed_entry_blocks_alone(entrypoint, is_token):
    risk = _risk(entrypoint, is_token, [ADMIN])
    assert risk["rug_probability"] >= 90
    assert risk["risk_level"] == "HIGH"
    assert format_extension_alert(risk)["risk_classification"] == "BLOCK_RECOMMENDED"


@pytest.mark.parametrize(
    "entrypoint, is_token", [("direct", True), ("registry", True), ("registry", False)]
)
def test_a_database_match_beside_a_community_report_keeps_its_own_floor(entrypoint, is_token):
    risk = _risk(entrypoint, is_token, [GOPLUS_HIGH, COMMUNITY])
    assert risk["rug_probability"] == 70
    assert "Reported by 3 users" in risk["critical_flags"]
    assert any(flag == "Scam DB match (1 sources)" for flag in risk["critical_flags"])


async def _scan(mock_web3_client, matches):
    scanner = TransactionScanner(mock_web3_client)
    scanner.scam_db.check_address = AsyncMock(return_value=ScamMatches(matches))
    return await scanner.scan_address(ADDRESS)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_contract", [False, True])
async def test_scan_names_a_community_report_and_holds_caution(mock_web3_client, is_contract):
    mock_web3_client.is_contract.return_value = is_contract
    result = await _scan(mock_web3_client, [COMMUNITY])
    assert "Reported by 3 users" in result["warnings"]
    assert not any("scam database" in warning for warning in result["warnings"])
    assert result["checks"]["scam_database_clean"] is True
    assert result["risk_score"] == 40
    assert result["risk_level"] == "medium"
    assert (
        format_extension_alert({**result, "rug_probability": result["risk_score"]})[
            "risk_classification"
        ]
        == "CAUTION"
    )


@pytest.mark.asyncio
async def test_scan_admin_entry_is_a_scam_database_match(mock_web3_client):
    result = await _scan(mock_web3_client, [ADMIN])
    assert "Found 1 scam database match(es)" in result["warnings"]
    assert result["checks"]["scam_database_clean"] is False


GOPLUS_BLOCK = {
    "type": "GoPlus Security",
    "reason": "Airdrop scam token",
    "source": "gopluslabs.io",
    "severity": "block",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("is_contract", [None, False, True])
@pytest.mark.parametrize(
    "matches, score, level, classification",
    [
        ([ADMIN], 90, "high", "BLOCK_RECOMMENDED"),
        ([GOPLUS_BLOCK], 90, "high", "BLOCK_RECOMMENDED"),
        ([COMMUNITY, GOPLUS_BLOCK], 90, "high", "BLOCK_RECOMMENDED"),
        ([GOPLUS_HIGH], 70, "medium", "HIGH_RISK"),
        ([COMMUNITY], 40, "medium", "CAUTION"),
    ],
)
async def test_legacy_scan_applies_the_firewall_severity_floors(
    mock_web3_client, is_contract, matches, score, level, classification
):
    mock_web3_client.is_contract.return_value = is_contract
    result = await _scan(mock_web3_client, matches)
    assert result["risk_score"] == score
    assert result["risk_level"] == level
    # /api/scan classifies the legacy score with the extension's bands.
    alert = format_extension_alert({**result, "rug_probability": result["risk_score"]})
    assert alert["risk_classification"] == classification


def _contract_section(report):
    return report.split("Contract Analysis")[1].split("Market Intelligence")[0]


@pytest.mark.parametrize(
    "matches, hits",
    [([COMMUNITY], None), ([ADMIN, COMMUNITY], "Scam DB Hits: 1")],
)
def test_full_report_counts_database_hits_apart_from_community_reports(matches, hits):
    contract = {**CONTRACT, "scam_matches": matches, "coverage": {"scam_database": True}}
    risk = RiskEngine().compute_composite_risk(contract, HONEYPOT, MARKET, ETHOS)
    section = _contract_section(format_full_report(risk, contract, MARKET, ETHOS, HONEYPOT))
    assert "Reported by 3 users" in section
    if hits:
        assert hits in section
    else:
        assert "Scam DB Hits" not in section


def test_fallback_firewall_response_names_a_community_report_without_blocking():
    import api

    scan = {
        "address": ADDRESS,
        "is_verified": True,
        "is_contract": True,
        "risk_level": "medium",
        "risk_score": 40,
        "checks": {},
        "warnings": ["Reported by 3 users"],
        "scam_matches": [COMMUNITY],
        "status": "ok",
        "coverage": {"scam_database": True},
        "is_honeypot": False,
    }
    data = api._build_fallback_response({}, scan, None, 56)
    assert data["classification"] == "CAUTION"
    assert "Reported by 3 users" in data["danger_signals"]
    assert not any("scam database" in signal for signal in data["danger_signals"])
    assert data["raw_checks"]["scam_matches"] == 0


COMMUNITY_LINE = "Community reports, unconfirmed, not a scam database match: Reported by 3 users"


def test_the_firewall_prompt_labels_a_community_report_and_keeps_it_out_of_warnings():
    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    scan = {
        "is_verified": True,
        "risk_level": "medium",
        "warnings": ["Reported by 3 users"],
        "scam_matches": [COMMUNITY],
        "coverage": {"scam_database": True},
    }
    context = analyzer._build_firewall_context({}, scan)
    assert COMMUNITY_LINE in context
    assert context.count("Reported by 3 users") == 1
    assert "Warnings:" not in context

    # Other warnings stay under Warnings; the community report still does not.
    context = analyzer._build_firewall_context(
        {}, {**scan, "warnings": ["Contract source code is not verified", "Reported by 3 users"]}
    )
    assert COMMUNITY_LINE in context
    assert context.count("Reported by 3 users") == 1
    assert "Contract source code is not verified" in context.split("Warnings:")[1]


def test_the_forensic_prompt_labels_a_community_report_and_keeps_it_out_of_the_flags():
    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    contract = {"is_verified": False, "scam_matches": [COMMUNITY], "coverage": {"scam_database": True}}
    risk = {"rug_probability": 40, "critical_flags": ["Reported by 3 users"]}
    context = analyzer._build_forensic_context(ADDRESS, {"contract": contract, "risk": risk}, "contract")
    assert COMMUNITY_LINE in context
    assert context.count("Reported by 3 users") == 1
    assert "Critical Flags:" not in context
    assert "Scam Database Matches: 0" in context

    risk = {**risk, "critical_flags": ["Reported by 3 users", "Contract not verified"]}
    context = analyzer._build_forensic_context(ADDRESS, {"contract": contract, "risk": risk}, "contract")
    assert context.count("Reported by 3 users") == 1
    assert "Contract not verified" in context.split("Critical Flags:")[1]


def test_raw_checks_count_only_database_matches():
    import api

    covered = {"coverage": {"scam_database": True}}
    assert api._scam_match_count({**covered, "scam_matches": [COMMUNITY]}) == 0
    assert api._scam_match_count({**covered, "scam_matches": [COMMUNITY, ADMIN]}) == 1
    assert ai_scam_match_count({**covered, "scam_matches": [COMMUNITY]}) == "0"
