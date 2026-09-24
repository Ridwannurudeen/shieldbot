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
from scanner.transaction_scanner import TransactionScanner
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


def test_raw_checks_count_only_database_matches():
    import api

    covered = {"coverage": {"scam_database": True}}
    assert api._scam_match_count({**covered, "scam_matches": [COMMUNITY]}) == 0
    assert api._scam_match_count({**covered, "scam_matches": [COMMUNITY, ADMIN]}) == 1
    assert ai_scam_match_count({**covered, "scam_matches": [COMMUNITY]}) == "0"
