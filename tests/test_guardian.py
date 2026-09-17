"""Tests for Portfolio Guardian service."""

import logging
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, create_autospec

from services.guardian import GuardianService


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.register_guardian_wallet = AsyncMock(return_value={
        "wallet_address": "0xabc", "chain_id": 56, "owner_id": "k1", "created_at": time.time(),
    })
    db.get_guardian_wallets = AsyncMock(return_value=[])
    db.get_guardian_wallet = AsyncMock(return_value=None)
    db.update_guardian_health = AsyncMock()
    db.create_guardian_alert = AsyncMock(return_value=1)
    db.get_guardian_alerts = AsyncMock(return_value=[])
    db.acknowledge_guardian_alert = AsyncMock(return_value=True)
    db.get_deployer_risk_summary = AsyncMock(return_value=None)
    db.is_watched_deployer = AsyncMock(return_value=None)
    return db


@pytest.fixture
def mock_rescue():
    """Mock rescue_service with a default empty scan result."""
    rescue = MagicMock()
    rescue.scan_approvals = AsyncMock(return_value={
        "wallet": "0xabc",
        "chain_id": 56,
        "total_approvals": 0,
        "high_risk": 0,
        "medium_risk": 0,
        "total_value_at_risk_usd": 0,
        "approvals": [],
        "alerts": [],
        "revoke_txs": [],
        "scanned_at": time.time(),
    })
    return rescue


@pytest.fixture
def guardian(mock_db):
    """Guardian without rescue_service — data unavailable path."""
    return GuardianService(db=mock_db)


@pytest.fixture
def guardian_with_rescue(mock_db, mock_rescue):
    """Guardian with rescue_service — full data path."""
    return GuardianService(db=mock_db, rescue_service=mock_rescue)


# --- Basic operations ---


@pytest.mark.asyncio
async def test_register_wallet(guardian, mock_db):
    result = await guardian.register_wallet("0xABC", 56, "k1")
    assert result["wallet_address"] == "0xabc"
    mock_db.register_guardian_wallet.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_wallets(guardian, mock_db):
    mock_db.get_guardian_wallets.return_value = [
        {"wallet_address": "0xabc", "chain_id": 56, "health_score": 85},
    ]
    wallets = await guardian.get_wallets("k1")
    assert len(wallets) == 1
    assert wallets[0]["health_score"] == 85


@pytest.mark.asyncio
async def test_health_no_data_returns_unknown(guardian):
    """No rescue_service = data unavailable, level should be 'unknown'."""
    result = await guardian.get_health("0xabc", 56)
    assert result["health_score"] == 50.0
    assert result["level"] == "unknown"
    assert "warnings" in result
    assert len(result["warnings"]) > 0


@pytest.mark.asyncio
async def test_health_score_weights_sum_to_one(guardian):
    total = sum(GuardianService.WEIGHTS.values())
    assert abs(total - 1.0) < 0.001


@pytest.mark.asyncio
async def test_health_level_classification(guardian):
    result = await guardian.get_health("0xabc", 56)
    assert result["level"] in ("excellent", "good", "fair", "poor", "critical", "unknown")


# --- Revoke TX builder ---


@pytest.mark.asyncio
async def test_build_revoke_tx_correct_calldata(guardian):
    approvals = [
        {"token_address": "0xToken1", "spender": "0xSpender1"},
        {"token_address": "0xToken2", "spender": "0xSpender2"},
    ]
    txs = await guardian.build_revoke_tx("0xWallet", approvals)
    assert len(txs) == 2
    for tx in txs:
        assert tx["data"].startswith("0x095ea7b3")  # approve selector
        assert tx["value"] == "0"
        assert "0" * 64 in tx["data"]  # amount = 0


@pytest.mark.asyncio
async def test_build_revoke_tx_empty_list(guardian):
    txs = await guardian.build_revoke_tx("0xWallet", [])
    assert txs == []


@pytest.mark.asyncio
async def test_build_revoke_tx_skips_incomplete(guardian):
    approvals = [
        {"token_address": "0xToken1"},  # missing spender
        {"spender": "0xSpender1"},  # missing token
    ]
    txs = await guardian.build_revoke_tx("0xWallet", approvals)
    assert len(txs) == 0


# --- Alerts ---


@pytest.mark.asyncio
async def test_create_alert(guardian, mock_db):
    alert_id = await guardian.create_alert(
        "0xabc", 56, "rug_signal", "critical", "Liquidity pulled",
        details={"pool": "0x123"},
    )
    assert alert_id == 1
    mock_db.create_guardian_alert.assert_awaited_once()


@pytest.mark.asyncio
async def test_acknowledge_alert(guardian, mock_db):
    result = await guardian.acknowledge_alert(1)
    assert result is True


@pytest.mark.asyncio
async def test_acknowledge_alert_not_found(guardian, mock_db):
    mock_db.acknowledge_guardian_alert.return_value = False
    result = await guardian.acknowledge_alert(999)
    assert result is False


@pytest.mark.asyncio
async def test_get_alerts(guardian, mock_db):
    mock_db.get_guardian_alerts.return_value = [
        {"id": 1, "alert_type": "rug_signal", "severity": "critical"},
    ]
    alerts = await guardian.get_alerts("0xabc")
    assert len(alerts) == 1


# --- Rescue-service-backed approval data ---


@pytest.mark.asyncio
async def test_approval_data_no_rescue_returns_none(mock_db):
    """Guardian without rescue_service returns None (data unavailable)."""
    g = GuardianService(db=mock_db)
    result = await g._get_approval_data("0xabc", 56)
    assert result is None


@pytest.mark.asyncio
async def test_approval_data_via_rescue(guardian_with_rescue, mock_rescue):
    """Rescue service results are mapped to guardian format."""
    mock_rescue.scan_approvals.return_value = {
        "approvals": [
            {
                "token_address": "0xtoken1",
                "token_name": "TestToken",
                "token_symbol": "TT",
                "spender": "0xspender1",
                "spender_label": "Unknown Contract",
                "allowance": "Unlimited",
                "risk_level": "HIGH",
                "risk_reason": "Unlimited approval to unknown contract",
                "chain_id": 56,
                "value_at_risk_usd": 1.50,
                "has_revoke_tx": True,
            },
        ],
    }
    guardian_with_rescue._db.get_contract_score = AsyncMock(return_value=None)

    result = await guardian_with_rescue._get_approval_data("0xabc", 56)
    assert result is not None
    assert len(result) == 1
    assert result[0]["is_unlimited"] is True
    assert result[0]["risk_level"] == "high"  # mapped from HIGH
    assert result[0]["spender"] == "0xspender1"
    assert result[0]["value_at_risk_usd"] == 1.50


@pytest.mark.asyncio
async def test_approval_data_db_score_upgrades_risk(guardian_with_rescue, mock_rescue):
    """DB contract score can upgrade risk from 'high' to 'critical'."""
    mock_rescue.scan_approvals.return_value = {
        "approvals": [
            {
                "token_address": "0xtoken1",
                "spender": "0xbadspender",
                "spender_label": "Unknown",
                "allowance": "Unlimited",
                "risk_level": "HIGH",
                "risk_reason": "test",
                "chain_id": 56,
                "value_at_risk_usd": None,
                "has_revoke_tx": True,
            },
        ],
    }

    async def mock_score(addr, chain_id, **kwargs):
        if "badspender" in addr:
            return {"risk_score": 85, "risk_level": "HIGH"}
        return None
    guardian_with_rescue._db.get_contract_score = mock_score

    result = await guardian_with_rescue._get_approval_data("0xabc", 56)
    assert len(result) == 1
    assert result[0]["risk_level"] == "critical"


@pytest.mark.asyncio
async def test_flagged_exposure_from_tokens(guardian_with_rescue):
    """Tokens with risk_score >= 70 add 20 points each."""
    async def mock_score(addr, chain_id, **kwargs):
        if addr == "0xtoken1":
            return {"risk_score": 80, "risk_level": "HIGH"}
        return None
    guardian_with_rescue._db.get_contract_score = mock_score

    result = await guardian_with_rescue._check_flagged_exposure_from_tokens(
        ["0xtoken1", "0xtoken2"], 56,
    )
    assert result == 20.0


@pytest.mark.asyncio
async def test_flagged_exposure_empty_tokens(guardian_with_rescue):
    """No tokens = 0 risk."""
    result = await guardian_with_rescue._check_flagged_exposure_from_tokens([], 56)
    assert result == 0.0


@pytest.mark.asyncio
async def test_concentration_single_token_max_risk():
    """One token with all USD value = HHI 1.0 = 100 risk."""
    approvals = [
        {"token_address": "0xtoken1", "value_at_risk_usd": 100.0},
    ]
    result = GuardianService._check_concentration_from_approvals(approvals)
    assert result == 100.0


@pytest.mark.asyncio
async def test_concentration_even_split_low_risk():
    """Even split across 4 tokens = HHI 0.25 = 25 risk."""
    approvals = [
        {"token_address": "0xt1", "value_at_risk_usd": 25.0},
        {"token_address": "0xt2", "value_at_risk_usd": 25.0},
        {"token_address": "0xt3", "value_at_risk_usd": 25.0},
        {"token_address": "0xt4", "value_at_risk_usd": 25.0},
    ]
    result = GuardianService._check_concentration_from_approvals(approvals)
    assert abs(result - 25.0) < 0.1


@pytest.mark.asyncio
async def test_concentration_no_usd_values():
    """No USD values = 0 risk (can't measure)."""
    approvals = [
        {"token_address": "0xt1", "value_at_risk_usd": None},
        {"token_address": "0xt2", "value_at_risk_usd": 0},
    ]
    result = GuardianService._check_concentration_from_approvals(approvals)
    assert result == 0.0


@pytest.mark.asyncio
async def test_deployer_risk_flagged(guardian_with_rescue):
    """Watched deployer adds 25 risk points."""
    guardian_with_rescue._db.get_deployer_risk_summary = AsyncMock(
        return_value={"deployer_address": "0xdeployer1", "total_contracts": 3, "high_risk_contracts": 2}
    )
    guardian_with_rescue._db.is_watched_deployer = AsyncMock(
        return_value={"deployer_address": "0xdeployer1", "chain_id": 0, "watch_reason": "SERIAL_SCAMMER"}
    )
    result = await guardian_with_rescue._check_deployer_risk_from_tokens(
        ["0xtoken1"], 56,
    )
    assert result == 25.0


@pytest.mark.asyncio
async def test_health_with_approvals(guardian_with_rescue, mock_rescue):
    """Full health check with rescue data returns real score."""
    mock_rescue.scan_approvals.return_value = {
        "approvals": [
            {
                "token_address": "0xtoken1",
                "token_name": "TestToken",
                "token_symbol": "TT",
                "spender": "0xspender1",
                "spender_label": "Unknown Contract",
                "allowance": "Unlimited",
                "risk_level": "HIGH",
                "risk_reason": "Unlimited approval to unknown contract",
                "chain_id": 56,
                "value_at_risk_usd": 2.00,
                "has_revoke_tx": True,
            },
        ],
    }
    guardian_with_rescue._db.get_contract_score = AsyncMock(return_value=None)

    result = await guardian_with_rescue.get_health("0xabc", 56)
    assert result["level"] != "unknown"
    assert "warnings" not in result
    assert result["total_approvals"] == 1
    assert result["total_value_at_risk_usd"] == 2.00


@pytest.mark.asyncio
async def test_health_no_approvals_excellent(guardian_with_rescue, mock_rescue):
    """Empty wallet (no approvals) = excellent health."""
    mock_rescue.scan_approvals.return_value = {"approvals": []}
    result = await guardian_with_rescue.get_health("0xabc", 56)
    assert result["health_score"] == 100.0
    assert result["level"] == "excellent"
    assert result["total_approvals"] == 0


@pytest.mark.asyncio
async def test_health_rescue_failure_returns_unknown(mock_db, mock_rescue):
    """If rescue_service.scan_approvals raises, Guardian falls back to 'unknown'."""
    mock_rescue.scan_approvals = AsyncMock(side_effect=RuntimeError("RPC down"))
    g = GuardianService(db=mock_db, rescue_service=mock_rescue)
    result = await g.get_health("0xabc", 56)
    assert result["level"] == "unknown"
    assert "warnings" in result


@pytest.mark.asyncio
async def test_risk_level_mapping():
    """Rescue uppercase → guardian lowercase."""
    assert GuardianService._map_risk_level("HIGH") == "high"
    assert GuardianService._map_risk_level("MEDIUM") == "medium"
    assert GuardianService._map_risk_level("LOW") == "low"
    assert GuardianService._map_risk_level("UNKNOWN") == "unknown"


@pytest.mark.asyncio
async def test_unknown_rescue_scan_cannot_be_empty_clean_approvals(guardian_with_rescue, mock_rescue, mock_db):
    mock_rescue.scan_approvals.return_value = {
        "status": "unknown", "approvals": [], "reason": "Approval log scan incomplete",
    }
    scan = await guardian_with_rescue.get_approvals("0xabc", 56)
    assert scan["approvals"] == []
    assert scan["status"] == "unknown"
    assert scan["coverage_reasons"]
    result = await guardian_with_rescue.get_health("0xabc", 56)
    assert result["status"] == "unknown"
    assert result["level"] == "unknown"
    assert result["coverage_reasons"]
    mock_db.update_guardian_health.assert_not_awaited()


@pytest.mark.asyncio
async def test_unavailable_approvals_raise_instead_of_empty_list(guardian, mock_db):
    with pytest.raises(RuntimeError, match="Approval data unavailable"):
        await guardian.get_approvals("0xabc", 56)
    await guardian.get_health("0xabc", 56)
    mock_db.update_guardian_health.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("unknown_source", ["cached_score", "rescue_approval", "risk_level", "score_failure"])
async def test_unknown_approval_risk_never_becomes_low_or_persisted_health(
    guardian_with_rescue, mock_rescue, mock_db, unknown_source,
):
    approval = {"token_address": "0xtoken", "spender": "0xspender", "risk_level": "LOW"}
    mock_rescue.scan_approvals.return_value = {"approvals": [approval]}
    mock_db.get_contract_score = AsyncMock(return_value=None)
    if unknown_source == "cached_score":
        mock_db.get_contract_score.return_value = {"status": "unknown", "risk_score": 0}
    elif unknown_source == "rescue_approval":
        approval["status"] = "unknown"
    elif unknown_source == "risk_level":
        approval["risk_level"] = "UNKNOWN"
    else:
        mock_db.get_contract_score.side_effect = RuntimeError("score unavailable")
    scan = await guardian_with_rescue.get_approvals("0xabc", 56)
    assert scan["status"] == "unknown"
    assert scan["coverage_reasons"]["approval_risk"]
    approvals = scan["approvals"]
    assert approvals[0]["risk_level"] == "unknown"
    assert approvals[0]["status"] == "unknown"
    assert approvals[0]["coverage_reasons"]
    result = await guardian_with_rescue.get_health("0xabc", 56)
    assert result["status"] == "unknown"
    assert result["level"] == "unknown"
    mock_db.update_guardian_health.assert_not_awaited()


@pytest.mark.asyncio
async def test_unknown_cached_token_exposure_is_not_clean(guardian_with_rescue, mock_db):
    mock_db.get_contract_score = AsyncMock(return_value={"status": "unknown", "risk_score": 0})
    assert await guardian_with_rescue._check_flagged_exposure_from_tokens(["0xtoken"], 56) is None


@pytest.mark.asyncio
async def test_complete_empty_approval_scan_still_persists_health(guardian_with_rescue, mock_db):
    result = await guardian_with_rescue.get_health("0xabc", 56)
    assert result["status"] == "ok"
    assert result["level"] == "excellent"
    mock_db.update_guardian_health.assert_awaited_once_with("0xabc", 56, 100.0)


@pytest.mark.asyncio
@pytest.mark.parametrize("check, method", [
    ("_check_flagged_exposure_from_tokens", "get_contract_score"),
    ("_check_deployer_risk_from_tokens", "get_deployer_risk_summary"),
    ("_check_deployer_risk_from_tokens", "is_watched_deployer"),
])
async def test_token_lookup_failure_is_unknown_not_zero_risk(
    guardian_with_rescue, mock_rescue, mock_db, check, method,
):
    mock_rescue.scan_approvals.return_value = {
        "approvals": [{"token_address": "0xtoken", "spender": "0xspender", "risk_level": "HIGH"}],
    }
    mock_db.get_contract_score = AsyncMock(return_value=None)
    mock_db.get_deployer_risk_summary = AsyncMock(return_value={"deployer_address": "0xdeployer"})
    getattr(mock_db, method).side_effect = RuntimeError("lookup unavailable")
    assert await getattr(guardian_with_rescue, check)(["0xtoken"], 56) is None
    result = await guardian_with_rescue.get_health("0xabc", 56)
    assert result["status"] == "unknown"
    assert result["level"] == "unknown"
    mock_db.update_guardian_health.assert_not_awaited()


@pytest.mark.asyncio
async def test_unavailable_rescue_scan_logs_warning_without_traceback(guardian_with_rescue, mock_rescue, caplog):
    mock_rescue.scan_approvals.side_effect = RuntimeError("Approval scan unavailable")
    with caplog.at_level(logging.WARNING, logger="services.guardian"):
        assert await guardian_with_rescue._get_approval_data("0xabc", 56) is None
    records = [record for record in caplog.records if record.name == "services.guardian"]
    assert [record.levelno for record in records] == [logging.WARNING]
    assert records[0].exc_info is None
    assert "Traceback" not in caplog.text


@pytest.mark.asyncio
async def test_unexpected_rescue_failure_logs_error_with_traceback(guardian_with_rescue, mock_rescue, caplog):
    mock_rescue.scan_approvals.side_effect = KeyError("SYNTHETIC-KEY-9d41b7")
    with caplog.at_level(logging.WARNING, logger="services.guardian"):
        assert await guardian_with_rescue._get_approval_data("0xabc", 56) is None
    records = [record for record in caplog.records if record.name == "services.guardian"]
    assert [record.levelno for record in records] == [logging.ERROR]
    assert records[0].exc_info is None
    assert "KeyError" in caplog.text
    assert 'File "' in caplog.text
    assert "SYNTHETIC-KEY-9d41b7" not in caplog.text


@pytest.mark.asyncio
async def test_incomplete_scan_still_returns_known_dangerous_approvals(guardian_with_rescue, mock_rescue, mock_db):
    mock_rescue.scan_approvals.return_value = {
        "approvals": [{
            "token_address": "0xtoken", "spender": "0xspender", "allowance": "Unlimited", "risk_level": "HIGH",
        }],
        "status": "unknown",
        "coverage": {"allowances": True, "balances": True, "prices": False},
        "coverage_reasons": {"prices": "USD price unavailable for 1 token(s)"},
    }
    mock_db.get_contract_score = AsyncMock(return_value=None)
    scan = await guardian_with_rescue.get_approvals("0xabc", 56)
    assert [approval["risk_level"] for approval in scan["approvals"]] == ["high"]
    assert scan["status"] == "unknown"
    assert scan["coverage"] == {"allowances": True, "balances": True, "prices": False}
    assert scan["coverage_reasons"] == {"prices": "USD price unavailable for 1 token(s)"}
    health = await guardian_with_rescue.get_health("0xabc", 56)
    assert health["status"] == "unknown"
    mock_db.update_guardian_health.assert_not_awaited()


@pytest.mark.asyncio
async def test_complete_scan_returns_ok_approvals(guardian_with_rescue, mock_rescue, mock_db):
    coverage = {"allowances": True, "balances": True, "prices": True}
    mock_rescue.scan_approvals.return_value = {
        "approvals": [{"token_address": "0xtoken", "spender": "0xspender", "risk_level": "HIGH"}],
        "status": "ok", "coverage": coverage, "coverage_reasons": {},
    }
    mock_db.get_contract_score = AsyncMock(return_value=None)
    scan = await guardian_with_rescue.get_approvals("0xabc", 56)
    assert len(scan["approvals"]) == 1
    assert scan["status"] == "ok"
    assert scan["coverage"] == coverage
    assert scan["coverage_reasons"] == {}


@pytest.mark.asyncio
async def test_approval_scan_failure_raises(guardian_with_rescue, mock_rescue):
    mock_rescue.scan_approvals.side_effect = RuntimeError("Approval scan unavailable")
    with pytest.raises(RuntimeError, match="^Approval data unavailable$"):
        await guardian_with_rescue.get_approvals("0xabc", 56)


def _database_mock():
    from core.database import Database

    db = create_autospec(Database, instance=True)
    db.get_contract_score.return_value = None
    db.get_deployer_risk_summary.return_value = None
    db.is_watched_deployer.return_value = None
    return db


@pytest.mark.asyncio
async def test_deployer_risk_uses_real_database_lookups(mock_rescue):
    db = _database_mock()
    db.get_deployer_risk_summary.return_value = {
        "deployer_address": "0xdeployer1", "total_contracts": 3, "high_risk_contracts": 2,
    }
    db.is_watched_deployer.return_value = {"deployer_address": "0xdeployer1", "chain_id": 0}
    guardian = GuardianService(db=db, rescue_service=mock_rescue)
    assert await guardian._check_deployer_risk_from_tokens(["0xtoken1"], 56) == 25.0
    db.get_deployer_risk_summary.assert_awaited_once_with("0xtoken1", 56)
    db.is_watched_deployer.assert_awaited_once_with("0xdeployer1", 56)


@pytest.mark.asyncio
async def test_unindexed_deployer_is_zero_risk_not_unknown_health(mock_rescue):
    db = _database_mock()
    mock_rescue.scan_approvals.return_value = {
        "approvals": [{"token_address": "0xtoken1", "spender": "0xspender", "risk_level": "LOW"}],
        "status": "ok", "coverage": {"allowances": True, "balances": True, "prices": True}, "coverage_reasons": {},
    }
    guardian = GuardianService(db=db, rescue_service=mock_rescue)
    assert await guardian._check_deployer_risk_from_tokens(["0xtoken1"], 56) == 0.0
    health = await guardian.get_health("0xabc", 56)
    assert health["status"] == "ok"
    assert health["components"]["deployer_risk"] == 100.0
    db.is_watched_deployer.assert_not_awaited()
    db.update_guardian_health.assert_awaited_once()
