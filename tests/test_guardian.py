"""Tests for Portfolio Guardian service."""

import time
import pytest
from unittest.mock import AsyncMock, MagicMock

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
    guardian_with_rescue._db.get_deployer = AsyncMock(
        return_value={"deployer_address": "0xDeployer1"}
    )
    guardian_with_rescue._db.get_watched_deployer = AsyncMock(
        return_value={"address": "0xDeployer1", "reason": "serial scammer"}
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
    assert GuardianService._map_risk_level("UNKNOWN") == "low"
