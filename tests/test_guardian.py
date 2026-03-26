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
def guardian(mock_db):
    return GuardianService(db=mock_db)


@pytest.fixture
def mock_settings():
    s = MagicMock()
    s.bsc_rpc_url = "https://bsc-dataseed.binance.org/"
    s.logs_rpc_url = "https://bsc-rpc.example.com"
    s.eth_rpc_url = "https://eth-rpc.example.com"
    s.base_rpc_url = ""
    s.arbitrum_rpc_url = ""
    s.polygon_rpc_url = ""
    s.opbnb_rpc_url = ""
    s.optimism_rpc_url = ""
    s.bscscan_api_key = ""
    return s


@pytest.fixture
def guardian_with_settings(mock_db, mock_settings):
    return GuardianService(db=mock_db, settings=mock_settings)


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
    """No RPC/settings = data unavailable, level should be 'unknown'."""
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


# --- RPC-based on-chain reads ---


@pytest.mark.asyncio
async def test_approval_data_no_settings_returns_none(mock_db):
    """Guardian without settings returns None (data unavailable)."""
    g = GuardianService(db=mock_db)
    result = await g._get_approval_data("0xabc", 56)
    assert result is None


@pytest.mark.asyncio
async def test_approval_data_via_rpc(guardian_with_settings):
    """Mock RPC getLogs and verify parsed approvals."""
    fake_log = {
        "address": "0xtokenaddress1234567890abcdef1234567890ab",
        "topics": [
            "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
            "0x000000000000000000000000abc0000000000000000000000000000000000000",
            "0x000000000000000000000000def0000000000000000000000000000000000000",
        ],
        "data": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "timeStamp": hex(int(time.time()) - 86400),
    }

    guardian_with_settings._rpc_block_number = AsyncMock(return_value=100)
    guardian_with_settings._rpc_get_logs = AsyncMock(return_value=[fake_log])
    guardian_with_settings._db.get_contract_score = AsyncMock(return_value=None)

    result = await guardian_with_settings._get_approval_data("0xabc", 56)
    assert result is not None
    assert len(result) == 1
    assert result[0]["is_unlimited"] is True
    assert result[0]["risk_level"] == "low"
    assert "spender" in result[0]


@pytest.mark.asyncio
async def test_approval_data_with_risky_spender(guardian_with_settings):
    """Spender with high risk score gets flagged."""
    fake_log = {
        "address": "0xtokenaddress1234567890abcdef1234567890ab",
        "topics": [
            "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
            "0x000000000000000000000000abc0000000000000000000000000000000000000",
            "0x000000000000000000000000def0000000000000000000000000000000000000",
        ],
        "data": "0x" + "f" * 64,
        "timeStamp": hex(int(time.time()) - 3600),
    }

    guardian_with_settings._rpc_block_number = AsyncMock(return_value=100)
    guardian_with_settings._rpc_get_logs = AsyncMock(return_value=[fake_log])

    async def mock_score(addr, chain_id, **kwargs):
        if "def0" in addr:
            return {"risk_score": 85, "risk_level": "HIGH"}
        return None
    guardian_with_settings._db.get_contract_score = mock_score

    result = await guardian_with_settings._get_approval_data("0xabc", 56)
    assert len(result) == 1
    assert result[0]["risk_level"] == "critical"


@pytest.mark.asyncio
async def test_flagged_exposure_from_tokens(guardian_with_settings):
    """Tokens with risk_score >= 70 add 20 points each."""
    async def mock_score(addr, chain_id, **kwargs):
        if addr == "0xtoken1":
            return {"risk_score": 80, "risk_level": "HIGH"}
        return None
    guardian_with_settings._db.get_contract_score = mock_score

    result = await guardian_with_settings._check_flagged_exposure_from_tokens(
        ["0xtoken1", "0xtoken2"], 56,
    )
    assert result == 20.0


@pytest.mark.asyncio
async def test_flagged_exposure_empty_tokens(guardian_with_settings):
    """No tokens = 0 risk."""
    result = await guardian_with_settings._check_flagged_exposure_from_tokens([], 56)
    assert result == 0.0


@pytest.mark.asyncio
async def test_concentration_single_token_max_risk(guardian_with_settings):
    """One token = HHI 1.0 = 100 risk."""
    guardian_with_settings._rpc_balance_of = AsyncMock(return_value=1000000)
    result = await guardian_with_settings._check_concentration_from_tokens(
        "0xabc", ["0xtoken1"], 56,
    )
    assert result == 100.0


@pytest.mark.asyncio
async def test_concentration_even_split_low_risk(guardian_with_settings):
    """Even split across 4 tokens = HHI 0.25 = 25 risk."""
    guardian_with_settings._rpc_balance_of = AsyncMock(return_value=1000)
    result = await guardian_with_settings._check_concentration_from_tokens(
        "0xabc", ["0xt1", "0xt2", "0xt3", "0xt4"], 56,
    )
    assert abs(result - 25.0) < 0.1


@pytest.mark.asyncio
async def test_deployer_risk_flagged(guardian_with_settings):
    """Watched deployer adds 25 risk points."""
    guardian_with_settings._db.get_deployer = AsyncMock(
        return_value={"deployer_address": "0xDeployer1"}
    )
    guardian_with_settings._db.get_watched_deployer = AsyncMock(
        return_value={"address": "0xDeployer1", "reason": "serial scammer"}
    )
    result = await guardian_with_settings._check_deployer_risk_from_tokens(
        ["0xtoken1"], 56,
    )
    assert result == 25.0


@pytest.mark.asyncio
async def test_health_with_approvals(guardian_with_settings):
    """Full health check with mocked RPC data returns real score."""
    fake_log = {
        "address": "0xtokenaddress1234567890abcdef1234567890ab",
        "topics": [
            "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
            "0x000000000000000000000000abc0000000000000000000000000000000000000",
            "0x000000000000000000000000def0000000000000000000000000000000000000",
        ],
        "data": "0x" + "f" * 64,
        "timeStamp": hex(int(time.time()) - 86400),
    }

    guardian_with_settings._rpc_block_number = AsyncMock(return_value=100)
    guardian_with_settings._rpc_get_logs = AsyncMock(return_value=[fake_log])
    guardian_with_settings._rpc_balance_of = AsyncMock(return_value=1000)
    guardian_with_settings._db.get_contract_score = AsyncMock(return_value=None)

    result = await guardian_with_settings.get_health("0xabc", 56)
    assert result["level"] != "unknown"
    assert "warnings" not in result
    assert result["total_approvals"] == 1
