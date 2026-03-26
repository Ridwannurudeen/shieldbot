"""Tests for Portfolio Guardian service."""

import json
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

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
    """No API key/settings = data unavailable, level should be 'unknown'."""
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


# --- Tests for on-chain reads (Item 2) ---


@pytest.fixture
def mock_settings():
    s = MagicMock()
    s.bscscan_api_key = "test_bsc_key"
    s.etherscan_api_key = ""
    s.basescan_api_key = ""
    s.arbiscan_api_key = ""
    s.polygonscan_api_key = ""
    s.opbnbscan_api_key = ""
    s.optimism_api_key = ""
    return s


@pytest.fixture
def guardian_with_settings(mock_db, mock_settings):
    return GuardianService(db=mock_db, settings=mock_settings)


@pytest.mark.asyncio
async def test_approval_data_no_settings_returns_none(mock_db):
    """Guardian without settings returns None (data unavailable)."""
    g = GuardianService(db=mock_db)
    result = await g._get_approval_data("0xabc", 56)
    assert result is None


@pytest.mark.asyncio
async def test_approval_data_with_explorer_api(guardian_with_settings):
    """Mock Etherscan logs response and verify parsed approvals."""
    fake_log = {
        "address": "0xTokenAddress1234567890abcdef1234567890ab",
        "topics": [
            "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
            "0x000000000000000000000000abc0000000000000000000000000000000000000",
            "0x000000000000000000000000def0000000000000000000000000000000000000",
        ],
        "data": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "timeStamp": hex(int(time.time()) - 86400),  # 1 day ago
    }
    fake_resp = {"status": "1", "result": [fake_log]}

    with patch("aiohttp.ClientSession") as MockSession:
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=fake_resp)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_ctx)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        MockSession.return_value = mock_session

        guardian_with_settings._db.get_contract_score = AsyncMock(return_value=None)
        result = await guardian_with_settings._get_approval_data("0xabc", 56)

    assert len(result) == 1
    assert result[0]["is_unlimited"] is True
    assert result[0]["risk_level"] == "low"
    assert "spender" in result[0]


@pytest.mark.asyncio
async def test_flagged_exposure_scoring(guardian_with_settings):
    """Tokens with risk_score >= 70 add 20 points each."""
    fake_resp = {
        "result": [
            {"contractAddress": "0xToken1", "balance": "1000"},
            {"contractAddress": "0xToken2", "balance": "2000"},
        ]
    }

    with patch("aiohttp.ClientSession") as MockSession:
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=fake_resp)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_ctx)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        MockSession.return_value = mock_session

        # Token1 flagged (risk_score=80), Token2 safe
        async def mock_score(addr, chain_id, **kwargs):
            if addr == "0xtoken1":
                return {"risk_score": 80, "risk_level": "HIGH"}
            return None
        guardian_with_settings._db.get_contract_score = mock_score

        result = await guardian_with_settings._check_flagged_exposure("0xabc", 56)
    assert result == 20.0  # 1 flagged token * 20 points


@pytest.mark.asyncio
async def test_concentration_single_token_max_risk(guardian_with_settings):
    """One token = HHI 1.0 = 100 risk."""
    fake_resp = {"result": [{"balance": "1000000"}]}

    with patch("aiohttp.ClientSession") as MockSession:
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=fake_resp)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_ctx)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        MockSession.return_value = mock_session

        result = await guardian_with_settings._check_concentration("0xabc", 56)
    assert result == 100.0


@pytest.mark.asyncio
async def test_concentration_even_split_low_risk(guardian_with_settings):
    """Even split across 4 tokens = HHI 0.25 = 25 risk."""
    fake_resp = {"result": [
        {"balance": "1000"}, {"balance": "1000"},
        {"balance": "1000"}, {"balance": "1000"},
    ]}

    with patch("aiohttp.ClientSession") as MockSession:
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=fake_resp)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_ctx)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        MockSession.return_value = mock_session

        result = await guardian_with_settings._check_concentration("0xabc", 56)
    assert abs(result - 25.0) < 0.1


@pytest.mark.asyncio
async def test_deployer_risk_flagged(guardian_with_settings):
    """Watched deployer adds 25 risk points."""
    fake_resp = {"result": [{"contractAddress": "0xToken1", "balance": "1000"}]}

    with patch("aiohttp.ClientSession") as MockSession:
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=fake_resp)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_ctx)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        MockSession.return_value = mock_session

        guardian_with_settings._db.get_deployer = AsyncMock(
            return_value={"deployer_address": "0xDeployer1"}
        )
        guardian_with_settings._db.get_watched_deployer = AsyncMock(
            return_value={"address": "0xDeployer1", "reason": "serial scammer"}
        )

        result = await guardian_with_settings._check_deployer_risk("0xabc", 56)
    assert result == 25.0
