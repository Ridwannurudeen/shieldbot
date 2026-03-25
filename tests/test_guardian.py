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
async def test_health_no_approvals_is_perfect(guardian):
    """No approvals = 100 health score."""
    result = await guardian.get_health("0xabc", 56)
    assert result["health_score"] == 100.0
    assert result["level"] == "excellent"
    assert result["total_approvals"] == 0


@pytest.mark.asyncio
async def test_health_score_weights_sum_to_one(guardian):
    total = sum(GuardianService.WEIGHTS.values())
    assert abs(total - 1.0) < 0.001


@pytest.mark.asyncio
async def test_health_level_classification(guardian):
    result = await guardian.get_health("0xabc", 56)
    # Perfect score with no approvals
    assert result["level"] in ("excellent", "good", "fair", "poor", "critical")


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
