"""Shared fixtures for ShieldBot tests."""

import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.fixture
def mock_web3_client():
    """Mock Web3Client that returns predictable data without network calls."""
    client = MagicMock()
    client.is_valid_address.return_value = True
    client.to_checksum_address.side_effect = lambda a: a
    client.is_contract = AsyncMock(return_value=True)
    client.get_bytecode = AsyncMock(return_value="0x6080604052")
    client.is_verified_contract = AsyncMock(return_value=(True, None))
    client.get_contract_creation_info = AsyncMock(return_value={"age_days": 90})
    client.get_token_info = AsyncMock(return_value={
        "name": "TestToken",
        "symbol": "TT",
        "decimals": 18,
        "total_supply": 1_000_000,
    })
    client.get_ownership_info = AsyncMock(return_value={
        "owner": "0x0000000000000000000000000000000000000000",
        "is_renounced": True,
    })
    client.get_liquidity_info = AsyncMock(return_value={
        "is_locked": True,
        "lock_percentage": 95,
    })
    client.check_honeypot = AsyncMock(return_value={"is_honeypot": False})
    client.get_tax_info = AsyncMock(return_value={"buy_tax": 0, "sell_tax": 0})
    client.can_transfer_token = AsyncMock(return_value=True)
    client.get_web3 = MagicMock()
    return client


@pytest.fixture
def mock_ai_analyzer():
    """Mock AIAnalyzer that returns a canned AI risk score."""
    analyzer = MagicMock()
    analyzer.is_available.return_value = True
    analyzer.compute_ai_risk_score = AsyncMock(return_value={
        "risk_score": 25,
        "confidence": 80,
        "risk_level": "LOW",
        "key_findings": [],
        "recommendation": "Generally safe.",
    })
    analyzer.generate_forensic_report = AsyncMock(return_value=None)
    return analyzer


@pytest.fixture
def mock_ai_analyzer_unavailable():
    """Mock AIAnalyzer that is not available (no API key)."""
    analyzer = MagicMock()
    analyzer.is_available.return_value = False
    return analyzer
