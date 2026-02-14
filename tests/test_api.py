"""Integration tests for the FastAPI endpoints (/api/health, /api/firewall fallback)."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch


@pytest.fixture
def client():
    """Create a TestClient with mocked dependencies."""
    # Patch heavy dependencies before importing api module
    mock_web3 = MagicMock()
    mock_web3.is_valid_address.return_value = True
    mock_web3.to_checksum_address.side_effect = lambda a: a
    mock_web3.is_token_contract = AsyncMock(return_value=False)
    mock_web3.is_contract = AsyncMock(return_value=True)
    mock_web3.get_token_info = AsyncMock(return_value={})
    mock_web3.get_bytecode = AsyncMock(return_value="0x6080")

    mock_ai = MagicMock()
    mock_ai.is_available.return_value = False  # AI unavailable for fallback tests

    mock_decoder = MagicMock()
    mock_decoder.decode.return_value = {
        "selector": None,
        "function_name": "Native Transfer",
        "signature": None,
        "category": "transfer",
        "risk": "low",
        "params": {},
        "is_approval": False,
        "is_unlimited_approval": False,
        "raw": "0x",
    }
    mock_decoder.is_whitelisted_target.return_value = None

    mock_scam_db = MagicMock()

    mock_tx_scanner = MagicMock()
    mock_tx_scanner.scan_address = AsyncMock(return_value={
        "address": "0xdeadbeef",
        "is_verified": False,
        "is_contract": True,
        "risk_level": "medium",
        "risk_score": 45,
        "confidence": 60,
        "checks": {},
        "warnings": [],
        "scam_matches": [],
        "is_honeypot": False,
    })

    mock_token_scanner = MagicMock()

    mock_greenfield = MagicMock()
    mock_greenfield.is_enabled.return_value = False
    mock_greenfield.async_init = AsyncMock()
    mock_greenfield.close = AsyncMock()

    mock_tenderly = MagicMock()
    mock_tenderly.is_enabled.return_value = False
    mock_tenderly.close = AsyncMock()

    mock_contract_service = MagicMock()
    mock_contract_service.fetch_contract_data = AsyncMock(side_effect=Exception("skip composite"))
    mock_honeypot_service = MagicMock()
    mock_dex_service = MagicMock()
    mock_ethos_service = MagicMock()
    mock_risk_engine = MagicMock()

    import api as api_module
    api_module.web3_client = mock_web3
    api_module.ai_analyzer = mock_ai
    api_module.tx_scanner = mock_tx_scanner
    api_module.token_scanner = mock_token_scanner
    api_module.calldata_decoder = mock_decoder
    api_module.scam_db = mock_scam_db
    api_module.greenfield_service = mock_greenfield
    api_module.tenderly_simulator = mock_tenderly
    api_module.contract_service = mock_contract_service
    api_module.honeypot_service = mock_honeypot_service
    api_module.dex_service = mock_dex_service
    api_module.ethos_service = mock_ethos_service
    api_module.risk_engine = mock_risk_engine

    from fastapi.testclient import TestClient
    return TestClient(api_module.app, raise_server_exceptions=False)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "shieldai-firewall"
        assert "ai_available" in data

    def test_health_ai_unavailable(self, client):
        resp = client.get("/api/health")
        data = resp.json()
        assert data["ai_available"] is False


class TestFirewallFallback:
    def test_firewall_fallback_when_ai_unavailable(self, client):
        """When composite pipeline fails and AI is unavailable, fallback should return heuristic result."""
        resp = client.post("/api/firewall", json={
            "to": "0x3ee505ba316879d246760e89f0a29a4403afa498",
            "from": "0x742d35Cc6634C0532925a3b844Bc9e7595f42bE1",
            "value": "0x2386F26FC10000",
            "data": "0x",
            "chainId": 56,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "classification" in data
        assert "risk_score" in data
        assert "raw_checks" in data
        # Should be heuristic fallback
        assert data["classification"] in ("SAFE", "CAUTION", "HIGH_RISK", "BLOCK_RECOMMENDED")

    def test_firewall_invalid_address(self, client):
        import api as api_module
        api_module.web3_client.is_valid_address.return_value = False
        resp = client.post("/api/firewall", json={
            "to": "not-an-address",
            "from": "0x742d35Cc6634C0532925a3b844Bc9e7595f42bE1",
            "value": "0x0",
            "data": "0x",
        })
        assert resp.status_code == 400
        # Restore
        api_module.web3_client.is_valid_address.return_value = True
