from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    import api as api_module

    db = MagicMock()
    db.get_deployment_alerts = AsyncMock(return_value=[])

    gate = MagicMock()
    gate.has_shieldbot_token = AsyncMock(return_value=False)

    api_module.container = SimpleNamespace(
        db=db,
        settings=SimpleNamespace(trusted_proxies=[]),
        token_gate_service=gate,
    )
    api_module.token_gate_service = gate
    api_module._watch_alerts_limiter = api_module.RateLimiter(
        requests_per_minute=10,
        burst=5,
    )

    return TestClient(api_module.app, raise_server_exceptions=False)


def test_holder_gets_alerts(client):
    import api as api_module

    sample_alerts = [
        {
            "id": 7,
            "deployer_address": "0x1111111111111111111111111111111111111111",
            "chain_id": 56,
            "new_contract_address": "0x2222222222222222222222222222222222222222",
            "watch_reason": "MANUAL",
            "telegram_sent": False,
            "created_at": 1234567890.0,
        }
    ]
    api_module.token_gate_service.has_shieldbot_token = AsyncMock(return_value=True)
    api_module.container.db.get_deployment_alerts = AsyncMock(return_value=sample_alerts)

    response = client.get(
        "/api/watch/alerts",
        params={"wallet": "0x4904c02efa081cb7685346968bac854cdf4e7777"},
    )

    assert response.status_code == 200
    assert response.json() == {"alerts": sample_alerts, "count": 1}
    api_module.token_gate_service.has_shieldbot_token.assert_awaited_once_with(
        "0x4904c02efa081cb7685346968bac854cdf4e7777"
    )
    api_module.container.db.get_deployment_alerts.assert_awaited_once_with(limit=50)


def test_non_holder_gets_403(client):
    import api as api_module

    api_module.token_gate_service.has_shieldbot_token = AsyncMock(return_value=False)

    response = client.get(
        "/api/watch/alerts",
        params={"wallet": "0x4904c02efa081cb7685346968bac854cdf4e7777"},
    )

    assert response.status_code == 403
    assert response.json() == {
        "error": "Token holding required",
        "token": "0x4904c02efa081cb7685346968bac854cdf4e7777",
    }
    api_module.container.db.get_deployment_alerts.assert_not_awaited()


def test_invalid_address_returns_422(client):
    import api as api_module

    response = client.get(
        "/api/watch/alerts",
        params={"wallet": "not-an-address"},
    )

    assert response.status_code == 422
    api_module.token_gate_service.has_shieldbot_token.assert_not_awaited()
