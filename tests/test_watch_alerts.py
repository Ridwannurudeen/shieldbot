"""Deployer alerts are public: no token holding, wallet or signature is needed to read them."""

import importlib.util
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

WALLET = "0x1111111111111111111111111111111111111111"


@pytest.fixture
def client():
    import api as api_module

    db = MagicMock()
    db.get_deployment_alerts = AsyncMock(return_value=[])
    api_module.container = SimpleNamespace(
        db=db,
        settings=SimpleNamespace(trusted_proxies=[]),
    )
    api_module._watch_alerts_limiter = api_module.RateLimiter(
        requests_per_minute=10,
        burst=5,
    )
    api_module.rate_limiter = api_module.RateLimiter(requests_per_minute=30, burst=10)

    return TestClient(api_module.app, raise_server_exceptions=False)


def test_alerts_are_served_without_a_wallet(client):
    import api as api_module

    sample_alerts = [
        {
            "id": 7,
            "deployer_address": "0x2222222222222222222222222222222222222222",
            "chain_id": 56,
            "new_contract_address": "0x3333333333333333333333333333333333333333",
            "watch_reason": "MANUAL",
            "telegram_sent": False,
            "created_at": 1234567890.0,
        }
    ]
    api_module.container.db.get_deployment_alerts = AsyncMock(return_value=sample_alerts)

    response = client.get("/api/watch/alerts")

    assert response.status_code == 200
    assert response.json() == {
        "alerts": [
            {
                "deployer_address": "0x2222222222222222222222222222222222222222",
                "chain_id": 56,
                "new_contract_address": "0x3333333333333333333333333333333333333333",
                "watch_reason": "MANUAL",
                "created_at": 1234567890.0,
            }
        ],
        "count": 1,
    }
    api_module.container.db.get_deployment_alerts.assert_awaited_once_with(limit=50)


def test_free_text_watch_reasons_stay_private(client):
    """Admin notes and agent reasons are free text; only the fixed reason codes are public."""
    import api as api_module

    alert = {
        "id": 8,
        "deployer_address": "0x2222222222222222222222222222222222222222",
        "chain_id": 1,
        "new_contract_address": "0x3333333333333333333333333333333333333333",
        "telegram_sent": True,
        "created_at": 1234567890.0,
    }
    api_module.container.db.get_deployment_alerts = AsyncMock(
        return_value=[
            {**alert, "watch_reason": "SERIAL_SCAMMER"},
            {**alert, "watch_reason": "tip from a private chat about this deployer"},
            {**alert, "watch_reason": None},
        ]
    )

    alerts = client.get("/api/watch/alerts").json()["alerts"]

    assert [a["watch_reason"] for a in alerts] == ["SERIAL_SCAMMER", None, None]
    assert all(set(a) == {
        "deployer_address", "chain_id", "new_contract_address", "watch_reason", "created_at",
    } for a in alerts)


def test_released_extension_query_still_gets_alerts(client):
    """The published extension still sends ?wallet=; it must get the alerts, not a 403."""
    response = client.get("/api/watch/alerts", params={"wallet": WALLET})

    assert response.status_code == 200
    assert response.json() == {"alerts": [], "count": 0}


def test_rate_limit_still_applies(client):
    statuses = [client.get("/api/watch/alerts").status_code for _ in range(6)]

    assert statuses == [200] * 5 + [429]


def test_alerts_unavailable_without_a_database(client):
    import api as api_module

    api_module.container = SimpleNamespace(db=None, settings=SimpleNamespace(trusted_proxies=[]))

    assert client.get("/api/watch/alerts").status_code == 503


def test_token_gate_is_gone(client):
    import api as api_module

    assert importlib.util.find_spec("services.token_gate_service") is None
    assert not hasattr(api_module, "token_gate_service")
    assert not hasattr(api_module, "SHIELDBOT_TOKEN_ADDRESS")
    assert client.get("/api/watch/nonce", params={"wallet": WALLET}).status_code == 404
