from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    import api as api_module

    advisor = MagicMock()
    advisor.chat = AsyncMock(return_value="This contract looks risky.")
    advisor.explain_scan = AsyncMock(return_value="High sell tax detected.")

    api_module.container = SimpleNamespace(
        db=MagicMock(),
        settings=SimpleNamespace(trusted_proxies=[]),
        advisor=advisor,
    )

    # Reset rate limiter so tests don't bleed into each other
    api_module.chat_limiter = api_module.RateLimiter(
        requests_per_minute=50, burst=10,
    )

    return TestClient(api_module.app, raise_server_exceptions=False)


def test_chat_success(client):
    response = client.post(
        "/api/agent/chat",
        json={"message": "Is this contract safe?", "user_id": "user123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["response"] == "This contract looks risky."
    assert data["user_id"] == "user123"


def test_chat_empty_message(client):
    response = client.post(
        "/api/agent/chat",
        json={"message": "", "user_id": "user123"},
    )
    assert response.status_code == 422


def test_chat_calls_advisor(client):
    import api as api_module

    advisor = api_module.container.advisor

    client.post(
        "/api/agent/chat",
        json={"message": "Check 0xdead", "user_id": "user42"},
    )

    advisor.chat.assert_awaited_once_with("user42", "Check 0xdead")


def test_explain_success(client):
    response = client.post(
        "/api/agent/explain",
        json={"scan_result": {"risk_score": 85, "risk_level": "HIGH"}},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["explanation"] == "High sell tax detected."


def test_explain_calls_advisor(client):
    import api as api_module

    advisor = api_module.container.advisor

    scan = {"risk_score": 85, "risk_level": "HIGH"}
    client.post("/api/agent/explain", json={"scan_result": scan})

    advisor.explain_scan.assert_awaited_once_with(scan)
