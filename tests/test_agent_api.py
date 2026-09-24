from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    import api as api_module
    from utils.web3_client import Web3Client

    web3_client = Web3Client.__new__(Web3Client)
    web3_client._adapters = {56: MagicMock(), 1: MagicMock()}
    monkeypatch.setattr(api_module, "web3_client", web3_client)

    advisor = MagicMock()
    advisor.chat = AsyncMock(return_value={"text": "This contract looks risky."})
    advisor.explain_scan = AsyncMock(return_value="High sell tax detected.")

    api_module.container = SimpleNamespace(
        db=MagicMock(),
        settings=SimpleNamespace(trusted_proxies=[]),
        advisor=advisor,
    )

    # Reset rate limiters so tests don't bleed into each other
    api_module.rate_limiter = api_module.RateLimiter(
        requests_per_minute=50, burst=10,
    )
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
    import hashlib

    advisor = api_module.container.advisor

    client.post(
        "/api/agent/chat",
        json={"message": "Check 0xdead", "user_id": "user42"},
    )

    # user_id is bound to client IP: sha256("testclient:user42")[:24]
    # TestClient uses "testclient" as the client host
    bound_id = hashlib.sha256("testclient:user42".encode()).hexdigest()[:24]
    advisor.chat.assert_awaited_once_with(bound_id, "Check 0xdead", chain_id=56)


def test_explain_success(client):
    response = client.post(
        "/api/agent/explain",
        json={"scan_result": {"risk_score": 85, "risk_level": "HIGH", "status": "ok", "coverage": {"honeypot": 1}}},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["explanation"] == "High sell tax detected."


def test_explain_calls_advisor(client):
    import api as api_module

    advisor = api_module.container.advisor

    scan = {"risk_score": 85, "risk_level": "HIGH", "status": "ok", "coverage": {"honeypot": 1}}
    client.post("/api/agent/explain", json={"scan_result": scan})

    advisor.explain_scan.assert_awaited_once_with(scan)


# ---------------------------------------------------------------------------
# Additional coverage: chain_id, scan_data, error paths
# ---------------------------------------------------------------------------

def test_chat_forwards_chain_id(client):
    """Non-default chain_id is forwarded to advisor.chat()."""
    import api as api_module
    import hashlib

    advisor = api_module.container.advisor
    client.post(
        "/api/agent/chat",
        json={"message": "Check 0xdead", "user_id": "u1", "chain_id": 1},
    )
    bound_id = hashlib.sha256("testclient:u1".encode()).hexdigest()[:24]
    advisor.chat.assert_awaited_once_with(bound_id, "Check 0xdead", chain_id=1)


def test_chat_invalid_chain_id_zero(client):
    """chain_id=0 rejected before the advisor is called."""
    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1", "chain_id": 0})
    assert resp.status_code == 400


def test_chat_invalid_chain_id_negative(client):
    """Negative chain_id rejected."""
    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1", "chain_id": -5})
    assert resp.status_code == 400


def test_chat_response_includes_scan_data(client):
    """When advisor returns scan_data, it passes through in the HTTP response."""
    import api as api_module
    api_module.container.advisor.chat = AsyncMock(return_value={
        "text": "This is dangerous.",
        "scan_data": {"address": "0xdead", "risk_level": "HIGH", "risk_score": 90,
                      "status": "ok", "coverage": {"honeypot": 1}},
    })
    resp = client.post("/api/agent/chat", json={"message": "Check 0xdead", "user_id": "u1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"] == "This is dangerous."
    assert data["scan_data"]["risk_level"] == "HIGH"
    assert data["scan_data"]["address"] == "0xdead"


def test_chat_no_scan_data_when_absent(client):
    """When advisor returns no scan_data, the key is absent from the response."""
    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"})
    data = resp.json()
    assert "scan_data" not in data


def test_chat_backward_compat_string_return(client):
    """If advisor.chat returns a plain string (old behavior), API still works."""
    import api as api_module
    api_module.rate_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    api_module.chat_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    api_module.container.advisor.chat = AsyncMock(return_value="Plain string response")
    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"] == "Plain string response"
    assert "scan_data" not in data


def test_chat_advisor_exception_returns_500(client):
    """If advisor.chat() raises, API returns 500."""
    import api as api_module
    api_module.rate_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    api_module.chat_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    api_module.container.advisor.chat = AsyncMock(side_effect=RuntimeError("DB crash"))
    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"})
    assert resp.status_code == 500


def test_chat_no_advisor_returns_503(client):
    """If container is None, returns 503."""
    import api as api_module
    api_module.rate_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    api_module.chat_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    saved = api_module.container
    api_module.container = None
    try:
        resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"})
        assert resp.status_code == 503
    finally:
        api_module.container = saved


INSTALL_ID = "3f2c9a1e-8b7d-4c6e-9f10-2a4b6c8d0e12"


def test_chat_binds_history_to_the_install_id_not_the_ip(client):
    """With X-Install-Id the history key no longer depends on the client IP or the proxy setup."""
    import api as api_module
    import asyncio
    import hashlib
    from types import SimpleNamespace

    advisor = api_module.container.advisor
    client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"}, headers={"X-Install-Id": INSTALL_ID})
    bound_id = hashlib.sha256(f"install:{INSTALL_ID}:u1".encode()).hexdigest()[:24]
    advisor.chat.assert_awaited_once_with(bound_id, "hi", chain_id=56)

    request = SimpleNamespace(client=SimpleNamespace(host="203.0.113.9"), headers={"x-install-id": INSTALL_ID})
    asyncio.run(api_module.agent_chat(api_module.ChatRequest(message="hi", user_id="u1"), request))
    assert advisor.chat.await_args.args[0] == bound_id


@pytest.mark.parametrize("install_id", ["", "short", "x" * 129, "has space in it here", "10.0.0.1:user-ip-look"])
def test_chat_rejects_a_malformed_install_id(client, install_id):
    import api as api_module

    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"}, headers={"X-Install-Id": install_id})
    assert resp.status_code == 400
    api_module.container.advisor.chat.assert_not_called()
