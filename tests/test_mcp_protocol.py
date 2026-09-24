"""MCP protocol conformance (2024-11-05, HTTP+SSE): handshake, ping and notifications."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import mcp_server.server as server
from utils.web3_client import Web3Client

AUTH_HEADERS = {"X-API-Key": "sb_testkey123456789012345678901234"}
PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 0,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {"roots": {"listChanged": True}},
        "clientInfo": {"name": "client", "version": "1.0.0"},
    },
}


@pytest.fixture
def container():
    c = MagicMock()
    c.web3_client = Web3Client.__new__(Web3Client)
    c.web3_client._adapters = {56: MagicMock(), 4663: MagicMock()}
    c.auth_manager.validate_key = AsyncMock(return_value={"key_id": "k1"})
    c.registry.run_all = AsyncMock(return_value=[])
    return c


@pytest.fixture
def sessions(monkeypatch):
    """The SSE connection managers created by create_mcp_router."""
    managers = []

    class RecordingManager(server.SSEConnectionManager):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            managers.append(self)

    monkeypatch.setattr(server, "SSEConnectionManager", RecordingManager)
    return managers


@pytest.fixture
def client(container, sessions):
    app = FastAPI()
    app.include_router(server.create_mcp_router(container), prefix="/mcp")
    return TestClient(app)


@pytest.mark.asyncio
async def test_initialize_answers_with_the_one_supported_version(container):
    response = await server.process_jsonrpc(container, INITIALIZE)

    assert response == {
        "jsonrpc": "2.0",
        "id": 0,
        "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "shieldbot-mcp", "version": "3.1.0"},
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
        },
    }


def test_every_declared_capability_is_served():
    # Declaring resources.subscribe obliges the server to answer resources/subscribe.
    assert "subscribe" not in server.SERVER_CAPABILITIES["resources"]
    for capability in server.SERVER_CAPABILITIES:
        assert f"{capability}/list" in server._METHODS


@pytest.mark.asyncio
@pytest.mark.parametrize("request_id", ["123", 0, 7])
async def test_ping_returns_an_empty_result(container, request_id):
    response = await server.process_jsonrpc(
        container, {"jsonrpc": "2.0", "id": request_id, "method": "ping"}
    )

    assert response == {"jsonrpc": "2.0", "id": request_id, "result": {}}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 3, "reason": "User cancelled"},
        },
        {"jsonrpc": "2.0", "method": "notifications/roots/list_changed"},
        {"jsonrpc": "2.0", "method": "no/such/method"},
        {"jsonrpc": "1.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0"},
    ],
)
async def test_a_message_without_an_id_gets_no_response(container, message):
    assert await server.process_jsonrpc(container, message) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [[{"jsonrpc": "2.0", "id": 1, "method": "ping"}], [], "id", 1])
async def test_a_body_that_is_not_one_request_object_is_an_invalid_request(container, body):
    response = await server.process_jsonrpc(container, body)

    assert response["id"] is None
    assert response["error"]["code"] == -32600


@pytest.mark.asyncio
@pytest.mark.parametrize("method", [5, "", [], {}, None])
async def test_a_method_that_is_not_a_string_is_an_invalid_request(container, method):
    response = await server.process_jsonrpc(container, {"jsonrpc": "2.0", "id": 4, "method": method})

    assert response["id"] == 4
    assert response["error"]["code"] == -32600


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [
        {"method": "tools/list", "params": None},
        {"method": "tools/list", "params": []},
        {"method": "ping", "params": "x"},
        {"method": "tools/call", "params": {"name": 5}},
        {"method": "tools/call", "params": {"name": {"a": 1}}},
        {"method": "tools/call", "params": {"name": "scan_contract", "arguments": "x"}},
        {"method": "resources/read", "params": {"uri": 5}},
        {"method": "prompts/get", "params": {"name": ["x"]}},
        {"method": "prompts/get", "params": {"name": "security-analysis", "arguments": "x"}},
    ],
)
async def test_malformed_params_are_invalid_params_without_a_traceback(container, message, caplog):
    response = await server.process_jsonrpc(container, {"jsonrpc": "2.0", "id": 8, **message})

    assert response["id"] == 8
    assert response["error"]["code"] == -32602
    assert not [record for record in caplog.records if record.exc_info]


@pytest.mark.asyncio
async def test_a_tool_call_without_an_id_runs_nothing(container):
    message = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_contract",
            "arguments": {"address": "0x" + "a" * 40, "chain_id": 56},
        },
    }

    assert await server.process_jsonrpc(container, message) is None
    container.registry.run_all.assert_not_awaited()


def test_a_notification_is_accepted_with_no_body_and_nothing_on_the_stream(client, sessions):
    session_id, queue = sessions[0].create("k1")
    url = f"/mcp/messages?session_id={session_id}"

    response = client.post(
        url, json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=AUTH_HEADERS
    )

    assert response.status_code == 202
    assert response.content == b""
    assert queue.empty()

    client.post(url, json={"jsonrpc": "2.0", "id": 5, "method": "ping"}, headers=AUTH_HEADERS)
    assert queue.get_nowait() == {"jsonrpc": "2.0", "id": 5, "result": {}}
    assert queue.empty()


def test_a_standard_client_handshake_completes(client, sessions):
    session_id, queue = sessions[0].create("k1")
    url = f"/mcp/messages?session_id={session_id}"

    def send(message):
        return client.post(url, json=message, headers=AUTH_HEADERS)

    assert send(INITIALIZE).status_code == 200
    assert send({"jsonrpc": "2.0", "method": "notifications/initialized"}).status_code == 202
    for request_id, method in enumerate(
        ["tools/list", "resources/list", "prompts/list", "ping"], 1
    ):
        assert send({"jsonrpc": "2.0", "id": request_id, "method": method}).status_code == 200

    streamed = [queue.get_nowait() for _ in range(queue.qsize())]
    assert [message["id"] for message in streamed] == [0, 1, 2, 3, 4]
    assert all("result" in message for message in streamed)
    assert streamed[0]["result"]["protocolVersion"] == "2024-11-05"


def test_a_post_without_a_session_is_answered_in_the_body(client):
    response = client.post("/mcp/messages", json=PING, headers=AUTH_HEADERS)

    assert response.status_code == 200
    assert response.json() == {"jsonrpc": "2.0", "id": 1, "result": {}}


def test_a_post_to_an_unknown_or_closed_session_is_404(client, sessions):
    session_id, _ = sessions[0].create("k1")
    sessions[0].remove(session_id)

    for unknown in ("not-a-session", session_id, ""):
        response = client.post(
            f"/mcp/messages?session_id={unknown}", json=PING, headers=AUTH_HEADERS
        )
        assert response.status_code == 404


def test_a_session_only_accepts_the_key_that_opened_it(client, sessions):
    session_id, queue = sessions[0].create("another-key")

    response = client.post(f"/mcp/messages?session_id={session_id}", json=PING, headers=AUTH_HEADERS)

    assert response.status_code == 403
    assert queue.empty()


def test_one_key_can_hold_at_most_five_streams(client, sessions):
    manager = sessions[0]
    opened = [manager.create("k1")[0] for _ in range(server.MAX_SSE_CONNECTIONS_PER_KEY)]
    manager.create("another-key")

    assert client.get("/mcp/sse?handshake_only=1", headers=AUTH_HEADERS).status_code == 429

    manager.remove(opened[0])
    assert client.get("/mcp/sse?handshake_only=1", headers=AUTH_HEADERS).status_code == 200


def test_idle_sessions_are_swept_before_the_capacity_check(client, sessions):
    # A stream cancelled before its first event never runs its cleanup, so its session lingers.
    manager = sessions[0]
    for index in range(server.MAX_SSE_CONNECTIONS):
        session_id, _ = manager.create(f"key-{index}")
        manager.get(session_id)["last_activity"] -= server.IDLE_TIMEOUT + 1
    assert manager.is_full()

    assert client.get("/mcp/sse?handshake_only=1", headers=AUTH_HEADERS).status_code == 200
    assert manager.count == 0


def test_a_session_quiet_for_ten_minutes_is_not_idle():
    manager = server.SSEConnectionManager()
    session_id, _ = manager.create("k1")
    manager.get(session_id)["last_activity"] -= 600

    assert not manager.is_idle(session_id)
