"""MCP protocol conformance (2024-11-05, HTTP+SSE): handshake, ping and notifications."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import mcp_server.server as server
from utils.web3_client import Web3Client

AUTH_HEADERS = {"X-API-Key": "sb_testkey123456789012345678901234"}
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
    session_id, queue = sessions[0].create()
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
    session_id, queue = sessions[0].create()
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
