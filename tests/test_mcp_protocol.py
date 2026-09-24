"""MCP protocol conformance (2024-11-05, HTTP+SSE): handshake, ping and notifications."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import httpx
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
def app(container, sessions):
    app = FastAPI()
    app.include_router(server.create_mcp_router(container), prefix="/mcp")
    return app


@pytest.fixture
def client(app):
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


@pytest.mark.asyncio
async def test_a_request_cancelled_while_it_runs_gets_no_response(app, container, sessions):
    started, release = asyncio.Event(), asyncio.Event()

    async def slow_scan(ctx):
        started.set()
        await release.wait()
        return []

    container.registry.run_all = AsyncMock(side_effect=slow_scan)
    container.risk_engine.compute_from_results.return_value = {"rug_probability": 0, "status": "ok", "coverage": {}}
    session_id, queue = sessions[0].create("k1")
    url = f"/mcp/messages?session_id={session_id}"
    call = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "scan_contract", "arguments": {"address": "0x" + "a" * 40, "chain_id": 56}},
    }

    def cancel(request_id):
        return {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": request_id}}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as http:
        running = asyncio.create_task(http.post(url, json=call, headers=AUTH_HEADERS))
        await asyncio.wait_for(started.wait(), 5)
        assert (await http.post(url, json=cancel(9), headers=AUTH_HEADERS)).status_code == 202
        release.set()
        response = await asyncio.wait_for(running, 5)

        assert response.status_code == 202
        assert response.content == b""
        assert queue.empty()

        # Cancelling an id that is not running changes nothing, and a finished id is not remembered.
        assert (await http.post(url, json=cancel(10), headers=AUTH_HEADERS)).status_code == 202
        for request_id in (9, 10):
            ping = {"jsonrpc": "2.0", "id": request_id, "method": "ping"}
            assert (await http.post(url, json=ping, headers=AUTH_HEADERS)).status_code == 200
            assert queue.get_nowait() == {"jsonrpc": "2.0", "id": request_id, "result": {}}
    assert sessions[0].get(session_id)["in_flight"] == {}


@pytest.mark.asyncio
async def test_a_client_session_over_the_sse_stream(app, container, sessions):
    """GET /sse and POST /messages together: every response arrives on the stream, in order."""
    container.risk_engine.compute_from_results.return_value = {
        "rug_probability": 12,
        "risk_level": "MEDIUM",
        "status": "unknown",
        "coverage": {"honeypot": 0},
        "coverage_reasons": {"honeypot": "Provider unavailable"},
    }
    sent = asyncio.Queue()
    disconnected = asyncio.Event()
    requested = False

    async def receive():
        nonlocal requested
        if not requested:
            requested = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await disconnected.wait()
        return {"type": "http.disconnect"}

    # The stream never ends on its own, so it is driven as a raw ASGI call rather than a test client.
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/mcp/sse",
        "raw_path": b"/mcp/sse",
        "root_path": "",
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 50000),
        "headers": [(b"host", b"testserver"), (b"x-api-key", AUTH_HEADERS["X-API-Key"].encode())],
    }
    stream = asyncio.create_task(app(scope, receive, sent.put))

    async def next_event():
        while True:
            message = await asyncio.wait_for(sent.get(), 5)
            if message["type"] == "http.response.body" and message.get("body"):
                return message["body"].decode()

    async def next_message():
        event = await next_event()
        assert event.startswith("event: message\ndata: ")
        return json.loads(event.split("data: ", 1)[1])

    start = await asyncio.wait_for(sent.get(), 5)
    assert start["type"] == "http.response.start"
    assert start["status"] == 200
    endpoint = await next_event()
    assert endpoint.startswith("event: endpoint\ndata: /mcp/messages?session_id=")
    url = endpoint.split("data: ", 1)[1].strip()

    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "scan_contract", "arguments": {"address": "0x" + "a" * 40, "chain_id": 56}},
    }
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as http:
        assert (await http.post(url, json=INITIALIZE, headers=AUTH_HEADERS)).status_code == 200
        initialized = await next_message()
        assert initialized["id"] == 0
        assert initialized["result"]["protocolVersion"] == "2024-11-05"

        notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        assert (await http.post(url, json=notification, headers=AUTH_HEADERS)).status_code == 202

        listing = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        assert (await http.post(url, json=listing, headers=AUTH_HEADERS)).status_code == 200
        tools = await next_message()
        assert tools["id"] == 1
        assert len(tools["result"]["tools"]) == 9

        assert (await http.post(url, json=call, headers=AUTH_HEADERS)).status_code == 200
        scanned = await next_message()
        assert scanned["id"] == 2
        result = json.loads(scanned["result"]["content"][0]["text"])
        assert result["status"] == "unknown"
        assert result["verdict"] == "UNKNOWN"
        assert result["coverage_reasons"] == {"honeypot": "Provider unavailable"}

    disconnected.set()
    await asyncio.wait_for(stream, 5)
    assert sessions[0].count == 0


def test_a_session_whose_stream_is_not_read_is_dropped(client, sessions):
    manager = sessions[0]
    session_id, queue = manager.create("k1")
    for _ in range(server.MAX_QUEUED_MESSAGES):
        queue.put_nowait({"jsonrpc": "2.0", "id": 0, "result": {}})
    url = f"/mcp/messages?session_id={session_id}"

    response = client.post(url, json=PING, headers=AUTH_HEADERS)

    assert response.status_code == 200
    assert response.json() == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert queue.qsize() == server.MAX_QUEUED_MESSAGES
    assert manager.get(session_id) is None
    assert client.post(url, json=PING, headers=AUTH_HEADERS).status_code == 404


def test_a_session_quiet_for_ten_minutes_is_not_idle():
    manager = server.SSEConnectionManager()
    session_id, _ = manager.create("k1")
    manager.get(session_id)["last_activity"] -= 600

    assert not manager.is_idle(session_id)
