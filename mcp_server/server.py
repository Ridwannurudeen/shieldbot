"""MCP (Model Context Protocol) server with SSE transport.

Exposes ShieldBot's security tools, resources, and prompts over the
MCP JSON-RPC 2.0 protocol using Server-Sent Events for the server->client
stream and a POST endpoint for client->server messages.

Endpoints:
    GET  /sse      — SSE event stream (server -> client)
    POST /messages — JSON-RPC messages (client -> server)
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response, StreamingResponse

from mcp_server.tools import TOOL_DEFINITIONS, execute_tool
from mcp_server.resources import RESOURCE_DEFINITIONS, RESOURCE_TEMPLATE_DEFINITIONS, read_resource
from mcp_server.prompts import PROMPT_DEFINITIONS, get_prompt

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_SSE_CONNECTIONS = 50
MAX_SSE_CONNECTIONS_PER_KEY = 5
MAX_QUEUED_MESSAGES = 100  # per session; a client that stops reading its stream is dropped
HEARTBEAT_INTERVAL = 30  # seconds
IDLE_TIMEOUT = 1800  # 30 minutes; a dead peer is caught sooner by is_disconnected()

SERVER_INFO = {
    "name": "shieldbot-mcp",
    "version": "3.1.0",
}

SERVER_CAPABILITIES = {
    "tools": {},
    "resources": {},
    "prompts": {},
}

# JSON-RPC 2.0 error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


# ---------------------------------------------------------------------------
# SSE Connection Manager
# ---------------------------------------------------------------------------

class SSEConnectionManager:
    """Track active SSE connections with idle timeout."""

    def __init__(self, max_connections: int = MAX_SSE_CONNECTIONS):
        self._max = max_connections
        # session_id -> {queue, key_id, in_flight, created_at, last_activity}
        # in_flight maps each running request id to whether it has been cancelled.
        self._connections: Dict[str, Dict] = {}

    @property
    def count(self) -> int:
        return len(self._connections)

    def is_full(self) -> bool:
        return self.count >= self._max

    def count_for(self, key_id: str) -> int:
        return sum(1 for conn in self._connections.values() if conn["key_id"] == key_id)

    def create(self, key_id: str) -> tuple:
        """Create a new SSE session owned by an API key. Returns (session_id, queue)."""
        session_id = str(uuid.uuid4())
        queue: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUED_MESSAGES)
        self._connections[session_id] = {
            "queue": queue,
            "key_id": key_id,
            "in_flight": {},
            "created_at": time.time(),
            "last_activity": time.time(),
        }
        logger.info("SSE session created: %s (total: %d)", session_id, self.count)
        return session_id, queue

    def get(self, session_id: str) -> Optional[Dict]:
        return self._connections.get(session_id)

    def touch(self, session_id: str) -> None:
        """Update last activity timestamp."""
        conn = self._connections.get(session_id)
        if conn:
            conn["last_activity"] = time.time()

    def remove(self, session_id: str) -> None:
        if session_id in self._connections:
            del self._connections[session_id]
            logger.info("SSE session removed: %s (total: %d)", session_id, self.count)

    def is_idle(self, session_id: str) -> bool:
        """Check if a session has exceeded the idle timeout."""
        conn = self._connections.get(session_id)
        if not conn:
            return True
        return (time.time() - conn["last_activity"]) > IDLE_TIMEOUT

    def remove_idle(self) -> None:
        """Drop idle sessions, including one whose stream was cancelled before it started and never cleaned up."""
        for session_id in [sid for sid in self._connections if self.is_idle(sid)]:
            self.remove(session_id)


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _jsonrpc_result(request_id: Any, result: Any) -> Dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _jsonrpc_error(request_id: Any, code: int, message: str, data: Any = None) -> Dict:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


# ---------------------------------------------------------------------------
# Method handlers
# ---------------------------------------------------------------------------

async def _handle_initialize(container, params: Dict, key_info: Dict) -> Dict:
    return {
        "protocolVersion": "2024-11-05",
        "serverInfo": SERVER_INFO,
        "capabilities": SERVER_CAPABILITIES,
    }


async def _handle_ping(container, params: Dict, key_info: Dict) -> Dict:
    return {}


async def _handle_tools_list(container, params: Dict, key_info: Dict) -> Dict:
    return {"tools": TOOL_DEFINITIONS}


async def _handle_tools_call(container, params: Dict, key_info: Dict) -> Dict:
    tool_name = params.get("name")
    arguments = params.get("arguments", {})

    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("Missing 'name' in tools/call params")
    if arguments is not None and not isinstance(arguments, dict):
        raise ValueError("'arguments' in tools/call params must be an object")

    try:
        result = await execute_tool(container, tool_name, arguments, key_info)
        return {
            "content": [
                {"type": "text", "text": json.dumps(result)},
            ],
        }
    except ValueError as exc:
        return {
            "content": [
                {"type": "text", "text": json.dumps({"error": str(exc)})},
            ],
            "isError": True,
        }
    except Exception as exc:
        logger.exception("Tool execution error: %s", tool_name)
        return {
            "content": [
                {"type": "text", "text": json.dumps({"error": "Internal server error"})},
            ],
            "isError": True,
        }


async def _handle_resources_list(container, params: Dict, key_info: Dict) -> Dict:
    return {"resources": RESOURCE_DEFINITIONS}


async def _handle_resource_templates_list(container, params: Dict, key_info: Dict) -> Dict:
    return {"resourceTemplates": RESOURCE_TEMPLATE_DEFINITIONS}


async def _handle_resources_read(container, params: Dict, key_info: Dict) -> Dict:
    uri = params.get("uri")
    if not isinstance(uri, str) or not uri:
        raise ValueError("Missing 'uri' in resources/read params")

    result = await read_resource(container, uri, key_info)
    if result is None:
        raise ValueError(f"Resource not found: {uri}")

    return {
        "contents": [
            {
                "uri": result["uri"],
                "mimeType": result.get("mimeType", "application/json"),
                "text": json.dumps(result["text"]) if not isinstance(result["text"], str) else result["text"],
            },
        ],
    }


async def _handle_prompts_list(container, params: Dict, key_info: Dict) -> Dict:
    return {"prompts": PROMPT_DEFINITIONS}


async def _handle_prompts_get(container, params: Dict, key_info: Dict) -> Dict:
    name = params.get("name")
    arguments = params.get("arguments", {})

    if not isinstance(name, str) or not name:
        raise ValueError("Missing 'name' in prompts/get params")
    if arguments is not None and not isinstance(arguments, dict):
        raise ValueError("'arguments' in prompts/get params must be an object")

    result = get_prompt(name, arguments)
    if result is None:
        raise ValueError(f"Prompt not found: {name}")

    return result


# Method dispatch table
_METHODS = {
    "initialize": _handle_initialize,
    "ping": _handle_ping,
    "tools/list": _handle_tools_list,
    "tools/call": _handle_tools_call,
    "resources/list": _handle_resources_list,
    "resources/templates/list": _handle_resource_templates_list,
    "resources/read": _handle_resources_read,
    "prompts/list": _handle_prompts_list,
    "prompts/get": _handle_prompts_get,
}


# ---------------------------------------------------------------------------
# Process a single JSON-RPC request
# ---------------------------------------------------------------------------

async def process_jsonrpc(container, body: Dict, key_info: Dict) -> Optional[Dict]:
    """Process a JSON-RPC 2.0 message from the API key ``key_info`` and return the response dict, or None
    for a notification.

    A message without an id is a notification, which must never be answered. The ones MCP clients
    send need no action here: notifications/initialized carries no data, and the transport handles
    notifications/cancelled by dropping the cancelled request's response.
    """
    if not isinstance(body, dict):
        return _jsonrpc_error(None, INVALID_REQUEST, "Expected a JSON-RPC request object")
    if "id" not in body:
        return None

    jsonrpc_version = body.get("jsonrpc")
    request_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})

    # MCP ids are strings or integers; a bool would also collide with 0 and 1 in a session's in_flight.
    if type(request_id) not in (str, int):
        return _jsonrpc_error(None, INVALID_REQUEST, "id must be a string or an integer")

    if jsonrpc_version != "2.0":
        return _jsonrpc_error(request_id, INVALID_REQUEST, "Expected jsonrpc 2.0")

    if not isinstance(method, str) or not method:
        return _jsonrpc_error(request_id, INVALID_REQUEST, "Missing method")

    handler = _METHODS.get(method)
    if handler is None:
        return _jsonrpc_error(request_id, METHOD_NOT_FOUND, f"Method not found: {method}")

    if not isinstance(params, dict):
        return _jsonrpc_error(request_id, INVALID_PARAMS, "params must be an object")

    try:
        result = await handler(container, params, key_info)
        return _jsonrpc_result(request_id, result)
    except ValueError as exc:
        return _jsonrpc_error(request_id, INVALID_PARAMS, str(exc))
    except Exception as exc:
        logger.exception("JSON-RPC handler error for method %s", method)
        return _jsonrpc_error(request_id, INTERNAL_ERROR, "Internal server error")


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------

def create_mcp_router(container) -> APIRouter:
    """Create the MCP server router with SSE transport.

    Args:
        container: ServiceContainer with all ShieldBot services.

    Returns:
        FastAPI APIRouter to mount at /mcp.
    """
    router = APIRouter(tags=["MCP Server"])
    sse_manager = SSEConnectionManager(max_connections=MAX_SSE_CONNECTIONS)

    async def _require_api_key(request: Request) -> Dict:
        """Validate API key from X-API-Key header."""
        raw_key = request.headers.get("X-API-Key", "")
        if not raw_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        key_info = await container.auth_manager.validate_key(raw_key)
        if not key_info:
            raise HTTPException(status_code=403, detail="Invalid API key")
        return key_info

    def _push(session_id: str, session: Dict, message: Dict) -> None:
        """Queue a message for the session's stream, dropping a session whose client stopped reading it."""
        try:
            session["queue"].put_nowait(message)
        except asyncio.QueueFull:
            logger.warning("SSE session %s dropped: its stream is not being read", session_id)
            sse_manager.remove(session_id)

    @router.get("/sse")
    async def sse_stream(request: Request):
        """SSE event stream endpoint. Sends server->client events."""
        key_info = await _require_api_key(request)
        handshake_only = request.query_params.get("handshake_only") in {"1", "true", "yes"}

        sse_manager.remove_idle()
        if sse_manager.count_for(key_info["key_id"]) >= MAX_SSE_CONNECTIONS_PER_KEY:
            raise HTTPException(
                status_code=429,
                detail=f"Max SSE connections for this API key reached ({MAX_SSE_CONNECTIONS_PER_KEY})",
            )
        if sse_manager.is_full():
            raise HTTPException(
                status_code=503,
                detail=f"Max SSE connections reached ({MAX_SSE_CONNECTIONS})",
            )

        session_id, queue = sse_manager.create(key_info["key_id"])

        async def event_generator():
            try:
                # Send initial endpoint event so client knows where to POST
                endpoint_event = f"event: endpoint\ndata: /mcp/messages?session_id={session_id}\n\n"
                yield endpoint_event
                if handshake_only:
                    return

                while True:
                    # Check disconnect
                    if await request.is_disconnected():
                        break

                    # Check idle timeout
                    if sse_manager.is_idle(session_id):
                        logger.info("SSE session %s idle timeout", session_id)
                        break

                    try:
                        # Wait for message with heartbeat interval
                        msg = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_INTERVAL)
                        sse_manager.touch(session_id)
                        yield f"event: message\ndata: {json.dumps(msg)}\n\n"
                    except asyncio.TimeoutError:
                        # Send heartbeat
                        yield ": heartbeat\n\n"

            except asyncio.CancelledError:
                pass
            finally:
                sse_manager.remove(session_id)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @router.post("/messages")
    async def messages(request: Request):
        """JSON-RPC message endpoint. Receives client->server messages."""
        key_info = await _require_api_key(request)

        # Without a session_id the response is only returned in the POST body.
        session = None
        session_id = request.query_params.get("session_id")
        if session_id is not None:
            session = sse_manager.get(session_id)
            # Another key's session gets the same answer as a missing one, so its existence is not disclosed.
            if session is None or session["key_id"] != key_info["key_id"]:
                raise HTTPException(status_code=404, detail="Unknown or expired session")
            sse_manager.touch(session_id)

        try:
            body = await request.json()
        except Exception:
            error_resp = _jsonrpc_error(None, PARSE_ERROR, "Invalid JSON")
            # If session exists, push error to SSE stream too
            if session:
                _push(session_id, session, error_resp)
            return error_resp

        request_id = body.get("id") if isinstance(body, dict) else None
        tracked = session is not None and type(request_id) in (str, int)
        if tracked:
            session["in_flight"][request_id] = False
        try:
            response = await process_jsonrpc(container, body, key_info)
        finally:
            cancelled = tracked and session["in_flight"].pop(request_id, False)

        if response is None:
            if session is not None and body.get("method") == "notifications/cancelled":
                params = body.get("params")
                cancelled_id = params.get("requestId") if isinstance(params, dict) else None
                if type(cancelled_id) in (str, int) and cancelled_id in session["in_flight"]:
                    session["in_flight"][cancelled_id] = True
            return Response(status_code=202)
        # A cancelled request gets no response, as the MCP cancellation spec asks.
        if cancelled:
            return Response(status_code=202)

        # If a session is active, push the response to the SSE stream
        if session:
            _push(session_id, session, response)

        # Also return inline for clients that prefer request/response
        return response

    @router.get("/health")
    async def mcp_health():
        """Health check for the MCP server."""
        return {
            "status": "ok",
            "server": SERVER_INFO,
            "active_sessions": sse_manager.count,
            "max_sessions": MAX_SSE_CONNECTIONS,
        }

    return router
