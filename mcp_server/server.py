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
from fastapi.responses import StreamingResponse

from mcp_server.tools import TOOL_DEFINITIONS, execute_tool
from mcp_server.resources import RESOURCE_DEFINITIONS, read_resource
from mcp_server.prompts import PROMPT_DEFINITIONS, get_prompt

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_SSE_CONNECTIONS = 50
HEARTBEAT_INTERVAL = 30  # seconds
IDLE_TIMEOUT = 300  # 5 minutes

SERVER_INFO = {
    "name": "shieldbot-mcp",
    "version": "3.1.0",
}

SERVER_CAPABILITIES = {
    "tools": {},
    "resources": {"subscribe": True},
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
        # session_id -> {queue, created_at, last_activity}
        self._connections: Dict[str, Dict] = {}

    @property
    def count(self) -> int:
        return len(self._connections)

    def is_full(self) -> bool:
        return self.count >= self._max

    def create(self) -> tuple:
        """Create a new SSE session. Returns (session_id, queue)."""
        session_id = str(uuid.uuid4())
        queue: asyncio.Queue = asyncio.Queue()
        self._connections[session_id] = {
            "queue": queue,
            "created_at": time.time(),
            "last_activity": time.time(),
        }
        logger.info("SSE session created: %s (total: %d)", session_id, self.count)
        return session_id, queue

    def get_queue(self, session_id: str) -> Optional[asyncio.Queue]:
        conn = self._connections.get(session_id)
        if conn:
            return conn["queue"]
        return None

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

async def _handle_initialize(container, params: Dict) -> Dict:
    return {
        "protocolVersion": "2024-11-05",
        "serverInfo": SERVER_INFO,
        "capabilities": SERVER_CAPABILITIES,
    }


async def _handle_tools_list(container, params: Dict) -> Dict:
    return {"tools": TOOL_DEFINITIONS}


async def _handle_tools_call(container, params: Dict) -> Dict:
    tool_name = params.get("name")
    arguments = params.get("arguments", {})

    if not tool_name:
        raise ValueError("Missing 'name' in tools/call params")

    try:
        result = await execute_tool(container, tool_name, arguments)
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


async def _handle_resources_list(container, params: Dict) -> Dict:
    return {"resources": RESOURCE_DEFINITIONS}


async def _handle_resources_read(container, params: Dict) -> Dict:
    uri = params.get("uri")
    if not uri:
        raise ValueError("Missing 'uri' in resources/read params")

    result = await read_resource(container, uri)
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


async def _handle_prompts_list(container, params: Dict) -> Dict:
    return {"prompts": PROMPT_DEFINITIONS}


async def _handle_prompts_get(container, params: Dict) -> Dict:
    name = params.get("name")
    arguments = params.get("arguments", {})

    if not name:
        raise ValueError("Missing 'name' in prompts/get params")

    result = get_prompt(name, arguments)
    if result is None:
        raise ValueError(f"Prompt not found: {name}")

    return result


# Method dispatch table
_METHODS = {
    "initialize": _handle_initialize,
    "tools/list": _handle_tools_list,
    "tools/call": _handle_tools_call,
    "resources/list": _handle_resources_list,
    "resources/read": _handle_resources_read,
    "prompts/list": _handle_prompts_list,
    "prompts/get": _handle_prompts_get,
}


# ---------------------------------------------------------------------------
# Process a single JSON-RPC request
# ---------------------------------------------------------------------------

async def process_jsonrpc(container, body: Dict) -> Dict:
    """Process a JSON-RPC 2.0 request and return the response dict."""
    jsonrpc_version = body.get("jsonrpc")
    request_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})

    if jsonrpc_version != "2.0":
        return _jsonrpc_error(request_id, INVALID_REQUEST, "Expected jsonrpc 2.0")

    if not method:
        return _jsonrpc_error(request_id, INVALID_REQUEST, "Missing method")

    handler = _METHODS.get(method)
    if handler is None:
        return _jsonrpc_error(request_id, METHOD_NOT_FOUND, f"Method not found: {method}")

    try:
        result = await handler(container, params)
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

    @router.get("/sse")
    async def sse_stream(request: Request):
        """SSE event stream endpoint. Sends server->client events."""
        await _require_api_key(request)

        if sse_manager.is_full():
            raise HTTPException(
                status_code=503,
                detail=f"Max SSE connections reached ({MAX_SSE_CONNECTIONS})",
            )

        session_id, queue = sse_manager.create()

        async def event_generator():
            try:
                # Send initial endpoint event so client knows where to POST
                endpoint_event = f"event: endpoint\ndata: /mcp/messages?session_id={session_id}\n\n"
                yield endpoint_event

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
        await _require_api_key(request)

        session_id = request.query_params.get("session_id")

        try:
            body = await request.json()
        except Exception:
            error_resp = _jsonrpc_error(None, PARSE_ERROR, "Invalid JSON")
            # If session exists, push error to SSE stream too
            if session_id:
                queue = sse_manager.get_queue(session_id)
                if queue:
                    await queue.put(error_resp)
            return error_resp

        # Process the JSON-RPC request
        response = await process_jsonrpc(container, body)

        # If a session is active, push the response to the SSE stream
        if session_id:
            queue = sse_manager.get_queue(session_id)
            if queue:
                sse_manager.touch(session_id)
                await queue.put(response)

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
