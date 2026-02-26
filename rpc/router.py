"""RPC Proxy FastAPI router — mounted under /rpc/{chain_id}."""

import time
import logging
from collections import defaultdict
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

rpc_router = APIRouter()

# Rate limiter: 100 req/min per IP
_rpc_hits: dict = defaultdict(list)
_RPC_RPM = 100
_RPC_WINDOW = 60.0

# Allowlist of permitted JSON-RPC methods.
# Only safe, read-heavy methods + send/signTransaction (intercepted by firewall).
# All other methods are rejected to prevent proxy abuse.
_ALLOWED_METHODS = {
    "eth_chainId",
    "eth_blockNumber",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_getBalance",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_getTransactionCount",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getLogs",
    "eth_call",
    "eth_estimateGas",
    "eth_sendRawTransaction",
    "eth_sendTransaction",
    "net_version",
    "net_listening",
    "web3_clientVersion",
}


def _rpc_rate_check(client_ip: str) -> bool:
    """Check RPC rate limit for a client IP."""
    now = time.monotonic()
    hits = _rpc_hits[client_ip]
    cutoff = now - _RPC_WINDOW
    while hits and hits[0] < cutoff:
        hits.pop(0)
    if len(hits) >= _RPC_RPM:
        return False
    hits.append(now)
    return True


@rpc_router.post("/rpc/{chain_id}")
async def rpc_endpoint(chain_id: int, request: Request):
    """JSON-RPC proxy endpoint.

    Users add this URL as a custom RPC in their wallet:
      https://api.example.com/rpc/56   (BSC)
      https://api.example.com/rpc/1    (Ethereum)
      https://api.example.com/rpc/8453 (Base)
    """
    # Rate limiting
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[-1].strip()
    else:
        client_ip = request.client.host

    if not _rpc_rate_check(client_ip):
        return JSONResponse(
            status_code=429,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32005, "message": "Rate limit exceeded"},
            },
        )

    # Get the RPC proxy from the app state
    proxy = getattr(request.app.state, "rpc_proxy", None)
    if not proxy:
        return JSONResponse(
            status_code=503,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32000, "message": "RPC proxy not available"},
            },
        )

    # Validate chain_id
    supported = proxy._container.web3_client.get_supported_chain_ids()
    if chain_id not in supported:
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32000, "message": f"Unsupported chain_id: {chain_id}. Supported: {supported}"},
            },
        )

    # Parse JSON-RPC body
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error: invalid JSON"},
            },
        )

    # Handle batch requests
    if isinstance(body, list):
        if not body:
            return JSONResponse(
                content={"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Empty batch"}},
            )
        if len(body) > 20:
            return JSONResponse(
                status_code=400,
                content={"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Batch size exceeds maximum of 20"}},
            )
        # Validate all methods in batch
        for item in body:
            if isinstance(item, dict) and item.get("method") not in _ALLOWED_METHODS:
                return JSONResponse(
                    status_code=400,
                    content={"jsonrpc": "2.0", "id": item.get("id"), "error": {
                        "code": -32601, "message": f"Method not allowed: {item.get('method')}",
                    }},
                )
        results = await proxy.handle_batch(chain_id, body)
        return JSONResponse(content=results)

    # Single request
    if not isinstance(body, dict):
        return JSONResponse(
            content={"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}},
        )

    # Validate method against allowlist
    method = body.get("method", "")
    if method not in _ALLOWED_METHODS:
        return JSONResponse(
            status_code=400,
            content={"jsonrpc": "2.0", "id": body.get("id"), "error": {
                "code": -32601, "message": f"Method not allowed: {method}",
            }},
        )

    result = await proxy.handle_request(chain_id, body)
    return JSONResponse(content=result)
