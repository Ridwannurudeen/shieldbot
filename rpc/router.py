"""RPC Proxy FastAPI router — mounted under /rpc/{chain_id}."""

import logging
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core.rate_limit import RateLimiter
from utils.web3_client import UnsupportedChainError

logger = logging.getLogger(__name__)

rpc_router = APIRouter()

# Rate limiter: 100 req/min per IP. A burst equal to the per-minute limit sets no separate burst limit.
rpc_limiter = RateLimiter(requests_per_minute=100, burst=100)

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


def _get_client_ip(request: Request, trusted_proxies: set) -> str:
    """Resolve client IP, trusting X-Forwarded-For only from known proxies."""
    client_ip = request.client.host if request.client else ""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and client_ip in trusted_proxies:
        chain = [part.strip() for part in forwarded.split(",") if part.strip()]
        for candidate in reversed(chain):
            if candidate not in trusted_proxies:
                return candidate
        if chain:
            return chain[0]
    return client_ip


@rpc_router.post("/rpc/{chain_id}")
async def rpc_endpoint(chain_id: int, request: Request):
    """JSON-RPC proxy endpoint.

    Users add this URL as a custom RPC in their wallet:
      https://api.example.com/rpc/56   (BSC)
      https://api.example.com/rpc/1    (Ethereum)
      https://api.example.com/rpc/8453 (Base)
    """
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

    try:
        proxy._container.web3_client.validate_chain_id(chain_id)
    except UnsupportedChainError as exc:
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32000, "message": str(exc)},
            },
        )

    # Rate limiting (API key preferred when provided)
    api_key = request.headers.get("x-api-key")
    if proxy and api_key and proxy._container and proxy._container.auth_manager:
        # Mounted in api.py, the rate-limit middleware has already validated and counted this key.
        if getattr(request.state, "api_key_info", None) is None:
            from core.auth import rate_limit_headers

            key_info = await proxy._container.auth_manager.validate_key(api_key)
            if not key_info:
                return JSONResponse(
                    status_code=401,
                    content={
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32001, "message": "Invalid API key"},
                    },
                )
            if not await proxy._container.auth_manager.check_rate_limit(key_info):
                return JSONResponse(
                    status_code=429,
                    content={
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32005, "message": "API key rate limit exceeded"},
                    },
                    headers=rate_limit_headers(key_info),
                )
            try:
                await proxy._container.auth_manager.record_usage(key_info["key_id"], f"/rpc/{chain_id}")
            except Exception as e:
                logger.error("API usage record failed: %s", type(e).__name__)
    else:
        trusted = set(proxy._container.settings.trusted_proxies) if proxy else set()
        client_ip = _get_client_ip(request, trusted)
        if not await rpc_limiter.is_allowed(client_ip):
            return JSONResponse(
                status_code=429,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32005, "message": "Rate limit exceeded"},
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
