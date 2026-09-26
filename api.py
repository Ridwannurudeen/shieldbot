"""
ShieldAI Firewall API
FastAPI backend for the Chrome extension transaction firewall
Runs alongside bot.py on the VPS
"""

import hmac
import json
import secrets
import time
import asyncio
import logging
import random
import re
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from functools import partial
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from redis.exceptions import RedisError
from typing import Optional, Dict, Any, List, Literal

from utils.calldata_decoder import CalldataDecoder, UNLIMITED_THRESHOLD, resolve_selector
from utils.chain_info import get_chain_name, get_native_symbol
from utils.web3_client import UnsupportedChainError
from utils.scam_db import BLACKLIST_RELOAD_SECONDS
from core.risk_engine import HONEYPOT_FLOOR, apply_local_match, database_matches, medium_matches, scam_match_floor
from services import rpc_guard
from services.counterparty_service import code_kind
from services.mempool_service import supports_pending_transactions
from core import verdicts
from core.auth import TIER_LIMITS, hash_key
from core.circuit_breaker import CLOSED, provider_breakers
from core.config import Settings
from core.container import ServiceContainer
from core.database import SCAN_EVIDENCE_RETENTION_DAYS, reporter_hash
from core.extension_formatter import format_extension_alert, is_scan_incomplete
from core.first_verdict import IN_PROGRESS, FirstVerdictProgress, build_first_verdict
from core.policy import PolicyMode
from core.rate_limit import RateLimiter, connect as connect_rate_limit_redis
from core.registry import FIRST_VERDICT_SECONDS
from core.scan_evidence import (
    analyzer_outcomes, build_scan_evidence, oldest_simulation_block, render_evidence_page, transaction_evidence,
    without_caller,
)
from core.unknown_ledger import unknown_ledger
from core.telegram_formatter import escape_markdown
from core.verdict_evidence import canonical_bytes, evidence_hash
from rpc.router import rpc_limiter, rpc_router
from rpc.proxy import RPCProxy

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


MAX_REQUEST_BODY_BYTES = 1_000_000
MAX_FIREWALL_DATA_CHARS = 200_000
MAX_TYPED_DATA_CHARS = 100_000
MAX_INJECTION_CONTENT_CHARS = 50_000
MAX_PHISHING_URL_CHARS = 2_048


# --- Rate Limiter ---

def _fire_and_forget(coro, label: str = "background"):
    """Schedule a coroutine as a fire-and-forget task with exception logging."""
    task = asyncio.create_task(coro)
    def _done_cb(t):
        if t.cancelled():
            return
        exc = t.exception()
        if exc:
            # An HTTPException names its status, so a refused request reads apart from a server error.
            failure = f"{type(exc).__name__} {exc.status_code}" if isinstance(exc, HTTPException) else type(exc).__name__
            logger.error("Fire-and-forget task '%s' failed: %s", label, failure)
    task.add_done_callback(_done_cb)
    return task


rate_limiter = RateLimiter(requests_per_minute=30, burst=10)
chat_limiter = RateLimiter(requests_per_minute=50, burst=10)


# Service container (initialized on startup)
container: Optional[ServiceContainer] = None

# BACKGROUND_WORKERS as the lifespan read it. With "external" the mempool monitor, the verdict drain, the
# hunter and the launch watch run in workers.py, and this process holds none of their in-memory state.
_background_workers = "api"
# With "external" the hunter's sweep, which reloads the scam blacklist, runs in workers.py, so the API
# rereads the blacklist itself in this task; None with "api".
_blacklist_reload_task: Optional[asyncio.Task] = None
_EXTERNAL_WORKERS_NOTE = (
    "Background work runs in the separate workers process (BACKGROUND_WORKERS=external), and this API "
    "process holds none of its in-memory state: the mempool counters and the launch watch's run state "
    "are null here, not zero. The Unknown ledger here counts this process's own lookups only."
)
_EXTERNAL_MEMPOOL_DETAIL = (
    "The mempool monitor runs in the separate workers process (BACKGROUND_WORKERS=external); "
    "this API process does not hold its alerts or counters."
)

# Convenience accessors — set after container startup
web3_client = None
ai_analyzer = None
tx_scanner = None
token_scanner = None
calldata_decoder = None
scam_db = None
dex_service = None
ethos_service = None
honeypot_service = None
contract_service = None
risk_engine = None
greenfield_service = None
tenderly_simulator = None
advisor = None


def _bind_globals(c: ServiceContainer):
    """Bind module-level names to container services for backward compat."""
    global web3_client, ai_analyzer, tx_scanner, token_scanner, calldata_decoder
    global scam_db, dex_service, ethos_service, honeypot_service, contract_service
    global risk_engine, greenfield_service, tenderly_simulator
    global advisor
    web3_client = c.web3_client
    ai_analyzer = c.ai_analyzer
    tx_scanner = c.tx_scanner
    token_scanner = c.token_scanner
    calldata_decoder = c.calldata_decoder
    scam_db = c.scam_db
    dex_service = c.dex_service
    ethos_service = c.ethos_service
    honeypot_service = c.honeypot_service
    contract_service = c.contract_service
    risk_engine = c.risk_engine
    greenfield_service = c.greenfield_service
    tenderly_simulator = c.tenderly_simulator
    advisor = c.advisor


async def _blacklist_reload_loop():
    """Reload the persisted scam blacklist every BLACKLIST_RELOAD_SECONDS until cancelled, so entries
    the bot or workers.py write reach this process's scans. Startup has just loaded it, so each pass
    waits first."""
    while True:
        await asyncio.sleep(BLACKLIST_RELOAD_SECONDS)
        try:
            await container.scam_db.load_blacklist()
        except Exception as e:
            logger.error(
                "Blacklist reload failed: %s\n%s",
                type(e).__name__, "".join(traceback.format_tb(e.__traceback__)),
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global container, _background_workers, _blacklist_reload_task
    settings = Settings()
    container = ServiceContainer(settings)
    _bind_globals(container)
    await container.startup()
    rate_limit_redis = None
    if settings.rate_limit_backend == "redis":
        rate_limit_redis = connect_rate_limit_redis(settings.redis_url)
        # When Redis cannot answer, the general request limiter, the RPC proxy's and the API key
        # minute window count in this process's memory (logged), so an outage takes neither the scan
        # API nor users' wallets down. The abuse-sensitive limiters refuse (core/rate_limit.py).
        rate_limiter.use_redis(rate_limit_redis, "requests", fail_open=True)
        rpc_limiter.use_redis(rate_limit_redis, "rpc", fail_open=True)
        chat_limiter.use_redis(rate_limit_redis, "chat", fail_open=False)
        _report_limiter.use_redis(rate_limit_redis, "report", fail_open=False)
        _outcome_limiter.use_redis(rate_limit_redis, "outcome", fail_open=False)
        _signup_limiter.use_redis(rate_limit_redis, "signup", fail_open=False)
        _free_key_limiter.use_redis(rate_limit_redis, "free-key", fail_open=False)
        _watch_alerts_limiter.use_redis(rate_limit_redis, "watch-alerts", fail_open=False)
        container.auth_manager.use_redis(rate_limit_redis)
        try:
            await rate_limit_redis.ping()
        except RedisError as e:
            logger.warning(
                "Rate limits configured for Redis, but it did not answer PING (%s). Until it does, the "
                "general, RPC proxy and API key limits count in this process's memory and the chat, "
                "report, outcome, signup, free key and watch alert limits refuse every request",
                type(e).__name__,
            )
        else:
            logger.info("Rate limits kept in Redis")
    # The API serves phishing checks itself, so MetaMask's list refreshes here whichever process runs the work.
    container.phishing_service.start()
    _background_workers = settings.background_workers
    if _background_workers == "api":
        await container.start_mempool_monitor()
        container.verdict_publisher.start()
    else:
        logger.info("Background work runs in workers.py (BACKGROUND_WORKERS=external)")

    # Initialize RPC proxy if enabled
    if settings.rpc_proxy_enabled:
        rpc_proxy = RPCProxy(container)
        app.state.rpc_proxy = rpc_proxy
        logger.info("RPC Proxy enabled")

    # Mount agent firewall routes (V3)
    from agent.firewall import create_agent_firewall_router
    agent_router = create_agent_firewall_router(container)
    app.include_router(agent_router, prefix="/api/agent")

    # Mount MCP server routes (V3.1)
    from mcp_server.server import create_mcp_router
    mcp_router_v3 = create_mcp_router(container)
    app.include_router(mcp_router_v3, prefix="/mcp")

    # Mount threat graph routes (V3.5)
    from services.threat_graph_router import create_threat_graph_router
    graph_router = create_threat_graph_router(container)
    app.include_router(graph_router, prefix="/api/graph")

    # Mount reputation routes (V3.3)
    from services.reputation_router import create_reputation_router
    rep_router = create_reputation_router(container)
    app.include_router(rep_router, prefix="/api/reputation")

    # Mount guardian routes (V3.2)
    from services.guardian_router import create_guardian_router
    guard_router = create_guardian_router(container)
    app.include_router(guard_router, prefix="/api/guardian")

    if _background_workers == "api":
        await container.hunter.start()
        await container.launch_watch.start()
        _blacklist_reload_task = None
    else:
        _blacklist_reload_task = asyncio.create_task(_blacklist_reload_loop())

    logger.info("ShieldAI Firewall API started")
    yield
    if _blacklist_reload_task is not None:
        _blacklist_reload_task.cancel()
        try:
            await _blacklist_reload_task
        except asyncio.CancelledError:
            pass
    await container.launch_watch.stop()
    await container.hunter.stop()
    await container.phishing_service.stop()
    await container.verdict_publisher.stop()
    await container.shutdown()
    rpc_proxy = getattr(app.state, "rpc_proxy", None)
    if rpc_proxy:
        await rpc_proxy.close()
    if rate_limit_redis is not None:
        await rate_limit_redis.aclose()
    logger.info("ShieldAI Firewall API shutting down")


app = FastAPI(
    title="ShieldAI Firewall API",
    version="3.0.0",
    lifespan=lifespan,
)

# Mount RPC proxy router
app.include_router(rpc_router)

# CORS: configurable via CORS_ALLOW_ORIGINS env (comma-separated)
# Parsed at startup from Settings; fallback to localhost dev origins.
_boot_settings = Settings()
_cors_origins = _boot_settings.cors_origins
_allow_credentials = True
if "*" in (_boot_settings.cors_allow_origins or "") and not _boot_settings.cors_allow_all:
    logger.warning("CORS_ALLOW_ORIGINS includes '*' but CORS_ALLOW_ALL is false; using safe default origins.")
if len(_cors_origins) == 1 and _cors_origins[0] == "*":
    # Never allow credentials with wildcard origins.
    _allow_credentials = False
    logger.warning("CORS_ALLOW_ALL enabled; credentials disabled for safety.")

# Trusted proxy IPs (X-Forwarded-For only honored from these)
TRUSTED_PROXIES = set(_boot_settings.trusted_proxies)


def _get_trusted_proxies() -> set:
    settings = getattr(container, "settings", None) if container else None
    if settings:
        return set(getattr(settings, "trusted_proxies", []))
    return TRUSTED_PROXIES


def _get_client_ip(request: Request) -> str:
    """Resolve client IP, trusting X-Forwarded-For only from known proxies."""
    client_ip = request.client.host if request.client else ""
    forwarded = request.headers.get("x-forwarded-for")
    trusted = _get_trusted_proxies()
    if forwarded and client_ip in trusted:
        chain = [part.strip() for part in forwarded.split(",") if part.strip()]
        for candidate in reversed(chain):
            if candidate not in trusted:
                return candidate
        if chain:
            return chain[0]
    return client_ip
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Skip rate limiting for health and readiness checks
    if request.url.path in ("/", "/api/health", "/api/ready", "/webhook/uptime"):
        return await call_next(request)

    # Check for API key authentication
    api_key = request.headers.get("x-api-key")
    if api_key and container and container.auth_manager:
        from core.auth import rate_limit_headers, request_quota_scope

        # Routers that check the key again for this request reuse this check instead of counting twice.
        with request_quota_scope():
            key_info = await container.auth_manager.validate_key(api_key)
            if not key_info:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid API key"},
                )
            allowed = await container.auth_manager.check_rate_limit(key_info)
            headers = rate_limit_headers(key_info)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "API key rate limit exceeded"},
                    headers=headers,
                )
            # The daily quota count is already committed; a failed analytics record is only logged.
            try:
                await container.auth_manager.record_usage(key_info["key_id"], request.url.path)
            except Exception as e:
                logger.error("API usage record failed: %s", type(e).__name__)
            # Store key info for downstream use
            request.state.api_key_info = key_info
            response = await call_next(request)
        response.headers.update(headers)
        return response

    # Fallback: IP-based rate limiting (extension/unauthenticated)
    client_ip = _get_client_ip(request)

    # Probabilistic cleanup of stale rate-limiter entries (1% of requests)
    if random.random() < 0.01:
        rate_limiter.cleanup()

    if not await rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}")
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Please wait before trying again."},
        )

    return await call_next(request)


def _validate_chain_id(chain_id: int) -> int:
    if web3_client is None:
        raise HTTPException(status_code=503, detail="Chain registry not available")
    try:
        web3_client.validate_chain_id(chain_id)
    except UnsupportedChainError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return chain_id


def _validate_signing_chain(typed_data: Optional[Dict], chain_id: int):
    if not isinstance(typed_data, dict):
        return
    domain = typed_data.get("domain")
    if not isinstance(domain, dict) or "chainId" not in domain:
        return

    domain_chain = domain["chainId"]
    range_error = "typedData.domain.chainId must be between 1 and 10000000"
    if isinstance(domain_chain, str):
        is_hex = domain_chain.startswith(("0x", "0X"))
        if len(domain_chain) > (66 if is_hex else 78):
            raise HTTPException(status_code=400, detail=range_error)
        if re.fullmatch(r"[0-9]+|0[xX][0-9a-fA-F]+", domain_chain):
            domain_chain = int(domain_chain, 16 if is_hex else 10)
    if type(domain_chain) is not int:
        raise HTTPException(status_code=400, detail="Invalid typedData.domain.chainId")
    if not 1 <= domain_chain <= 10_000_000:
        raise HTTPException(status_code=400, detail=range_error)

    _validate_chain_id(domain_chain)
    if domain_chain != chain_id:
        raise HTTPException(
            status_code=400,
            detail=f"Signing domain chain ID {domain_chain} does not match request chain ID {chain_id}",
        )


def _refuse_json_constant(name: str):
    raise ValueError(f"{name} is not JSON")


@app.middleware("http")
async def request_validation_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})

    # Validate before authentication records usage or an endpoint accesses providers.
    chain_ids = [
        value for key, value in request.query_params.multi_items()
        if key in {"chainId", "chain_id"}
    ]
    request_path = request.url.path.rstrip("/")
    path_parts = request_path.strip("/").split("/")
    if len(path_parts) == 2 and path_parts[0] == "rpc":
        chain_ids.append(path_parts[1])
    allows_all_chain_watch = (
        request.method == "POST" and request_path == "/api/admin/watch/deployer"
        or request.method == "GET" and request_path == "/api/admin/watch/deployers"
        or request.method == "DELETE" and len(path_parts) == 5
        and path_parts[:4] == ["api", "admin", "watch", "deployer"]
    )
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    raw_body = await request.body()
    is_json = content_type == "application/json" or (
        content_type.startswith("application/") and content_type.endswith("+json")
    )
    is_webhook_form = request_path == "/webhook/uptime" and content_type in {
        "application/x-www-form-urlencoded", "multipart/form-data",
    }
    if raw_body and not is_json and not is_webhook_form:
        return JSONResponse(status_code=415, content={"detail": "Content-Type must be application/json"})
    body = None
    if raw_body and is_json:
        try:
            # NaN and Infinity are not JSON (RFC 8259). Refusing them keeps every body serialisable:
            # a validation error echoes its input, and the evidence document hashes typed data.
            body = json.loads(raw_body, parse_constant=_refuse_json_constant)
        except (ValueError, UnicodeDecodeError):
            return JSONResponse(status_code=400, content={"detail": "Invalid JSON body"})
        if isinstance(body, dict):
            body_chain_ids = [body[key] for key in ("chainId", "chain_id") if key in body]
            if request_path == "/api/agent/firewall":
                transaction = body.get("transaction")
                if isinstance(transaction, dict):
                    body_chain_ids.append(transaction.get("chain_id", 56))
            # MCP tool arguments are checked by the MCP router, which reports a bad chain as a tool
            # error on the client's SSE stream; an HTTP error here would never reach that stream.
            if any(type(chain_id) is not int for chain_id in body_chain_ids):
                return JSONResponse(status_code=400, content={"detail": "Invalid chain ID"})
            chain_ids.extend(body_chain_ids)

    for chain_id in chain_ids:
        if isinstance(chain_id, bool) or not isinstance(chain_id, (int, str)):
            return JSONResponse(status_code=400, content={"detail": "Invalid chain ID"})
        try:
            parsed_chain_id = int(chain_id)
        except (ValueError, TypeError, OverflowError):
            return JSONResponse(status_code=400, content={"detail": "Invalid chain ID"})
        if parsed_chain_id == 0 and allows_all_chain_watch:
            continue
        try:
            _validate_chain_id(parsed_chain_id)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    if request_path == "/api/firewall" and isinstance(body, dict):
        try:
            _validate_signing_chain(body.get("typedData"), body.get("chainId", 56))
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)


# --- Request / Response Models ---

class ChainRequest(BaseModel):
    model_config = ConfigDict(validate_default=True)

    @field_validator("chainId", "chain_id", check_fields=False)
    @classmethod
    def validate_chain(cls, value):
        return _validate_chain_id(value)


class FirewallRequest(ChainRequest):
    model_config = ConfigDict(populate_by_name=True)

    to: str = Field(..., max_length=64)
    sender: str = Field(..., alias="from", max_length=64)
    value: str = Field(default="0", max_length=80)
    data: str = Field(default="0x", max_length=MAX_FIREWALL_DATA_CHARS)
    chainId: int = Field(default=56, ge=1, le=10_000_000)
    typedData: Optional[Dict] = None
    signMethod: Optional[str] = Field(default=None, max_length=64)
    # An EIP-7702 (type 0x04) transaction's authorizations; the analysis reads each one's address.
    authorizationList: Optional[List[Dict]] = Field(default=None, max_length=16)

    @model_validator(mode="after")
    def validate_signing_chain(self):
        _validate_signing_chain(self.typedData, self.chainId)
        return self

    @field_validator("typedData")
    @classmethod
    def validate_typed_data_size(cls, v):
        if v is None:
            return v
        try:
            encoded = json.dumps(v, separators=(",", ":"), default=str, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("typedData must be JSON serializable") from exc
        if len(encoded) > MAX_TYPED_DATA_CHARS:
            raise ValueError("typedData is too large")
        return v


class ScanRequest(ChainRequest):
    address: str = Field(..., min_length=1, max_length=64)
    chainId: int = Field(default=56, ge=1, le=10_000_000)


class OutcomeRequest(ChainRequest):
    address: str = Field(..., min_length=1, max_length=64)
    chainId: int = Field(default=56, ge=1, le=10_000_000)
    risk_score_at_scan: Optional[float] = Field(default=None, ge=0, le=100)
    user_decision: Literal["proceed", "block", "ignore"]
    outcome: Optional[Literal["safe", "scam", "unknown"]] = None
    tx_hash: Optional[str] = Field(default=None, pattern=r"^0x[0-9a-fA-F]{64}$")


class CommunityReportRequest(ChainRequest):
    address: str = Field(..., min_length=1, max_length=64)
    chainId: int = Field(default=56, ge=1, le=10_000_000)
    report_type: str = Field(..., min_length=1, max_length=32)  # "false_positive", "false_negative", "scam"
    reason: Optional[str] = Field(default=None, max_length=1_000)


class ChatRequest(ChainRequest):
    message: str = Field(..., min_length=1, max_length=2000)
    user_id: str = Field(..., min_length=1, max_length=100)
    chain_id: int = Field(default=56, ge=1)


# A random per-install token from the side panel (its chatUserId UUID), sent as X-Install-Id.
_INSTALL_ID_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")


class ExplainRequest(BaseModel):
    scan_result: Dict[str, Any]

    @field_validator("scan_result")
    @classmethod
    def validate_scan_result(cls, v):
        # Only allow known fields to prevent prompt injection via extra keys
        allowed = {
            "risk_score", "risk_level", "classification", "danger_signals",
            "decoded_action", "flags", "critical_flags", "contract_verified",
            "honeypot", "sell_tax", "buy_tax", "is_honeypot",
            "status", "coverage", "coverage_reasons", "risk_display", "partial",
        }
        return {k: v[k] for k in v if k in allowed}


# Report rate limiter: 5 reports/min per IP
_report_limiter = RateLimiter(requests_per_minute=5, burst=3)

# Outcome rate limiter for callers without an API key: 10 outcomes/min per IP
_outcome_limiter = RateLimiter(requests_per_minute=10, burst=5)

# Beta-signup rate limiter: 3 signups/min per IP
_signup_limiter = RateLimiter(requests_per_minute=3, burst=2)

# Self-serve free key requests: 3/min per IP; the per-address limit is one unexpired link at a time
_free_key_limiter = RateLimiter(requests_per_minute=3, burst=2)

# Public watch alerts: 10 requests/min per IP
_watch_alerts_limiter = RateLimiter(requests_per_minute=10, burst=5)


# --- Endpoints ---

@app.get("/", include_in_schema=False)
async def landing_page():
    """Redirect to the marketing site; the API host does not serve the landing page."""
    return RedirectResponse("https://shieldbotsecurity.online/", status_code=301)


class BetaSignupRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)


@app.post("/api/beta-signup")
async def beta_signup(req: BetaSignupRequest, request: Request):
    """Collect beta signup emails."""
    # Rate limit per IP
    client_ip = _get_client_ip(request)
    if not await _signup_limiter.is_allowed(client_ip):
        return JSONResponse(status_code=429, content={"detail": "Too many requests. Please try again later."})

    import re
    email = req.email.strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        raise HTTPException(status_code=400, detail="Invalid email address")
    if not container or not container.db:
        raise HTTPException(status_code=503, detail="Database not available")
    is_new = await container.db.add_beta_signup(email)
    if is_new:
        if container.email_service and container.email_service.is_enabled():
            try:
                await container.email_service.send_beta_welcome(email)
            except Exception as e:
                logger.error(f"Beta welcome email failed: {type(e).__name__}")
        return {"message": "You're on the list! We'll be in touch."}
    return JSONResponse(
        status_code=409,
        content={"detail": "This email is already signed up."},
    )


@app.post("/webhook/uptime", include_in_schema=False)
async def uptime_webhook(request: Request, secret: str = ""):
    """UptimeRobot webhook — forwards status alerts to Telegram.

    Authentication: prefer X-Webhook-Secret header (WEBHOOK_SECRET).
    Optional legacy support for ?secret= query param if WEBHOOK_ALLOW_QUERY_SECRET=true.
    """
    import httpx
    expected_secret = container.settings.webhook_secret if container else ""
    header_secret = request.headers.get("x-webhook-secret", "")
    provided = ""
    used_query = False
    if header_secret:
        provided = header_secret
    elif secret:
        allow_query = container.settings.webhook_allow_query_secret if container else False
        if allow_query:
            provided = secret
            used_query = True
        else:
            raise HTTPException(status_code=403, detail="Forbidden")
    if not expected_secret or not provided or not hmac.compare_digest(provided, expected_secret):
        raise HTTPException(status_code=403, detail="Forbidden")
    if used_query:
        logger.warning("Deprecated webhook query secret used. Prefer X-Webhook-Secret header.")

    try:
        data = await request.form()
    except AssertionError:
        # python-multipart not installed; fall back to urlencoded parsing
        from urllib.parse import parse_qs
        raw = (await request.body()).decode(errors="ignore")
        parsed = parse_qs(raw, keep_blank_values=True)
        data = {k: v[0] for k, v in parsed.items()}
    except Exception:
        # Final fallback: attempt JSON
        try:
            data = await request.json()
        except Exception:
            data = {}
    alert_type   = data.get("alertType", "")
    monitor_name = data.get("monitorFriendlyName", "ShieldBot API")
    monitor_url  = data.get("monitorURL", "")
    details      = data.get("alertDetails", "")

    if alert_type == "1":
        msg = (
            f"🚨 *ShieldBot DOWN*\n{escape_markdown(monitor_name)} is unreachable.\n"
            f"URL: {escape_markdown(monitor_url)}\n{escape_markdown(details)}"
        )
    elif alert_type == "2":
        msg = (
            f"✅ *ShieldBot Recovered*\n{escape_markdown(monitor_name)} is back online.\n"
            f"URL: {escape_markdown(monitor_url)}"
        )
    else:
        return {"ok": True}

    bot_token = container.settings.telegram_bot_token if container else ""
    chat_id   = container.settings.telegram_alert_chat_id if container else ""
    if not bot_token or not chat_id:
        logger.warning("Telegram alert not sent — TELEGRAM_BOT_TOKEN or TELEGRAM_ALERT_CHAT_ID not configured")
        return {"ok": True}

    async with httpx.AsyncClient() as client:
        await client.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"},
        )
    return {"ok": True}


@app.get("/api/phishing")
async def check_phishing(url: str, request: Request):
    """Check if a URL is a known phishing site.

    Called by the Chrome extension content script on every page load.
    A host on MetaMask's open phishing list (refreshed hourly) is phishing with source "metamask";
    otherwise GoPlus decides. GoPlus verdicts are cached server-side for 1 hour per domain; when neither
    source flags the host and GoPlus gives no answer, the result is is_phishing null with a reason,
    held for 45 seconds per domain.
    No API key required — rate-limited by IP via the existing middleware.
    """
    if not container or not container.phishing_service:
        raise HTTPException(status_code=503, detail="Service unavailable")

    clean_url = url.strip()
    if len(clean_url) > MAX_PHISHING_URL_CHARS:
        raise HTTPException(status_code=400, detail="URL is too long")
    parsed = urlparse(clean_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="URL must be an absolute http(s) URL")

    result = await container.phishing_service.check_url(clean_url)
    return result


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "shieldai-firewall",
        "supported_chains": list(web3_client.get_supported_chain_ids()) if web3_client else [],
    }


# /api/ready answers from a result at most READY_CACHE_SECONDS old, so polling it cannot multiply
# requests to the database or the RPCs, and each of its checks is cut at READY_TIMEOUT_SECONDS.
READY_CACHE_SECONDS = 5
READY_TIMEOUT_SECONDS = 2
_ready_lock = asyncio.Lock()
_ready_cache = {"body": None, "expires_at": 0.0}
# The RPC probes' own threads, so a hung RPC never holds a worker of the default pool that scans
# use. Eight: the seven chains probed at once, and one more for a probe still hanging from the
# previous check (an RPC request times out after 10 s, twice the cache period).
_READY_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="readiness")


async def _database_answers() -> bool:
    cursor = await container.db._db.execute("SELECT 1")
    return await cursor.fetchone() == (1,)


async def _any_rpc_answers() -> bool:
    """Ask every chain's RPC for eth_blockNumber at once; True on the first answer.

    Robinhood Chain is left out: its RPC is paced by the shared RPC guard, which a probe must not
    bypass. The probes run on _READY_EXECUTOR. Once one answers, or the check is cut at its
    timeout, the probes still queued for a thread are cancelled; one already sending finishes at
    the RPC request timeout. Readiness is not a provider lookup, so the Unknown ledger does not
    count it.
    """
    from services.launch_discovery import CHAIN_ID as ROBINHOOD_CHAIN_ID

    loop = asyncio.get_running_loop()
    web3_client = container.web3_client
    probes = {
        loop.run_in_executor(_READY_EXECUTOR, web3_client.get_web3(chain_id).eth.get_block_number): chain_id
        for chain_id in web3_client.get_supported_chain_ids()
        if chain_id != ROBINHOOD_CHAIN_ID
    }
    try:
        pending = set(probes)
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for probe in done:
                if probe.exception() is not None:
                    logger.warning(
                        "Readiness: chain %s RPC did not answer: %s",
                        probes[probe], type(probe.exception()).__name__,
                    )
            if any(probe.exception() is None for probe in done):
                return True
        return False
    finally:
        for probe in probes:
            probe.cancel()


async def _check_within_timeout(check) -> bool:
    try:
        return await asyncio.wait_for(check(), READY_TIMEOUT_SECONDS)
    except Exception as e:
        logger.warning("Readiness check %s failed: %s", check.__name__, type(e).__name__)
        return False


async def _readiness() -> Dict:
    if not container:
        return {"ready": False, "checks": {"database": "failed", "rpc": "failed"}}
    database, rpc = await asyncio.gather(
        _check_within_timeout(_database_answers), _check_within_timeout(_any_rpc_answers),
    )
    checks = {
        "database": "ok" if database else "failed",
        "rpc": "ok" if rpc else "failed",
        "robinhood_rpc": "ok" if container.robinhood_rpc_guard.state == rpc_guard.CLOSED else "open",
    }
    for name, state in provider_breakers.states().items():
        checks[name] = "ok" if state == CLOSED else "open"
    return {"ready": database and rpc, "checks": checks}


@app.get("/api/ready")
async def ready():
    """Readiness: 200 when this process can serve scans, 503 when it cannot.

    Ready means the database answers SELECT 1 and at least one chain's RPC answers eth_blockNumber,
    each within READY_TIMEOUT_SECONDS; `checks` has each as "ok" or "failed". The RPCs are asked
    at once and the first answer is enough, so one that hangs cannot hold the check up; Robinhood
    Chain's is not asked, as its requests go through the shared RPC guard. It also lists the
    Robinhood Chain RPC guard (`robinhood_rpc`) and every provider circuit breaker used so far
    (core.circuit_breaker, named provider or provider:chain_id) as "ok" or "open". An open breaker
    does not make the process unready: that provider's lookups come back Unknown, never clean.
    The body holds check names only. One result serves every request for READY_CACHE_SECONDS, and
    concurrent requests share one check. /api/health stays pure liveness.
    """
    async with _ready_lock:
        if time.monotonic() >= _ready_cache["expires_at"]:
            _ready_cache["body"] = await _readiness()
            _ready_cache["expires_at"] = time.monotonic() + READY_CACHE_SECONDS
        body = _ready_cache["body"]
    return JSONResponse(status_code=200 if body["ready"] else 503, content=body)


# The built dashboard inlines its scripts and styles; only Google Fonts is fetched from elsewhere.
DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
# The evidence page has no scripts and loads nothing; its only styles are inline.
EVIDENCE_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


@app.get("/dashboard")
async def threat_dashboard():
    """Public real-time threat intelligence dashboard."""
    import os
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard", "index.html")
    return FileResponse(
        dashboard_path,
        media_type="text/html",
        headers={"Cache-Control": "no-cache", "Content-Security-Policy": DASHBOARD_CSP},
    )


def _is_valid_evm_address(value: str) -> bool:
    try:
        return bool(value and web3_client and web3_client.is_valid_address(value))
    except Exception:
        return False


def _checksum_if_possible(value: str) -> str:
    try:
        if _is_valid_evm_address(value):
            return web3_client.to_checksum_address(value)
    except Exception:
        pass
    return value


def _extract_signature_target(req: FirewallRequest) -> str:
    """The signature's target: `to`, then the typed data's addresses. The evidence document records
    it, so it is never the signer's own address."""
    candidates: List[str] = [req.to]

    typed_data = req.typedData if isinstance(req.typedData, dict) else {}
    domain = typed_data.get("domain") if isinstance(typed_data.get("domain"), dict) else {}
    message = typed_data.get("message") if isinstance(typed_data.get("message"), dict) else {}
    details = message.get("details") if isinstance(message.get("details"), dict) else {}

    for value in (
        domain.get("verifyingContract"),
        message.get("verifyingContract"),
        message.get("spender"),
        message.get("token"),
        details.get("token"),
    ):
        if isinstance(value, str):
            candidates.append(value)

    for candidate in candidates:
        if _is_valid_evm_address(candidate):
            return _checksum_if_possible(candidate)
    return ""


# The wallet methods the extension checks as signatures. A typed-data method whose typed data did not
# arrive as an object (MetaMask's legacy list of fields, or data the extension could not parse) is
# still a signature, answered as unknown, not a transaction to an invalid address.
SIGNING_METHODS = {
    "personal_sign", "eth_sign",
    "eth_signTypedData", "eth_signTypedData_v1", "eth_signTypedData_v3", "eth_signTypedData_v4",
}


def _is_signature_only_request(req: FirewallRequest) -> bool:
    # eth_sign signs a raw hash, not a call to `to`, so it is answered here whatever `to` is: the
    # signature path applies its floor, and the transaction path would answer it from the target's
    # cached row or scan and store its verdict as the target's.
    if req.signMethod == "eth_sign":
        return True
    if req.typedData:
        return not _is_valid_evm_address(req.to)
    return (req.signMethod or "") in SIGNING_METHODS and not _is_valid_evm_address(req.to)


async def _build_signature_only_response(
    req: FirewallRequest, policy_override: Optional[str] = None, trail: Optional[Dict] = None,
) -> Dict:
    from analyzers.signature import SignaturePermitAnalyzer
    from core.analyzer import AnalysisContext
    from core.policy import PolicyEngine

    target = _extract_signature_target(req) or "0x0000000000000000000000000000000000000000"
    ctx = AnalysisContext(
        address=target,
        chain_id=req.chainId,
        from_address=req.sender,
        is_token=False,
        extra={
            "typed_data": req.typedData,
            "sign_method": req.signMethod or "",
            "calldata": req.data,
        },
    )
    result = await SignaturePermitAnalyzer(container.counterparty_service if container else None).analyze(ctx)
    risk_score = int(max(0, min(100, round(result.score))))
    danger_signals = list(result.flags)

    # eth_sign signs a raw 32-byte hash, which can be a transaction's: it is always Block Recommended.
    if req.signMethod == "eth_sign" and risk_score < verdicts.BLIND_SIGN_MIN:
        risk_score = verdicts.BLIND_SIGN_MIN
        danger_signals.insert(0, "eth_sign signs a raw hash, and that hash can be a transaction that moves your funds")

    classification = verdicts.classify(risk_score, verdicts.SIGNATURE_BANDS)

    sig_type = result.data.get("sig_type", "signature")
    sign_method = req.signMethod or result.data.get("sign_method") or "signature"
    covered = not result.error and 'Failed to parse typed data' not in danger_signals and (
        sig_type in {'eip2612_permit', 'permit2', 'permit2_transfer', 'seaport_order', 'seaport_bulk_order', 'blur_order'}
        or (not req.typedData and req.signMethod == 'personal_sign')
    ) and result.data.get('status') != 'unknown'
    # As core.policy does, STRICT turns an unavailable or incomplete analysis into a block.
    policy = container.policy_engine if container and container.policy_engine else PolicyEngine()
    strict_block = not covered and policy.apply([], {}, mode_override=policy_override)['policy_mode'] == PolicyMode.STRICT.value
    if strict_block:
        risk_score = max(risk_score, verdicts.STRICT_BLOCK_SCORE)
        classification = verdicts.BLOCK_RECOMMENDED
        danger_signals.insert(0, 'Policy override: signature analysis unavailable or incomplete')
    alert = format_extension_alert({
        'rug_probability': risk_score, 'risk_level': verdicts.LOW if covered else verdicts.UNKNOWN,
        'status': 'ok' if covered else 'unknown', 'coverage': {'signature': int(covered)},
        'coverage_reasons': {} if covered else {
            'signature': result.data.get('reason') or 'Signature payload analysis unavailable or unsupported',
        },
    })
    if not covered and classification == verdicts.SAFE:
        classification = verdicts.CAUTION
    decoded_action = f"{sign_method} signature request"
    if sig_type and sig_type not in {"unknown", sign_method}:
        decoded_action += f" ({sig_type})"

    # What the evidence document records (see _firewall_verdict): the signed data only as a hash.
    if trail is not None:
        trail.update(
            target=target,
            analyzers=analyzer_outcomes([result], {
                'coverage': {'signature': int(covered)}, 'category_scores': {'signature': risk_score},
                'coverage_reasons': alert['coverage_reasons'],
            }),
            transaction=transaction_evidence(req.data, sign_method=req.signMethod, typed_data=req.typedData),
        )

    return {
        **_coverage_fields(alert),
        "classification": classification,
        "risk_score": risk_score,
        "decoded_action": decoded_action,
        "calldata_details": {
            "summary": decoded_action,
            "fields": [
                {"label": "Method", "value": sign_method},
                {"label": "Signature Type", "value": sig_type},
                {"label": "Target", "value": target or "N/A"},
            ],
        },
        "danger_signals": danger_signals,
        "transaction_impact": {
            "sending": "No on-chain transaction",
            "granting_access": "Signature may grant token or marketplace permissions" if danger_signals else "None detected",
            "recipient": target if _is_valid_evm_address(target) else "N/A",
            "post_tx_state": "Signature can be submitted later by the requesting dApp or spender",
        },
        "analysis": f"Signature-only analysis for {sign_method}",
        "plain_english": (
            alert['recommended_action'] if not covered else
            "This signature request contains risky permission patterns. Verify the spender, token, and terms before signing."
            if classification in (verdicts.HIGH_RISK, verdicts.BLOCK_RECOMMENDED)
            else "No dangerous signature permission pattern was detected."
        ),
        "verdict": f"{classification} - Signature risk {alert['risk_display']}",
        "raw_checks": {
            "signature": result.data,
            "flags": danger_signals,
        },
        "shield_score": {
            "overall": risk_score,
            "category_scores": {"signature": risk_score},
            **_coverage_fields(alert),
            "risk_level": classification if covered else verdicts.UNKNOWN,
            "threat_type": sig_type or "signature",
            "critical_flags": danger_signals,
            "confidence": 80 if req.typedData else 60,
        },
        "simulation": None,
        "asset_delta": [],
        "simulated": False,
        "greenfield_url": None,
        "chain_id": req.chainId,
        "network": _chain_id_to_name(req.chainId),
        "partial": not covered,
        "failed_sources": [] if covered else ["signature"],
        "policy_mode": PolicyMode.STRICT.value if strict_block else "SIGNATURE_ONLY",
        "notes": [],
    }


@app.post("/api/firewall")
async def firewall(req: FirewallRequest, request: Request):
    """
    Main firewall endpoint — intercepts a pending transaction,
    analyzes calldata + target contract, and returns a security verdict.
    Every verdict carries evidence_hash and evidence_url (see _with_evidence).

    A request with Accept: text/event-stream gets server-sent events instead (_firewall_events):
    `first`, an interim verdict that is always Unknown and never SAFE, then `final`, the plain
    response with final: true, or `error`. STRICT sends no interim verdict, so a STRICT request (the
    X-Policy-Mode header or the server's default) gets the plain JSON response whatever it accepts.
    """
    if request.headers.get("accept", "").startswith("text/event-stream"):
        started = time.monotonic()
        policy_mode = _policy_mode(request)
        if policy_mode != PolicyMode.STRICT.value:
            # A bad request is refused before the stream's headers go out.
            if not _is_signature_only_request(req) and not web3_client.is_valid_address(req.to):
                raise HTTPException(status_code=400, detail="Invalid 'to' address")
            return StreamingResponse(
                _firewall_events(req, request, started, policy_mode),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )
    return await _firewall_response(req, request)


async def _firewall_response(
    req: FirewallRequest, request: Request, progress: Optional[FirstVerdictProgress] = None,
) -> Dict:
    """The firewall's verdict with its stored evidence: the plain response, and the stream's final."""
    trail = {}
    response = await _firewall_verdict(req, request, trail, progress)
    return await _with_evidence(
        response, "/api/firewall", req.chainId, caller=_checksum_if_possible(req.sender), **trail,
    )


def _policy_mode(request: Request) -> str:
    """The effective policy mode: the X-Policy-Mode header, or the server's default."""
    if container and container.policy_engine:
        return container.policy_engine.apply(
            [], {}, mode_override=request.headers.get("X-Policy-Mode"),
        )['policy_mode']
    return PolicyMode.BALANCED.value


def _sse(event: str, data: Dict) -> str:
    """One server-sent event whose data is the JSON body the plain route would send for `data`."""
    return f"event: {event}\ndata: {JSONResponse(jsonable_encoder(data)).body.decode('utf-8')}\n\n"


def _first_transaction_fields(
    decoded: Dict, value_bnb: float, chain_id: int, to_addr: str, whitelisted: Optional[str],
) -> Dict:
    """The fields of an interim verdict that describe the request, worded as the final response's
    (a trusted router's as _analyze_router_swap words them)."""
    return {
        "decoded_action": _format_decoded_action(decoded, chain_id),
        "calldata_details": _build_calldata_details(decoded),
        "transaction_impact": {
            "sending": _sending(decoded, value_bnb, chain_id, "Tokens (via router)" if whitelisted else "Tokens"),
            "granting_access": _granting_access(decoded),
            "recipient": f"{whitelisted} ({to_addr})" if whitelisted else to_addr,
            "post_tx_state": IN_PROGRESS,
        },
        "chain_id": chain_id,
        "network": _chain_id_to_name(chain_id),
    }


async def _firewall_events(req: FirewallRequest, request: Request, started: float, policy_mode: str):
    """The streamed firewall's events. `first` comes as soon as a Block-level floor is known, else
    FIRST_VERDICT_SECONDS after the handler started (`started`, a time.monotonic() reading), and only
    while the scan is still running; a scan that finishes first, or a request with nothing decoded
    yet (a signature request never has anything), sends only `final`.

    The scan runs in its own task, and closing this generator (a client disconnect) never cancels
    it: its side effects (the evidence document, the stored score, the threat graph, the sentinel,
    the deployer index) still happen once, and only from the final verdict. A started stream always
    ends in `final` or `error`. Logs one line per request with the timings.
    """
    progress = FirstVerdictProgress(
        [analyzer.name for analyzer in container.registry.get_all()] if container and container.registry else [],
        policy_mode,
    )
    scan = _fire_and_forget(_firewall_response(req, request, progress), label="firewall_stream_scan")
    block_known = asyncio.ensure_future(progress.block_known.wait())
    timings = {
        "chain_id": req.chainId, "first_at_ms": None, "first_kind": "none", "pending_at_first": None,
        "final_at_ms": None,
    }
    try:
        await asyncio.wait(
            (scan, block_known),
            timeout=max(0.0, started + FIRST_VERDICT_SECONDS - time.monotonic()),
            return_when=asyncio.FIRST_COMPLETED,
        )
        if not scan.done() and progress.describe:
            elapsed_ms = round((time.monotonic() - started) * 1000)
            first = build_first_verdict(progress, progress.describe(), elapsed_ms)
            timings.update(
                first_at_ms=elapsed_ms,
                first_kind="block" if progress.block_known.is_set() else "unknown",
                pending_at_first=first["pending_sources"],
            )
            yield _sse("first", first)
        final = await asyncio.shield(scan)
        timings["final_at_ms"] = round((time.monotonic() - started) * 1000)
        yield _sse("final", {**final, "final": True})
    except HTTPException as exc:
        yield _sse("error", {"status": exc.status_code, "detail": exc.detail})
    except Exception as e:
        # The headers are sent, so a started stream ends in final or error: this is its 500. A
        # disconnect (CancelledError, GeneratorExit) is not an Exception and goes straight to finally.
        logger.error(
            "Firewall stream error: %s\n%s", type(e).__name__, "".join(traceback.format_tb(e.__traceback__)),
        )
        yield _sse("error", {"status": 500, "detail": "Internal server error"})
    finally:
        block_known.cancel()
        logger.info("Firewall stream %s", json.dumps(timings, sort_keys=True))


async def _firewall_verdict(
    req: FirewallRequest, request: Request, trail: Dict, progress: Optional[FirstVerdictProgress] = None,
) -> Dict:
    """The firewall's verdict. Each path records in `trail` what its evidence document needs:
    target, target_token, transaction (transaction-specific verdicts only), analyzers,
    observed_block and, for a verdict served from contract_scores, cached_scan_at.

    A streamed request passes `progress`, which hears the target's local blacklist match and each
    analyzer's result as it returns. Nothing else changes: the verdict is the plain route's."""
    try:
        to_addr = req.to
        from_addr = req.sender

        if _is_signature_only_request(req):
            return await _build_signature_only_response(
                req, policy_override=request.headers.get("X-Policy-Mode"), trail=trail,
            )

        if not web3_client.is_valid_address(to_addr):
            raise HTTPException(status_code=400, detail="Invalid 'to' address")

        to_addr = web3_client.to_checksum_address(to_addr)
        trail['target'] = to_addr

        # 1. Decode calldata
        decoded = calldata_decoder.decode(req.data)
        # Use chain-specific adapter for router lookup when available
        _adapter = container.web3_client._get_adapter(req.chainId) if container else None
        whitelisted = calldata_decoder.is_whitelisted_target(to_addr, chain_id=req.chainId, adapter=_adapter)

        # Resolve value
        value_wei = _parse_value(req.value)
        value_bnb = value_wei / 1e18

        # The target's local blacklist entry. An admin entry (block severity) is authoritative, so a
        # trusted router it lists is judged on the full path below, where its Block floor applies; a
        # community entry, which any three reporters can make, never takes a swap off the router path.
        # A delegation is judged on the full path too, whatever the target.
        local_match = scam_db.local_match(to_addr, req.chainId)
        router_answers = bool(whitelisted) and req.authorizationList is None and not (
            local_match and local_match['severity'] == 'block'
        )

        # A streamed request hears each analyzer's result as it returns; a plain one calls run_all as before.
        run_options = {}
        if progress is not None:
            # The router shortcut judges only the path tokens, so the entry of a target it answers for
            # (a community one) never reaches the final and must not raise the first above it.
            if not router_answers:
                progress.add_local_match(local_match)
            # Worded as the router's answer only when the router answers.
            progress.describe = partial(
                _first_transaction_fields, decoded, value_bnb, req.chainId, to_addr,
                whitelisted if router_answers else None,
            )
            run_options = {"on_result": progress.add_result}

        # Enrich decoded calldata with token names and formatted amounts
        await _enrich_decoded(decoded, to_addr, chain_id=req.chainId)
        if decoded.get('token_symbol'):
            trail['target_token'] = {'name': decoded.get('token_name'), 'symbol': decoded['token_symbol']}

        # contract_scores holds one verdict per target. An approval's, a claim's, a signature's or
        # a paying call's verdict also depends on this transaction (the spender, the value, the
        # typed data), so a row cached from another transaction never answers one. A spender's
        # floor describes the spender, not the target, so approval and typed-data verdicts are not
        # written to the target's row either, and do not put the target's deployer on the watch
        # list. Neither is another call's payment floor: it comes from one user's payment, and the
        # contract's other requests (a transfer, a zero-value call) must not be served it. A
        # claim's floor, paid or not, describes the target, so its row is kept. A plain native
        # send has no payment rule and its recipient is the row, so it stays cacheable. An EIP-7702
        # delegation's floor describes the delegate, never the target.
        paying = value_wei > 0 and decoded.get('selector') is not None
        tx_specific = (
            decoded.get('category') in ('approval', 'claim') or bool(req.typedData) or paying
            or req.authorizationList is not None
        )
        describes_target = not (
            decoded.get('category') == 'approval' or req.typedData
            or (paying and decoded.get('category') != 'claim') or req.authorizationList is not None
        )
        if tx_specific:
            trail['transaction'] = transaction_evidence(
                req.data, function=decoded.get('function_name'), sign_method=req.signMethod,
                typed_data=req.typedData,
            )

        policy_mode = _policy_mode(request)

        # 2. If the target is a trusted router that answers for the swap (router_answers above), analyze
        # the swap path tokens instead of bypassing.
        if router_answers:
            router_response = await _analyze_router_swap(
                req=req,
                to_addr=to_addr,
                from_addr=from_addr,
                decoded=decoded,
                whitelisted=whitelisted,
                value_bnb=value_bnb,
                policy_override=request.headers.get("X-Policy-Mode"),
                policy_mode=policy_mode,
                trail=trail,
                progress=progress,
            )
            if router_response:
                return router_response

        # 2b. Check cache for recent result. A row is up to five minutes old and keeps no scam matches,
        # so a target with a local blacklist entry (admin or community: both set a floor) is scanned
        # afresh: an entry added since the row was written must not be answered with the row.
        if container and container.db and not tx_specific and local_match is None:
            cached = await container.db.get_contract_score(to_addr, req.chainId, max_age_seconds=300)
            if cached and cached.get('category_scores', {}).get('_scan_metadata', {}).get('coverage'):
                # A full rescan costs provider calls, so only a caller with a valid API key can force one
                # with STRICT. Anyone else is answered from the cached facts in STRICT mode.
                if policy_mode != PolicyMode.STRICT.value or not getattr(request.state, "api_key_info", None):
                    trail['cached_scan_at'] = cached['last_scanned_at']
                    return _build_cached_response(
                        cached, decoded, value_bnb, req.chainId, to_addr=to_addr, policy_mode=policy_mode,
                    )

        # 2c. Fast deployer history lookup (uses already-indexed data — non-blocking DB query)
        _deployer_ctx = None
        if container and container.db:
            _deployer_ctx = await _get_deployer_campaign_context(to_addr, req.chainId, container)

        # 3. Try composite intelligence pipeline (registry-based)
        try:
            from core.analyzer import AnalysisContext

            # Detect if target is a token contract — non-tokens (marketplaces,
            # bridges, governance) should not be penalized by token-specific
            # checks (honeypot simulation, DEX liquidity, etc.)
            is_token = None
            is_verified = None
            # The target's code, read once. A wallet (no code, or an EIP-7702 delegation) has no
            # source to verify and takes payments with no contract to judge; for a contract, the
            # verification's clone check reads this code instead of fetching it again.
            code = await web3_client.get_bytecode(to_addr, chain_id=req.chainId)
            has_code, delegated = code_kind(code)
            is_contract = None if has_code is None else has_code and not delegated
            try:
                is_token = await web3_client.is_token_contract(to_addr, chain_id=req.chainId)
            except UnsupportedChainError:
                raise
            except Exception:
                pass
            if is_contract is not False:
                try:
                    verified_result = await web3_client.is_verified_contract(to_addr, chain_id=req.chainId, code=code)
                    is_verified = verified_result[0] if isinstance(verified_result, tuple) else verified_result
                except UnsupportedChainError:
                    raise
                except Exception:
                    pass

            ctx = AnalysisContext(
                address=to_addr, chain_id=req.chainId, from_address=from_addr,
                is_token=is_token,
                extra={
                    'calldata': req.data,
                    'value': req.value,
                    'typed_data': req.typedData,
                    'sign_method': req.signMethod,
                    'is_verified': is_verified,
                    'is_contract': is_contract,
                    'authorization_list': req.authorizationList,
                },
            )

            # Run analyzers + optional Tenderly simulation in parallel
            run_simulation = tenderly_simulator and tenderly_simulator.is_enabled()
            if run_simulation and container and container.registry:
                sim_task = tenderly_simulator.simulate_transaction(
                    to_address=to_addr, from_address=from_addr,
                    value=req.value, data=req.data, chain_id=req.chainId,
                )
                analyzer_results, simulation_result = await asyncio.gather(
                    container.registry.run_all(ctx, **run_options), sim_task,
                )
            elif container and container.registry:
                analyzer_results = await container.registry.run_all(ctx, **run_options)
                simulation_result = None
            else:
                # Fallback: no container (e.g. tests), use old 4-service gather
                from analyzers.behavioral import counterparty_reputation

                gather_tasks = [
                    contract_service.fetch_contract_data(to_addr, chain_id=req.chainId),
                    honeypot_service.fetch_honeypot_data(to_addr, chain_id=req.chainId),
                    dex_service.fetch_token_market_data(to_addr),
                    counterparty_reputation(ethos_service, decoded, to_addr),
                ]
                results = await asyncio.gather(*gather_tasks)
                risk_output = risk_engine.compute_composite_risk(
                    results[0], results[1], results[2], results[3],
                )
                analyzer_results = None
                simulation_result = None

            # Compute risk from analyzer results
            if analyzer_results is not None:
                risk_output = risk_engine.compute_from_results(analyzer_results, is_token=is_token)
                # The target's local blacklist entry holds even when the structural analyzer, which
                # reports it, failed or ran past the deadline.
                risk_output = apply_local_match(risk_output, local_match, analyzer_results)

                # Apply policy mode (handles partial failures)
                if container and container.policy_engine:
                    req_policy = request.headers.get("X-Policy-Mode")
                    risk_output = container.policy_engine.apply(
                        analyzer_results, risk_output, mode_override=req_policy,
                    )

                # Extract service data from analyzer results for backward compat
                by_name = {r.name: r for r in analyzer_results}
                contract_data = by_name["structural"].data if "structural" in by_name else {}
                honeypot_data = by_name["honeypot"].data if "honeypot" in by_name else {}
                dex_data = by_name["market"].data if "market" in by_name else {}
                ethos_data = by_name["behavioral"].data if "behavioral" in by_name else {}
            else:
                contract_data, honeypot_data, dex_data, ethos_data = results

            if simulation_result is not None and simulation_result.get('success') is False:
                risk_output = {
                    **risk_output, 'status': 'unknown',
                    'coverage': {**risk_output.get('coverage', {}), 'transaction_simulation': 0},
                    'coverage_reasons': {**risk_output.get('coverage_reasons', {}),
                        'transaction_simulation': simulation_result.get('revert_reason') or 'Transaction simulation failed'},
                }
            alert = format_extension_alert(risk_output)

            # Policy override may force BLOCK
            policy_override = risk_output.get('policy_override')
            if policy_override:
                alert['risk_classification'] = policy_override

            # Simulation overrides
            danger_signals = list(alert["top_flags"])
            classification = alert["risk_classification"]

            # Campaign risk boost — inject serial-scammer signal
            if _deployer_ctx and _deployer_ctx.get("danger_signal"):
                danger_signals.insert(0, _deployer_ctx["danger_signal"])

            if simulation_result:
                if not simulation_result.get("success") and simulation_result.get("revert_reason"):
                    danger_signals.insert(0, f"Simulation reverted: {simulation_result['revert_reason']}")
                    if _revert_blocks(risk_output):
                        classification = verdicts.BLOCK_RECOMMENDED
                for w in simulation_result.get("warnings", []):
                    if w not in danger_signals:
                        danger_signals.append(w)

            risk_score = alert["rug_probability"]

            # Apply campaign risk boost from deployer history
            if _deployer_ctx and _deployer_ctx.get("risk_boost", 0) > 0:
                boosted = min(95, risk_score + _deployer_ctx["risk_boost"])
                if boosted > risk_score:
                    risk_score = boosted
                    alert["rug_probability"] = risk_score
                    if alert['status'] == 'ok':
                        alert['risk_display'] = f'{risk_score}%'
                    # The boosted score takes its band, as the extension draws it.
                    band = verdicts.classify(risk_score)
                    if band == verdicts.BLOCK_RECOMMENDED:
                        classification = verdicts.BLOCK_RECOMMENDED
                    elif band == verdicts.HIGH_RISK and classification in (verdicts.SAFE, verdicts.CAUTION):
                        classification = verdicts.HIGH_RISK

            # The level follows the final score, the campaign boost included, here and where it is stored.
            risk_level = verdicts.stored_level(risk_score, risk_output.get("risk_level", verdicts.UNKNOWN))

            # Shield score breakdown
            shield_score = {
                **_coverage_fields(alert),
                "overall": risk_score,
                "category_scores": risk_output.get("category_scores", {}),
                "risk_level": risk_level,
                "threat_type": risk_output.get("risk_archetype", "unknown"),
                "critical_flags": risk_output.get("critical_flags", []),
                "confidence": alert["confidence"],
            }

            # Build response
            response = {
                **_coverage_fields(alert),
                "classification": classification,
                "risk_score": risk_score,
                "decoded_action": _format_decoded_action(decoded, req.chainId),
                "calldata_details": _build_calldata_details(decoded),
                "danger_signals": danger_signals,
                "transaction_impact": {
                    "sending": _sending(decoded, value_bnb, req.chainId, "Tokens"),
                    "granting_access": _granting_access(decoded),
                    "recipient": to_addr,
                    "post_tx_state": f"Risk archetype: {alert['risk_archetype']}",
                },
                "analysis": f"Composite risk analysis — archetype: {alert['risk_archetype']}, confidence: {alert['confidence']}%",
                "plain_english": alert["recommended_action"],
                "verdict": f"{classification} — Rug probability {alert['risk_display']}",
                "raw_checks": {
                    "is_verified": contract_data.get("is_verified"),
                    "scam_matches": _scam_match_count(contract_data),
                    "contract_age_days": contract_data.get("contract_age_days"),
                    "is_honeypot": honeypot_data.get("is_honeypot"),
                    "buy_tax": honeypot_data.get("buy_tax"),
                    "sell_tax": honeypot_data.get("sell_tax"),
                    "can_sell": honeypot_data.get("can_sell"),
                    "ownership_renounced": contract_data.get("ownership_renounced"),
                    "risk_score_heuristic": risk_score,
                    "whitelisted_router": whitelisted,
                },
                "shield_score": shield_score,
                "simulation": simulation_result,
                "asset_delta": _build_asset_delta(simulation_result, decoded, value_bnb, req.chainId),
                "simulated": _simulated(simulation_result),
                "greenfield_url": None,
                "chain_id": req.chainId,
                "network": _chain_id_to_name(req.chainId),
                "partial": alert['status'] == 'unknown' or risk_output.get("partial", False),
                "failed_sources": risk_output.get("failed_sources", []),
                "policy_mode": risk_output.get("policy_mode", PolicyMode.BALANCED.value),
                "campaign_context": _deployer_ctx,
                "notes": risk_output.get("notes", []),
            }

            # Persist contract score to DB. The row keeps the policy engine's failed_sources, the
            # required checks STRICT decides on, so a cached answer is judged as this one was.
            if container and container.db and describes_target:
                scan_metadata = {**_coverage_fields(alert), 'notes': risk_output.get('notes', [])}
                if 'failed_sources' in risk_output:
                    scan_metadata['failed_sources'] = risk_output['failed_sources']
                try:
                    await container.db.upsert_contract_score(
                        address=to_addr,
                        chain_id=req.chainId,
                        risk_score=risk_score,
                        risk_level=risk_level,
                        archetype=risk_output.get("risk_archetype"),
                        category_scores={
                            **risk_output.get("category_scores", {}),
                            '_scan_metadata': scan_metadata,
                        },
                        flags=risk_output.get("critical_flags"),
                        confidence=alert.get("confidence"),
                    )
                except UnsupportedChainError:
                    raise
                except Exception as e:
                    logger.error(f"DB upsert failed: {type(e).__name__}")

            # Auto-enrich threat graph (fire-and-forget), from verdicts that describe the target
            if container and hasattr(container, 'threat_graph') and describes_target:
                _fire_and_forget(
                    container.threat_graph.enrich_from_scan(
                        to_addr, req.chainId, {**risk_output, "rug_probability": risk_score, "risk_level": risk_level},
                    ),
                    label="threat_graph_enrich",
                )

            # Sentinel feedback loop: auto-watch deployers of blocked contracts
            if container and hasattr(container, 'sentinel') and classification == verdicts.BLOCK_RECOMMENDED and describes_target:
                try:
                    deployer_info = await container.db.get_deployer_risk_summary(to_addr, req.chainId)
                    deployer_addr = deployer_info["deployer_address"] if deployer_info else None
                    _fire_and_forget(container.sentinel.on_scan_blocked(
                        address=to_addr,
                        deployer=deployer_addr,
                        chain_id=req.chainId,
                        risk_score=risk_score,
                    ), label="sentinel_on_scan_blocked")
                except UnsupportedChainError:
                    raise
                except Exception as e:
                    logger.error(f"Sentinel feedback failed: {type(e).__name__}")

            # Enqueue deployer indexing (fire-and-forget)
            if container and container.indexer:
                container.indexer.enqueue(to_addr, req.chainId)

            # Greenfield upload for risky transactions (HIGH_RISK and above)
            if greenfield_service and greenfield_service.is_enabled() and risk_score >= verdicts.HIGH_RISK_MIN:
                try:
                    gf_url = await greenfield_service.upload_report(
                        target_address=to_addr,
                        risk_score=risk_score,
                        category_scores=risk_output.get("category_scores", {}),
                        full_analysis={
                            **_coverage_fields(alert),
                            "classification": response.get("classification"),
                            "danger_signals": response.get("danger_signals"),
                            "raw_checks": response.get("raw_checks"),
                        },
                    )
                    response["greenfield_url"] = gf_url
                except UnsupportedChainError:
                    raise
                except Exception as e:
                    logger.error(f"Greenfield upload failed: {type(e).__name__}")

            if analyzer_results is not None:
                trail['analyzers'] = analyzer_outcomes(analyzer_results, risk_output)
                trail['observed_block'] = oldest_simulation_block(analyzer_results)
            return response

        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.warning(f"Composite pipeline failed for {to_addr}, falling back: {type(e).__name__}")

        # 4. Fallback: legacy scanner + AI firewall
        is_token = None
        contract_scan = {}
        try:
            is_token = await web3_client.is_token_contract(to_addr, chain_id=req.chainId)
        except UnsupportedChainError:
            raise
        except Exception:
            pass

        if is_token is not False:
            contract_scan = await token_scanner.check_token(to_addr, chain_id=req.chainId)
        else:
            contract_scan = await tx_scanner.scan_address(to_addr, chain_id=req.chainId)

        contract_scan.pop("forensic_report", None)
        contract_scan.pop("source_code", None)
        # The target's local blacklist entry, which the token scanner never asks for: an admin entry's
        # Block holds here as on the composite path. The address scanner's scam lookup already reports
        # the same match, which is not added twice.
        scam_matches = list(contract_scan.get("scam_matches") or [])
        if local_match and local_match not in scam_matches:
            contract_scan["scam_matches"] = [*scam_matches, local_match]

        # The AI provider gets no wallet address: not the sender, nor a mention of it in the calldata
        # (a swap's recipient), which is masked as the evidence document masks it.
        tx_data = without_caller({
            "to": to_addr,
            "value": req.value,
            "data": req.data,
            "chainId": req.chainId,
            "decoded_calldata": decoded,
            "whitelisted_router": whitelisted,
        }, from_addr)

        # The trusted-router discount applies only where the router shortcut would have answered: never
        # to a delegation or to a router an admin has listed.
        response = _build_fallback_response(
            decoded, contract_scan, whitelisted if router_answers else None, req.chainId,
            transaction_specific=tx_specific, policy_mode=policy_mode,
        )
        # The AI explains a known verdict and never sets it: of its reply only the prose is kept.
        if response["status"] == "ok" and ai_analyzer and ai_analyzer.is_available():
            explanation = await ai_analyzer.generate_firewall_report(
                tx_data, contract_scan, response["classification"], response["risk_score"],
            )
            if explanation:
                response.update({
                    key: explanation[key] for key in ("analysis", "plain_english") if isinstance(explanation.get(key), str)
                })
                impact = explanation.get("transaction_impact")
                if isinstance(impact, dict):
                    response["transaction_impact"].update({
                        key: impact[key] for key in ("sending", "post_tx_state") if isinstance(impact.get(key), str)
                    })
        return response

    except HTTPException:
        raise
    except UnsupportedChainError:
        raise
    except Exception as e:
        logger.error(f"Firewall error: {type(e).__name__}\n{''.join(traceback.format_tb(e.__traceback__))}")
        raise HTTPException(status_code=500, detail="Internal server error")


async def _with_evidence(response: Dict, endpoint: str, chain_id: int, **trail) -> Dict:
    """`response` with evidence_hash, the hash of its evidence document (core/scan_evidence.py), and
    evidence_url, where GET /evidence/{hash} shows it.

    The document is stored before its URL is returned, so the URL never names a missing document;
    evidence_url is None when it could not be stored, and both are None when the document could not
    be serialised. Neither failure withholds the verdict.
    """
    digest = url = None
    try:
        document = build_scan_evidence(endpoint, chain_id, response, int(time.time()), **trail)
        canonical = canonical_bytes(document).decode("utf-8")
        digest = evidence_hash(document)
    except (TypeError, ValueError) as e:
        logger.error("Scan evidence could not be serialised: %s", type(e).__name__)
    if digest and container and container.db:
        try:
            await container.db.insert_scan_evidence(digest, canonical)
            url = f"{container.settings.public_api_url.rstrip('/')}/evidence/{digest}"
        except Exception as e:
            logger.error("Scan evidence store failed: %s", type(e).__name__)
    return {**response, "evidence_hash": digest, "evidence_url": url}


@app.post("/api/scan")
async def scan(req: ScanRequest):
    """Quick contract scan — reuses TransactionScanner.scan_address."""
    try:
        address = req.address
        if not web3_client.is_valid_address(address):
            raise HTTPException(status_code=400, detail="Invalid address")

        address = web3_client.to_checksum_address(address)
        result = await tx_scanner.scan_address(address, chain_id=req.chainId)

        # Strip large fields
        result.pop("source_code", None)
        result.pop("forensic_report", None)

        alert = format_extension_alert({**result, 'rug_probability': result.get('risk_score', 0)})
        result.update(_coverage_fields(alert))
        result['classification'] = alert['risk_classification']
        result['partial'] = alert['status'] == 'unknown' or result.get('partial', False)
        result['notes'] = []
        if alert['status'] == 'unknown':
            result['risk_level'] = verdicts.UNKNOWN
            result['verdict'] = alert['recommended_action']
            result.pop('ai_analysis', None)
        return await _with_evidence(result, "/api/scan", req.chainId, target=address)

    except HTTPException:
        raise
    except UnsupportedChainError:
        raise
    except Exception as e:
        logger.error(f"Scan error: {type(e).__name__}\n{''.join(traceback.format_tb(e.__traceback__))}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/scan/injection")
async def scan_injection(request: Request):
    """Scan text content for prompt injection attempts targeting AI agents."""
    try:
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON body must be an object")

        raw_content = body.get("content", body.get("text", ""))
        if raw_content is None:
            raw_content = ""
        if not isinstance(raw_content, str):
            raise HTTPException(status_code=400, detail="content/text must be a string")
        content = raw_content[:MAX_INJECTION_CONTENT_CHARS]
        depth = body.get("depth", "fast")

        if depth not in ("fast", "thorough"):
            raise HTTPException(status_code=400, detail="depth must be 'fast' or 'thorough'")

        if not container or not container.injection_scanner:
            raise HTTPException(status_code=503, detail="Injection scanner not available")

        result = await container.injection_scanner.scan(content, depth=depth)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Injection scan error: {type(e).__name__}\n{''.join(traceback.format_tb(e.__traceback__))}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/outcome")
async def report_outcome(req: OutcomeRequest, request: Request):
    """Record a user decision/outcome for a scanned contract.

    Anyone may call this, so each row records who sent it: 'key:<key_id>' for a valid API key, or
    'client'. No score reads these rows; scripts/calibrate.py reads only the API key rows, into a
    proposal the owner reviews.
    """
    # A valid API key is already held to its own quota by the middleware.
    key_info = getattr(request.state, "api_key_info", None)
    if key_info is None and not await _outcome_limiter.is_allowed(_get_client_ip(request)):
        return JSONResponse(
            status_code=429,
            content={"detail": "Outcome rate limit exceeded (10/min)."},
        )

    if not web3_client or not web3_client.is_valid_address(req.address):
        raise HTTPException(status_code=400, detail="Invalid address")

    try:
        if container and container.db:
            await container.db.record_outcome(
                address=req.address,
                chain_id=req.chainId,
                risk_score_at_scan=req.risk_score_at_scan,
                user_decision=req.user_decision,
                outcome=req.outcome,
                tx_hash=req.tx_hash,
                source=f"key:{key_info['key_id']}" if key_info else "client",
            )
        return {"status": "recorded"}
    except Exception as e:
        logger.error(f"Outcome recording error: {type(e).__name__}\n{''.join(traceback.format_tb(e.__traceback__))}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/report")
async def community_report(req: CommunityReportRequest, request: Request):
    """Record a community report (false positive, false negative, or scam)."""
    # Rate limit per IP (rightmost = proxy-set, not spoofable)
    client_ip = _get_client_ip(request)
    if not await _report_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Report rate limit exceeded (5/min)."},
        )

    valid_types = {"false_positive", "false_negative", "scam"}
    if req.report_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"report_type must be one of {valid_types}")

    if not web3_client or not web3_client.is_valid_address(req.address):
        raise HTTPException(status_code=400, detail="Invalid address")

    try:
        if container and container.db:
            await container.db.record_community_report(
                address=req.address,
                chain_id=req.chainId,
                report_type=req.report_type,
                reporter_id=reporter_hash(container.settings.reporter_hash_secret, client_ip),
                reason=req.reason,
            )
        return {"status": "recorded", "address": req.address, "report_type": req.report_type}
    except Exception as e:
        logger.error(f"Community report error: {type(e).__name__}\n{''.join(traceback.format_tb(e.__traceback__))}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/usage")
async def get_usage(request: Request):
    """Get API usage stats for the authenticated key."""
    key_info = getattr(request.state, "api_key_info", None)
    if not key_info:
        raise HTTPException(status_code=401, detail="API key required")
    if not container or not container.auth_manager:
        raise HTTPException(status_code=503, detail="Auth not available")
    usage = await container.auth_manager.get_usage(key_info["key_id"])
    quota = await container.auth_manager.get_quota(key_info)
    return {"key_id": key_info["key_id"], "tier": key_info["tier"], "usage": usage, "quota": quota}


@app.get("/api/campaign/{address}")
async def campaign_graph(address: str, chain_id: int = None):
    """Get cross-chain deployer/funder campaign graph for an address.

    Enhanced with campaign detection: cross-chain correlation, funder clustering,
    and coordinated scam campaign indicators.
    """
    if chain_id is not None:
        _validate_chain_id(chain_id)
    if not container or not container.campaign_service:
        raise HTTPException(status_code=503, detail="Campaign service not available")
    if not web3_client or not web3_client.is_valid_address(address):
        raise HTTPException(status_code=400, detail="Invalid address")
    graph = await container.campaign_service.get_entity_graph(address)
    return graph


@app.get("/api/campaigns/top")
async def top_campaigns(limit: int = 20):
    """Get the most prolific deployers/funders (likely campaign operators)."""
    if not container or not container.campaign_service:
        raise HTTPException(status_code=503, detail="Campaign service not available")
    limit = max(1, min(limit, 100))
    campaigns = await container.campaign_service.get_top_campaigns(limit=limit)
    return {"campaigns": campaigns, "count": len(campaigns)}


@app.post("/api/keys", include_in_schema=False)
async def create_api_key(request: Request):
    """Create a new API key. Requires ADMIN_SECRET header."""
    admin_secret = request.headers.get("x-admin-secret")
    expected = container.settings.admin_secret if container else ""
    if not expected:
        raise HTTPException(status_code=503, detail="Admin not configured")
    if not admin_secret or not hmac.compare_digest(admin_secret, expected):
        raise HTTPException(status_code=403, detail="Forbidden")
    if not container or not container.auth_manager:
        raise HTTPException(status_code=503, detail="Auth not available")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    owner = body.get("owner", "anonymous")
    tier = body.get("tier", "free")
    result = await container.auth_manager.create_key(owner, tier)
    return result


FREE_KEY_LINK_TTL_SECONDS = 1800


class FreeKeyRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)


class FreeKeyVerifyRequest(BaseModel):
    token: str = Field(..., min_length=16, max_length=128)


@app.post("/api/keys/free")
async def request_free_key(req: FreeKeyRequest, request: Request):
    """Email a single-use link that creates one free-tier API key for the address."""
    if not container or not container.email_service.is_enabled():
        raise HTTPException(status_code=503, detail="Self-serve keys are not enabled")
    client_ip = _get_client_ip(request)
    if not await _free_key_limiter.is_allowed(client_ip):
        return JSONResponse(status_code=429, content={"detail": "Too many requests. Please try again later."})

    email = req.email.strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        raise HTTPException(status_code=400, detail="Invalid email address")

    # One answer whether the address is new, has a pending link or already has a key, so the
    # endpoint does not reveal which. Every mail takes the address's pending slot, so an address
    # gets at most one mail per link lifetime; while a slot is pending nothing new is sent.
    answer = {"message": "Check your email for the next step. A link that creates a key expires in 30 minutes."}
    token = secrets.token_urlsafe(32)
    token_hash = hash_key(token)
    if not await container.db.add_free_key_request(email, token_hash, time.time() + FREE_KEY_LINK_TTL_SECONDS):
        return answer
    if await container.auth_manager.has_active_key(email, "free"):
        delivered = await container.email_service.send_free_key_exists_notice(email)
    else:
        # The token rides in the fragment, which browsers never send, so it stays out of access logs.
        verify_url = f"{container.settings.public_api_url.rstrip('/')}/api/keys/free/verify#token={token}"
        delivered = await container.email_service.send_free_key_verification(email, verify_url)
    if not delivered:
        await container.db.delete_free_key_request(token_hash)
        raise HTTPException(status_code=503, detail="The email could not be sent. Please try again later.")
    return answer


@app.get("/api/keys/free/verify", response_class=HTMLResponse, include_in_schema=False)
async def free_key_page():
    """Page the emailed link opens. Nothing is created until the reader presses its button, so a mail
    scanner that only fetches the link neither uses up the token nor receives the key."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ShieldBot free API key</title>
  <style>
    body { background: #0a0a0a; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 40px 16px; }
    main { max-width: 560px; margin: 0 auto; }
    h1 { color: #00ff88; font-size: 24px; }
    p { line-height: 1.6; }
    button { padding: 12px 24px; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; background: #00ff88; color: #000; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    pre { background: #111; border: 1px solid #333; border-radius: 8px; padding: 16px; font-size: 14px; white-space: pre-wrap; word-break: break-all; }
  </style>
</head>
<body>
  <main>
    <h1>ShieldBot free API key</h1>
    <p id="status">Create the free-tier API key for the address this link was sent to. The key is shown once.</p>
    <button id="create" type="button">Create my key</button>
    <pre id="key" hidden></pre>
  </main>
  <script>
    const token = new URLSearchParams(location.hash.slice(1)).get("token");
    const status = document.getElementById("status");
    const button = document.getElementById("create");
    const keyBox = document.getElementById("key");
    if (!token) {
      status.textContent = "This link has no token. Open the link from your email again.";
      button.hidden = true;
    }
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const resp = await fetch("/api/keys/free/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });
        const body = await resp.json();
        if (!resp.ok) throw new Error(body.detail || `Request failed (HTTP ${resp.status})`);
        status.textContent = `Your free-tier key (${body.rpm_limit} requests a minute, ${body.daily_limit} a day). ` +
          "Copy it now: it is not shown again. Send it in the X-API-Key header.";
        keyBox.textContent = body.key;
        keyBox.hidden = false;
        button.hidden = true;
      } catch (err) {
        status.textContent = err.message;
        button.disabled = false;
      }
    });
  </script>
</body>
</html>"""


@app.post("/api/keys/free/verify")
async def verify_free_key(req: FreeKeyVerifyRequest):
    """Use an emailed link's token once and create the address's free-tier key, shown only in this response."""
    if not container or not container.auth_manager:
        raise HTTPException(status_code=503, detail="Auth not available")
    email = await container.db.claim_free_key_request(hash_key(req.token))
    if email is None:
        raise HTTPException(status_code=400, detail="This link is invalid, expired or already used. Request a new one.")
    if await container.auth_manager.has_active_key(email, "free"):
        raise HTTPException(status_code=409, detail="This email already has an active free key.")
    created = await container.auth_manager.create_key(email, "free")
    return JSONResponse(
        content={
            "key": created["key"],
            "key_id": created["key_id"],
            "tier": "free",
            "rpm_limit": TIER_LIMITS["free"]["rpm"],
            "daily_limit": TIER_LIMITS["free"]["daily"],
        },
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/admin/stats", include_in_schema=False)
async def admin_stats(request: Request):
    """Platform metrics — scans, threats, blocks, chain breakdown, mempool.

    Requires X-Admin-Secret header. Use this endpoint to document metrics
    for grant applications, AvengerDAO membership, and weekly snapshots.
    """
    admin_secret = request.headers.get("x-admin-secret")
    expected = container.settings.admin_secret if container else ""
    if not expected:
        raise HTTPException(status_code=503, detail="Admin not configured")
    if not admin_secret or not hmac.compare_digest(admin_secret, expected):
        raise HTTPException(status_code=403, detail="Forbidden")
    if not container or not container.db:
        raise HTTPException(status_code=503, detail="Database not available")

    import datetime
    db_stats = await container.db.get_platform_stats()

    # Mempool stats (in-memory counters)
    mempool = {}
    if _background_workers == "external":
        mempool = None
    elif container.mempool_monitor:
        mempool = container.mempool_monitor.get_stats()

    # Phishing cache size (server-side, in-memory)
    phishing_cache_size = 0
    if container.phishing_service:
        phishing_cache_size = len(container.phishing_service._cache)

    guard_watch = None
    if container.hunter:
        guard_watch = await container.hunter.guard_watch_stats()
        if _background_workers == "external":
            # The launch watch and its RPC budget run in workers.py; this process's copies are idle.
            guard_watch.update(running=None, rpc_budget=None)

    stats = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        **db_stats,
        "mempool": mempool,
        "guard_watch": guard_watch,
        "phishing": {
            "domains_cached": phishing_cache_size,
        },
    }
    if _background_workers == "external":
        stats["background_workers_note"] = _EXTERNAL_WORKERS_NOTE
    return stats


@app.get("/api/stats")
async def public_stats():
    """Public platform statistics — safe to display on the dashboard.

    A source that is not running reports null, never 0. Mempool counters live in memory and restart
    from zero with the process; `mempool_counting_since` says when the current count began.
    `chains_protected` counts only the chains whose mempool the monitor read on its last poll
    (`mempool_chains_observable`); a monitored chain it could not read is listed in
    `mempool_chains_unobservable`: its mempool is unknown, not protected.
    `launch_discovery` says how far Robinhood Chain launch discovery has read, from the database
    alone: its lowest source cursor, when a sweep last moved a cursor, and the newest launch block.
    A cursor far below the chain head, or an old `last_sweep_at`, means discovery has stalled.
    Its `scanned_share` counts the launches whose block is in the last 24 hours and how many of
    them have any scan outcome. `evidence_documents` counts the stored verdict evidence documents
    per chain; `registry_records_confirmed` counts those whose record in the Robinhood Chain
    verdict registry is confirmed on-chain. `contracts_scanned` and `threats_detected` count the contracts
    the extension and agent firewalls scored; Telegram, /api/scan and launch scans do not add to them.
    `contracts_scanned` and `transactions_blocked` are all time. `threats_detected` is on record now: it
    counts the contracts whose latest score is high risk, and a rescan overwrites a contract's score.
    Each `_24h` field counts the same table over the last 24 hours (a contract counts when its latest
    scan falls in that window).
    `unknown_ledger` sums, per provider and per chain, how often a provider lookup was answered,
    came back unknown or failed since `counting_since` (core.unknown_ledger); it restarts with the
    process. GET /api/coverage/{chain_id} has one chain's providers in full.
    With BACKGROUND_WORKERS=external the mempool monitor runs in workers.py: every mempool field is
    null, `unknown_ledger` counts this process's lookups only (not the hunter's or the launch
    watch's), and `background_workers_note` says so.
    """
    from services.launch_discovery import CHAIN_ID as LAUNCH_CHAIN_ID
    from services.verdict_publisher import CHAIN_ID as REGISTRY_CHAIN_ID

    db_stats = {}
    launch_discovery = None
    evidence_documents = registry_records_confirmed = None
    if container and container.db:
        db_stats = await container.db.get_platform_stats()
        window_hours = 24
        launch_discovery = {
            "chain_id": LAUNCH_CHAIN_ID,
            **await container.db.get_launch_discovery_status(LAUNCH_CHAIN_ID),
            "scanned_share": {
                "window_hours": window_hours,
                **await container.db.get_launch_scan_share(LAUNCH_CHAIN_ID, time.time() - window_hours * 3600),
            },
        }
        evidence = await container.db.get_verdict_evidence_counts()
        evidence_documents = {chain_id: counts["documents"] for chain_id, counts in evidence.items()}
        registry_records_confirmed = evidence[REGISTRY_CHAIN_ID]["confirmed"] if REGISTRY_CHAIN_ID in evidence else 0

    mempool = {}
    observable = unobservable = None
    if container and container.mempool_monitor and _background_workers == "api":
        mempool = container.mempool_monitor.get_stats()
        unobservable = mempool["unobservable_chains"]
        observable = sorted(set(mempool["monitored_chains"]) - set(unobservable))

    at = db_stats.get("all_time", {})
    day = db_stats.get("last_24h", {})
    stats = {
        "transactions_monitored": mempool.get("total_pending_seen"),
        "contracts_scanned":      at.get("unique_contracts_scanned"),
        "threats_detected":       at.get("threats_detected"),
        "transactions_blocked":   at.get("transactions_blocked"),
        "contracts_scanned_24h":  day.get("scans"),
        "threats_detected_24h":   day.get("threats_detected"),
        "transactions_blocked_24h": day.get("transactions_blocked"),
        "sandwiches_caught":      mempool.get("sandwiches_detected"),
        "suspicious_approvals":   mempool.get("suspicious_approvals"),
        "chains_protected":       len(observable) if observable is not None else None,
        "mempool_chains_observable": observable,
        "mempool_chains_unobservable": unobservable,
        "mempool_counting_since": mempool.get("counting_since"),
        "launch_discovery":       launch_discovery,
        "evidence_documents":     evidence_documents,
        "registry_records_confirmed": registry_records_confirmed,
        "unknown_ledger":         unknown_ledger.summary(),
    }
    if _background_workers == "external":
        stats["background_workers_note"] = _EXTERNAL_WORKERS_NOTE
    return stats


@app.get("/api/verdicts")
async def verdict_vocabulary():
    """The verdict vocabulary and band tables every ShieldBot surface uses, read-only.

    A score is in the first band whose min_score it reaches. risk_level_thresholds are the lowest
    scores at which a stored risk level is HIGH and MEDIUM on this server: the calibrated thresholds,
    or the band table's where that is lower, since a stored level is raised to the band of its score.
    agent_firewall gives the agent firewall's default thresholds and the decisions each
    classification can meet under them. first_verdict describes the interim event of a streamed
    POST /api/firewall (Accept: text/event-stream): sent at most `seconds` after the handler starts,
    always status 'unknown', never a classification in `never`, and only under the listed policy
    modes.
    """
    return verdicts.describe(container.calibration if container else None)


@app.get("/api/coverage/{chain_id}")
async def chain_coverage(chain_id: int):
    """What a scan on this chain can check, from its configuration, and how its providers are answering.

    `capabilities`: `sell_simulation` is honeypot.is, eth_simulateV1, or goplus_reported (no sell is
    simulated; GoPlus's own flags only); `contract_age` and `verification` name the explorer each lookup
    asks (`contract_age` is null where no request can be sent: Robinhood Chain's creation lookup needs
    the Blockscout gateway key, and without it verification is Sourcify alone); `liquidity_lock` says
    whether any real locker is known (with only burn addresses known, lock status is unknown);
    `router_allowlist` counts the swap routers configured as trusted on this chain; `public_mempool` is
    yes when the mempool monitor read this chain on its last poll, unobservable when the chain has a
    public mempool that was not read, and no when it has none; `approvals` says whether a rescue scan
    tries the full approval history (within its deadline; each result's `scanned_blocks` says what
    was read) or only the newest `window_blocks` blocks.
    `provider_health` is this chain's Unknown ledger (core.unknown_ledger): per provider, how many
    lookups were answered, came back unknown or failed since `counting_since`, and the latest outcome;
    `chain_independent` holds providers asked about no chain. A provider with no entry has not been
    asked since the process started. Nothing here sends a request to any provider.
    With BACKGROUND_WORKERS=external this process reads no mempool, so `public_mempool` is never yes,
    and `provider_health` counts this process's lookups only; `background_workers_note` says so.
    """
    _validate_chain_id(chain_id)
    if not container:
        raise HTTPException(status_code=503, detail="Service not available")
    adapter = web3_client._get_adapter(chain_id)
    if not supports_pending_transactions(chain_id):
        public_mempool = "no"
    else:
        mempool = (
            container.mempool_monitor.get_stats()
            if container.mempool_monitor and _background_workers == "api" else None
        )
        observed = mempool and chain_id in set(mempool["monitored_chains"]) - set(mempool["unobservable_chains"])
        public_mempool = "yes" if observed else "unobservable"
    coverage = {
        "chain_id": chain_id,
        "chain_name": adapter.chain_name,
        "capabilities": {
            **adapter.capabilities(),
            "public_mempool": public_mempool,
            "approvals": container.rescue_service.approval_history(chain_id),
        },
        "provider_health": {
            "counting_since": unknown_ledger.counting_since,
            "providers": unknown_ledger.for_chain(chain_id),
            "chain_independent": unknown_ledger.for_chain(None),
        },
    }
    if _background_workers == "external":
        coverage["background_workers_note"] = _EXTERNAL_WORKERS_NOTE
    return coverage


@app.get("/api/base/attestations")
async def base_attestations(limit: int = 25):
    """ShieldBot's attestations on Base EAS, newest first. The attestor was retired on 2026-09-26: no new
    records are written, so this is history."""
    if not container or not container.base_attestation_reader.is_available():
        return {"available": False, "attestations": [], "summary": {}}
    reader = container.base_attestation_reader
    return {
        "available": True,
        "retired_on": "2026-09-26",
        "attestor": reader.attestor_address,
        "explorer": f"https://base.easscan.org/address/{reader.attestor_address}",
        "attestations": await reader.get_recent(limit=limit),
        "summary": await reader.get_summary(),
    }


@app.get("/api/verdict/{chain_id}/{address}")
async def verdict_permalink(chain_id: int, address: str):
    """Latest published ShieldBot verdict for a token, with its evidence document and on-chain record."""
    from core.verdict_evidence import Verdict
    from services.verdict_publisher import MAX_SEND_ATTEMPTS

    _validate_chain_id(chain_id)
    if not web3_client.is_valid_address(address):
        raise HTTPException(status_code=400, detail="Invalid address")
    if not container or not container.db:
        raise HTTPException(status_code=503, detail="Database not available")
    stored = await container.db.get_latest_verdict_evidence(chain_id, address.lower())
    if stored is None:
        raise HTTPException(status_code=404, detail="No verdict published for this address")
    return {
        "chain_id": stored["chain_id"],
        "subject": stored["subject"],
        "verdict": stored["verdict"],
        "verdict_code": int(Verdict[stored["verdict"]]),
        "evidence_hash": stored["evidence_hash"],
        "canonical": stored["canonical"],
        "evidence": json.loads(stored["canonical"]),
        "published_at": stored["created_at"],
        "onchain_status": stored["onchain_status"],
        "registry": stored["registry"],
        "tx_hash": stored["tx_hash"],
        "onchain_error": stored["onchain_error"],
        "verify": (
            "keccak256 of the UTF-8 bytes of `canonical`, exactly as served, must equal evidence_hash. "
            "onchain_status `confirmed`: Robinhood Chain transaction tx_hash emitted "
            "VerdictRecorded(subject, verdict, evidenceHash, observedBlock, timestamp) from `registry` "
            "with this subject, verdict_code, evidence_hash and the evidence's observed_block; this is the "
            "sequencer's soft finality, final on the parent chain once the batch is posted. "
            "`reverted`: transaction tx_hash reverted and recorded nothing. "
            "`pending` and `sending`: queued for, or being sent to, the chain. "
            "`submitted`, `unconfirmed` and `failed`: not yet proven on-chain. Every transaction sent for this "
            "verdict is looked up again periodically, and a mined one makes it `confirmed` or `reverted`; it is "
            f"sent again only until {MAX_SEND_ATTEMPTS} transactions have been signed for it, and after that it "
            "is only looked up. "
            "`off`: this verdict is stored here only and is not recorded on-chain."
        ),
    }


async def _stored_scan_evidence(evidence_hash: str) -> Dict:
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", evidence_hash):
        raise HTTPException(status_code=404, detail="No evidence document with this hash")
    if not container or not container.db:
        raise HTTPException(status_code=503, detail="Database not available")
    stored = await container.db.get_scan_evidence(evidence_hash.lower())
    if stored is None:
        raise HTTPException(status_code=404, detail="No evidence document with this hash")
    return stored


@app.get("/api/evidence/{evidence_hash}")
async def scan_evidence(evidence_hash: str):
    """The evidence document of an /api/firewall or /api/scan verdict, by the evidence_hash its
    response carried (core/scan_evidence.py).

    Public, and rate-limited by IP like every route. A document is kept SCAN_EVIDENCE_RETENTION_DAYS
    (90) days; a hash never stored, or pruned since, is 404.
    """
    stored = await _stored_scan_evidence(evidence_hash)
    return {
        "evidence_hash": evidence_hash.lower(),
        "canonical": stored["canonical"],
        "evidence": json.loads(stored["canonical"]),
        "stored_at": stored["created_at"],
        "expires_at": stored["created_at"] + SCAN_EVIDENCE_RETENTION_DAYS * 86400,
        "verify": (
            "keccak256 of the UTF-8 bytes of `canonical`, exactly as served, must equal evidence_hash. "
            "This is ShieldBot's own record of the verdict it returned and is not recorded on any chain. "
            "`source` `cache`: the verdict was served from the stored scan made at `cached_scan_at`."
        ),
    }


@app.get("/evidence/{evidence_hash}", response_class=HTMLResponse, include_in_schema=False)
async def scan_evidence_page(evidence_hash: str):
    """The same document as a self-contained page: no scripts, every value escaped."""
    stored = await _stored_scan_evidence(evidence_hash)
    return HTMLResponse(
        render_evidence_page(
            evidence_hash.lower(), stored["canonical"],
            stored["created_at"] + SCAN_EVIDENCE_RETENTION_DAYS * 86400,
        ),
        headers={"Content-Security-Policy": EVIDENCE_CSP, "Cache-Control": "no-cache"},
    )


@app.get("/api/admin/signups", include_in_schema=False)
async def admin_signups(request: Request):
    """List all beta signups. Requires ADMIN_SECRET header."""
    admin_secret = request.headers.get("x-admin-secret")
    expected = container.settings.admin_secret if container else ""
    if not expected:
        raise HTTPException(status_code=503, detail="Admin not configured")
    if not admin_secret or not hmac.compare_digest(admin_secret, expected):
        raise HTTPException(status_code=403, detail="Forbidden")
    if not container or not container.db:
        raise HTTPException(status_code=503, detail="Database not available")
    signups = await container.db.get_beta_signups()
    return {"signups": signups, "count": len(signups)}


# --- Watched Deployers (admin) ---

def _require_admin(request: Request):
    """Raise 403 if X-Admin-Secret header is missing or wrong."""
    admin_secret = request.headers.get("x-admin-secret")
    expected = container.settings.admin_secret if container else ""
    if not expected:
        raise HTTPException(status_code=503, detail="Admin not configured")
    if not admin_secret or not hmac.compare_digest(admin_secret, expected):
        raise HTTPException(status_code=403, detail="Forbidden")
    if not container or not container.db:
        raise HTTPException(status_code=503, detail="Database not available")


class WatchDeployerRequest(ChainRequest):
    address: str = Field(..., min_length=1, max_length=64)
    chain_id: int = Field(default=0, ge=0, le=10_000_000)
    reason: str = Field(default="MANUAL", max_length=240)
    severity: str = Field(default="HIGH", max_length=16)

    @field_validator("chain_id")
    @classmethod
    def validate_chain(cls, value):
        return value if value == 0 else _validate_chain_id(value)


@app.post("/api/admin/watch/deployer", include_in_schema=False)
async def watch_deployer_add(req: WatchDeployerRequest, request: Request):
    """Add a deployer address to the watch list. Requires X-Admin-Secret."""
    _require_admin(request)
    if not web3_client.is_valid_address(req.address):
        raise HTTPException(status_code=400, detail="Invalid address")
    await container.db.add_watched_deployer(
        req.address, req.chain_id, req.reason, req.severity,
    )
    return {"ok": True, "address": req.address.lower(), "chain_id": req.chain_id}


@app.delete("/api/admin/watch/deployer/{address}", include_in_schema=False)
async def watch_deployer_remove(address: str, request: Request, chain_id: int = 0):
    """Remove a deployer from the watch list. Requires X-Admin-Secret."""
    if chain_id != 0:
        _validate_chain_id(chain_id)
    _require_admin(request)
    await container.db.remove_watched_deployer(address, chain_id)
    return {"ok": True, "address": address.lower(), "chain_id": chain_id}


@app.get("/api/admin/watch/deployers", include_in_schema=False)
async def watch_deployer_list(request: Request):
    """List all watched deployers. Requires X-Admin-Secret."""
    _require_admin(request)
    deployers = await container.db.get_watched_deployers()
    return {"deployers": deployers, "count": len(deployers)}


@app.get("/api/admin/watch/alerts", include_in_schema=False)
async def watch_alerts_list(request: Request, limit: int = 50):
    """List recent deployment alerts from watched deployers. Requires X-Admin-Secret."""
    _require_admin(request)
    alerts = await container.db.get_deployment_alerts(limit=limit)
    return {"alerts": alerts, "count": len(alerts)}


@app.post("/api/admin/guard-subjects/{chain_id}/{address}", include_in_schema=False)
async def guard_subject_add(chain_id: int, address: str, request: Request):
    """Watch a subject with a verdict confirmed on the configured registry. Requires X-Admin-Secret."""
    _require_admin(request)
    if chain_id != 4663:
        raise HTTPException(status_code=400, detail="Guard watches are only available on chain 4663")
    _validate_chain_id(chain_id)
    if not web3_client.is_valid_address(address):
        raise HTTPException(status_code=400, detail="Invalid address")
    if not await container.db.register_guard_subject(
        chain_id, address.lower(), container.verdict_publisher.registry,
    ):
        raise HTTPException(
            status_code=409, detail="Guard watch cap reached or no confirmed verdict for this subject",
        )
    return {"ok": True, "address": address.lower(), "chain_id": chain_id}


@app.delete("/api/admin/guard-subjects/{chain_id}/{address}", include_in_schema=False)
async def guard_subject_remove(chain_id: int, address: str, request: Request):
    """Opt a subject out of continuous rescans. Requires X-Admin-Secret."""
    _require_admin(request)
    if chain_id != 4663:
        raise HTTPException(status_code=400, detail="Guard watches are only available on chain 4663")
    _validate_chain_id(chain_id)
    if not web3_client.is_valid_address(address):
        raise HTTPException(status_code=400, detail="Invalid address")
    await container.db.unregister_guard_subject(chain_id, address.lower())
    return {"ok": True, "address": address.lower(), "chain_id": chain_id}


class BlacklistConfirmRequest(ChainRequest):
    address: str = Field(..., min_length=1, max_length=64)
    # Omitted: the entry covers every chain.
    chainId: Optional[int] = Field(default=None, ge=1, le=10_000_000)
    reason: Optional[str] = Field(default=None, max_length=240)

    @field_validator("chainId")
    @classmethod
    def validate_chain(cls, value):
        return value if value is None else _validate_chain_id(value)


@app.post("/api/admin/blacklist", include_in_schema=False)
async def blacklist_confirm(req: BlacklistConfirmRequest, request: Request):
    """Confirm an address as a scam: a block-severity match that never expires, replacing a community
    entry for the same address and chain. Requires X-Admin-Secret."""
    _require_admin(request)
    if not web3_client.is_valid_address(req.address):
        raise HTTPException(status_code=400, detail="Invalid address")
    if not await container.scam_db.confirm_scam(req.address, req.chainId, req.reason):
        raise HTTPException(status_code=409, detail="This address is a known legitimate contract and cannot be blacklisted")
    # Off chain only: the BSC verifier and the Base attestor were retired on 2026-09-26; nothing writes to them.
    return {"ok": True, "address": req.address.lower(), "chain_id": req.chainId, "source": "admin"}


@app.delete("/api/admin/blacklist/{address}", include_in_schema=False)
async def blacklist_remove(address: str, request: Request, chain_id: Optional[int] = None):
    """Remove a blacklist entry, community or admin. Without chain_id, removes the entry that covers
    every chain. Requires X-Admin-Secret."""
    _require_admin(request)
    if chain_id is not None:
        _validate_chain_id(chain_id)
    if not web3_client.is_valid_address(address):
        raise HTTPException(status_code=400, detail="Invalid address")
    if not await container.scam_db.remove_from_blacklist(address, chain_id):
        raise HTTPException(status_code=404, detail="No blacklist entry for this address and chain")
    return {"ok": True, "address": address.lower(), "chain_id": chain_id}


# Reason codes the code itself assigns; admin-entered and agent-written reasons are free text and stay private.
_PUBLIC_WATCH_REASONS = {"MANUAL", "SERIAL_SCAMMER"}


@app.get("/api/watch/alerts")
async def public_watch_alerts(request: Request):
    """List recent deployment alerts from watched deployers."""
    if not container or not container.db:
        raise HTTPException(status_code=503, detail="Watch alerts not available")

    client_ip = _get_client_ip(request)
    if not await _watch_alerts_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Watch alerts rate limit exceeded (10/min)."},
        )

    alerts = [
        {
            "deployer_address": alert["deployer_address"],
            "chain_id": alert["chain_id"],
            "new_contract_address": alert["new_contract_address"],
            "watch_reason": alert["watch_reason"] if alert["watch_reason"] in _PUBLIC_WATCH_REASONS else None,
            "created_at": alert["created_at"],
        }
        for alert in await container.db.get_deployment_alerts(limit=50)
    ]
    return {"alerts": alerts, "count": len(alerts)}


# --- Agent Chat ---

@app.post("/api/agent/chat")
async def agent_chat(req: ChatRequest, request: Request):
    if not container or not hasattr(container, 'advisor'):
        raise HTTPException(503, "Agent not available")

    client_ip = _get_client_ip(request)
    if not await chat_limiter.is_allowed(client_ip):
        raise HTTPException(429, "Rate limit exceeded")

    # Bind user_id to the caller so users cannot read/poison each other's history: to the install
    # token when one is sent, which does not depend on the proxy passing the client IP, else to the IP.
    import hashlib
    install_id = request.headers.get("x-install-id")
    if install_id is None:
        bound_user_id = hashlib.sha256(f"{client_ip}:{req.user_id}".encode()).hexdigest()[:24]
    elif _INSTALL_ID_RE.fullmatch(install_id):
        bound_user_id = hashlib.sha256(f"install:{install_id}:{req.user_id}".encode()).hexdigest()[:24]
    else:
        raise HTTPException(400, "X-Install-Id must be 16 to 128 letters, digits, '-' or '_'")

    try:
        result = await container.advisor.chat(bound_user_id, req.message, chain_id=req.chain_id)
        # Advisor returns dict with "text" and optional "scan_data"
        if isinstance(result, dict):
            resp = {"response": result["text"], "user_id": req.user_id}
            if result.get("scan_data"):
                scan_data = result['scan_data']
                alert = format_extension_alert({
                    **scan_data, 'rug_probability': scan_data.get('risk_score') or 0,
                    'risk_archetype': scan_data.get('archetype') or 'unknown',
                })
                resp["scan_data"] = {**scan_data, **_coverage_fields(alert)}
                if alert['status'] == 'unknown':
                    resp['response'] = alert['recommended_action']
            return resp
        # Backward compat: plain string return
        return {"response": result, "user_id": req.user_id}
    except UnsupportedChainError:
        raise
    except Exception as e:
        logger.error(f"Agent chat error: {type(e).__name__}\n{''.join(traceback.format_tb(e.__traceback__))}")
        raise HTTPException(500, "Agent error")


@app.post("/api/agent/explain")
async def agent_explain(req: ExplainRequest, request: Request):
    if not container or not hasattr(container, 'advisor'):
        raise HTTPException(503, "Agent not available")

    client_ip = _get_client_ip(request)
    if not await chat_limiter.is_allowed(client_ip):
        raise HTTPException(429, "Rate limit exceeded")

    try:
        if is_scan_incomplete(req.scan_result):
            alert = format_extension_alert({
                **req.scan_result, 'rug_probability': req.scan_result.get('risk_score') or 0,
            })
            return {"explanation": alert['recommended_action']}
        explanation = await container.advisor.explain_scan(req.scan_result)
        return {"explanation": explanation}
    except UnsupportedChainError:
        raise
    except Exception as e:
        logger.error(f"Agent explain error: {type(e).__name__}\n{''.join(traceback.format_tb(e.__traceback__))}")
        raise HTTPException(500, "Agent error")


# --- Mempool Monitoring ---

@app.get("/api/mempool/alerts")
async def mempool_alerts(request: Request, chain_id: int = None, limit: int = 50):
    """Get recent mempool alerts (sandwich attacks, suspicious approvals)."""
    if chain_id is not None:
        _validate_chain_id(chain_id)
        if not supports_pending_transactions(chain_id):
            raise HTTPException(status_code=400, detail="Pending-transaction monitoring is not available on this chain")
    if not container or not container.mempool_monitor:
        raise HTTPException(status_code=503, detail="Mempool monitor not available")
    if _background_workers == "external":
        raise HTTPException(status_code=503, detail=_EXTERNAL_MEMPOOL_DETAIL)
    limit = max(1, min(limit, 200))
    alerts = container.mempool_monitor.get_alerts(chain_id=chain_id, limit=limit)
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/api/mempool/stats")
async def mempool_stats(request: Request, chain_id: int = None):
    """Get mempool monitoring statistics."""
    if chain_id is not None:
        _validate_chain_id(chain_id)
        if not supports_pending_transactions(chain_id):
            raise HTTPException(status_code=400, detail="Pending-transaction monitoring is not available on this chain")
    if not container or not container.mempool_monitor:
        raise HTTPException(status_code=503, detail="Mempool monitor not available")
    if _background_workers == "external":
        raise HTTPException(status_code=503, detail=_EXTERNAL_MEMPOOL_DETAIL)
    return container.mempool_monitor.get_stats()


# --- Rescue Mode ---

@app.get("/api/rescue/{wallet_address}")
async def rescue_scan(wallet_address: str, chain_id: int = 56):
    """Scan a wallet's active token approvals and assess risk (Rescue Mode).

    Returns risky approvals, Tier 1 alerts with explanations, and
    Tier 2 pre-built revoke transactions for one-click cleanup. When the chain's RPC serves only
    part of the approval history, or none of it, the scan answers status "unknown" with the reason
    and the blocks it read (scanned_blocks), never an error.
    """
    _validate_chain_id(chain_id)
    if not container or not container.rescue_service:
        raise HTTPException(status_code=503, detail="Rescue service not available")

    if not web3_client.is_valid_address(wallet_address):
        raise HTTPException(status_code=400, detail="Invalid wallet address")

    api_key = container.settings.bscscan_api_key
    return await container.rescue_service.scan_approvals(
        wallet_address, chain_id=chain_id, etherscan_api_key=api_key,
    )


# --- Threat Feed API ---

@app.get("/api/threats/feed")
async def threat_feed(
    chain_id: int = None, limit: int = 50, since: float = None, source: str = None,
):
    """Real-time threat intelligence feed.

    Returns recent high-risk detections and mempool alerts.
    Query params:
    - chain_id: filter by chain (optional)
    - limit: max results (default 50, max 200)
    - since: unix timestamp to fetch threats after (optional)
    - source: 'contracts' or 'mempool' returns only that source, so frequent mempool alerts
      cannot crowd contract detections out of the limit (optional)
    """
    if chain_id is not None:
        _validate_chain_id(chain_id)
    if source not in (None, "contracts", "mempool"):
        raise HTTPException(status_code=400, detail="source must be 'contracts' or 'mempool'")
    if not container:
        raise HTTPException(status_code=503, detail="Service not available")

    limit = max(1, min(limit, 200))  # cap between 1 and 200
    threats = []

    # Recent high-risk contract scans from DB: the rows the threat counts in core.database count. The
    # queries interpolate only the code constant verdicts.THREAT_CONDITION, never user input.
    try:
        if source == "mempool":
            cursor = None
        elif chain_id is not None:
            cursor = await container.db._db.execute(f"""
                SELECT address, chain_id, risk_score, risk_level, archetype, flags,
                       last_scanned_at
                FROM contract_scores
                WHERE {verdicts.THREAT_CONDITION} AND chain_id = ?
                ORDER BY last_scanned_at DESC
                LIMIT ?
            """, (int(chain_id), limit))  # nosec B608
        else:
            cursor = await container.db._db.execute(f"""
                SELECT address, chain_id, risk_score, risk_level, archetype, flags,
                       last_scanned_at
                FROM contract_scores
                WHERE {verdicts.THREAT_CONDITION}
                ORDER BY last_scanned_at DESC
                LIMIT ?
            """, (limit,))  # nosec B608
        rows = await cursor.fetchall() if cursor else []

        import json as _json
        for row in rows:
            scanned_at = row[6]
            if since and scanned_at < since:
                continue
            threats.append({
                'type': 'high_risk_contract',
                'address': row[0],
                'chain_id': row[1],
                'risk_score': row[2],
                'risk_level': row[3],
                'archetype': row[4],
                'flags': _json.loads(row[5]) if row[5] else [],
                'detected_at': scanned_at,
            })
    except Exception as e:
        logger.error(f"Threat feed DB error: {type(e).__name__}")

    # Mempool alerts
    mempool_available = chain_id is None or supports_pending_transactions(chain_id)
    mempool_external = _background_workers == "external"
    mempool_alerts = (
        container.mempool_monitor.get_alerts(chain_id=chain_id, limit=limit)
        if mempool_available and not mempool_external and source != "contracts" else []
    )
    for alert in mempool_alerts:
        if since and alert.get('created_at', 0) < since:
            continue
        threats.append({
            'type': f"mempool_{alert['alert_type']}",
            **alert,
        })

    # Sort all by time, most recent first
    threats.sort(key=lambda t: t.get('detected_at') or t.get('created_at', 0), reverse=True)

    response = {
        'threats': threats[:limit],
        'count': len(threats[:limit]),
        'chain_id': chain_id,
    }
    if not mempool_available:
        response['mempool_unavailable'] = "Pending-transaction monitoring is not available on this chain"
    elif mempool_external and source != "contracts":
        response['mempool_unavailable'] = _EXTERNAL_MEMPOOL_DETAIL
    return response


@app.get("/api/launches/{chain_id}")
async def launch_feed(chain_id: int, limit: int = 50, cursor: str = None):
    """Recently discovered token launches, newest first, each with its latest scan outcome.

    The outcome is blocked, watching, cleared, unknown (scan incomplete) or not_scanned, with
    its status and coverage reasons; unknown and not_scanned are never safe. scan.status is
    authoritative: "ok" only for a complete scan. Per-field coverage is included only where the
    hunter recorded it, for blocked launches. impostor_check is the launch's check against
    Robinhood's official token list (official, impostor, collision, none or unknown), or null when
    it was never checked. Each launch links its public verdict at verdict_url.
    scanned_share counts the launches whose block is in the last 24 hours and how many of them
    have any scan outcome. Scans share one small RPC budget and only launches seen trading soon
    after launch are picked, so most launches are never scanned; this says how many were.
    Query params:
    - limit: max results (default 50, max 200)
    - cursor: next_cursor from the previous page (optional)
    """
    from services.launch_discovery import CHAIN_ID as LAUNCH_CHAIN_ID

    _validate_chain_id(chain_id)
    if not container:
        raise HTTPException(status_code=503, detail="Service not available")

    limit = max(1, min(limit, 200))  # cap between 1 and 200
    if chain_id != LAUNCH_CHAIN_ID:
        return {
            'launches': [],
            'count': 0,
            'chain_id': chain_id,
            'next_cursor': None,
            'discovery_unavailable': "Launch discovery is not available on this chain",
        }
    try:
        launches, next_cursor = await container.db.get_launch_feed(chain_id, limit, cursor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid cursor") from exc
    window_hours = 24
    scanned_share = await container.db.get_launch_scan_share(chain_id, time.time() - window_hours * 3600)
    return {
        'launches': launches,
        'count': len(launches),
        'chain_id': chain_id,
        'next_cursor': next_cursor,
        'scanned_share': {'window_hours': window_hours, **scanned_share},
    }


@app.get("/api/threats/subscribe")
async def threat_subscribe_info():
    """Information about threat feed subscription options."""
    return {
        'endpoints': {
            'rest_polling': '/api/threats/feed?since=<unix_timestamp>',
        },
        'supported_chains': list(web3_client.get_supported_chain_ids()) if web3_client else [],
        'alert_types': [
            'high_risk_contract',
            'mempool_sandwich_attack',
            'mempool_suspicious_approval',
        ],
    }


# --- Helpers ---

def _chain_id_to_name(chain_id: int) -> str:
    """Map chain_id to a human-readable network name."""
    return get_chain_name(chain_id)


# Campaign risk boost thresholds
_SERIAL_SCAMMER_THRESHOLD = 2   # HIGH-risk contracts to trigger campaign boost
_CAMPAIGN_BOOST_LOW  = 15       # boost for 2–3 HIGH-risk prior contracts
_CAMPAIGN_BOOST_HIGH = 25       # boost for 4+ HIGH-risk prior contracts


async def _get_deployer_campaign_context(contract_addr: str, chain_id: int, container) -> Optional[Dict]:
    """Check if contract_addr was deployed by a known serial scammer.

    Queries the already-indexed deployers + contract_scores tables for a fast in-DB lookup.
    Returns a campaign context dict, or None if the deployer has a clean (or unknown) history.
    Side effect: auto-adds serial scammers to the watched_deployers list.
    """
    try:
        summary = await container.db.get_deployer_risk_summary(contract_addr, chain_id)
        if not summary or summary["high_risk_contracts"] < _SERIAL_SCAMMER_THRESHOLD:
            return None

        n = summary["high_risk_contracts"]
        boost = _CAMPAIGN_BOOST_HIGH if n >= 4 else _CAMPAIGN_BOOST_LOW
        label = "serial scammer" if n >= 4 else "repeat scammer"
        signal = f"Deployer has {n} HIGH RISK contracts on record ({label} pattern)"

        # Auto-add to watch list if not already there
        try:
            existing = await container.db.is_watched_deployer(summary["deployer_address"])
            if not existing:
                await container.db.add_watched_deployer(
                    summary["deployer_address"], 0, "SERIAL_SCAMMER", "HIGH",
                    summary["total_contracts"], n,
                )
        except UnsupportedChainError:
            raise
        except Exception:
            pass

        return {
            "deployer_address": summary["deployer_address"],
            "total_contracts": summary["total_contracts"],
            "high_risk_contracts": n,
            "is_serial_scammer": True,
            "danger_signal": signal,
            "risk_boost": boost,
        }
    except UnsupportedChainError:
        raise
    except Exception as e:
        logger.debug(f"Campaign context lookup failed for {contract_addr}: {type(e).__name__}")
        return None


def _format_decoded_action(decoded: Dict, chain_id: int) -> str:
    """Convert decoded calldata into a plain English action label for the overlay."""
    func = decoded.get("function_name", "")
    category = decoded.get("category", "")
    params = decoded.get("params", {})

    if not func or func == "Native Transfer":
        return f"Native {get_native_symbol(chain_id) or 'Coin'} Transfer"

    if category == "approval":
        spender_label = _approval_spender(decoded) or "an unknown spender"
        if decoded.get("is_unlimited_approval"):
            return f"UNLIMITED Approval to {spender_label}"
        if "permit" in func.lower():
            return f"Gas-less Permit to {spender_label}"
        return f"Token Approval to {spender_label}"

    if category == "transfer":
        if func == "transfer":
            recipient = params.get("param_0", "")
        elif func == "transferFrom":
            recipient = params.get("param_1", "")
        else:
            recipient = params.get("param_0", "")
        return f"Token Transfer to {_checksum_if_possible(str(recipient))}"

    if category == "swap":
        return "DEX Token Swap"

    if category == "liquidity":
        return "Add Liquidity" if "add" in func.lower() else "Remove Liquidity"

    if category == "supply":
        return "Mint Tokens" if func == "mint" else "Burn Tokens"

    if category == "claim":
        return "Claim Reward / Airdrop"

    if func.startswith("Unknown"):
        selector = decoded.get("selector", "")
        return f"Unknown Function (0x{selector})"

    return func


def _short_addr(addr: str) -> str:
    """Shorten an address to '0x1234...abcd' format."""
    if not addr or not isinstance(addr, str):
        return str(addr)
    if len(addr) > 12:
        return f"{addr[:6]}...{addr[-4:]}"
    return addr


def _build_calldata_details(decoded: Dict) -> Dict:
    """Build structured calldata breakdown for the extension overlay."""
    func = decoded.get("function_name", "Unknown")
    category = decoded.get("category", "unknown")
    params = decoded.get("params", {})
    fields = []

    if category == "approval":
        granted = _granting_access(decoded)
        fields = [
            {"label": "Function", "value": func},
            {"label": "Spender", "value": _approval_spender(decoded) or "Unknown"},
            {"label": "Grants", "value": granted, "danger": granted in ("UNLIMITED", "ALL tokens in the collection")},
        ]
    elif category == "transfer":
        if func == "transferFrom":
            frm = params.get("param_0", "")
            to = params.get("param_1", "")
            amount = params.get("param_2")
            fields = [
                {"label": "Function", "value": func},
                {"label": "From", "value": _short_addr(str(frm))},
                {"label": "To", "value": _checksum_if_possible(str(to))},
                {"label": "Amount", "value": str(amount) if amount is not None else "Unknown"},
            ]
        else:
            to = params.get("param_0", "")
            amount = params.get("param_1")
            fields = [
                {"label": "Function", "value": func},
                {"label": "To", "value": _checksum_if_possible(str(to))},
                {"label": "Amount", "value": str(amount) if amount is not None else "Unknown"},
            ]
    elif category == "swap":
        # Find the address[] path param
        path = None
        for v in params.values():
            if isinstance(v, list) and len(v) >= 2 and all(isinstance(x, str) for x in v):
                path = v
                break
        fields = [{"label": "Function", "value": func}]
        if path:
            path_str = " → ".join(_short_addr(a) for a in path)
            fields.append({"label": "Token Path", "value": path_str})
    elif category == "claim":
        fields = [
            {"label": "Function", "value": func},
            {"label": "Type", "value": "Claim Rewards / Airdrop"},
        ]
    elif category == "supply":
        fields = [
            {"label": "Function", "value": func},
            {"label": "Type", "value": "Mint" if func == "mint" else "Burn"},
        ]
    else:
        fields = [{"label": "Function", "value": func}]

    return {"category": category, "fields": fields}


# Where the decoder puts each approval function's spender and amount (None when
# it does not decode it: Permit2 keeps both inside a struct).
_APPROVAL_PARAMS = {
    "approve": ("param_0", "param_1"),
    "increaseAllowance": ("param_0", "param_1"),
    "setApprovalForAll": ("param_0", None),
    "permit": ("param_1", "param_2"),
    "permit (DAI-style)": ("param_1", None),
    "permit (Permit2)": (None, None),
    "permit (Permit2 batch)": (None, None),
}
# Approval functions that grant or revoke with a boolean, and the label when they grant.
_APPROVAL_FLAG_PARAM = {
    "setApprovalForAll": ("param_1", "ALL tokens in the collection"),
    "permit (DAI-style)": ("param_4", "UNLIMITED"),
}


# Universal Router execute(): its commands can include a Permit2 permit.
_UNIVERSAL_ROUTER_EXECUTE = "3593564c"


def _approval_spender(decoded: Dict) -> Optional[str]:
    """The approved spender: its known name, else its checksummed address, else None."""
    param = _APPROVAL_PARAMS.get(decoded.get("function_name"), (None, None))[0]
    spender = decoded.get("params", {}).get(param) if param else None
    return decoded.get("spender_label") or (_checksum_if_possible(str(spender)) if spender else None)


def _native_symbol(chain_id: int) -> str:
    return get_native_symbol(chain_id) or "native coin"


def _sending(decoded: Dict, value_bnb: float, chain_id: int, tokens: str) -> str:
    """The Sending row: the native amount, nothing for a bare approval, else tokens."""
    if value_bnb > 0:
        return f"{value_bnb:g} {_native_symbol(chain_id)}"
    return "Nothing (approval only)" if decoded.get("is_approval") else tokens


def _granting_access(decoded: Dict) -> str:
    """Say what spending rights a call grants. "None" only when it grants nothing."""
    if decoded.get("selector") == _UNIVERSAL_ROUTER_EXECUTE:
        return "Unknown (may include a Permit2 permit)"
    if decoded.get("category", "unknown") == "unknown":
        return "Unknown"
    if not decoded.get("is_approval"):
        return "None"
    func = decoded.get("function_name")
    params = decoded.get("params", {})
    if func in _APPROVAL_FLAG_PARAM:
        param, granted = _APPROVAL_FLAG_PARAM[func]
        flag = params.get(param)
        if flag is None:
            return "Approval, amount unknown"
        return granted if flag else "None (revokes access)"
    if decoded.get("is_unlimited_approval"):
        return "UNLIMITED"
    amount_param = _APPROVAL_PARAMS.get(func, (None, None))[1]
    amount = params.get(amount_param) if amount_param else None
    if not isinstance(amount, int):
        return "Approval, amount unknown"
    if decoded.get("formatted_amount"):
        return "None (amount is 0)" if amount == 0 else f"Limited approval: {decoded['formatted_amount']}"
    if func == "approve":
        # approve() shares its selector with ERC-721 approve(to, tokenId). Without
        # the token's decimals the number may be an NFT id, and 0 may be token #0.
        return f"Approval: {amount} (raw amount or NFT token id)"
    return "None (amount is 0)" if amount == 0 else f"Limited approval: {amount} (raw token units)"


def _build_asset_delta_fallback(decoded: Dict, value_bnb: float, chain_id: int) -> List:
    """Construct basic asset_delta from calldata when simulation is unavailable."""
    deltas = []
    if value_bnb > 0:
        deltas.append(f"-{value_bnb:g} {_native_symbol(chain_id)}")
    if decoded.get("is_approval"):
        deltas.append(f"Access granted: {_granting_access(decoded)}")
    return deltas


def _simulated(simulation_result: Optional[Dict]) -> bool:
    """Whether a response's asset changes are a Tenderly simulation's: one ran, succeeded and returned
    them. The extension labels asset changes simulated only then; otherwise they are read from the
    calldata, or a notice."""
    return bool(simulation_result and simulation_result.get("success") and simulation_result.get("asset_deltas"))


def _build_asset_delta(
    simulation_result: Optional[Dict], decoded: Dict, value_bnb: float, chain_id: int,
) -> List:
    """Build asset_delta list for the extension response.

    Uses simulation deltas when available and simulation succeeded.
    When simulation reverted (e.g. bridge/cross-chain tx), falls back to a
    human-readable notice instead of the misleading native balance_diff.
    """
    if simulation_result:
        if simulation_result.get("success") and simulation_result.get("asset_deltas"):
            return [d["display"] for d in simulation_result["asset_deltas"]]
        if not simulation_result.get("success"):
            # Simulation reverted — common for bridge/cross-chain transactions.
            # Do not show native BNB delta (msg.value relay fee) as if it were
            # the full picture. Show a clear notice instead.
            return ["Unable to simulate — cross-chain or complex transaction. Verify manually."]
    return _build_asset_delta_fallback(decoded, value_bnb, chain_id)


def _coverage_fields(alert: Dict) -> Dict:
    return {key: alert[key] for key in ('status', 'coverage', 'coverage_reasons', 'risk_display')}


def _revert_blocks(risk_output: Dict) -> bool:
    """Whether a reverted simulation escalates a verdict to BLOCK: only a risk already elevated,
    verdicts.REVERT_BLOCK_MIN or more before the community floor. Low-risk reverts are just bad
    transaction parameters. Reading the score before that floor, three accounts' reports neither turn a
    routine revert (slippage, a deadline, an allowance) into a block nor keep a risky target's revert
    from one."""
    return risk_output["score_before_community_floor"] >= verdicts.REVERT_BLOCK_MIN


def _scam_match_count(scan: Dict) -> Optional[int]:
    # A community report is not a scam database match; its reason names it instead.
    matches = database_matches(scan.get("scam_matches"))
    if matches:
        return len(matches)
    if scan.get("coverage", {}).get("scam_database") is False:
        return None
    return 0


def _build_cached_response(
    cached: Dict, decoded: Dict, value_bnb: float, chain_id: int = 56,
    to_addr: str = "", policy_mode: str = PolicyMode.BALANCED.value,
) -> Dict:
    """Build a firewall response from a cached DB row."""
    risk_score = cached['risk_score']
    risk_level = cached.get('risk_level', verdicts.UNKNOWN)
    flags = cached.get('flags', [])
    archetype = cached.get('archetype', 'unknown')

    category_scores = dict(cached.get('category_scores', {}))
    metadata = category_scores.pop('_scan_metadata', {})
    # STRICT blocks what core.policy blocked on the fresh scan: a failed required check, which the row
    # keeps as failed_sources. A row written without them (before they were stored, or by a path with
    # no policy engine) does not say which fields were missing, so any Unknown in it blocks.
    failed_sources = metadata.get('failed_sources')
    failed = bool(failed_sources) if failed_sources is not None else is_scan_incomplete(
        {**metadata, 'risk_level': risk_level}
    )
    if policy_mode == PolicyMode.STRICT.value and failed:
        risk_score = max(risk_score, verdicts.STRICT_BLOCK_SCORE)
        risk_level = verdicts.HIGH
        flags = ['Policy override: cached analysis unavailable or incomplete', *flags]
    alert = format_extension_alert({
        **metadata, 'rug_probability': risk_score, 'risk_level': risk_level,
        'critical_flags': flags, 'risk_archetype': archetype or 'unknown',
        'confidence_level': cached.get('confidence', 0),
    })
    classification = alert['risk_classification']

    return {
        **_coverage_fields(alert),
        "classification": classification,
        "risk_score": risk_score,
        "decoded_action": _format_decoded_action(decoded, chain_id),
        "calldata_details": _build_calldata_details(decoded),
        "danger_signals": flags,
        "transaction_impact": {
            "sending": _sending(decoded, value_bnb, chain_id, "Tokens"),
            "granting_access": _granting_access(decoded),
            "recipient": to_addr or "Unknown",
            "post_tx_state": f"Risk archetype: {archetype}",
        },
        "analysis": f"Cached result (scanned {cached.get('scan_count', 1)} times)",
        "plain_english": alert['recommended_action'],
        "verdict": f"{classification} — Rug probability {alert['risk_display']} (cached)",
        "raw_checks": {
            "risk_score_heuristic": risk_score,
        },
        "shield_score": {
            **_coverage_fields(alert),
            "overall": risk_score,
            "category_scores": category_scores,
            "risk_level": risk_level,
            "threat_type": archetype,
            "critical_flags": flags,
            "confidence": cached.get('confidence', 0),
        },
        "simulation": None,
        "asset_delta": _build_asset_delta_fallback(decoded, value_bnb, chain_id),
        "simulated": False,
        "greenfield_url": None,
        "cached": True,
        "chain_id": chain_id,
        "network": _chain_id_to_name(chain_id),
        "partial": alert['status'] == 'unknown',
        "failed_sources": metadata.get('failed_sources', []),
        "policy_mode": policy_mode,
        "notes": metadata.get('notes', []),
    }


def _extract_raw_checks(scan: Dict) -> Dict:
    """Extract key raw check values for the extension."""
    return {
        "is_verified": scan.get("is_verified"),
        "scam_matches": _scam_match_count(scan),
        "contract_age_days": scan.get("contract_age_days"),
        "is_honeypot": scan.get("is_honeypot"),
        "ownership_renounced": scan.get("checks", {}).get("ownership_renounced"),
        "buy_tax": scan.get('buy_tax'),
        "sell_tax": scan.get('sell_tax'),
        "can_sell": scan.get('checks', {}).get('can_sell'),
        "risk_score_heuristic": scan.get("risk_score"),
    }


# The legacy scan sees only the target, never the transaction's spender, payment or signature, so
# it cannot clear a transaction-specific request.
_TX_CHECKS_UNAVAILABLE = "Transaction checks unavailable: the spender, payment or signature was not analysed"
# Nor does it check the scam database (the token scanner never asks it) or the calldata's intent, so its
# heuristics alone never clear a transaction.
_FULL_ANALYSIS_UNAVAILABLE = (
    "Full analysis unavailable: heuristic results only, scam database and calldata intent not checked"
)


def _build_fallback_response(
    decoded: Dict, scan: Dict, whitelisted: Optional[str], chain_id: int, transaction_specific: bool = False,
    policy_mode: str = PolicyMode.BALANCED.value,
) -> Dict:
    """Build a firewall response from the legacy scan when the analysis pipeline failed. The score and
    classification come from the scan's heuristics and the band table only."""
    risk_score = scan.get("risk_score")
    if risk_score is None:
        # A scan with no heuristic score is Unknown, not a number made up for it.
        scan = {**scan, 'status': 'unknown', 'coverage_reasons': {
            **scan.get('coverage_reasons', {}), 'risk_score': 'Heuristic risk score unavailable',
        }}
        risk_score = 0
    scam_matches = _scam_match_count(scan)
    is_honeypot = scan.get("is_honeypot")
    is_verified = scan.get("is_verified")
    is_unlimited_approval = decoded.get("is_unlimited_approval", False)

    danger_signals = []

    # The engine's floors for the same evidence, so a scam match or a honeypot scores here what it
    # scores on the composite path.
    if scam_matches is not None and scam_matches > 0:
        danger_signals.append(f"Found {scam_matches} scam database match(es)")

    for match in medium_matches(scan.get("scam_matches")):
        danger_signals.append(match["reason"])

    risk_score = max(risk_score, scam_match_floor(scan.get("scam_matches")))

    if is_honeypot:
        danger_signals.append("Honeypot detected — cannot sell after buying")
        risk_score = max(risk_score, HONEYPOT_FLOOR)

    if is_unlimited_approval and is_verified is False:
        danger_signals.append("Unlimited approval to unverified contract")
        risk_score = max(risk_score, 85)

    if is_verified is False:
        danger_signals.append("Contract source code is not verified")
    elif is_verified is None:
        danger_signals.append("Contract source verification unknown")

    if whitelisted:
        risk_score = max(0, risk_score - 20)

    # STRICT blocks a degraded analysis, as core.policy does an incomplete one. The fallback has no
    # policy engine to say which required checks failed, so under STRICT it blocks whatever it covers.
    strict = policy_mode == PolicyMode.STRICT.value
    if strict:
        risk_score = max(risk_score, verdicts.STRICT_BLOCK_SCORE)
        danger_signals.insert(0, 'Policy override: composite analysis unavailable')

    alert = format_extension_alert({**scan, 'rug_probability': risk_score})
    classification = verdicts.BLOCK_RECOMMENDED if strict else alert['risk_classification']
    action = alert['recommended_action']
    if classification == verdicts.SAFE:
        classification = verdicts.CAUTION
        danger_signals.append(_FULL_ANALYSIS_UNAVAILABLE)
        action = f'{_FULL_ANALYSIS_UNAVAILABLE}. Review the transaction before proceeding.'
        if transaction_specific:
            danger_signals.append(_TX_CHECKS_UNAVAILABLE)

    return {
        **_coverage_fields(alert),
        "partial": alert['status'] == 'unknown',
        "classification": classification,
        "risk_score": min(100, risk_score),
        "decoded_action": _format_decoded_action(decoded, chain_id),
        "calldata_details": _build_calldata_details(decoded),
        "danger_signals": danger_signals,
        "transaction_impact": {
            "sending": "Unknown (AI unavailable)",
            "granting_access": _granting_access(decoded),
            "recipient": scan.get("address", "Unknown"),
            "post_tx_state": "AI analysis unavailable — review manually",
        },
        "analysis": "AI analysis unavailable. Showing heuristic results only.",
        "plain_english": action,
        "verdict": (f"{classification} — {alert['risk_display']}" if alert['status'] == 'unknown'
                    else f"{classification} — Risk score {risk_score}/100"),
        "raw_checks": _extract_raw_checks(scan),
        "asset_delta": [],
        "simulated": False,
        "policy_mode": policy_mode,
        "notes": [],
    }


def _extract_swap_path(decoded: Dict, raw_calldata: str = "") -> List[str]:
    """Extract token swap path from decoded calldata.

    For Universal Router (execute selector 3593564c), delegates to the dedicated
    parser that walks the nested commands/inputs ABI structure.
    For standard V2 routers, scans decoded params for an address[].
    """
    if not decoded:
        return []

    # Universal Router: path is buried inside inputs[i] bytes — needs dedicated decode
    if decoded.get("selector") == "3593564c" and raw_calldata and calldata_decoder:
        path = calldata_decoder.decode_universal_router_path(raw_calldata)
        if path:
            return path

    # Standard V2 routers: path is a top-level address[] param
    params = decoded.get("params", {})
    for v in params.values():
        if isinstance(v, list) and v and all(isinstance(x, str) and x.startswith("0x") for x in v):
            return v
    return []


def _select_router_tokens(path: List[str]) -> List[str]:
    """Select every distinct token in a swap path."""
    return list(dict.fromkeys(token.lower() for token in path))


def _build_unverified_swap_response(
    req: FirewallRequest, to_addr: str, decoded: Dict, whitelisted: str, value_bnb: float,
    source: str, reason: str, policy_mode: str = PolicyMode.BALANCED.value,
) -> Dict:
    """Build a CAUTION response for a trusted-router swap whose path tokens were not analyzed. Under
    STRICT it blocks, as the legacy fallback does a degraded analysis.

    Returning None instead would make the main pipeline analyse the whitelisted
    router itself, which always scores safe, while the swapped tokens are never checked.
    """
    coverage_fields = {
        "status": "unknown",
        "coverage": {source: 0},
        "coverage_reasons": {source: reason},
        "risk_display": 'Unknown (incomplete provider coverage)',
    }
    classification = verdicts.CAUTION
    risk_score = verdicts.CAUTION_MIN
    danger_signals = [f"Swap via trusted router ({whitelisted}) but {reason.lower()} — token safety unverified"]
    strict = policy_mode == PolicyMode.STRICT.value
    if strict:
        classification = verdicts.BLOCK_RECOMMENDED
        risk_score = verdicts.STRICT_BLOCK_SCORE
        danger_signals.insert(0, 'Policy override: swap path tokens not analysed')
    return {
        "classification": classification,
        **coverage_fields,
        "risk_score": risk_score,
        "decoded_action": _format_decoded_action(decoded, req.chainId),
        "calldata_details": _build_calldata_details(decoded),
        "danger_signals": danger_signals,
        "transaction_impact": {
            "sending": _sending(decoded, value_bnb, req.chainId, "Tokens (via router)"),
            "granting_access": _granting_access(decoded),
            "recipient": f"{whitelisted} ({to_addr})",
            "post_tx_state": f"Swap via {whitelisted} — {reason.lower()}",
        },
        "analysis": (
            f"Trusted router ({whitelisted}) detected but {reason.lower()}. "
            "Token safety cannot be verified."
        ),
        "plain_english": (
            "This transaction goes to a trusted DEX router, but the tokens in the swap "
            "path could not be checked. Verify the tokens manually before proceeding."
        ),
        "verdict": f"{classification} — Token safety unverifiable",
        "raw_checks": {
            "is_verified": None,
            "scam_matches": None,
            "contract_age_days": None,
            "is_honeypot": None,
            "ownership_renounced": None,
            "risk_score_heuristic": risk_score,
            "whitelisted_router": whitelisted,
            "tokens_analyzed": [],
        },
        "shield_score": {
            **coverage_fields,
            "overall": risk_score,
            "category_scores": {},
            # As core.policy sets it when STRICT blocks.
            "risk_level": verdicts.HIGH if strict else verdicts.UNKNOWN,
            "threat_type": "unknown",
            "critical_flags": [],
            "confidence": 30,
        },
        "simulation": None,
        "asset_delta": _build_asset_delta_fallback(decoded, value_bnb, req.chainId),
        "simulated": False,
        "greenfield_url": None,
        "chain_id": req.chainId,
        "network": _chain_id_to_name(req.chainId),
        "partial": True,
        "failed_sources": [source],
        "policy_mode": policy_mode,
        "notes": [],
    }


async def _analyze_router_swap(
    req: FirewallRequest,
    to_addr: str,
    from_addr: str,
    decoded: Dict,
    whitelisted: str,
    value_bnb: float,
    policy_override: Optional[str] = None,
    trail: Optional[Dict] = None,
    progress: Optional[FirstVerdictProgress] = None,
    policy_mode: str = PolicyMode.BALANCED.value,
) -> Optional[Dict]:
    """Analyze swap path tokens when interacting with a trusted router. `policy_mode` is the
    effective mode `policy_override` selects, which a response for unanalysed tokens reports.

    When it returns a verdict from the tokens' analyzers, it records their outcomes, keyed
    "token:analyzer" like the response's coverage, and the observed block in `trail`.
    A streamed request's `progress` hears each token's results, keyed token:analyzer as well.
    """
    if not container or not container.registry or not risk_engine:
        return _build_unverified_swap_response(
            req, to_addr, decoded, whitelisted, value_bnb,
            'token_analysis', 'Token analyzers are unavailable', policy_mode,
        )

    path = _extract_swap_path(decoded, req.data)
    if not path or not any(web3_client.is_valid_address(token) for token in path):
        # Cannot decode the swap path (e.g. Uniswap V3 / aggregator calldata).
        return _build_unverified_swap_response(
            req, to_addr, decoded, whitelisted, value_bnb,
            'token_path', 'Token path could not be decoded', policy_mode,
        )

    candidates = _select_router_tokens(path)
    if not candidates:
        return None

    # Optional simulation (still useful for asset deltas)
    sim_result = None
    if tenderly_simulator and tenderly_simulator.is_enabled():
        sim_result = await tenderly_simulator.simulate_transaction(
            to_address=to_addr, from_address=from_addr,
            value=req.value, data=req.data, chain_id=req.chainId,
        )

    best = None
    token_summaries = []
    outcomes = {}
    all_results = []
    notes = []

    for token in candidates:
        if not web3_client.is_valid_address(token):
            continue
        token_addr = web3_client.to_checksum_address(token)

        is_verified = None
        try:
            verified_result = await web3_client.is_verified_contract(token_addr, chain_id=req.chainId)
            is_verified = verified_result[0] if isinstance(verified_result, tuple) else verified_result
        except UnsupportedChainError:
            raise
        except Exception:
            pass

        from core.analyzer import AnalysisContext

        ctx = AnalysisContext(
            address=token_addr,
            chain_id=req.chainId,
            from_address=from_addr,
            is_token=True,
            extra={
                'calldata': req.data,
                'value': req.value,
                'typed_data': req.typedData,
                'sign_method': req.signMethod,
                'is_verified': is_verified,
                'router': to_addr,
                'whitelisted_router': whitelisted,
            },
        )

        run_options = {}
        if progress is not None:
            progress.expect(token_addr, [analyzer.name for analyzer in container.registry.get_all()])
            run_options = {"on_result": partial(progress.add_result, token=token_addr)}
        analyzer_results = await container.registry.run_all(ctx, **run_options)
        risk_output = risk_engine.compute_from_results(analyzer_results, is_token=True)

        # Apply policy mode (handles partial failures)
        if container.policy_engine:
            risk_output = container.policy_engine.apply(
                analyzer_results, risk_output, mode_override=policy_override,
            )

        token_summaries.append({
            **_coverage_fields(format_extension_alert(risk_output)),
            "address": token_addr,
            "risk_score": risk_output.get("rug_probability", 0),
            "risk_level": risk_output.get("risk_level", verdicts.UNKNOWN),
        })
        outcomes.update({
            f"{token_addr}:{name}": outcome
            for name, outcome in analyzer_outcomes(analyzer_results, risk_output).items()
        })
        all_results += analyzer_results
        notes += [f"{token_addr}: {note}" for note in risk_output.get("notes", [])]

        if not best or risk_output.get("rug_probability", 0) > best["risk_output"].get("rug_probability", 0):
            best = {"address": token_addr, "risk_output": risk_output, "results": analyzer_results}

    if not best:
        return None

    risk_output = dict(best["risk_output"])
    unknown_tokens = [item for item in token_summaries if item['status'] == 'unknown']
    if unknown_tokens or len(token_summaries) != len(candidates):
        risk_output['status'] = 'unknown'
        if risk_output.get('risk_level') == verdicts.LOW:
            risk_output['risk_level'] = verdicts.UNKNOWN
        risk_output['coverage_reasons'] = {
            f"{item['address']}:{source}": reason
            for item in unknown_tokens for source, reason in item['coverage_reasons'].items()
        }
        if len(token_summaries) != len(candidates):
            risk_output['coverage_reasons']['token_path'] = 'Invalid token address in swap path'
    risk_output['coverage'] = {
        f"{item['address']}:{source}": fraction
        for item in token_summaries for source, fraction in item['coverage'].items()
    }
    if sim_result is not None and sim_result.get('success') is False:
        risk_output['status'] = 'unknown'
        risk_output['coverage']['transaction_simulation'] = 0
        risk_output['coverage_reasons'] = {
            **risk_output.get('coverage_reasons', {}),
            'transaction_simulation': sim_result.get('revert_reason') or 'Transaction simulation failed',
        }
    alert = format_extension_alert(risk_output)

    # Simulation overrides
    danger_signals = list(alert["top_flags"])
    classification = alert["risk_classification"]

    if sim_result:
        if not sim_result.get("success") and sim_result.get("revert_reason"):
            danger_signals.insert(0, f"Simulation reverted: {sim_result['revert_reason']}")
            if _revert_blocks(risk_output):
                classification = verdicts.BLOCK_RECOMMENDED
        for w in sim_result.get("warnings", []):
            if w not in danger_signals:
                danger_signals.append(w)

    risk_score = alert["rug_probability"]

    # Extract service data for raw checks
    by_name = {r.name: r for r in best["results"]}
    contract_data = (by_name["structural"].data or {}) if "structural" in by_name else {}
    honeypot_data = (by_name["honeypot"].data or {}) if "honeypot" in by_name else {}

    shield_score = {
        **_coverage_fields(alert),
        "overall": risk_score,
        "category_scores": risk_output.get("category_scores", {}),
        "risk_level": risk_output.get("risk_level", verdicts.UNKNOWN),
        "threat_type": risk_output.get("risk_archetype", "unknown"),
        "critical_flags": risk_output.get("critical_flags", []),
        "confidence": alert["confidence"],
    }

    if trail is not None:
        trail.update(analyzers=outcomes, observed_block=oldest_simulation_block(all_results))

    return {
        **_coverage_fields(alert),
        "classification": classification,
        "risk_score": risk_score,
        "decoded_action": _format_decoded_action(decoded, req.chainId),
        "calldata_details": _build_calldata_details(decoded),
        "danger_signals": danger_signals,
        "transaction_impact": {
            "sending": _sending(decoded, value_bnb, req.chainId, "Tokens (via router)"),
            "granting_access": _granting_access(decoded),
            "recipient": f"{whitelisted} ({to_addr})",
            "post_tx_state": f"Swap via {whitelisted} — analyzed {best['address'][:10]}...",
        },
        "analysis": f"Trusted router detected ({whitelisted}), analyzed swap path tokens.",
        "plain_english": alert["recommended_action"],
        "verdict": f"{classification} — Rug probability {alert['risk_display']}",
        "raw_checks": {
            "is_verified": contract_data.get("is_verified"),
            "scam_matches": _scam_match_count(contract_data),
            "contract_age_days": contract_data.get("contract_age_days"),
            "is_honeypot": honeypot_data.get("is_honeypot"),
            "buy_tax": honeypot_data.get("buy_tax"),
            "sell_tax": honeypot_data.get("sell_tax"),
            "can_sell": honeypot_data.get("can_sell"),
            "ownership_renounced": contract_data.get("ownership_renounced"),
            "risk_score_heuristic": risk_score,
            "whitelisted_router": whitelisted,
            "tokens_analyzed": token_summaries,
        },
        "shield_score": shield_score,
        "simulation": sim_result,
        "asset_delta": _build_asset_delta(sim_result, decoded, value_bnb, req.chainId),
        "simulated": _simulated(sim_result),
        "greenfield_url": None,
        "chain_id": req.chainId,
        "network": _chain_id_to_name(req.chainId),
        "partial": alert['status'] == 'unknown' or risk_output.get("partial", False),
        "failed_sources": risk_output.get("failed_sources", []),
        "policy_mode": risk_output.get("policy_mode", PolicyMode.BALANCED.value),
        "notes": notes,
    }


# Token info cache: "address:chain_id" -> (data, timestamp)
_token_cache: Dict[str, tuple] = {}
_TOKEN_CACHE_TTL = 3600  # 1 hour
_TOKEN_CACHE_MAX = 5000  # max entries before eviction


def _parse_value(value_str: str) -> int:
    """Parse hex or decimal value string to int wei."""
    if not value_str:
        return 0
    try:
        if value_str.startswith("0x") or value_str.startswith("0X"):
            return int(value_str, 16)
        return int(value_str)
    except (ValueError, TypeError):
        return 0


async def _resolve_token(address: str, chain_id: int = 56) -> Optional[Dict]:
    """Resolve token symbol/name/decimals. Returns cached result if available."""
    if not address or not web3_client.is_valid_address(address):
        return None

    cache_key = f"{address.lower()}:{chain_id}"
    cached = _token_cache.get(cache_key)
    if cached and (time.time() - cached[1]) < _TOKEN_CACHE_TTL:
        return cached[0]

    try:
        info = await web3_client.get_token_info(address, chain_id=chain_id)
        if info.get("symbol"):
            result = {
                "symbol": info["symbol"],
                "name": info.get("name", ""),
                "decimals": info.get("decimals", 18),
            }
            # Evict oldest entries if cache is full
            if len(_token_cache) >= _TOKEN_CACHE_MAX:
                oldest_key = min(_token_cache, key=lambda k: _token_cache[k][1])
                del _token_cache[oldest_key]
            _token_cache[cache_key] = (result, time.time())
            return result
    except UnsupportedChainError:
        raise
    except Exception:
        pass

    return None


async def _enrich_decoded(decoded: Dict, to_addr: str, chain_id: int = 56):
    """
    Enrich decoded calldata with token names and formatted amounts.
    Modifies decoded dict in-place, adding human_readable fields.
    """
    if not decoded or decoded.get("selector") is None:
        return

    category = decoded.get("category", "")
    params = decoded.get("params", {})

    # For approvals: resolve the token being approved (the `to` address is the token)
    if decoded.get("is_approval"):
        token_info = await _resolve_token(to_addr, chain_id=chain_id)
        if token_info:
            decoded["token_symbol"] = token_info["symbol"]
            decoded["token_name"] = token_info["name"]

            spender_param, amount_param = _APPROVAL_PARAMS.get(decoded.get("function_name"), (None, None))

            # Format the approval amount
            amount = params.get(amount_param) if amount_param else None
            if isinstance(amount, int):
                if amount >= UNLIMITED_THRESHOLD:
                    decoded["formatted_amount"] = f"UNLIMITED {token_info['symbol']}"
                else:
                    decimals = token_info.get("decimals", 18)
                    human_amount = amount / (10 ** decimals)
                    number = f"{human_amount:,.4f}".rstrip("0").rstrip(".")
                    if number == "0" and amount:
                        number = f"{human_amount:.4g}"
                    decoded["formatted_amount"] = f"{number} {token_info['symbol']}"

            # Resolve the spender address
            spender = params.get(spender_param) if spender_param else None
            if spender:
                spender_name = calldata_decoder.is_whitelisted_target(spender)
                if spender_name:
                    decoded["spender_label"] = spender_name

    # For transfers: resolve the token
    elif category == "transfer":
        token_info = await _resolve_token(to_addr, chain_id=chain_id)
        if token_info:
            decoded["token_symbol"] = token_info["symbol"]
            decoded["token_name"] = token_info["name"]

            amount = params.get("param_1")  # transfer amount
            if isinstance(amount, int):
                decimals = token_info.get("decimals", 18)
                human_amount = amount / (10 ** decimals)
                decoded["formatted_amount"] = f"{human_amount:g} {token_info['symbol']}"

    # Resolve unknown selectors via OpenChain API
    if decoded.get("category") == "unknown" and decoded.get("selector"):
        resolved_name = await resolve_selector(decoded["selector"])
        if resolved_name:
            decoded["function_name"] = resolved_name
