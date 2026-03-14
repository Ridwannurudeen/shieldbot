"""
ShieldAI Firewall API
FastAPI backend for the Chrome extension transaction firewall
Runs alongside bot.py on the VPS
"""

import os
import hmac
import time
import asyncio
import logging
import random
from collections import defaultdict
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Dict, Any, List

from utils.calldata_decoder import CalldataDecoder, UNLIMITED_THRESHOLD
from core.config import Settings
from core.container import ServiceContainer
from core.extension_formatter import format_extension_alert
from rpc.router import rpc_router
from rpc.proxy import RPCProxy

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


# --- Rate Limiter ---

class RateLimiter:
    """In-memory sliding window rate limiter per IP."""

    def __init__(self, requests_per_minute: int = 30, burst: int = 10):
        self.rpm = requests_per_minute
        self.burst = burst
        self.window = 60.0  # seconds
        self._hits: Dict[str, list] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]

        # Prune expired entries
        cutoff = now - self.window
        while hits and hits[0] < cutoff:
            hits.pop(0)

        if len(hits) >= self.rpm:
            return False

        # Burst check: no more than `burst` requests in 5 seconds
        burst_cutoff = now - 5.0
        recent = sum(1 for t in hits if t >= burst_cutoff)
        if recent >= self.burst:
            return False

        hits.append(now)
        return True

    def cleanup(self):
        """Remove stale IPs (call periodically if needed)."""
        now = time.monotonic()
        cutoff = now - self.window * 2
        stale = [k for k, v in self._hits.items() if not v or v[-1] < cutoff]
        for k in stale:
            del self._hits[k]


rate_limiter = RateLimiter(requests_per_minute=30, burst=10)
chat_limiter = RateLimiter(requests_per_minute=50, burst=10)


# Service container (initialized on startup)
container: Optional[ServiceContainer] = None

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
token_gate_service = None
advisor = None

SHIELDBOT_TOKEN_ADDRESS = "0x4904c02efa081cb7685346968bac854cdf4e7777"

# Nonce store for token-gate signature verification: wallet -> (nonce, expires_at)
import secrets
from eth_account.messages import encode_defunct
from web3 import Web3 as _Web3

_nonce_store: Dict[str, tuple[str, float]] = {}
_NONCE_TTL = 300  # 5 minutes


def _issue_nonce(wallet: str) -> str:
    """Issue a random nonce for wallet signature verification."""
    nonce = secrets.token_hex(16)
    _nonce_store[wallet.lower()] = (nonce, time.time() + _NONCE_TTL)
    return nonce


def _verify_wallet_signature(wallet: str, signature: str, nonce: str) -> bool:
    """Verify that `signature` was produced by `wallet` over the expected message."""
    key = wallet.lower()
    stored = _nonce_store.get(key)
    if not stored or stored[0] != nonce or time.time() > stored[1]:
        return False
    # Consume nonce (one-time use)
    _nonce_store.pop(key, None)
    message_text = f"ShieldBot alert access: {nonce}"
    try:
        message = encode_defunct(text=message_text)
        recovered = _Web3().eth.account.recover_message(message, signature=signature)
        return recovered.lower() == key
    except Exception:
        return False


def _bind_globals(c: ServiceContainer):
    """Bind module-level names to container services for backward compat."""
    global web3_client, ai_analyzer, tx_scanner, token_scanner, calldata_decoder
    global scam_db, dex_service, ethos_service, honeypot_service, contract_service
    global risk_engine, greenfield_service, tenderly_simulator, token_gate_service
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
    token_gate_service = c.token_gate_service
    advisor = c.advisor


@asynccontextmanager
async def lifespan(app: FastAPI):
    global container
    settings = Settings()
    container = ServiceContainer(settings)
    _bind_globals(container)
    await container.startup()

    # Initialize RPC proxy if enabled
    if settings.rpc_proxy_enabled:
        rpc_proxy = RPCProxy(container)
        app.state.rpc_proxy = rpc_proxy
        logger.info("RPC Proxy enabled")

    await container.hunter.start()

    logger.info("ShieldAI Firewall API started")
    yield
    await container.hunter.stop()
    await container.shutdown()
    rpc_proxy = getattr(app.state, "rpc_proxy", None)
    if rpc_proxy:
        await rpc_proxy.close()
    logger.info("ShieldAI Firewall API shutting down")


app = FastAPI(
    title="ShieldAI Firewall API",
    version="1.0.4",
    lifespan=lifespan,
)

# Mount RPC proxy router
app.include_router(rpc_router)

# Serve Vite-built landing page assets (hashed JS/CSS bundles)
app.mount("/assets", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "landing", "assets")), name="landing-assets")

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
    if container and container.settings:
        return set(container.settings.trusted_proxies)
    return TRUSTED_PROXIES


def _get_client_ip(request: Request) -> str:
    """Resolve client IP, trusting X-Forwarded-For only from known proxies."""
    client_ip = request.client.host if request.client else ""
    forwarded = request.headers.get("x-forwarded-for")
    trusted = _get_trusted_proxies()
    if forwarded and client_ip in trusted:
        return forwarded.split(",")[-1].strip()
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
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Skip rate limiting for health checks
    if request.url.path in ("/", "/api/health", "/test", "/webhook/uptime"):
        return await call_next(request)

    # Check for API key authentication
    api_key = request.headers.get("x-api-key")
    if api_key and container and container.auth_manager:
        key_info = await container.auth_manager.validate_key(api_key)
        if not key_info:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid API key"},
            )
        if not await container.auth_manager.check_rate_limit(key_info):
            return JSONResponse(
                status_code=429,
                content={"detail": "API key rate limit exceeded"},
            )
        # Record usage (fire-and-forget)
        try:
            await container.auth_manager.record_usage(key_info["key_id"], request.url.path)
        except Exception:
            pass
        # Store key info for downstream use
        request.state.api_key_info = key_info
        return await call_next(request)

    # Fallback: IP-based rate limiting (extension/unauthenticated)
    client_ip = _get_client_ip(request)

    # Probabilistic cleanup of stale rate-limiter entries (1% of requests)
    if random.random() < 0.01:
        rate_limiter.cleanup()

    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}")
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Please wait before trying again."},
        )

    return await call_next(request)


# --- Request / Response Models ---

class FirewallRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    to: str
    sender: str = Field(alias="from")
    value: str = "0"
    data: str = "0x"
    chainId: int = 56
    typedData: Optional[Dict] = None
    signMethod: Optional[str] = None


class ScanRequest(BaseModel):
    address: str
    chainId: int = 56


class OutcomeRequest(BaseModel):
    address: str
    chainId: int = 56
    risk_score_at_scan: Optional[float] = None
    user_decision: str  # "proceed", "block", "ignore"
    outcome: Optional[str] = None  # "safe", "scam", "unknown"
    tx_hash: Optional[str] = None


class CommunityReportRequest(BaseModel):
    address: str
    chainId: int = 56
    report_type: str  # "false_positive", "false_negative", "scam"
    reason: Optional[str] = None


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    user_id: str = Field(..., min_length=1, max_length=100)


class ExplainRequest(BaseModel):
    scan_result: Dict[str, Any]


# Report rate limiter: 5 reports/min per IP
_report_limiter = RateLimiter(requests_per_minute=5, burst=3)

# Beta-signup rate limiter: 3 signups/min per IP
_signup_limiter = RateLimiter(requests_per_minute=3, burst=2)

# Public watch alerts: 10 requests/min per IP
_watch_alerts_limiter = RateLimiter(requests_per_minute=10, burst=5)


# --- Endpoints ---

@app.get("/", include_in_schema=False)
async def landing_page():
    """Marketing landing page."""
    landing_path = os.path.join(os.path.dirname(__file__), "landing", "index.html")
    return FileResponse(landing_path, media_type="text/html")


class BetaSignupRequest(BaseModel):
    email: str


@app.post("/api/beta-signup")
async def beta_signup(req: BetaSignupRequest, request: Request):
    """Collect beta signup emails."""
    # Rate limit per IP
    client_ip = _get_client_ip(request)
    if not _signup_limiter.is_allowed(f"signup:{client_ip}"):
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
                logger.error(f"Beta welcome email failed: {e}")
        return {"message": "You're on the list! We'll be in touch."}
    return JSONResponse(
        status_code=409,
        content={"detail": "This email is already signed up."},
    )


@app.post("/webhook/uptime")
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
        msg = f"🚨 *ShieldBot DOWN*\n`{monitor_name}` is unreachable.\nURL: `{monitor_url}`\n{details}"
    elif alert_type == "2":
        msg = f"✅ *ShieldBot Recovered*\n`{monitor_name}` is back online.\nURL: `{monitor_url}`"
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
    Results are cached server-side for 1 hour per domain.
    No API key required — rate-limited by IP via the existing middleware.
    """
    if not container or not container.phishing_service:
        raise HTTPException(status_code=503, detail="Service unavailable")

    result = await container.phishing_service.check_url(url)
    return result


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "shieldai-firewall",
        "supported_chains": [56, 1, 8453, 42161, 137, 10, 204],
    }


@app.get("/dashboard")
async def threat_dashboard():
    """Public real-time threat intelligence dashboard."""
    import os
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard", "index.html")
    return FileResponse(dashboard_path, media_type="text/html")


@app.get("/test-phishing", response_class=HTMLResponse)
async def test_phishing_page():
    """Stable test page for the phishing banner.

    The PhishingService always flags test-phishing.shieldbotsecurity.online,
    so loading this page with the extension installed will reliably trigger
    the red warning banner — no dependency on live phishing sites.
    """
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ShieldBot Phishing Banner Test</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
           display: flex; align-items: center; justify-content: center;
           min-height: 100vh; margin: 0; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px;
            padding: 32px; max-width: 480px; text-align: center; }
    h1 { color: #ef4444; margin: 0 0 12px; }
    p  { color: #94a3b8; line-height: 1.6; margin: 0; }
  </style>
</head>
<body>
  <div class="card">
    <h1>&#9888; Phishing Test Page</h1>
    <p>This page is intentionally flagged by ShieldBot for testing purposes.<br><br>
       If the extension is installed and enabled, you should see a red warning
       banner at the top of this page.</p>
  </div>
</body>
</html>"""


@app.get("/test", response_class=HTMLResponse)
async def test_page():
    """Test page for the Chrome extension — simulates wallet transactions."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ShieldBot Extension Test</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #0a0a0a; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 40px 20px; }
    .container { max-width: 640px; margin: 0 auto; }
    h1 { color: #00ff88; margin-bottom: 8px; font-size: 28px; }
    .subtitle { color: #888; margin-bottom: 32px; }
    .card { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 24px; margin-bottom: 16px; }
    .card h3 { color: #fff; margin-bottom: 12px; }
    .card p { color: #aaa; font-size: 14px; margin-bottom: 16px; line-height: 1.5; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
    .badge-danger { background: #ff444433; color: #ff4444; border: 1px solid #ff444466; }
    .badge-safe { background: #00ff8833; color: #00ff88; border: 1px solid #00ff8866; }
    .badge-warn { background: #ffaa0033; color: #ffaa00; border: 1px solid #ffaa0066; }
    .addr { font-family: monospace; font-size: 12px; color: #888; word-break: break-all; background: #111; padding: 4px 8px; border-radius: 4px; display: block; margin-bottom: 12px; }
    button { padding: 12px 24px; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; width: 100%; transition: opacity 0.2s; }
    button:hover { opacity: 0.85; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-danger { background: #ff4444; color: white; }
    .btn-safe { background: #00ff88; color: black; }
    .btn-warn { background: #ffaa00; color: black; }
    #log { background: #111; border: 1px solid #333; border-radius: 8px; padding: 16px; margin-top: 24px; font-family: monospace; font-size: 13px; max-height: 300px; overflow-y: auto; white-space: pre-wrap; }
    .log-entry { margin-bottom: 4px; }
    .log-info { color: #00ff88; }
    .log-warn { color: #ffaa00; }
    .log-error { color: #ff4444; }
    .log-block { color: #ff4444; font-weight: bold; }
    .status { display: flex; align-items: center; gap: 8px; margin-bottom: 24px; padding: 12px 16px; background: #1a1a1a; border-radius: 8px; }
    .dot { width: 10px; height: 10px; border-radius: 50%; }
    .dot-green { background: #00ff88; box-shadow: 0 0 6px #00ff88; }
    .dot-red { background: #ff4444; }
    .dot-yellow { background: #ffaa00; animation: pulse 1s infinite; }
    @keyframes pulse { 50% { opacity: 0.5; } }
  </style>
</head>
<body>
  <div class="container">
    <h1>ShieldBot Extension Test</h1>
    <p class="subtitle">Simulate wallet transactions to test the extension's firewall</p>

    <div class="status" id="status">
      <div class="dot dot-yellow" id="statusDot"></div>
      <span id="statusText">Checking extension...</span>
    </div>

    <div class="card">
      <h3>Honeypot Token <span class="badge badge-danger">BLOCK_RECOMMENDED</span></h3>
      <p>Confirmed honeypot with 100% sell tax. Extension should show a <strong style="color:#ff4444">red BLOCK modal</strong> and prevent the transaction.</p>
      <code class="addr">0xdbda907a02750f79cbf0414f7112eabe5091c286</code>
      <button class="btn-danger" onclick="sendTx('0xdbda907a02750f79cbf0414f7112eabe5091c286', '0x2386F26FC10000', this)">
        Send 0.01 BNB to Honeypot
      </button>
    </div>

    <div class="card">
      <h3>PancakeSwap Router <span class="badge badge-safe">SAFE</span></h3>
      <p>Whitelisted DEX router. Extension should <strong style="color:#00ff88">allow silently</strong> without any modal.</p>
      <code class="addr">0x10ED43C718714eb63d5aA57B78B54704E256024E</code>
      <button class="btn-safe" onclick="sendTx('0x10ED43C718714eb63d5aA57B78B54704E256024E', '0x2386F26FC10000', this)">
        Swap on PancakeSwap
      </button>
    </div>

    <div class="card">
      <h3>Unverified Contract <span class="badge badge-warn">CAUTION</span></h3>
      <p>Random unverified address. Extension should show an <strong style="color:#ffaa00">orange warning modal</strong>.</p>
      <code class="addr">0x3ee505ba316879d246760e89f0a29a4403afa498</code>
      <button class="btn-warn" onclick="sendTx('0x3ee505ba316879d246760e89f0a29a4403afa498', '0x2386F26FC10000', this)">
        Send to Unverified Contract
      </button>
    </div>

    <div id="log"><span class="log-info">Waiting for test...</span></div>
  </div>

  <script>
    const MOCK_SENDER = '0x742d35Cc6634C0532925a3b844Bc9e7595f42bE1';
    const logEl = document.getElementById('log');

    function log(msg, cls = 'log-info') {
      const ts = new Date().toLocaleTimeString();
      logEl.innerHTML += '\\n<span class="' + cls + '">[' + ts + '] ' + msg + '</span>';
      logEl.scrollTop = logEl.scrollHeight;
    }

    // Detect extension by checking for injected elements and flags
    function detectExtension() {
      // v1 flags
      if (window.__shieldai_injected) return 'v1';
      if (window.ethereum && window.ethereum.__shieldai_proxied) return 'v1';
      // v2 flags
      if (window.__shieldbot_injected) return 'v2';
      if (window.ethereum && window.ethereum.__shieldbot_proxied) return 'v2';
      // Check for extension-injected link/script elements
      const links = document.querySelectorAll('link[href*="chrome-extension"]');
      if (links.length > 0) return 'v1';
      const scripts = document.querySelectorAll('script[src*="chrome-extension"]');
      if (scripts.length > 0) return 'v1';
      return null;
    }

    // Get the actual wallet account (or use mock if no wallet)
    let activeAccount = MOCK_SENDER;

    async function initWallet() {
      if (window.ethereum) {
        log('Real wallet detected: ' + (window.ethereum.isMetaMask ? 'MetaMask' : 'Unknown'));
        try {
          const accounts = await window.ethereum.request({ method: 'eth_accounts' });
          if (accounts && accounts.length > 0) {
            activeAccount = accounts[0];
            log('Connected account: ' + activeAccount);
          } else {
            log('No accounts connected — click Connect Wallet below', 'log-warn');
          }
        } catch (e) {
          log('Could not get accounts: ' + e.message, 'log-warn');
        }
      } else {
        // No wallet — install mock provider
        log('No wallet detected — installing mock provider');
        window.ethereum = {
          isMetaMask: true,
          chainId: '0x38',
          selectedAddress: MOCK_SENDER,
          request: async function(args) {
            log('Mock wallet received: ' + args.method);
            if (args.method === 'eth_sendTransaction') {
              return '0x' + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join('');
            }
            if (args.method === 'eth_chainId') return '0x38';
            if (args.method === 'eth_accounts') return [MOCK_SENDER];
            if (args.method === 'eth_requestAccounts') return [MOCK_SENDER];
            return null;
          },
        };
        window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {
          detail: { info: { name: 'MockWallet' }, provider: window.ethereum }
        }));
      }
    }

    setTimeout(initWallet, 200);

    // Poll for extension detection (inject.js loads async)
    let pollCount = 0;
    const pollMax = 25; // 5 seconds total
    const pollInterval = setInterval(() => {
      pollCount++;
      const dot = document.getElementById('statusDot');
      const text = document.getElementById('statusText');
      const version = detectExtension();

      if (version) {
        clearInterval(pollInterval);
        dot.className = 'dot dot-green';
        text.textContent = 'ShieldBot extension active (' + version + ') — firewall is intercepting transactions';
        log('Extension detected: ' + version + ' | __shieldai_injected=' + !!window.__shieldai_injected + ' | proxied=' + !!(window.ethereum && window.ethereum.__shieldai_proxied));
        return;
      }

      if (pollCount >= pollMax) {
        clearInterval(pollInterval);
        dot.className = 'dot dot-red';
        text.textContent = 'Extension NOT detected';
        log('Extension not found after ' + (pollMax * 200) + 'ms', 'log-error');
        log('Debug: __shieldai_injected=' + !!window.__shieldai_injected + ', __shieldbot_injected=' + !!window.__shieldbot_injected, 'log-error');
        log('Debug: ethereum exists=' + !!window.ethereum + ', proxied(v1)=' + !!(window.ethereum && window.ethereum.__shieldai_proxied) + ', proxied(v2)=' + !!(window.ethereum && window.ethereum.__shieldbot_proxied), 'log-error');
        log('Debug: extension elements=' + document.querySelectorAll('[href*="chrome-extension"],[src*="chrome-extension"]').length, 'log-error');
        log('Make sure extension is loaded in chrome://extensions from: shieldbot/extension/', 'log-warn');
      }
    }, 200);

    async function connectWallet() {
      if (!window.ethereum) { log('No wallet found', 'log-error'); return; }
      try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        if (accounts && accounts.length > 0) {
          activeAccount = accounts[0];
          log('Connected: ' + activeAccount);
        }
      } catch (e) {
        log('Connect failed: ' + e.message, 'log-error');
      }
    }

    async function sendTx(to, value, btn) {
      if (activeAccount === MOCK_SENDER && window.ethereum && window.ethereum.isMetaMask) {
        log('Connecting wallet first...', 'log-warn');
        await connectWallet();
      }

      const originalText = btn.textContent;
      btn.textContent = 'Analyzing...';
      btn.disabled = true;

      log('Sending eth_sendTransaction from ' + activeAccount.substring(0, 10) + '... to ' + to.substring(0, 10) + '...', 'log-warn');

      try {
        const result = await window.ethereum.request({
          method: 'eth_sendTransaction',
          params: [{
            from: activeAccount,
            to: to,
            value: value,
            data: '0x',
          }],
        });
        log('Transaction allowed! Hash: ' + result, 'log-info');
      } catch (err) {
        if (err.message.includes('Shield') || err.message.includes('blocked') || err.message.includes('Firewall')) {
          log('BLOCKED: ' + err.message, 'log-block');
        } else if (err.message.includes('canceled') || err.message.includes('denied') || err.message.includes('rejected')) {
          log('User rejected: ' + err.message, 'log-warn');
        } else {
          log('Error: ' + err.message, 'log-error');
        }
      } finally {
        btn.textContent = originalText;
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>"""


@app.post("/api/firewall")
async def firewall(req: FirewallRequest, request: Request):
    """
    Main firewall endpoint — intercepts a pending transaction,
    analyzes calldata + target contract, and returns a security verdict.
    """
    try:
        to_addr = req.to
        from_addr = req.sender

        if not web3_client.is_valid_address(to_addr):
            raise HTTPException(status_code=400, detail="Invalid 'to' address")

        to_addr = web3_client.to_checksum_address(to_addr)

        # 1. Decode calldata
        decoded = calldata_decoder.decode(req.data)
        # Use chain-specific adapter for router lookup when available
        _adapter = container.web3_client._get_adapter(req.chainId) if container else None
        whitelisted = calldata_decoder.is_whitelisted_target(to_addr, chain_id=req.chainId, adapter=_adapter)

        # Resolve value
        value_wei = _parse_value(req.value)
        value_bnb = value_wei / 1e18

        # Enrich decoded calldata with token names and formatted amounts
        await _enrich_decoded(decoded, to_addr, chain_id=req.chainId)

        # 2. If target is a whitelisted router, analyze the swap path tokens instead of bypassing
        if whitelisted:
            router_response = await _analyze_router_swap(
                req=req,
                to_addr=to_addr,
                from_addr=from_addr,
                decoded=decoded,
                whitelisted=whitelisted,
                value_bnb=value_bnb,
                policy_override=request.headers.get("X-Policy-Mode"),
            )
            if router_response:
                return router_response

        # 2b. Check cache for recent result
        if container and container.db:
            cached = await container.db.get_contract_score(to_addr, req.chainId, max_age_seconds=300)
            if cached:
                policy_mode = container.settings.policy_mode if container else "BALANCED"
                req_policy = request.headers.get("X-Policy-Mode")
                return _build_cached_response(
                    cached, decoded, value_bnb, req.chainId,
                    to_addr=to_addr, policy_mode=req_policy or policy_mode,
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
            is_token = True
            is_verified = False
            try:
                is_token = await web3_client.is_token_contract(to_addr, chain_id=req.chainId)
            except Exception:
                pass
            try:
                verified_result = await web3_client.is_verified_contract(to_addr, chain_id=req.chainId)
                is_verified = verified_result[0] if isinstance(verified_result, tuple) else bool(verified_result)
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
                    container.registry.run_all(ctx), sim_task,
                )
            elif container and container.registry:
                analyzer_results = await container.registry.run_all(ctx)
                simulation_result = None
            else:
                # Fallback: no container (e.g. tests), use old 4-service gather
                gather_tasks = [
                    contract_service.fetch_contract_data(to_addr, chain_id=req.chainId),
                    honeypot_service.fetch_honeypot_data(to_addr, chain_id=req.chainId),
                    dex_service.fetch_token_market_data(to_addr),
                    ethos_service.fetch_wallet_reputation(from_addr),
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
                contract_data = {}
                honeypot_data = {}
                dex_data = {}
                ethos_data = {}

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
                    # Only escalate to BLOCK if risk is already elevated (>= 30)
                    # Low-risk reverts are just bad tx params, not malicious
                    if alert["rug_probability"] >= 30:
                        classification = "BLOCK_RECOMMENDED"
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
                    if risk_score >= 71:
                        classification = "BLOCK_RECOMMENDED"

            # Shield score breakdown
            shield_score = {
                "overall": risk_score,
                "category_scores": risk_output.get("category_scores", {}),
                "risk_level": risk_output.get("risk_level", "UNKNOWN"),
                "threat_type": risk_output.get("risk_archetype", "unknown"),
                "critical_flags": risk_output.get("critical_flags", []),
                "confidence": alert["confidence"],
            }

            # Build response
            response = {
                "classification": classification,
                "risk_score": risk_score,
                "decoded_action": _format_decoded_action(decoded),
                "calldata_details": _build_calldata_details(decoded),
                "danger_signals": danger_signals,
                "transaction_impact": {
                    "sending": f"{value_bnb:g} BNB" if value_bnb > 0 else "Tokens",
                    "granting_access": "UNLIMITED" if decoded.get("is_unlimited_approval") else "None",
                    "recipient": f"{to_addr[:10]}...",
                    "post_tx_state": f"Risk archetype: {alert['risk_archetype']}",
                },
                "analysis": f"Composite risk analysis — archetype: {alert['risk_archetype']}, confidence: {alert['confidence']}%",
                "plain_english": alert["recommended_action"],
                "verdict": f"{classification} — Rug probability {risk_score}%",
                "raw_checks": {
                    "is_verified": contract_data.get("is_verified", False),
                    "scam_matches": len(contract_data.get("scam_matches", [])),
                    "contract_age_days": contract_data.get("contract_age_days"),
                    "is_honeypot": honeypot_data.get("is_honeypot", False),
                    "ownership_renounced": contract_data.get("ownership_renounced", False),
                    "risk_score_heuristic": risk_score,
                    "whitelisted_router": whitelisted,
                },
                "shield_score": shield_score,
                "simulation": simulation_result,
                "asset_delta": _build_asset_delta(simulation_result, decoded, value_bnb),
                "greenfield_url": None,
                "chain_id": req.chainId,
                "network": _chain_id_to_name(req.chainId),
                "partial": risk_output.get("partial", False),
                "failed_sources": risk_output.get("failed_sources", []),
                "policy_mode": risk_output.get("policy_mode", "BALANCED"),
                "campaign_context": _deployer_ctx,
            }

            # Persist contract score to DB
            if container and container.db:
                try:
                    await container.db.upsert_contract_score(
                        address=to_addr,
                        chain_id=req.chainId,
                        risk_score=risk_score,
                        risk_level=risk_output.get("risk_level", "UNKNOWN"),
                        archetype=risk_output.get("risk_archetype"),
                        category_scores=risk_output.get("category_scores"),
                        flags=risk_output.get("critical_flags"),
                        confidence=alert.get("confidence"),
                    )
                except Exception as e:
                    logger.error(f"DB upsert failed: {e}")

            # Sentinel feedback loop: auto-watch deployers of blocked contracts
            if container and hasattr(container, 'sentinel') and classification == "BLOCK_RECOMMENDED":
                try:
                    deployer_info = await container.db.get_deployer_risk_summary(to_addr, req.chainId)
                    deployer_addr = deployer_info["deployer_address"] if deployer_info else None
                    asyncio.create_task(container.sentinel.on_scan_blocked(
                        address=to_addr,
                        deployer=deployer_addr,
                        chain_id=req.chainId,
                        risk_score=risk_score,
                    ))
                except Exception as e:
                    logger.error(f"Sentinel feedback failed: {e}")

            # Enqueue deployer indexing (fire-and-forget)
            if container and container.indexer:
                container.indexer.enqueue(to_addr, req.chainId)

            # Greenfield upload for risky transactions (risk >= 50)
            if greenfield_service and greenfield_service.is_enabled() and risk_score >= 50:
                try:
                    gf_url = await greenfield_service.upload_report(
                        target_address=to_addr,
                        risk_score=risk_score,
                        category_scores=risk_output.get("category_scores", {}),
                        full_analysis={
                            "classification": response.get("classification"),
                            "danger_signals": response.get("danger_signals"),
                            "raw_checks": response.get("raw_checks"),
                        },
                    )
                    response["greenfield_url"] = gf_url
                except Exception as e:
                    logger.error(f"Greenfield upload failed: {e}")

            return response

        except Exception as e:
            logger.warning(f"Composite pipeline failed for {to_addr}, falling back: {e}")

        # 4. Fallback: legacy scanner + AI firewall
        is_token = False
        contract_scan = {}
        try:
            is_token = await web3_client.is_token_contract(to_addr, chain_id=req.chainId)
        except Exception:
            pass

        if is_token:
            contract_scan = await token_scanner.check_token(to_addr, chain_id=req.chainId)
        else:
            contract_scan = await tx_scanner.scan_address(to_addr, chain_id=req.chainId)

        contract_scan.pop("forensic_report", None)
        contract_scan.pop("source_code", None)

        tx_data = {
            "to": to_addr,
            "from": from_addr,
            "value": req.value,
            "data": req.data,
            "chainId": req.chainId,
            "decoded_calldata": decoded,
            "whitelisted_router": whitelisted,
        }

        firewall_result = None
        if ai_analyzer and ai_analyzer.is_available():
            firewall_result = await ai_analyzer.generate_firewall_report(tx_data, contract_scan)

        if firewall_result:
            firewall_result["raw_checks"] = _extract_raw_checks(contract_scan)
            firewall_result.setdefault("asset_delta", [])
            return firewall_result
        else:
            return _build_fallback_response(decoded, contract_scan, whitelisted)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Firewall error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


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

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/outcome")
async def report_outcome(req: OutcomeRequest):
    """Record a user decision/outcome for a scanned contract (extension reports back)."""
    try:
        if container and container.db:
            await container.db.record_outcome(
                address=req.address,
                chain_id=req.chainId,
                risk_score_at_scan=req.risk_score_at_scan,
                user_decision=req.user_decision,
                outcome=req.outcome,
                tx_hash=req.tx_hash,
            )
        return {"status": "recorded"}
    except Exception as e:
        logger.error(f"Outcome recording error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/report")
async def community_report(req: CommunityReportRequest, request: Request):
    """Record a community report (false positive, false negative, or scam)."""
    # Rate limit per IP (rightmost = proxy-set, not spoofable)
    client_ip = _get_client_ip(request)
    if not _report_limiter.is_allowed(f"report:{client_ip}"):
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
                reporter_id=client_ip,
                reason=req.reason,
            )
        return {"status": "recorded", "address": req.address, "report_type": req.report_type}
    except Exception as e:
        logger.error(f"Community report error: {e}", exc_info=True)
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
    return {"key_id": key_info["key_id"], "tier": key_info["tier"], "usage": usage}


@app.get("/api/campaign/{address}")
async def campaign_graph(address: str, chain_id: int = None):
    """Get cross-chain deployer/funder campaign graph for an address.

    Enhanced with campaign detection: cross-chain correlation, funder clustering,
    and coordinated scam campaign indicators.
    """
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


@app.post("/api/keys")
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


@app.get("/api/admin/stats")
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
    if container.mempool_monitor:
        mempool = container.mempool_monitor.get_stats()

    # Phishing cache size (server-side, in-memory)
    phishing_cache_size = 0
    if container.phishing_service:
        phishing_cache_size = len(container.phishing_service._cache)

    return {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        **db_stats,
        "mempool": mempool,
        "phishing": {
            "domains_cached": phishing_cache_size,
        },
    }


@app.get("/api/stats")
async def public_stats():
    """Public platform statistics — safe to display on the dashboard."""
    db_stats = {}
    if container and container.db:
        db_stats = await container.db.get_platform_stats()

    mempool = {}
    if container and container.mempool_monitor:
        mempool = container.mempool_monitor.get_stats()

    at = db_stats.get("all_time", {})
    return {
        "transactions_monitored": mempool.get("total_pending_seen", 0),
        "contracts_scanned":      at.get("unique_contracts_scanned", 0),
        "threats_detected":       at.get("threats_detected", 0),
        "transactions_blocked":   at.get("transactions_blocked", 0),
        "sandwiches_caught":      mempool.get("sandwiches_detected", 0),
        "suspicious_approvals":   mempool.get("suspicious_approvals", 0),
        "chains_protected":       len(mempool.get("monitored_chains", [])),
    }


@app.get("/api/admin/signups")
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


class WatchDeployerRequest(BaseModel):
    address: str
    chain_id: int = 0
    reason: str = "MANUAL"
    severity: str = "HIGH"


@app.post("/api/admin/watch/deployer")
async def watch_deployer_add(req: WatchDeployerRequest, request: Request):
    """Add a deployer address to the watch list. Requires X-Admin-Secret."""
    _require_admin(request)
    if not web3_client.is_valid_address(req.address):
        raise HTTPException(status_code=400, detail="Invalid address")
    await container.db.add_watched_deployer(
        req.address, req.chain_id, req.reason, req.severity,
    )
    return {"ok": True, "address": req.address.lower(), "chain_id": req.chain_id}


@app.delete("/api/admin/watch/deployer/{address}")
async def watch_deployer_remove(address: str, request: Request, chain_id: int = 0):
    """Remove a deployer from the watch list. Requires X-Admin-Secret."""
    _require_admin(request)
    await container.db.remove_watched_deployer(address, chain_id)
    return {"ok": True, "address": address.lower(), "chain_id": chain_id}


@app.get("/api/admin/watch/deployers")
async def watch_deployer_list(request: Request):
    """List all watched deployers. Requires X-Admin-Secret."""
    _require_admin(request)
    deployers = await container.db.get_watched_deployers()
    return {"deployers": deployers, "count": len(deployers)}


@app.get("/api/admin/watch/alerts")
async def watch_alerts_list(request: Request, limit: int = 50):
    """List recent deployment alerts from watched deployers. Requires X-Admin-Secret."""
    _require_admin(request)
    alerts = await container.db.get_deployment_alerts(limit=limit)
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/api/watch/nonce")
async def watch_nonce(
    wallet: str = Query(..., pattern=r"^0x[a-fA-F0-9]{40}$"),
):
    """Issue a one-time nonce for wallet signature verification."""
    nonce = _issue_nonce(wallet)
    message = f"ShieldBot alert access: {nonce}"
    return {"nonce": nonce, "message": message}


@app.get("/api/watch/alerts")
async def public_watch_alerts(
    request: Request,
    wallet: str = Query(..., pattern=r"^0x[a-fA-F0-9]{40}$"),
    signature: Optional[str] = Query(None, min_length=130, max_length=134),
    nonce: Optional[str] = Query(None, min_length=32, max_length=32),
):
    """List recent deployment alerts for verified $SHIELDBOT holders.

    When signature + nonce are provided, wallet ownership is verified
    via personal_sign (stronger auth for web callers).  When omitted,
    only the on-chain balanceOf gate applies (sufficient for the
    browser extension context where the user controls the client).
    """
    if not container or not container.db or not token_gate_service:
        raise HTTPException(status_code=503, detail="Watch alerts not available")

    client_ip = _get_client_ip(request)
    if not _watch_alerts_limiter.is_allowed(f"watch-alerts:{client_ip}"):
        return JSONResponse(
            status_code=429,
            content={"detail": "Watch alerts rate limit exceeded (10/min)."},
        )

    # Verify wallet ownership via signature when provided
    if signature and nonce:
        if not _verify_wallet_signature(wallet, signature, nonce):
            return JSONResponse(
                status_code=401,
                content={"error": "Invalid or expired signature"},
            )

    if not await token_gate_service.has_shieldbot_token(wallet):
        return JSONResponse(
            status_code=403,
            content={
                "error": "Token holding required",
                "token": SHIELDBOT_TOKEN_ADDRESS,
            },
        )

    alerts = await container.db.get_deployment_alerts(limit=50)
    return {"alerts": alerts, "count": len(alerts)}


# --- Agent Chat ---

@app.post("/api/agent/chat")
async def agent_chat(req: ChatRequest, request: Request):
    if not container or not hasattr(container, 'advisor'):
        raise HTTPException(503, "Agent not available")

    client_ip = request.client.host if request.client else "unknown"
    if not chat_limiter.is_allowed(req.user_id):
        raise HTTPException(429, "Rate limit exceeded")

    try:
        response = await container.advisor.chat(req.user_id, req.message)
        return {"response": response, "user_id": req.user_id}
    except Exception as e:
        logger.error(f"Agent chat error: {e}")
        raise HTTPException(500, "Agent error")


@app.post("/api/agent/explain")
async def agent_explain(req: ExplainRequest, request: Request):
    if not container or not hasattr(container, 'advisor'):
        raise HTTPException(503, "Agent not available")

    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.is_allowed(client_ip):
        raise HTTPException(429, "Rate limit exceeded")

    try:
        explanation = await container.advisor.explain_scan(req.scan_result)
        return {"explanation": explanation}
    except Exception as e:
        logger.error(f"Agent explain error: {e}")
        raise HTTPException(500, "Agent error")


# --- Mempool Monitoring ---

@app.get("/api/mempool/alerts")
async def mempool_alerts(request: Request, chain_id: int = None, limit: int = 50):
    """Get recent mempool alerts (sandwich attacks, frontrunning, suspicious approvals)."""
    if not container or not container.mempool_monitor:
        raise HTTPException(status_code=503, detail="Mempool monitor not available")
    limit = max(1, min(limit, 200))
    alerts = container.mempool_monitor.get_alerts(chain_id=chain_id, limit=limit)
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/api/mempool/stats")
async def mempool_stats(request: Request):
    """Get mempool monitoring statistics."""
    if not container or not container.mempool_monitor:
        raise HTTPException(status_code=503, detail="Mempool monitor not available")
    return container.mempool_monitor.get_stats()


# --- Rescue Mode ---

@app.get("/api/rescue/{wallet_address}")
async def rescue_scan(wallet_address: str, chain_id: int = 56):
    """Scan a wallet's active token approvals and assess risk (Rescue Mode).

    Returns risky approvals, Tier 1 alerts with explanations, and
    Tier 2 pre-built revoke transactions for one-click cleanup.
    """
    if not container or not container.rescue_service:
        raise HTTPException(status_code=503, detail="Rescue service not available")

    if not web3_client.is_valid_address(wallet_address):
        raise HTTPException(status_code=400, detail="Invalid wallet address")

    api_key = container.settings.bscscan_api_key
    result = await container.rescue_service.scan_approvals(
        wallet_address, chain_id=chain_id, etherscan_api_key=api_key,
    )
    return result


# --- Threat Feed API ---

@app.get("/api/threats/feed")
async def threat_feed(
    chain_id: int = None, limit: int = 50, since: float = None,
):
    """Real-time threat intelligence feed.

    Returns recent high-risk detections and mempool alerts.
    Query params:
    - chain_id: filter by chain (optional)
    - limit: max results (default 50, max 200)
    - since: unix timestamp to fetch threats after (optional)
    """
    if not container:
        raise HTTPException(status_code=503, detail="Service not available")

    limit = max(1, min(limit, 200))  # cap between 1 and 200
    threats = []

    # Recent high-risk contract scans from DB
    try:
        if chain_id is not None:
            cursor = await container.db._db.execute("""
                SELECT address, chain_id, risk_score, risk_level, archetype, flags,
                       last_scanned_at
                FROM contract_scores
                WHERE risk_level = 'HIGH' AND chain_id = ?
                ORDER BY last_scanned_at DESC
                LIMIT ?
            """, (int(chain_id), limit))
        else:
            cursor = await container.db._db.execute("""
                SELECT address, chain_id, risk_score, risk_level, archetype, flags,
                       last_scanned_at
                FROM contract_scores
                WHERE risk_level = 'HIGH'
                ORDER BY last_scanned_at DESC
                LIMIT ?
            """, (limit,))
        rows = await cursor.fetchall()

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
        logger.error(f"Threat feed DB error: {e}")

    # Mempool alerts
    mempool_alerts = container.mempool_monitor.get_alerts(chain_id=chain_id, limit=limit)
    for alert in mempool_alerts:
        if since and alert.get('created_at', 0) < since:
            continue
        threats.append({
            'type': f"mempool_{alert['alert_type']}",
            **alert,
        })

    # Sort all by time, most recent first
    threats.sort(key=lambda t: t.get('detected_at') or t.get('created_at', 0), reverse=True)

    return {
        'threats': threats[:limit],
        'count': len(threats[:limit]),
        'chain_id': chain_id,
    }


@app.get("/api/threats/subscribe")
async def threat_subscribe_info():
    """Information about threat feed subscription options."""
    return {
        'endpoints': {
            'rest_polling': '/api/threats/feed?since=<unix_timestamp>',
            'websocket': '/ws/threats (coming soon)',
        },
        'supported_chains': list(_CHAIN_NAMES.keys()),
        'alert_types': [
            'high_risk_contract',
            'mempool_sandwich_attack',
            'mempool_suspicious_approval',
        ],
    }


# --- Helpers ---

_CHAIN_NAMES = {56: "BSC", 204: "opBNB", 1: "Ethereum", 8453: "Base", 42161: "Arbitrum", 137: "Polygon", 10: "Optimism"}


def _chain_id_to_name(chain_id: int) -> str:
    """Map chain_id to a human-readable network name."""
    return _CHAIN_NAMES.get(chain_id, f"Chain {chain_id}")


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
    except Exception as e:
        logger.debug(f"Campaign context lookup failed for {contract_addr}: {e}")
        return None


def _format_decoded_action(decoded: Dict) -> str:
    """Convert decoded calldata into a plain English action label for the overlay."""
    func = decoded.get("function_name", "")
    category = decoded.get("category", "")
    params = decoded.get("params", {})

    if not func or func == "Native Transfer":
        return "Native BNB Transfer"

    if category == "approval":
        spender = params.get("param_0", "")
        spender_label = decoded.get("spender_label") or _short_addr(str(spender))
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
        r = str(recipient)
        recipient_short = f"{r[:8]}..." if len(r) > 10 else r
        return f"Token Transfer to {recipient_short}"

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
        spender = params.get("param_0", "")
        spender_label = decoded.get("spender_label") or _short_addr(str(spender))
        amount = params.get("param_1")
        is_unlimited = decoded.get("is_unlimited_approval", False)
        fields = [
            {"label": "Function", "value": func},
            {"label": "Spender", "value": spender_label},
            {"label": "Amount", "value": "Unlimited", "danger": True} if is_unlimited else
            {"label": "Amount", "value": str(amount) if amount is not None else "Unknown"},
        ]
    elif category == "transfer":
        if func == "transferFrom":
            frm = params.get("param_0", "")
            to = params.get("param_1", "")
            amount = params.get("param_2")
            fields = [
                {"label": "Function", "value": func},
                {"label": "From", "value": _short_addr(str(frm))},
                {"label": "To", "value": _short_addr(str(to))},
                {"label": "Amount", "value": str(amount) if amount is not None else "Unknown"},
            ]
        else:
            to = params.get("param_0", "")
            amount = params.get("param_1")
            fields = [
                {"label": "Function", "value": func},
                {"label": "To", "value": _short_addr(str(to))},
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


def _build_asset_delta_fallback(decoded: Dict, value_bnb: float) -> List:
    """Construct basic asset_delta from calldata when simulation is unavailable."""
    deltas = []
    if value_bnb > 0:
        deltas.append(f"-{value_bnb:g} BNB")
    if decoded.get("is_approval"):
        if decoded.get("is_unlimited_approval"):
            deltas.append("Approval: unlimited token spend")
        else:
            deltas.append("Approval: limited token spend")
    return deltas


def _build_asset_delta(simulation_result: Optional[Dict], decoded: Dict, value_bnb: float) -> List:
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
    return _build_asset_delta_fallback(decoded, value_bnb)


def _build_cached_response(
    cached: Dict, decoded: Dict, value_bnb: float, chain_id: int = 56,
    to_addr: str = "", policy_mode: str = "BALANCED",
) -> Dict:
    """Build a firewall response from a cached DB row."""
    risk_score = cached['risk_score']
    risk_level = cached.get('risk_level', 'UNKNOWN')
    flags = cached.get('flags', [])
    archetype = cached.get('archetype', 'unknown')

    if risk_score >= 80:
        classification = "BLOCK_RECOMMENDED"
    elif risk_score >= 60:
        classification = "HIGH_RISK"
    elif risk_score >= 30:
        classification = "CAUTION"
    else:
        classification = "SAFE"

    return {
        "classification": classification,
        "risk_score": risk_score,
        "decoded_action": _format_decoded_action(decoded),
        "calldata_details": _build_calldata_details(decoded),
        "danger_signals": flags,
        "transaction_impact": {
            "sending": f"{value_bnb:g} BNB" if value_bnb > 0 else "Tokens",
            "granting_access": "UNLIMITED" if decoded.get("is_unlimited_approval") else "None",
            "recipient": f"{to_addr[:10]}..." if to_addr else "Unknown",
            "post_tx_state": f"Risk archetype: {archetype}",
        },
        "analysis": f"Cached result (scanned {cached.get('scan_count', 1)} times)",
        "plain_english": f"Previously analyzed — risk level: {risk_level}",
        "verdict": f"{classification} — Rug probability {risk_score}% (cached)",
        "raw_checks": {
            "risk_score_heuristic": risk_score,
        },
        "shield_score": {
            "overall": risk_score,
            "category_scores": cached.get('category_scores', {}),
            "risk_level": risk_level,
            "threat_type": archetype,
            "critical_flags": flags,
            "confidence": cached.get('confidence', 0),
        },
        "simulation": None,
        "asset_delta": _build_asset_delta_fallback(decoded, value_bnb),
        "greenfield_url": None,
        "cached": True,
        "chain_id": chain_id,
        "network": _chain_id_to_name(chain_id),
        "partial": False,
        "failed_sources": [],
        "policy_mode": policy_mode,
    }


def _extract_raw_checks(scan: Dict) -> Dict:
    """Extract key raw check values for the extension."""
    return {
        "is_verified": scan.get("is_verified", False),
        "scam_matches": len(scan.get("scam_matches", [])),
        "contract_age_days": scan.get("contract_age_days"),
        "is_honeypot": scan.get("is_honeypot", False),
        "ownership_renounced": scan.get("checks", {}).get("ownership_renounced", False),
        "risk_score_heuristic": scan.get("risk_score", 0),
    }


def _build_fallback_response(decoded: Dict, scan: Dict, whitelisted: Optional[str]) -> Dict:
    """Build a firewall response when AI is unavailable."""
    risk_score = scan.get("risk_score", 50)
    scam_matches = len(scan.get("scam_matches", []))
    is_honeypot = scan.get("is_honeypot", False)
    is_verified = scan.get("is_verified", False)
    is_unlimited_approval = decoded.get("is_unlimited_approval", False)

    danger_signals = []

    if scam_matches > 0:
        danger_signals.append(f"Found {scam_matches} scam database match(es)")
        risk_score = max(risk_score, 80)

    if is_honeypot:
        danger_signals.append("Honeypot detected — cannot sell after buying")
        risk_score = max(risk_score, 90)

    if is_unlimited_approval and not is_verified:
        danger_signals.append("Unlimited approval to unverified contract")
        risk_score = max(risk_score, 85)

    if not is_verified:
        danger_signals.append("Contract source code is not verified")

    if whitelisted:
        risk_score = max(0, risk_score - 20)

    # Classify
    if risk_score >= 80:
        classification = "BLOCK_RECOMMENDED"
    elif risk_score >= 60:
        classification = "HIGH_RISK"
    elif risk_score >= 30:
        classification = "CAUTION"
    else:
        classification = "SAFE"

    return {
        "classification": classification,
        "risk_score": min(100, risk_score),
        "decoded_action": _format_decoded_action(decoded),
        "calldata_details": _build_calldata_details(decoded),
        "danger_signals": danger_signals,
        "transaction_impact": {
            "sending": "Unknown (AI unavailable)",
            "granting_access": "Unknown" if not decoded.get("is_approval") else (
                "UNLIMITED" if is_unlimited_approval else "Limited approval"
            ),
            "recipient": scan.get("address", "Unknown"),
            "post_tx_state": "AI analysis unavailable — review manually",
        },
        "analysis": "AI analysis unavailable. Showing heuristic results only.",
        "plain_english": "Could not generate AI analysis. Review the danger signals above carefully.",
        "verdict": f"{classification} — Risk score {risk_score}/100",
        "raw_checks": _extract_raw_checks(scan),
        "asset_delta": [],
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
    """Select representative token addresses from a swap path (first + last)."""
    if not path:
        return []
    if len(path) == 1:
        return [path[0]]
    return [path[0], path[-1]]


async def _analyze_router_swap(
    req: FirewallRequest,
    to_addr: str,
    from_addr: str,
    decoded: Dict,
    whitelisted: str,
    value_bnb: float,
    policy_override: Optional[str] = None,
) -> Optional[Dict]:
    """Analyze swap path tokens when interacting with a trusted router."""
    if not container or not container.registry or not risk_engine:
        return None

    path = _extract_swap_path(decoded, req.data)
    if not path:
        # Cannot decode the swap path (e.g. Uniswap V3 / aggregator calldata).
        # Returning None here would cause the main pipeline to analyse the
        # whitelisted router itself — which always scores safe — giving a false
        # SAFE result while the token in the path is never checked.
        # Return CAUTION so the user is warned that token safety is unverified.
        return {
            "classification": "CAUTION",
            "risk_score": 35,
            "decoded_action": _format_decoded_action(decoded),
            "calldata_details": _build_calldata_details(decoded),
            "danger_signals": [
                f"Swap via trusted router ({whitelisted}) but token path could not be decoded — token safety unverified",
            ],
            "transaction_impact": {
                "sending": f"{value_bnb:g} BNB" if value_bnb > 0 else "Tokens (via router)",
                "granting_access": "UNLIMITED" if decoded.get("is_unlimited_approval") else "None",
                "recipient": f"{whitelisted} ({to_addr[:10]}...)",
                "post_tx_state": f"Swap via {whitelisted} — token path not decoded",
            },
            "analysis": (
                f"Trusted router ({whitelisted}) detected but the swap path tokens could not be "
                "decoded from the calldata. Token safety cannot be verified."
            ),
            "plain_english": (
                "This transaction goes to a trusted DEX router, but the specific tokens in the swap "
                "path couldn't be identified. Verify the tokens manually before proceeding."
            ),
            "verdict": "CAUTION — Token path unverifiable",
            "raw_checks": {
                "is_verified": False,
                "scam_matches": 0,
                "contract_age_days": None,
                "is_honeypot": False,
                "ownership_renounced": False,
                "risk_score_heuristic": 35,
                "whitelisted_router": whitelisted,
                "tokens_analyzed": [],
            },
            "shield_score": {
                "overall": 35,
                "category_scores": {},
                "risk_level": "CAUTION",
                "threat_type": "unknown",
                "critical_flags": [],
                "confidence": 30,
            },
            "simulation": None,
            "asset_delta": _build_asset_delta_fallback(decoded, value_bnb),
            "greenfield_url": None,
            "chain_id": req.chainId,
            "network": _chain_id_to_name(req.chainId),
            "partial": True,
            "failed_sources": ["token_path_decoding"],
            "policy_mode": "BALANCED",
        }

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

    for token in candidates:
        if not web3_client.is_valid_address(token):
            continue
        token_addr = web3_client.to_checksum_address(token)

        is_verified = False
        try:
            verified_result = await web3_client.is_verified_contract(token_addr, chain_id=req.chainId)
            is_verified = verified_result[0] if isinstance(verified_result, tuple) else bool(verified_result)
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

        analyzer_results = await container.registry.run_all(ctx)
        risk_output = risk_engine.compute_from_results(analyzer_results, is_token=True)

        # Apply policy mode (handles partial failures)
        if container.policy_engine:
            risk_output = container.policy_engine.apply(
                analyzer_results, risk_output, mode_override=policy_override,
            )

        token_summaries.append({
            "address": token_addr,
            "risk_score": risk_output.get("rug_probability", 0),
            "risk_level": risk_output.get("risk_level", "UNKNOWN"),
        })

        if not best or risk_output.get("rug_probability", 0) > best["risk_output"].get("rug_probability", 0):
            best = {"address": token_addr, "risk_output": risk_output, "results": analyzer_results}

    if not best:
        return None

    risk_output = best["risk_output"]
    alert = format_extension_alert(risk_output)

    # Simulation overrides
    danger_signals = list(alert["top_flags"])
    classification = alert["risk_classification"]

    if sim_result:
        if not sim_result.get("success") and sim_result.get("revert_reason"):
            danger_signals.insert(0, f"Simulation reverted: {sim_result['revert_reason']}")
            if alert["rug_probability"] >= 30:
                classification = "BLOCK_RECOMMENDED"
        for w in sim_result.get("warnings", []):
            if w not in danger_signals:
                danger_signals.append(w)

    risk_score = alert["rug_probability"]

    # Extract service data for raw checks
    by_name = {r.name: r for r in best["results"]}
    contract_data = (by_name["structural"].data or {}) if "structural" in by_name else {}
    honeypot_data = (by_name["honeypot"].data or {}) if "honeypot" in by_name else {}

    shield_score = {
        "overall": risk_score,
        "category_scores": risk_output.get("category_scores", {}),
        "risk_level": risk_output.get("risk_level", "UNKNOWN"),
        "threat_type": risk_output.get("risk_archetype", "unknown"),
        "critical_flags": risk_output.get("critical_flags", []),
        "confidence": alert["confidence"],
    }

    return {
        "classification": classification,
        "risk_score": risk_score,
        "decoded_action": _format_decoded_action(decoded),
        "calldata_details": _build_calldata_details(decoded),
        "danger_signals": danger_signals,
        "transaction_impact": {
            "sending": f"{value_bnb:g} BNB" if value_bnb > 0 else "Tokens (via router)",
            "granting_access": "UNLIMITED" if decoded.get("is_unlimited_approval") else "None",
            "recipient": f"{whitelisted} ({to_addr[:10]}...)",
            "post_tx_state": f"Swap via {whitelisted} — analyzed {best['address'][:10]}...",
        },
        "analysis": f"Trusted router detected ({whitelisted}), analyzed swap path tokens.",
        "plain_english": alert["recommended_action"],
        "verdict": f"{classification} — Rug probability {risk_score}%",
        "raw_checks": {
            "is_verified": contract_data.get("is_verified", False),
            "scam_matches": len(contract_data.get("scam_matches", [])),
            "contract_age_days": contract_data.get("contract_age_days"),
            "is_honeypot": honeypot_data.get("is_honeypot", False),
            "ownership_renounced": contract_data.get("ownership_renounced", False),
            "risk_score_heuristic": risk_score,
            "whitelisted_router": whitelisted,
            "tokens_analyzed": token_summaries,
        },
        "shield_score": shield_score,
        "simulation": sim_result,
        "asset_delta": (
            [d["display"] for d in sim_result["asset_deltas"]]
            if sim_result and sim_result.get("asset_deltas")
            else _build_asset_delta_fallback(decoded, value_bnb)
        ),
        "greenfield_url": None,
        "chain_id": req.chainId,
        "network": _chain_id_to_name(req.chainId),
        "partial": risk_output.get("partial", False),
        "failed_sources": risk_output.get("failed_sources", []),
        "policy_mode": risk_output.get("policy_mode", "BALANCED"),
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

            # Format the approval amount
            amount = params.get("param_1")  # uint256 amount
            if isinstance(amount, int):
                if amount >= UNLIMITED_THRESHOLD:
                    decoded["formatted_amount"] = f"UNLIMITED {token_info['symbol']}"
                else:
                    decimals = token_info.get("decimals", 18)
                    human_amount = amount / (10 ** decimals)
                    decoded["formatted_amount"] = f"{human_amount:,.4f} {token_info['symbol']}".rstrip("0").rstrip(".")
                    decoded["formatted_amount"] += f" {token_info['symbol']}" if not decoded["formatted_amount"].endswith(token_info['symbol']) else ""

            # Resolve the spender address
            spender = params.get("param_0", "")
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
