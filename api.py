"""
ShieldAI Firewall API
FastAPI backend for the Chrome extension transaction firewall
Runs alongside bot.py on the VPS
"""

import os
import time
import asyncio
import logging
from collections import defaultdict
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

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


def _bind_globals(c: ServiceContainer):
    """Bind module-level names to container services for backward compat."""
    global web3_client, ai_analyzer, tx_scanner, token_scanner, calldata_decoder
    global scam_db, dex_service, ethos_service, honeypot_service, contract_service
    global risk_engine, greenfield_service, tenderly_simulator
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

    logger.info("ShieldAI Firewall API started")
    yield
    await container.shutdown()
    logger.info("ShieldAI Firewall API shutting down")


app = FastAPI(
    title="ShieldAI Firewall API",
    version="1.0.0",
    lifespan=lifespan,
)

# Mount RPC proxy router
app.include_router(rpc_router)

# CORS: configurable via CORS_ALLOW_ORIGINS env (comma-separated)
# Parsed at startup from Settings; fallback to localhost dev origins.
_boot_settings = Settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_boot_settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Skip rate limiting for health checks
    if request.url.path in ("/api/health", "/test"):
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
    client_ip = request.headers.get("x-forwarded-for", request.client.host)
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}")
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Please wait before trying again."},
        )

    return await call_next(request)


# --- Request / Response Models ---

class FirewallRequest(BaseModel):
    to: str
    sender: str = Field(alias="from")
    value: str = "0"
    data: str = "0x"
    chainId: int = 56
    typedData: Optional[Dict] = None
    signMethod: Optional[str] = None

    class Config:
        populate_by_name = True


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


# Report rate limiter: 5 reports/min per IP
_report_limiter = RateLimiter(requests_per_minute=5, burst=3)


# --- Endpoints ---

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "shieldai-firewall",
        "ai_available": ai_analyzer.is_available() if ai_analyzer else False,
        "greenfield_enabled": greenfield_service.is_enabled() if greenfield_service else False,
        "tenderly_enabled": tenderly_simulator.is_enabled() if tenderly_simulator else False,
    }


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

        # 2. If target is a whitelisted router, skip deep scan — it's trusted
        if whitelisted:
            sending = f"{value_bnb:g} BNB" if value_bnb > 0 else "Tokens (via router)"

            return {
                "classification": "SAFE",
                "risk_score": 5,
                "danger_signals": [],
                "transaction_impact": {
                    "sending": sending,
                    "granting_access": "None",
                    "recipient": f"{whitelisted} ({to_addr[:10]}...)",
                    "post_tx_state": f"Standard {decoded.get('category', 'swap')} on {whitelisted}",
                },
                "analysis": f"Transaction targets {whitelisted}, a trusted and widely-used DEX router on BNB Chain. No deep scan required.",
                "plain_english": f"This is a normal {decoded.get('category', 'transaction')} on {whitelisted}. This router is trusted and safe to use.",
                "verdict": f"SAFE — {whitelisted} is a verified, trusted router",
                "raw_checks": {
                    "is_verified": True,
                    "scam_matches": 0,
                    "contract_age_days": 999,
                    "is_honeypot": False,
                    "ownership_renounced": True,
                    "risk_score_heuristic": 5,
                    "whitelisted_router": whitelisted,
                },
            }

        # 2b. Check cache for recent result
        if container and container.db:
            cached = await container.db.get_contract_score(to_addr, req.chainId, max_age_seconds=300)
            if cached:
                return _build_cached_response(cached, decoded, value_bnb, req.chainId)

        # 3. Try composite intelligence pipeline (registry-based)
        try:
            from core.analyzer import AnalysisContext

            ctx = AnalysisContext(
                address=to_addr, chain_id=req.chainId, from_address=from_addr,
                extra={
                    'calldata': req.data,
                    'value': req.value,
                    'typed_data': req.typedData,
                    'sign_method': req.signMethod,
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
                risk_output = risk_engine.compute_from_results(analyzer_results)

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
                },
                "shield_score": shield_score,
                "simulation": simulation_result,
                "greenfield_url": None,
                "chain_id": req.chainId,
                "network": _chain_id_to_name(req.chainId),
                "partial": risk_output.get("partial", False),
                "failed_sources": risk_output.get("failed_sources", []),
                "policy_mode": risk_output.get("policy_mode", "BALANCED"),
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
            return firewall_result
        else:
            return _build_fallback_response(decoded, contract_scan, whitelisted)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Firewall error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


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
        raise HTTPException(status_code=500, detail=str(e))


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
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/report")
async def community_report(req: CommunityReportRequest, request: Request):
    """Record a community report (false positive, false negative, or scam)."""
    # Rate limit per IP
    client_ip = request.headers.get("x-forwarded-for", request.client.host)
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
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
        raise HTTPException(status_code=500, detail=str(e))


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
async def campaign_graph(address: str, chain_id: int = 56):
    """Get deployer/funder campaign graph for an address."""
    if not container or not container.db:
        raise HTTPException(status_code=503, detail="Database not available")
    if not web3_client or not web3_client.is_valid_address(address):
        raise HTTPException(status_code=400, detail="Invalid address")
    graph = await container.db.get_campaign_graph(address, chain_id)
    return graph


@app.post("/api/keys")
async def create_api_key(request: Request):
    """Create a new API key. Requires ADMIN_SECRET header."""
    admin_secret = request.headers.get("x-admin-secret")
    expected = os.getenv("ADMIN_SECRET", "") or (container.settings.admin_secret if container else "")
    if not admin_secret or not expected or admin_secret != expected:
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


# --- Helpers ---

_CHAIN_NAMES = {56: "BSC", 204: "opBNB", 1: "Ethereum", 8453: "Base", 42161: "Arbitrum", 137: "Polygon"}


def _chain_id_to_name(chain_id: int) -> str:
    """Map chain_id to a human-readable network name."""
    return _CHAIN_NAMES.get(chain_id, f"Chain {chain_id}")


def _build_cached_response(cached: Dict, decoded: Dict, value_bnb: float, chain_id: int = 56) -> Dict:
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
        "danger_signals": flags,
        "transaction_impact": {
            "sending": f"{value_bnb:g} BNB" if value_bnb > 0 else "Tokens",
            "granting_access": "UNLIMITED" if decoded.get("is_unlimited_approval") else "None",
            "recipient": "cached",
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
        "greenfield_url": None,
        "cached": True,
        "chain_id": chain_id,
        "network": _chain_id_to_name(chain_id),
        "partial": False,
        "failed_sources": [],
        "policy_mode": "BALANCED",
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
    }


# Token info cache (address -> {symbol, name, decimals})
_token_cache: Dict[str, Dict] = {}


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

    addr_lower = address.lower()
    if addr_lower in _token_cache:
        return _token_cache[addr_lower]

    try:
        info = await web3_client.get_token_info(address, chain_id=chain_id)
        if info.get("symbol"):
            result = {
                "symbol": info["symbol"],
                "name": info.get("name", ""),
                "decimals": info.get("decimals", 18),
            }
            _token_cache[addr_lower] = result
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
                spender_name = CalldataDecoder().is_whitelisted_target(spender)
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
