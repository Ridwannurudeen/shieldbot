# ShieldBot - Technical Documentation

## Architecture Overview

### System Design

ShieldBot follows a **3-tier architecture**:

```
┌─────────────────────────────────────────────────────────────────┐
│                        DELIVERY LAYER                            │
├─────────────────────────────────────────────────────────────────┤
│  • Chrome Extension (Manifest V3, EIP-6963)                      │
│  • Telegram Bot (python-telegram-bot 20.7)                       │
│  • FastAPI REST API (uvicorn, async endpoints)                   │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│                      INTELLIGENCE ENGINE                         │
├─────────────────────────────────────────────────────────────────┤
│  • RiskEngine: Composite weighted scoring (4 categories)         │
│  • AI Analyzer: Claude-powered forensic analysis                 │
│  • Calldata Decoder: Function signature + router detection       │
│  • Tenderly Simulator: Pre-execution transaction simulation      │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│                       DATA SERVICES LAYER                        │
├─────────────────────────────────────────────────────────────────┤
│  1. ContractService  → GoPlus + BscScan + Scam DBs               │
│  2. HoneypotService  → Honeypot.is simulation API                │
│  3. DexService       → DexScreener market data                   │
│  4. EthosService     → Ethos Network reputation                  │
│  5. TenderlyService  → Transaction simulation                    │
│  6. GreenfieldService → BNB Greenfield storage (SDK)             │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│                       BLOCKCHAIN LAYER                           │
├─────────────────────────────────────────────────────────────────┤
│  • BSC Mainnet (chain ID 56)                                     │
│  • opBNB Mainnet (chain ID 204)                                  │
│  • BNB Greenfield (decentralized storage)                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. Chrome Extension (Real-Time Firewall)

**Architecture**: Manifest V3 with isolated worlds

```javascript
// Extension Components
manifest.json       → Permissions, content_scripts, background service worker
inject.js           → Runs in "MAIN" world, wraps window.ethereum.request()
content.js          → Runs in "ISOLATED" world, renders overlays
background.js       → Service worker, API communication, modal injection
popup.html/js       → Extension popup UI (scan history, settings)
```

**Transaction Interception Flow**:

```
User clicks "Swap" on PancakeSwap
         ↓
dApp calls window.ethereum.request({method: 'eth_sendTransaction', params: [...]})
         ↓
inject.js (MAIN world) intercepts the call
         ↓
Sends transaction to background.js via window.postMessage
         ↓
background.js calls ShieldBot API: POST /api/firewall
         ↓
API returns verdict: {classification: "HIGH_RISK", risk_score: 85, ...}
         ↓
background.js injects modal:
  • HIGH_RISK → Full-screen red BLOCK modal
  • MEDIUM_RISK → Orange warning overlay (proceed/cancel)
  • LOW_RISK → Silent passthrough
         ↓
User action:
  • BLOCK: Transaction rejected (never reaches wallet)
  • WARN + Cancel: Transaction rejected
  • WARN + Proceed: Transaction forwarded to wallet
  • ALLOW: Transaction forwarded to wallet immediately
```

**Key Technical Details**:
- **EIP-6963 Compatible**: Detects multiple wallet providers via `eip6963:announceProvider` events
- **Direct Provider Wrapping**: Wraps `provider.request()` at the lowest level (cannot be bypassed)
- **Zero Wallet Permissions**: Extension never accesses private keys or user data
- **CORS-Safe**: All API calls from background service worker (no content script CORS issues)

---

### 2. Risk Engine (Composite Scoring)

**File**: `core/risk_engine.py`

**ShieldScore Computation**:

```python
# Category Weights
STRUCTURAL_WEIGHT = 0.40   # Contract verification, ownership, bytecode
MARKET_WEIGHT = 0.25       # Liquidity, volume, FDV
BEHAVIORAL_WEIGHT = 0.20   # Wallet reputation, scam flags
HONEYPOT_WEIGHT = 0.15     # Honeypot simulation, taxes

# Base Score
composite_score = (
    structural_score * 0.40 +
    market_score * 0.25 +
    behavioral_score * 0.20 +
    honeypot_score * 0.15
)

# Escalation Rules (override base score)
if honeypot_confirmed:
    composite_score = max(composite_score, 80)

if rug_pull_pattern:  # mint + proxy + owner not renounced
    composite_score = max(composite_score, 85)

if severe_reputation and new_pair:  # <24h pair + scam flags
    composite_score += 15

# Reduction Rules
if ownership_renounced and high_liquidity:  # >$100k liquidity
    composite_score -= 20

# Final Verdict
if composite_score >= 71:
    return "HIGH_RISK"  # Auto-block
elif composite_score >= 31:
    return "MEDIUM_RISK"  # Warning
else:
    return "LOW_RISK"  # Allow
```

**Structural Score Factors** (0-100):
- Contract verification status (BscScan)
- Bytecode patterns (mint, pause, blacklist, proxy)
- Ownership status (renounced vs. active owner)
- Contract age (days since deployment)
- Source code patterns (if verified)

**Market Score Factors** (0-100):
- Liquidity depth (DexScreener)
- Trading volume / liquidity ratio (wash trade detection)
- Pair age (new pairs = risky)
- FDV / 24h volume ratio
- Price volatility (>200% change = flag)

**Behavioral Score Factors** (0-100):
- Wallet reputation (Ethos Network)
- Scam database matches (ChainAbuse, ScamSniffer)
- Historical abuse flags
- Community reports

**Honeypot Score Factors** (0-100):
- Honeypot.is simulation result
- Buy/sell tax differential (>50% sell tax = honeypot)
- Transfer restrictions
- Liquidity lock status (PinkLock, Unicrypt)

---

### 3. Data Services (Parallel Intelligence)

All services run **asynchronously in parallel** via `asyncio.gather()`:

**Example from `bot.py`**:
```python
contract_data, honeypot_data, dex_data, ethos_data, token_info = await asyncio.gather(
    contract_service.fetch_contract_data(address),
    honeypot_service.fetch_honeypot_data(address),
    dex_service.fetch_token_market_data(address),
    ethos_service.fetch_wallet_reputation(address),
    web3_client.get_token_info(address),
)
# Total execution time: ~1.5-2 seconds (not 5-7 seconds sequential)
```

**Service Details**:

#### ContractService (`services/contract_service.py`)
- BscScan API: Contract verification, source code, deployment age
- Web3.py: Bytecode analysis, ownership checks
- Scam databases: ChainAbuse, ScamSniffer cross-reference
- Rate limiting: 0.25s delay between BscScan calls (free tier = 5 req/sec)

#### HoneypotService (`services/honeypot_service.py`)
- Honeypot.is API: Buy/sell simulation
- Tax extraction: Buy tax %, sell tax %
- Transfer simulation: Can buy? Can sell?
- False positive filtering: Ignores flags when taxes <50%

#### DexService (`services/dex_service.py`)
- DexScreener API: Token market data
- Metrics: Liquidity USD, 24h volume, FDV, pair age
- Anomaly detection: Volume > 10x liquidity (wash trading)
- Multi-pair aggregation: Sums volume across all pairs

#### EthosService (`services/ethos_service.py`)
- Ethos Network API: Wallet reputation scoring
- Scam flags, abuse history, community reviews
- Reputation score: 0-100 (lower = more trustworthy for wallets)

#### TenderlyService (`services/tenderly_service.py`)
- Tenderly Simulation API: Pre-execution transaction simulation
- Predicts: Success/revert, gas usage, asset deltas, subcalls
- Detects: Reentrancy, failed internal calls, excessive gas

#### GreenfieldService (`services/greenfield_service.py`)
- BNB Greenfield Python SDK: On-chain storage
- Uploads: JSON forensic reports for high-risk transactions
- Bucket: `shieldbot-reports`
- Public URLs: `https://greenfield-sp.bnbchain.org/view/shieldbot-reports/reports/<id>.json`

---

### 4. AI Analyzer (Claude-Powered)

**File**: `utils/ai_analyzer.py`

Uses **Anthropic Claude API** for contextual risk analysis:

```python
# Input: Composite risk data from all services
scan_data = {
    'contract': contract_data,
    'honeypot': honeypot_data,
    'dex': dex_data,
    'ethos': ethos_data,
    'risk': risk_output,
}

# Output: Human-readable forensic analysis
ai_analysis = """
This contract exhibits a dangerous rug pull pattern:

🚨 Critical Issues:
- Mint function allows owner to create unlimited tokens
- Proxy pattern enables owner to change logic at any time
- Ownership NOT renounced (active owner can rug)
- Only $2,300 liquidity (easy to drain)
- Pair created <12 hours ago (pump-and-dump window)

💡 Recommendation: DO NOT INTERACT
This is a textbook rug pull setup. Owner can mint tokens to dilute holders,
or upgrade the proxy to steal funds. The low liquidity + new pair indicates
a coordinated scam launch.
"""
```

**Why AI?**
- Explains **WHY** a contract is risky (not just flags)
- Contextualizes **COMBINATIONS** of signals (e.g., "mint + proxy + new pair = rug")
- Reduces false positives via nuanced analysis
- Provides **educational value** (users learn security patterns)

---

## Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Backend** | Python | 3.11+ | Async runtime |
| **Web Framework** | FastAPI | Latest | REST API endpoints |
| **ASGI Server** | uvicorn | Latest | Production server |
| **Async HTTP** | aiohttp, httpx | Latest | Non-blocking API calls |
| **Web3** | web3.py | 6.15+ | Blockchain interaction |
| **Telegram** | python-telegram-bot | 20.7 | Bot framework |
| **AI** | Anthropic Claude | Latest | Forensic analysis |
| **Simulation** | Tenderly API | V1 | Transaction simulation |
| **Storage** | BNB Greenfield SDK | Latest | On-chain reports |
| **Extension** | Chrome Manifest V3 | Latest | Browser integration |

---

## Project Structure

```
shieldbot/
├── README.md                    # Project overview
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment template
├── bot.py                       # Telegram bot entry point
├── api.py                       # FastAPI backend entry point
│
├── docs/
│   ├── PROJECT.md               # Problem, solution, impact, roadmap
│   ├── TECHNICAL.md             # This file (architecture, setup)
│   └── EXTRAS.md                # Additional documentation (optional)
│
├── scanner/
│   ├── transaction_scanner.py  # Pre-tx security checks
│   └── token_scanner.py        # Token safety analysis (legacy)
│
├── core/
│   ├── risk_engine.py          # Composite weighted scoring
│   ├── extension_formatter.py  # Chrome extension response format
│   └── telegram_formatter.py   # Telegram message format
│
├── services/
│   ├── contract_service.py     # GoPlus + BscScan intelligence
│   ├── honeypot_service.py     # Honeypot.is simulation
│   ├── dex_service.py          # DexScreener market data
│   ├── ethos_service.py        # Ethos Network reputation
│   ├── tenderly_service.py     # Tenderly simulation
│   └── greenfield_service.py   # BNB Greenfield storage
│
├── utils/
│   ├── ai_analyzer.py          # Claude AI forensic analysis
│   ├── calldata_decoder.py     # Transaction decoder + whitelist
│   ├── risk_scorer.py          # Blended scoring logic
│   ├── web3_client.py          # Web3 + liquidity lock detection
│   ├── scam_db.py              # Multi-source scam database
│   ├── firewall_prompt.py      # AI system prompt
│   └── onchain_recorder.py     # On-chain scan recording
│
├── extension/
│   ├── manifest.json           # Extension config (V3)
│   ├── inject.js               # Provider wrapper (MAIN world)
│   ├── content.js              # Modal renderer (ISOLATED world)
│   ├── background.js           # Service worker (API calls)
│   ├── popup.html              # Extension popup UI
│   ├── popup.js                # Popup logic
│   └── overlay.css             # Firewall modal styles
│
└── contracts/
    └── ShieldBotVerifier.sol   # On-chain verification contract (future)
```

---

## Setup & Installation

### ⚠️ Important Note for Judges/Evaluators

**You don't need all API keys to evaluate ShieldBot!**

**Minimum setup to test core features:**
1. **Only BSCSCAN_API_KEY is required** (free at [bscscan.com/myapikey](https://bscscan.com/myapikey))
2. Run: `uvicorn api:app --host 0.0.0.0 --port 8000`
3. Visit: `http://localhost:8000/test`
4. All risk analysis features work with just BscScan API

**Features that require optional API keys:**
- **Telegram Bot**: Requires TELEGRAM_BOT_TOKEN → **Alternative: Use live bot [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot)**
- **BNB Greenfield**: Requires GREENFIELD_PRIVATE_KEY → Optional, only for report uploads
- **Tenderly Simulation**: Requires TENDERLY_API_KEY → Optional, core features work without it
- **AI Analysis**: Requires ANTHROPIC_API_KEY → Optional enhancement

**Easiest evaluation methods:**
1. **Live Telegram Bot** (no setup): [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot)
2. **Demo Video** (3 minutes): [Watch on Loom](https://www.loom.com/share/6769a5e1ab744286b48380175fa6c50c)
3. **Local API** (BscScan key only): Follow setup below

---

### Prerequisites

- **Python 3.11+** ([download](https://www.python.org/downloads/))
- **Git** ([download](https://git-scm.com/downloads))
- **Chrome/Brave Browser** (for extension testing)
- **API Keys** (see Environment Variables below)

### 1. Clone Repository

```bash
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv

# Linux/Mac
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

**Key Dependencies**:
```
fastapi==0.109.0
uvicorn==0.27.0
python-telegram-bot==20.7
web3==6.15.1
aiohttp==3.9.1
httpx==0.26.0
anthropic==0.23.1
greenfield-python-sdk==0.2.1
python-dotenv==1.0.0
```

### 4. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env`:

```env
# REQUIRED: Telegram Bot
TELEGRAM_BOT_TOKEN=your_telegram_bot_token

# REQUIRED: Blockchain
BSCSCAN_API_KEY=your_bscscan_api_key
BSC_RPC_URL=https://bsc-dataseed1.binance.org/
OPBNB_RPC_URL=https://opbnb-mainnet-rpc.bnbchain.org

# OPTIONAL: Advanced Features
TENDERLY_API_KEY=your_tenderly_key
TENDERLY_PROJECT_ID=your_tenderly_project_id
GREENFIELD_PRIVATE_KEY=your_greenfield_private_key
ANTHROPIC_API_KEY=your_anthropic_key

# OPTIONAL: Extension CORS
CORS_ALLOW_ORIGINS=chrome-extension://YOUR_EXTENSION_ID,http://localhost:8000
```

**How to Get API Keys**:

| Service | URL | Free Tier |
|---------|-----|-----------|
| BscScan | https://bscscan.com/myapikey | ✅ 5 req/sec |
| Telegram Bot | https://t.me/BotFather | ✅ Unlimited |
| Tenderly | https://dashboard.tenderly.co/ | ✅ 100 sim/month |
| Anthropic Claude | https://console.anthropic.com/ | ✅ $5 free credit |
| Greenfield | https://greenfield.bnbchain.org/ | ✅ Pay-as-you-go |

### 5. Run Services

**Terminal 1: FastAPI Backend**
```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2: Telegram Bot**
```bash
python bot.py
```

**Verify Services**:
- FastAPI: http://localhost:8000/docs (Swagger UI)
- Health: http://localhost:8000/api/health
- Test Page: http://localhost:8000/test

### 6. Install Chrome Extension

1. Open Chrome: `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select `/path/to/shieldbot/extension/` folder
5. Copy the **Extension ID** (e.g., `abcdefghijklmnopqrstuvwxyz123456`)
6. Update `.env`: `CORS_ALLOW_ORIGINS=chrome-extension://YOUR_EXTENSION_ID`
7. Restart FastAPI backend

**Verify Extension**:
- Visit http://localhost:8000/test
- Click "Test BLOCK Verdict" → Should show red modal
- Click "Test WARN Verdict" → Should show orange overlay
- Click "Test ALLOW Verdict" → Should pass through silently

---

## Demo Guide

### 🎥 Video Walkthrough

**Watch the complete 3-minute demo:** [View on Loom](https://www.loom.com/share/6769a5e1ab744286b48380175fa6c50c)

The video shows:
- Chrome extension intercepting and blocking honeypot transactions
- Telegram bot displaying token names and symbols
- Real-time risk analysis with composite ShieldScore
- BNB Greenfield forensic report storage

### Expected Output Examples

**Extension BLOCK Verdict:**
```
╔═══════════════════════════════════════════════════════════╗
║              🔴 TRANSACTION BLOCKED                        ║
║                                                            ║
║  Risk Score: 85/100 - HIGH RISK                           ║
║                                                            ║
║  ⚠️ Critical Flags:                                       ║
║  ✗ Honeypot confirmed - cannot sell after buying          ║
║  ✗ Sell tax: 99%                                          ║
║  ✗ Ownership not renounced                                ║
║  ✗ Low liquidity: $2,000                                  ║
║  ✗ Contract not verified                                  ║
║                                                            ║
║  Contract: 0x1234...5678                                   ║
║                                                            ║
║  This transaction has been blocked for your protection.   ║
║  ShieldBot detected multiple high-risk indicators.        ║
╚═══════════════════════════════════════════════════════════╝
```

**Telegram Bot Response (with Token Names):**
```
🟢 ShieldBot Intelligence Report

Token: Wrapped BNB (WBNB)
Address: 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
Risk Archetype: Low Risk
Rug Probability: 5% | Risk Level: LOW
Confidence: 95%

✓ Category Scores:
  • Structural: 10/100 (LOW)
  • Market: 5/100 (LOW)
  • Behavioral: 0/100 (SAFE)
  • Honeypot: 0/100 (SAFE)

✓ No Critical Flags

Contract Details:
  • Verified: ✓ Yes (BscScan)
  • Age: 1825 days (5.0 years)
  • Ownership: Renounced
  • Liquidity: $523,450,000

Market Metrics:
  • Liquidity: $523.45M
  • 24h Volume: $145.2M
  • Pair Age: 1825 days
```

**BNB Greenfield Forensic Report:**
```json
{
  "report_id": "3a4039ef0349eb5f",
  "timestamp": "2026-02-16T03:45:12.234Z",
  "contract_address": "0x1234567890abcdef1234567890abcdef12345678",
  "chain_id": 56,
  "risk_score": 85,
  "risk_level": "HIGH",
  "rug_probability": 87.5,
  "confidence_level": 75,
  "risk_archetype": "honeypot",
  "critical_flags": [
    "Honeypot confirmed - cannot sell after buying",
    "Sell tax 99%",
    "Ownership not renounced",
    "Low liquidity ($2,000)",
    "Contract not verified"
  ],
  "category_scores": {
    "structural": 90,
    "market": 75,
    "behavioral": 45,
    "honeypot": 95
  },
  "data_sources": {
    "goplus": { "is_honeypot": true, "honeypot_score": 95 },
    "honeypot_is": { "can_buy": true, "can_sell": false, "sell_tax": 99 },
    "dexscreener": { "liquidity_usd": 2000, "pair_age_hours": 12 },
    "ethos": { "reputation_score": 45, "scam_flags": true },
    "tenderly": { "simulation_success": false }
  },
  "public_url": "https://greenfield-sp.bnbchain.org/view/shieldbot-reports/reports/3a4039ef0349eb5f.json"
}
```

### Live Telegram Bot Demo

**Bot**: [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot)

**Commands to Try**:

1. **Safe Contract Scan**:
   ```
   /scan 0x10ED43C718714eb63d5aA57B78B54704E256024E
   ```
   *(PancakeSwap Router - should return LOW RISK)*

2. **Safe Token Check**:
   ```
   /token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
   ```
   *(WBNB - should return LOW RISK with token name/symbol)*

3. **View History** (if any scans recorded):
   ```
   /history 0x10ED43C718714eb63d5aA57B78B54704E256024E
   ```

4. **Report Scam**:
   ```
   /report 0xSCAMADDRESS
   ```

### Chrome Extension Demo

**Prerequisites**:
- Extension installed and enabled
- FastAPI backend running on port 8000
- CORS configured correctly

**Test Page Demo** (http://localhost:8000/test):

1. **BLOCK Verdict**:
   - Click "Test BLOCK Verdict (Honeypot Token)"
   - Full-screen **red modal** appears
   - Shows risk score 85/100, critical flags
   - Transaction cannot proceed (no wallet popup)

2. **WARN Verdict**:
   - Click "Test WARN Verdict (Unverified Contract)"
   - **Orange warning overlay** appears
   - Shows risk score 45/100, medium risk
   - Two buttons: "Proceed Anyway" or "Cancel Transaction"

3. **ALLOW Verdict**:
   - Click "Test ALLOW Verdict (PancakeSwap)"
   - **No overlay** appears
   - Transaction passes through silently
   - MetaMask popup appears immediately

**Live dApp Demo** (PancakeSwap):

1. Visit https://pancakeswap.finance/swap
2. Connect wallet (MetaMask/Rabby)
3. Try to swap BNB for a **known honeypot token** (e.g., `0xSCAMADDRESS`)
4. ShieldBot intercepts → Shows BLOCK modal
5. Try to swap BNB for **WBNB** (verified safe token)
6. ShieldBot allows → MetaMask signature request appears

### API Demo

**Scan Contract**:
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"address": "0x10ED43C718714eb63d5aA57B78B54704E256024E"}'
```

**Firewall Check**:
```bash
curl -X POST http://localhost:8000/api/firewall \
  -H "Content-Type: application/json" \
  -d '{
    "to": "0x10ED43C718714eb63d5aA57B78B54704E256024E",
    "from": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD61",
    "value": "0x2386F26FC10000",
    "data": "0x",
    "chainId": 56
  }'
```

**Health Check**:
```bash
curl http://localhost:8000/api/health
```

---

## Testing

### Unit Tests (Future Implementation)

```bash
# Install pytest
pip install pytest pytest-asyncio

# Run tests
pytest tests/
```

### Manual Testing Checklist

**Extension**:
- [ ] Loads without errors in Chrome
- [ ] Intercepts transactions on test page
- [ ] Shows correct verdict modals (BLOCK/WARN/ALLOW)
- [ ] Allows user to cancel WARN verdicts
- [ ] Silent passthrough for whitelisted routers
- [ ] Works with MetaMask, Rabby, and other EIP-6963 wallets

**Telegram Bot**:
- [ ] Responds to /start, /help commands
- [ ] /scan returns risk analysis for contracts
- [ ] /token shows token name, symbol, and risk score
- [ ] /history retrieves on-chain scan records
- [ ] Handles invalid addresses gracefully
- [ ] Response time <3 seconds for scans

**API**:
- [ ] /api/firewall returns correct verdict for honeypots
- [ ] /api/scan returns composite risk data
- [ ] /api/health shows service status
- [ ] /test page renders correctly
- [ ] CORS allows extension requests
- [ ] Handles network errors gracefully (external APIs down)

---

## Deployment

### Production Deployment (VPS/Cloud)

**Recommended**: Ubuntu 22.04 LTS, 2GB RAM, 1 vCPU

```bash
# SSH to server
ssh user@your-server-ip

# Install dependencies
sudo apt update
sudo apt install python3.11 python3.11-venv nginx certbot

# Clone repo
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot

# Setup environment
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure .env (use production API keys)
nano .env

# Create systemd service for Telegram bot
sudo nano /etc/systemd/system/shieldbot-bot.service
```

**shieldbot-bot.service**:
```ini
[Unit]
Description=ShieldBot Telegram Bot
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/shieldbot
Environment="PATH=/home/ubuntu/shieldbot/venv/bin"
ExecStart=/home/ubuntu/shieldbot/venv/bin/python bot.py
Restart=always

[Install]
WantedBy=multi-user.target
```

**Start services**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable shieldbot-bot
sudo systemctl start shieldbot-bot

# Run FastAPI with gunicorn
gunicorn api:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

**Nginx Reverse Proxy** (for HTTPS):
```nginx
server {
    listen 80;
    server_name api.shieldbot.xyz;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**SSL Certificate**:
```bash
sudo certbot --nginx -d api.shieldbot.xyz
```

### Docker Deployment (Future)

```dockerfile
# Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "bot.py"]
```

---

## Performance Optimization

### Response Time Targets

| Operation | Target | Current |
|-----------|--------|---------|
| Extension verdict | <2s | ~1.5s |
| Telegram /scan | <3s | ~2s |
| API /firewall | <2s | ~1.5s |
| Greenfield upload | <5s | ~3s |

### Optimization Strategies

1. **Parallel API Calls**: All data services run via `asyncio.gather()`
2. **Caching**: 5-minute TTL for contract scans (Telegram bot)
3. **Router Whitelist**: PancakeSwap, 1inch fast-path bypass
4. **Rate Limiting**: Respects BscScan free tier (5 req/sec)
5. **Connection Pooling**: Reuses HTTP connections via aiohttp

---

## Security Considerations

### Extension Security

- **No Private Key Access**: Extension never touches wallet private keys
- **HTTPS Only**: All API calls over HTTPS in production
- **Content Security Policy**: Strict CSP in manifest.json
- **No Remote Code Execution**: All logic bundled in extension

### API Security

- **CORS Whitelist**: Only allows registered extension IDs
- **Rate Limiting**: Prevents API abuse (future: implement rate limits)
- **Input Validation**: All addresses validated via Web3.is_address()
- **Error Handling**: Never exposes internal error messages to users

### Data Privacy

- **No User Tracking**: No analytics, cookies, or user identification
- **No Transaction Storage**: Transactions never logged/stored
- **On-Chain Reports**: Only high-risk transactions (opt-in via threshold)
- **Open Source**: All code auditable at https://github.com/Ridwannurudeen/shieldbot

---

## Troubleshooting

### Extension Not Intercepting Transactions

1. Check extension is enabled: `chrome://extensions`
2. Verify CORS_ALLOW_ORIGINS includes extension ID
3. Restart FastAPI backend after .env changes
4. Check console for errors: Right-click extension → Inspect
5. Test on http://localhost:8000/test first

### Telegram Bot Not Responding

1. Check bot is running: `systemctl status shieldbot-bot`
2. Verify TELEGRAM_BOT_TOKEN is correct
3. Check logs: `journalctl -u shieldbot-bot -f`
4. Test API independently: `curl localhost:8000/api/health`

### API Calls Failing

1. Check all required API keys in .env
2. Verify internet connectivity (external APIs)
3. Test endpoints: http://localhost:8000/docs
4. Check rate limits (BscScan free tier = 5/sec)

### Greenfield Upload Failing

1. Verify GREENFIELD_PRIVATE_KEY is set
2. Check Greenfield bucket exists
3. Ensure wallet has BNB for gas
4. Test on testnet first

---

## Contributing

Contributions are welcome! Areas for improvement:

- **Additional Data Sources**: Chainlink feeds, on-chain heuristics
- **Machine Learning**: Pattern recognition from Greenfield reports
- **Mobile SDKs**: Trust Wallet, SafePal integration
- **Testing**: Unit tests, integration tests, E2E tests
- **Documentation**: Tutorials, security guides, case studies

**Contribution Process**:
1. Fork repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

---

## License

MIT License - see LICENSE file for details

---

## Contact & Support

- **Issues**: https://github.com/Ridwannurudeen/shieldbot/issues
- **Telegram**: [@Ggudman](https://t.me/Ggudman)
- **Twitter**: [@Ggudman1](https://twitter.com/Ggudman1)

---

**Last Updated**: February 2026
