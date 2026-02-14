# ShieldBot - Autonomous Transaction Firewall for BNB Chain

**Good Vibes Only: OpenClaw Edition - Builders Track**

ShieldBot is an autonomous transaction firewall for BNB Chain. It intercepts Web3 transactions in real-time via a Chrome extension, analyzes them using composite intelligence from multiple sources (GoPlus, Honeypot.is, DexScreener, Ethos Network, Tenderly), computes a weighted ShieldScore, and blocks honeypots, rug pulls, and malicious contracts before they execute. High-risk forensic reports are stored immutably on BNB Greenfield.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![BNB Chain](https://img.shields.io/badge/BNB-Chain-yellow)](https://www.bnbchain.org/)

---

## How It Works

1. **Intercept** -- The Chrome extension wraps the wallet provider's `request()` method in the page context (`world: MAIN`). When `eth_sendTransaction` or `eth_signTransaction` is called, the transaction is intercepted before reaching the wallet.

2. **Analyze** -- The intercepted transaction is sent to the ShieldBot API, which runs five analyses in parallel: contract intelligence (GoPlus), honeypot detection, DEX market data (DexScreener), wallet reputation (Ethos Network), and transaction simulation (Tenderly).

3. **Score** -- The RiskEngine computes a weighted composite score from the parallel results. Escalation rules override the base score for confirmed honeypots and rug pull patterns.

4. **Verdict** -- Based on the composite score and simulation result, the API returns BLOCK, WARN, or ALLOW. The extension renders a full-screen modal for blocks, a warning overlay with proceed/cancel for warnings, or passes through silently for safe transactions.

5. **Record** -- For transactions scoring >= 50, a forensic report is uploaded to BNB Greenfield as an immutable JSON object with a public URL.

---

## Architecture

```
+-------------------------------------------------------------+
|  DELIVERY                                                    |
|  - Chrome Extension (Manifest V3, MetaMask + EIP-6963)       |
|  - FastAPI REST API (/api/firewall, /api/scan, /test)        |
|  - Telegram Bot (/scan, /token, /history, /report)           |
+-------------------------------------------------------------+
|  INTELLIGENCE ENGINE                                         |
|  - RiskEngine (composite weighted scoring)                   |
|  - AI Analyzer (Claude-powered forensic analysis)            |
|  - Calldata Decoder (approve, swap, transfer detection)      |
|  - Transaction Simulator (Tenderly pre-execution)            |
+-------------------------------------------------------------+
|  DATA SERVICES                                               |
|  - ContractService (GoPlus + BscScan + scam databases)       |
|  - HoneypotService (honeypot.is simulation)                  |
|  - DexService (DexScreener market data + volume anomalies)   |
|  - EthosService (wallet reputation scoring)                  |
|  - TenderlySimulator (pre-execution simulation)              |
|  - GreenfieldService (on-chain forensic report storage)      |
+-------------------------------------------------------------+
```

---

## Features

### Real-Time Transaction Firewall (Chrome Extension)

The extension intercepts `eth_sendTransaction` and `eth_signTransaction` before they reach the wallet. Each transaction is analyzed via the ShieldBot API. The result determines the action:

- **BLOCK**: Critical risk -- transaction is rejected with a full-screen red modal
- **WARN**: High/medium risk -- user sees an orange warning overlay with risk details and can proceed or cancel
- **ALLOW**: Low risk -- transaction passes through silently (whitelisted routers like PancakeSwap fast-path)

The extension uses **direct request wrapping** via `inject.js` running in `world: MAIN`. It wraps the provider's `request()` method directly (both `window.ethereum` and EIP-6963 providers), making it compatible with MetaMask, Rabby, and other modern wallets without proxy interference.

### Composite Risk Scoring (ShieldScore)

A weighted 0-100 risk score computed from four categories:

```
Composite = (Structural x 0.40) + (Market x 0.25) + (Behavioral x 0.20) + (Honeypot x 0.15)

Escalation Rules:
  - Honeypot confirmed          -> floor at 80
  - Rug pull pattern (mint +    -> floor at 85
    proxy + owner not renounced)
  - Severe reputation + new     -> +15 escalation
    pair (<24h)
  - Renounced + high liquidity  -> -20 reduction
```

| Level  | Score | Action |
|--------|-------|--------|
| HIGH   | 71+   | Auto-block |
| MEDIUM | 31-70 | Warning overlay |
| LOW    | 0-30  | Allow |

### Tenderly Transaction Simulation

Before a transaction executes, ShieldBot simulates it via Tenderly's API to predict:

- **Success/revert status** -- catches transactions that would fail on-chain
- **Asset deltas** -- shows token balance changes before signing
- **Gas estimation** -- flags excessive gas usage
- **Subcall analysis** -- detects failed internal calls and reentrancy patterns

### BNB Greenfield On-Chain Reports

When a transaction scores >= 50, ShieldBot uploads a forensic report to BNB Greenfield as an immutable JSON object:

- Tamper-proof evidence of risk analysis
- Public URL for each report (e.g., `https://greenfield-sp.bnbchain.org/view/shieldbot-reports/reports/<id>.json`)
- Full analysis data: composite score breakdown, contract flags, market metrics, simulation results

### Multi-Source Intelligence

| Source | Purpose |
|--------|---------|
| GoPlus | Contract verification, scam flags, bytecode analysis |
| Honeypot.is | Honeypot simulation, buy/sell tax detection |
| DexScreener | Liquidity depth, pair age, volume anomalies, FDV/volume ratio |
| Ethos Network | Wallet reputation scoring, scam flag aggregation |
| Tenderly | Pre-execution transaction simulation |
| BNB Greenfield | Immutable forensic report storage |
| BscScan | Contract verification, deployment age, transaction history |
| ChainAbuse / ScamSniffer | Scam database cross-referencing |

### Telegram Bot

```
/start              - Welcome message
/scan <address>     - Security scan for any contract
/token <address>    - Token safety check (honeypot, taxes, liquidity)
/history <address>  - View on-chain scan records
/report <address>   - Report a scam address
/help               - Command list
```

### Test Page

Visit `http://<host>:8000/test` to test the Chrome extension with pre-configured transactions:
- Honeypot token (should trigger BLOCK)
- PancakeSwap router (should ALLOW silently)
- Unverified contract (should trigger WARN)

---

## Quick Start

### Try the Live Bot

1. Open Telegram and search for: **@shieldbot_bnb_bot**
2. Send `/start` to begin
3. Test: `/scan 0x10ED43C718714eb63d5aA57B78B54704E256024E` (PancakeSwap -- safe)
4. Test: `/token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` (WBNB -- safe)

**Direct Link:** https://t.me/shieldbot_bnb_bot

### Run Locally

```bash
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot

python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your API keys

# Run Telegram bot
python bot.py

# Run FastAPI backend (separate terminal)
uvicorn api:app --host 0.0.0.0 --port 8000
```

### Install Chrome Extension

1. Open `chrome://extensions` in Chrome
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** -> select the `extension/` folder
4. Visit the test page (`http://<host>:8000/test`) to verify the extension is active
5. Visit any dApp (e.g., PancakeSwap) and initiate a swap -- the firewall overlay will appear

### Configuration

Edit `.env`:

```env
# Required
TELEGRAM_BOT_TOKEN=your_bot_token
BSCSCAN_API_KEY=your_bscscan_key

# Tenderly Simulation
TENDERLY_API_KEY=your_tenderly_key
TENDERLY_PROJECT_ID=your_tenderly_project_id

# BNB Greenfield (on-chain forensic reports)
GREENFIELD_PRIVATE_KEY=your_greenfield_private_key

# AI Analysis
ANTHROPIC_API_KEY=your_anthropic_key

# Optional
BSC_RPC_URL=https://bsc-dataseed1.binance.org/
OPBNB_RPC_URL=https://opbnb-mainnet-rpc.bnbchain.org
```

---

## API

### POST `/api/firewall`

Main endpoint called by the Chrome extension before transaction submission.

```bash
curl -X POST http://localhost:8000/api/firewall \
  -H "Content-Type: application/json" \
  -d '{
    "to": "0xSuspiciousContract...",
    "from": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD61",
    "value": "0x2386F26FC10000",
    "data": "0x095ea7b3...",
    "chainId": 56
  }'
```

**Response:**

```json
{
  "classification": "HIGH_RISK",
  "risk_score": 72,
  "danger_signals": [
    "Contract not verified",
    "Mint function detected",
    "Proxy/upgradeable contract",
    "Low liquidity (<$10k)"
  ],
  "shield_score": {
    "rug_probability": 72.5,
    "risk_level": "HIGH",
    "risk_archetype": "rug_pull",
    "category_scores": {
      "structural": 85.0,
      "market": 55.0,
      "behavioral": 30.0,
      "honeypot": 0.0
    },
    "confidence_level": 75
  },
  "simulation": {
    "success": true,
    "gas_used": 125000,
    "asset_deltas": [],
    "warnings": ["Asset outflow detected"]
  },
  "greenfield_url": "https://greenfield-sp.bnbchain.org/view/shieldbot-reports/reports/3a4039ef0349eb5f.json",
  "transaction_impact": {
    "sending": "0.01 BNB",
    "granting_access": "None",
    "recipient": "0xSusp... (Unverified Contract)"
  },
  "verdict": "HIGH RISK - Proceed with extreme caution"
}
```

### POST `/api/scan`

Quick contract security scan.

### GET `/api/health`

Returns service status for AI, Greenfield, and Tenderly modules.

### GET `/test`

Interactive test page for Chrome extension E2E testing.

---

## Project Structure

```
shieldbot/
+-- bot.py                       # Telegram bot (commands, cache, on-chain recording)
+-- api.py                       # FastAPI backend (firewall, scan, test page)
+-- scanner/
|   +-- transaction_scanner.py   # Pre-tx security checks + AI scoring
|   +-- token_scanner.py         # Token safety + honeypot + AI scoring
+-- core/
|   +-- risk_engine.py           # Composite weighted risk scoring (4 categories)
|   +-- extension_formatter.py   # Chrome extension response formatting
|   +-- telegram_formatter.py    # Telegram message formatting
+-- services/
|   +-- contract_service.py      # GoPlus + BscScan contract intelligence
|   +-- honeypot_service.py      # Honeypot.is simulation
|   +-- dex_service.py           # DexScreener market data + anomaly detection
|   +-- ethos_service.py         # Ethos Network reputation scoring
|   +-- tenderly_service.py      # Tenderly transaction simulation
|   +-- greenfield_service.py    # BNB Greenfield report storage (SDK)
+-- utils/
|   +-- ai_analyzer.py           # Claude AI risk analysis + forensic verdicts
|   +-- calldata_decoder.py      # Transaction calldata decoding + router whitelist
|   +-- risk_scorer.py           # Blended scoring (heuristic + AI)
|   +-- web3_client.py           # BNB Chain Web3 + liquidity lock detection
|   +-- scam_db.py               # Multi-source scam database
|   +-- firewall_prompt.py       # AI firewall system prompt
|   +-- onchain_recorder.py      # On-chain scan recording
+-- extension/                   # Chrome Extension (Manifest V3)
|   +-- manifest.json            # Permissions, content scripts
|   +-- inject.js                # Provider wrapping (world: MAIN, direct request)
|   +-- content.js               # Content script (overlay, messaging bridge)
|   +-- background.js            # Service worker (API calls, modal injection)
|   +-- popup.html / popup.js    # Extension popup (settings, scan history)
|   +-- overlay.css              # Firewall overlay styles
+-- contracts/
|   +-- ShieldBotVerifier.sol    # On-chain verification contract (BSC Mainnet)
+-- requirements.txt
+-- .env.example
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11+, FastAPI, uvicorn |
| Async HTTP | httpx, aiohttp |
| Web3 | web3.py 6.15, eth-utils |
| AI Analysis | Anthropic Claude API (AsyncAnthropic) |
| Transaction Simulation | Tenderly API |
| On-Chain Storage | BNB Greenfield (greenfield-python-sdk) |
| Contract Intelligence | GoPlus, BscScan, ChainAbuse, ScamSniffer |
| Honeypot Detection | Honeypot.is API |
| Market Data | DexScreener API |
| Reputation | Ethos Network API |
| Telegram | python-telegram-bot 20.7 |
| Extension | Manifest V3, EIP-6963, Chrome Scripting API |

---

## Hackathon

Built for **Good Vibes Only: OpenClaw Edition** - **Builders Track**

**Key Differentiators:**
- Real-time transaction firewall with MetaMask-compatible direct provider wrapping
- Composite ShieldScore from 6+ data sources with weighted category scoring
- Tenderly pre-execution simulation with asset delta prediction
- BNB Greenfield immutable forensic reports for high-risk transactions
- AI-powered forensic analysis via Claude (contextual risk explanations, not just flags)
- Interactive test page for end-to-end extension verification
- Fully async architecture (httpx, aiohttp, no blocking I/O)
- Telegram bot + Chrome extension + REST API -- three delivery channels, one engine

---

## Contact

- **Telegram**: [@Ggudman](https://t.me/Ggudman)
- **GitHub**: [Ridwannurudeen](https://github.com/Ridwannurudeen)
- **Twitter**: [@Ggudman1](https://twitter.com/Ggudman1)

---

**Repo**: https://github.com/Ridwannurudeen/shieldbot
