# ShieldBot — Autonomous Transaction Firewall for BNB Chain

**Good Vibes Only: OpenClaw Edition — Builders Track**

ShieldBot is an autonomous transaction firewall built for BNB Chain. It intercepts Web3 transactions in real-time, analyzes them through a multi-source intelligence pipeline with 6 pluggable analyzers, computes a weighted ShieldScore, and blocks honeypots, rug pulls, and malicious contracts before they execute. High-risk forensic reports are stored immutably on BNB Greenfield.

BNB Chain is the primary chain and the core of ShieldBot. To provide stronger protection for BNB users, ShieldBot also monitors 6 additional EVM chains — because scam campaigns frequently originate on Ethereum or L2s before migrating to BSC. Cross-chain intelligence means threats are caught earlier.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![BNB Chain](https://img.shields.io/badge/BNB-Chain-yellow)](https://www.bnbchain.org/)

**[Full Roadmap](ROADMAP.md)** | **[Live Dashboard](https://api.shieldbotsecurity.online/dashboard)** | **[Demo Video](https://youtu.be/a-PbFsZz0Ds)**

---

## Supported Chains

| Chain | ID | Role | Status |
|-------|-----|------|--------|
| **BNB Smart Chain** | **56** | **Primary** | **Live** |
| **opBNB** | **204** | **BNB L2** | **Live** |
| Ethereum | 1 | Cross-chain intel | Live |
| Base | 8453 | Cross-chain intel | Live |
| Arbitrum One | 42161 | Cross-chain intel | Live |
| Polygon PoS | 137 | Cross-chain intel | Live |
| Optimism | 10 | Cross-chain intel | Live |

---

## How It Works

1. **Intercept** — The Chrome extension wraps the wallet provider's `request()` method in `world: MAIN`. When `eth_sendTransaction` or `eth_signTransaction` is called, the transaction is intercepted before reaching the wallet. The RPC proxy provides the same protection for any wallet (including mobile) without an extension.

2. **Analyze** — The intercepted transaction runs through 6 pluggable analyzers in parallel: Structural (contract verification, bytecode patterns), Market (DEX liquidity, wash trading), Behavioral (wallet reputation), Honeypot (simulation), Intent Mismatch (disguised selectors, unlimited approvals), and Signature/Permit (EIP-2612, Permit2, Seaport).

3. **Score** — The RiskEngine computes a weighted composite ShieldScore. Escalation rules override the base score for confirmed honeypots, rug pull patterns, and destroyed contracts.

4. **Verdict** — Based on the composite score: BLOCK (>= 71), WARN (31-70), or ALLOW (< 31). The extension renders a full-screen modal for blocks, a warning overlay for medium risk, or passes through silently.

5. **Record** — High-risk transactions are recorded to BNB Greenfield as immutable forensic reports. The deployer/funder indexer runs in the background to build campaign graphs.

---

## Architecture

```
+-------------------------------------------------------------------------+
|  DELIVERY                                                                |
|  - Chrome Extension (Manifest V3, MetaMask + EIP-6963)                   |
|  - RPC Proxy (/rpc/{chain_id} — works with any wallet including mobile)  |
|  - Telegram Bot (/scan, /token, /history, /report, chain selector)       |
|  - REST API (/api/firewall, /api/scan, /api/rescue, /api/threats/feed)   |
|  - SDK (shieldbot-sdk — TypeScript, npm-publishable)                     |
|  - Threat Dashboard (/dashboard — real-time web UI)                      |
+-------------------------------------------------------------------------+
|  INTELLIGENCE ENGINE                                                     |
|  - Analyzer Registry (pluggable pipeline, weight normalization)          |
|  - RiskEngine (composite weighted scoring + escalation rules)            |
|  - Campaign Graph Radar (cross-chain entity correlation)                 |
|  - Mempool Monitor (sandwich detection, frontrun detection)              |
|  - Rescue Mode (approval scanning, one-click revoke)                     |
|  - PolicyEngine (STRICT / BALANCED modes)                                |
|  - Calibration (data-driven threshold tuning from outcome events)        |
+-------------------------------------------------------------------------+
|  ANALYZERS (6 pluggable plugins)                                         |
|  - Structural: verification, age, bytecode (mint, proxy, blacklist)      |
|  - Market: liquidity, volatility, wash trading, volume/FDV anomaly       |
|  - Behavioral: Ethos wallet reputation, scam flags                       |
|  - Honeypot: honeypot.is simulation, buy/sell tax                        |
|  - IntentMismatch: disguised selectors, unlimited approvals              |
|  - SignaturePermit: EIP-2612, Permit2, Seaport zero-price detection      |
+-------------------------------------------------------------------------+
|  DATA SERVICES                                                           |
|  - ContractService (GoPlus + Etherscan v2 + scam databases)              |
|  - HoneypotService (honeypot.is simulation)                              |
|  - DexService (DexScreener market data + volume anomalies)               |
|  - EthosService (wallet reputation scoring)                              |
|  - TenderlySimulator (pre-execution simulation)                          |
|  - GreenfieldService (BNB Greenfield immutable report storage)           |
+-------------------------------------------------------------------------+
|  INFRASTRUCTURE                                                          |
|  - ChainAdapter (abstract base + 7 EVM adapters)                         |
|  - SQLite WAL (contract_scores, outcome_events, deployers, funder_links) |
|  - API Auth (sb_ keys, SHA-256 hashed, tiered rate limits)               |
|  - DeployerIndexer (background async queue worker)                       |
|  - Evaluation Pipeline (benchmark CLI: precision/recall/F1)              |
+-------------------------------------------------------------------------+
```

---

## Features

### Transaction Firewall (Chrome Extension + RPC Proxy)

The extension intercepts transactions before they reach the wallet. The RPC proxy provides the same protection for any wallet — users configure `https://api.shieldbotsecurity.online/rpc/56` as their BSC RPC in MetaMask.

- **BLOCK**: Critical risk — full-screen red modal, transaction rejected
- **WARN**: Medium risk — orange warning overlay with risk details, proceed/cancel
- **ALLOW**: Low risk — silent passthrough (whitelisted routers fast-path)

### Composite Risk Scoring (ShieldScore)

Weighted 0-100 risk score from 6 analyzer categories:

```
Composite = (Structural x 0.40) + (Market x 0.25) + (Behavioral x 0.20) + (Honeypot x 0.15)
            + IntentMismatch bonus + SignaturePermit bonus

Escalation Rules:
  - Honeypot confirmed                  -> floor at 80
  - mint + proxy + owner not renounced  -> floor at 85
  - Destroyed contract + sim failed     -> floor at 80
  - Severe reputation + new pair <24h   -> +15
  - Renounced + high liquidity + safe   -> -20
```

### Mempool Monitoring

Real-time detection of:
- **Sandwich attacks** — frontrun + backrun patterns around victim swaps
- **Frontrunning** — higher-gas competing transactions
- **Suspicious approvals** — unlimited/large approvals in pending transactions

### Rescue Mode

- **Tier 1 (Alerts)** — Scans wallet approvals, explains risks in plain language (`what_it_means`, `what_you_can_do`)
- **Tier 2 (Revoke)** — Pre-built `approve(spender, 0)` transactions for one-click approval cleanup

### Campaign Graph Radar

Cross-chain entity correlation linking deployers, funders, and contracts across all 7 chains:
- Funder clustering (same wallet funding multiple deployers)
- High-risk contract ratio detection
- Multi-chain scam campaign identification

### Threat Intelligence Feed

REST API for real-time threat data:
- `GET /api/threats/feed` — high-risk contracts + mempool alerts
- `GET /api/campaigns/top` — most prolific scam deployers
- Filter by chain, time range, severity

### SDK (shieldbot-sdk)

TypeScript SDK for wallet/dApp integration:

```typescript
import { ShieldBot } from 'shieldbot-sdk';
const shield = new ShieldBot({ apiKey: 'sb_...' });

const result = await shield.scan('0x...', { chainId: 56 });
const rescue = await shield.rescue('0xMyWallet', 56);
const threats = await shield.getThreats({ chainId: 1, limit: 20 });
```

### Threat Dashboard

Real-time web dashboard at `/dashboard` showing:
- Live threat feed with chain filtering
- Mempool attack statistics
- Top scam campaigns
- Auto-refreshing every 15 seconds

### Telegram Bot

```
/start              - Welcome message
/scan <address>     - Security scan for any contract
/token <address>    - Token safety check (honeypot, taxes, liquidity)
/history <address>  - View on-chain scan records
/report <address>   - Report a scam address
/help               - Command list
```

Supports chain selection (BSC, ETH, Base, Arbitrum, Polygon, Optimism, opBNB).

**Try it:** [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot)

### BNB Greenfield On-Chain Reports

High-risk transactions (score >= 50) are stored as immutable JSON objects on BNB Greenfield — tamper-proof forensic evidence with public URLs.

---

## Quick Start

### Demo Video

**3-Minute Walkthrough:** [View on YouTube](https://youtu.be/a-PbFsZz0Ds)

### Run Locally

```bash
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot

python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your API keys

# Run FastAPI backend
uvicorn api:app --host 0.0.0.0 --port 8000

# Run Telegram bot (separate terminal)
python bot.py
```

### Install Chrome Extension

1. Open `chrome://extensions` in Chrome
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** -> select the `extension/` folder
4. Visit the test page (`http://localhost:8000/test`) to verify

### Use the RPC Proxy (No Extension Needed)

Add this as a custom RPC in MetaMask or any wallet:
- BSC: `https://api.shieldbotsecurity.online/rpc/56`
- Ethereum: `https://api.shieldbotsecurity.online/rpc/1`
- Base: `https://api.shieldbotsecurity.online/rpc/8453`
- Arbitrum: `https://api.shieldbotsecurity.online/rpc/42161`
- Polygon: `https://api.shieldbotsecurity.online/rpc/137`
- Optimism: `https://api.shieldbotsecurity.online/rpc/10`
- opBNB: `https://api.shieldbotsecurity.online/rpc/204`

### Configuration

```env
# Required
TELEGRAM_BOT_TOKEN=your_bot_token
BSCSCAN_API_KEY=your_bscscan_key

# RPC endpoints (defaults provided)
BSC_RPC_URL=https://bsc-dataseed.binance.org/
ETH_RPC_URL=https://eth.llamarpc.com
BASE_RPC_URL=https://mainnet.base.org
ARBITRUM_RPC_URL=https://arb1.arbitrum.io/rpc
POLYGON_RPC_URL=https://polygon-rpc.com
OPTIMISM_RPC_URL=https://mainnet.optimism.io
OPBNB_RPC_URL=https://opbnb-mainnet-rpc.bnbchain.org

# Optional Etherscan keys (fall back to BSCSCAN_API_KEY via Etherscan v2)
ETHERSCAN_API_KEY=
BASESCAN_API_KEY=
ARBISCAN_API_KEY=
POLYGONSCAN_API_KEY=
OPBNBSCAN_API_KEY=
OPTIMISM_API_KEY=

# Simulation + Storage
TENDERLY_API_KEY=your_tenderly_key
TENDERLY_PROJECT_ID=your_tenderly_project_id
GREENFIELD_PRIVATE_KEY=your_greenfield_private_key

# AI Analysis
ANTHROPIC_API_KEY=your_anthropic_key

# Policy mode (STRICT or BALANCED)
POLICY_MODE=BALANCED

# Admin (for API key management)
ADMIN_SECRET=your_admin_secret
```

---

## API Reference

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/firewall` | Transaction firewall analysis (Chrome extension) |
| POST | `/api/scan` | Contract/token security scan |
| GET | `/api/health` | Service status |
| GET | `/test` | Chrome extension test page |

### Mempool Monitoring

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/mempool/alerts` | Recent mempool alerts (sandwich, frontrun) |
| GET | `/api/mempool/stats` | Monitoring statistics |

### Rescue Mode

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/rescue/{wallet}` | Scan approvals + generate revoke txs |

### Campaign Intelligence

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/campaign/{address}` | Cross-chain entity graph |
| GET | `/api/campaigns/top` | Most prolific scam deployers |

### Threat Feed

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/threats/feed` | Real-time threat intelligence |
| GET | `/api/threats/subscribe` | Subscription info |

### User Reporting

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/outcome` | Record user decision/outcome |
| POST | `/api/report` | Community false positive/negative report |
| GET | `/api/usage` | API key usage stats |

### RPC Proxy

| Method | Path | Description |
|--------|------|-------------|
| POST | `/rpc/{chain_id}` | JSON-RPC proxy with firewall |

### Dashboard

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | Public threat dashboard |

---

## Project Structure

```
shieldbot/
├── api.py                      # FastAPI backend — all REST endpoints
├── bot.py                      # Telegram bot — multi-command scanner
├── ROADMAP.md                  # V2 roadmap (3 phases)
│
├── core/                       # Core engine
│   ├── analyzer.py             # Analyzer ABC + AnalysisContext + AnalyzerResult
│   ├── registry.py             # Pluggable analyzer registry
│   ├── risk_engine.py          # Composite weighted scoring + escalation
│   ├── policy.py               # PolicyEngine (STRICT/BALANCED)
│   ├── database.py             # Async SQLite with WAL mode
│   ├── auth.py                 # API key management (tiered rate limits)
│   ├── calibration.py          # Data-driven threshold calibration
│   ├── indexer.py              # Background DeployerIndexer
│   ├── config.py               # Pydantic Settings from .env
│   └── container.py            # ServiceContainer (dependency injection)
│
├── analyzers/                  # 6 pluggable analyzer plugins
│   ├── structural.py           # Contract verification, age, bytecode
│   ├── market.py               # DEX liquidity, volatility, wash trading
│   ├── behavioral.py           # Wallet reputation (Ethos)
│   ├── honeypot.py             # Honeypot.is simulation
│   ├── intent.py               # Intent mismatch (disguised selectors)
│   └── signature.py            # EIP-2612, Permit2, Seaport analysis
│
├── adapters/                   # Chain-specific adapters (7 chains)
│   ├── evm_base.py             # Shared EVM adapter base class
│   ├── bsc.py                  # BSC (56)
│   ├── eth.py                  # Ethereum (1)
│   ├── base_chain.py           # Base (8453)
│   ├── arbitrum.py             # Arbitrum (42161)
│   ├── polygon.py              # Polygon (137)
│   ├── optimism.py             # Optimism (10)
│   └── opbnb.py                # opBNB (204)
│
├── services/                   # Intelligence + feature services
│   ├── contract_service.py     # GoPlus + Etherscan + scam DB
│   ├── honeypot_service.py     # Honeypot.is
│   ├── dex_service.py          # DexScreener
│   ├── ethos_service.py        # Ethos Network reputation
│   ├── tenderly_service.py     # Tenderly simulation
│   ├── greenfield_service.py   # BNB Greenfield storage
│   ├── mempool_service.py      # Mempool monitoring (sandwich/frontrun)
│   ├── rescue_service.py       # Rescue Mode (approvals + revoke)
│   └── campaign_service.py     # Campaign Graph Radar (cross-chain)
│
├── rpc/                        # JSON-RPC Proxy
│   ├── proxy.py                # Intercepts eth_sendTransaction/Raw
│   └── router.py               # FastAPI router for /rpc/{chain_id}
│
├── sdk/                        # TypeScript SDK (shieldbot-sdk)
│   ├── package.json
│   ├── tsconfig.json
│   └── src/index.ts            # Full typed client
│
├── dashboard/                  # Public threat dashboard
│   └── index.html              # Real-time single-page app
│
├── extension/                  # Chrome Extension (Manifest V3)
│   ├── manifest.json
│   ├── inject.js               # Provider wrapper (world: MAIN)
│   ├── content.js / background.js / popup.html/js
│   └── overlay.css
│
├── eval/                       # Evaluation pipeline
│   ├── live_scorer.py          # Live benchmark against real pipeline
│   ├── benchmark.py            # Precision/recall/F1
│   └── data/benchmark_v1.json
│
├── utils/                      # Utilities
│   ├── ai_analyzer.py          # AI forensic analysis
│   ├── calldata_decoder.py     # Function selector decode
│   ├── web3_client.py          # Multi-chain Web3 router
│   ├── chain_info.py           # Chain metadata (7 chains)
│   ├── scam_db.py              # Scam address database
│   └── onchain_recorder.py     # On-chain recording
│
├── tests/                      # Test suite (25+ files)
├── docs/                       # Documentation
├── deploy/                     # nginx/caddy/certbot setup
├── contracts/                  # ShieldBotVerifier.sol
└── scripts/                    # Key management, PDF builders
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11+, FastAPI, uvicorn |
| Async HTTP | aiohttp |
| Web3 | web3.py 6.15+, eth-account, rlp |
| Database | SQLite with WAL mode (aiosqlite) |
| AI Analysis | Anthropic Claude API |
| Simulation | Tenderly API |
| On-Chain Storage | BNB Greenfield |
| Contract Intel | GoPlus, Etherscan v2 API, scam databases |
| Honeypot Detection | Honeypot.is API |
| Market Data | DexScreener API |
| Reputation | Ethos Network API |
| Telegram | python-telegram-bot 20.7 |
| Extension | Manifest V3, EIP-6963 |
| SDK | TypeScript, tsup (CJS + ESM) |
| Settings | Pydantic Settings |

---

## Testing

```bash
pip install pytest pytest-asyncio pytest-cov

# Run all tests
pytest tests/ -v

# Run evaluation benchmark
python eval/live_scorer.py
```

---

## Hackathon

Built for **Good Vibes Only: OpenClaw Edition** — **Builders Track** (BNB Chain).

**Key Differentiators:**
- Real-time transaction firewall with MetaMask-compatible direct provider wrapping
- Composite ShieldScore from 6+ data sources with weighted category scoring
- Tenderly pre-execution simulation with asset delta prediction
- BNB Greenfield immutable forensic reports for high-risk transactions
- AI-powered forensic analysis (contextual risk explanations, not just flags)
- Mempool monitoring for sandwich attacks and frontrunning on BSC
- Rescue Mode — scan approvals and one-click revoke dangerous ones
- Campaign Graph Radar — detect coordinated scam campaigns across chains
- Cross-chain intelligence feeds back into BSC protection (scams migrate between chains)
- RPC proxy — zero-friction protection for any wallet, including mobile
- 7 EVM chains, 6 pluggable analyzers, 5 delivery channels (extension, RPC proxy, Telegram, API, SDK)

**Development Phases:**
- **Phase 1** (Foundation): ChainAdapter interface, pluggable analyzer registry, policy modes, API auth, contract reputation DB, deployer indexer, outcome tracking
- **Phase 2** (Detection + Distribution): Intent mismatch analyzer, signature/permit analyzer, confidence calibration, evaluation pipeline, community reporting, Ethereum/Base adapters, RPC proxy, Telegram scan-by-address
- **Phase 3** (Moat Features + Growth): Campaign Graph Radar, mempool monitoring, Rescue Mode, Arbitrum/Polygon/Optimism/opBNB adapters, SDK, threat dashboard, threat feed API

---

## Contact

- **Telegram**: [@Ggudman](https://t.me/Ggudman)
- **GitHub**: [Ridwannurudeen](https://github.com/Ridwannurudeen)
- **Twitter**: [@Ggudman1](https://twitter.com/Ggudman1)

---

**Live:** https://api.shieldbotsecurity.online | **Repo:** https://github.com/Ridwannurudeen/shieldbot
