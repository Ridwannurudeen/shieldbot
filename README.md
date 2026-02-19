<div align="center">

# ShieldBot

### Autonomous Transaction Firewall for BNB Chain

**Good Vibes Only: OpenClaw Edition — Builders Track**

ShieldBot intercepts Web3 transactions in real-time, analyzes them through a multi-source intelligence pipeline with 6 pluggable analyzers, computes a weighted ShieldScore, and blocks honeypots, rug pulls, and malicious contracts before they execute. High-risk forensic reports are stored immutably on BNB Greenfield.

BNB Chain is the primary chain. To provide stronger protection, ShieldBot monitors 6 additional EVM chains — because scam campaigns frequently originate on Ethereum or L2s before migrating to BSC. Cross-chain intelligence means threats are caught earlier.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![BNB Chain](https://img.shields.io/badge/BNB-Chain-yellow)](https://www.bnbchain.org/)

**[Full Roadmap](ROADMAP.md)** | **[Live Dashboard](https://api.shieldbotsecurity.online/dashboard)** | **[Demo Video](https://youtu.be/a-PbFsZz0Ds)** | **[Telegram Bot](https://t.me/shieldbot_bnb_bot)**

</div>

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

## Core Features

<table>
<tr>
<td width="50%" valign="top">

### Transaction Firewall
**Chrome Extension + RPC Proxy**

Intercepts transactions before they reach your wallet. Works with MetaMask, any EIP-6963 wallet, or any wallet via RPC proxy — including mobile.

| Verdict | Score | Action |
|---------|-------|--------|
| **BLOCK** | >= 71 | Full-screen red modal, tx rejected |
| **WARN** | 31-70 | Orange overlay, proceed or cancel |
| **ALLOW** | < 31 | Silent passthrough |

</td>
<td width="50%" valign="top">

### Composite ShieldScore
**Weighted 0-100 Risk Score from 6 Analyzers**

```
Structural  x 0.40  (verification, bytecode)
Market      x 0.25  (liquidity, wash trading)
Behavioral  x 0.20  (wallet reputation)
Honeypot    x 0.15  (simulation, taxes)
+ IntentMismatch bonus
+ SignaturePermit bonus
```

Escalation rules override scores for confirmed honeypots, rug patterns, and destroyed contracts.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Mempool Monitoring
**Real-Time Threat Detection**

Monitors pending transactions across all 7 chains:
- **Sandwich attacks** — frontrun + backrun around victim swaps
- **Frontrunning** — higher-gas competing transactions
- **Suspicious approvals** — unlimited allowances in the mempool

Access via `/threats` in Telegram, `/api/mempool/alerts` in REST, or the live dashboard.

</td>
<td width="50%" valign="top">

### Rescue Mode
**Wallet Approval Scanner + One-Click Revoke**

Scans all token approvals in a wallet and flags dangerous ones:
- **Tier 1 — Alerts**: Plain-language risk explanations (`what_it_means`, `what_you_can_do`)
- **Tier 2 — Revoke**: Pre-built `approve(spender, 0)` transactions for instant cleanup

Access via `/rescue <wallet>` in Telegram or `GET /api/rescue/{wallet}`.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Campaign Graph Radar
**Cross-Chain Scam Campaign Detection**

Links deployers, funders, and contracts across all 7 chains:
- Funder clustering (same wallet funding multiple deployers)
- High-risk contract ratio detection
- Multi-chain scam campaign identification with severity scoring

Access via `/campaign <address>` in Telegram or `GET /api/campaign/{address}`.

</td>
<td width="50%" valign="top">

### Threat Intelligence Feed
**REST API for Real-Time Threat Data**

```
GET /api/threats/feed      High-risk contracts + mempool alerts
GET /api/campaigns/top     Most prolific scam deployers
```

Filter by chain, time range, and severity. Powers the live dashboard and third-party integrations.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Telegram Bot
**10 Commands — Full Security Suite**

```
/scan <address>     Contract security scan
/token <address>    Token safety check
/rescue <wallet>    Risky approval scanner
/threats            Live mempool threats
/campaign <address> Scam campaign links
/chain              Switch active chain
/history <address>  On-chain scan records
/report <address>   Report a scam
/start              Welcome & quick start
/help               All commands
```

Supports: **BSC, Ethereum, Base, Arbitrum, Polygon, Optimism, opBNB**
Chain prefixes: `eth:0x...` `base:0x...` `arb:0x...` `poly:0x...` `op:0x...`

**Try it:** [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot)

</td>
<td width="50%" valign="top">

### 5 Delivery Channels
**Protection Everywhere You Transact**

| Channel | Description |
|---------|-------------|
| **Chrome Extension** | Manifest V3, MetaMask + EIP-6963 |
| **RPC Proxy** | Any wallet, including mobile |
| **Telegram Bot** | 10-command security suite |
| **REST API** | Firewall, scan, rescue, threats |
| **TypeScript SDK** | npm-ready, typed client |

```typescript
import { ShieldBot } from 'shieldbot-sdk';
const shield = new ShieldBot({ apiKey: 'sb_...' });
const result = await shield.scan('0x...', { chainId: 56 });
```

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Threat Dashboard
**Real-Time Web UI**

Live dashboard at `/dashboard` with:
- Threat feed with chain filtering
- Mempool attack statistics
- Top scam campaigns
- Auto-refresh every 15 seconds

</td>
<td width="50%" valign="top">

### BNB Greenfield Storage
**Immutable On-Chain Forensic Reports**

High-risk transactions (score >= 50) are stored as immutable JSON objects on BNB Greenfield — tamper-proof forensic evidence with permanent public URLs.

</td>
</tr>
</table>

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

| # | Differentiator |
|---|----------------|
| 1 | **Transaction Firewall** — real-time interception via Chrome extension + RPC proxy (any wallet, including mobile) |
| 2 | **Composite ShieldScore** — weighted 0-100 score from 6 pluggable analyzers with escalation rules |
| 3 | **Mempool Monitoring** — sandwich attack, frontrun, and suspicious approval detection across 7 chains |
| 4 | **Rescue Mode** — scan wallet approvals, plain-language risk alerts, pre-built revoke transactions |
| 5 | **Campaign Graph Radar** — cross-chain deployer/funder correlation to detect coordinated scam campaigns |
| 6 | **BNB Greenfield** — immutable on-chain forensic reports for high-risk transactions |
| 7 | **Tenderly Simulation** — pre-execution simulation with asset delta prediction |
| 8 | **AI Forensic Analysis** — contextual risk explanations, not just flags |
| 9 | **7 EVM Chains** — cross-chain intelligence feeds back into BSC protection |
| 10 | **5 Delivery Channels** — Chrome extension, RPC proxy, Telegram bot (10 commands), REST API, TypeScript SDK |

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
