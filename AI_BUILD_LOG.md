# AI Build Log - ShieldBot

This document describes how AI was used in the architecture, development, and debugging of ShieldBot. Submitted as part of the **Good Vibes Only: OpenClaw Edition** hackathon (Builders Track).

---

## 1. AI-Powered Transaction Firewall

ShieldBot's core loop is an AI-informed decision pipeline:

1. **Intercept** -- The Chrome extension wraps the wallet provider's `request()` method in the page context (`world: MAIN`). When `eth_sendTransaction` or `eth_signTransaction` is called, the transaction is intercepted before reaching the wallet.

2. **Analyze** -- The intercepted transaction is forwarded through the content script bridge to the background service worker, which calls the ShieldBot API (`POST /api/firewall`). The API runs five analyses in parallel:
   - Contract intelligence (GoPlus + BscScan + scam databases)
   - Honeypot detection (Honeypot.is simulation)
   - DEX market data (DexScreener -- liquidity, volume, pair age)
   - Wallet reputation (Ethos Network)
   - Transaction simulation (Tenderly pre-execution)

3. **Score** -- The RiskEngine (`core/risk_engine.py`) computes a weighted composite score from four categories: structural (40%), market (25%), behavioral (20%), honeypot (15%). Escalation rules override the base score for confirmed honeypots and rug pull patterns.

4. **AI Forensics** -- Claude analyzes the combined data and produces a natural-language verdict with contextual risk explanations, transaction impact summary, and actionable recommendations.

5. **Verdict** -- Based on the composite score, AI analysis, and simulation result, the API returns a classification (BLOCK_RECOMMENDED, HIGH_RISK, CAUTION, SAFE). The extension renders a full-screen modal for blocks, a warning overlay with proceed/cancel for warnings, or passes through silently for safe transactions.

6. **Record** -- For transactions scoring >= 50, a forensic report is uploaded to BNB Greenfield as an immutable JSON object with a public URL.

---

## 2. Composite Risk Intelligence (ShieldScore)

The RiskEngine (`core/risk_engine.py`) uses a weighted multi-source scoring model:

```
Composite = (Structural x 0.40) + (Market x 0.25) + (Behavioral x 0.20) + (Honeypot x 0.15)
```

### Structural Score (40% weight)
Analyzes contract properties via GoPlus and BscScan: verification status (+25), contract age < 7 days (+20), mint function (+15), proxy/upgradeable (+15), pause (+10), blacklist (+10), scam DB matches (+30), ownership not renounced (+5).

### Market Score (25% weight)
Evaluates trading health via DexScreener: low liquidity < $10k (+30), new pair < 24h (+25), extreme volatility > 200% (+20), wash trading detection (+25), volume/FDV anomaly for dead tokens (+20).

### Behavioral Score (20% weight)
Assesses wallet and deployer reputation via Ethos Network: severe reputation warning (+50), low reputation (+30), scam flags (+40).

### Honeypot Score (15% weight)
Honeypot.is simulation results: honeypot confirmed (+80), cannot sell (+60), extreme sell tax > 50% (+40), high sell tax > 20% (+20), high buy tax > 20% (+10).

### Escalation Rules
Hard floors override the weighted score for critical patterns:
- Honeypot confirmed -> floor at 80
- Rug pull pattern (mint + proxy + owner not renounced) -> floor at 85
- Severe reputation + new pair < 24h -> +15 escalation
- Positive signals (renounced ownership + $100k+ liquidity) -> -20 reduction

### Confidence Score
A data completeness metric (0-100) based on how many data points were actually available across all four sources. Higher confidence means more data sources returned results.

---

## 3. Tenderly Transaction Simulation

The transaction simulator (`services/tenderly_service.py`) calls the Tenderly API to predict transaction outcomes before on-chain execution:

- **Pre-execution simulation**: Sends the full transaction payload (from, to, value, data, gas) to Tenderly's simulation endpoint with state overrides for balance
- **Revert detection**: If the simulation shows the transaction would revert, ShieldBot includes the revert reason in the analysis. Reverts only escalate to BLOCK when the risk score is already >= 30 (avoids blocking simple failed txs)
- **Asset delta parsing**: Extracts balance changes from the simulation to show the user exactly what tokens they would gain or lose
- **Warning generation**: Produces human-readable warnings for asset outflows, failed subcalls, and suspicious patterns

The simulator is fully async (httpx) and integrates into the parallel analysis pipeline. If Tenderly is not configured, the analysis proceeds without simulation data.

---

## 4. BNB Greenfield Forensic Reports

The Greenfield service (`services/greenfield_service.py`) stores forensic evidence on-chain using the official greenfield-python-sdk:

- **Trigger**: Any transaction with composite risk score >= 50 automatically generates a report
- **Content**: Full JSON report containing report ID, target address, composite score breakdown (all 4 categories), critical flags, confidence level, risk archetype, AI analysis, and simulation results
- **Storage**: Objects are uploaded to BNB Greenfield mainnet via the official SDK with KeyManager signing
- **Immutability**: Once stored, reports cannot be modified or deleted -- providing tamper-proof evidence
- **Public access**: Each report gets a public URL: `https://greenfield-sp.bnbchain.org/view/shieldbot-reports/reports/<id>.json`

---

## 5. Chrome Extension Architecture

The extension uses a three-layer architecture designed for MetaMask compatibility:

### inject.js (world: MAIN)
Runs in the page context. Wraps `provider.request()` directly on the existing provider object (no Proxy, no Object.defineProperty replacement). Listens for EIP-6963 provider announcements to intercept modern wallets. Uses `Object.defineProperty` on `window.ethereum` only as a setter trap to catch late-loading providers. Communicates with the content script via `window.postMessage`.

### content.js (ISOLATED world)
Bridges between the page world and the service worker. Receives `SHIELDAI_TX_INTERCEPT` messages from inject.js, forwards to background via `chrome.runtime.sendMessage`, and relays verdicts back. Injects the overlay CSS and handles modal rendering for block/warn verdicts.

### background.js (service worker)
Makes the actual API calls to the ShieldBot backend (`/api/firewall`). Maps API response classifications to extension actions (BLOCK/WARN/ALLOW). Injects block/warning modals into the page via `chrome.scripting.executeScript`. Manages pending transaction state and user decisions (proceed/cancel).

This "direct request wrapping" approach was chosen specifically because MetaMask detects and blocks Proxy-based providers. The original implementation used `new Proxy(window.ethereum, ...)` which MetaMask rejected. Switching to direct `request()` method wrapping on the existing provider object fixed compatibility.

---

## 6. AI in Development (Vibe Coding)

AI (Claude Code) was used extensively throughout development:

### Architecture Design
- Designed the layered architecture (Services -> Engine -> Delivery)
- Chose the 4-category weighted scoring model with escalation rules over a simple threshold approach
- Decided on 6+ data source aggregation for higher confidence scoring
- Selected httpx over pure aiohttp for Tenderly/Greenfield integration (cleaner async API)

### Core Implementation
- Built the RiskEngine with configurable category weights and escalation overrides
- Implemented the Tenderly simulator with state overrides and asset delta parsing
- Created the Greenfield service with official SDK integration and async initialization
- Designed the calldata decoder with router whitelisting for PancakeSwap V2/V3 and 1inch
- Built the DexService with volume/FDV anomaly detection for dead token identification

### Extension Debugging
- Diagnosed MetaMask incompatibility with the original Proxy-based approach (`new Proxy(window.ethereum, ...)`)
- Switched to direct `request()` wrapping in `world: MAIN` -- MetaMask no longer rejects the provider
- Added EIP-6963 support for Rabby and modern wallet providers
- Fixed content script bridge to handle async verdict flow correctly
- Added `host_permissions` to manifest so the service worker can reach the API from any site
- Built the `/test` page with three pre-configured test cases (honeypot, safe router, unverified contract) for end-to-end extension testing

### Integration
- Parallelized all five data source queries (contract, honeypot, dex, ethos, tenderly) with asyncio
- Added whitelisted router fast-path to skip deep scan for PancakeSwap, 1inch, and other trusted contracts
- Implemented graceful degradation (Tenderly/Greenfield/AI disabled if not configured)
- Fixed Greenfield SDK configuration to avoid pydantic-settings env conflicts
- Switched Greenfield from testnet to mainnet endpoints
- Fixed state override for Tenderly simulation balance to avoid insufficient-funds reverts

---

## Related Files

| File | Purpose |
|------|---------|
| `core/risk_engine.py` | Composite weighted risk scoring (4 categories) |
| `services/tenderly_service.py` | Tenderly transaction simulation |
| `services/contract_service.py` | GoPlus + BscScan contract intelligence |
| `services/honeypot_service.py` | Honeypot.is simulation |
| `services/dex_service.py` | DexScreener market data + anomaly detection |
| `services/ethos_service.py` | Ethos Network reputation scoring |
| `services/greenfield_service.py` | BNB Greenfield report storage (SDK) |
| `utils/ai_analyzer.py` | Claude AI forensic analysis |
| `utils/calldata_decoder.py` | Transaction calldata decoding + router whitelist |
| `utils/risk_scorer.py` | Blended scoring (heuristic + AI) |
| `api.py` | FastAPI backend (firewall, scan, test page) |
| `bot.py` | Telegram bot |
| `extension/inject.js` | Provider wrapping (world: MAIN, direct request) |
| `extension/content.js` | Content script bridge + overlay rendering |
| `extension/background.js` | Service worker (API calls, modal injection) |
