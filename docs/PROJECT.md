# ShieldBot - Project Overview

This is a historical BNB hackathon overview. The roadmap, projected metrics, example scores and release-status notes below are not current deployment evidence. Current coverage limits are documented in [TECHNICAL.md](TECHNICAL.md). In particular, the previously shipped extension defaults an omitted transaction `chainId` to BNB Chain; it does not establish multichain protection in that case. The provider-chain repair on this branch is unreleased.

## 🎥 Demo Video

**Watch the demo walkthrough:** [View on YouTube](https://youtu.be/NN95rom10R8)

See ShieldBot blocking honeypots in real-time, the Telegram bot displaying token names, and BNB Greenfield forensic reports in action.

---

## Problem Statement

The original BNB-focused pitch addressed honeypots, risky approvals and contracts that users cannot assess before signing. The Robinhood submission focuses on sellability, stock-token impostors and explicit missing coverage; see [the current README](../README.md).

The earlier market-loss figures, competitor comparisons and exclusivity claims have been removed because this repository does not establish them.

---

## Solution

**ShieldBot analyzes transaction and token risk before execution where its checks are available. Browser warnings can be overridden, and incomplete required coverage is not a safety decision.**

### How It Works

```
User initiates swap on PancakeSwap
         ↓
ShieldBot intercepts via Chrome Extension (before MetaMask sees it)
         ↓
Applicable intelligence checks (coverage and latency depend on chain and provider):
  • GoPlus: Contract verification, scam flags, bytecode analysis
  • Honeypot.is: Buy/sell simulation, tax detection
  • DexScreener: Liquidity depth, pair age, volume anomalies
  • Ethos Network: Wallet reputation scoring
  Optional Tenderly: Pre-execution simulation when configured and available
  • BscScan: Deployment age, transaction history
         ↓
RiskEngine computes composite ShieldScore (0-100):
  • Structural risk (40%): Verification, mint, proxy, ownership
  • Market risk (25%): Liquidity, volume, FDV ratio
  • Behavioral risk (20%): Wallet reputation, scam flags
  • Honeypot risk (15%): Confirmed honeypot, sell tax >50%
         ↓
Verdict determination:
  • HIGH RISK (71+): Red risk overlay (browser override remains)
  • MEDIUM RISK (31-70): WARNING overlay (user can proceed/cancel)
  • LOW RISK (0-30): Eligible for ALLOW only with complete required coverage
  • INCOMPLETE: Unknown; no automatic safety decision (browser overrides remain)
         ↓
For risk >=50: Attempt optional Greenfield upload when enabled; failure is possible
         ↓
Transaction proceeds/rejected based on verdict + user choice
```

### Visual Proof of Concept

**Extension BLOCK in Action:**

When a scan detects a honeypot or severe tax risk, the extension can display a red warning overlay showing:
- Risk Score: 85/100 (HIGH RISK)
- Critical flags explaining WHY it's dangerous (honeypot confirmed, cannot sell after buying, extreme sell tax)
- The user can cancel the transaction; the current risk overlay also offers a proceed override

**Result:** The warning appears before the wrapped request reaches the wallet. It is not an unbypassable block or a guarantee against loss; browser overrides and auxiliary coverage gaps are listed in [TECHNICAL.md](TECHNICAL.md).

**Telegram Bot Intelligence:**

The Telegram bot provides instant security analysis with token identification:
```
🟢 ShieldBot Intelligence Report

Token: Wrapped BNB (WBNB)
Address: 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
Risk Level: LOW (5/100)

✓ Contract verified on BscScan
✓ Ownership renounced
✓ High liquidity: $500M+
✓ 5+ years old, 50M+ transactions
```

The historical bot link is [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot). For current reproducible checks, use [JUDGE_GUIDE.md](JUDGE_GUIDE.md); this document does not verify live availability or response latency.

**Optional BNB Greenfield Report Storage:**

When enabled, the firewall can upload a public JSON report for risk scores of at least 50. The service creates an on-chain object record and sends the bytes to a storage provider; uploads can fail. This code path does not establish that a particular report exists or remains available. Reports include:
- Complete risk analysis with category breakdowns
- Timestamp and contract address
- All critical flags and danger signals
- Public URL accessible to anyone

**Watch the full demo:** [3-minute video walkthrough](https://youtu.be/a-PbFsZz0Ds)

### Key Innovations

1. **Real-Time Transaction Interception**
   - Chrome extension wraps wallet provider's `request()` method
   - Catches `eth_sendTransaction` BEFORE wallet signature
   - Discovers EIP-6963 providers; the unreleased provider-chain repair still needs real MetaMask/Rabby/EIP-6963 testing
   - Wraps discovered providers in page context; this is not a wallet-level guarantee against bypass

2. **Composite ShieldScore**
   - Weighted scoring from 4 categories (structural, market, behavioral, honeypot)
   - Escalation rules for confirmed rug patterns
   - Reduction rules for verified safe contracts
   - A risk recommendation is distinct from browser enforcement; proceed overrides remain

3. **Optional BNB Greenfield Forensic Reports**
   - Object metadata is recorded on-chain; JSON bytes go to a storage provider
   - Public URL returned only after a successful configured upload
   - Separate from the Robinhood evidence-hash registry described in the README

4. **Pre-Execution Simulation**
   - Optional Tenderly API reports success/revert, gas usage and asset deltas
   - Warns about reported failed subcalls and a large state-change count
   - A state-change warning is not proof of reentrancy; a simulation is a point-in-time observation

5. **Multi-Channel Delivery**
   - Chrome Extension: Real-time firewall for dApp users
   - Telegram Bot: Quick contract scans via @shieldbot_bnb_bot
   - REST API: Integration point for wallets/dApps

---

## Impact and Metrics

Risk warnings and explanations can inform a user's decision; loss prevention and false-positive reduction have not been measured here. Browser users can proceed past warnings. Recognized routers still require analysis of decoded path tokens.

The former projected scan counts, loss savings, report totals and accuracy improvements are withdrawn from this overview. They were not observed traction. No production scan count is supplied here; the current README reserves a field for an owner-verified `GET /api/stats` snapshot.

Repository code includes optional Tenderly and Greenfield clients. Their presence is not evidence that either service is enabled in a deployed backend. The extension chain repair is not scheduled for release before the submission deadline.

---

## BNB Chain Integration

### Historical BNB Scope

The initial product targeted BSC and opBNB. The current backend chain list is in the README; adapter availability alone does not establish complete risk coverage or shipped browser coverage.

### BNB-Specific Features

- **BSC Mainnet Scanning**: Contract verification via BscScan API
- **opBNB RPC Support**: Dual-chain analysis (BSC + opBNB)
- **Optional BNB Greenfield Storage**: Object records plus storage-provider JSON uploads, when enabled and successful
- **PancakeSwap Integration**: Router recognition and decoded swap-path token analysis
- **BNB Ecosystem Data**: Liquidity lock detection (PinkLock, Unicrypt on BSC)

---

## 4. Limitations & Future Work

### Current Limitations

**Technical Constraints:**
- **Off-Chain Analysis**: Provider data and risk computation occur off-chain. On-chain publication commits a result; it does not independently rerun the analysis.
- **API Dependency**: Core functionality requires external API availability (GoPlus, Honeypot.is, DexScreener, etc.). Graceful fallbacks exist, but total API failure would reduce effectiveness.
- **Browser Extension Only**: Currently supports Chrome/Brave via Manifest V3. Firefox and mobile wallet integration pending.
- **Chain-Specific Coverage**: Backend chain support does not establish browser-extension coverage. Each check depends on its provider and chain; the shipped extension's omitted-chain fallback is described above.

**Security & Risk:**
- **False Negatives Possible**: Sophisticated scams using novel techniques may evade detection. No measured false-negative reduction is claimed here.
- **Router Coverage**: Recognized swap paths are scanned; undecodable or unscanned paths remain unknown. This does not prove that a router or its future upgrades cannot be compromised.
- **API Key Management**: Users must secure their own API keys for optional features (Tenderly, Greenfield uploads). No centralized key management.
- **Test Coverage**: Core features tested (API, risk scoring, calldata, ownership), but E2E extension testing requires manual verification.

**User Experience:**
- **Setup Friction**: Local deployment requires Python 3.11+, multiple API keys, and extension sideloading. Not yet one-click install.
- **Rate Limiting**: BscScan free tier limits to 5 req/sec. High-volume users may experience delays.
- **No Mobile Support**: Chrome extension architecture incompatible with mobile. Mobile wallet SDK integration required.

**Data & Scalability:**
- **BNB Greenfield Costs**: Optional publication incurs storage and transaction costs; the firewall upload threshold is risk >=50.
- **Point-in-Time Results**: A recorded result does not establish future sellability or future contract behavior.
- **Centralized Bot Hosting**: Telegram bot runs on single VPS. No redundancy or load balancing yet.

### Short-Term Future Work (Next 3-6 Months)

**Immediate Priorities (Q2 2026):**
- Proposed opBNB verifier deployment; existing deployment status must be independently verified
- Add Firefox extension support (Manifest V3 compatible)
- Implement caching layer for common contract queries (reduce API calls)
- Add batch scanning API endpoint (analyze multiple addresses in one call)
- Create browser extension store listings (Chrome Web Store, Firefox Add-ons)

**User Experience Improvements:**
- One-click installer script (auto-configures .env with default settings)
- Hosted API endpoint (users don't need to run local server)
- Mobile wallet SDK for Trust Wallet and SafePal integration
- Desktop notifications for high-risk transaction attempts

**Security Enhancements:**
- ML-based anomaly detection trained on BNB Greenfield historical reports
- Cross-reference multiple honeypot detection APIs (reduce false negatives)
- Real-time smart contract upgrade monitoring (detect proxy changes)
- Community reporting system with reputation staking

**Scalability & Reliability:**
- Redis caching for frequent contract lookups
- Load balancer for Telegram bot (multi-instance deployment)
- Failover RPC endpoints (automatic BSC node switching on failure)
- Prometheus metrics and Grafana dashboards for monitoring

**Aligned with Existing Roadmap:**
- Phase 2 (Q2 2026): Extension marketplace deployment, mobile SDK, historical analysis
- Phase 3 (Q3 2026): On-chain verification contract, DAO governance, decentralized oracle
- Phase 4 (Q4 2026): Multi-chain support (Ethereum, Polygon, Arbitrum)

### Operational Verification

Historical provider-retry, startup-timing and keep-alive claims are omitted because this document does not demonstrate them. See the relevant service implementations and current tests for error behavior; repository code alone does not establish deployed availability.

---

## Roadmap

### Phase 1: Core Security Engine (Completed ✅)
- [x] Chrome extension with real-time transaction interception
- [x] Composite risk scoring from applicable provider data; no fixed number of successful sources is implied
- [x] Telegram bot for manual contract scans
- [x] Optional BNB Greenfield upload implementation; deployment not verified here
- [x] Optional Tenderly simulation implementation; provider coverage varies
- [x] Optional model-generated risk explanations

### Phase 2: Expansion & Hardening (Q2 2026)
- [ ] Browser extension marketplace deployment (Chrome Web Store, Firefox Add-ons)
- [ ] Mobile wallet SDK (Trust Wallet, SafePal integration)
- [ ] Historical scam pattern analysis (ML model trained on Greenfield reports)
- [ ] Community scam reporting system with reputation staking
- [ ] Support for additional DEXs (Biswap, THENA, Venus)

### Phase 3: Decentralization (Q3 2026)
- [ ] Deploy on-chain verification contract to opBNB
- [ ] DAO governance for risk threshold tuning
- [ ] Decentralized oracle network for off-chain data
- [ ] Incentive mechanism for data source providers
- [ ] Open API marketplace (wallets/dApps can integrate)

### Phase 4: Expansion (Q4 2026)
- [x] Ethereum, Base, Arbitrum, Polygon and Optimism backend adapters exist; provider coverage differs and deployment is not established here
- [ ] Non-EVM chain support (Solana, Sui)
- [ ] Unified cross-chain scam database
- [ ] Chain-agnostic ShieldScore standard

---

## Team & Commitment

**Builder**: Ridwan Nurudeen ([@Ggudman](https://t.me/Ggudman))

- **Active BNB Chain contributor**: OpenMind/OM1 PRs merged, privacy-focused robotics projects
- **Security-focused**: Experience with cryptographic protocols, blockchain security analysis
- **Full-stack blockchain developer**: Smart contracts (Solidity), Web3 integrations, Chrome extensions
- **Long-term commitment**: ShieldBot will continue post-hackathon as an open-source public good

---

## Open Source & Community

- **License**: MIT (fully open-source)
- **Repository**: https://github.com/Ridwannurudeen/shieldbot
- **Historical Bot Link (availability unverified)**: https://t.me/shieldbot_bnb_bot
- **Architecture**: Fully documented in `/docs/TECHNICAL.md`
- **Contributions Welcome**: Security researchers, data source integrations, ML/AI improvements

---

## Current Evidence

See [JUDGE_GUIDE.md](JUDGE_GUIDE.md) for offline Robinhood fixture replay and independent evidence-hash verification. The former competitor feature matrix was not backed by a reproducible comparison and has been removed.

---

## Contact & Links

- **Telegram**: [@Ggudman](https://t.me/Ggudman)
- **Twitter**: [@Ggudman1](https://twitter.com/Ggudman1)
- **GitHub**: [Ridwannurudeen](https://github.com/Ridwannurudeen)
- **Historical Demo Bot Link (availability unverified)**: [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot)
- **Repository**: https://github.com/Ridwannurudeen/shieldbot

---

**ShieldBot: Protecting BNB Chain users, one transaction at a time.** 🛡️
