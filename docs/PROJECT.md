# ShieldBot - Project Overview

## 🎥 Demo Video

**Watch the 3-minute walkthrough:** [View on Loom](https://www.loom.com/share/6769a5e1ab744286b48380175fa6c50c)

See ShieldBot blocking honeypots in real-time, the Telegram bot displaying token names, and BNB Greenfield forensic reports in action.

---

## Problem Statement

**The DeFi security crisis on BNB Chain is costing users billions.**

In 2024 alone, over $2.3 billion was stolen through smart contract exploits, rug pulls, and honeypot tokens across all chains, with BNB Chain being a primary target due to its high trading volume and ease of token deployment. Current security solutions have critical gaps:

### Current Solutions Fall Short

1. **Post-Mortem Block Explorers** (BscScan, DexScreener)
   - Users check AFTER buying
   - No real-time intervention
   - Requires manual verification knowledge

2. **Centralized Token Scanners** (TokenSniffer, RugDoc)
   - Single-point-of-failure
   - High false positive rates
   - No transaction interception
   - Users still click "approve" on risky contracts

3. **Wallet Warnings** (MetaMask Phishing Detection)
   - Only flags known scam domains
   - Cannot analyze contract bytecode in real-time
   - No honeypot detection
   - No simulation of transaction outcomes

4. **Manual Due Diligence**
   - Time-consuming (20+ min per token)
   - Requires expertise (reading bytecode, checking liquidity locks)
   - Users skip it in FOMO situations
   - Inconsistent methodology

### The Core Problem

**Users need protection BEFORE transactions execute, not after losses occur.**

There is no autonomous firewall that:
- Intercepts transactions at the wallet level
- Runs composite intelligence from multiple sources in parallel
- Simulates transaction outcomes before execution
- Blocks confirmed scams automatically
- Records forensic evidence immutably on-chain

---

## Solution

**ShieldBot is an autonomous transaction firewall for BNB Chain that protects users from honeypots, rug pulls, and malicious contracts in real-time.**

### How It Works

```
User initiates swap on PancakeSwap
         ↓
ShieldBot intercepts via Chrome Extension (before MetaMask sees it)
         ↓
Parallel intelligence gathering (6 sources, <2 seconds):
  • GoPlus: Contract verification, scam flags, bytecode analysis
  • Honeypot.is: Buy/sell simulation, tax detection
  • DexScreener: Liquidity depth, pair age, volume anomalies
  • Ethos Network: Wallet reputation scoring
  • Tenderly: Pre-execution simulation (success/revert, asset deltas)
  • BscScan: Deployment age, transaction history
         ↓
RiskEngine computes composite ShieldScore (0-100):
  • Structural risk (40%): Verification, mint, proxy, ownership
  • Market risk (25%): Liquidity, volume, FDV ratio
  • Behavioral risk (20%): Wallet reputation, scam flags
  • Honeypot risk (15%): Confirmed honeypot, sell tax >50%
         ↓
Verdict determination:
  • HIGH RISK (71+): AUTO-BLOCK with full-screen red modal
  • MEDIUM RISK (31-70): WARNING overlay (user can proceed/cancel)
  • LOW RISK (0-30): ALLOW silently (no friction)
         ↓
For risky transactions: Upload forensic report to BNB Greenfield
         ↓
Transaction proceeds/rejected based on verdict + user choice
```

### Visual Proof of Concept

**Extension BLOCK in Action:**

ShieldBot's most powerful feature is its ability to hard-block dangerous transactions. When analyzing a honeypot token with 99% sell tax, the extension displays a full-screen red modal showing:
- Risk Score: 85/100 (HIGH RISK)
- Critical flags explaining WHY it's dangerous (honeypot confirmed, cannot sell after buying, extreme sell tax)
- The transaction is completely blocked - users cannot proceed even if they choose to

**Result:** The user's funds are protected BEFORE the transaction executes. This is fundamentally different from post-mortem block explorers or warnings that users can ignore.

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

Users can scan any address in seconds without technical knowledge. The bot is live at [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot) for judges to test.

**BNB Greenfield Immutable Storage:**

High-risk transaction reports are stored on BNB Greenfield as public, immutable JSON objects. This creates a permanent, community-verifiable database of dangerous contracts on BNB Chain. Each report includes:
- Complete risk analysis with category breakdowns
- Timestamp and contract address
- All critical flags and danger signals
- Public URL accessible to anyone

**Watch the full demo:** [3-minute video walkthrough](https://www.loom.com/share/6769a5e1ab744286b48380175fa6c50c)

### Key Innovations

1. **Real-Time Transaction Interception**
   - Chrome extension wraps wallet provider's `request()` method
   - Catches `eth_sendTransaction` BEFORE wallet signature
   - Works with MetaMask, Rabby, Coinbase Wallet (EIP-6963 compatible)
   - Cannot be bypassed (runs in page context, `world: MAIN`)

2. **Composite ShieldScore**
   - Weighted scoring from 4 categories (structural, market, behavioral, honeypot)
   - Escalation rules for confirmed rug patterns
   - Reduction rules for verified safe contracts
   - 75%+ confidence threshold for auto-block

3. **BNB Greenfield Forensic Reports**
   - Immutable on-chain storage of high-risk transaction analysis
   - Public URLs for community verification
   - Tamper-proof evidence trail
   - Enables pattern recognition across scams

4. **Pre-Execution Simulation**
   - Tenderly API simulates transaction before signing
   - Predicts success/revert, gas usage, asset deltas
   - Detects failed internal calls and reentrancy
   - Shows "what will happen" before it happens

5. **Multi-Channel Delivery**
   - Chrome Extension: Real-time firewall for dApp users
   - Telegram Bot: Quick contract scans via @shieldbot_bnb_bot
   - REST API: Integration point for wallets/dApps

---

## Impact

### User Protection
- **Prevents losses BEFORE they occur** (not just alerts)
- **Zero-knowledge protection**: Users don't need to understand bytecode, liquidity locks, or honeypot mechanisms
- **Frictionless for safe transactions**: PancakeSwap, 1inch, verified DEXs pass through silently
- **Transparent risk explanations**: AI-powered analysis explains WHY a contract is dangerous

### Ecosystem Benefits
- **Reduces scam success rate** → Fewer victims → Less incentive for scammers
- **Builds trust in BNB Chain DeFi** → More users willing to explore new tokens
- **Immutable scam database** on BNB Greenfield → Community-verifiable threat intelligence
- **Open-source security layer** → Other projects can integrate ShieldBot API

### Measurable Outcomes (Projected)
- **$10M+ in losses prevented** in first year (based on blocking 1 in 500 risky swaps)
- **50,000+ scans performed** via Telegram bot and extension
- **5,000+ forensic reports** stored on BNB Greenfield
- **95% reduction in false positives** vs. single-source scanners (via composite scoring)

### Current Traction
- Live Telegram bot: [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot)
- Chrome extension deployed and tested
- BNB Greenfield integration live (testnet)
- Multi-source intelligence pipeline operational

---

## BNB Chain Integration

### Why BNB Chain?

ShieldBot is purpose-built for BNB Chain because:

1. **High Trading Volume**
   - BNB Chain processes 3M+ daily transactions
   - PancakeSwap is the 2nd largest DEX globally
   - High activity = high scam exposure

2. **Easy Token Deployment**
   - Low gas fees enable rapid token launches
   - Many unverified/new contracts daily
   - Perfect environment for honeypots and rug pulls

3. **BNB Greenfield Native Integration**
   - Decentralized storage for forensic reports
   - Lower costs than traditional storage
   - Built-in redundancy and immutability
   - Native to BNB ecosystem

4. **opBNB Support**
   - Layer-2 scalability for high-frequency scans
   - Sub-cent transaction costs
   - Future: Real-time on-chain verification contract

### BNB-Specific Features

- **BSC Mainnet Scanning**: Contract verification via BscScan API
- **opBNB RPC Support**: Dual-chain analysis (BSC + opBNB)
- **BNB Greenfield Storage**: Immutable forensic reports (using greenfield-python-sdk)
- **PancakeSwap Integration**: Whitelisted router for fast-path approval
- **BNB Ecosystem Data**: Liquidity lock detection (PinkLock, Unicrypt on BSC)

---

## Roadmap

### Phase 1: Core Security Engine (Completed ✅)
- [x] Chrome extension with real-time transaction interception
- [x] Composite risk scoring from 6 data sources
- [x] Telegram bot for manual contract scans
- [x] BNB Greenfield forensic report storage
- [x] Tenderly transaction simulation
- [x] AI-powered risk analysis via Claude

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

### Phase 4: Cross-Chain (Q4 2026)
- [ ] Ethereum mainnet support
- [ ] Polygon, Arbitrum, Optimism support
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
- **Live Bot**: https://t.me/shieldbot_bnb_bot
- **Architecture**: Fully documented in `/docs/TECHNICAL.md`
- **Contributions Welcome**: Security researchers, data source integrations, ML/AI improvements

---

## Differentiators vs. Existing Solutions

| Feature | ShieldBot | TokenSniffer | RugDoc | MetaMask Warnings |
|---------|-----------|--------------|--------|-------------------|
| Real-time interception | ✅ | ❌ | ❌ | ❌ |
| Auto-block dangerous txs | ✅ | ❌ | ❌ | ❌ |
| Composite scoring (6 sources) | ✅ | ❌ (1 source) | ❌ (manual) | ❌ |
| Pre-execution simulation | ✅ | ❌ | ❌ | ❌ |
| On-chain forensic reports | ✅ (Greenfield) | ❌ | ❌ | ❌ |
| AI risk explanations | ✅ | ❌ | ❌ | ❌ |
| Zero wallet permissions | ✅ | ❌ | ❌ | N/A |
| Open-source | ✅ | ❌ | ❌ | Partial |

---

## Contact & Links

- **Telegram**: [@Ggudman](https://t.me/Ggudman)
- **Twitter**: [@Ggudman1](https://twitter.com/Ggudman1)
- **GitHub**: [Ridwannurudeen](https://github.com/Ridwannurudeen)
- **Live Demo Bot**: [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot)
- **Repository**: https://github.com/Ridwannurudeen/shieldbot

---

**ShieldBot: Protecting BNB Chain users, one transaction at a time.** 🛡️
