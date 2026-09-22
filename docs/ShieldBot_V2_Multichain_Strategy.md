# ShieldBot V2: Cross-Chain Security Intelligence Network

Historical strategy proposal. Product pillars, API sketches, architecture choices, schedules and KPI figures below are proposed work or targets, not measured outcomes or release evidence. Read [the current README](../README.md) and [TECHNICAL.md](TECHNICAL.md) for implemented scope and the shipped extension limitation.

## Why V2

ShieldBot V1 is a BNB transaction scanner. The market has well-funded players doing the same thing (GoPlus, Blockaid, De.Fi). Competing on features alone is a losing game.

ShieldBot V2 proposed a shared security intelligence service distributed through multiple client interfaces. Whether additional observations improve detection requires evaluation.

This document covers:
1. Strategic repositioning
2. Distribution strategy (how users find ShieldBot)
3. Business model (how ShieldBot makes money)
4. Data flywheel (how ShieldBot gets smarter)
5. Product pillars (what ShieldBot does)
6. Technical architecture
7. Multi-chain expansion
8. 12-week execution roadmap
9. KPIs and operating model
10. Immediate founder actions

---

## 1) Strategic repositioning

### V1 frame (commodity)
"Transaction scanner for BNB users."

### V2 frame (infrastructure)
"Cross-chain security intelligence network for wallets, traders, and applications."

### Why this wins
- A scanner competes on features. A network competes on data.
- Proposed: retain useful observations for later analysis, subject to actual persistence and coverage.
- Detection applies to the checked context; it does not establish coverage for other users or chains.
- Wallets and dApps integrate ShieldBot because building this in-house is harder than paying per scan.

If ShieldBot only shows warnings, users compare it to free alternatives.
Improvement from additional scans is a hypothesis to measure, not an established effect.

---

## 2) Distribution strategy

The Chrome extension is one channel. It cannot be the only channel. ShieldBot needs to meet users where they already are.

### Channel A: RPC Proxy (highest leverage)

The repository mounts a configurable proxy at `/rpc/{chain_id}` (`rpc/router.py`). Only requests sent through that endpoint enter its checks; a wallet or dapp can use another RPC. Compatibility must be tested with each client.

`rpc/proxy.py` intercepts `eth_sendTransaction` and `eth_sendRawTransaction`; raw transactions are already signed. Contract-creation requests without a destination are forwarded without analysis. Other allowed methods are forwarded. This path is not wallet-wide or pre-signature protection for every transaction.

### Channel B: SDK for wallet and dApp developers

Historical proposed SDK syntax (not the installed SDK API or evidence of package publication):

```js
import { ShieldBot } from '@shieldbot/sdk';
const shield = new ShieldBot({ apiKey: 'sk_...', chain: 'bsc' });

const verdict = await shield.analyze(transaction);
if (verdict.risk > 0.7) {
  showWarning(verdict.reasons);
}
```

Target integrations:
- MetaMask Snaps
- Rabby wallet plugins
- Trust Wallet partnerships
- DEX aggregator frontends

Proposed integrations need separate implementation and adoption evidence.

### Channel C: Telegram as a scanning service

The existing Telegram bot should let users paste any address, contract, or tx hash and receive an instant risk report.

Why this matters:
- Users share results in group chats — every share is a ShieldBot impression.
- Crypto communities live on Telegram — this is organic distribution.
- Wallet checkers like De.Fi grew primarily through Telegram virality.
- Low engineering cost, high distribution leverage.

### Channel D: Public threat dashboard and API

Proposed dashboard examples, not observed publication or traffic:
- "ShieldBot blocked 347 phishing attacks across 5 chains today."
- Real-time feed of detected campaigns, flagged contracts, and risk trends.

This serves three purposes:
1. Marketing — builds trust and brand visibility.
2. Data product — other tools and researchers consume the feed.
3. Community contribution — users can report false positives/negatives through the dashboard.

### Channel E: Chrome extension (existing)

Maintained and improved, but no longer the sole distribution channel. The extension becomes the power-user interface for those who want the richest experience.

---

## 3) Business model

### Why B2B-first

Charging individual users $9-15/month for security has brutal conversion rates (<2% in crypto). The real revenue comes from selling ShieldBot as infrastructure.

### Revenue tiers

**Tier 1: B2B API sales (primary revenue)**
- Wallets and dApps embed ShieldBot via SDK/API.
- Pricing: $0.001-0.005 per scan, volume discounts.
- At 10M scans/month = $10-50K/month.
- This is how GoPlus and Blockaid monetize.
- Requires: API-first design, usage metering, API keys, rate limiting, service-level commitments.

**Tier 2: Chain ecosystem grants (development funding)**
- Every L1/L2 has a grants program and wants their ecosystem safe.
- BSC, Base, Arbitrum, Optimism, Polygon all fund security tooling.
- ShieldBot protecting their users is a direct grant pitch.
- Target $25-100K per chain grant to fund development runway.

**Tier 3: Insurance protocol integration (partnership revenue)**
- ShieldBot risk scores reduce insurance premiums.
- Partner with Nexus Mutual, InsurAce, etc.
- Revenue share on premium reductions driven by ShieldBot data.

**Tier 4: Premium consumer features (secondary revenue)**
- Free tier: 50 scans/day, single chain, basic risk scores.
- Pro tier ($9-15/month): Unlimited scans, all chains, rescue mode, campaign alerts, priority analysis.
- This is additive, not the primary business.

### Monetization implications for engineering

From day 1, the API must support:
- API key authentication and management.
- Per-key usage metering and rate limiting.
- Tier-based feature gating.
- Usage analytics and billing-ready event logging.

---

## 4) Data flywheel

Proposed data feedback loop. Any detection improvement must be measured against labeled outcomes.

### The loop

```
More users → More transactions scanned → More threat data collected
    ↑                                              ↓
Better protection ← Better detection models ← Labeled outcomes
```

### Flywheel components

**A. Outcome tracking**

When ShieldBot warns about a transaction and the user proceeds anyway, track what happened:
- Did they lose funds?
- Was the contract actually safe?
- Did the approval get exploited later?

This creates labeled training data automatically and continuously. Not a one-time benchmark dataset — a growing, living dataset fed by real user outcomes.

**B. Contract reputation database**

Every contract ShieldBot analyzes gets scored and cached:
- When the 1000th user interacts with the same Uniswap router, it is an instant cache hit.
- When a new contract appears and gets flagged by 5 users in an hour, that is a signal.
- Contract scores decay over time and refresh on new interactions.

Faster or more accurate results at scale are proposed evaluation goals, not measured benefits.

**C. Community reporting**

Users can flag false positives ("this was actually safe") and false negatives ("I got rugged despite low risk"). Each report feeds back into scoring models.

Incentive structure:
- Accurate reporters build reputation.
- High-reputation reports carry more weight.
- Gamification drives engagement.

**D. Mempool monitoring**

Watch pending transactions to detect threats before they execute:
- Sandwich attacks targeting the user's pending swap.
- Frontrunning bots extracting MEV from the user's transaction.
- Suspicious approval transactions appearing in the same block.

This is a proposed detection capability. The RPC proxy sees only requests sent through it; a separate mempool feed would require its own coverage evaluation.

---

## 5) Product pillars

### Pillar A: Pluggable analyzer pipeline

All detection capabilities are plugins in a unified pipeline, not separate systems:

```
Transaction → [ContractAnalyzer, HoneypotDetector, IntentMatcher,
               SignatureAnalyzer, CampaignGraph, MempoolMonitor, ...]
           → CompositeScore → PolicyEngine → Verdict
```

Each analyzer implements a common interface:
```python
class BaseAnalyzer:
    async def analyze(self, tx, chain_context) -> RiskSignal
```

Adding new detection capabilities means registering a new analyzer class — no core pipeline changes.

**Intent matching** is one analyzer in the pipeline, not a separate pillar. It compares what the user thinks they are doing against what the transaction actually does:
- User thinks "claim rewards" but tx grants unlimited approval.
- User thinks "swap" but tx path routes through suspicious intermediary.
- User thinks "mint NFT" but tx drains wallet via hidden delegatecall.

Output: intent match score, mismatch reason, recommended action.

### Pillar B: Campaign Graph Radar

Detect scams as coordinated campaigns, not isolated transactions.

Model entities:
- Deployer wallets and their contract creation patterns.
- Funder wallets and bridge transfer origins.
- Domain registrations linked to contract addresses.
- Contract factory templates and bytecode similarity.
- Signature patterns reused across phishing sites.

Cross-chain correlation:
- Same deployer launches contracts on BSC, then Base, then Arbitrum.
- Same funder wallet seeds multiple deployers across chains.
- Same phishing site template targets different chain users.

Output:
- Campaign confidence score.
- Cluster ID linking related entities.
- Blast radius estimate (number of chains, contracts, potential victims).

### Pillar C: Rescue Mode (3-tier trust ladder)

Not a binary on/off. Users graduate through trust levels:

**Tier 1 — Alert (default for all users):**
- Explain what was detected and why it is dangerous.
- Show what actions are available.
- Educate the user on the risk.

**Tier 2 — Assisted response (opt-in):**
- Pre-build the revoke transaction, user just signs.
- Generate safe wallet migration transaction.
- One-click approval cleanup for compromised tokens.

**Tier 3 — Policy-automated response (explicit policy + confirmation):**
- Auto-execute revoke with a time-delayed cancel window (like Gmail undo-send).
- Requires explicit user policy setup and confirmation.
- Only available after user has used Tier 1 and Tier 2 successfully.

Why the trust ladder matters: if a false positive triggers an automated rescue and moves funds mid-trade, that destroys user trust permanently. Earn trust through Tier 1 and 2 before offering Tier 3.

### Pillar D: Personalized security engine

Risk policy adapts by user profile:
- New user: strong guardrails, lower thresholds for warnings.
- Pro trader: high-speed analysis, controlled override capability.
- Treasury/team: higher value thresholds, mandatory review for large transactions.

Profile is learned from user behavior and adjustable through settings.

### Pillar E: Threat Feed API

Replace Guardian Circles (multisig already exists and is not differentiated) with a Threat Feed API:
- Other wallets, dApps, and security tools subscribe to ShieldBot's threat intelligence.
- Real-time feed of flagged contracts, campaigns, and risk scores.
- Transforms ShieldBot from a consumer product into infrastructure.

This creates network effects: more consumers = more data = better detection = more consumers wanting the feed.

---

## 6) Technical architecture

Flat, pluggable, no unnecessary abstraction layers.

```
┌─────────────────────────────────┐
│         Entry Points            │
│  RPC Proxy | REST API | SDK     │
│  Extension | Telegram           │
└──────────────┬──────────────────┘
               │
┌──────────────▼──────────────────┐
│         Chain Router            │
│  BSC | ETH | Base | ARB | ...   │
│  (ChainAdapter per chain)       │
└──────────────┬──────────────────┘
               │
┌──────────────▼──────────────────┐
│     Analyzer Pipeline           │
│     (pluggable registry)        │
│  Contract | Honeypot | Intent   │
│  Signature | Campaign | Mempool │
└──────────────┬──────────────────┘
               │
┌──────────────▼──────────────────┐
│    Threat Intelligence Store    │
│  Contract DB | Campaign Graph   │
│  Outcome data | Community reports│
└──────────────┬──────────────────┘
               │
┌──────────────▼──────────────────┐
│        Policy Engine            │
│  strict | balanced | custom     │
│  per-user | per-tier            │
└──────────────┬──────────────────┘
               │
┌──────────────▼──────────────────┐
│          Response               │
│  Verdict | Rescue actions       │
│  Threat feed | Alerts           │
└─────────────────────────────────┘
```

### ChainAdapter interface

```python
class ChainAdapter(ABC):
    @abstractmethod
    async def decode_transaction(self, raw_tx) -> NormalizedTx
    @abstractmethod
    async def analyze_approvals(self, tx) -> list[ApprovalRisk]
    @abstractmethod
    async def simulate_transaction(self, tx) -> SimulationResult
    @abstractmethod
    async def fetch_contract_metadata(self, address) -> ContractMeta
    @abstractmethod
    async def fetch_market_context(self, token) -> MarketData
    @abstractmethod
    async def normalize_risk_features(self, tx) -> RiskFeatures
```

All chain-specific logic lives inside adapters. The pipeline above the adapter is chain-agnostic.

### Analyzer registry

```python
class AnalyzerRegistry:
    def register(self, analyzer: BaseAnalyzer)
    async def run_all(self, tx, chain_ctx) -> list[RiskSignal]
```

Adding a new detection capability = writing a class and calling `registry.register()`. No pipeline changes required.

### Data infrastructure

- Contract reputation DB: PostgreSQL (SQLite for dev/testing).
- Campaign graph: PostgreSQL with adjacency tables (Neo4j if graph queries become complex).
- Outcome tracking: append-only event log with labeled results.
- Cache layer: Redis for hot contract scores and API response caching.
- Queue: async worker for report generation, Greenfield uploads, and non-critical side effects.

---

## 7) Multi-chain expansion

### Phase M0: Foundation (Weeks 1-2)
Refactor current BSC-specific code behind the `ChainAdapter` interface. BSC becomes the first adapter. Pipeline becomes chain-agnostic.

### Phase M1: EVM mesh (Weeks 7-10)
Add adapters for:
- Ethereum
- Base
- Arbitrum
- Polygon
- Optimism
- opBNB

All EVM chains share 80% of logic (tx decoding, ABI parsing, approval patterns). Each adapter handles chain-specific RPCs, explorers, and token lists.

### Phase M2: Campaign graph unification (Weeks 9-12)
One shared threat graph across all supported chains. Cross-chain deployer correlation active.

### Phase M3: Non-EVM (V3, out of scope for this plan)
Solana requires a fundamentally different adapter (account model, instruction parsing, program analysis). Scope it as V3 after EVM multichain is proven in production.

---

## 8) 12-week execution roadmap

Three parallel tracks running simultaneously. Not sequential blocks.

### Phase 1: Foundation that compounds (Weeks 1-4)

| Track | Work | Exit criteria |
|-------|------|---------------|
| **Core** | ChainAdapter interface + BSC adapter refactor. Analyzer registry pattern. | All existing analyzers running through registry. BSC adapter passes integration tests. |
| **Data** | Contract reputation DB schema. Outcome tracking schema. Deployer/funder indexer collecting data in background. | Indexer running, >1000 contracts scored in first week. |
| **API** | API key auth, usage metering, rate limiting, tier-based gating. B2B-ready from day 1. | External API consumers can register, authenticate, and hit rate limits correctly. |
| **Policy** | Strict/balanced modes. Deterministic timeout behavior. Docs aligned with runtime behavior. | Policy mode tests passing. Block/proceed behavior matches docs exactly. |
| **Extension** | Policy mode selector. Improved error states. Setup flow. | Extension reflects policy mode. Clear error messages for all failure states. |

### Phase 2: Detection superiority + distribution (Weeks 5-8)

| Track | Work | Exit criteria |
|-------|------|---------------|
| **Detection** | Intent mismatch analyzer. Signature/permit analyzer. Confidence calibration framework. | Precision >85% on benchmark set. False positive rate <2% on safe protocol set. |
| **Data** | Evaluation pipeline on collected data. Labeled outcome integration. Community reporting endpoint. | Evaluation CLI produces precision/recall report. Outcomes feeding back into scores. |
| **Multichain** | Ethereum and Base adapters. Chain-aware caching and source routing. | ETH and Base scanning functional in staging. |
| **Distribution** | RPC proxy v1 (BSC). Telegram scan-by-address/contract. | RPC proxy intercepting and analyzing txs. Telegram bot responding to address queries. |

### Phase 3: Moat features + growth (Weeks 9-12)

| Track | Work | Exit criteria |
|-------|------|---------------|
| **Detection** | Campaign graph v1 on accumulated data. Mempool monitoring v1. | Campaign detection identifying linked deployers across 2+ chains. |
| **Multichain** | Arbitrum, Polygon, Optimism, opBNB adapters. RPC proxy multichain. | 7 EVM chains scanning in production beta. |
| **Rescue** | Tier 1 (alerts with action options). Tier 2 (pre-built revoke transactions). | Users can one-click revoke flagged approvals. |
| **Distribution** | SDK v1 published. Public threat dashboard live. Threat feed API. | At least 1 external integration consuming the API. |
| **Growth** | Chain grant applications (BSC, Base, Arbitrum). Wallet partnership outreach. Private beta cohort (50-200 users). | At least 1 grant application submitted. Beta users providing feedback. |

---

## 9) KPIs and operating model

### Protection quality
- Block precision > 90%.
- False positive rate on top-50 safe protocols < 1%.
- Campaign detection: >60% of known rug pulls linked to prior campaign clusters within 24h.

### Performance
- Firewall p95 < 1.2s.
- Firewall p99 < 2.5s.
- RPC proxy added latency < 500ms p95.

### Reliability
- Decision-path error rate < 1.5%.
- Upstream source health tracked with automatic fallback behavior.
- 99.5% uptime for API and RPC proxy.

### Data flywheel
- Contract reputation DB growing by >500 contracts/day by week 4.
- Outcome tracking capturing >20% of warned-then-proceeded transactions.
- Community reports: >10/week by end of beta.

### Distribution and growth
- RPC proxy: >1000 transactions/day by week 8.
- API: >1 external B2B consumer by week 12.
- Telegram: >100 queries/day by week 8.
- Extension: install-to-first-scan conversion > 40%.
- Week-4 retention > 25%.

### Revenue (by end of 90 days)
- At least 1 chain grant application submitted.
- API pricing published and metering functional.
- At least 1 wallet/dApp partnership conversation active.

### Trust
- Doc/behavior consistency: 100%.
- User override rates monitored and trending down.

---

## 10) Competitive evaluation

The former competitor feature matrix and exclusivity claims have been removed. This proposal has no current reproducible comparative evaluation.

---

## 11) What is explicitly out of scope for V2

- **Non-EVM chains (Solana, Tron, TON):** The account model is fundamentally different. Scope as V3 after EVM multichain is proven.
- **Guardian Circles / multisig:** Existing solutions (Safe, Squads) handle this better. Not differentiated enough.
- **Proof-of-Safety Receipts:** Nice concept but zero user value at current stage.
- **Mobile native app:** A configured RPC proxy could offer another access path, but mobile-wallet compatibility needs testing.
- **Autonomous rescue execution (Tier 3):** Too risky before trust is established through Tier 1 and Tier 2. Scope for V2.5 after beta feedback.

---

## 12) Immediate founder actions

1. **Keep Chrome Web Store submission alive** but position as limited beta until policy fixes ship.
2. **Apply for chain ecosystem grants immediately** — BSC (BNB Chain grant program), Base (Base ecosystem fund), Arbitrum (Arbitrum Foundation grants). These fund the runway.
3. **Position ShieldBot publicly as "cross-chain security intelligence network in active beta."**
4. **Set up the contract/deployer indexer this week.** Data collection starts now; the campaign graph depends on weeks of accumulated data.
5. **Recruit 50-200 beta users** for instrumented testing and outcome tracking.
6. **Publish API pricing and docs** even before the full multichain rollout — signal that ShieldBot is B2B infrastructure, not just a browser extension.
7. **Prioritize trust, speed, and data collection** over cosmetic features. Every week without data collection is a week the campaign graph starts later.

---

## Engineering standards

- Unit + integration tests for each subsystem changed.
- Contract tests for external API adapters.
- Regression tests for known false positive/false negative examples.
- Structured logs with request_id and decision_trace.
- Typed config and env validation.
- Every PR includes: objective, behavior changes, files changed, tests added, risks, rollback plan.

---

This is the plan. Execute, measure, iterate.
