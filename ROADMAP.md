# ShieldBot V2 Roadmap

ShieldBot is evolving from a BNB Chain transaction scanner into a **cross-chain security intelligence network**. Every user makes every other user safer.

For the full strategic context, see [V2 Strategy Document](docs/ShieldBot_V2_Multichain_Strategy_And_Claude_Opus46_Prompt.md).

---

## Vision

**V1 (current):** Transaction scanner for BNB Chain.
**V2 (building):** Cross-chain security intelligence network for wallets, traders, and applications.

---

## Distribution channels (V2)

| Channel | Description | Status |
|---------|------------|--------|
| Chrome Extension | Browser-based transaction interception and verdict overlay | Live |
| RPC Proxy | Custom RPC endpoint — users add to any wallet, works on mobile | Planned |
| SDK | `shieldbot.js` for wallets and dApps to embed scanning | Planned |
| Telegram | Paste any address/contract/tx hash, get instant risk report | Partial (token scanning live) |
| Threat Dashboard | Public real-time feed of detected threats and campaigns | Planned |
| API | B2B threat intelligence API with key auth and usage metering | Planned |

---

## Phase 1: Foundation (Weeks 1-4)

Build the infrastructure everything else depends on.

- [ ] **ChainAdapter interface** — Abstract chain-specific logic behind a common adapter. BSC becomes the first adapter.
- [ ] **Analyzer registry** — Pluggable pipeline where each detection capability is a registered plugin. No core changes needed to add new analyzers.
- [ ] **Policy modes** — Strict (fail closed) and Balanced (fail open with warning). Deterministic timeout behavior.
- [ ] **API auth and metering** — API key management, per-key rate limiting, usage tracking. B2B-ready from day 1.
- [ ] **Contract reputation DB** — Score and cache every contract analyzed. Shared intelligence across all users.
- [ ] **Deployer/funder indexer** — Background data collection for the campaign graph. Starts now, pays off in Phase 3.
- [ ] **Outcome tracking** — Track what happens when users proceed past warnings. Builds labeled training data continuously.
- [ ] **Extension updates** — Policy mode selector, improved error states, setup flow.

**Exit criteria:** Analyzers running through registry. BSC adapter passing integration tests. API accepting authenticated requests. Indexer collecting >1000 contracts/week.

---

## Phase 2: Detection + Distribution (Weeks 5-8)

Ship superior detection and new distribution channels.

- [ ] **Intent mismatch analyzer** — Detect when transaction behavior doesn't match user intent (e.g., "claim rewards" that actually grants unlimited approval).
- [ ] **Signature/permit analyzer** — Typed signature risks, permit-like approvals, hidden delegate patterns.
- [ ] **Confidence calibration** — Threshold tuning framework to minimize false positives on known-safe protocols.
- [ ] **Evaluation pipeline** — Benchmark dataset + CLI that produces precision/recall reports on collected data.
- [ ] **Community reporting** — Endpoint for users to flag false positives and false negatives.
- [ ] **Ethereum and Base adapters** — First multichain expansion. Chain-aware caching and source routing.
- [ ] **RPC proxy v1** — BSC first. Zero-friction scanning for any wallet including mobile.
- [ ] **Telegram scan-by-address** — Paste any address or contract, get a full risk report.

**Exit criteria:** Precision >85% on benchmark set. False positive rate <2% on safe protocols. ETH and Base functional in staging. RPC proxy live.

---

## Phase 3: Moat Features + Growth (Weeks 9-12)

Ship the features competitors can't easily replicate.

- [ ] **Campaign Graph Radar v1** — Cross-chain entity correlation: deployers, funders, contract factories, signature templates. Detect scams as coordinated campaigns, not isolated transactions.
- [ ] **Mempool monitoring v1** — Detect sandwich attacks, frontrunning, and suspicious approvals in pending transactions.
- [ ] **Rescue Mode Tier 1** — Alerts with clear explanation and available actions.
- [ ] **Rescue Mode Tier 2** — Pre-built revoke transactions. One-click approval cleanup.
- [ ] **Arbitrum, Polygon, Optimism, opBNB adapters** — Full EVM multichain coverage.
- [ ] **RPC proxy multichain** — All supported chains available as custom RPC endpoints.
- [ ] **SDK v1** — Published `shieldbot.js` package for wallet/dApp integration.
- [ ] **Public threat dashboard** — Real-time feed of detected threats and campaigns.
- [ ] **Threat Feed API** — Subscribe to ShieldBot's intelligence. Other tools build on this.
- [ ] **Chain grant applications** — BSC, Base, Arbitrum ecosystem fund submissions.
- [ ] **Private beta cohort** — 50-200 instrumented users providing feedback and outcome data.

**Exit criteria:** 7 EVM chains scanning in production beta. Campaign detection linking deployers across 2+ chains. At least 1 external API consumer. At least 1 grant application submitted.

---

## Out of scope for V2

| Feature | Reason |
|---------|--------|
| Non-EVM chains (Solana, Tron, TON) | Fundamentally different architecture. Scope as V3 after EVM multichain is proven. |
| Autonomous rescue execution (Tier 3) | Too risky before trust is established through Tier 1 and 2. Scope for V2.5. |
| Mobile native app | RPC proxy solves mobile access without a separate app. |
| Multisig / Guardian Circles | Existing solutions (Safe, Squads) handle this. Not differentiated. |

---

## KPI Targets

| Category | Metric | Target |
|----------|--------|--------|
| Protection | Block precision | > 90% |
| Protection | False positive rate (top-50 safe protocols) | < 1% |
| Performance | Firewall p95 latency | < 1.2s |
| Performance | RPC proxy added latency p95 | < 500ms |
| Reliability | Decision-path error rate | < 1.5% |
| Reliability | API/RPC uptime | > 99.5% |
| Growth | RPC proxy transactions/day (week 8) | > 1,000 |
| Growth | Telegram queries/day (week 8) | > 100 |
| Growth | Extension install-to-scan conversion | > 40% |
| Data | Contracts scored/day (week 4) | > 500 |
| Revenue | Grant applications submitted (week 12) | >= 1 |
| Revenue | B2B API consumers (week 12) | >= 1 |

---

## Business model

| Tier | Channel | Revenue model |
|------|---------|--------------|
| Primary | B2B API | $0.001-0.005 per scan, volume discounts |
| Funding | Chain grants | $25-100K per chain ecosystem grant |
| Partnership | Insurance protocols | Revenue share on premium reductions |
| Secondary | Consumer Pro | $9-15/month for unlimited scans, all chains, rescue mode |

---

## How to contribute

ShieldBot is open source. If you want to contribute to V2:

1. Check this roadmap for unchecked items.
2. Open an issue to discuss the approach before submitting a PR.
3. See [SETUP_GUIDE.md](SETUP_GUIDE.md) for local development setup.

---

*Last updated: February 2026*
