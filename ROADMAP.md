# ShieldBot Roadmap

ShieldBot is evolving from a BNB Chain transaction scanner into a **cross-chain security intelligence network**. Every user makes every other user safer.

**Hackathon Winner — Good Vibes Only: OpenClaw Edition (Builders Track, BNB Chain)**

---

## Vision

**V1:** Transaction scanner for BNB Chain.
**V2 (current):** Cross-chain security intelligence network for wallets, traders, and applications.
**V3 (next):** Non-EVM expansion, consumer monetization, and B2B partnerships.

---

## Distribution Channels

| Channel | Description | Status |
|---------|------------|--------|
| Chrome Extension | Browser-based transaction interception and verdict overlay | Live |
| RPC Proxy | Custom RPC endpoint — any wallet, works on mobile | Live (7 chains) |
| SDK | `shieldbot-sdk` TypeScript client for wallets and dApps | Live |
| Telegram | 10-command security suite with multi-chain support | Live |
| Threat Dashboard | Public real-time feed of detected threats and campaigns | Live |
| API | B2B threat intelligence API with key auth and usage metering | Live |

---

## Phase 1: Foundation — Complete

- [x] **ChainAdapter interface** — Abstract chain-specific logic behind a common adapter. BSC as first adapter.
- [x] **Analyzer registry** — Pluggable pipeline where each detection capability is a registered plugin.
- [x] **Policy modes** — Strict (fail closed) and Balanced (fail open with warning). Deterministic timeout behavior.
- [x] **API auth and metering** — API key management, per-key rate limiting, usage tracking.
- [x] **Contract reputation DB** — Score and cache every contract analyzed. Shared intelligence across all users.
- [x] **Deployer/funder indexer** — Background data collection for the campaign graph.
- [x] **Outcome tracking** — Track what happens when users proceed past warnings. Labeled training data.
- [x] **Extension updates** — Policy mode selector, improved error states, setup flow.

---

## Phase 2: Detection + Distribution — Complete

- [x] **Intent mismatch analyzer** — Detect when transaction behavior doesn't match user intent.
- [x] **Signature/permit analyzer** — Typed signature risks, permit-like approvals, hidden delegate patterns.
- [x] **Confidence calibration** — Threshold tuning framework to minimize false positives on known-safe protocols.
- [x] **Evaluation pipeline** — Benchmark dataset + CLI that produces precision/recall reports.
- [x] **Community reporting** — Endpoint for users to flag false positives and false negatives.
- [x] **Ethereum and Base adapters** — First multichain expansion. Chain-aware caching and source routing.
- [x] **RPC proxy v1** — Zero-friction scanning for any wallet including mobile.
- [x] **Telegram scan-by-address** — Full risk report for any address or contract.

---

## Phase 3: Moat Features + Growth — Complete

- [x] **Campaign Graph Radar v1** — Cross-chain entity correlation: deployers, funders, contract factories.
- [x] **Mempool monitoring v1** — Sandwich attack, frontrunning, and suspicious approval detection.
- [x] **Rescue Mode Tier 1** — Alerts with plain-language risk explanations.
- [x] **Rescue Mode Tier 2** — Pre-built revoke transactions. One-click approval cleanup.
- [x] **Arbitrum, Polygon, Optimism, opBNB adapters** — Full 7-chain EVM coverage.
- [x] **RPC proxy multichain** — All supported chains available as custom RPC endpoints.
- [x] **SDK v1** — Published `shieldbot-sdk` TypeScript package.
- [x] **Public threat dashboard** — Real-time feed of detected threats and campaigns.
- [x] **Threat Feed API** — Subscribe to ShieldBot's intelligence.
- [x] **Chrome Web Store submission** — Extension v1.0.1 published.

---

## Phase 4: Post-Hackathon — Growth and Monetization

Leverage hackathon win momentum to build real user base and revenue.

### Grants and Funding
- [ ] **BNB Chain MVB / Kickstart grant** — Apply with hackathon win as proof of traction.
- [ ] **Base Ecosystem Fund** — Base adapter is live, apply for ecosystem grant.
- [ ] **Arbitrum Foundation grant** — Arbitrum adapter is live, apply for STIP/ecosystem grant.

### User Acquisition
- [ ] **Private beta cohort** — 50-200 instrumented users providing feedback and outcome data.
- [ ] **Community launch** — Announce on X/Twitter, BNB community channels, crypto security groups.
- [ ] **Chrome Web Store SEO** — Optimize listing, screenshots, and description for organic installs.

### Production Hardening
- [ ] **Monitoring and alerting** — Uptime checks, error rate alerts, latency dashboards.
- [ ] **Database backup strategy** — Automated SQLite backups on VPS.
- [ ] **Rate limiting tuning** — Adjust limits based on real traffic patterns.
- [ ] **CI/CD pipeline** — Automated tests and deployment on push.

### Monetization
- [ ] **Consumer Pro tier** — $9-15/month for unlimited scans, all chains, priority analysis.
- [ ] **B2B API partnerships** — Onboard first wallet/dApp integrating ShieldBot API.
- [ ] **Insurance protocol partnerships** — Revenue share on premium reductions for protected wallets.

---

## Phase 5: V3 — Expansion

- [ ] **Solana support** — New chain architecture, different transaction model.
- [ ] **TON support** — Telegram-native chain, natural fit with existing Telegram bot.
- [ ] **Autonomous rescue execution (Tier 3)** — Auto-revoke dangerous approvals with user consent.
- [ ] **Mobile native app** — Dedicated mobile experience beyond RPC proxy.
- [ ] **On-chain reputation token** — Tokenized security scores for DeFi composability.

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
| Growth | RPC proxy transactions/day | > 1,000 |
| Growth | Telegram queries/day | > 100 |
| Growth | Chrome extension installs | > 500 |
| Revenue | Grant applications submitted | >= 2 |
| Revenue | B2B API consumers | >= 1 |

---

## Business Model

| Tier | Channel | Revenue Model |
|------|---------|--------------|
| Primary | B2B API | $0.001-0.005 per scan, volume discounts |
| Funding | Chain grants | $25-100K per chain ecosystem grant |
| Partnership | Insurance protocols | Revenue share on premium reductions |
| Secondary | Consumer Pro | $9-15/month for unlimited scans, all chains, rescue mode |

---

## How to Contribute

ShieldBot is open source. If you want to contribute:

1. Check this roadmap for unchecked items.
2. Open an issue to discuss the approach before submitting a PR.
3. See [SETUP_GUIDE.md](SETUP_GUIDE.md) for local development setup.

---

*Last updated: February 2026*
