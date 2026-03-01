# ShieldBot Roadmap

ShieldBot is evolving from a BNB Chain transaction scanner into a **cross-chain security intelligence network**. Every user makes every other user safer.

**3rd Place — Good Vibes Only: OpenClaw Edition (Builders Track, BNB Chain)**

---

## Vision

**V1:** Transaction scanner for BNB Chain.
**V2 (current):** Cross-chain security intelligence network for wallets, traders, and applications.
**V3 (next):** Non-EVM expansion, consumer monetization, B2B partnerships, and full feature parity with — and beyond — every competitor.

---

## Market Landscape (March 2026)

The standalone crypto security extension market has undergone rapid consolidation. Three of the largest tools are gone:

| Tool | Status | Notes |
|------|--------|-------|
| Blowfish | Acquired by Phantom (Nov 2024) | External API shut down; wallets must find alternatives |
| WalletGuard | Acquired by MetaMask (Jul 2024), sunset Mar 2025 | ML-based phishing detection and soft-locking lost |
| Pocket Universe | Acquired by Kerberus (Aug 2025) | 200K+ user base in transition; roadmap uncertain |
| Stelo | Shut down Oct 2023 | a16z-backed; failed to monetize |

**ShieldBot is now the only active, dedicated real-time transaction firewall extension for BNB Chain.** This window is the primary growth opportunity.

Active competitors and their coverage gaps:

| Tool | BNB Real-time Firewall | Telegram Bot | RPC Proxy | Campaign Graph | Mempool Monitor |
|------|----------------------|--------------|-----------|----------------|-----------------|
| Fire | ❌ No BNB support | ❌ | ❌ | ❌ | ❌ |
| Revoke.cash | ❌ Approvals only | ❌ | ❌ | ❌ | ❌ |
| De.Fi Shield | ❌ Web-only, no interception | ❌ | ❌ | ❌ | ❌ |
| GoPlus | ❌ API only, not consumer-facing | ❌ | ❌ | ❌ | ❌ |
| Token Sniffer | ❌ Static scanner only | ❌ | ❌ | ❌ | ❌ |
| **ShieldBot** | ✅ | ✅ 10 commands | ✅ 7 chains | ✅ | ✅ |

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
| Firefox Extension | Port of Chrome extension for Firefox users | Planned |

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
- [x] **Chrome Web Store submission** — Extension v1.0.3 submitted, under review.
- [x] **Landing page** — Live at [shieldbotsecurity.online](https://shieldbotsecurity.online).

---

## Phase 4: Gap Closing + Market Capture

This phase captures users and closes the feature gaps that remain.

### Capture the Vacuum
- [x] **Landing page** — Live at [shieldbotsecurity.online](https://shieldbotsecurity.online). Positioned as the dedicated BNB Chain security extension for real-time transaction protection.
- [x] **Chrome Web Store SEO** — Optimize listing title, description, and screenshots for: "BNB Chain security", "BSC transaction protection", "honeypot detector".
- [ ] **Community launch** — Announce on X/Twitter, BNB community channels, crypto security groups targeting users migrating from defunct tools.
- [ ] **AvengerDAO membership** — Apply to BNB Chain's official community security coalition. Membership = ecosystem credibility, DappBay visibility, and referral from BNB Chain itself. GoPlus and HashDit are members.
- [ ] **Extension onboarding flow** — First-time user tutorial and guided first scan.
- [x] **Beta waitlist** — Email/wallet collection for early access to new features. Live at shieldbotsecurity.online.

### Close the Detection Gaps
- [x] **Phishing / URL blocker** — Content script checks active URL against GoPlus Phishing Site Detection API on every page load. Red banner on hit. 1hr cache. Live in v1.0.3.
- [x] **Bytecode fingerprinting for unverified contracts** — Token Sniffer API integrated. Data-driven unverified penalty (10/25/40 risk based on Smell Test score). Gracefully disabled without API key. Live in v1.0.4.
- [ ] **Deployer cluster auto-blocking** — When Campaign Graph Radar identifies a known bad deployer cluster, automatically flag all future tokens from that cluster in real-time — not just individually scanned contracts. Block entire scam networks, not just individual tokens.

### Production Hardening
- [ ] **Monitoring and alerting** — Uptime checks, error rate alerts, latency dashboards.
- [ ] **Internal analytics dashboard** — Track scan volume, block rate, user retention, and chain distribution.
- [ ] **Database backup strategy** — Automated SQLite backups on VPS.
- [ ] **Rate limiting tuning** — Adjust limits based on real traffic patterns.
- [ ] **CI/CD pipeline** — Automated tests and deployment on push.

### Grants and Funding
- [ ] **BNB Chain MVB / Kickstart grant** — Apply with hackathon win + live product + market position as proof of traction.
- [ ] **Base Ecosystem Fund** — Base adapter is live; apply for ecosystem grant.
- [ ] **Arbitrum Foundation grant** — Arbitrum adapter is live; apply for STIP/ecosystem grant.

### Monetization
- [ ] **Consumer Pro tier** — $9-15/month for unlimited scans, all chains, priority analysis, post-deploy alerts.
- [ ] **B2B API partnerships** — Onboard first BSC wallet or DEX integrating ShieldBot API. Target: PancakeSwap, Biswap. GoPlus holds this position; approach as a BNB-native alternative.
- [ ] **Insurance protocol partnerships** — Revenue share on premium reductions for protected wallets.

### UX & Localization
- [ ] **Human-readable transaction decoder** — Structured plain-English breakdown of what a transaction actually does, displayed before the risk score. Surfaces existing calldata decoding (`calldata_decoder.py`) as a visual summary: function called, amounts sent/received, spender address, approval type. Reduces false-positive friction — users trust a clear breakdown more than a score alone.
- [ ] **Wallet security health score** — One-command scan of a full wallet that returns a security grade (0–100), open dangerous approvals count, risky tokens held, and a prioritized action list. Packages existing Rescue Mode and scan endpoints into a shareable summary. Organic growth driver: users share their score.
- [x] **Asset delta preview** — Tenderly full simulation output surfaced in extension overlay. Green = tokens in, red = tokens out, dollar value when available. "SIMULATED" badge. Gracefully hidden when Tenderly not configured. Live in v1.0.4.
- [ ] **Multi-language support** — Extension UI and Telegram bot responses in Mandarin, Korean, Vietnamese, and Portuguese. BNB Chain's largest user bases are in Asia and Brazil. No other security tool targets these communities in their native language.

---

## Phase 5: V3 — Moat Extension + Expansion

Features that go beyond every active competitor and establish ShieldBot as the definitive standard.

### New Detection Capabilities
- [ ] **Post-deployment contract monitoring** — Background watcher that periodically re-scans high-traffic BSC tokens for state changes: ownership transfers, tax rate changes, blacklist additions, new mint functions. Push Telegram alerts to users who previously scanned the token. No competitor does this.
- [ ] **Asset soft-locking** — Let users designate specific tokens or NFTs as "protected". Any transaction involving a protected asset triggers an elevated confirmation step. WalletGuard (now defunct) pioneered this; no active tool offers it.
- [ ] **ML-based phishing detection** — Move beyond blocklists to behavioral pattern detection: homoglyph URLs, newly registered domains, impersonation patterns. WalletGuard (now MetaMask) had this; it is the most advanced phishing protection in the industry and is no longer available independently.

### Platform Expansion
- [ ] **Firefox extension** — Port the Manifest V3 extension to Firefox. Revoke.cash and Fire support Firefox; Chrome-only limits the addressable market. MV3 Firefox compatibility is available since 2023.
- [ ] **Solana support** — New chain architecture, different transaction model.
- [ ] **TON support** — Telegram-native chain, natural fit for the existing Telegram bot.
- [ ] **Mobile native app** — Dedicated mobile experience beyond RPC proxy.

### Ecosystem Integrations
- [ ] **BSC trading bot integrations** — Maestro, Banana Gun, and UniBot serve millions of BSC retail traders through Telegram. Integrate ShieldBot's `/token` scan into their pre-trade flow. ShieldBot already has the Telegram bot infrastructure; this is a partnership + API integration.
- [ ] **DEX security widgets** — Embeddable ShieldBot token safety badge for PancakeSwap, Biswap, and other BSC DEXs. Display the ShieldScore directly in the swap UI.
- [ ] **Autonomous rescue execution (Tier 3)** — Auto-revoke dangerous approvals with user consent. Extend Rescue Mode from advisory to action.
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
| Partnership | DEX / trading bot integrations | Revenue share or flat integration fee |
| Partnership | Insurance protocols | Revenue share on premium reductions |
| Secondary | Consumer Pro | $9-15/month for unlimited scans, all chains, rescue mode, post-deploy alerts |

---

## How to Contribute

ShieldBot is open source. If you want to contribute:

1. Check this roadmap for unchecked items.
2. Open an issue to discuss the approach before submitting a PR.
3. See [SETUP_GUIDE.md](SETUP_GUIDE.md) for local development setup.

---

*Last updated: March 2026*
