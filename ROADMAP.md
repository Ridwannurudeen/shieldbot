# ShieldBot Roadmap

Historical March 2026 planning record. Repository checklists below are not current deployment evidence. Current repository coverage and the shipped extension limitation are in [README.md](README.md) and [docs/TECHNICAL.md](docs/TECHNICAL.md). Future targets below are proposals, not measured outcomes.

ShieldBot is a transaction security service for eight EVM chains. The V2 plan below frames it as a **cross-chain security intelligence network**; shared observations can inform later scans, and missing observations remain unknown.

---

## Vision

**V1:** Transaction scanner for BNB Chain.
**V2 (current):** Cross-chain security intelligence network for wallets, traders, and applications.
**V3 (proposed):** Non-EVM expansion, consumer monetization and B2B partnerships.

---

## Distribution Channels

| Channel | Repository scope | Release qualification |
|---------|------------------|-----------------------|
| Chrome Extension | Wrapped provider requests and risk overlays | Shipped omitted-chain limitation; provider-chain repair unreleased; proceed overrides remain |
| RPC Proxy | Transaction-checking proxy implementation | Deployment and wallet compatibility not verified by this roadmap; coverage depends on chain and providers |
| SDK | See `sdk/` and the current README | Package publication status not verified here |
| Telegram | 12 registered command handlers | Running deployment not verified here; chain support is not complete provider coverage |
| Threat Dashboard | Display of recorded observations | Deployment and feed freshness not verified here |
| API | Scan and policy interfaces | Deployment not verified here; inspect coverage and failure fields |
| Firefox Extension | Proposed port | Not established as released |

---

## Historical Phase 1: Foundation (repository checklist, not deployment evidence)

- [x] **ChainAdapter interface** — Abstract chain-specific logic behind a common adapter. BSC as first adapter.
- [x] **Analyzer registry** — Pluggable pipeline where each detection capability is a registered plugin.
- [x] **Policy modes** — STRICT recommends blocking on analyzer errors; BALANCED retains a partial result with a warning. Shared coverage checks still govern scan authorization; browser overrides and auxiliary gaps remain (see `docs/TECHNICAL.md`).
- [x] **API auth and metering** — API key management, per-key rate limiting, usage tracking.
- [x] **Contract reputation DB** — Score and cache every contract analyzed. Shared intelligence across all users.
- [x] **Deployer/funder indexer** — Background data collection for the campaign graph.
- [x] **Outcome tracking** — Track what happens when users proceed past warnings. Labeled training data.
- [x] **Extension updates** — Policy mode selector, improved error states, setup flow.

---

## Historical Phase 2: Detection + Distribution (repository checklist, not deployment evidence)

- [x] **Intent mismatch analyzer** — Detect when transaction behavior doesn't match user intent.
- [x] **Signature/permit analyzer** — Typed signature risks, permit-like approvals, hidden delegate patterns.
- [x] **Confidence calibration** — Threshold tuning framework to minimize false positives on known-safe protocols.
- [x] **Evaluation pipeline** — Benchmark dataset + CLI that produces precision/recall reports.
- [x] **Community reporting** — Endpoint for users to flag false positives and false negatives.
- [x] **Ethereum and Base adapters** — First multichain expansion. Chain-aware caching and source routing.
- [x] **RPC proxy v1**: Proxy implementation; compatibility with a particular wallet and transaction path requires testing.
- [x] **Telegram scan-by-address**: Reports observed risk and missing required coverage for the selected chain.

---

## Historical Phase 3: Moat Features + Growth (repository checklist, not deployment evidence)

- [x] **Campaign Graph Radar v1** — Cross-chain entity correlation: deployers, funders, contract factories.
- [x] **Mempool monitoring v1** — Sandwich attack, frontrunning, and suspicious approval detection.
- [x] **Rescue Mode Tier 1** — Alerts with plain-language risk explanations.
- [x] **Rescue Mode Tier 2** — Pre-built revoke transactions. One-click approval cleanup.
- [x] **Arbitrum, Polygon, Optimism, opBNB adapters** — Backend adapters exist; per-provider coverage is incomplete and differs by chain. See the current README chain table.
- [x] **RPC proxy multichain**: Routes configured chains; this does not imply complete check coverage.
- [x] **SDK code**: See `sdk/`; package publication is not verified by this roadmap.
- [x] **Public threat dashboard** — Real-time feed of detected threats and campaigns.
- [x] **Threat Feed API** — Subscribe to ShieldBot's intelligence.
- [ ] **Chrome Web Store release evidence**: Owner must verify the published version; the provider-chain repair remains unreleased.
- [x] **Landing page**: Historical URL https://shieldbotsecurity.online; deployment is not verified here.

---

## Phase 4: Gap Closing + Market Capture

This phase captures users and closes the feature gaps that remain.

### Capture the Vacuum
- [x] **Landing page**: Historical URL https://shieldbotsecurity.online; deployment is not verified here.
- [x] **Chrome Web Store listing** — Listing title, description and screenshots; the text prepared for the next release is in [docs/store-listing.md](docs/store-listing.md).
- [ ] **Community launch** — Announce on X/Twitter, the community channels of each supported chain, crypto security groups targeting users migrating from defunct tools.
- [ ] **AvengerDAO membership** — Apply to BNB Chain's official community security coalition. Membership = ecosystem credibility, DappBay visibility, and referral from BNB Chain itself. GoPlus and HashDit are members.
- [x] **Extension onboarding flow** — First-time user tutorial and guided first scan. Welcome tab on install, auto-fills API URL, Connect & Protect flow. Historical version claim; current release status not verified here.
- [x] **Beta waitlist** — Email/wallet collection for early access to new features. Historical deployment claim; current availability not verified here.

### Close the Detection Gaps
- [x] **Phishing / URL blocker** — Content script checks active URL against GoPlus Phishing Site Detection API on every page load. Red banner on hit. 1hr cache. Historical version claim; current release status not verified here.
- [x] **Bytecode fingerprinting for unverified contracts** — Token Sniffer API integrated. Data-driven unverified penalty (10/25/40 risk based on Smell Test score). Gracefully disabled without API key. Historical version claim; current release status not verified here.
- [ ] **Deployer cluster auto-blocking** — When Campaign Graph Radar identifies a known bad deployer cluster, automatically flag all future tokens from that cluster in real-time — not just individually scanned contracts. Block entire scam networks, not just individual tokens.

### Production Hardening
- [ ] **Monitoring and alerting evidence**: Verify active jobs and alert delivery before describing an operational schedule.
- [ ] **Internal analytics dashboard** — Track scan volume, block rate, user retention, and chain distribution.
- [ ] **Database backup evidence**: Verify retention, successful backups and restoration before claiming a deployed schedule.
- [ ] **Rate limiting tuning** — Adjust limits based on real traffic patterns.
- [ ] **CI/CD pipeline** — Automated tests and deployment on push.

### Grants and Funding
- [ ] **BNB Chain MVB / Kickstart grant** — Apply only with owner-verified deployment and usage evidence.
- [ ] **Base Ecosystem Fund** — Base adapter exists in the repository; verify deployment before using it as grant evidence; apply for ecosystem grant.
- [ ] **Arbitrum Foundation grant** — Arbitrum adapter exists in the repository; verify deployment before using it as grant evidence; apply for STIP/ecosystem grant.

### Monetization
- [ ] **Consumer Pro tier** — $9-15/month for unlimited scans, all chains, priority analysis, post-deploy alerts.
- [ ] **B2B API partnerships** — Onboard the first wallet or DEX integrating the ShieldBot API. Target: PancakeSwap, Uniswap and other DEXs.
- [ ] **Insurance protocol partnerships** — Revenue share on premium reductions for protected wallets.

### UX & Localization
- [x] **Human-readable transaction decoder** — Structured plain-English breakdown of what a transaction actually does, displayed before the risk score. Surfaces existing calldata decoding (`calldata_decoder.py`) as a visual summary: function called, amounts sent/received, spender address, approval type. Reduces false-positive friction — users trust a clear breakdown more than a score alone. The extension overlay's decoded calldata section implements it (`_build_calldata_details` in `api.py`, `buildCalldataSection` in `extension/content.js`); current release status not verified here.
- [ ] **Wallet security health score** — One-command scan of a full wallet that returns a security grade (0–100), open dangerous approvals count, risky tokens held, and a prioritized action list. Packages existing Rescue Mode and scan endpoints into a shareable summary. Organic growth driver: users share their score.
- [x] **Asset delta preview** — Tenderly full simulation output surfaced in extension overlay. Green = tokens in, red = tokens out, dollar value when available. "SIMULATED" badge. Gracefully hidden when Tenderly not configured. Historical version claim; current release status not verified here.
- [ ] **Multi-language support** — Extension UI and Telegram bot responses in Mandarin, Korean, Vietnamese, and Portuguese.

---

## Phase 5: V3 — Moat Extension + Expansion

Proposed detection and distribution work; these items are not release claims.

### New Detection Capabilities
- [ ] **Post-deployment contract monitoring** — Background watcher that periodically re-scans high-traffic tokens for state changes: ownership transfers, tax rate changes, blacklist additions, new mint functions. Push Telegram alerts to users who previously scanned the token.
- [ ] **Asset soft-locking** — Let users designate specific tokens or NFTs as "protected". Any transaction involving a protected asset triggers an elevated confirmation step.
- [ ] **ML-based phishing detection** — Move beyond blocklists to behavioral pattern detection: homoglyph URLs, newly registered domains, impersonation patterns.

### Platform Expansion
- [ ] **Firefox extension** — Port the Manifest V3 extension to Firefox. Compatibility and store review would be required.
- [ ] **Solana support** — New chain architecture, different transaction model.
- [ ] **TON support** — Telegram-native chain, natural fit for the existing Telegram bot.
- [ ] **Mobile native app** — Dedicated mobile experience beyond RPC proxy.

### Ecosystem Integrations
- [ ] **Trading bot integrations** — Integrate ShieldBot's `/token` scan into their pre-trade flow. ShieldBot already has the Telegram bot infrastructure; this is a partnership + API integration.
- [ ] **DEX security widgets** — Embeddable ShieldBot token safety badge for PancakeSwap, Uniswap and other DEXs. Display the ShieldScore directly in the swap UI.
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
