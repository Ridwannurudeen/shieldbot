# AvengerDAO Membership Application -- ShieldBot

> STATUS: DRAFT -- DO NOT SUBMIT WITHOUT EXPLICIT APPROVAL
> Last updated: 2026-05-05

---

## Table of Contents

1. [Research Summary](#research-summary)
2. [Application Strategy](#application-strategy)
3. [Form Responses (Membership Form)](#form-responses-membership-form)
4. [Form Responses (RFP/Contact Form)](#form-responses-rfpcontact-form)
5. [Supporting Material](#supporting-material)
6. [Next Steps](#next-steps)

---

## Research Summary

### What is AvengerDAO?

AvengerDAO is a community-driven security infrastructure project on BNB Chain, launched in September 2022. It protects users from exploits, scams, and malicious actors through three core components:

- **Meter**: A passive API system that aggregates risk ratings from multiple security providers (producers) and serves them to wallets/dApps (consumers). Has scanned over 1 million unique contract addresses, flagging 35,000+ as high risk.
- **Watch**: A subscription-based alert system for real-time threat notifications.
- **Vault**: A programmable fund management system.

### Current Members

**Founding members (2022):**
CertiK, GoPlus, SlowMist, Zokyo, BlockSec, Hashdit, Verichains, Pessimistic, CoinMarketCap, TrustWallet, PancakeSwap, BSCtrace (NodeReal), BscScan, MathWallet, DappBay, Coin98, Opera

**Later additions:**
Automata (Jan 2023), Bubblemaps, Ironblocks (Sep 2023), Ancilia, Salus Security

### Member Roles

- **Producers**: Security auditors/firms that generate risk data fed into the Meter API. Currently Hashdit and GoPlus are the primary data producers.
- **Consumers**: Wallets, dApps, explorers that display security data to end users (TrustWallet, PancakeSwap, DappBay, etc.).
- **Contributors**: Projects that contribute security frameworks, threat intelligence, or monitoring tools.

### How to Apply

There are two relevant forms:

1. **Membership/Collaboration Form** (primary): https://forms.monday.com/forms/d29ec674a6e737d0d931c04d896c4f56?r=use1
   - Header: "Thank you for expressing interest to work with AvengerDAO! Kindly input the information below and our team will reach out to you."
   - Required fields: Name, Website, TG handle, Email, "How would you like to work with AvengerDAO?"
   - Optional: Phone, Address, Comments, File uploads

2. **RFP/Contact Form**: https://forms.monday.com/forms/8cc0bbbd50e856eea12e15ace1a4e62b?r=use1
   - For responding to specific challenges (smart contract monitoring, dApps directory, threat intelligence, security analytics)
   - Required fields: Project name, TG handle, Email, Project website, Reasons to contact

### Application Process (from official sources)

1. Fill out the membership form with project details
2. Ideally have an open API in place already
3. AvengerDAO team assesses and schedules an introduction call
4. Founding members decide on membership approval

### What Makes a Strong Application

Based on analysis of existing members, successful applicants typically:
- Provide unique security data or capabilities not already covered
- Have an existing, functional product (not vaporware)
- Offer an API that can integrate with the Meter ecosystem
- Serve the BNB Chain ecosystem directly
- Complement rather than compete with existing members

### ShieldBot's Competitive Advantage

No current AvengerDAO member does what ShieldBot does -- **real-time transaction-level interception before signing**. The existing members are:
- Auditors (CertiK, SlowMist, etc.) -- audit code, not transactions
- Token scanners (GoPlus, Hashdit) -- scan contracts, not user intent
- Analytics (Bubblemaps, BlockSec) -- post-hoc analysis
- Wallets (TrustWallet, MathWallet) -- show warnings but don't intercept

ShieldBot is the **missing piece**: an active transaction firewall that sits between the user and the blockchain, analyzing every transaction before it executes. This is a genuinely new capability for the AvengerDAO ecosystem.

---

## Application Strategy

### Positioning: Both Producer AND Consumer

ShieldBot should apply as BOTH:

**As a Producer:**
- ShieldBot's AI agents (Hunter, Sentinel) continuously scan BNB Chain for threats
- Hunter runs 30-minute sweep cycles finding malicious contracts, honeypots, rug pulls
- Sentinel maintains a feedback loop on tracked pairs
- This threat intelligence data can be fed into the Meter API
- ShieldBot already has a REST API at https://api.shieldbotsecurity.online

**As a Consumer:**
- ShieldBot can integrate AvengerDAO's Meter API ratings into its transaction analysis
- Display AvengerDAO risk scores alongside ShieldBot's own analysis in the Chrome extension
- Cross-reference AvengerDAO's flagged addresses with ShieldBot's real-time interception

### Key Differentiators to Emphasize

1. **Transaction-level, not contract-level** -- we intercept individual transactions, not just scan contracts
2. **Pre-execution, not post-mortem** -- we block threats BEFORE the user signs
3. **AI-powered proactive hunting** -- our agents don't wait for reports, they hunt threats
4. **BNB Chain native** -- built specifically for BNB Chain first (hackathon winner)
5. **Free and open source** -- zero barrier to adoption
6. **Already live** -- V3 + Apr 30 hardening, 519 tests, CWS published, real users
7. **Cross-chain attestations on Base EAS** -- every BSC scan also produces a permanent attestation on Base via Ethereum Attestation Service (the same primitive Coinbase Verifications uses). Threat intel becomes verifiable from any L2.

---

## Form Responses (Membership Form)

**Form URL**: https://forms.monday.com/forms/d29ec674a6e737d0d931c04d896c4f56?r=use1

### Name (required)
```
Ridwan Nurudeen -- ShieldBot (ShieldAI Transaction Firewall)
```

### Website (required)
```
https://shieldbotsecurity.online
```

### TG handle (required)
```
[YOUR TELEGRAM HANDLE HERE]
```

### Email address (required)
```
[YOUR EMAIL HERE]
```

### How would you like to work with AvengerDAO? (required)

```
ShieldBot is a real-time transaction firewall for BNB Chain -- a Chrome extension,
Telegram bot, and REST API that intercepts and analyzes every transaction BEFORE the
user signs it. We won 3rd Place at BNB Chain's Good Vibes Only hackathon (Builders
Track) and are live on the Chrome Web Store with v2.0.0.

We would like to contribute to AvengerDAO as both a Producer and Consumer:

AS A PRODUCER:
ShieldBot runs three AI agents that continuously generate threat intelligence:
- Hunter Agent: Sweeps BNB Chain every 30 minutes, identifying honeypots, rug pulls,
  and malicious contracts through on-chain analysis
- Sentinel Agent: Maintains a real-time feedback loop on tracked token pairs,
  detecting liquidity removals and ownership changes as they happen
- Advisor Agent: Routes and classifies security intents from user queries

This threat data is served via our REST API (https://api.shieldbotsecurity.online)
and could be integrated as a new data source for the Meter API. Unlike existing
producers that scan contracts statically, ShieldBot produces dynamic, behavioral
threat intelligence -- flagging contracts that BECOME dangerous after deployment.

AS A CONSUMER:
We want to integrate AvengerDAO's Meter risk ratings into ShieldBot's transaction
analysis pipeline. When a user is about to interact with a contract, ShieldBot would
cross-reference AvengerDAO's aggregated risk score alongside our own analysis, giving
users the most comprehensive pre-transaction security check available on BNB Chain.

WHAT MAKES SHIELDBOT UNIQUE IN THE AVENGERDAO ECOSYSTEM:
No current member provides real-time transaction interception. Auditors scan code.
Scanners check contracts. Analytics look backward. ShieldBot is the missing layer --
an active firewall that blocks threats at the moment of transaction, before the user
signs. This fills a critical gap: even if every contract is scanned, users still
interact with unscanned or newly-deployed contracts daily. ShieldBot catches those.

KEY FACTS:
- V3 + Apr 30 2026 hardening live on Chrome Web Store (v3.0.1)
- 519 Python + 18 Solidity tests passing
- 7 chains supported (BNB Chain primary, Base now first-class)
- Open source: https://github.com/Ridwannurudeen/shieldbot
- Free to use -- zero cost for end users
- AI agents: Hunter (threat sweeps), Sentinel (pair monitoring), Advisor (intent routing)
- 8 production features: Agent Firewall, MCP Server v3.1.0, Portfolio Guardian,
  Reputation Service, Injection Scanner, Anomaly Detection, Threat Graph, Premium Tiering
- Cross-chain attestations on Base via EAS (ShieldBotAttestor on Base mainnet)
- Demo: https://youtu.be/NN95rom10R8
- BNB Chain hackathon winner (Good Vibes Only, Builders Track, 3rd Place)
```

### Phone (optional)
```
[LEAVE BLANK OR ADD IF DESIRED]
```

### Comments (optional)
```
ShieldBot was purpose-built for BNB Chain and won recognition at the Good Vibes Only
hackathon. We are actively building and shipping -- v2.0.0 includes a full AI agent
system with proactive threat hunting. We believe ShieldBot fills a critical gap in
AvengerDAO's security stack by providing the transaction-level interception layer
that no current member offers. Happy to schedule a call to demo the product and
discuss integration specifics.
```

### Files (optional)
```
Consider attaching:
- ShieldBot architecture diagram (docs/ARCHITECTURE_DIAGRAM.md or export as PDF)
- Product deck (docs/ShieldBot_Investor_Deck_Mainstream_Plan_With_V2_Appendix.pdf)
```

---

## Form Responses (RFP/Contact Form)

**Form URL**: https://forms.monday.com/forms/8cc0bbbd50e856eea12e15ace1a4e62b?r=use1

This form is for responding to AvengerDAO's specific RFP challenges. ShieldBot is relevant to:
- **Challenge 1 (Smart Contract Monitoring)**: Hunter agent monitors newly deployed contracts
- **Challenge 3 (Threat Intelligence)**: Continuous on-chain threat detection
- **Challenge 4 (Security Analytics Infrastructure)**: Fund flow analysis and malicious address clustering

### Name of your project (required)
```
ShieldBot (ShieldAI Transaction Firewall)
```

### Your TG handle (required)
```
[YOUR TELEGRAM HANDLE HERE]
```

### Your email address (required)
```
[YOUR EMAIL HERE]
```

### Your project's website (required)
```
https://shieldbotsecurity.online
```

### Reasons to Contact (required)

```
Responding to AvengerDAO RFP challenges -- ShieldBot addresses Challenges 1, 3, and 4:

CHALLENGE 1 - SMART CONTRACT MONITORING:
ShieldBot's Hunter agent runs automated 30-minute sweep cycles on BNB Chain, detecting
newly deployed contracts and analyzing them for honeypot patterns, rug pull signals,
ownership concentration, and liquidity manipulation. When a contract triggers risk
thresholds, it is flagged in real-time and users interacting with it receive immediate
warnings through our Chrome extension overlay.

CHALLENGE 3 - THREAT INTELLIGENCE:
Our Sentinel agent maintains persistent monitoring on tracked token pairs, detecting:
- Sudden liquidity removals
- Ownership transfers or renouncement patterns
- Unusual trading volume spikes
- Contract upgrades or proxy changes
This produces a continuous stream of behavioral threat intelligence that goes beyond
static contract analysis.

CHALLENGE 4 - SECURITY ANALYTICS INFRASTRUCTURE:
ShieldBot's transaction analysis engine performs fund flow tracing, identifying related
addresses and potential malicious clusters. Our API exposes this data at:
https://api.shieldbotsecurity.online

ShieldBot is open source (https://github.com/Ridwannurudeen/shieldbot), free to use,
and live on the Chrome Web Store. We won 3rd Place at BNB Chain's Good Vibes Only
hackathon (Builders Track). 519 Python + 18 Solidity tests passing, V3 + Apr 30 hardening deployed.
Threat intel is now also published as cross-chain attestations on Base EAS for
ecosystem-wide verifiability.
```

---

## Supporting Material

### Links to Include

| Resource | URL |
|----------|-----|
| Website | https://shieldbotsecurity.online |
| Chrome Web Store | https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk |
| API | https://api.shieldbotsecurity.online |
| GitHub | https://github.com/Ridwannurudeen/shieldbot |
| Demo Video | https://youtu.be/NN95rom10R8 |

### Files to Attach

- `docs/ShieldBot_Investor_Deck_Mainstream_Plan_With_V2_Appendix.pdf` -- product overview deck
- Architecture diagram (export from `docs/ARCHITECTURE_DIAGRAM.md`)

### Talking Points for the Introduction Call

If the AvengerDAO team schedules a follow-up call, key points to hit:

1. **Live demo of transaction interception** -- show a real swap being analyzed in real-time
2. **Hunter agent sweep** -- show the 30-minute cycle finding threats autonomously
3. **API integration proposal** -- concrete plan for feeding ShieldBot data into Meter
4. **Meter consumption** -- how ShieldBot would display AvengerDAO risk scores
5. **Adoption metrics** -- CWS installs, Telegram bot users, API calls
6. **Open source commitment** -- full transparency, anyone can verify the security logic

---

## Next Steps

1. [ ] Review and finalize this draft
2. [ ] Fill in Telegram handle and email address
3. [ ] Export architecture diagram as PDF for attachment
4. [ ] **DECISION**: Submit membership form only, RFP form only, or both?
   - Recommendation: Submit membership form FIRST. If accepted, then engage with RFP challenges.
5. [ ] Submit membership form at: https://forms.monday.com/forms/d29ec674a6e737d0d931c04d896c4f56?r=use1
6. [ ] Wait for AvengerDAO team response / introduction call scheduling
7. [ ] Prepare live demo environment for the call

---

## Research Sources

- [AvengerDAO Official Site](https://www.avengerdao.org/)
- [AvengerDAO Documentation](https://www.avengerdao.org/docs/)
- [BNB Chain Blog: Introducing AvengerDAO](https://www.bnbchain.org/en/blog/introducing-avengerdao-the-security-initiative-protecting-users-from-malicious-actors)
- [BNB Chain Blog: Meet With BNB Chain Experts #3](https://www.bnbchain.org/en/blog/meet-with-bnb-chain-experts-3-protect-users-and-projects-together-with-avengerdao)
- [CoinDesk: BNB Chain Security Firms Start AvengerDAO](https://www.coindesk.com/business/2022/09/20/bnb-chain-blockchain-security-firms-start-avengerdao-to-protect-users)
- [BNB Chain Blog: 2023 Security Report by AvengerDAO](https://www.bnbchain.org/en/blog/bnb-smart-chain-2023-security-report-by-avengerdao-contributed-by-hashdit-certik-ancilia-and-salus-security)
- [Ironblocks Partners with AvengerDAO (Yahoo Finance)](https://finance.yahoo.com/news/ironblocks-partners-avengerdao-bolster-security-231500256.html)
- [Bubblemaps Joins AvengerDAO (BSC News)](https://bsc.news/post/bubble-maps-joins-avengerdao-bnb-chain-security-intiative)
- [AvengerDAO RFP on GitHub](https://github.com/bnb-chain/avengerdao/blob/main/rfps/rfp-avengerdao.md)
- [AvengerDAO Marketplace](https://www.avengerdao.org/marketplace)
- [BNB Chain Security Programs Overview](https://www.bnbchain.org/en/blog/an-overview-of-bnb-chains-security-programs)
- [CoinMarketCap: AvengerDAO Q&A](https://coinmarketcap.com/community/articles/63638bbae0e9157c042f622f/)
