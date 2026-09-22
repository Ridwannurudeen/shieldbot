# AvengerDAO Membership Application -- ShieldBot

> STATUS: DRAFT -- DO NOT SUBMIT WITHOUT EXPLICIT APPROVAL
> Last updated: 2026-05-05

---

This historical application draft is not a current release or deployment record. External research, agent scheduling, store versions and award assertions below need owner verification before reuse. The current coverage and shipped extension limitations are in [TECHNICAL.md](TECHNICAL.md).

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

### ShieldBot's Proposed Contribution

ShieldBot exposes transaction and token risk checks. Its browser wrapper can display a warning before a wrapped request reaches the wallet, but users can proceed and the shipped extension has an omitted-chain limitation. This draft does not claim exclusivity or compare current member capabilities.

---

## Application Strategy

A producer/consumer relationship with Meter is proposed, not implemented by this draft. Before submission, demonstrate the specific API fields offered, their missing-data semantics and any planned Meter adapter. Do not describe agent scheduling as operational without deployment evidence.

The optional Base EAS publisher schedules best-effort calls. Bot cache hits and publication failures need not produce an attestation. A scan response is not proof of an on-chain record.

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
ShieldBot exposes token and transaction risk checks through a REST API and
Telegram bot. The browser extension warns on wrapped requests before signing
where supported; proceed overrides remain, and the shipped version has an
omitted-chain limitation. The provider-chain repair is unreleased.

We propose contributing observed risk and explicit coverage information to
Meter, and evaluating Meter as an additional input. Neither connection is
established by this draft. Missing data must not become permission to execute.

Optional Base EAS publication exists in the repository; configuration,
publication success and individual records require separate verification.
Current reproducible evidence and measured test results are in
README.md, docs/JUDGE_GUIDE.md and docs/TESTING.md.

Repository: https://github.com/Ridwannurudeen/shieldbot
```

### Phone (optional)
```
[LEAVE BLANK OR ADD IF DESIRED]
```

### Comments (optional)
```
We can demonstrate supported checks, their evidence and their limits. We
would welcome a discussion of the proposed Meter producer/consumer interface.
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

Before selecting an RFP challenge, recheck its current requirements and map each claimed capability to a reproducible demonstration. This draft does not establish deployed threat hunting, monitoring cadence or cluster coverage.

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
We propose a discussion about exposing ShieldBot's observed risk and coverage
information to the AvengerDAO ecosystem. The specific RFP fit and Meter
interface require joint scoping; this draft makes no deployment or
continuous-monitoring claim.

The repository includes reproducible recorded simulation tests and explicit
unknown results where required checks are incomplete. Browser warnings can
be overridden, and the shipped extension's omitted-chain limitation remains.

Repository: https://github.com/Ridwannurudeen/shieldbot
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

1. **Supported transaction check** -- show coverage and the browser cancel/proceed choices
2. **Agent scheduling evidence** -- show a deployed run and cadence only after verifying both
3. **API integration proposal** -- concrete plan for feeding ShieldBot data into Meter
4. **Meter consumption** -- how ShieldBot would display AvengerDAO risk scores
5. **Usage evidence** -- use an owner-verified stats snapshot; do not invent installs or users
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
