# Base Ecosystem Fund Application — ShieldBot

> STATUS: DRAFT — DO NOT SUBMIT WITHOUT EXPLICIT APPROVAL
> Last updated: 2026-05-05
> Application URL: https://docs.base.org/get-started/get-funded

---

This is a historical funding draft, not deployment or adoption evidence. The current source-tree scope and unreleased extension chain repair are documented in [TECHNICAL.md](TECHNICAL.md). Deployment, award and identity assertions retained below require owner verification before reuse.

## One-line pitch

ShieldBot is a transaction-firewall security stack — Chrome extension, MCP server, and REST API — that analyzes wrapped wallet requests before signing, with user overrides and shipped chain-identification limits. An optional Base EAS publisher exists in the repository; configured publication can fail and is not a prerequisite for a scan response.

## Funding ask

```
Amount: $30,000 - $75,000 (6-month runway)
```

## Status evidence required

Current test results are recorded in [TESTING.md](TESTING.md). This draft does not establish production versions, store approval, awards, token-launch status or adoption; those claims have been omitted pending owner evidence. The extension's provider-chain repair is unreleased.

## Base implementation (deployment unverified in this document)

- **`ShieldBotAttestor` / EAS adapter**: `utils/base_attestor.py` requires configuration and schedules best-effort publication. Bot cache hits return before the publication call. A scan response therefore does not prove an attestation exists. The original draft has no verified attestor deployment address; do not describe it as deployed from this document.
- **Portfolio Guardian** — extended to scan Base 8453 wallets for risky token approvals, reusing the same on-chain `eth_getLogs → eth_call` verification pipeline that runs on BSC.

## What we'd build with funding

```
1. Coinbase Smart Wallet integration — gasless, one-tap revoke for risky
   approvals via OnchainKit's <SmartWallet /> + <Transaction /> components.
   Removes the biggest UX friction in Portfolio Guardian: users seeing
   risky approvals but not revoking because of gas.

2. x402 paid query API — pay-per-request `/api/threats/check?address=X`
   priced in USDC on Base. Lets agents (ERC-8004, AgentKit, MCP clients)
   query ShieldBot's threat intel without API keys. Demonstrates a
   real x402 use case beyond demos.

3. Base-native threat graph — extend our existing BFS traversal +
   Union-Find clustering to Base 8453 deployer relationships. Surface
   sybil clusters and rug-pull deployer rings for Base apps.

4. AgentKit Action Provider for Coinbase agentkit — an "is-this-safe?"
   tool that any agentkit-built agent can call before broadcasting
   a transaction on Base. Open-source PR upstream so any Coinbase
   agent gets transaction firewalling for free.

5. Verified-attestation badge on dapps — serve a tiny embeddable widget
   that reads a contract's ShieldBot attestation from EAS and renders
   a status pill with explicit unknown/coverage information. This remains a
   proposal; an attested label would not prove that a dapp is safe.
```

## Traction evidence required

The former 99.9% uptime and approximately 50-install claims were not supported by measurements in this document and have been removed. Current first-party scan volume must come from an owner-verified `GET /api/stats` snapshot, not this draft. No adoption, uptime or loss-prevention metric is claimed here.

## Why Base is proposed

The optional EAS adapter provides a place to publish attestations for independently readable records. Publication success, record contents and continued access must be checked for the particular deployment; this draft makes no permanence or unlimited-access claim. AgentKit and Smart Wallet support above remain proposed funding work.

## Verification

| Resource | URL |
|----------|-----|
| Website | https://shieldbotsecurity.online |
| API | https://api.shieldbotsecurity.online |
| GitHub | https://github.com/Ridwannurudeen/shieldbot |
| Demo video | https://youtu.be/NN95rom10R8 |
| Chrome Web Store | https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk |
| Base attestor | Owner must supply a verified deployment address before use |
| Base identity wallet | https://basescan.org/address/0xB2Fae83de08b285cB3D6A77Ff520F6AD669D5f33 |

## Contact

- GitHub: @Ridwannurudeen
- Email: [FILL IN]
- Telegram: [FILL IN]
- X: @shieldbot_

## Talking points for follow-up call

1. Demonstrate a supported BNB request with its coverage result and browser cancel/proceed choices
2. Live demo: Base wallet approval scan via Portfolio Guardian + revoke transaction
3. Show an EAS attestation only after verifying its deployment and transaction
4. Walk through x402 API design (USDC pricing per call, gas-paid signatures via Smart Wallet)
5. AgentKit Action Provider PR plan — concrete file/test list for upstream contribution

## Submission checklist

- [ ] Wait for `ShieldBotAttestor` deploy + BaseScan verify before submitting
- [ ] Fill in email + Telegram
- [ ] Attach 2-min demo video showing both BSC interception AND Base attestation flow
- [ ] Cross-post in Base Discord #builders after submission
- [ ] Tag @base + @jessepollak on the X announcement
