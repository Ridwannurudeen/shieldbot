# Base Ecosystem Fund Application — ShieldBot

> STATUS: DRAFT — DO NOT SUBMIT WITHOUT EXPLICIT APPROVAL
> Last updated: 2026-05-05
> Application URL: https://docs.base.org/get-started/get-funded

---

## One-line pitch

ShieldBot is a transaction-firewall security stack — Chrome extension, MCP server, and REST API — that intercepts wallet transactions before signing and now publishes threat attestations on Base via Ethereum Attestation Service so any L2 app can read ShieldBot's verdict.

## Funding ask

```
Amount: $30,000 - $75,000 (6-month runway)
```

## Status snapshot

- V3 + April 2026 hardening pass live in production (api.shieldbotsecurity.online)
- 519 Python + 18 Solidity tests passing, CI green on every push
- Chrome extension v3.0.1 (BNB Chain Web Store listing approved at v3.0.0; v3.0.1 awaiting upload)
- 8 production features: Agent Firewall, MCP Server v3.1.0, Portfolio Guardian, Reputation Service, Injection Scanner, Anomaly Detection, Threat Graph, Premium Tiering
- 3rd Place at BNB Chain Good Vibes Only hackathon (Builders Track)
- $SHIELDBOT community token launched on four.meme

## Base integration (delivered May 5 2026)

- **`ShieldBotAttestor` contract on Base mainnet** — wraps EAS predeploy at `0x42…0021`. Every ShieldBot scan posts a permanent attestation with schema: `address scannedAddress, uint8 riskLevel, string scanType, uint64 sourceChainId, bytes32 evidenceHash, string evidenceURI`. The `sourceChainId` field means BSC scans become verifiable on Base too — ShieldBot's threat intel reads from Base for any consumer.
- **Portfolio Guardian** — extended to scan Base 8453 wallets for risky token approvals, reusing the same on-chain `eth_getLogs → eth_call` verification pipeline that runs on BSC.
- **Same primitive Coinbase Verifications uses** — EAS schema `0xf8b05c79…0de9` (Verified Account) lives on the same EAS contract our attestations write to.
- **Identity wallet:** `0xB2Fae83de08b285cB3D6A77Ff520F6AD669D5f33` (also holds Basename `sentinelnet.base.eth`, Coinbase Verified Account, two verified Base mainnet contracts from SentinelNet).

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
   a status pill (SAFE / WARNING / DANGER). Two-line integration; lets
   any Base dapp show "verified safe by ShieldBot" without a backend.
```

## Traction proof

```
- V3 production deployment live on Contabo VPS, 99.9% uptime since Mar 2026
- ~50 unique installs across BNB Chain Web Store + direct CRX
- Daily Telegram backups + Prometheus-style metrics, weekly snapshots
- Open source: github.com/Ridwannurudeen/shieldbot — 519 + 18 tests passing
- BNB Chain Good Vibes Only hackathon — 3rd Place (Builders Track)
- Verified Base contracts from 0xB2Fae83…D5f33: TrustGate
  (0xE3b6069f632ab439ef5B084C769F21b4beeE3506), SentinelNetStaking
  (0xEe1A8f34F1320D534b9a547f882762EABCB4f96d), and now ShieldBotAttestor
- Coinbase Verified Account (EAS UID 0xa8d745…f50)
```

## Why Base specifically

```
1. Base is the L2 where Coinbase users land first — security UX matters
   most where retail users transact. ShieldBot's transaction interception
   is exactly the kind of layer Base ecosystem dapps will reuse.

2. EAS as a public attestation primitive lets ShieldBot publish threat
   intel that any Base contract or app can read on-chain — no proprietary
   API, no auth, no rate limits. The data lives on Base permanently.

3. Coinbase agentkit + ERC-8004 + Smart Wallet + x402 form a stack we
   already build against. ShieldBot is the security primitive missing
   from that stack.
```

## Verification

| Resource | URL |
|----------|-----|
| Website | https://shieldbotsecurity.online |
| API | https://api.shieldbotsecurity.online |
| GitHub | https://github.com/Ridwannurudeen/shieldbot |
| Demo video | https://youtu.be/NN95rom10R8 |
| Chrome Web Store | https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk |
| Base attestor | (deployed on approval; will live at https://basescan.org/address/0x...) |
| Base identity wallet | https://basescan.org/address/0xB2Fae83de08b285cB3D6A77Ff520F6AD669D5f33 |

## Contact

- GitHub: @Ridwannurudeen
- Email: [FILL IN]
- Telegram: [FILL IN]
- X: @shieldbot_

## Talking points for follow-up call

1. Live demo: BNB Chain swap intercepted in real-time, threat scored, blocked
2. Live demo: Base wallet approval scan via Portfolio Guardian + revoke transaction
3. Show EAS attestation on `base.easscan.org` written by `ShieldBotAttestor`
4. Walk through x402 API design (USDC pricing per call, gas-paid signatures via Smart Wallet)
5. AgentKit Action Provider PR plan — concrete file/test list for upstream contribution

## Submission checklist

- [ ] Wait for `ShieldBotAttestor` deploy + BaseScan verify before submitting
- [ ] Fill in email + Telegram
- [ ] Attach 2-min demo video showing both BSC interception AND Base attestation flow
- [ ] Cross-post in Base Discord #builders after submission
- [ ] Tag @base + @jessepollak on the X announcement
