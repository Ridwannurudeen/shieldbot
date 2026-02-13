# X Thread — ShieldAI Transaction Firewall

Copy-paste each tweet as a reply in a thread.

---

**Tweet 1 (Hook)**

Built a real-time transaction firewall for BNB Chain.

It intercepts your wallet transactions BEFORE you sign — decodes the calldata, scans the contract, and tells you exactly what you're about to do.

Open source. Free. Here's how it works:

---

**Tweet 2 (The Problem)**

$5.6B lost to crypto scams in 2025.

The #1 attack vector? Unlimited token approvals to malicious contracts.

You click "Approve" on a dApp, and a drainer silently gets permission to move ALL your tokens. Most users don't even know what they signed.

---

**Tweet 3 (The Solution)**

ShieldAI is a Chrome extension that sits between your wallet and every dApp.

When you initiate a transaction, it:
- Intercepts the tx before MetaMask pops up
- Decodes the calldata (approve? transfer? swap?)
- Scans the target contract
- Shows an AI-powered security verdict

---

**Tweet 4 (How It Works - Technical)**

Under the hood:

1. JS Proxy wraps `window.ethereum.request` — catches every `eth_sendTransaction`
2. Calldata decoder maps function selectors (approve, transferFrom, swap, mint, etc.)
3. Backend runs contract scan: verification, scam DB, bytecode patterns, honeypot check
4. Claude AI generates a firewall verdict with danger signals + plain-English explanation

---

**Tweet 5 (Smart Features)**

Smart details that matter:

- Whitelisted routers (PancakeSwap V2/V3, 1inch) get fast-tracked — no false alarms on trusted DEXs
- Unlimited approvals to unverified contracts get flagged BLOCK_RECOMMENDED
- Token names and symbols resolved on-chain — shows "UNLIMITED USDT" not "0xffffffff..."
- Safety score: 0-100, color-coded badge, one-click Block or Proceed

---

**Tweet 6 (Stack)**

Stack:
- Chrome Extension (Manifest V3, EIP-6963)
- FastAPI backend on VPS
- web3.py for BNB Chain
- Claude AI for security verdicts
- Reuses the same engine as our Telegram bot (@shieldbot_bnb_bot)

One security engine, two surfaces: chat + browser.

---

**Tweet 7 (Demo)**

Tested on PancakeSwap:

Swap BNB → USDT: "SAFE — Safety 95/100. PancakeSwap Universal Router is a verified, trusted router."

Approve unlimited USDT to unknown contract: "BLOCK RECOMMENDED — Safety 10/100. Unlimited approval to unverified contract."

Exactly what you want.

---

**Tweet 8 (CTA)**

Everything is open source:

github.com/Ridwannurudeen/shieldbot

Built for the @BNBChain Good Vibes Only hackathon.

Try the Telegram bot: @shieldbot_bnb_bot
Try the extension: clone the repo → load `extension/` folder in Chrome

Protecting BNB Chain users, one transaction at a time.

---
