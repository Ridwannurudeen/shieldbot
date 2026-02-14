# Judge Quick Start (2 minutes)

## 1. Try the Telegram Bot (30 seconds)

Open [@shieldbot_bnb_bot](https://t.me/shieldbot_bnb_bot) in Telegram.

```
/start
/scan 0x10ED43C718714eb63d5aA57B78B54704E256024E
/token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
/history 0x10ED43C718714eb63d5aA57B78B54704E256024E
```

**Expected output:**
- `/scan` returns a risk report with ShieldScore, danger signals, and AI analysis.
- `/token` returns honeypot check, tax info, ownership, and liquidity lock status.
- `/history` queries on-chain scan records from the ShieldBotVerifier contract.

## 2. Try the Chrome Extension (1 minute)

1. Clone the repo and load `extension/` as an unpacked extension in `chrome://extensions`.
2. Visit the test page: `http://38.49.212.108:8000/test`
3. Click **"Send 0.01 BNB to Honeypot"** — the firewall overlay should appear with a BLOCK recommendation.
4. Click **"Swap on PancakeSwap"** — whitelisted router, should pass silently.
5. Open the extension popup to see scan history.

## 3. On-Chain Proof

- **ShieldBotVerifier contract:** [`0x867aE7449af56BB56a4978c758d7E88066E1f795`](https://bscscan.com/address/0x867aE7449af56BB56a4978c758d7E88066E1f795#events)
- Every scan triggers a fire-and-forget on-chain recording. View event logs on BscScan.
- `/history <address>` reads the on-chain data back (zero gas, view function).

## 4. REST API

```bash
# Health check
curl http://38.49.212.108:8000/api/health

# Scan a contract
curl -X POST http://38.49.212.108:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"address": "0x10ED43C718714eb63d5aA57B78B54704E256024E"}'

# Firewall verdict (simulates what the extension sends)
curl -X POST http://38.49.212.108:8000/api/firewall \
  -H "Content-Type: application/json" \
  -d '{"to": "0x10ED43C718714eb63d5aA57B78B54704E256024E", "from": "0x0000000000000000000000000000000000000001", "value": "0x2386F26FC10000", "data": "0x", "chainId": 56}'
```

## 5. Run Locally (if preferred)

```bash
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # Add at least TELEGRAM_BOT_TOKEN and BSCSCAN_API_KEY
uvicorn api:app --port 8000
```

## Fallback: No AI Key

If `ANTHROPIC_API_KEY` is not set:
- The bot and API still work — AI scoring is skipped and heuristic-only results are returned.
- `/api/health` will show `"ai_available": false`.
- The extension firewall falls back to heuristic classification (SAFE / CAUTION / HIGH_RISK / BLOCK_RECOMMENDED).

## Chain Selection (BSC vs opBNB)

- Default chain is BSC (chainId 56). The API accepts `chainId: 204` for opBNB.
- Honeypot.is API only supports BSC — honeypot checks are skipped on opBNB with a clear fallback.
- BscScan API only covers BSC — verification/age checks use BSC regardless of chain.
- RPC calls (bytecode, ownership, token info) use the correct chain.
