# ShieldBot

BNB Chain transaction firewall with cross-chain threat detection.

## Stack
- Python 3.11+, FastAPI, uvicorn
- web3.py 6.15, aiohttp, aiosqlite (SQLite WAL)
- python-telegram-bot 20.7
- Anthropic Claude API for analysis

## Setup
```bash
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env  # fill in API keys
```

## Run
```bash
# API server
uvicorn api:app --host 0.0.0.0 --port 8000

# Telegram bot (separate terminal)
python bot.py
```

## Test
```bash
pytest tests/ -v
```

## Deploy
```bash
git push origin main
# Then on VPS (root@38.49.212.108):
cd /opt/shieldbot && git pull && systemctl restart shieldbot
```

## Architecture
- `core/` — Engine, risk scoring, database, auth, calibration
- `analyzers/` — 6 pluggable plugins (structural, market, behavioral, honeypot, intent, signature)
- `adapters/` — EVM chain adapters
- `services/` — Contract intel, DEX data, reputation, simulation, mempool
- `extension/` — Chrome Extension (Manifest V3)
- `dashboard/` — Threat dashboard

## Conventions
- Async throughout (aiohttp, aiosqlite, asyncio)
- Tests use pytest + unittest.mock, fixtures in `conftest.py`
- Pluggable analyzer pattern with registry
- Never commit `.env` — contains API keys and secrets
