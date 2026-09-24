# ShieldBot Deployment Guide

## Quick Start (Local Testing)

### 1. Setup
```bash
# Clone and navigate to project
cd shieldbot

# Run setup script
chmod +x setup.sh run.sh
./setup.sh

# Edit .env with your credentials
nano .env
```

### 2. Get Telegram Bot Token
1. Open Telegram and search for [@BotFather](https://t.me/BotFather)
2. Send `/newbot`
3. Choose a name (e.g., "ShieldBot BNB")
4. Choose a username (e.g., "shieldbot_bnb_bot")
5. Copy the token and add to `.env`:
   ```
   TELEGRAM_BOT_TOKEN=your_token_here
   ```

### 3. Get BscScan API Key (Recommended)
1. Go to [BscScan](https://bscscan.com)
2. Sign up and verify email
3. Go to [API Keys](https://bscscan.com/myapikey)
4. Create new API key
5. Add to `.env`:
   ```
   BSCSCAN_API_KEY=your_api_key_here
   ```

### 4. Run the Bot
```bash
./run.sh
```

Test in Telegram:
- Send `/start` to your bot
- Send a BSC contract address to scan

---

## Production Deployment (VPS/Server)

**API sender constraint:** `shieldbot-api.service` runs one uvicorn process without `--workers`. Preserve that topology: the API lifespan starts the verdict publisher, and its nonce lock is process-local. Multiple API processes, workers or replicas can compete for the same recorder. The bot examples below are not instructions to replicate the API sender.

### Option 1: systemd Service (Recommended)

1. **Create service file:**
```bash
sudo nano /etc/systemd/system/shieldbot.service
```

2. **Add configuration:**
```ini
[Unit]
Description=ShieldBot - BNB Chain Security Bot
After=network.target

[Service]
Type=simple
User=your_username
WorkingDirectory=/path/to/shieldbot
Environment="PATH=/path/to/shieldbot/venv/bin"
ExecStart=/path/to/shieldbot/venv/bin/python bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

3. **Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable shieldbot
sudo systemctl start shieldbot
sudo systemctl status shieldbot
```

4. **View logs:**
```bash
sudo journalctl -u shieldbot -f
```

### Option 2: Docker Deployment

1. **Create Dockerfile:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "bot.py"]
```

2. **Build and run:**
```bash
docker build -t shieldbot .
docker run -d --name shieldbot --env-file .env shieldbot
```

### Option 3: Screen/tmux Session

```bash
# Using screen
screen -S shieldbot
./run.sh
# Ctrl+A then D to detach

# Reattach later
screen -r shieldbot

# Or using tmux
tmux new -s shieldbot
./run.sh
# Ctrl+B then D to detach
```

### Shared rate limits in Redis (opt-in)

By default every rate limiter counts in the API process's memory: a restart forgets the counts, and a second
API process would give each caller a second allowance. With `RATE_LIMIT_BACKEND=redis` the API counts in Redis
at `REDIS_URL` (default `redis://localhost:6379/0`), one count per caller shared by every API process. With the
setting unset or `memory`, nothing changes. Any other value stops the API at startup.

| Limiter | Limit | When Redis cannot answer |
|---|---|---|
| Every request without an API key (health checks aside), per IP | 30 a minute, 10 in 5 s | let through, error logged |
| RPC proxy `/rpc/{chain_id}` without a key, per IP | 100 a minute | let through, error logged |
| API key, per key | the key's per-minute limit | minute limit skipped, error logged; the daily quota (SQLite) still applies and refuses when it cannot be read |
| `/api/agent/chat` and `/api/agent/explain`, per IP | 50 a minute, 10 in 5 s | refused (429), error logged |
| `/api/report`, per IP | 5 a minute, 3 in 5 s | refused (429), error logged |
| `/api/beta-signup`, per IP | 3 a minute, 2 in 5 s | refused (429), error logged |
| `/api/keys/free`, per IP | 3 a minute, 2 in 5 s | refused (429), error logged |
| `/api/watch/alerts`, per IP | 10 a minute, 5 in 5 s | refused (429), error logged |

The general limiters let requests through so that a Redis outage does not take the scan API, or wallets that
use the RPC proxy, down. The others guard AI spend, email sending and writes, so they refuse. The client gives
Redis 0.5 seconds to connect or reply, so a Redis that hangs adds at most that to a request.

Each limiter keeps a sorted set per caller at `shieldbot:ratelimit:<limiter>:<caller>`, where the caller is the
client IP (prefixed with the route for some limiters) or the API key's id, never the key itself. Every check
renews the key's 60 second TTL, so an idle caller's key expires. The limiters write nothing else to Redis.

To turn it on:

1. Run Redis where only the API host can reach it (bound to 127.0.0.1, or a private network with a password in
   `REDIS_URL`).
2. Add `RATE_LIMIT_BACKEND=redis` and, if Redis is not on localhost, `REDIS_URL=redis://...` to
   `/opt/shieldbot/.env`.
3. Restart the API. Its log says `Rate limits kept in Redis`. After a few requests,
   `redis-cli --scan --pattern 'shieldbot:ratelimit:*'` lists the callers' keys.

To turn it off, remove the setting and restart the API.

---

## BNB Chain Deployment (For Onchain Proof)

### Deploy Verification Contract

ShieldBot needs an onchain component for hackathon submission:

1. **Create simple verification contract:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ShieldBotVerifier {
    event AddressScanned(address indexed scannedAddress, uint8 riskLevel, uint256 timestamp);
    
    function recordScan(address _address, uint8 _riskLevel) external {
        emit AddressScanned(_address, _riskLevel, block.timestamp);
    }
}
```

2. **Deploy using Remix:**
   - Go to [remix.ethereum.org](https://remix.ethereum.org)
   - Connect MetaMask to BSC or opBNB
   - Deploy the contract
   - Copy contract address

3. **Add to bot** (optional integration):
   - Create `contracts/verifier.py` to interact with the contract
   - Record scans onchain for transparency

---

## Configuration

### Environment Variables

```bash
# Required
TELEGRAM_BOT_TOKEN=your_bot_token

# Recommended
BSCSCAN_API_KEY=your_api_key

# Optional (defaults provided)
BSC_RPC_URL=https://bsc-dataseed1.binance.org/
OPBNB_RPC_URL=https://opbnb-mainnet-rpc.bnbchain.org
```

### Performance Tuning

For high traffic:
1. Add rate limiting
2. Use caching (Redis) for scanned addresses
3. Do not replicate the API while its verdict sender is embedded in each API process
4. Use webhook mode instead of polling

---

## Monitoring

### Health Check
```bash
curl http://localhost:8080/health  # If health endpoint added
```

### Logs
```bash
tail -f logs/shieldbot.log
```

### Metrics (Optional)
- Add Prometheus metrics
- Set up Grafana dashboard
- Monitor API rate limits

---

## Troubleshooting

### Bot doesn't respond
- Check bot token is correct
- Verify bot is running: `systemctl status shieldbot`
- Check logs for errors

### "Invalid API Key" errors
- Verify BscScan API key is active
- Check rate limits (5 calls/sec for free tier)
- Consider upgrading to paid tier for production

### Slow responses
- Check RPC endpoint health
- Use faster RPC (QuickNode, Alchemy, etc.)
- Add caching for repeated scans

---

## Security Best Practices

1. **Never commit `.env` to git**
2. **Use environment variables for secrets**
3. **Keep dependencies updated:** `pip install --upgrade -r requirements.txt`
4. **Monitor bot usage** for abuse
5. **Set rate limits** per user
6. **Use HTTPS** for webhooks (production)

---

## Hackathon Submission Checklist

- [ ] Bot running and tested
- [ ] Public GitHub repo with code
- [ ] README.md with demo instructions
- [x] Verification contract deployed on BSC (opBNB pending)
- [x] Contract source verified on BscScan
- [x] Contract address documented: https://bscscan.com/address/0x867aE7449af56BB56a4978c758d7E88066E1f795#code
- [x] Deployment tx documented: https://bscscan.com/tx/0x021fb404910c2621497bcda167ffcc70e8ece846d1ade8066ab5ad87f13b6bbd
- [ ] Demo video/screenshots prepared
- [ ] Submission on DoraHacks platform

---

## Support

- **GitHub Issues:** [Create an issue](https://github.com/Ridwannurudeen/shieldbot/issues)
- **Telegram:** @Ggudman
- **Discord:** Good Vibes Only #vibe-coding

---

Built for Good Vibes Only: OpenClaw Edition Hackathon 🛡️
