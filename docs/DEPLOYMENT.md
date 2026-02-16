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
3. Set up load balancing
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
- [ ] Verification contract deployed on BSC/opBNB
- [ ] Contract address and tx hash documented
- [ ] Demo video/screenshots prepared
- [ ] Submission on DoraHacks platform

---

## Support

- **GitHub Issues:** [Create an issue](https://github.com/Ridwannurudeen/shieldbot/issues)
- **Telegram:** @Ggudman
- **Discord:** Good Vibes Only #vibe-coding

---

Built for Good Vibes Only: OpenClaw Edition Hackathon 🛡️
