# ShieldBot Quick Start Guide

## ⚠️ Important: Deployment Location

ShieldBot **cannot run in the OpenClaw sandbox** because it requires Python packages (telegram-bot, web3.py, etc.) that need pip installation.

You need to deploy ShieldBot on:
- **Your local machine** (Windows/Mac/Linux)
- **A VPS** (DigitalOcean, AWS, Linode, etc.)
- **A Raspberry Pi**
- Any machine with Python 3.11+ and pip installed

---

## 🚀 Deployment Steps

### Option 1: Local Machine (Fastest for Testing)

#### On Linux/Mac:
```bash
# Clone the repo
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure .env
cat > .env << 'EOF'
TELEGRAM_BOT_TOKEN=8385839520:AAEJSBSBRZu0MFDyebvY6q5aEsLBGs6FIQ8
BSCSCAN_API_KEY=FTPU56HKYQHKMWXUX7ECE86CK44ZP7ZT8W
BSC_RPC_URL=https://bsc-dataseed1.binance.org/
OPBNB_RPC_URL=https://opbnb-mainnet-rpc.bnbchain.org
EOF

# Run the bot
python bot.py
```

#### On Windows:
```cmd
# Clone the repo
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create .env file manually or:
echo TELEGRAM_BOT_TOKEN=8385839520:AAEJSBSBRZu0MFDyebvY6q5aEsLBGs6FIQ8 > .env
echo BSCSCAN_API_KEY=FTPU56HKYQHKMWXUX7ECE86CK44ZP7ZT8W >> .env

# Run the bot
python bot.py
```

---

### Option 2: VPS (Best for 24/7 Operation)

#### Step 1: Create VPS
Use any provider:
- **DigitalOcean** ($6/month droplet)
- **Linode** ($5/month)
- **AWS Free Tier** (free for 12 months)
- **Vultr** ($5/month)

Choose: **Ubuntu 22.04 LTS**

#### Step 2: SSH into VPS
```bash
ssh root@your_vps_ip
```

#### Step 3: Install Dependencies
```bash
# Update system
apt update && apt upgrade -y

# Install Python and git
apt install -y python3 python3-pip python3-venv git

# Clone repo
cd /opt
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r requirements.txt
```

#### Step 4: Configure
```bash
# Create .env file
cat > .env << 'EOF'
TELEGRAM_BOT_TOKEN=8385839520:AAEJSBSBRZu0MFDyebvY6q5aEsLBGs6FIQ8
BSCSCAN_API_KEY=FTPU56HKYQHKMWXUX7ECE86CK44ZP7ZT8W
BSC_RPC_URL=https://bsc-dataseed1.binance.org/
OPBNB_RPC_URL=https://opbnb-mainnet-rpc.bnbchain.org
EOF
```

#### Step 5: Run as Service (24/7)
```bash
# Create systemd service
cat > /etc/systemd/system/shieldbot.service << 'EOF'
[Unit]
Description=ShieldBot - BNB Chain Security Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/shieldbot
Environment="PATH=/opt/shieldbot/venv/bin"
ExecStart=/opt/shieldbot/venv/bin/python bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable shieldbot
systemctl start shieldbot

# Check status
systemctl status shieldbot

# View logs
journalctl -u shieldbot -f
```

---

### Option 3: Docker (Cleanest)

```bash
# Clone repo
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "bot.py"]
EOF

# Create .env file with your tokens
echo "TELEGRAM_BOT_TOKEN=8385839520:AAEJSBSBRZu0MFDyebvY6q5aEsLBGs6FIQ8" > .env
echo "BSCSCAN_API_KEY=FTPU56HKYQHKMWXUX7ECE86CK44ZP7ZT8W" >> .env

# Build and run
docker build -t shieldbot .
docker run -d --name shieldbot --env-file .env --restart unless-stopped shieldbot

# View logs
docker logs -f shieldbot
```

---

## ✅ Testing the Bot

Once running, open Telegram and:

1. **Search for your bot** (the username you gave @BotFather)
2. **Send `/start`** - Should show welcome message
3. **Test safe contract:**
   ```
   /scan 0x10ED43C718714eb63d5aA57B78B54704E256024E
   ```
   Expected: LOW risk (PancakeSwap Router)

4. **Test safe token:**
   ```
   /token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
   ```
   Expected: SAFE (WBNB)

5. **Test auto-detection:**
   Just send an address without command:
   ```
   0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
   ```

---

## 🐛 Troubleshooting

### Bot doesn't respond
```bash
# Check if bot is running
systemctl status shieldbot  # VPS
# or
ps aux | grep bot.py        # Local

# Check logs for errors
journalctl -u shieldbot -n 50  # VPS
# or
cat logs/shieldbot.log         # Local (if logging enabled)
```

### "Invalid token" error
- Check .env file has correct TELEGRAM_BOT_TOKEN
- Verify token with @BotFather: `/mybots` → select bot → API Token

### "Connection refused" or RPC errors
- Check BSC_RPC_URL is accessible
- Try alternative RPC: `https://bsc-dataseed2.binance.org/`
- Or use QuickNode/Alchemy for faster RPC

### Rate limiting from BscScan
- Free tier: 5 calls/second
- Upgrade at https://bscscan.com/apis or add caching

---

## 📊 Monitoring

### Check bot status:
```bash
# VPS
systemctl status shieldbot
journalctl -u shieldbot -f

# Docker
docker logs -f shieldbot

# Local
# Just watch the terminal output
```

### Performance:
- Response time should be <5 seconds
- Memory usage: ~50-100MB
- CPU: Minimal (<5%)

---

## 🎥 Creating Demo for Hackathon

### Record your screen:
1. Open Telegram bot
2. Send `/start` - show welcome
3. Scan PancakeSwap: `/scan 0x10ED43C718714eb63d5aA57B78B54704E256024E`
4. Check WBNB: `/token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`
5. Show auto-detection by sending address directly
6. Show inline buttons (BscScan link, etc.)

### Tools for recording:
- **OBS Studio** (free, all platforms)
- **QuickTime** (Mac)
- **Xbox Game Bar** (Windows: Win+G)
- **Kazam** (Linux)

---

## 🏆 Hackathon Submission Checklist

Before submitting to DoraHacks:

- [ ] Bot running and tested ✅
- [ ] GitHub repo public: https://github.com/Ridwannurudeen/shieldbot ✅
- [ ] README.md complete ✅
- [ ] Demo video recorded
- [ ] Screenshots taken
- [ ] (Optional) Deploy verification contract for onchain proof
- [ ] Submission form filled on DoraHacks
- [ ] Submit before Feb 19, 2026, 3:00 PM UTC

---

## 💡 Pro Tips

1. **Keep bot running 24/7**: Use VPS + systemd or Docker
2. **Monitor logs**: Set up log rotation and monitoring
3. **Add caching**: Cache repeated scans to reduce API calls
4. **Upgrade APIs**: Consider paid BscScan tier for production
5. **Add analytics**: Track number of scans, popular tokens, etc.

---

## 🆘 Need Help?

- **Telegram:** @Ggudman
- **GitHub Issues:** https://github.com/Ridwannurudeen/shieldbot/issues
- **Discord:** Good Vibes Only #vibe-coding

---

**Your credentials are configured!** Just deploy to a machine with Python/pip and run it. 🛡️
