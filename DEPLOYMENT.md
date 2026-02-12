# ShieldBot Deployment Guide

## Prerequisites

1. **Python 3.9+**
2. **BSCScan API Key** - Get free at https://bscscan.com/apis
3. **Telegram Bot Token** - Create bot via @BotFather on Telegram

## Step 1: Environment Setup

```bash
# Clone repository
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Step 2: Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your credentials
nano .env  # or use any text editor
```

Required environment variables:
```
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
BSCSCAN_API_KEY=YOURAPIKEY123456789
```

## Step 3: Run Bot

```bash
# Make sure you're in the project directory
cd /path/to/shieldbot

# Activate virtual environment
source venv/bin/activate

# Run bot
python bot.py
```

You should see:
```
INFO:__main__:ShieldBot starting...
```

## Step 4: Test Bot

1. Open Telegram
2. Search for your bot (@YourBotName)
3. Send `/start`
4. Try analyzing a token:
   ```
   0x55d398326f99059fF775485246999027B3197955
   ```

## Production Deployment

### Option 1: VPS (Recommended for Hackathon)

```bash
# On your VPS (Ubuntu/Debian)
apt update
apt install python3 python3-pip git tmux -y

# Clone and setup
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot
pip3 install -r requirements.txt

# Configure .env
nano .env

# Run in tmux (persistent session)
tmux new -s shieldbot
python3 bot.py

# Detach: Ctrl+B then D
# Reattach: tmux attach -t shieldbot
```

### Option 2: Docker (Alternative)

```dockerfile
# Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "bot.py"]
```

```bash
# Build and run
docker build -t shieldbot .
docker run -d --env-file .env --name shieldbot shieldbot
```

### Option 3: Heroku (Free Tier)

```bash
# Install Heroku CLI, then:
heroku create shieldbot
heroku config:set TELEGRAM_BOT_TOKEN=your_token
heroku config:set BSCSCAN_API_KEY=your_key
git push heroku main
```

## Monitoring

```bash
# Check if bot is running
ps aux | grep bot.py

# View logs (if using tmux)
tmux attach -t shieldbot

# View logs (if using Docker)
docker logs -f shieldbot
```

## Troubleshooting

**Bot doesn't respond:**
- Check if bot.py is running
- Verify TELEGRAM_BOT_TOKEN in .env
- Check internet connection

**"BSCScan API error":**
- Verify BSCSCAN_API_KEY is correct
- Check API rate limits (free tier: 5 calls/sec)

**"Module not found":**
- Make sure virtual environment is activated
- Run: `pip install -r requirements.txt` again

## Stopping the Bot

```bash
# If using tmux
tmux attach -t shieldbot
# Then press Ctrl+C

# If using Docker
docker stop shieldbot

# If running directly
pkill -f bot.py
```

## Updating

```bash
cd shieldbot
git pull origin main
pip install -r requirements.txt  # in case deps changed
python bot.py
```

## For Hackathon Submission

1. **Demo Bot:** Keep running 24/7 during judging period
2. **GitHub:** Ensure repo is public and has clear README
3. **Video:** Record demo showing both modules working
4. **Onchain Proof:** Deploy a simple contract on BSC (for hackathon requirement)
