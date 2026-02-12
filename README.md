# ShieldBot 🛡️

**Your BNB Chain Shield**

ShieldBot is an AI-powered security agent that protects BNB Chain users from scams, honeypots, and malicious transactions before they happen.

## Hackathon Entry
- **Event:** Good Vibes Only: OpenClaw Edition
- **Track:** Agent (AI Agent × Onchain Actions)
- **Chain:** BSC / opBNB
- **Submission Deadline:** Feb 19, 2026

## Features

### Module 1: Pre-Transaction Scanner
- Analyzes transactions before signing
- Verifies contract authenticity
- Detects known scam addresses
- Checks dangerous permissions (unlimited approvals, etc.)
- Real-time risk assessment

### Module 2: Token Safety Check
- Honeypot detection
- Sell-ability verification
- Hidden tax detection
- Blacklist function identification
- Liquidity lock verification

## Tech Stack
- **Bot Framework:** Python + Telegram Bot API
- **Blockchain:** Web3.py (BSC/opBNB)
- **APIs:** BSCScan API, Token analysis services
- **AI:** Pattern detection + risk scoring
- **Database:** Local cache for known scams

## Quick Start

```bash
# Clone repo
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot

# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your API keys

# Run bot
python bot.py
```

## Environment Variables

```
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
BSCSCAN_API_KEY=your_bscscan_api_key
RPC_URL=https://bsc-dataseed.binance.org/
```

## Usage

1. Start bot: `/start`
2. Paste transaction data or token address
3. ShieldBot analyzes and returns security report
4. Decide to proceed or cancel based on risk score

## Demo

[Video Demo Link - Coming Soon]

## Onchain Proof

- **Contract Address:** TBA (deployed on BSC)
- **Transaction Hash:** TBA

## Repository Structure

```
shieldbot/
├── bot.py                  # Main Telegram bot
├── scanner/
│   ├── transaction.py      # Transaction analysis
│   ├── token.py           # Token safety checks
│   ├── contracts.py       # Contract verification
│   └── database.py        # Known scam database
├── utils/
│   ├── web3_client.py     # Web3 connection
│   └── risk_scorer.py     # Risk calculation
├── requirements.txt       # Python dependencies
├── .env.example          # Environment template
└── README.md             # This file
```

## AI Build Log

This project leverages AI assistance via OpenClaw/Claude for:
- Code generation and debugging
- Smart contract analysis patterns
- Risk scoring algorithms
- Documentation and testing

## Team

- **Builder:** Ridwan Nurudeen (@Ridwannurudeen)
- **AI Assistant:** Claude/OpenClaw

## License

MIT

## Disclaimer

ShieldBot is a security tool for educational and informational purposes. Always verify transactions independently. No security tool is 100% foolproof. Use at your own risk.
