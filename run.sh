#!/bin/bash
# ShieldBot Run Script

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "❌ Virtual environment not found. Run ./setup.sh first"
    exit 1
fi

# Check .env exists
if [ ! -f .env ]; then
    echo "❌ .env file not found. Copy .env.example and configure it"
    exit 1
fi

# Run the bot
echo "🛡️ Starting ShieldBot..."
python bot.py
