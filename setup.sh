#!/bin/bash
# ShieldBot Setup Script

echo "🛡️ ShieldBot Setup"
echo "=================="

# Check Python version
python_version=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
echo "✅ Python version: $python_version"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Check for .env file
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from template..."
    cp .env.example .env
    echo "📝 Please edit .env with your actual tokens and API keys:"
    echo "   - TELEGRAM_BOT_TOKEN (required)"
    echo "   - BSCSCAN_API_KEY (recommended)"
    echo "   - RPC URLs (optional, defaults provided)"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env with your configuration"
echo "2. Run: source venv/bin/activate"
echo "3. Run: python bot.py"
echo ""
echo "🛡️ Happy scanning!"
