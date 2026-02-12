"""
ShieldBot - Your BNB Chain Shield
Telegram bot for transaction and token security analysis
"""

import os
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Import our modules
from scanner.transaction import analyze_transaction
from scanner.token import analyze_token
from utils.risk_scorer import calculate_risk_score, format_risk_report

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a message when the command /start is issued."""
    welcome_message = (
        "🛡️ *ShieldBot - Your BNB Chain Shield*\n\n"
        "I protect you from scams, honeypots, and malicious transactions.\n\n"
        "*Features:*\n"
        "• Pre-transaction security analysis\n"
        "• Token safety checks (honeypot detection)\n"
        "• Contract verification\n"
        "• Known scam detection\n\n"
        "*How to use:*\n"
        "1. Send me a transaction hash\n"
        "2. Send me a token contract address\n"
        "3. I'll analyze and give you a security report\n\n"
        "*Commands:*\n"
        "/start - Show this message\n"
        "/help - Get help\n"
        "/stats - View bot statistics\n\n"
        "🔒 Stay safe on BNB Chain!"
    )
    await update.message.reply_text(welcome_message, parse_mode='Markdown')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a message when the command /help is issued."""
    help_text = (
        "🛡️ *ShieldBot Help*\n\n"
        "*Transaction Analysis:*\n"
        "Send me a transaction hash (0x...) and I'll check:\n"
        "• Contract verification status\n"
        "• Known scam addresses\n"
        "• Dangerous permissions\n"
        "• Risk score\n\n"
        "*Token Analysis:*\n"
        "Send me a token contract address (0x...) and I'll check:\n"
        "• Honeypot detection\n"
        "• Sell-ability\n"
        "• Hidden taxes\n"
        "• Liquidity locks\n\n"
        "*Risk Levels:*\n"
        "🟢 Low (0-30): Generally safe\n"
        "🟡 Medium (31-70): Proceed with caution\n"
        "🔴 High (71-100): Dangerous, avoid!\n\n"
        "Report issues: @Ridwannurudeen"
    )
    await update.message.reply_text(help_text, parse_mode='Markdown')

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show bot statistics."""
    stats_text = (
        "📊 *ShieldBot Statistics*\n\n"
        "• Total scans: Coming soon\n"
        "• Scams detected: Coming soon\n"
        "• Users protected: Coming soon\n\n"
        "🚀 Bot Version: 1.0.0 (Alpha)\n"
        "⛓️ Supported Chains: BSC, opBNB"
    )
    await update.message.reply_text(stats_text, parse_mode='Markdown')

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle incoming messages (addresses, transaction hashes, etc.)."""
    message_text = update.message.text.strip()
    
    # Check if it's an Ethereum-style address/hash (0x followed by 40 or 64 hex chars)
    if message_text.startswith('0x'):
        if len(message_text) == 42:
            # It's an address (could be token contract or wallet)
            await update.message.reply_text(
                "🔍 Analyzing token contract...\n"
                "⏳ This may take a few seconds...",
                parse_mode='Markdown'
            )
            # TODO: Call token analysis
            await update.message.reply_text(
                "⚠️ Token analysis coming soon!\n"
                "🚧 Module under development.",
                parse_mode='Markdown'
            )
        elif len(message_text) == 66:
            # It's a transaction hash
            await update.message.reply_text(
                "🔍 Analyzing transaction...\n"
                "⏳ This may take a few seconds...",
                parse_mode='Markdown'
            )
            # Analyze transaction
            result = await analyze_transaction(message_text, chain="BSC")
            
            if result.get("status") == "error":
                await update.message.reply_text(
                    f"❌ Error: {result.get('findings', [{}])[0].get('message', 'Unknown error')}",
                    parse_mode='Markdown'
                )
            else:
                # Format and send report
                report = format_risk_report(result)
                await update.message.reply_text(report, parse_mode='Markdown')
        else:
            await update.message.reply_text(
                "❌ Invalid address/hash format.\n\n"
                "Please send:\n"
                "• Token address (42 chars): 0x...\n"
                "• Transaction hash (66 chars): 0x...",
                parse_mode='Markdown'
            )
    else:
        await update.message.reply_text(
            "👋 Hi! Send me a token address or transaction hash to analyze.\n"
            "Use /help for more information.",
            parse_mode='Markdown'
        )

def main():
    """Start the bot."""
    # Get bot token from environment
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN not found in environment variables")
        return
    
    # Create the Application
    application = Application.builder().token(token).build()
    
    # Register command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("stats", stats_command))
    
    # Register message handler (for addresses and transaction hashes)
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Start the Bot
    logger.info("ShieldBot starting...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
