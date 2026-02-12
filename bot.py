#!/usr/bin/env python3
"""
ShieldBot - Your BNB Chain Shield
Telegram bot for pre-transaction scanning and token safety checks
"""

import os
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)
from dotenv import load_dotenv

from scanner.transaction_scanner import TransactionScanner
from scanner.token_scanner import TokenScanner
from utils.web3_client import Web3Client

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Initialize scanners
web3_client = Web3Client()
tx_scanner = TransactionScanner(web3_client)
token_scanner = TokenScanner(web3_client)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message with instructions"""
    welcome_text = """
🛡️ **Welcome to ShieldBot!**

Your BNB Chain security assistant. I can help you:

**📡 Pre-Transaction Scan**
Send me a contract address or transaction data, and I'll check:
• Scam database matches
• Contract verification status
• Security risks
• Recent similar scams

**🔍 Token Safety Check**
Send me a token address, and I'll analyze:
• Honeypot detection
• Contract ownership
• Trading restrictions
• Liquidity locks

**How to use:**
Just send a BNB Chain address (contract or token) and I'll analyze it!

You can also use:
/scan <address> - Scan a contract
/token <address> - Check token safety
/help - Show this message
"""
    
    keyboard = [
        [InlineKeyboardButton("📖 Learn More", url="https://github.com/Ridwannurudeen/shieldbot")],
        [InlineKeyboardButton("🔗 BNB Chain", url="https://www.bnbchain.org/")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(welcome_text, parse_mode='Markdown', reply_markup=reply_markup)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show help message"""
    help_text = """
🛡️ **ShieldBot Commands**

**/start** - Show welcome message
**/scan <address>** - Scan a contract for security risks
**/token <address>** - Check if a token is safe to trade
**/help** - Show this help message

**Quick Tips:**
• Send any BNB Chain address and I'll auto-detect what to scan
• Addresses starting with 0x are valid
• I support both BSC and opBNB networks

Stay safe! 🛡️
"""
    await update.message.reply_text(help_text, parse_mode='Markdown')


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /scan command"""
    if not context.args:
        await update.message.reply_text(
            "❌ Please provide an address to scan.\n\n"
            "Usage: `/scan <address>`",
            parse_mode='Markdown'
        )
        return
    
    address = context.args[0]
    await scan_contract(update, address)


async def token_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /token command"""
    if not context.args:
        await update.message.reply_text(
            "❌ Please provide a token address.\n\n"
            "Usage: `/token <address>`",
            parse_mode='Markdown'
        )
        return
    
    address = context.args[0]
    await check_token(update, address)


async def handle_address(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Auto-detect and handle addresses sent in messages"""
    message_text = update.message.text.strip()
    
    # Check if it looks like an Ethereum address
    if message_text.startswith('0x') and len(message_text) == 42:
        # Show scanning message
        status_msg = await update.message.reply_text("🔍 Analyzing address...")
        
        # Check if it's a token contract
        is_token = await web3_client.is_token_contract(message_text)
        
        if is_token:
            await status_msg.edit_text("🔍 Detected token contract - running safety checks...")
            await check_token(update, message_text)
        else:
            await status_msg.edit_text("🔍 Running security scan...")
            await scan_contract(update, message_text)
    else:
        await update.message.reply_text(
            "❌ Invalid address format. Please send a valid BNB Chain address (0x...)."
        )


async def scan_contract(update: Update, address: str):
    """Scan a contract for security risks"""
    try:
        # Run the scan
        result = await tx_scanner.scan_address(address)
        
        # Format the response
        response = format_scan_result(result)
        
        # Add action buttons
        keyboard = [
            [InlineKeyboardButton("🔍 View on BscScan", url=f"https://bscscan.com/address/{address}")],
            [InlineKeyboardButton("💰 Check Token Safety", callback_data=f"token_{address}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(response, parse_mode='Markdown', reply_markup=reply_markup)
    
    except Exception as e:
        logger.error(f"Error scanning contract: {e}")
        await update.message.reply_text(
            f"❌ Error scanning contract: {str(e)}\n\n"
            "Please check the address and try again."
        )


async def check_token(update: Update, address: str):
    """Check token safety"""
    try:
        # Run token safety checks
        result = await token_scanner.check_token(address)
        
        # Format the response
        response = format_token_result(result)
        
        # Add action buttons
        keyboard = [
            [InlineKeyboardButton("🔍 View on BscScan", url=f"https://bscscan.com/token/{address}")],
            [InlineKeyboardButton("📊 View on DexScreener", url=f"https://dexscreener.com/bsc/{address}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(response, parse_mode='Markdown', reply_markup=reply_markup)
    
    except Exception as e:
        logger.error(f"Error checking token: {e}")
        await update.message.reply_text(
            f"❌ Error checking token: {str(e)}\n\n"
            "Please check the address and try again."
        )


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button callbacks"""
    query = update.callback_query
    await query.answer()
    
    if query.data.startswith('token_'):
        address = query.data.replace('token_', '')
        await query.message.reply_text(f"🔍 Running token safety check for `{address}`...", parse_mode='Markdown')
        await check_token(query, address)


def format_scan_result(result: dict) -> str:
    """Format scan result as a readable message"""
    risk_emoji = {
        'high': '🔴',
        'medium': '🟡',
        'low': '🟢',
        'none': '✅'
    }
    
    risk_level = result.get('risk_level', 'unknown')
    emoji = risk_emoji.get(risk_level, '⚪')
    
    response = f"""
🛡️ **Security Scan Report**

**Address:** `{result['address']}`
**Risk Level:** {emoji} {risk_level.upper()}

**Verification Status:**
{'✅' if result['is_verified'] else '❌'} Contract {'verified' if result['is_verified'] else 'not verified'} on BscScan

**Security Checks:**
"""
    
    for check, status in result.get('checks', {}).items():
        status_icon = '✅' if status else '❌'
        check_name = check.replace('_', ' ').title()
        response += f"{status_icon} {check_name}\n"
    
    if result.get('scam_matches'):
        response += f"\n⚠️ **Warning:** Found {len(result['scam_matches'])} scam database match(es)\n"
        for match in result['scam_matches'][:3]:  # Show first 3
            response += f"• {match['type']}: {match['reason']}\n"
    
    if result.get('warnings'):
        response += "\n**Warnings:**\n"
        for warning in result['warnings']:
            response += f"• {warning}\n"
    
    return response


def format_token_result(result: dict) -> str:
    """Format token result as a readable message"""
    safety_emoji = {
        'safe': '✅',
        'warning': '⚠️',
        'danger': '🔴',
        'unknown': '⚪'
    }
    
    safety_level = result.get('safety_level', 'unknown')
    emoji = safety_emoji.get(safety_level, '⚪')
    
    response = f"""
💰 **Token Safety Report**

**Token:** {result.get('name', 'Unknown')} ({result.get('symbol', 'N/A')})
**Address:** `{result['address']}`
**Safety:** {emoji} {safety_level.upper()}

**Honeypot Check:**
{'✅ Not a honeypot' if not result.get('is_honeypot') else '🔴 HONEYPOT DETECTED'}

**Contract Analysis:**
"""
    
    checks = result.get('checks', {})
    response += f"{'✅' if checks.get('can_buy') else '❌'} Can Buy\n"
    response += f"{'✅' if checks.get('can_sell') else '❌'} Can Sell\n"
    response += f"{'✅' if checks.get('ownership_renounced') else '❌'} Ownership Renounced\n"
    response += f"{'✅' if checks.get('liquidity_locked') else '❌'} Liquidity Locked\n"
    
    if result.get('risks'):
        response += "\n**Risks Detected:**\n"
        for risk in result['risks']:
            response += f"• {risk}\n"
    
    if result.get('buy_tax') or result.get('sell_tax'):
        response += f"\n**Taxes:**\n"
        response += f"Buy: {result.get('buy_tax', 0)}% | Sell: {result.get('sell_tax', 0)}%\n"
    
    return response


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Log errors"""
    logger.error(f"Update {update} caused error {context.error}")


def main():
    """Start the bot"""
    # Get bot token from environment
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN not found in environment variables!")
        return
    
    # Create application
    application = Application.builder().token(token).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("scan", scan_command))
    application.add_handler(CommandHandler("token", token_command))
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_address))
    
    # Add error handler
    application.add_error_handler(error_handler)
    
    # Start the bot
    logger.info("🛡️ ShieldBot starting...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
