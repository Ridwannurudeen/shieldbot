#!/usr/bin/env python3
"""
ShieldBot - Your BNB Chain Shield
Telegram bot for pre-transaction scanning and token safety checks
Features: AI risk scoring, on-chain recording, caching, progress indicators
"""

import os
import time
import asyncio
import logging
from datetime import datetime, timezone
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)

from core.config import Settings
from core.container import ServiceContainer
from core.telegram_formatter import format_full_report

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Initialize container
settings = Settings()
container = ServiceContainer(settings)

# Convenience accessors
web3_client = container.web3_client
ai_analyzer = container.ai_analyzer
tx_scanner = container.tx_scanner
token_scanner = container.token_scanner
onchain_recorder = container.onchain_recorder
scam_db = container.scam_db
dex_service = container.dex_service
ethos_service = container.ethos_service
honeypot_service = container.honeypot_service
contract_service = container.contract_service
risk_engine = container.risk_engine

# In-memory scan cache (address -> {result, timestamp})
_scan_cache = {}
CACHE_TTL = 300  # 5 minutes


def _get_cached(address: str, scan_type: str):
    """Return cached result if fresh, else None."""
    key = f"{scan_type}:{address.lower()}"
    entry = _scan_cache.get(key)
    if entry and (time.time() - entry['timestamp']) < CACHE_TTL:
        logger.info(f"Cache hit for {key}")
        return entry['result']
    return None


def _set_cache(address: str, scan_type: str, result: dict):
    """Store result in cache."""
    key = f"{scan_type}:{address.lower()}"
    _scan_cache[key] = {'result': result, 'timestamp': time.time()}


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message with instructions"""
    welcome_text = """
🛡️ **Welcome to ShieldBot!**

Your AI-powered BNB Chain security assistant. I can help you:

**📡 Pre-Transaction Scan**
Send me a contract address or transaction data, and I'll check:
• Scam database matches
• Contract verification status
• AI-powered risk scoring
• Bytecode & source code analysis

**🔍 Token Safety Check**
Send me a token address, and I'll analyze:
• Honeypot detection
• Contract ownership
• Trading restrictions & taxes
• Liquidity lock verification

**📜 On-Chain History**
All scans are recorded on BNB Chain for transparency.

**How to use:**
Just send a BNB Chain address and I'll analyze it!

Commands:
/scan <address> - Scan a contract
/token <address> - Check token safety
/history <address> - View on-chain scan history
/report <address> <reason> - Report a scam
/help - Show this message
"""

    keyboard = [
        [InlineKeyboardButton("📖 GitHub", url="https://github.com/Ridwannurudeen/shieldbot")],
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
**/history <address>** - View on-chain scan history
**/report <address> <reason>** - Report a scam address
**/help** - Show this help message

**Quick Tips:**
• Send any BNB Chain address and I'll auto-detect what to scan
• Addresses starting with 0x are valid
• I support both BSC and opBNB networks
• All scans include AI-powered risk scoring

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


async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /history command - query on-chain scan records"""
    if not context.args:
        await update.message.reply_text(
            "❌ Please provide an address.\n\n"
            "Usage: `/history <address>`",
            parse_mode='Markdown'
        )
        return

    address = context.args[0]

    if not web3_client.is_valid_address(address):
        await update.message.reply_text("❌ Invalid address format.")
        return

    status_msg = await update.message.reply_text("📜 Querying on-chain scan history...")

    try:
        scan_data = await onchain_recorder.get_latest_scan(address)

        if not scan_data:
            await status_msg.edit_text(
                f"📜 **On-Chain History**\n\n"
                f"**Address:** `{address}`\n\n"
                f"No on-chain scan records found for this address.\n"
                f"Use `/scan` or `/token` to scan it first!",
                parse_mode='Markdown'
            )
            return

        # Format timestamp
        ts = scan_data.get('timestamp', 0)
        scan_time = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if ts > 0 else 'Unknown'

        risk_emoji = {'LOW': '🟢', 'MEDIUM': '🟡', 'HIGH': '🔴', 'SAFE': '✅', 'WARNING': '⚠️', 'DANGER': '🔴'}
        risk = scan_data.get('risk_level', 'UNKNOWN')
        emoji = risk_emoji.get(risk, '⚪')

        response = f"""📜 **On-Chain Scan History**

**Address:** `{address}`
**Last Scan:** {scan_time}
**Risk Level:** {emoji} {risk}
**Scan Type:** {scan_data.get('scan_type', 'unknown')}
**Total Scans:** {scan_data.get('scan_count', 0)}

🔗 [View on BscScan](https://bscscan.com/address/0x867aE7449af56BB56a4978c758d7E88066E1f795#events)
"""

        await status_msg.edit_text(response, parse_mode='Markdown', disable_web_page_preview=True)

    except Exception as e:
        logger.error(f"Error in /history: {e}")
        await status_msg.edit_text(f"❌ Error querying history: {str(e)}")


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /report command - community scam reporting"""
    if len(context.args) < 2:
        await update.message.reply_text(
            "❌ Please provide an address and reason.\n\n"
            "Usage: `/report <address> <reason>`\n"
            "Example: `/report 0x1234...5678 honeypot scam`",
            parse_mode='Markdown'
        )
        return

    address = context.args[0]
    reason = ' '.join(context.args[1:])

    if not web3_client.is_valid_address(address):
        await update.message.reply_text("❌ Invalid address format.")
        return

    # Add to local blacklist
    scam_db.add_to_blacklist(address)

    response = f"""✅ **Scam Report Submitted**

**Address:** `{address}`
**Reason:** {reason}
**Reporter:** User {update.effective_user.id}

This address has been added to our local blacklist.
Future scans will flag it as a known scam.
"""

    # Record on-chain (fire-and-forget — non-blocking)
    if onchain_recorder.is_available():
        await onchain_recorder.record_scan_fire_and_forget(address, 'high', 'report')
        response += "\n🔗 On-chain recording scheduled — [view contract](https://bscscan.com/address/0x867aE7449af56BB56a4978c758d7E88066E1f795#events)"

    await update.message.reply_text(response, parse_mode='Markdown', disable_web_page_preview=True)


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
            await status_msg.edit_text("🔍 Detected token contract — running safety checks...")
            await check_token(update, message_text)
        else:
            await status_msg.edit_text("🔍 Running security scan...")
            await scan_contract(update, message_text)
    else:
        await update.message.reply_text(
            "❌ Invalid address format. Please send a valid BNB Chain address (0x...)."
        )


async def scan_contract(update: Update, address: str):
    """Scan a contract for security risks with composite intelligence pipeline"""
    try:
        # Check cache first
        cached = _get_cached(address, 'contract')
        if cached:
            response = format_scan_result(cached)
            keyboard = _scan_buttons(address)
            await update.message.reply_text(response, parse_mode='Markdown', reply_markup=keyboard, disable_web_page_preview=True)
            return

        # Progress indicator
        progress_msg = await update.message.reply_text(
            "\U0001F6E1\uFE0F **Scanning contract...**\n\n"
            "\u23F3 Gathering intelligence from multiple sources...",
            parse_mode='Markdown'
        )

        # Try new composite pipeline first
        response = None
        risk_level = 'medium'
        try:
            from core.analyzer import AnalysisContext

            ctx = AnalysisContext(address=address, chain_id=56)
            analyzer_results, token_info = await asyncio.gather(
                container.registry.run_all(ctx),
                web3_client.get_token_info(address),
            )

            risk_output = risk_engine.compute_from_results(analyzer_results)

            # Extract service data for report formatting
            by_name = {r.name: r for r in analyzer_results}
            contract_data = by_name["structural"].data if "structural" in by_name else {}
            honeypot_data = by_name["honeypot"].data if "honeypot" in by_name else {}
            dex_data = by_name["market"].data if "market" in by_name else {}
            ethos_data = by_name["behavioral"].data if "behavioral" in by_name else {}

            # Generate AI forensic analysis
            ai_analysis = None
            if ai_analyzer and ai_analyzer.is_available():
                scan_data = {
                    'contract': contract_data,
                    'honeypot': honeypot_data,
                    'dex': dex_data,
                    'ethos': ethos_data,
                    'risk': risk_output,
                }
                ai_analysis = await ai_analyzer.generate_forensic_report(address, scan_data, 'contract')

            response = format_full_report(
                risk_output, contract_data, dex_data, ethos_data,
                honeypot_data=honeypot_data, address=address, ai_analysis=ai_analysis,
                token_info=token_info,
            )
            risk_level = risk_output.get('risk_level', 'medium').lower()

            # Cache the composite result
            _set_cache(address, 'contract', {'composite_report': response, 'risk_level': risk_level})

            # Enqueue deployer/funder indexing (fire-and-forget)
            if hasattr(container, 'indexer') and container.indexer:
                container.indexer.enqueue(address, 56)

        except Exception as e:
            logger.warning(f"Composite pipeline failed for {address}, falling back: {e}")

        # Fallback to legacy scanner
        if not response:
            result = await tx_scanner.scan_address(address)
            _set_cache(address, 'contract', result)
            response = format_scan_result(result)
            risk_level = result.get('risk_level', 'medium')

        keyboard = _scan_buttons(address)

        # Record on-chain (fire-and-forget — non-blocking)
        onchain_line = ""
        if onchain_recorder.is_available():
            await onchain_recorder.record_scan_fire_and_forget(address, risk_level, 'contract')
            onchain_line = "\n\U0001F517 On-chain recording scheduled\n"

        try:
            await progress_msg.delete()
        except Exception:
            pass

        await update.message.reply_text(
            response + onchain_line,
            parse_mode='Markdown',
            reply_markup=keyboard,
            disable_web_page_preview=True
        )

    except Exception as e:
        logger.error(f"Error scanning contract: {e}")
        await update.message.reply_text(
            f"\u274C Error scanning contract: {str(e)}\n\n"
            "Please check the address and try again."
        )


async def check_token(update: Update, address: str):
    """Check token safety with composite intelligence pipeline"""
    try:
        # Check cache first
        cached = _get_cached(address, 'token')
        if cached:
            response = format_token_result(cached)
            keyboard = _token_buttons(address)
            await update.message.reply_text(response, parse_mode='Markdown', reply_markup=keyboard, disable_web_page_preview=True)
            return

        # Progress indicator
        progress_msg = await update.message.reply_text(
            "\U0001F4B0 **Checking token safety...**\n\n"
            "\u23F3 Gathering intelligence from multiple sources...",
            parse_mode='Markdown'
        )

        # Try new composite pipeline first
        response = None
        risk_level = 'warning'
        try:
            from core.analyzer import AnalysisContext

            ctx = AnalysisContext(address=address, chain_id=56)
            analyzer_results, token_info = await asyncio.gather(
                container.registry.run_all(ctx),
                web3_client.get_token_info(address),
            )

            risk_output = risk_engine.compute_from_results(analyzer_results)

            by_name = {r.name: r for r in analyzer_results}
            contract_data = by_name["structural"].data if "structural" in by_name else {}
            honeypot_data = by_name["honeypot"].data if "honeypot" in by_name else {}
            dex_data = by_name["market"].data if "market" in by_name else {}
            ethos_data = by_name["behavioral"].data if "behavioral" in by_name else {}

            # Generate AI forensic analysis
            ai_analysis = None
            if ai_analyzer and ai_analyzer.is_available():
                scan_data = {
                    'contract': contract_data,
                    'honeypot': honeypot_data,
                    'dex': dex_data,
                    'ethos': ethos_data,
                    'risk': risk_output,
                }
                ai_analysis = await ai_analyzer.generate_forensic_report(address, scan_data, 'token')

            response = format_full_report(
                risk_output, contract_data, dex_data, ethos_data,
                honeypot_data=honeypot_data, address=address, ai_analysis=ai_analysis,
                token_info=token_info,
            )
            risk_level = risk_output.get('risk_level', 'medium').lower()

            _set_cache(address, 'token', {'composite_report': response, 'risk_level': risk_level})

            # Enqueue deployer/funder indexing (fire-and-forget)
            if hasattr(container, 'indexer') and container.indexer:
                container.indexer.enqueue(address, 56)

        except Exception as e:
            logger.warning(f"Composite pipeline failed for {address}, falling back: {e}")

        # Fallback to legacy scanner
        if not response:
            result = await token_scanner.check_token(address)
            _set_cache(address, 'token', result)
            response = format_token_result(result)
            risk_level = result.get('safety_level', 'warning')

        keyboard = _token_buttons(address)

        # Record on-chain (fire-and-forget — non-blocking)
        onchain_line = ""
        if onchain_recorder.is_available():
            await onchain_recorder.record_scan_fire_and_forget(address, risk_level, 'token')
            onchain_line = "\n\U0001F517 On-chain recording scheduled\n"

        try:
            await progress_msg.delete()
        except Exception:
            pass

        await update.message.reply_text(
            response + onchain_line,
            parse_mode='Markdown',
            reply_markup=keyboard,
            disable_web_page_preview=True
        )

    except Exception as e:
        logger.error(f"Error checking token: {e}")
        await update.message.reply_text(
            f"\u274C Error checking token: {str(e)}\n\n"
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


def _scan_buttons(address: str) -> InlineKeyboardMarkup:
    """Generate action buttons for scan results."""
    keyboard = [
        [InlineKeyboardButton("🔍 View on BscScan", url=f"https://bscscan.com/address/{address}")],
        [InlineKeyboardButton("💰 Check Token Safety", callback_data=f"token_{address}")]
    ]
    return InlineKeyboardMarkup(keyboard)


def _token_buttons(address: str) -> InlineKeyboardMarkup:
    """Generate action buttons for token results."""
    keyboard = [
        [InlineKeyboardButton("🔍 View on BscScan", url=f"https://bscscan.com/token/{address}")],
        [InlineKeyboardButton("📊 View on DexScreener", url=f"https://dexscreener.com/bsc/{address}")]
    ]
    return InlineKeyboardMarkup(keyboard)


def format_scan_result(result: dict) -> str:
    """Format scan result — use composite report, forensic report, or fallback"""
    if result.get('composite_report'):
        return result['composite_report']
    if result.get('forensic_report'):
        return result['forensic_report']

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
**Risk Score:** {result.get('risk_score', 'N/A')}/100 (Confidence: {result.get('confidence', 'N/A')}%)

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
        for match in result['scam_matches'][:3]:
            response += f"• {match['type']}: {match['reason']}\n"

    if result.get('warnings'):
        response += "\n**Warnings:**\n"
        for warning in result['warnings'][:5]:
            response += f"• {warning}\n"

    # AI structured risk score
    ai_risk = result.get('ai_risk_score')
    if ai_risk:
        response += f"\n🤖 **AI Risk Assessment:**\n"
        response += f"Score: {ai_risk.get('risk_score', 'N/A')}/100 | Level: {ai_risk.get('risk_level', 'N/A')}\n"
        findings = ai_risk.get('key_findings', [])
        for f in findings[:3]:
            response += f"• {f}\n"
        rec = ai_risk.get('recommendation', '')
        if rec:
            response += f"💡 {rec}\n"

    # Narrative AI analysis
    if result.get('ai_analysis'):
        response += f"\n🧠 **AI Analysis:**\n{result['ai_analysis'][:500]}\n"

    return response


def format_token_result(result: dict) -> str:
    """Format token result — use composite report, forensic report, or fallback"""
    if result.get('composite_report'):
        return result['composite_report']
    if result.get('forensic_report'):
        return result['forensic_report']

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
**Risk Score:** {result.get('risk_score', 'N/A')}/100 (Confidence: {result.get('confidence', 'N/A')}%)

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
        for risk in result['risks'][:6]:
            response += f"• {risk}\n"

    if result.get('buy_tax') or result.get('sell_tax'):
        response += f"\n**Taxes:**\n"
        response += f"Buy: {result.get('buy_tax', 0)}% | Sell: {result.get('sell_tax', 0)}%\n"

    # AI structured risk score
    ai_risk = result.get('ai_risk_score')
    if ai_risk:
        response += f"\n🤖 **AI Risk Assessment:**\n"
        response += f"Score: {ai_risk.get('risk_score', 'N/A')}/100 | Level: {ai_risk.get('risk_level', 'N/A')}\n"
        findings = ai_risk.get('key_findings', [])
        for f in findings[:3]:
            response += f"• {f}\n"
        rec = ai_risk.get('recommendation', '')
        if rec:
            response += f"💡 {rec}\n"

    # Narrative AI analysis
    if result.get('ai_analysis'):
        response += f"\n🧠 **AI Analysis:**\n{result['ai_analysis'][:500]}\n"

    return response


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Log errors"""
    logger.error(f"Update {update} caused error {context.error}")


def main():
    """Start the bot"""
    token = settings.telegram_bot_token
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN not found in environment variables!")
        return

    application = Application.builder().token(token).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("scan", scan_command))
    application.add_handler(CommandHandler("token", token_command))
    application.add_handler(CommandHandler("history", history_command))
    application.add_handler(CommandHandler("report", report_command))
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_address))

    # Add error handler
    application.add_error_handler(error_handler)

    # Start the bot
    logger.info("🛡️ ShieldBot starting...")
    logger.info(f"AI Analysis: {'enabled' if ai_analyzer.is_available() else 'disabled'}")
    logger.info(f"On-chain Recording: {'enabled' if onchain_recorder.is_available() else 'disabled'}")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
