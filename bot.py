#!/usr/bin/env python3
"""
ShieldBot Telegram bot
Pre-transaction scanning and token safety checks on every supported chain
Features: AI risk scoring, on-chain recording, caching, progress indicators
"""

import os
import sys
import time
import asyncio
import logging
import traceback

import aiohttp

try:
    from telegram import Chat, ChatMember, Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.error import BadRequest, ChatMigrated, Forbidden, NetworkError, RetryAfter, TelegramError
    from telegram.ext import (
        Application,
        CommandHandler,
        MessageHandler,
        CallbackQueryHandler,
        ContextTypes,
        filters,
    )
except ImportError:
    print("ERROR: python-telegram-bot is not installed. Run: pip install python-telegram-bot==20.7")
    sys.exit(1)

from core.config import Settings
from core.container import ServiceContainer
from core.telegram_formatter import (
    describe_impostor_check, escape_markdown, escape_markdown_lines, format_full_report, unlinked,
)
from core.extension_formatter import is_scan_incomplete
from core.registry import RUN_ALL_DEADLINE_SECONDS
from core.risk_engine import database_matches, medium_matches
from core.verdicts import UNKNOWN
from services.launch_discovery import CHAIN_ID as LAUNCH_CHAIN_ID
from services.robinhood_assets import with_impostor_check
from services.mempool_service import supports_pending_transactions
from utils.web3_client import UnsupportedChainError
from utils.scam_db import BLACKLIST_RELOAD_SECONDS
from utils.chain_info import (
    get_chain_name, get_explorer_url, get_dexscreener_slug,
    parse_chain_prefix,
)

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logging.getLogger("httpx").setLevel(logging.WARNING)
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
base_attestor = container.base_attestor
scam_db = container.scam_db
dex_service = container.dex_service
ethos_service = container.ethos_service
honeypot_service = container.honeypot_service
contract_service = container.contract_service
risk_engine = container.risk_engine

# In-memory scan cache (address -> {result, timestamp})
_scan_cache = {}
CACHE_TTL = 300  # 5 minutes

# /threats reads the API's mempool monitor. Every bot request reaches the API from one address and
# so shares one IP rate-limit bucket there; a busy chat reuses a snapshot instead of using it up.
MEMPOOL_CACHE_SECONDS = 15
# ('alerts', chain filter or None) or 'stats' -> (fetched_at, response body). Stats do not depend on
# the chain filter, so one read serves every filter.
_mempool_cache = {}

# Robinhood Chain launch alerts. The API's hunter records launch outcomes in the shared
# database; this process queues alerts for subscribed chats there and sends them.
LAUNCH_ALERT_POLL_SECONDS = 30
# Telegram allows about 20 messages a minute to a group and 30 a second in all, so a pass sends
# at most 3 alerts to a chat and 30 in all: 6 a minute per chat and 60 a minute in all.
LAUNCH_ALERTS_PER_CHAT_PER_PASS = 3
LAUNCH_ALERTS_PER_PASS = 30
# A launch alert only helps near launch time, so an older one expires instead of queueing up.
LAUNCH_ALERT_MAX_AGE_SECONDS = 3600
# The hunter stamps an outcome just before committing it, so each pass rereads the minute
# before the last one; the outbox never queues an alert twice.
LAUNCH_ALERT_OVERLAP_SECONDS = 60
VERDICT_BASE_URL = "https://api.shieldbotsecurity.online"
_LAUNCH_ALERT_HEADERS = {
    'blocked': '🔴 BLOCKED: high-risk Robinhood Chain launch',
    'watching': '🟡 WATCHING: medium-risk Robinhood Chain launch',
    'cleared': '🟢 CLEARED: a complete scan found no major risks',
}
_UNKNOWN_LAUNCH_HEADER = '⚪ UNKNOWN: scan incomplete, not a safety verdict'
_IMPOSTOR_LAUNCH_HEADER = '🚨 IMPOSTOR: {}'
_COLLISION_LAUNCH_HEADER = '⚠️ NOT OFFICIAL: shares a ticker or name with an official Robinhood token'
_launch_alert_task = None
_blacklist_reload_task = None


def _get_user_chain_id(context: ContextTypes.DEFAULT_TYPE) -> int:
    """Get the user's selected chain_id, default BSC (56)."""
    return web3_client.validate_chain_id(context.user_data.get('chain_id', 56))


def _get_cached(address: str, scan_type: str):
    """Return cached result if fresh, else None."""
    key = f"{scan_type}:{address.lower()}"
    entry = _scan_cache.get(key)
    if entry and (time.time() - entry['timestamp']) < CACHE_TTL:
        if not entry['result'].get('coverage') or entry['result'].get('status') not in ('ok', 'unknown'):
            return None
        logger.info(f"Cache hit for {key}")
        return entry['result']
    return None


def _set_cache(address: str, scan_type: str, result: dict):
    """Store result in cache."""
    key = f"{scan_type}:{address.lower()}"
    _scan_cache[key] = {'result': result, 'timestamp': time.time()}


async def post_init(application):
    """Initialize services, register bot command menu, and start launch alert delivery and the
    blacklist reload."""
    global _launch_alert_task, _blacklist_reload_task
    await container.startup()
    await application.bot.set_my_commands([
        ("start", "Welcome message & quick start"),
        ("scan", "Scan a contract for risks"),
        ("token", "Check if a token is safe"),
        ("chain", "Switch active chain"),
        ("rescue", "Scan wallet for risky approvals"),
        ("threats", "Live mempool threat alerts"),
        ("campaign", "Check if address is part of scam campaign"),
        ("report", "Report a scam address"),
        ("launchalerts", "Robinhood Chain launch alerts"),
        ("stopalerts", "Stop launch alerts"),
        ("help", "Show all commands"),
    ])
    _launch_alert_task = asyncio.create_task(launch_alert_loop(application.bot))
    _blacklist_reload_task = asyncio.create_task(blacklist_reload_loop())


async def post_stop(application):
    """Stop launch alert delivery and the blacklist reload before the bot and its services shut down."""
    for task in (_launch_alert_task, _blacklist_reload_task):
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


async def post_shutdown(application):
    """Clean up services on bot shutdown."""
    await container.shutdown()


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message with instructions"""
    welcome_text = """
🛡️ **Welcome to ShieldBot!**

I check contracts and tokens before you sign, and I say what I checked. When data is missing I answer Unknown instead of guessing Safe. I build on GoPlus, honeypot.is and others; I do not replace them.

I can help you:

**📡 Pre-Transaction Scan**
Send me a contract address or transaction data, and I'll check:
• Scam database matches
• Contract verification status
• Risk scoring that names any check it could not run
• Bytecode & source code analysis

**🔍 Token Safety Check**
Send me a token address, and I'll analyze:
• Honeypot detection
• Contract ownership
• Trading restrictions & taxes
• Liquidity lock verification

**🚨 Advanced Security**
• Rescue mode — find risky token approvals in your wallet
• Mempool threats — live sandwich & frontrun detection
• Campaign radar — link addresses to coordinated scam campaigns

**How to use:**
Send any address and I'll auto-detect what to scan!
Use chain prefixes: `eth:0x...`, `base:0x...`, `bsc:0x...`, `opbnb:0x...`, `arb:0x...`, `poly:0x...`, `op:0x...`, `rh:0x...`, `robinhood:0x...`

Commands:
/scan — Scan a contract
/token — Check token safety
/chain — Switch active chain
/rescue — Scan wallet for risky approvals
/threats — Live mempool threat alerts
/campaign — Check scam campaign links
/report — Report a scam address
/launchalerts — Robinhood Chain launch alerts
/stopalerts — Stop launch alerts
/help — Show all commands
"""

    keyboard = [
        [InlineKeyboardButton("📖 GitHub", url="https://github.com/Ridwannurudeen/shieldbot")],
        [InlineKeyboardButton("🌐 Website", url="https://shieldbotsecurity.online")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(welcome_text, parse_mode='Markdown', reply_markup=reply_markup)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show help message"""
    supported_chains = ", ".join(get_chain_name(cid) for cid in web3_client.get_supported_chain_ids())
    help_text = f"""
🛡️ **ShieldBot Commands**

**/start** - Welcome message & quick start
**/scan <address>** - Scan a contract for security risks
**/token <address>** - Check if a token is safe to trade
**/chain** - Switch active chain
**/rescue <wallet>** - Scan wallet for risky token approvals
**/threats** - Live mempool threat alerts
**/campaign <address>** - Check if address is part of a scam campaign
**/report <address> <reason>** - Report a scam address
**/launchalerts** - Alert this chat to blocked Robinhood Chain launches and impostors of official tokens (`/launchalerts all` for every launch)
**/stopalerts** - Stop launch alerts
**/help** - Show this help message

**Quick Tips:**
• Send any address and I'll auto-detect what to scan
• Use chain prefixes: `eth:0x...`, `base:0x...`, `bsc:0x...`, `opbnb:0x...`, `arb:0x...`, `poly:0x...`, `op:0x...`, `rh:0x...`, `robinhood:0x...`
• Or use /chain to switch your default chain
• Supported: {supported_chains}

Stay safe! 🛡️
"""
    await update.message.reply_text(help_text, parse_mode='Markdown')


async def chain_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /chain command — select active chain."""
    if context.args:
        selection = context.args[0]
        try:
            chain_id = int(selection)
        except ValueError:
            chain_id, _ = parse_chain_prefix(selection + ':0x')
        try:
            web3_client.validate_chain_id(chain_id)
        except ValueError:
            await update.message.reply_text(
                f"Unsupported chain selection. Supported: {web3_client.get_supported_chain_ids()}",
            )
            return
        context.user_data['chain_id'] = chain_id
        await update.message.reply_text(
            f"Switched to {get_chain_name(chain_id)} (chain_id={chain_id}).",
        )
        return

    try:
        current = _get_user_chain_id(context)
    except UnsupportedChainError:
        current = None
    keyboard = []
    for cid in web3_client.get_supported_chain_ids():
        marker = " (current)" if cid == current else ""
        keyboard.append([InlineKeyboardButton(
            f"{get_chain_name(cid)}{marker}",
            callback_data=f"chain_{cid}",
        )])

    await update.message.reply_text(
        "Select the chain to scan on:\n\n"
        "You can also use chain prefixes like `eth:0x...` or `base:0x...`",
        parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup(keyboard),
    )


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /scan command"""
    if not context.args:
        await update.message.reply_text(
            "❌ Please provide an address to scan.\n\n"
            "Usage: `/scan <address>`\n"
            "Tip: Use chain prefixes like `/scan eth:0x...` or `/scan base:0x...`",
            parse_mode='Markdown'
        )
        return

    raw = context.args[0]
    prefix_chain_id, address = parse_chain_prefix(raw)
    chain_id = web3_client.validate_chain_id(prefix_chain_id or _get_user_chain_id(context))
    if not web3_client.is_valid_address(address):
        await update.message.reply_text("❌ Invalid address format.")
        return
    await scan_contract(update, address, chain_id=chain_id)


async def token_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /token command"""
    if not context.args:
        await update.message.reply_text(
            "❌ Please provide a token address.\n\n"
            "Usage: `/token <address>`\n"
            "Tip: Use chain prefixes like `/token eth:0x...` or `/token base:0x...`",
            parse_mode='Markdown'
        )
        return

    raw = context.args[0]
    prefix_chain_id, address = parse_chain_prefix(raw)
    chain_id = web3_client.validate_chain_id(prefix_chain_id or _get_user_chain_id(context))
    if not web3_client.is_valid_address(address):
        await update.message.reply_text("❌ Invalid address format.")
        return
    await check_token(update, address, chain_id=chain_id)


async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /history command - on-chain scan history is not available"""
    # Still registered so chats with a cached command menu get a plain answer instead of silence.
    await update.message.reply_text(
        "On-chain scan history is not available. Use /scan or /token to check an address."
    )


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /report command - community scam reporting"""
    if len(context.args) < 2:
        await update.message.reply_text(
            "❌ Please provide an address and reason.\n\n"
            "Usage: `/report <address> <reason>`\n"
            "Example: `/report 0x1234...5678 honeypot scam`\n"
            "Tip: Use chain prefixes like `/report eth:0x... <reason>`; without one the report is for your current chain.",
            parse_mode='Markdown'
        )
        return

    # The report is for the chain a /scan of the same text would check.
    prefix_chain_id, address = parse_chain_prefix(context.args[0])
    chain_id = web3_client.validate_chain_id(prefix_chain_id or _get_user_chain_id(context))
    reason = ' '.join(context.args[1:])

    if not web3_client.is_valid_address(address):
        await update.message.reply_text("❌ Invalid address format.")
        return

    # Community report with safeguards
    result = await scam_db.report_address(address, str(update.effective_user.id), chain_id)

    if not result["accepted"]:
        await update.message.reply_text(f"❌ {result['reason']}")
        return

    # A report writes nothing on chain: three accounts can manufacture a blacklisting.
    if result["blacklisted"]:
        if result.get("confirmed"):
            status = "This address is confirmed as a scam."
        elif result.get("already_listed"):
            status = (
                f"This address is already reported by {result['reports']} users in scans. "
                "It is not confirmed as a scam."
            )
        else:
            status = (
                f"This address now shows as reported by {result['reports']} users in scans. "
                "It is not confirmed as a scam."
            )
        response = f"""✅ **Scam Report — Address Blacklisted**

**Address:** `{address}`
**Chain:** {get_chain_name(chain_id)}
**Reason:** {escape_markdown(reason)}
**Reporter:** User {update.effective_user.id}

{status}
"""
    else:
        response = f"""📝 **Report Recorded**

**Address:** `{address}`
**Chain:** {get_chain_name(chain_id)}
**Reason:** {escape_markdown(reason)}
**Progress:** {result['reports']}/{result['needed']} independent reports needed to blacklist.

Thank you — more reports from different users are needed before this address is blacklisted.
"""

    await update.message.reply_text(response, parse_mode='Markdown', disable_web_page_preview=True)


async def rescue_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /rescue command — scan wallet for risky token approvals."""
    if not context.args:
        await update.message.reply_text(
            "❌ Please provide a wallet address.\n\n"
            "Usage: `/rescue <wallet_address>`\n"
            "Scans for risky token approvals on your current chain.",
            parse_mode='Markdown',
        )
        return

    raw = context.args[0]
    prefix_chain_id, address = parse_chain_prefix(raw)
    chain_id = web3_client.validate_chain_id(prefix_chain_id or _get_user_chain_id(context))

    if not web3_client.is_valid_address(address):
        await update.message.reply_text("❌ Invalid address format.")
        return

    chain_name = get_chain_name(chain_id)
    status_msg = await update.message.reply_text(
        f"🚨 **Scanning approvals on {chain_name}...**\n\n"
        "⏳ Checking token allowances for risky spenders...",
        parse_mode='Markdown',
    )

    try:
        # Pick the best API key for the target chain
        api_key = settings.bscscan_api_key
        if chain_id == 1:
            api_key = settings.etherscan_api_key or api_key

        result = await container.rescue_service.scan_approvals(
            address, chain_id=chain_id, etherscan_api_key=api_key,
        )

        total = result.get('total_approvals', 0)
        high = result.get('high_risk', 0)
        medium = result.get('medium_risk', 0)
        lower_risk = total - high - medium
        incomplete = is_scan_incomplete(result)

        response = f"🚨 **Rescue Mode — Approval Scan**\n\n"
        response += f"**Wallet:** `{address}`\n"
        response += f"**Chain:** {chain_name}\n"
        response += f"**Total Approvals:** {total}\n"
        if incomplete:
            reasons = '; '.join(dict.fromkeys(result.get('coverage_reasons', {}).values())) or 'Approval data unavailable'
            response += f"🔴 High Risk: {high} | 🟡 Medium: {medium} | ⚪ Unconfirmed: {lower_risk}\n"
            response += f"⚠️ **Scan incomplete:** {escape_markdown(reasons)}\n"
        else:
            response += f"🔴 High Risk: {high} | 🟡 Medium: {medium} | Lower risk: {lower_risk}\n"

        response += (
            "\n**Scope:** ERC-20 allowances found in the queried approval history; "
            "risk labels use approval amounts and known-spender labels. "
            "This does not audit spender contracts, NFT approvals, or off-chain signatures.\n"
        )

        # Show risky approvals
        approvals = result.get('approvals', [])
        risky = [a for a in approvals if a.get('risk_level') in ('HIGH', 'MEDIUM')]
        if risky:
            response += "\n**Risky Approvals:**\n"
            for a in risky[:10]:
                risk_icon = '🔴' if a['risk_level'] == 'HIGH' else '🟡'
                symbol = a.get('token_symbol', '???')
                spender_label = a.get('spender_label') or a.get('spender', '')[:10] + '...'
                response += f"{risk_icon} {escape_markdown(symbol)} → {escape_markdown(spender_label)}"
                if a.get('risk_reason'):
                    response += f" — {escape_markdown(a['risk_reason'])}"
                response += "\n"

        # Show alerts
        alerts = result.get('alerts', [])
        if alerts:
            response += "\n**Alerts:**\n"
            for alert in alerts[:5]:
                response += f"⚠️ **{escape_markdown(alert.get('title', 'Alert'))}**\n"
                response += f"  {escape_markdown(alert.get('description', ''))}\n"
                if alert.get('what_you_can_do'):
                    response += f"  💡 {escape_markdown(alert['what_you_can_do'])}\n"

        # Revoke instructions
        revoke_txs = result.get('revoke_txs', [])
        if revoke_txs:
            response += f"\n**Revoke Instructions:**\n"
            response += f"Found {len(revoke_txs)} approval(s) flagged for revocation review.\n"
            response += (
                "This bot has not revoked any approvals or submitted transactions. "
                "Review the token, spender and chain in your wallet or "
                "[Revoke.cash](https://revoke.cash/), then sign and submit any revocation yourself.\n"
            )
        elif total > 0 and high == 0 and medium == 0 and not incomplete:
            response += "\nNo high- or medium-risk approvals found among the approvals checked.\n"

        try:
            await status_msg.delete()
        except Exception:
            pass

        await update.message.reply_text(
            response, parse_mode='Markdown', disable_web_page_preview=True,
        )

    except UnsupportedChainError:
        raise
    except Exception as e:
        logger.error(f"Error in /rescue: {type(e).__name__}")
        await status_msg.edit_text("❌ Error scanning approvals. Please try again later.")


async def _read_mempool_route(session, key, path, params=None):
    """GET one API mempool route, reusing a read of it younger than MEMPOOL_CACHE_SECONDS.

    A failed read raises and is not kept.
    """
    cached = _mempool_cache.get(key)
    if cached and time.monotonic() - cached[0] < MEMPOOL_CACHE_SECONDS:
        return cached[1]
    async with session.get(f"{settings.shieldbot_api_url.rstrip('/')}{path}", params=params) as resp:
        resp.raise_for_status()
        body = await resp.json()
    _mempool_cache[key] = (time.monotonic(), body)
    return body


async def _fetch_mempool_data(chain_id):
    """Read mempool alerts and counters from the API, whose process runs the only mempool monitor."""
    params = {'limit': 10}
    if chain_id is not None:
        params['chain_id'] = chain_id
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
        alerts = (await _read_mempool_route(session, ('alerts', chain_id), '/api/mempool/alerts', params))['alerts']
        stats = await _read_mempool_route(session, 'stats', '/api/mempool/stats')
    return alerts, stats


async def threats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /threats command — show live mempool threat alerts."""
    # Optional chain filter
    chain_id = None
    if context.args:
        try:
            chain_id = int(context.args[0])
        except ValueError:
            prefix_chain_id, _ = parse_chain_prefix(context.args[0] + ":0x")
            chain_id = prefix_chain_id
        try:
            web3_client.validate_chain_id(chain_id)
        except UnsupportedChainError as e:
            await update.message.reply_text(str(e))
            return
        if not supports_pending_transactions(chain_id):
            await update.message.reply_text(
                f"Mempool monitoring is not available on {get_chain_name(chain_id)}: it has no public "
                "mempool. Contract scans still cover it."
            )
            return

    try:
        alerts, stats = await _fetch_mempool_data(chain_id)
    except Exception as e:
        logger.error(f"Mempool data unavailable for /threats: {type(e).__name__}")
        await update.message.reply_text("❌ Live mempool data is unavailable right now. Please try again later.")
        return

    try:
        response = "🔍 **Mempool Threat Monitor**\n\n"

        # Stats summary
        response += "**Stats:**\n"
        response += f"• Pending txs seen: {stats.get('total_pending_seen', 0):,}\n"
        response += f"• Sandwiches detected: {stats.get('sandwiches_detected', 0)}\n"
        response += f"• Frontruns detected: {stats.get('frontruns_detected', 0)}\n"
        response += f"• Suspicious approvals: {stats.get('suspicious_approvals', 0)}\n"
        monitored = stats.get('monitored_chains', [])
        # A chain whose mempool the API could not read is unknown, never clear. Stats that do not
        # say which chains were read leave every chain unknown.
        unobservable = stats.get('unobservable_chains', monitored)
        observed = [c for c in monitored if c not in unobservable]
        if observed:
            response += f"• Monitoring: {', '.join(get_chain_name(c) for c in observed)}\n"
        if unobservable:
            response += f"• Live data unavailable: {', '.join(get_chain_name(c) for c in unobservable)}\n"

        # Recent alerts
        if alerts:
            response += f"\n**Recent Alerts ({len(alerts)}):**\n"
            for alert in alerts:
                sev = alert.get('severity', 'MEDIUM')
                sev_icon = '🔴' if sev == 'HIGH' else '🟡'
                atype = alert.get('alert_type', 'unknown').replace('_', ' ').title()
                chain_name = get_chain_name(alert.get('chain_id', 56))
                response += f"\n{sev_icon} **{escape_markdown(atype)}** ({chain_name})\n"
                response += f"  {escape_markdown(alert.get('description', 'No details'))}\n"
                if alert.get('attacker_addr'):
                    response += f"  Attacker: `{alert['attacker_addr'][:16]}...`\n"
        else:
            watched = [chain_id] if chain_id else monitored
            clear = [c for c in watched if c in observed]
            unknown = [c for c in watched if c not in observed]
            if clear:
                response += f"\n✅ No recent threats detected on {', '.join(get_chain_name(c) for c in clear)}.\n"
            if unknown or not watched:
                where = f" for {', '.join(get_chain_name(c) for c in unknown)}" if unknown else ""
                response += f"\n⚪ Live mempool data is not available{where} right now, so no result is shown.\n"

        await update.message.reply_text(
            response, parse_mode='Markdown', disable_web_page_preview=True,
        )

    except Exception as e:
        logger.error(f"Error in /threats: {type(e).__name__}")
        await update.message.reply_text("❌ Error fetching threats. Please try again later.")


async def campaign_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /campaign command — check if address is part of a scam campaign."""
    if not context.args:
        await update.message.reply_text(
            "❌ Please provide an address to investigate.\n\n"
            "Usage: `/campaign <address>`\n"
            "Checks deployer, funder, and cross-chain links.",
            parse_mode='Markdown',
        )
        return

    address = context.args[0]
    if not web3_client.is_valid_address(address):
        await update.message.reply_text("❌ Invalid address format.")
        return

    status_msg = await update.message.reply_text(
        "🕵️ **Investigating campaign links...**\n\n"
        "⏳ Tracing deployer, funder, and cross-chain connections...",
        parse_mode='Markdown',
    )

    try:
        graph = await container.campaign_service.get_entity_graph(address)
        campaign = graph.get('campaign', {})

        is_campaign = campaign.get('is_campaign', False)
        severity = campaign.get('severity', 'NONE')
        sev_icon = {'CRITICAL': '🔴', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
        # An address in no deployer or funder record has not been indexed: its links are unknown, not absent.
        indexed = bool(graph.get('deployer') or graph.get('funder') or graph.get('contracts_deployed'))

        response = "🕵️ **Campaign Radar**\n\n"
        response += f"**Address:** `{address}`\n"
        if indexed:
            response += f"**Campaign Detected:** {'Yes' if is_campaign else 'No'}\n"
            response += f"**Severity:** {sev_icon} {severity}\n"
        else:
            response += "**Campaign Detected:** Unknown (not indexed yet)\n"

        # Deployer / funder from graph
        deployer = graph.get('deployer')
        funder = graph.get('funder')
        if deployer:
            response += f"**Deployer:** `{deployer}`\n"
        if funder:
            response += f"**Funder:** `{funder}`\n"

        # Indicators
        indicators = campaign.get('indicators', [])
        if indicators:
            response += "\n**Indicators:**\n"
            for ind in indicators[:8]:
                response += f"• {escape_markdown(ind)}\n"

        # Cross-chain contracts
        xchain = graph.get('cross_chain_contracts', [])
        if xchain:
            chains_involved = campaign.get('chains_involved', [])
            chain_names = [get_chain_name(c) for c in chains_involved] if chains_involved else []
            response += f"\n**Cross-Chain Contracts:** {len(xchain)}"
            if chain_names:
                response += f" ({', '.join(chain_names)})"
            response += "\n"
            for c in xchain[:5]:
                c_chain = get_chain_name(c.get('chain_id', 56))
                risk = c.get('risk_level', '?')
                response += f"  • `{c['contract'][:16]}...` on {c_chain} — {risk}\n"
            if len(xchain) > 5:
                response += f"  ... and {len(xchain) - 5} more\n"

        # Funder cluster
        cluster = graph.get('funder_cluster', [])
        if cluster:
            response += f"\n**Funder Cluster:** {len(cluster)} deployer(s) share the same funder\n"
            total_contracts = campaign.get('total_contracts', 0)
            high_risk = campaign.get('high_risk_contracts', 0)
            if total_contracts:
                response += f"  Total contracts: {total_contracts} (🔴 {high_risk} high risk)\n"

        if not indexed:
            response += (
                "\n⚪ ShieldBot has not indexed this address yet, so its deployer, funder and "
                "campaign links are unknown.\n"
            )
        elif not is_campaign and not xchain and not cluster:
            response += "\n✅ No campaign links found — address appears isolated.\n"

        try:
            await status_msg.delete()
        except Exception:
            pass

        await update.message.reply_text(
            response, parse_mode='Markdown', disable_web_page_preview=True,
        )

    except UnsupportedChainError:
        raise
    except Exception as e:
        logger.error(f"Error in /campaign: {type(e).__name__}")
        await status_msg.edit_text("❌ Error investigating campaign. Please try again later.")


async def _may_change_launch_alerts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Whether the sender may turn this chat's launch alerts on or off, and if not say so.

    Anyone may in a private chat; in a group only an administrator or the creator, including an
    anonymous administrator, whose message comes from the group itself.
    """
    chat = update.effective_chat
    if chat.type not in (Chat.GROUP, Chat.SUPERGROUP):
        return True
    sender_chat = update.message.sender_chat
    if sender_chat is not None and sender_chat.id == chat.id:
        return True
    member = await context.bot.get_chat_member(chat.id, update.effective_user.id)
    if member.status in (ChatMember.ADMINISTRATOR, ChatMember.OWNER):
        return True
    await update.message.reply_text("Only an administrator of this group can turn launch alerts on or off.")
    return False


async def launch_alerts_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /launchalerts — alert this chat to new Robinhood Chain launch verdicts."""
    if not await _may_change_launch_alerts(update, context):
        return
    mode = context.args[0].lower() if context.args else 'blocked'
    if mode not in ('blocked', 'all'):
        await update.message.reply_text(
            "Usage: /launchalerts for blocked launches, or /launchalerts all for every scanned launch."
        )
        return
    await container.db.subscribe_launch_alerts(update.effective_chat.id, LAUNCH_CHAIN_ID, mode)
    if mode == 'all':
        text = (
            "🔔 Robinhood Chain launch alerts are on for every scanned launch.\n\n"
            "Incomplete scans are marked UNKNOWN, never safe.\n"
            "Send /launchalerts for blocked launches only, or /stopalerts to stop."
        )
    else:
        text = (
            "🔔 Robinhood Chain launch alerts are on for blocked launches (honeypots and other "
            "high-risk tokens) and impostors of official Robinhood tokens.\n\n"
            "Send /launchalerts all for every scanned launch, or /stopalerts to stop."
        )
    await update.message.reply_text(text)


async def stop_alerts_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /stopalerts — stop launch alerts for this chat."""
    if not await _may_change_launch_alerts(update, context):
        return
    if await container.db.unsubscribe_launch_alerts(update.effective_chat.id, LAUNCH_CHAIN_ID):
        await update.message.reply_text("🔕 Robinhood Chain launch alerts are off for this chat.")
    else:
        await update.message.reply_text(
            "This chat is not subscribed to launch alerts. Send /launchalerts to subscribe."
        )


def format_launch_alert(item: dict) -> str:
    """Plain-text alert for one launch outcome from the launch feed.

    An incomplete scan is headed UNKNOWN unless it is blocked, so it never reads as safe, and
    its partial score is not shown. An impostor of an official Robinhood token is headed IMPOSTOR,
    whatever its scan found, and never under a CLEARED heading. A token that shares an official
    token's ticker or name without impersonating it (a collision) names the official token, and a
    cleared one is headed NOT OFFICIAL instead of CLEARED.
    """
    scan = item['scan']
    header = _LAUNCH_ALERT_HEADERS.get(scan['outcome'])
    if header is None or (scan['status'] != 'ok' and scan['outcome'] != 'blocked'):
        header = _UNKNOWN_LAUNCH_HEADER
    headings, flags = [header], scan['flags']
    check = item.get('impostor_check') or {}
    if check.get('status') == 'impostor':
        # The official symbol comes from Robinhood's list, so it is stripped like any other text.
        label = describe_impostor_check(check)
        headings = [_IMPOSTOR_LAUNCH_HEADER.format(unlinked(label))]
        if header != _LAUNCH_ALERT_HEADERS['cleared']:
            headings.append(header)
        # A blocked launch's evidence repeats the heading as its first flag.
        flags = [flag for flag in flags if flag != label]
    elif check.get('status') == 'collision' and header == _LAUNCH_ALERT_HEADERS['cleared']:
        headings = [_COLLISION_LAUNCH_HEADER]
    lines = [*headings, f"Token: {item['token_address']}", f"Launchpad: {item['launchpad']}"]
    if header != _UNKNOWN_LAUNCH_HEADER and scan['risk_score'] is not None:
        lines.append(f"Risk score: {scan['risk_score']:g}/100")
    lines += [f"• {unlinked(flag)[:150]}" for flag in flags[:3]]
    if scan['status'] != 'ok':
        reasons = '; '.join(dict.fromkeys(
            unlinked(reason) for reason in scan['coverage_reasons'].values()
        )) or 'Provider data unavailable or incomplete'
        lines.append(f"Unknown: {reasons[:300]}")
    if check.get('status') == 'unknown':
        lines.append(f"Official token check: unknown ({unlinked(check['reason'])})")
    elif check.get('status') in ('official', 'collision'):
        lines.append(unlinked(describe_impostor_check(check)))
    lines.append(f"Evidence: {VERDICT_BASE_URL}{item['verdict_url']}")
    explorer = get_explorer_url(item['chain_id'])
    if explorer:
        lines.append(f"Explorer: {explorer}/token/{item['token_address']}")
    return '\n'.join(lines)


async def deliver_launch_alerts(bot):
    """Send one pass of queued launch alerts, each at most once.

    An alert is claimed before it is sent, so one that may have reached Telegram is never sent
    again, even after a restart. Flood control returns the alert to the queue and skips that
    chat for the rest of the pass, so other chats still get theirs. A group that migrated keeps
    its subscription and queue under its new id. A chat that blocked the bot, or that Telegram
    reports as not found, is unsubscribed. An unclear network error or a bot-wide error ends
    the pass.
    """
    alerts = await container.db.get_pending_launch_alerts(
        time.time(), LAUNCH_ALERT_MAX_AGE_SECONDS, LAUNCH_ALERTS_PER_CHAT_PER_PASS, LAUNCH_ALERTS_PER_PASS,
    )
    skipped_chats = set()
    for alert in alerts:
        if alert['chat_id'] in skipped_chats or not await container.db.claim_launch_alert(alert['id']):
            continue
        # A failed send comes back as a value, so its migration target and Telegram's
        # description can be read; only the error class is ever logged or stored.
        (result,) = await asyncio.gather(
            bot.send_message(
                chat_id=alert['chat_id'], text=format_launch_alert(alert['payload']),
                disable_web_page_preview=True,
            ),
            return_exceptions=True,
        )
        if not isinstance(result, BaseException):
            await container.db.set_launch_alert_state(alert['id'], 'sent')
            continue
        error = type(result).__name__
        if isinstance(result, RetryAfter):
            # Telegram refused the message, so it was not delivered and can be sent later.
            await container.db.set_launch_alert_state(alert['id'], 'pending')
            skipped_chats.add(alert['chat_id'])
            logger.warning("Launch alerts to a chat paused by Telegram flood control (%s)", error)
        elif isinstance(result, ChatMigrated):
            # Telegram refused the message, so it and the rest of the queue follow the group.
            await container.db.set_launch_alert_state(alert['id'], 'pending')
            await container.db.move_launch_alert_chat(alert['chat_id'], result.new_chat_id, alert['chain_id'])
            skipped_chats.add(alert['chat_id'])
            logger.warning("Launch alerts moved to a migrated group (%s)", error)
        elif isinstance(result, Forbidden) or (
            # Telegram's description for a deleted chat or one the bot was never in.
            isinstance(result, BadRequest) and result.message.lower() == 'chat not found'
        ):
            await container.db.set_launch_alert_state(alert['id'], 'failed', error)
            await container.db.unsubscribe_launch_alerts(alert['chat_id'], alert['chain_id'])
            logger.warning("Launch alerts stopped for an unreachable chat: %s", error)
        elif isinstance(result, BadRequest):
            await container.db.set_launch_alert_state(alert['id'], 'failed', error)
            logger.warning("Launch alert rejected: %s", error)
        elif isinstance(result, NetworkError):
            # The message may have been delivered, so it is recorded as unconfirmed and never resent.
            await container.db.set_launch_alert_state(alert['id'], 'unconfirmed', error)
            logger.warning("Launch alert delivery unconfirmed: %s", error)
            return
        elif isinstance(result, TelegramError):
            await container.db.set_launch_alert_state(alert['id'], 'failed', error)
            logger.warning("Launch alert delivery failed: %s", error)
            return
        else:
            raise result


async def launch_alert_loop(bot):
    """Queue and send launch alerts every LAUNCH_ALERT_POLL_SECONDS until cancelled.

    The first pass after a start covers the last LAUNCH_ALERT_MAX_AGE_SECONDS; later passes
    reread LAUNCH_ALERT_OVERLAP_SECONDS before the previous one, or from the oldest blocked
    launch still held back for its evidence.
    """
    next_since = None
    while True:
        now = time.time()
        since = now - LAUNCH_ALERT_MAX_AGE_SECONDS
        if next_since is not None:
            since = max(since, next_since)
        try:
            held = await container.db.enqueue_launch_alerts(LAUNCH_CHAIN_ID, since)
            next_since = now - LAUNCH_ALERT_OVERLAP_SECONDS
            if held is not None:
                next_since = min(next_since, held)
            await deliver_launch_alerts(bot)
        except Exception as e:
            logger.error(
                "Launch alert pass failed: %s\n%s",
                type(e).__name__, "".join(traceback.format_tb(e.__traceback__)),
            )
        await asyncio.sleep(LAUNCH_ALERT_POLL_SECONDS)


async def blacklist_reload_loop():
    """Reload the persisted scam blacklist every BLACKLIST_RELOAD_SECONDS until cancelled.

    Startup has just loaded it, so each pass waits first.
    """
    while True:
        await asyncio.sleep(BLACKLIST_RELOAD_SECONDS)
        try:
            await scam_db.load_blacklist()
        except Exception as e:
            logger.error(
                "Blacklist reload failed: %s\n%s",
                type(e).__name__, "".join(traceback.format_tb(e.__traceback__)),
            )


async def _handle_advisor_chat(update: Update, message: str, chain_id: int = 56):
    """Route free-text messages to the AI advisor."""
    web3_client.validate_chain_id(chain_id)
    if not hasattr(container, 'advisor') or container.advisor is None:
        await update.message.reply_text(
            "AI advisor is not available at the moment."
        )
        return

    user_id = f"tg-{update.effective_user.id}"
    typing_msg = await update.message.reply_text("\U0001f914 Thinking...")

    try:
        response = await container.advisor.chat(user_id, message, chain_id=chain_id)
        scan_data = response.get('scan_data')
        response_text = '\n'.join(unlinked(line) for line in response['text'].split('\n'))
        # The model's text never sets a verdict: a contract check ends with the scan's own.
        if scan_data is not None:
            if is_scan_incomplete(scan_data):
                response_text = 'Unknown risk: provider coverage incomplete. Review the missing data before proceeding.'
                verdict = f'risk level {UNKNOWN}, score unknown, status unknown'
            else:
                verdict = (
                    f"risk level {scan_data['risk_level']}, score {scan_data['risk_score']}/100, "
                    f"status {scan_data['status']}"
                )
            response_text += f'\n\nShieldBot scan verdict: {verdict}'
        await typing_msg.edit_text(response_text)
    except UnsupportedChainError:
        raise
    except Exception as e:
        logger.error(f"Advisor chat error: {type(e).__name__}")
        await typing_msg.edit_text(
            "Sorry, I couldn't process that request. Try again or send a contract address to scan."
        )


async def handle_address(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Auto-detect addresses or route free text to AI advisor."""
    message_text = update.message.text.strip()

    # Parse optional chain prefix (e.g. "eth:0x..." or "base:0x...")
    prefix_chain_id, address = parse_chain_prefix(message_text)
    if prefix_chain_id:
        web3_client.validate_chain_id(prefix_chain_id)
        context.user_data['chain_id'] = prefix_chain_id

    user_chain_id = _get_user_chain_id(context)
    chain_name = get_chain_name(user_chain_id)

    # Check if it looks like an Ethereum address
    if address.startswith('0x') and len(address) == 42:
        # Replies show the address in code spans, which legacy Markdown cannot escape.
        if not web3_client.is_valid_address(address):
            await update.message.reply_text("❌ Invalid address format.")
            return

        # Show scanning message
        status_msg = await update.message.reply_text(
            f"🔍 Analyzing address on {chain_name}..."
        )

        # Check if it's a token contract
        is_token = await web3_client.is_token_contract(address, chain_id=user_chain_id)

        if is_token is not False:
            await status_msg.edit_text(f"🔍 Running token safety checks on {chain_name}...")
            await check_token(update, address, chain_id=user_chain_id)
        else:
            await status_msg.edit_text(f"🔍 Running security scan on {chain_name}...")
            await scan_contract(update, address, chain_id=user_chain_id)
    else:
        # Route free text to AI advisor
        await _handle_advisor_chat(update, message_text, chain_id=user_chain_id)


async def scan_contract(update: Update, address: str, chain_id: int = 56):
    """Scan a contract for security risks with composite intelligence pipeline"""
    web3_client.validate_chain_id(chain_id)
    try:
        # Check cache first
        cache_key = f"{chain_id}:{address}"
        cached = _get_cached(cache_key, 'contract')
        if cached:
            response = format_scan_result(cached)
            keyboard = _scan_buttons(address, chain_id)
            await update.message.reply_text(response, parse_mode='Markdown', reply_markup=keyboard, disable_web_page_preview=True)
            return

        # Progress indicator
        chain_name = get_chain_name(chain_id)
        progress_msg = await update.message.reply_text(
            f"\U0001F6E1\uFE0F **Scanning contract on {chain_name}...**\n\n"
            "\u23F3 Gathering intelligence from multiple sources...",
            parse_mode='Markdown'
        )

        # Try new composite pipeline first
        response = None
        risk_level = 'medium'
        try:
            from core.analyzer import AnalysisContext

            ctx = AnalysisContext(address=address, chain_id=chain_id)
            reads = [container.registry.run_all(ctx), web3_client.get_token_info(address, chain_id=chain_id)]
            if chain_id == 4663:
                # The official-token check reads symbol() and name() itself, alongside the analyzers, as the
                # launch hunter's does: the token info read comes back empty when decimals() or totalSupply()
                # reverts, which a token can arrange.
                reads.append(container.robinhood_assets.check_onchain(address, RUN_ALL_DEADLINE_SECONDS))
            analyzer_results, token_info, *impostor_check = await asyncio.gather(*reads)

            risk_output = risk_engine.compute_from_results(analyzer_results)
            if impostor_check:
                risk_output = with_impostor_check(risk_output, impostor_check[0])

            # Extract service data for report formatting
            by_name = {r.name: r for r in analyzer_results}
            contract_data = by_name["structural"].data if "structural" in by_name else {}
            honeypot_data = by_name["honeypot"].data if "honeypot" in by_name else {}
            dex_data = by_name["market"].data if "market" in by_name else {}
            ethos_data = by_name["behavioral"].data if "behavioral" in by_name else {}

            # Generate AI forensic analysis
            ai_analysis = None
            if ai_analyzer and ai_analyzer.is_available() and not is_scan_incomplete(risk_output):
                scan_data = {
                    'chain_id': chain_id,
                    'chain_name': chain_name,
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
            verdict_scan, verdict_honeypot = risk_output, honeypot_data
            risk_level = 'unknown' if is_scan_incomplete(risk_output) else risk_output.get('risk_level', 'medium').lower()

            # Cache the composite result
            _set_cache(cache_key, 'contract', {
                **risk_output, 'address': address, 'composite_report': response,
                'risk_level': risk_level, 'status': 'unknown' if risk_level == 'unknown' else 'ok',
            })

            # Enqueue deployer/funder indexing (fire-and-forget)
            if hasattr(container, 'indexer') and container.indexer:
                container.indexer.enqueue(address, chain_id)

        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.warning(f"Composite pipeline failed for {address}, falling back: {type(e).__name__}")

        # Fallback to legacy scanner
        if not response:
            result = await tx_scanner.scan_address(address, chain_id=chain_id)
            if is_scan_incomplete(result):
                result = {**result, 'status': 'unknown', 'risk_level': 'unknown', 'safety_level': 'unknown'}
            _set_cache(cache_key, 'contract', result)
            verdict_scan, verdict_honeypot = result, None
            response = format_scan_result(result)
            risk_level = 'unknown' if is_scan_incomplete(result) else result.get('risk_level', 'medium')

        keyboard = _scan_buttons(address, chain_id)

        # Record on-chain (fire-and-forget — non-blocking)
        if risk_level != 'unknown' and onchain_recorder.is_available():
            await onchain_recorder.record_scan_fire_and_forget(address, risk_level, 'contract')
        if risk_level != 'unknown' and base_attestor.is_available():
            await base_attestor.attest_fire_and_forget(address, risk_level, 'contract', source_chain_id=chain_id)
        if chain_id == 4663:
            container.verdict_publisher.publish_fire_and_forget(
                chain_id, address, verdict_scan, honeypot_data=verdict_honeypot,
            )

        try:
            await progress_msg.delete()
        except Exception:
            pass

        await update.message.reply_text(
            response,
            parse_mode='Markdown',
            reply_markup=keyboard,
            disable_web_page_preview=True
        )

    except UnsupportedChainError:
        raise
    except Exception as e:
        logger.error(f"Error scanning contract: {type(e).__name__}")
        await update.message.reply_text(
            "\u274C Error scanning contract.\n\n"
            "Please check the address and try again."
        )


async def check_token(update: Update, address: str, chain_id: int = 56):
    """Check token safety with composite intelligence pipeline"""
    web3_client.validate_chain_id(chain_id)
    try:
        # Check cache first
        cache_key = f"{chain_id}:{address}"
        cached = _get_cached(cache_key, 'token')
        if cached:
            response = format_token_result(cached)
            keyboard = _token_buttons(address, chain_id)
            await update.message.reply_text(response, parse_mode='Markdown', reply_markup=keyboard, disable_web_page_preview=True)
            return

        # Progress indicator
        chain_name = get_chain_name(chain_id)
        progress_msg = await update.message.reply_text(
            f"\U0001F4B0 **Checking token safety on {chain_name}...**\n\n"
            "\u23F3 Gathering intelligence from multiple sources...",
            parse_mode='Markdown'
        )

        # Try new composite pipeline first
        response = None
        risk_level = 'warning'
        try:
            from core.analyzer import AnalysisContext

            ctx = AnalysisContext(address=address, chain_id=chain_id)
            reads = [container.registry.run_all(ctx), web3_client.get_token_info(address, chain_id=chain_id)]
            if chain_id == 4663:
                # The official-token check reads symbol() and name() itself, alongside the analyzers, as the
                # launch hunter's does: the token info read comes back empty when decimals() or totalSupply()
                # reverts, which a token can arrange.
                reads.append(container.robinhood_assets.check_onchain(address, RUN_ALL_DEADLINE_SECONDS))
            analyzer_results, token_info, *impostor_check = await asyncio.gather(*reads)

            risk_output = risk_engine.compute_from_results(analyzer_results)
            if impostor_check:
                risk_output = with_impostor_check(risk_output, impostor_check[0])

            by_name = {r.name: r for r in analyzer_results}
            contract_data = by_name["structural"].data if "structural" in by_name else {}
            honeypot_data = by_name["honeypot"].data if "honeypot" in by_name else {}
            dex_data = by_name["market"].data if "market" in by_name else {}
            ethos_data = by_name["behavioral"].data if "behavioral" in by_name else {}

            # Generate AI forensic analysis
            ai_analysis = None
            if ai_analyzer and ai_analyzer.is_available() and not is_scan_incomplete(risk_output):
                scan_data = {
                    'chain_id': chain_id,
                    'chain_name': chain_name,
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
            verdict_scan, verdict_honeypot = risk_output, honeypot_data
            risk_level = 'unknown' if is_scan_incomplete(risk_output) else risk_output.get('risk_level', 'medium').lower()

            _set_cache(cache_key, 'token', {
                **risk_output, 'address': address, 'composite_report': response,
                'risk_level': risk_level, 'status': 'unknown' if risk_level == 'unknown' else 'ok',
            })

            # Enqueue deployer/funder indexing (fire-and-forget)
            if hasattr(container, 'indexer') and container.indexer:
                container.indexer.enqueue(address, chain_id)

        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.warning(f"Composite pipeline failed for {address}, falling back: {type(e).__name__}")

        # Fallback to legacy scanner
        if not response:
            result = await token_scanner.check_token(address, chain_id=chain_id)
            if is_scan_incomplete(result):
                result = {**result, 'status': 'unknown', 'risk_level': 'unknown', 'safety_level': 'unknown'}
            _set_cache(cache_key, 'token', result)
            verdict_scan, verdict_honeypot = result, None
            response = format_token_result(result)
            risk_level = 'unknown' if is_scan_incomplete(result) else result.get('safety_level', 'warning')

        keyboard = _token_buttons(address, chain_id)

        # Record on-chain (fire-and-forget — non-blocking)
        if risk_level != 'unknown' and onchain_recorder.is_available():
            await onchain_recorder.record_scan_fire_and_forget(address, risk_level, 'token')
        if risk_level != 'unknown' and base_attestor.is_available():
            await base_attestor.attest_fire_and_forget(address, risk_level, 'token', source_chain_id=chain_id)
        if chain_id == 4663:
            container.verdict_publisher.publish_fire_and_forget(
                chain_id, address, verdict_scan, honeypot_data=verdict_honeypot,
            )

        try:
            await progress_msg.delete()
        except Exception:
            pass

        await update.message.reply_text(
            response,
            parse_mode='Markdown',
            reply_markup=keyboard,
            disable_web_page_preview=True
        )

    except UnsupportedChainError:
        raise
    except Exception as e:
        logger.error(f"Error checking token: {type(e).__name__}")
        await update.message.reply_text(
            "\u274C Error checking token.\n\n"
            "Please check the address and try again."
        )


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button callbacks"""
    query = update.callback_query
    await query.answer()

    if query.data.startswith('chain_'):
        try:
            chain_id = int(query.data.replace('chain_', ''))
            web3_client.validate_chain_id(chain_id)
        except ValueError:
            await query.edit_message_text(
                f"Unsupported chain selection. Supported: {web3_client.get_supported_chain_ids()}",
            )
            return
        context.user_data['chain_id'] = chain_id
        chain_name = get_chain_name(chain_id)
        await query.edit_message_text(
            f"Switched to {chain_name} (chain_id={chain_id}).\n"
            f"All scans will now target {chain_name}.",
        )
    elif query.data.startswith('token_'):
        # The button names the chain its scan ran on, which the user's current chain may no longer be.
        chain_text, _, address = query.data[len('token_'):].rpartition('_')
        if not chain_text.isdigit() or not web3_client.is_valid_address(address):
            await query.message.reply_text("❌ Invalid address format.")
            return
        chain_id = web3_client.validate_chain_id(int(chain_text))
        await query.message.reply_text(f"🔍 Running token safety check for `{address}`...", parse_mode='Markdown')
        await check_token(query, address, chain_id=chain_id)


def _scan_buttons(address: str, chain_id: int = 56) -> InlineKeyboardMarkup:
    """Generate action buttons for scan results."""
    explorer = get_explorer_url(chain_id)
    chain_name = get_chain_name(chain_id)
    keyboard = []
    if explorer:
        keyboard.append([InlineKeyboardButton(f"🔍 View on {chain_name} Explorer", url=f"{explorer}/address/{address}")])
    # "token_<chain id>_<address>" is 57 bytes with an eight-digit chain id; Telegram allows 64.
    keyboard.append([InlineKeyboardButton("💰 Check Token Safety", callback_data=f"token_{chain_id}_{address}")])
    return InlineKeyboardMarkup(keyboard)


def _token_buttons(address: str, chain_id: int = 56) -> InlineKeyboardMarkup:
    """Generate action buttons for token results."""
    explorer = get_explorer_url(chain_id)
    dex_slug = get_dexscreener_slug(chain_id)
    chain_name = get_chain_name(chain_id)
    keyboard = []
    if explorer:
        keyboard.append([InlineKeyboardButton(f"🔍 View on {chain_name} Explorer", url=f"{explorer}/token/{address}")])
    if dex_slug:
        keyboard.append([InlineKeyboardButton("📊 View on DexScreener", url=f"https://dexscreener.com/{dex_slug}/{address}")])
    return InlineKeyboardMarkup(keyboard)


def format_scan_result(result: dict) -> str:
    """Format scan result — use composite report, forensic report, or fallback"""
    if result.get('composite_report'):
        return result['composite_report']
    incomplete = is_scan_incomplete(result) or (
        result.get('is_contract') is not False and result.get('is_verified') is None
    )
    if result.get('forensic_report') and not incomplete:
        return escape_markdown_lines(result['forensic_report'])

    risk_emoji = {
        'high': '🔴',
        'medium': '🟡',
        'low': '🟢',
        'none': '✅'
    }

    risk_level = 'unknown' if incomplete else result.get('risk_level', 'unknown')
    emoji = risk_emoji.get(risk_level, '⚪')
    score = 'Unknown (incomplete provider coverage)' if incomplete else f"{result.get('risk_score', 'N/A')}/100"
    verified = result.get('is_verified')
    if result.get('is_contract') is False:
        verification = 'Not applicable (wallet address, not a contract)'
    else:
        verification = 'Unknown (verification data unavailable)' if verified is None else (
            '✅ Contract verified' if verified else '❌ Contract not verified'
        )

    response = f"""
🛡️ **Security Scan Report**

**Address:** `{result['address']}`
**Risk Level:** {emoji} {risk_level.upper()}
**Risk Score:** {score} (Confidence: {result.get('confidence', 'N/A')}%)

**Verification Status:**
{verification}

**Security Checks:**
"""

    for check, status in result.get('checks', {}).items():
        status_icon = 'Unknown' if status is None else ('✅' if status else '❌')
        check_name = check.replace('_', ' ').title()
        response += f"{status_icon} {check_name}\n"

    scam_matches = database_matches(result.get('scam_matches'))
    if scam_matches:
        response += f"\n⚠️ **Warning:** Found {len(scam_matches)} scam database match(es)\n"
        for match in scam_matches[:3]:
            response += f"• {escape_markdown(match['type'])}: {escape_markdown(match['reason'])}\n"

    # A community report is not a scam database match; it is named on its own, once.
    reported = [match['reason'] for match in medium_matches(result.get('scam_matches'))]
    for reason in reported:
        response += f"\n⚠️ {escape_markdown(reason)}\n"

    warnings = [warning for warning in result.get('warnings', []) if warning not in reported]
    if warnings:
        response += "\n**Warnings:**\n"
        for warning in warnings[:5]:
            response += f"• {escape_markdown(warning)}\n"

    # AI structured risk score
    ai_risk = result.get('ai_risk_score')
    if ai_risk and not incomplete:
        response += f"\n🤖 **AI Risk Assessment:**\n"
        response += (
            f"Score: {escape_markdown(ai_risk.get('risk_score', 'N/A'))}/100 | "
            f"Level: {escape_markdown(ai_risk.get('risk_level', 'N/A'))}\n"
        )
        findings = ai_risk.get('key_findings', [])
        for f in findings[:3]:
            response += f"• {escape_markdown(f)}\n"
        rec = ai_risk.get('recommendation', '')
        if rec:
            response += f"💡 {escape_markdown(rec)}\n"

    # Narrative AI analysis
    if result.get('ai_analysis') and not incomplete:
        response += f"\n🧠 **AI Analysis:**\n{escape_markdown_lines(result['ai_analysis'][:500])}\n"

    return response


def format_token_result(result: dict) -> str:
    """Format token result — use composite report, forensic report, or fallback"""
    if result.get('composite_report'):
        return result['composite_report']
    incomplete = is_scan_incomplete(result) or any(
        result.get(field) is None for field in ('is_honeypot', 'buy_tax', 'sell_tax')
    ) or result.get('checks', {}).get('can_sell') is None
    if result.get('forensic_report') and not incomplete:
        return escape_markdown_lines(result['forensic_report'])

    safety_emoji = {
        'safe': '✅',
        'warning': '⚠️',
        'danger': '🔴',
        'unknown': '⚪'
    }

    safety_level = 'unknown' if incomplete else result.get('safety_level', 'unknown')
    emoji = safety_emoji.get(safety_level, '⚪')
    score = 'Unknown (incomplete provider coverage)' if incomplete else f"{result.get('risk_score', 'N/A')}/100"
    honeypot = result.get('is_honeypot')
    if honeypot is None or (result.get('simulation_failed') and honeypot is False):
        honeypot_display = 'Unknown (honeypot data incomplete)'
    else:
        honeypot_display = '🔴 HONEYPOT DETECTED' if honeypot else '✅ Not a honeypot'

    response = f"""
💰 **Token Safety Report**

**Token:** {escape_markdown(result.get('name', 'Unknown'))} ({escape_markdown(result.get('symbol', 'N/A'))})
**Address:** `{result['address']}`
**Safety:** {emoji} {safety_level.upper()}
**Risk Score:** {score} (Confidence: {result.get('confidence', 'N/A')}%)

**Honeypot Check:**
{honeypot_display}

**Contract Analysis:**
"""

    checks = result.get('checks', {})
    for key, label in (('can_buy', 'Can Buy'), ('can_sell', 'Can Sell'),
                       ('ownership_renounced', 'Ownership Renounced'), ('liquidity_locked', 'Liquidity Locked')):
        value = checks.get(key)
        if key == 'can_sell' and result.get('simulation_failed'):
            value = None
        status_icon = 'Unknown' if value is None else ('✅' if value else '❌')
        response += f"{status_icon} {label}\n"

    if result.get('risks'):
        response += "\n**Risks Detected:**\n"
        for risk in result['risks'][:6]:
            response += f"• {escape_markdown(risk)}\n"

    buy_tax = result.get('buy_tax')
    sell_tax = result.get('sell_tax')
    buy_display = 'Unknown' if buy_tax is None else f'{buy_tax}%'
    sell_display = 'Unknown' if sell_tax is None else f'{sell_tax}%'
    response += f"\n**Taxes:**\nBuy: {buy_display} | Sell: {sell_display}\n"

    # AI structured risk score
    ai_risk = result.get('ai_risk_score')
    if ai_risk and not incomplete:
        response += f"\n🤖 **AI Risk Assessment:**\n"
        response += (
            f"Score: {escape_markdown(ai_risk.get('risk_score', 'N/A'))}/100 | "
            f"Level: {escape_markdown(ai_risk.get('risk_level', 'N/A'))}\n"
        )
        findings = ai_risk.get('key_findings', [])
        for f in findings[:3]:
            response += f"• {escape_markdown(f)}\n"
        rec = ai_risk.get('recommendation', '')
        if rec:
            response += f"💡 {escape_markdown(rec)}\n"

    # Narrative AI analysis
    if result.get('ai_analysis') and not incomplete:
        response += f"\n🧠 **AI Analysis:**\n{escape_markdown_lines(result['ai_analysis'][:500])}\n"

    return response


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Log errors"""
    logger.error(f"Update caused error {type(context.error).__name__}")
    if isinstance(context.error, UnsupportedChainError) and update and update.effective_message:
        await update.effective_message.reply_text(str(context.error))


def main():
    """Start the bot"""
    token = settings.telegram_bot_token
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN not found in environment variables!")
        return

    application = (
        Application.builder()
        .token(token)
        .post_init(post_init)
        .post_stop(post_stop)
        .post_shutdown(post_shutdown)
        .build()
    )

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("scan", scan_command))
    application.add_handler(CommandHandler("token", token_command))
    application.add_handler(CommandHandler("chain", chain_command))
    application.add_handler(CommandHandler("rescue", rescue_command))
    application.add_handler(CommandHandler("threats", threats_command))
    application.add_handler(CommandHandler("campaign", campaign_command))
    application.add_handler(CommandHandler("history", history_command))
    application.add_handler(CommandHandler("report", report_command))
    application.add_handler(CommandHandler("launchalerts", launch_alerts_command))
    application.add_handler(CommandHandler("stopalerts", stop_alerts_command))
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_address))

    # Add error handler
    application.add_error_handler(error_handler)

    # Start the bot
    logger.info("🛡️ ShieldBot starting...")
    logger.info(f"AI Analysis: {'enabled' if ai_analyzer.is_available() else 'disabled'}")
    logger.info(f"On-chain Recording: {'enabled' if onchain_recorder.is_available() else 'disabled'}")
    logger.info(f"Base EAS Attestor: {'enabled' if base_attestor.is_available() else 'disabled'}")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
