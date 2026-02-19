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
from utils.chain_info import (
    get_chain_name, get_explorer_url, get_dexscreener_slug,
    parse_chain_prefix, CHAIN_INFO,
)

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


def _get_user_chain_id(context: ContextTypes.DEFAULT_TYPE) -> int:
    """Get the user's selected chain_id, default BSC (56)."""
    return context.user_data.get('chain_id', 56)


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


async def post_init(application):
    """Initialize services and register bot command menu."""
    await container.startup()
    await application.bot.set_my_commands([
        ("start", "Welcome message & quick start"),
        ("scan", "Scan a contract for risks"),
        ("token", "Check if a token is safe"),
        ("chain", "Switch active chain"),
        ("rescue", "Scan wallet for risky approvals"),
        ("threats", "Live mempool threat alerts"),
        ("campaign", "Check if address is part of scam campaign"),
        ("history", "View on-chain scan history"),
        ("report", "Report a scam address"),
        ("help", "Show all commands"),
    ])


async def post_shutdown(application):
    """Clean up services on bot shutdown."""
    await container.shutdown()


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message with instructions"""
    welcome_text = """
🛡️ **Welcome to ShieldBot!**

Your AI-powered multi-chain security assistant. I can help you:

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

**🚨 Advanced Security**
• Rescue mode — find risky token approvals in your wallet
• Mempool threats — live sandwich & frontrun detection
• Campaign radar — link addresses to coordinated scam campaigns

**📜 On-Chain History**
All scans are recorded on BNB Chain for transparency.

**How to use:**
Send any address and I'll auto-detect what to scan!
Use chain prefixes: `eth:0x...`, `base:0x...`, `arb:0x...`, `poly:0x...`, `op:0x...`

Commands:
/scan — Scan a contract
/token — Check token safety
/chain — Switch active chain
/rescue — Scan wallet for risky approvals
/threats — Live mempool threat alerts
/campaign — Check scam campaign links
/history — View on-chain scan history
/report — Report a scam address
/help — Show all commands
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

**/start** - Welcome message & quick start
**/scan <address>** - Scan a contract for security risks
**/token <address>** - Check if a token is safe to trade
**/chain** - Switch active chain
**/rescue <wallet>** - Scan wallet for risky token approvals
**/threats** - Live mempool threat alerts
**/campaign <address>** - Check if address is part of a scam campaign
**/history <address>** - View on-chain scan history
**/report <address> <reason>** - Report a scam address
**/help** - Show this help message

**Quick Tips:**
• Send any address and I'll auto-detect what to scan
• Use chain prefixes: `eth:0x...`, `base:0x...`, `bsc:0x...`, `arb:0x...`, `poly:0x...`, `op:0x...`
• Or use /chain to switch your default chain
• Supported: BSC, Ethereum, Base, Arbitrum, Polygon, Optimism, opBNB

Stay safe! 🛡️
"""
    await update.message.reply_text(help_text, parse_mode='Markdown')


async def chain_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /chain command — select active chain."""
    keyboard = []
    for cid, info in CHAIN_INFO.items():
        current = _get_user_chain_id(context)
        marker = " (current)" if cid == current else ""
        keyboard.append([InlineKeyboardButton(
            f"{info['name']}{marker}",
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
    chain_id = prefix_chain_id or _get_user_chain_id(context)
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
    chain_id = prefix_chain_id or _get_user_chain_id(context)
    await check_token(update, address, chain_id=chain_id)


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
    chain_id = prefix_chain_id or _get_user_chain_id(context)

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
        safe = total - high - medium

        response = f"🚨 **Rescue Mode — Approval Scan**\n\n"
        response += f"**Wallet:** `{address}`\n"
        response += f"**Chain:** {chain_name}\n"
        response += f"**Total Approvals:** {total}\n"
        response += f"🔴 High Risk: {high} | 🟡 Medium: {medium} | 🟢 Safe: {safe}\n"

        # Show risky approvals
        approvals = result.get('approvals', [])
        risky = [a for a in approvals if a.get('risk_level') in ('HIGH', 'MEDIUM')]
        if risky:
            response += "\n**Risky Approvals:**\n"
            for a in risky[:10]:
                risk_icon = '🔴' if a['risk_level'] == 'HIGH' else '🟡'
                symbol = a.get('token_symbol', '???')
                spender_label = a.get('spender_label') or a.get('spender', '')[:10] + '...'
                response += f"{risk_icon} {symbol} → {spender_label}"
                if a.get('risk_reason'):
                    response += f" — {a['risk_reason']}"
                response += "\n"

        # Show alerts
        alerts = result.get('alerts', [])
        if alerts:
            response += "\n**Alerts:**\n"
            for alert in alerts[:5]:
                response += f"⚠️ **{alert.get('title', 'Alert')}**\n"
                response += f"  {alert.get('description', '')}\n"
                if alert.get('what_you_can_do'):
                    response += f"  💡 {alert['what_you_can_do']}\n"

        # Revoke instructions
        revoke_txs = result.get('revoke_txs', [])
        if revoke_txs:
            response += f"\n**Revoke Instructions:**\n"
            response += f"Found {len(revoke_txs)} approval(s) to revoke.\n"
            response += "Use [Revoke.cash](https://revoke.cash/) or submit the revoke transactions from your wallet.\n"
        elif total > 0 and high == 0 and medium == 0:
            response += "\n✅ All approvals look safe — no action needed.\n"

        try:
            await status_msg.delete()
        except Exception:
            pass

        await update.message.reply_text(
            response, parse_mode='Markdown', disable_web_page_preview=True,
        )

    except Exception as e:
        logger.error(f"Error in /rescue: {e}")
        await status_msg.edit_text(f"❌ Error scanning approvals: {str(e)}")


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
        alerts = container.mempool_monitor.get_alerts(chain_id=chain_id, limit=10)
        stats = container.mempool_monitor.get_stats()

        response = "🔍 **Mempool Threat Monitor**\n\n"

        # Stats summary
        response += "**Stats:**\n"
        response += f"• Pending txs seen: {stats.get('total_pending_seen', 0):,}\n"
        response += f"• Sandwiches detected: {stats.get('sandwiches_detected', 0)}\n"
        response += f"• Frontruns detected: {stats.get('frontruns_detected', 0)}\n"
        response += f"• Suspicious approvals: {stats.get('suspicious_approvals', 0)}\n"
        monitored = stats.get('monitored_chains', [])
        if monitored:
            chain_names = [get_chain_name(c) for c in monitored]
            response += f"• Monitoring: {', '.join(chain_names)}\n"

        # Recent alerts
        if alerts:
            response += f"\n**Recent Alerts ({len(alerts)}):**\n"
            for alert in alerts:
                sev = alert.get('severity', 'MEDIUM')
                sev_icon = '🔴' if sev == 'HIGH' else '🟡'
                atype = alert.get('alert_type', 'unknown').replace('_', ' ').title()
                chain_name = get_chain_name(alert.get('chain_id', 56))
                response += f"\n{sev_icon} **{atype}** ({chain_name})\n"
                response += f"  {alert.get('description', 'No details')}\n"
                if alert.get('attacker_addr'):
                    response += f"  Attacker: `{alert['attacker_addr'][:16]}...`\n"
        else:
            filter_text = f" on {get_chain_name(chain_id)}" if chain_id else ""
            response += f"\n✅ No recent threats detected{filter_text}.\n"

        await update.message.reply_text(
            response, parse_mode='Markdown', disable_web_page_preview=True,
        )

    except Exception as e:
        logger.error(f"Error in /threats: {e}")
        await update.message.reply_text(f"❌ Error fetching threats: {str(e)}")


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

        response = "🕵️ **Campaign Radar**\n\n"
        response += f"**Address:** `{address}`\n"
        response += f"**Campaign Detected:** {'Yes' if is_campaign else 'No'}\n"
        response += f"**Severity:** {sev_icon} {severity}\n"

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
                response += f"• {ind}\n"

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

        if not is_campaign and not xchain and not cluster:
            response += "\n✅ No campaign links found — address appears isolated.\n"

        try:
            await status_msg.delete()
        except Exception:
            pass

        await update.message.reply_text(
            response, parse_mode='Markdown', disable_web_page_preview=True,
        )

    except Exception as e:
        logger.error(f"Error in /campaign: {e}")
        await status_msg.edit_text(f"❌ Error investigating campaign: {str(e)}")


async def handle_address(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Auto-detect and handle addresses sent in messages"""
    message_text = update.message.text.strip()

    # Parse optional chain prefix (e.g. "eth:0x..." or "base:0x...")
    prefix_chain_id, address = parse_chain_prefix(message_text)
    if prefix_chain_id:
        context.user_data['chain_id'] = prefix_chain_id

    user_chain_id = _get_user_chain_id(context)
    chain_name = get_chain_name(user_chain_id)

    # Check if it looks like an Ethereum address
    if address.startswith('0x') and len(address) == 42:
        # Show scanning message
        status_msg = await update.message.reply_text(
            f"🔍 Analyzing address on {chain_name}..."
        )

        # Check if it's a token contract
        is_token = await web3_client.is_token_contract(address, chain_id=user_chain_id)

        if is_token:
            await status_msg.edit_text(f"🔍 Detected token on {chain_name} — running safety checks...")
            await check_token(update, address, chain_id=user_chain_id)
        else:
            await status_msg.edit_text(f"🔍 Running security scan on {chain_name}...")
            await scan_contract(update, address, chain_id=user_chain_id)
    else:
        await update.message.reply_text(
            "❌ Invalid address format. Send a valid address (0x...).\n\n"
            "Tip: Use chain prefixes like `eth:0x...` or `base:0x...`",
            parse_mode='Markdown',
        )


async def scan_contract(update: Update, address: str, chain_id: int = 56):
    """Scan a contract for security risks with composite intelligence pipeline"""
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
            analyzer_results, token_info = await asyncio.gather(
                container.registry.run_all(ctx),
                web3_client.get_token_info(address, chain_id=chain_id),
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
            _set_cache(cache_key, 'contract', {'composite_report': response, 'risk_level': risk_level})

            # Enqueue deployer/funder indexing (fire-and-forget)
            if hasattr(container, 'indexer') and container.indexer:
                container.indexer.enqueue(address, chain_id)

        except Exception as e:
            logger.warning(f"Composite pipeline failed for {address}, falling back: {e}")

        # Fallback to legacy scanner
        if not response:
            result = await tx_scanner.scan_address(address, chain_id=chain_id)
            _set_cache(cache_key, 'contract', result)
            response = format_scan_result(result)
            risk_level = result.get('risk_level', 'medium')

        keyboard = _scan_buttons(address, chain_id)

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


async def check_token(update: Update, address: str, chain_id: int = 56):
    """Check token safety with composite intelligence pipeline"""
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
            analyzer_results, token_info = await asyncio.gather(
                container.registry.run_all(ctx),
                web3_client.get_token_info(address, chain_id=chain_id),
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

            _set_cache(cache_key, 'token', {'composite_report': response, 'risk_level': risk_level})

            # Enqueue deployer/funder indexing (fire-and-forget)
            if hasattr(container, 'indexer') and container.indexer:
                container.indexer.enqueue(address, chain_id)

        except Exception as e:
            logger.warning(f"Composite pipeline failed for {address}, falling back: {e}")

        # Fallback to legacy scanner
        if not response:
            result = await token_scanner.check_token(address, chain_id=chain_id)
            _set_cache(cache_key, 'token', result)
            response = format_token_result(result)
            risk_level = result.get('safety_level', 'warning')

        keyboard = _token_buttons(address, chain_id)

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

    if query.data.startswith('chain_'):
        chain_id = int(query.data.replace('chain_', ''))
        context.user_data['chain_id'] = chain_id
        chain_name = get_chain_name(chain_id)
        await query.edit_message_text(
            f"Switched to {chain_name} (chain_id={chain_id}).\n"
            f"All scans will now target {chain_name}.",
        )
    elif query.data.startswith('token_'):
        address = query.data.replace('token_', '')
        user_chain_id = _get_user_chain_id(context)
        await query.message.reply_text(f"🔍 Running token safety check for `{address}`...", parse_mode='Markdown')
        await check_token(query, address, chain_id=user_chain_id)


def _scan_buttons(address: str, chain_id: int = 56) -> InlineKeyboardMarkup:
    """Generate action buttons for scan results."""
    explorer = get_explorer_url(chain_id)
    chain_name = get_chain_name(chain_id)
    keyboard = [
        [InlineKeyboardButton(f"🔍 View on {chain_name} Explorer", url=f"{explorer}/address/{address}")],
        [InlineKeyboardButton("💰 Check Token Safety", callback_data=f"token_{address}")]
    ]
    return InlineKeyboardMarkup(keyboard)


def _token_buttons(address: str, chain_id: int = 56) -> InlineKeyboardMarkup:
    """Generate action buttons for token results."""
    explorer = get_explorer_url(chain_id)
    dex_slug = get_dexscreener_slug(chain_id)
    chain_name = get_chain_name(chain_id)
    keyboard = [
        [InlineKeyboardButton(f"🔍 View on {chain_name} Explorer", url=f"{explorer}/token/{address}")],
        [InlineKeyboardButton("📊 View on DexScreener", url=f"https://dexscreener.com/{dex_slug}/{address}")]
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

    application = (
        Application.builder()
        .token(token)
        .post_init(post_init)
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
