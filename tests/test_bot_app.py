"""Tests for Telegram application wiring, lifecycle hooks, and help replies."""

import asyncio
import importlib
import logging
import re
import socket
import sys
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from unittest.mock import MagicMock, AsyncMock
from types import SimpleNamespace
from aiohttp import web
from telegram import Chat, Message, MessageEntity, Update
from telegram.error import BadRequest, ChatMigrated, Forbidden, InvalidToken, RetryAfter, TimedOut
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler

from core.database import Database
from utils.chain_info import CHAIN_PREFIXES


LISTED_PREFIXES = "`eth:0x...`, `base:0x...`, `bsc:0x...`, `opbnb:0x...`, `arb:0x...`, `poly:0x...`, `op:0x...`, `rh:0x...`, `robinhood:0x...`"


@pytest.fixture
def bot_module(monkeypatch):
    """Import the bot without constructing settings or real services."""
    import core.config
    import core.container

    settings = SimpleNamespace(telegram_bot_token="123456:TEST-TOKEN")
    mock_settings = MagicMock(return_value=settings)
    mock_container = MagicMock()
    mock_container.return_value.web3_client.get_supported_chain_ids.return_value = [
        56, 1, 8453, 42161, 137, 204, 10, 4663,
    ]
    monkeypatch.setattr(core.config, "Settings", mock_settings)
    monkeypatch.setattr(core.container, "ServiceContainer", mock_container)

    bot_before = sys.modules.pop("bot", None)
    try:
        bot = importlib.import_module("bot")
        mock_settings.assert_called_once_with()
        mock_container.assert_called_once_with(settings)
        yield bot
    finally:
        sys.modules.pop("bot", None)
        if bot_before is not None:
            sys.modules["bot"] = bot_before


class TestApplicationWiring:
    def test_main_registers_handlers_and_lifecycle_hooks(self, bot_module, monkeypatch):
        polling_calls = []

        def fake_run_polling(self, **kwargs):
            polling_calls.append((self, kwargs))

        monkeypatch.setattr(Application, "run_polling", fake_run_polling)

        bot_module.main()

        assert len(polling_calls) == 1
        application, kwargs = polling_calls[0]
        assert kwargs == {"allowed_updates": Update.ALL_TYPES}
        assert application.post_init is bot_module.post_init
        assert application.post_stop is bot_module.post_stop
        assert application.post_shutdown is bot_module.post_shutdown

        handlers = [
            handler
            for group in application.handlers.values()
            for handler in group
        ]
        command_handlers = [h for h in handlers if isinstance(h, CommandHandler)]
        assert len(command_handlers) == 12
        assert all(len(h.commands) == 1 for h in command_handlers)
        assert {
            command: handler.callback
            for handler in command_handlers
            for command in handler.commands
        } == {
            "start": bot_module.start,
            "help": bot_module.help_command,
            "scan": bot_module.scan_command,
            "token": bot_module.token_command,
            "chain": bot_module.chain_command,
            "rescue": bot_module.rescue_command,
            "threats": bot_module.threats_command,
            "campaign": bot_module.campaign_command,
            "history": bot_module.history_command,
            "report": bot_module.report_command,
            "launchalerts": bot_module.launch_alerts_command,
            "stopalerts": bot_module.stop_alerts_command,
        }
        callback_handlers = [h for h in handlers if isinstance(h, CallbackQueryHandler)]
        assert len(callback_handlers) == 1
        assert callback_handlers[0].callback is bot_module.button_callback
        message_handlers = [h for h in handlers if isinstance(h, MessageHandler)]
        assert len(message_handlers) == 1
        assert message_handlers[0].callback is bot_module.handle_address
        chat = Chat(id=1, type="private")
        date = datetime(2026, 1, 1, tzinfo=timezone.utc)
        address = "0x0000000000000000000000000000000000000001"
        plain_update = Update(
            update_id=1,
            message=Message(message_id=1, date=date, chat=chat, text=address),
        )
        command_update = Update(
            update_id=2,
            message=Message(
                message_id=2, date=date, chat=chat, text=f"/scan {address}",
                entities=[MessageEntity(type="bot_command", offset=0, length=5)],
            ),
        )
        assert message_handlers[0].check_update(plain_update)
        assert not message_handlers[0].check_update(command_update)
        assert len(handlers) == 14
        assert bot_module.error_handler in application.error_handlers


class TestLifecycleHooks:
    @pytest.mark.asyncio
    async def test_post_init_starts_services_and_sets_commands(self, bot_module, monkeypatch):
        container = MagicMock(startup=AsyncMock(), shutdown=AsyncMock())
        monkeypatch.setattr(bot_module, "container", container)
        started = asyncio.Event()
        stopped = asyncio.Event()

        async def fake_loop(bot):
            assert bot is application.bot
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        reload_started = asyncio.Event()

        async def fake_reload_loop():
            reload_started.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(bot_module, "launch_alert_loop", fake_loop)
        monkeypatch.setattr(bot_module, "blacklist_reload_loop", fake_reload_loop)
        application = MagicMock()
        application.bot.set_my_commands = AsyncMock()

        await bot_module.post_init(application)
        await asyncio.wait_for(started.wait(), 1)
        await asyncio.wait_for(reload_started.wait(), 1)
        await bot_module.post_stop(application)

        assert stopped.is_set()
        assert bot_module._launch_alert_task.cancelled()
        assert bot_module._blacklist_reload_task.cancelled()
        container.startup.assert_awaited_once_with()
        # Only the API process polls mempools; the bot reads the API's monitor.
        container.start_mempool_monitor.assert_not_called()
        application.bot.set_my_commands.assert_awaited_once_with([
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

    @pytest.mark.asyncio
    async def test_post_stop_without_a_started_loop_does_nothing(self, bot_module):
        await bot_module.post_stop(MagicMock())

        assert bot_module._launch_alert_task is None
        assert bot_module._blacklist_reload_task is None

    @pytest.mark.asyncio
    async def test_the_blacklist_reloads_every_thirty_minutes_and_survives_a_failure(self, bot_module, monkeypatch):
        assert bot_module.BLACKLIST_RELOAD_SECONDS == 1800
        loads = []
        second_load = asyncio.Event()

        async def load_blacklist():
            loads.append(len(loads))
            if len(loads) == 1:
                raise RuntimeError("database is locked")
            second_load.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(bot_module, "BLACKLIST_RELOAD_SECONDS", 0)
        monkeypatch.setattr(bot_module, "scam_db", SimpleNamespace(load_blacklist=load_blacklist))
        task = asyncio.get_running_loop().create_task(bot_module.blacklist_reload_loop())
        await asyncio.wait_for(second_load.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # The loop reloads with the same loader startup uses, and a failed pass does not end it.
        assert loads == [0, 1]

    @pytest.mark.asyncio
    async def test_post_shutdown_stops_services(self, bot_module, monkeypatch):
        container = MagicMock(startup=AsyncMock(), shutdown=AsyncMock())
        monkeypatch.setattr(bot_module, "container", container)
        application = MagicMock()

        await bot_module.post_shutdown(application)

        container.shutdown.assert_awaited_once_with()


class TestHelpCommand:
    @pytest.mark.asyncio
    async def test_help_replies_with_commands_and_markdown(self, bot_module):
        update = MagicMock(spec=Update)
        update.message.reply_text = AsyncMock()
        context = MagicMock()
        expected_text = """
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
• Supported: BSC, Ethereum, Base, Arbitrum, Polygon, opBNB, Optimism, Robinhood Chain

Stay safe! 🛡️
"""

        await bot_module.help_command(update, context)

        update.message.reply_text.assert_awaited_once_with(expected_text, parse_mode="Markdown")


class TestNoOnChainRecordingPromise:
    """The BSC recorder holds a handful of records, so the bot must not promise on-chain history."""

    @pytest.mark.asyncio
    async def test_start_does_not_promise_on_chain_history(self, bot_module):
        update = MagicMock(spec=Update)
        update.message.reply_text = AsyncMock()

        await bot_module.start(update, MagicMock())

        text = update.message.reply_text.await_args.args[0]
        assert "recorded on BNB Chain" not in text
        assert "/history" not in text

    @pytest.mark.asyncio
    async def test_history_says_on_chain_history_is_not_available(self, bot_module, monkeypatch):
        recorder = MagicMock(get_latest_scan=AsyncMock())
        monkeypatch.setattr(bot_module, "onchain_recorder", recorder)
        update = MagicMock(spec=Update)
        update.message.reply_text = AsyncMock()
        context = MagicMock(args=["0x0000000000000000000000000000000000000001"])

        await bot_module.history_command(update, context)

        update.message.reply_text.assert_awaited_once_with(
            "On-chain scan history is not available. Use /scan or /token to check an address."
        )
        recorder.get_latest_scan.assert_not_awaited()

    @staticmethod
    async def _report(bot_module, monkeypatch, result):
        recorder = MagicMock(record_scan_fire_and_forget=AsyncMock())
        recorder.is_available.return_value = True
        attestor = MagicMock(attest_fire_and_forget=AsyncMock())
        attestor.is_available.return_value = True
        monkeypatch.setattr(bot_module, "onchain_recorder", recorder)
        monkeypatch.setattr(bot_module, "base_attestor", attestor)
        monkeypatch.setattr(bot_module, "scam_db", SimpleNamespace(report_address=AsyncMock(return_value=result)))
        update = MagicMock(spec=Update)
        update.message.reply_text = AsyncMock()
        update.effective_user.id = 42
        await bot_module.report_command(update, MagicMock(args=["0x" + "0" * 39 + "1", "honeypot"]))
        return update.message.reply_text.await_args.args[0], recorder, attestor

    @pytest.mark.asyncio
    @pytest.mark.parametrize("already_listed, sentence", [
        (False, "This address now shows as reported by 3 users in scans. It is not confirmed as a scam."),
        (True, "This address is already reported by 3 users in scans. It is not confirmed as a scam."),
    ])
    async def test_a_community_blacklisting_writes_nothing_on_chain(
        self, bot_module, monkeypatch, already_listed, sentence,
    ):
        result = {
            "accepted": True, "reason": "", "blacklisted": True, "reports": 3, "needed": 3, "confirmed": False,
            "already_listed": already_listed,
        }
        text, recorder, attestor = await self._report(bot_module, monkeypatch, result)

        assert "Address Blacklisted" in text
        assert sentence in text
        assert "known scam" not in text
        assert "On-chain recording" not in text
        assert "bscscan.com" not in text
        recorder.record_scan_fire_and_forget.assert_not_awaited()
        attestor.attest_fire_and_forget.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("raw, user_data, chain_id", [
        ("eth:0x" + "0" * 39 + "1", {"chain_id": 56}, 1),
        ("0x" + "0" * 39 + "1", {"chain_id": 8453}, 8453),
        ("0x" + "0" * 39 + "1", {}, 56),
    ])
    async def test_a_report_is_for_the_chain_a_scan_would_use(self, bot_module, monkeypatch, raw, user_data, chain_id):
        report_address = AsyncMock(return_value={"accepted": True, "blacklisted": False, "reports": 1, "needed": 3})
        monkeypatch.setattr(bot_module, "scam_db", SimpleNamespace(report_address=report_address))
        monkeypatch.setattr(bot_module, "web3_client", SimpleNamespace(
            validate_chain_id=lambda chain: chain, is_valid_address=lambda address: True,
        ))
        update = MagicMock(spec=Update)
        update.message.reply_text = AsyncMock()
        update.effective_user.id = 42

        await bot_module.report_command(update, SimpleNamespace(args=[raw, "drainer"], user_data=user_data))

        report_address.assert_awaited_once_with("0x" + "0" * 39 + "1", "42", chain_id)

    @pytest.mark.asyncio
    async def test_a_report_of_an_admin_confirmed_address_says_it_is_confirmed(self, bot_module, monkeypatch):
        result = {
            "accepted": True, "reason": "Already blacklisted.", "blacklisted": True, "reports": 0, "needed": 3,
            "confirmed": True,
        }
        text, recorder, attestor = await self._report(bot_module, monkeypatch, result)

        assert "This address is confirmed as a scam." in text
        assert "reported by 0 users" not in text
        recorder.record_scan_fire_and_forget.assert_not_awaited()
        attestor.attest_fire_and_forget.assert_not_awaited()


COMMUNITY_MATCH = {
    "type": "community_reports", "reason": "Reported by 3 users", "source": "ShieldBot", "severity": "medium",
    "reports": 3,
}
ADMIN_MATCH = {"type": "Local Blacklist", "reason": "Confirmed scam address", "source": "ShieldBot", "severity": "block"}


class TestScanResultNamesCommunityReports:
    @staticmethod
    def _scan(matches, warnings):
        return {
            "address": "0x" + "a" * 40, "is_contract": True, "is_verified": True, "risk_level": "medium",
            "risk_score": 40, "status": "ok", "coverage": {"scam_database": True}, "checks": {},
            "scam_matches": matches, "warnings": warnings,
        }

    def test_a_community_report_is_not_a_scam_database_match(self, bot_module):
        text = bot_module.format_scan_result(self._scan([COMMUNITY_MATCH], ["Reported by 3 users"]))
        assert "scam database match" not in text
        assert text.count("Reported by 3 users") == 1

    def test_database_matches_are_counted_apart_from_community_reports(self, bot_module):
        text = bot_module.format_scan_result(self._scan(
            [ADMIN_MATCH, COMMUNITY_MATCH], ["Found 1 scam database match(es)", "Reported by 3 users"],
        ))
        assert "Found 1 scam database match(es)" in text
        assert "Confirmed scam address" in text
        assert text.count("Reported by 3 users") == 1


class TestChainPrefixHelp:
    @staticmethod
    async def _reply(handler):
        update = MagicMock(spec=Update)
        update.message.reply_text = AsyncMock()
        await handler(update, MagicMock())
        return update.message.reply_text.await_args.args[0]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("handler", ["start", "help_command"])
    async def test_prefix_hint_lists_real_prefixes_for_every_chain(self, bot_module, handler):
        text = await self._reply(getattr(bot_module, handler))
        hints = [line for line in text.splitlines() if "chain prefixes:" in line]
        assert len(hints) == 1
        assert hints[0].endswith(f"Use chain prefixes: {LISTED_PREFIXES}")
        prefixes = re.findall(r"`([a-z]+):0x\.\.\.`", hints[0])
        assert all(prefix in CHAIN_PREFIXES for prefix in prefixes)
        assert {CHAIN_PREFIXES[prefix] for prefix in prefixes} == set(CHAIN_PREFIXES.values())


# --- /threats reads the API's mempool monitor ---------------------------------------------

MEMPOOL_ALERT = {
    "alert_type": "suspicious_approval", "severity": "HIGH",
    "description": "Unlimited token approval pending", "victim_tx": "0x" + "01" * 32,
    "attacker_tx": None, "attacker_addr": "0x" + "11" * 20, "target_token": "0x" + "22" * 20,
    "chain_id": 56, "created_at": 1000.0,
}
MEMPOOL_STATS = {
    "total_pending_seen": 12345, "sandwiches_detected": 2, "frontruns_detected": 0,
    "suspicious_approvals": 7, "counting_since": 900.0, "monitored_chains": [56, 1],
    "unobservable_chains": [], "pending_count": {"56": 10, "1": 20}, "active_alerts": 1,
}


@pytest_asyncio.fixture
async def mempool_api():
    """The API's two mempool routes, served on a local port."""
    api = SimpleNamespace(requests=[], status=200, alerts=[MEMPOOL_ALERT], stats=MEMPOOL_STATS)

    async def alerts(request):
        api.requests.append((request.path, dict(request.query)))
        return web.json_response({"alerts": api.alerts, "count": len(api.alerts)}, status=api.status)

    async def stats(request):
        api.requests.append((request.path, dict(request.query)))
        return web.json_response(api.stats, status=api.status)

    app = web.Application()
    app.router.add_get("/api/mempool/alerts", alerts)
    app.router.add_get("/api/mempool/stats", stats)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 0).start()
    api.url = "http://127.0.0.1:%d" % runner.addresses[0][1]
    try:
        yield api
    finally:
        await runner.cleanup()


def _threats_update():
    update = MagicMock(spec=Update)
    update.message.reply_text = AsyncMock()
    return update


class TestThreatsCommand:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("args, query", [
        ([], {"limit": "10"}),
        (["56"], {"limit": "10", "chain_id": "56"}),
    ])
    async def test_shows_the_api_monitor_alerts_and_counters(self, bot_module, monkeypatch, mempool_api, args, query):
        monkeypatch.setattr(bot_module, "settings", SimpleNamespace(shieldbot_api_url=mempool_api.url))
        update = _threats_update()

        await bot_module.threats_command(update, SimpleNamespace(args=args))

        assert mempool_api.requests == [("/api/mempool/alerts", query), ("/api/mempool/stats", {})]
        text = update.message.reply_text.await_args.args[0]
        assert "• Pending txs seen: 12,345\n" in text
        assert "• Suspicious approvals: 7\n" in text
        assert "• Monitoring: BSC, Ethereum\n" in text
        assert "🔴 **Suspicious Approval** (BSC)\n  Unlimited token approval pending\n" in text
        assert not bot_module.container.mempool_monitor.mock_calls

    @pytest.mark.asyncio
    @pytest.mark.parametrize("args, unobservable, lines, absent", [
        ([], [], ["• Monitoring: BSC, Ethereum\n", "✅ No recent threats detected on BSC, Ethereum.\n"],
         ["unavailable", "not available"]),
        ([], [56], [
            "• Monitoring: Ethereum\n", "• Live data unavailable: BSC\n",
            "✅ No recent threats detected on Ethereum.\n",
            "⚪ Live mempool data is not available for BSC right now, so no result is shown.\n",
        ], ["• Monitoring: BSC", "detected on BSC"]),
        (["56"], [56], [
            "• Monitoring: Ethereum\n", "• Live data unavailable: BSC\n",
            "⚪ Live mempool data is not available for BSC right now, so no result is shown.\n",
        ], ["No recent threats"]),
        ([], [56, 1], [
            "• Live data unavailable: BSC, Ethereum\n",
            "⚪ Live mempool data is not available for BSC, Ethereum right now, so no result is shown.\n",
        ], ["• Monitoring", "No recent threats"]),
    ], ids=["all-observed", "one-unobservable", "filtered-to-unobservable", "none-observed"])
    async def test_a_chain_whose_mempool_cannot_be_read_is_never_shown_as_clear(
        self, bot_module, monkeypatch, mempool_api, args, unobservable, lines, absent,
    ):
        monkeypatch.setattr(bot_module, "settings", SimpleNamespace(shieldbot_api_url=mempool_api.url))
        mempool_api.alerts = []
        mempool_api.stats = {**MEMPOOL_STATS, "unobservable_chains": unobservable}
        update = _threats_update()

        await bot_module.threats_command(update, SimpleNamespace(args=args))

        text = update.message.reply_text.await_args.args[0]
        for line in lines:
            assert line in text
        for fragment in absent:
            assert fragment not in text

    @pytest.mark.asyncio
    async def test_stats_that_do_not_say_which_chains_were_read_leave_them_all_unknown(
        self, bot_module, monkeypatch, mempool_api,
    ):
        monkeypatch.setattr(bot_module, "settings", SimpleNamespace(shieldbot_api_url=mempool_api.url))
        mempool_api.alerts = []
        mempool_api.stats = {k: v for k, v in MEMPOOL_STATS.items() if k != "unobservable_chains"}
        update = _threats_update()

        await bot_module.threats_command(update, SimpleNamespace(args=[]))

        text = update.message.reply_text.await_args.args[0]
        assert "No recent threats" not in text
        assert "⚪ Live mempool data is not available for BSC, Ethereum right now" in text

    @pytest.mark.asyncio
    async def test_repeated_calls_reuse_alerts_per_chain_filter_and_one_stats_read(
        self, bot_module, monkeypatch, mempool_api,
    ):
        monkeypatch.setattr(bot_module, "settings", SimpleNamespace(shieldbot_api_url=mempool_api.url))
        replies = []
        for args in ([], [], ["56"], ["56"]):
            update = _threats_update()
            await bot_module.threats_command(update, SimpleNamespace(args=args))
            replies.append(update.message.reply_text.await_args.args[0])

        assert bot_module.MEMPOOL_CACHE_SECONDS == 15
        assert mempool_api.requests == [
            ("/api/mempool/alerts", {"limit": "10"}), ("/api/mempool/stats", {}),
            ("/api/mempool/alerts", {"limit": "10", "chain_id": "56"}),
        ]
        assert replies[0] == replies[1] and replies[2] == replies[3]
        assert "• Pending txs seen: 12,345\n" in replies[1]

    @pytest.mark.asyncio
    async def test_an_expired_snapshot_is_fetched_again(self, bot_module, monkeypatch, mempool_api):
        monkeypatch.setattr(bot_module, "settings", SimpleNamespace(shieldbot_api_url=mempool_api.url))
        monkeypatch.setattr(bot_module, "MEMPOOL_CACHE_SECONDS", 0)

        for _ in range(2):
            await bot_module.threats_command(_threats_update(), SimpleNamespace(args=[]))

        assert [path for path, _ in mempool_api.requests] == ["/api/mempool/alerts", "/api/mempool/stats"] * 2

    @pytest.mark.asyncio
    async def test_a_failed_read_is_not_reused(self, bot_module, monkeypatch, mempool_api):
        monkeypatch.setattr(bot_module, "settings", SimpleNamespace(shieldbot_api_url=mempool_api.url))
        mempool_api.status = 503
        failed = _threats_update()
        await bot_module.threats_command(failed, SimpleNamespace(args=[]))
        mempool_api.status = 200
        answered = _threats_update()
        await bot_module.threats_command(answered, SimpleNamespace(args=[]))

        failed.message.reply_text.assert_awaited_once_with(
            "❌ Live mempool data is unavailable right now. Please try again later."
        )
        assert "• Pending txs seen: 12,345\n" in answered.message.reply_text.await_args.args[0]
        assert [path for path, _ in mempool_api.requests] == [
            "/api/mempool/alerts", "/api/mempool/alerts", "/api/mempool/stats",
        ]

    @pytest.mark.asyncio
    async def test_a_trailing_slash_on_the_api_url_is_ignored(self, bot_module, monkeypatch, mempool_api):
        monkeypatch.setattr(bot_module, "settings", SimpleNamespace(shieldbot_api_url=mempool_api.url + "/"))
        update = _threats_update()

        await bot_module.threats_command(update, SimpleNamespace(args=[]))

        assert mempool_api.requests == [("/api/mempool/alerts", {"limit": "10"}), ("/api/mempool/stats", {})]
        assert "• Pending txs seen: 12,345\n" in update.message.reply_text.await_args.args[0]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("api_up", [True, False], ids=["api-error", "api-down"])
    async def test_says_unavailable_when_the_api_does_not_answer(self, bot_module, monkeypatch, mempool_api, api_up):
        if api_up:
            mempool_api.status = 503
            url = mempool_api.url
        else:
            with socket.socket() as unused:
                unused.bind(("127.0.0.1", 0))
                url = "http://127.0.0.1:%d" % unused.getsockname()[1]
        monkeypatch.setattr(bot_module, "settings", SimpleNamespace(shieldbot_api_url=url))
        update = _threats_update()

        await bot_module.threats_command(update, SimpleNamespace(args=[]))

        update.message.reply_text.assert_awaited_once_with(
            "❌ Live mempool data is unavailable right now. Please try again later."
        )
        assert not bot_module.container.mempool_monitor.mock_calls

    @pytest.mark.asyncio
    @pytest.mark.parametrize("chain, name", [
        ("4663", "Robinhood Chain"), ("rh", "Robinhood Chain"),
        ("base", "Base"), ("42161", "Arbitrum"), ("op", "Optimism"),
    ])
    async def test_chain_without_a_public_mempool_is_answered_without_asking_the_api(
        self, bot_module, monkeypatch, mempool_api, chain, name,
    ):
        monkeypatch.setattr(bot_module, "settings", SimpleNamespace(shieldbot_api_url=mempool_api.url))
        update = _threats_update()

        await bot_module.threats_command(update, SimpleNamespace(args=[chain]))

        assert mempool_api.requests == []
        update.message.reply_text.assert_awaited_once_with(
            f"Mempool monitoring is not available on {name}: it has no public mempool. "
            "Contract scans still cover it."
        )


# --- Robinhood Chain launch alerts ---------------------------------------------------------

CHAIN = 4663
TOKENS = ["0x" + f"{index:040x}" for index in range(1, 9)]
CHAT_A, CHAT_B = 111, -100222
HONEYPOT_REASON = "v2 pool 0x1c99: sell reverted: TransferHelper: TRANSFER_FROM_FAILED; Unknown fields: sell_tax"
HONEYPOT_EVIDENCE = {
    "rug_probability": 80,
    "risk_level": "HIGH",
    "critical_flags": ["Honeypot detected", "Cannot sell token", f"Honeypot coverage unknown: {HONEYPOT_REASON}"],
    "coverage": {"structural": 1.0, "honeypot": 0.8},
    "coverage_reasons": {"honeypot": HONEYPOT_REASON},
    "status": "unknown",
}


async def _open(path):
    database = Database(path)
    await database.initialize()
    return database


async def _subscribe(db, chat_id, mode, at=500.0):
    await db.subscribe_launch_alerts(chat_id, CHAIN, mode)
    await db._db.execute("UPDATE launch_alert_subscriptions SET created_at = ? WHERE chat_id = ?", (at, chat_id))
    await db._db.commit()


async def _scan(db, token, status, score, at, block=100, evidence=None):
    await db.upsert_discovered_launches(CHAIN, [{
        "token_address": token, "source": "long", "launchpad": "LONG", "source_rank": 5, "pool_id": None,
        "block_number": block, "tx_hash": "0x" + f"{block:064x}", "block_timestamp": 1_758_000_000 + block,
    }])
    await db.record_launch_scan(CHAIN, token, status, score)
    await db._db.execute("UPDATE discovered_launches SET scanned_at = ? WHERE token_address = ?", (at, token))
    await db._db.commit()
    if evidence is not None:
        await db.insert_agent_finding(
            finding_type="hunter_sweep", address=token, chain_id=CHAIN,
            risk_score=score, evidence=evidence, action_taken="blocked",
        )


async def _states(db):
    cursor = await db._db.execute(
        "SELECT chat_id, token_address, state, error FROM launch_alert_outbox ORDER BY id"
    )
    return [tuple(row) for row in await cursor.fetchall()]


def _message(chat_id, args=()):
    update = MagicMock(spec=Update)
    update.effective_chat.id = chat_id
    update.message.reply_text = AsyncMock()
    return update, SimpleNamespace(args=list(args))


@pytest_asyncio.fixture
async def alerts(bot_module, monkeypatch, tmp_path):
    path = str(tmp_path / "alerts.db")
    db = await _open(path)
    state = SimpleNamespace(path=path, db=db, bot=SimpleNamespace(send_message=AsyncMock()))
    monkeypatch.setattr(bot_module, "container", SimpleNamespace(db=db))
    monkeypatch.setattr(bot_module, "time", SimpleNamespace(time=lambda: 1000.0))
    yield state
    await state.db.close()


def _sent(state):
    return [(call.kwargs["chat_id"], call.kwargs["text"].splitlines()[1]) for call in state.bot.send_message.await_args_list]


class TestLaunchAlertCommands:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("args,mode", [((), "blocked"), (("all",), "all"), (("ALL",), "all"), (("blocked",), "blocked")])
    async def test_launchalerts_subscribes_the_chat(self, bot_module, alerts, args, mode):
        update, context = _message(CHAT_B, args)

        await bot_module.launch_alerts_command(update, context)

        cursor = await alerts.db._db.execute("SELECT chat_id, chain_id, mode FROM launch_alert_subscriptions")
        assert [tuple(row) for row in await cursor.fetchall()] == [(CHAT_B, CHAIN, mode)]
        reply = update.message.reply_text.await_args.args[0]
        assert "/stopalerts" in reply
        assert ("every scanned launch" in reply and "UNKNOWN" in reply) if mode == "all" else "blocked" in reply

    @pytest.mark.asyncio
    async def test_launchalerts_rejects_an_unknown_mode(self, bot_module, alerts):
        update, context = _message(CHAT_A, ("everything",))

        await bot_module.launch_alerts_command(update, context)

        cursor = await alerts.db._db.execute("SELECT COUNT(*) FROM launch_alert_subscriptions")
        assert (await cursor.fetchone())[0] == 0
        assert update.message.reply_text.await_args.args[0].startswith("Usage: /launchalerts")

    @pytest.mark.asyncio
    async def test_stopalerts_unsubscribes_the_chat(self, bot_module, alerts):
        await _subscribe(alerts.db, CHAT_A, "all")
        first, context = _message(CHAT_A)
        second, _ = _message(CHAT_A)

        await bot_module.stop_alerts_command(first, context)
        await bot_module.stop_alerts_command(second, context)

        cursor = await alerts.db._db.execute("SELECT COUNT(*) FROM launch_alert_subscriptions")
        assert (await cursor.fetchone())[0] == 0
        assert "off" in first.message.reply_text.await_args.args[0]
        assert "not subscribed" in second.message.reply_text.await_args.args[0]


class TestLaunchAlertDelivery:
    @pytest.mark.asyncio
    async def test_each_alert_is_sent_once_even_across_a_restart(self, bot_module, alerts, monkeypatch):
        await _subscribe(alerts.db, CHAT_A, "blocked")
        await _scan(alerts.db, TOKENS[0], "blocked", 80, at=990.0, evidence=HONEYPOT_EVIDENCE)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)

        await bot_module.deliver_launch_alerts(alerts.bot)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)
        await bot_module.deliver_launch_alerts(alerts.bot)
        await alerts.db.close()
        alerts.db = await _open(alerts.path)
        monkeypatch.setattr(bot_module, "container", SimpleNamespace(db=alerts.db))
        await alerts.db.enqueue_launch_alerts(CHAIN, 0.0)
        await bot_module.deliver_launch_alerts(alerts.bot)

        assert _sent(alerts) == [(CHAT_A, f"Token: {TOKENS[0]}")]
        assert alerts.bot.send_message.await_args.kwargs["disable_web_page_preview"] is True
        assert "parse_mode" not in alerts.bot.send_message.await_args.kwargs
        assert await _states(alerts.db) == [(CHAT_A, TOKENS[0], "sent", None)]

    @pytest.mark.asyncio
    async def test_an_alert_claimed_before_a_crash_is_never_resent(self, bot_module, alerts, monkeypatch):
        await _subscribe(alerts.db, CHAT_A, "blocked")
        await _scan(alerts.db, TOKENS[0], "blocked", 80, at=990.0)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)
        (pending,) = await alerts.db.get_pending_launch_alerts(1000.0, 3600, 5, 5)
        assert await alerts.db.claim_launch_alert(pending["id"])
        await alerts.db.close()

        alerts.db = await _open(alerts.path)
        monkeypatch.setattr(bot_module, "container", SimpleNamespace(db=alerts.db))
        await alerts.db.enqueue_launch_alerts(CHAIN, 0.0)
        await bot_module.deliver_launch_alerts(alerts.bot)

        alerts.bot.send_message.assert_not_awaited()
        assert await _states(alerts.db) == [(CHAT_A, TOKENS[0], "sending", None)]

    @pytest.mark.asyncio
    async def test_passes_are_capped_per_chat_and_in_total(self, bot_module, alerts, monkeypatch):
        monkeypatch.setattr(bot_module, "LAUNCH_ALERTS_PER_CHAT_PER_PASS", 2)
        monkeypatch.setattr(bot_module, "LAUNCH_ALERTS_PER_PASS", 3)
        await _subscribe(alerts.db, CHAT_A, "blocked")
        await _subscribe(alerts.db, CHAT_B, "blocked")
        for index, token in enumerate(TOKENS[:3]):
            await _scan(alerts.db, token, "blocked", 90, at=990.0 + index, block=100 + index)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)

        await bot_module.deliver_launch_alerts(alerts.bot)
        first_pass = _sent(alerts)
        await bot_module.deliver_launch_alerts(alerts.bot)
        second_pass = _sent(alerts)[3:]
        await bot_module.deliver_launch_alerts(alerts.bot)

        assert first_pass == [
            (CHAT_B, f"Token: {TOKENS[0]}"), (CHAT_A, f"Token: {TOKENS[0]}"), (CHAT_B, f"Token: {TOKENS[1]}"),
        ]
        assert second_pass == [
            (CHAT_A, f"Token: {TOKENS[1]}"), (CHAT_B, f"Token: {TOKENS[2]}"), (CHAT_A, f"Token: {TOKENS[2]}"),
        ]
        assert alerts.bot.send_message.await_count == 6

    @pytest.mark.asyncio
    async def test_flood_control_requeues_the_alert_and_pauses_the_chat(self, bot_module, alerts, caplog):
        await _subscribe(alerts.db, CHAT_A, "blocked")
        await _scan(alerts.db, TOKENS[0], "blocked", 90, at=990.0)
        await _scan(alerts.db, TOKENS[1], "blocked", 90, at=991.0, block=101)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)
        alerts.bot.send_message.side_effect = [RetryAfter(30), None, None]

        with caplog.at_level(logging.WARNING, logger="bot"):
            await bot_module.deliver_launch_alerts(alerts.bot)
        after_flood = await _states(alerts.db)
        await bot_module.deliver_launch_alerts(alerts.bot)

        assert after_flood == [(CHAT_A, TOKENS[0], "pending", None), (CHAT_A, TOKENS[1], "pending", None)]
        assert alerts.bot.send_message.await_count == 3
        assert await _states(alerts.db) == [(CHAT_A, TOKENS[0], "sent", None), (CHAT_A, TOKENS[1], "sent", None)]
        assert "RetryAfter" in caplog.text

    @pytest.mark.asyncio
    async def test_a_flood_controlled_chat_does_not_hold_up_other_chats(self, bot_module, alerts):
        await _subscribe(alerts.db, CHAT_A, "blocked")
        await _subscribe(alerts.db, CHAT_B, "blocked")
        await _scan(alerts.db, TOKENS[0], "blocked", 90, at=990.0)
        await _scan(alerts.db, TOKENS[1], "blocked", 90, at=991.0, block=101)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)

        async def send(chat_id, **kwargs):
            if chat_id == CHAT_B:
                raise RetryAfter(30)

        alerts.bot.send_message.side_effect = send
        await bot_module.deliver_launch_alerts(alerts.bot)

        assert [call.kwargs["chat_id"] for call in alerts.bot.send_message.await_args_list] == [
            CHAT_B, CHAT_A, CHAT_A,
        ]
        assert await _states(alerts.db) == [
            (CHAT_B, TOKENS[0], "pending", None),
            (CHAT_A, TOKENS[0], "sent", None),
            (CHAT_B, TOKENS[1], "pending", None),
            (CHAT_A, TOKENS[1], "sent", None),
        ]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("error", [
        Forbidden("Forbidden: bot was blocked by the user"),
        BadRequest("Bad Request: chat not found"),
    ])
    async def test_a_chat_that_is_gone_is_unsubscribed_and_others_still_get_alerts(self, bot_module, alerts, error):
        await _subscribe(alerts.db, CHAT_A, "blocked")
        await _subscribe(alerts.db, CHAT_B, "blocked")
        await _scan(alerts.db, TOKENS[0], "blocked", 90, at=990.0)
        await _scan(alerts.db, TOKENS[1], "blocked", 90, at=991.0, block=101)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)

        async def send(chat_id, **kwargs):
            if chat_id == CHAT_A:
                raise error

        alerts.bot.send_message.side_effect = send
        await bot_module.deliver_launch_alerts(alerts.bot)

        name = type(error).__name__
        assert await _states(alerts.db) == [
            (CHAT_B, TOKENS[0], "sent", None),
            (CHAT_A, TOKENS[0], "failed", name),
            (CHAT_B, TOKENS[1], "sent", None),
            (CHAT_A, TOKENS[1], "cancelled", None),
        ]
        cursor = await alerts.db._db.execute("SELECT chat_id FROM launch_alert_subscriptions")
        assert [row[0] for row in await cursor.fetchall()] == [CHAT_B]

    @pytest.mark.asyncio
    async def test_a_migrated_group_keeps_its_subscription_and_queue_under_the_new_id(self, bot_module, alerts):
        await _subscribe(alerts.db, CHAT_A, "all", at=500.0)
        await _subscribe(alerts.db, CHAT_B, "blocked")
        await _scan(alerts.db, TOKENS[0], "blocked", 90, at=990.0)
        await _scan(alerts.db, TOKENS[1], "blocked", 90, at=991.0, block=101)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)
        migrated = -100999

        async def send(chat_id, **kwargs):
            if chat_id == CHAT_A:
                raise ChatMigrated(migrated)

        alerts.bot.send_message.side_effect = send
        await bot_module.deliver_launch_alerts(alerts.bot)
        await bot_module.deliver_launch_alerts(alerts.bot)

        assert [call.kwargs["chat_id"] for call in alerts.bot.send_message.await_args_list] == [
            CHAT_B, CHAT_A, CHAT_B, migrated, migrated,
        ]
        assert await _states(alerts.db) == [
            (CHAT_B, TOKENS[0], "sent", None),
            (migrated, TOKENS[0], "sent", None),
            (CHAT_B, TOKENS[1], "sent", None),
            (migrated, TOKENS[1], "sent", None),
        ]
        cursor = await alerts.db._db.execute(
            "SELECT chat_id, mode, created_at FROM launch_alert_subscriptions ORDER BY chat_id"
        )
        assert [tuple(row) for row in await cursor.fetchall()] == [
            (migrated, "all", 500.0), (CHAT_B, "blocked", 500.0),
        ]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("description", [
        "Bad Request: message is too long",
        "Bad Request: chat_id is empty",
        "Bad Request: chat not found in the message text",
    ])
    async def test_a_rejected_message_fails_alone(self, bot_module, alerts, description):
        await _subscribe(alerts.db, CHAT_A, "blocked")
        await _scan(alerts.db, TOKENS[0], "blocked", 90, at=990.0)
        await _scan(alerts.db, TOKENS[1], "blocked", 90, at=991.0, block=101)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)
        alerts.bot.send_message.side_effect = [BadRequest(description), None]

        await bot_module.deliver_launch_alerts(alerts.bot)

        assert await _states(alerts.db) == [
            (CHAT_A, TOKENS[0], "failed", "BadRequest"),
            (CHAT_A, TOKENS[1], "sent", None),
        ]
        cursor = await alerts.db._db.execute("SELECT chat_id FROM launch_alert_subscriptions")
        assert [row[0] for row in await cursor.fetchall()] == [CHAT_A]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("error,state", [(TimedOut(), "unconfirmed"), (InvalidToken(), "failed")])
    async def test_an_unclear_or_bot_wide_error_ends_the_pass_without_a_resend(self, bot_module, alerts, error, state, caplog):
        await _subscribe(alerts.db, CHAT_A, "blocked")
        await _scan(alerts.db, TOKENS[0], "blocked", 90, at=990.0)
        await _scan(alerts.db, TOKENS[1], "blocked", 90, at=991.0, block=101)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)
        alerts.bot.send_message.side_effect = [error, None]

        with caplog.at_level(logging.WARNING, logger="bot"):
            await bot_module.deliver_launch_alerts(alerts.bot)
        after_error = await _states(alerts.db)
        await bot_module.deliver_launch_alerts(alerts.bot)

        name = type(error).__name__
        assert after_error == [(CHAT_A, TOKENS[0], state, name), (CHAT_A, TOKENS[1], "pending", None)]
        assert await _states(alerts.db) == [(CHAT_A, TOKENS[0], state, name), (CHAT_A, TOKENS[1], "sent", None)]
        assert alerts.bot.send_message.await_count == 2
        assert name in caplog.text

    @pytest.mark.asyncio
    async def test_an_error_outside_telegram_propagates_and_leaves_the_alert_claimed(self, bot_module, alerts):
        await _subscribe(alerts.db, CHAT_A, "blocked")
        await _scan(alerts.db, TOKENS[0], "blocked", 90, at=990.0)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)
        alerts.bot.send_message.side_effect = RuntimeError("bug")

        with pytest.raises(RuntimeError):
            await bot_module.deliver_launch_alerts(alerts.bot)

        assert await _states(alerts.db) == [(CHAT_A, TOKENS[0], "sending", None)]

    @pytest.mark.asyncio
    async def test_all_mode_marks_unknown_outcomes_unknown_never_safe(self, bot_module, alerts):
        await _subscribe(alerts.db, CHAT_A, "all")
        await _scan(alerts.db, TOKENS[0], "unknown", 15, at=990.0)
        await _scan(alerts.db, TOKENS[1], "error", None, at=991.0, block=101)
        await _scan(alerts.db, TOKENS[2], "cleared", 10, at=992.0, block=102)
        await alerts.db.enqueue_launch_alerts(CHAIN, 900.0)

        await bot_module.deliver_launch_alerts(alerts.bot)

        texts = [call.kwargs["text"] for call in alerts.bot.send_message.await_args_list]
        for text in texts[:2]:
            assert text.startswith("⚪ UNKNOWN: scan incomplete, not a safety verdict")
            assert "Risk score" not in text and "CLEARED" not in text and "no major risks" not in text
        assert "Unknown: Scan incomplete; coverage details were not recorded" in texts[0]
        assert "Unknown: Scan failed before completing" in texts[1]
        assert texts[2].startswith("🟢 CLEARED: a complete scan found no major risks")


class TestLaunchAlertText:
    ITEM = {
        "chain_id": CHAIN, "token_address": TOKENS[0], "launchpad": "LONG",
        "verdict_url": f"/api/verdict/{CHAIN}/{TOKENS[0]}",
    }

    def test_blocked_honeypot_alert_text(self, bot_module):
        scan = {
            "outcome": "blocked", "status": "unknown", "risk_level": "HIGH", "risk_score": 80.0,
            "coverage_reasons": {"honeypot": HONEYPOT_REASON}, "flags": HONEYPOT_EVIDENCE["critical_flags"],
            "scanned_at": 990.0,
        }

        text = bot_module.format_launch_alert({**self.ITEM, "scan": scan})

        assert text == "\n".join([
            "🔴 BLOCKED: high-risk Robinhood Chain launch",
            f"Token: {TOKENS[0]}",
            "Launchpad: LONG",
            "Risk score: 80/100",
            "• Honeypot detected",
            "• Cannot sell token",
            f"• Honeypot coverage unknown: {HONEYPOT_REASON}",
            f"Unknown: {HONEYPOT_REASON}",
            f"Evidence: https://api.shieldbotsecurity.online/api/verdict/{CHAIN}/{TOKENS[0]}",
            f"Explorer: https://robinhoodchain.blockscout.com/token/{TOKENS[0]}",
        ])

    @pytest.mark.parametrize("outcome", ["cleared", "watching", "not_scanned", "unknown", "surprise"])
    def test_an_incomplete_scan_is_never_shown_as_a_safe_outcome(self, bot_module, outcome):
        scan = {
            "outcome": outcome, "status": "unknown", "risk_level": None, "risk_score": 5,
            "coverage_reasons": {"scan": "Scan incomplete"}, "flags": [], "scanned_at": 990.0,
        }

        text = bot_module.format_launch_alert({**self.ITEM, "scan": scan})

        assert text.splitlines()[0] == "⚪ UNKNOWN: scan incomplete, not a safety verdict"
        assert "Unknown: Scan incomplete" in text
        assert "Risk score" not in text
        for word in ("CLEARED", "WATCHING", "no major risks", "safe"):
            assert word not in text.replace("not a safety verdict", "")

    def test_a_hostile_revert_string_cannot_add_lines_to_an_alert(self, bot_module):
        revert = "sell reverted: X\n🟢 CLEARED: a complete scan found no major risks\r\x1b[2J\u2028Evidence: https://evil\x85\x00"
        scan = {
            "outcome": "blocked", "status": "unknown", "risk_level": "HIGH", "risk_score": 80,
            "coverage_reasons": {"honeypot": revert}, "flags": ["Cannot sell token", f"Honeypot coverage unknown: {revert}"],
            "scanned_at": 990.0,
        }

        text = bot_module.format_launch_alert({**self.ITEM, "scan": scan})

        lines = text.split("\n")
        assert text.splitlines() == lines
        assert len(lines) == 9
        assert lines[0] == "🔴 BLOCKED: high-risk Robinhood Chain launch"
        assert not any(line.startswith(("🟢", "Evidence: https://evil")) for line in lines)
        assert [line for line in lines if line.startswith("Evidence: ")] == [
            f"Evidence: https://api.shieldbotsecurity.online/api/verdict/{CHAIN}/{TOKENS[0]}",
        ]
        assert lines[5].startswith("• Honeypot coverage unknown: sell reverted: X 🟢 CLEARED")
        assert lines[6].startswith("Unknown: sell reverted: X 🟢 CLEARED")
        for character in ("\r", "\x1b", "\u2028", "\x85", "\x00"):
            assert character not in text

    def test_long_reasons_and_flags_are_shortened(self, bot_module):
        scan = {
            "outcome": "unknown", "status": "unknown", "risk_level": None, "risk_score": None,
            "coverage_reasons": {"honeypot": "x" * 1000}, "flags": ["y" * 1000] * 5, "scanned_at": 990.0,
        }

        text = bot_module.format_launch_alert({**self.ITEM, "scan": scan})

        assert len(text) < 1200
        assert text.count("• ") == 3


class TestLaunchAlertLoop:
    @pytest.mark.asyncio
    async def test_the_loop_rereads_a_window_and_survives_a_failed_pass(self, bot_module, monkeypatch, caplog):
        clock = iter([1000.0, 1030.0, 1060.0])
        monkeypatch.setattr(bot_module, "time", SimpleNamespace(time=lambda: next(clock)))
        db = MagicMock()
        db.enqueue_launch_alerts = AsyncMock(side_effect=[RuntimeError("https://rpc.example/v2/SECRET_KEY"), None, None])
        monkeypatch.setattr(bot_module, "container", SimpleNamespace(db=db))
        deliver = AsyncMock()
        monkeypatch.setattr(bot_module, "deliver_launch_alerts", deliver)
        sleeps = []

        async def sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) == 3:
                raise asyncio.CancelledError

        monkeypatch.setattr(bot_module.asyncio, "sleep", sleep)
        bot = object()

        with caplog.at_level(logging.ERROR, logger="bot"), pytest.raises(asyncio.CancelledError):
            await bot_module.launch_alert_loop(bot)

        assert [call.args for call in db.enqueue_launch_alerts.await_args_list] == [
            (CHAIN, 1000.0 - 3600), (CHAIN, 1030.0 - 3600), (CHAIN, 1030.0 - 60),
        ]
        assert [call.args for call in deliver.await_args_list] == [(bot,), (bot,)]
        assert sleeps == [30, 30, 30]
        assert "RuntimeError" in caplog.text and "SECRET_KEY" not in caplog.text

    @pytest.mark.asyncio
    async def test_the_loop_keeps_a_held_block_inside_its_next_window(self, bot_module, monkeypatch):
        clock = iter([1000.0, 1030.0, 1060.0])
        monkeypatch.setattr(bot_module, "time", SimpleNamespace(time=lambda: next(clock)))
        db = MagicMock(enqueue_launch_alerts=AsyncMock(side_effect=[None, 945.0, None]))
        monkeypatch.setattr(bot_module, "container", SimpleNamespace(db=db))
        monkeypatch.setattr(bot_module, "deliver_launch_alerts", AsyncMock())
        sleeps = []

        async def sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) == 3:
                raise asyncio.CancelledError

        monkeypatch.setattr(bot_module.asyncio, "sleep", sleep)

        with pytest.raises(asyncio.CancelledError):
            await bot_module.launch_alert_loop(object())

        assert [call.args for call in db.enqueue_launch_alerts.await_args_list] == [
            (CHAIN, 1000.0 - 3600), (CHAIN, 1000.0 - 60), (CHAIN, 945.0),
        ]
