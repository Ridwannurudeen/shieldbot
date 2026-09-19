"""Tests for Telegram application wiring, lifecycle hooks, and help replies."""

import importlib
import re
import sys
from datetime import datetime, timezone

import pytest
from unittest.mock import MagicMock, AsyncMock
from types import SimpleNamespace
from telegram import Chat, Message, MessageEntity, Update
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler

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
        assert application.post_shutdown is bot_module.post_shutdown

        handlers = [
            handler
            for group in application.handlers.values()
            for handler in group
        ]
        command_handlers = [h for h in handlers if isinstance(h, CommandHandler)]
        assert len(command_handlers) == 10
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
        assert len(handlers) == 12
        assert bot_module.error_handler in application.error_handlers


class TestLifecycleHooks:
    @pytest.mark.asyncio
    async def test_post_init_starts_services_and_sets_commands(self, bot_module, monkeypatch):
        container = MagicMock(startup=AsyncMock(), shutdown=AsyncMock())
        monkeypatch.setattr(bot_module, "container", container)
        application = MagicMock()
        application.bot.set_my_commands = AsyncMock()

        await bot_module.post_init(application)

        container.startup.assert_awaited_once_with()
        application.bot.set_my_commands.assert_awaited_once_with([
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
**/history <address>** - View on-chain scan history
**/report <address> <reason>** - Report a scam address
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
