"""An address without a chain prefix asks which chain it is on; a prefix, or a tap on the picker, scans that chain.

Every report names the chain its scan ran on.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from telegram import Update
from telegram.error import BadRequest, TelegramError

from core.telegram_formatter import format_full_report
from tests.test_bot_app import bot_module  # noqa: F401  (pytest fixture)
from tests.test_telegram_markdown import assert_literal, parse_legacy_markdown
from utils.web3_client import Web3Client

ADDRESS = "0x" + "a" * 40
# ADDRESS checksummed, with the case of its first letter flipped: not a valid checksum.
BAD_CHECKSUM = "0xAAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
HOSTILE_ADDRESS = "0x`[Claim](https://evil.example)`aaaa"
# The order core.container registers the adapters in.
REGISTERED = [56, 1, 8453, 42161, 137, 204, 10, 4663]
# The product's order, which the picker uses.
CANONICAL = [
    (1, "Ethereum"),
    (56, "BSC"),
    (204, "opBNB"),
    (8453, "Base"),
    (42161, "Arbitrum"),
    (137, "Polygon"),
    (10, "Optimism"),
    (4663, "Robinhood Chain"),
]
INVALID = "\N{CROSS MARK} Invalid address format."
UNSUPPORTED = f"Unsupported chain selection. Supported: {REGISTERED}"


@pytest.fixture
def bot(bot_module, monkeypatch):
    """The bot with a real chain registry and address check, and its scans replaced."""
    client = Web3Client.__new__(Web3Client)
    client._adapters = {chain_id: MagicMock() for chain_id in REGISTERED}
    client.is_token_contract = AsyncMock(return_value=True)
    monkeypatch.setattr(bot_module, "web3_client", client)
    monkeypatch.setattr(bot_module, "scan_contract", AsyncMock())
    monkeypatch.setattr(bot_module, "check_token", AsyncMock())
    return bot_module


def _message(text=None):
    update = MagicMock(spec=Update)
    update.effective_user.id = 42
    update.message.text = text
    update.message.reply_text = AsyncMock(
        return_value=SimpleNamespace(edit_text=AsyncMock(), delete=AsyncMock())
    )
    return update


def _picker(update):
    """The one reply: the picker's text and its buttons, row by row, as (label, callback data)."""
    call = update.message.reply_text.await_args
    assert update.message.reply_text.await_count == 1
    assert call.kwargs["parse_mode"] == "Markdown"
    rows = [
        [(button.text, button.callback_data) for button in row]
        for row in call.kwargs["reply_markup"].inline_keyboard
    ]
    return call.args[0], rows


def _tap(data):
    query = MagicMock()
    query.data = data
    query.answer = AsyncMock()
    query.edit_message_text = AsyncMock()
    query.message.reply_text = AsyncMock(
        return_value=SimpleNamespace(edit_text=AsyncMock(), delete=AsyncMock())
    )
    return query


def _assert_nothing_scanned(bot):
    bot.web3_client.is_token_contract.assert_not_awaited()
    bot.check_token.assert_not_awaited()
    bot.scan_contract.assert_not_awaited()


# --- A pasted address -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_bare_paste_asks_which_chain_and_scans_nothing(bot):
    update = _message(ADDRESS)
    context = SimpleNamespace(user_data={})

    await bot.handle_address(update, context)

    text, _ = _picker(update)
    rendered, entities = parse_legacy_markdown(text)
    assert rendered.splitlines() == [
        "Which chain is this address on?",
        "",
        ADDRESS,
        "",
        "Tip: a prefix such as rh:0x... or eth:0x... skips this question.",
    ]
    start = rendered.index(ADDRESS)
    assert ("code", start, start + len(ADDRESS), None) in entities
    _assert_nothing_scanned(bot)
    assert context.user_data == {}


@pytest.mark.asyncio
async def test_the_picker_offers_every_supported_chain_in_the_products_order_two_to_a_row(bot):
    # A chain outside the product's order, such as a demo chain, follows it.
    bot.web3_client._adapters[677] = MagicMock()
    update = _message(ADDRESS)

    await bot.handle_address(update, SimpleNamespace(user_data={}))

    _, rows = _picker(update)
    buttons = [(name, f"pick_a_{chain_id}_{ADDRESS}") for chain_id, name in CANONICAL]
    buttons.append(("Chain 677", f"pick_a_677_{ADDRESS}"))
    assert rows == [buttons[i : i + 2] for i in range(0, len(buttons), 2)]
    assert [len(row) for row in rows] == [2, 2, 2, 2, 1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "saved, marked",
    [(None, None), (4663, "Robinhood Chain"), (1, "Ethereum"), (999999, None)],
    ids=["none-saved", "robinhood", "ethereum", "stale"],
)
async def test_only_the_stored_chain_is_marked_last_used_and_nothing_is_preselected(
    bot, saved, marked
):
    user_data = {} if saved is None else {"chain_id": saved}
    update = _message(ADDRESS)

    await bot.handle_address(update, SimpleNamespace(user_data=user_data))

    _, rows = _picker(update)
    assert [button for row in rows for button in row] == [
        (f"{name} (last used)" if name == marked else name, f"pick_a_{chain_id}_{ADDRESS}")
        for chain_id, name in CANONICAL
    ]
    _assert_nothing_scanned(bot)


@pytest.mark.asyncio
@pytest.mark.parametrize("prefix, chain_id", [("rh", 4663), ("eth", 1), ("bsc", 56)])
@pytest.mark.parametrize("is_token", [True, None, False])
async def test_a_prefixed_paste_scans_on_the_prefix_chain_without_asking(
    bot, prefix, chain_id, is_token
):
    bot.web3_client.is_token_contract.return_value = is_token
    update = _message(f"{prefix}:{ADDRESS}")
    context = SimpleNamespace(user_data={"chain_id": 8453})

    await bot.handle_address(update, context)

    bot.web3_client.is_token_contract.assert_awaited_once_with(ADDRESS, chain_id=chain_id)
    ran, skipped = (
        (bot.check_token, bot.scan_contract)
        if is_token is not False
        else (bot.scan_contract, bot.check_token)
    )
    ran.assert_awaited_once_with(update, ADDRESS, chain_id=chain_id)
    skipped.assert_not_awaited()
    assert context.user_data["chain_id"] == chain_id
    assert all(
        "reply_markup" not in call.kwargs for call in update.message.reply_text.await_args_list
    )


@pytest.mark.asyncio
async def test_free_text_still_goes_to_the_advisor_on_the_saved_chain(bot, monkeypatch):
    advisor = AsyncMock()
    monkeypatch.setattr(bot, "_handle_advisor_chat", advisor)
    update = _message("Is this token safe to buy?")

    await bot.handle_address(update, SimpleNamespace(user_data={"chain_id": 4663}))

    advisor.assert_awaited_once_with(update, "Is this token safe to buy?", chain_id=4663)
    update.message.reply_text.assert_not_awaited()
    _assert_nothing_scanned(bot)


# --- /scan and /token -----------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("command, kind", [("scan_command", "s"), ("token_command", "t")])
@pytest.mark.parametrize(
    "saved", [{}, {"chain_id": 4663}, {"chain_id": 999999}], ids=["none", "saved", "stale"]
)
async def test_scan_and_token_without_a_prefix_ask_which_chain(bot, command, kind, saved):
    update = _message()

    await getattr(bot, command)(update, SimpleNamespace(args=[ADDRESS], user_data=dict(saved)))

    text, rows = _picker(update)
    assert text.startswith("Which chain is this address on?")
    assert [data for row in rows for _, data in row] == [
        f"pick_{kind}_{chain_id}_{ADDRESS}" for chain_id, _ in CANONICAL
    ]
    _assert_nothing_scanned(bot)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command, scan", [("scan_command", "scan_contract"), ("token_command", "check_token")]
)
@pytest.mark.parametrize("prefix, chain_id", [("rh", 4663), ("eth", 1)])
async def test_scan_and_token_with_a_prefix_run_on_that_chain_at_once(
    bot, command, scan, prefix, chain_id
):
    update = _message()

    await getattr(bot, command)(
        update, SimpleNamespace(args=[f"{prefix}:{ADDRESS}"], user_data={"chain_id": 56})
    )

    getattr(bot, scan).assert_awaited_once_with(update, ADDRESS, chain_id=chain_id)
    update.message.reply_text.assert_not_awaited()


# --- A tap on the picker --------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind, is_token, scan",
    [
        ("a", True, "check_token"),
        ("a", None, "check_token"),
        ("a", False, "scan_contract"),
        # /scan and /token keep their own scan whatever the address looks like.
        ("s", True, "scan_contract"),
        ("t", False, "check_token"),
    ],
)
@pytest.mark.parametrize("chain_id, name", [(4663, "Robinhood Chain"), (1, "Ethereum")])
async def test_a_tap_runs_its_scan_on_the_chosen_chain_and_remembers_the_chain(
    bot, kind, is_token, scan, chain_id, name
):
    bot.web3_client.is_token_contract.return_value = is_token
    query = _tap(f"pick_{kind}_{chain_id}_{ADDRESS}")
    context = SimpleNamespace(user_data={"chain_id": 56})

    await bot.button_callback(SimpleNamespace(callback_query=query), context)

    assert context.user_data["chain_id"] == chain_id
    edit = query.edit_message_text.await_args
    assert edit.kwargs == {"parse_mode": "Markdown"}
    assert (
        assert_literal(edit.args[0])
        == f"\N{LEFT-POINTING MAGNIFYING GLASS} Scanning {ADDRESS} on {name} ({chain_id})..."
    )
    getattr(bot, scan).assert_awaited_once_with(query, ADDRESS, chain_id=chain_id)
    (bot.scan_contract if scan == "check_token" else bot.check_token).assert_not_awaited()
    if kind == "a":
        bot.web3_client.is_token_contract.assert_awaited_once_with(ADDRESS, chain_id=chain_id)
    else:
        bot.web3_client.is_token_contract.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_chosen_chain_is_marked_last_used_on_the_next_picker(bot):
    context = SimpleNamespace(user_data={})
    await bot.button_callback(
        SimpleNamespace(callback_query=_tap(f"pick_a_4663_{ADDRESS}")), context
    )
    update = _message(ADDRESS)

    await bot.handle_address(update, context)

    _, rows = _picker(update)
    assert [label for row in rows for label, _ in row if "(last used)" in label] == [
        "Robinhood Chain (last used)"
    ]


@pytest.mark.asyncio
async def test_the_picker_keeps_no_state_so_a_repeated_tap_runs_again(bot):
    query = _tap(f"pick_s_4663_{ADDRESS}")
    context = SimpleNamespace(user_data={})

    for _ in range(2):
        await bot.button_callback(SimpleNamespace(callback_query=query), context)

    assert bot.scan_contract.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind, scan, error",
    [
        ("a", "check_token", BadRequest("Message is not modified")),
        ("s", "scan_contract", BadRequest("Message is not modified")),
        ("t", "check_token", BadRequest("Message is not modified")),
        ("s", "scan_contract", TelegramError("Message can't be edited")),
    ],
    ids=["a-not-modified", "s-not-modified", "t-not-modified", "s-telegram-error"],
)
async def test_a_tap_runs_its_scan_even_when_telegram_refuses_to_edit_the_picker(
    bot, caplog, kind, scan, error
):
    query = _tap(f"pick_{kind}_4663_{ADDRESS}")
    query.edit_message_text.side_effect = error
    context = SimpleNamespace(user_data={"chain_id": 56})

    await bot.button_callback(SimpleNamespace(callback_query=query), context)

    query.edit_message_text.assert_awaited_once()
    getattr(bot, scan).assert_awaited_once_with(query, ADDRESS, chain_id=4663)
    assert context.user_data["chain_id"] == 4663
    # The log names the error's class, never Telegram's text.
    (record,) = [record for record in caplog.records if record.name == "bot"]
    assert type(error).__name__ in record.getMessage()
    assert error.message not in record.getMessage()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "data, reply",
    [
        (f"pick_x_56_{ADDRESS}", INVALID),
        (f"pick__56_{ADDRESS}", INVALID),
        (f"pick_aa_56_{ADDRESS}", INVALID),
        (f"pick_a__{ADDRESS}", INVALID),
        (f"pick_a_\N{FULLWIDTH DIGIT FIVE}\N{FULLWIDTH DIGIT SIX}_{ADDRESS}", INVALID),
        (f"pick_a_\N{SUPERSCRIPT TWO}_{ADDRESS}", INVALID),
        (f"pick_a_-56_{ADDRESS}", INVALID),
        (f"pick_a_5 6_{ADDRESS}", INVALID),
        (f"pick_a_0x38_{ADDRESS}", INVALID),
        (f"pick_a_56_{ADDRESS[:-1]}", INVALID),
        (f"pick_a_56_{ADDRESS}a", INVALID),
        (f"pick_a_56_{ADDRESS}_56", INVALID),
        (f"pick_a_56_{HOSTILE_ADDRESS}", INVALID),
        (f"pick_a_56_{BAD_CHECKSUM}", INVALID),
        ("pick_a_56", INVALID),
        ("pick_", INVALID),
        ("pick_a_56_0x" + "a" * 400, INVALID),
        (f"pick_a_999999_{ADDRESS}", UNSUPPORTED),
        (f"pick_a_0_{ADDRESS}", UNSUPPORTED),
        (f"pick_t_10000001_{ADDRESS}", UNSUPPORTED),
        (f"pick_s_{'9' * 80}_{ADDRESS}", UNSUPPORTED),
        (f"pick_s_{'9' * 5000}_{ADDRESS}", UNSUPPORTED),
    ],
)
async def test_a_tap_with_malformed_oversized_or_unsupported_data_is_rejected_without_scanning(
    bot, data, reply
):
    query = _tap(data)
    context = SimpleNamespace(user_data={"chain_id": 56})

    await bot.button_callback(SimpleNamespace(callback_query=query), context)

    (text,) = query.message.reply_text.await_args.args
    assert query.message.reply_text.await_count == 1
    assert text == reply
    query.edit_message_text.assert_not_awaited()
    _assert_nothing_scanned(bot)
    assert context.user_data == {"chain_id": 56}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "entry, kind", [("handle_address", "a"), ("scan_command", "s"), ("token_command", "t")]
)
async def test_every_picker_button_fits_telegrams_64_byte_callback_data_limit(bot, entry, kind):
    # validate_chain_id accepts ids up to 10000000, so that chain's button is the longest one possible.
    bot.web3_client._adapters[10_000_000] = MagicMock()
    update = _message(ADDRESS)

    await getattr(bot, entry)(update, SimpleNamespace(args=[ADDRESS], user_data={}))

    _, rows = _picker(update)
    data = [data for row in rows for _, data in row]
    assert len(data) == len(REGISTERED) + 1
    assert (
        max(len(value.encode()) for value in data)
        == len(f"pick_{kind}_10000000_{ADDRESS}".encode())
        == 58
    )
    assert all(len(value.encode()) <= 64 for value in data)
    # The longest value still parses.
    query = _tap(f"pick_{kind}_10000000_{ADDRESS}")
    await bot.button_callback(SimpleNamespace(callback_query=query), SimpleNamespace(user_data={}))
    scan = {"a": bot.check_token, "s": bot.scan_contract, "t": bot.check_token}[kind]
    scan.assert_awaited_once_with(query, ADDRESS, chain_id=10_000_000)


# --- Every report names its chain -----------------------------------------------------------------

RISK = {"rug_probability": 5, "risk_level": "LOW", "status": "ok", "coverage": {"structural": 1}}
# A complete legacy scanner result, which the fallback formatters render in full.
LEGACY = {
    "address": ADDRESS,
    "status": "ok",
    "coverage": {"structural": 1},
    "risk_level": "low",
    "safety_level": "safe",
    "risk_score": 5,
    "confidence": 90,
    "is_contract": True,
    "is_verified": True,
    "is_honeypot": False,
    "buy_tax": 0,
    "sell_tax": 0,
    "checks": {"can_buy": True, "can_sell": True},
}


@pytest.mark.parametrize(
    "token_info, top",
    [
        (None, [f"Target: {ADDRESS}", "Chain: Robinhood Chain (4663)"]),
        (
            {"name": "Moon", "symbol": "MOON"},
            ["Token: Moon (MOON)", f"Address: {ADDRESS}", "Chain: Robinhood Chain (4663)"],
        ),
    ],
)
def test_the_full_report_names_its_chain_right_after_the_target(token_info, top):
    report = format_full_report(
        RISK, {}, {}, {}, address=ADDRESS, token_info=token_info, chain_id=4663
    )

    lines = assert_literal(report).splitlines()
    assert lines[2 : 2 + len(top)] == top
    # No other line changes with the chain.
    other = format_full_report(
        RISK, {}, {}, {}, address=ADDRESS, token_info=token_info, chain_id=56
    ).splitlines()
    assert [i for i, (a, b) in enumerate(zip(report.splitlines(), other)) if a != b] == [
        1 + len(top)
    ]
    assert len(other) == len(report.splitlines())


@pytest.mark.parametrize("formatter", ["format_scan_result", "format_token_result"])
def test_the_fallback_reports_name_their_chain_right_after_the_address(bot, formatter):
    lines = assert_literal(getattr(bot, formatter)(dict(LEGACY), 8453)).splitlines()

    assert lines[lines.index(f"Address: {ADDRESS}") + 1] == "Chain: Base (8453)"


@pytest.mark.parametrize("formatter", ["format_scan_result", "format_token_result"])
def test_a_forensic_fallback_report_starts_with_its_chain(bot, formatter):
    result = {**LEGACY, "forensic_report": "**Risk Score:** 5/100 — LOW"}

    rendered = assert_literal(getattr(bot, formatter)(result, 42161))

    assert rendered.splitlines() == ["Chain: Arbitrum (42161)", "", "Risk Score: 5/100 — LOW"]


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["scan_contract", "check_token"])
@pytest.mark.parametrize("composite", [True, False], ids=["composite", "legacy-fallback"])
async def test_a_scan_report_names_the_chain_it_ran_on_fresh_and_from_the_cache(
    bot_module, monkeypatch, handler, composite
):
    client = Web3Client.__new__(Web3Client)
    client._adapters = {chain_id: MagicMock() for chain_id in REGISTERED}
    client.get_token_info = AsyncMock(return_value={})
    monkeypatch.setattr(bot_module, "web3_client", client)
    monkeypatch.setattr(
        bot_module, "ai_analyzer", MagicMock(is_available=MagicMock(return_value=False))
    )
    monkeypatch.setattr(
        bot_module,
        "risk_engine",
        MagicMock(
            compute_from_results=MagicMock(
                return_value={**RISK, "coverage": {"structural": 1, "honeypot": 1}}
            )
        ),
    )
    run_all = (
        AsyncMock(return_value=[])
        if composite
        else AsyncMock(side_effect=RuntimeError("Unavailable"))
    )
    monkeypatch.setattr(bot_module.container.registry, "run_all", run_all)
    monkeypatch.setattr(
        bot_module, "tx_scanner", SimpleNamespace(scan_address=AsyncMock(return_value=dict(LEGACY)))
    )
    monkeypatch.setattr(
        bot_module,
        "token_scanner",
        SimpleNamespace(check_token=AsyncMock(return_value=dict(LEGACY))),
    )

    replies = []
    for _ in range(2):
        update = _message()
        await getattr(bot_module, handler)(update, ADDRESS, chain_id=8453)
        replies.append(update.message.reply_text.await_args.args[0])

    assert "Chain: Base (8453)" in assert_literal(replies[0]).splitlines()
    # The second reply came from the cache, whose key holds the chain.
    assert run_all.await_count == 1
    assert replies[1] == replies[0]


# --- Help -----------------------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["start", "help_command"])
async def test_start_and_help_say_a_bare_address_asks_and_a_prefix_skips_the_question(bot, handler):
    update = _message()

    await getattr(bot, handler)(update, MagicMock())

    text = update.message.reply_text.await_args.args[0]
    (line,) = [line for line in text.splitlines() if "Send any address" in line]
    assert "ask which chain it is on" in line
    assert "chain prefix skips the question" in line


@pytest.mark.asyncio
async def test_switching_the_saved_chain_says_what_it_still_controls_not_that_every_scan_follows(
    bot,
):
    update = _message()
    await bot.chain_command(update, SimpleNamespace(args=["rh"], user_data={}))
    query = _tap("chain_4663")
    await bot.button_callback(SimpleNamespace(callback_query=query), SimpleNamespace(user_data={}))

    typed = update.message.reply_text.await_args.args[0]
    tapped = query.edit_message_text.await_args.args[0]
    assert (
        typed
        == tapped
        == (
            "Switched to Robinhood Chain (chain_id=4663).\n"
            "It is now the default for /rescue, /report and the advisor chat. An address without a chain prefix, "
            "pasted or sent with /scan or /token, still asks which chain it is on."
        )
    )
    assert "All scans" not in tapped
