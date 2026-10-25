"""BOT Chain approvals stay inside the explicitly prefixed Telegram rescue path."""

import asyncio
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import aiohttp
import pytest
from web3 import Web3

from core.telegram_formatter import escape_untrusted
from services.rescue_service import (
    APPROVAL_TOPIC,
    ApprovalInfo,
    KNOWN_SAFE_SPENDERS,
    PUBLIC_LOG_WINDOW_BLOCKS,
    RescueService,
    truncate_token_text,
)
from tests.test_api import client as api_client  # noqa: F401 (pytest fixture)
from tests.test_bot_app import bot_module  # noqa: F401 (pytest fixture)
from tests.test_rescue_bounded_history import FakeRpc, LATEST, OWNER_TOPIC, TOKEN, UNLIMITED, ok
from utils.chain_info import CHAIN_INFO, CHAIN_PREFIXES
from utils.web3_client import UnsupportedChainError


BOTCHAIN = 677
BOTCHAIN_RPC = "https://rpc.botchain.ai"
BOTCHAIN_USDT = "0xababc7ddc03e501d190c676bf3d92ef0e6e87a3c"
WALLET = "0xabcdef0123456789abcdef0123456789abcdef01"
SPENDER = "0x" + "9" * 40
WINDOW_BLOCKS = 1_000_000
WINDOW_START = LATEST - 24_000_000 + 1
REVOKE_PAGE = "https://botchain.gudman.xyz/revoke.html"

MAINNET_SPENDERS = {
    "0x1414ed29fdfd322c3c0a830330ed982e2d629e76": "BDEX V2 Router02",
    "0x07032d47a1b9f8460cbee9dc17c1d3e438693929": "BDEX V3 SwapRouter",
    "0xae6ae8630f7a888dec0b9195c85f7515d5887655": "BDEX Universal Router",
    "0x8366170f09a04f715a13549d616a06aed16db7c3": "Permit2",
    "0xdac3fcff004d8a8675b94e44941a1a2e3b240090": "BDEX V3 Position Manager",
}


def approval_log(spender, amount=UNLIMITED, block=LATEST - 5, log_index="0x1"):
    return {
        "address": TOKEN,
        "topics": [APPROVAL_TOPIC, OWNER_TOPIC, "0x" + "0" * 24 + spender[2:]],
        "data": amount,
        "blockNumber": hex(block),
        "logIndex": log_index,
    }


def rpc_handler(logs, allowance=UNLIMITED, balance=10**18, code="0x6000", latest=LATEST):
    def handle(payload):
        method = payload["method"]
        if method == "eth_blockNumber":
            return ok(hex(latest))
        if method == "eth_getLogs":
            params = payload["params"][0]
            from_block = int(params["fromBlock"], 16)
            to_block = int(params["toBlock"], 16)
            return ok([log for log in logs if from_block <= int(log["blockNumber"], 16) <= to_block])
        if method == "eth_getCode":
            return ok(code)
        if payload["params"][0]["data"].startswith("0xdd62ed3e"):
            return ok(allowance if isinstance(allowance, str) else hex(allowance))
        return ok(hex(balance))

    return handle


def botchain_service(price=1.25, info=None):
    web3_client = MagicMock()
    service = RescueService(web3_client)
    service._botchain_adapter = SimpleNamespace(
        get_token_info=AsyncMock(return_value=info or {
            "name": "Token",
            "symbol": "TKN",
            "decimals": 18,
            "total_supply": 1000,
        })
    )
    service._fetch_prices = AsyncMock(return_value={TOKEN: price})
    return service


async def scan_botchain(handler, service=None):
    service = service or botchain_service()
    rpc = FakeRpc(handler)
    with patch("services.rescue_service.aiohttp.ClientSession") as factory:
        factory.return_value.__aenter__.return_value = rpc
        result = await service.scan_approvals(
            WALLET, chain_id=BOTCHAIN, botchain_approval_scan=True,
        )
    return result, rpc


def price_session(answer, status=200, error=None):
    class Response:
        def __init__(self):
            self.status = status

        async def json(self, **kwargs):
            if error:
                raise error
            return answer

    class Context:
        async def __aenter__(self):
            return Response()

        async def __aexit__(self, *args):
            return False

    class Session:
        def __init__(self):
            self.calls = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            if isinstance(error, (aiohttp.ClientError, asyncio.TimeoutError)):
                raise error
            if error == "request":
                raise RuntimeError("offline")
            return Context()

    return Session()


def price_answer(price="2.5", path=None, token=TOKEN):
    return {
        "success": True,
        "data": {
            "token": token,
            "price": price,
            "path": [token, BOTCHAIN_USDT] if path is None else path,
        },
    }


@pytest.mark.asyncio
async def test_chain_677_requires_the_private_approval_scan_opt_in():
    service = RescueService(MagicMock())

    with pytest.raises(UnsupportedChainError):
        await service.scan_approvals(WALLET, chain_id=BOTCHAIN)
    with pytest.raises(ValueError):
        await service.scan_approvals(WALLET, chain_id=56, botchain_approval_scan=True)


def test_botchain_labels_are_confined_to_677_and_public_history_lists_stay_unchanged():
    assert KNOWN_SAFE_SPENDERS[BOTCHAIN] == MAINNET_SPENDERS
    assert BOTCHAIN not in CHAIN_INFO
    assert BOTCHAIN not in CHAIN_PREFIXES.values()
    assert BOTCHAIN not in PUBLIC_LOG_WINDOW_BLOCKS
    assert RescueService(MagicMock()).approval_history(BOTCHAIN) == {
        "history": "recent",
        "window_blocks": 24_000_000,
    }


@pytest.mark.asyncio
async def test_botchain_uses_twenty_four_million_recent_blocks_and_discloses_older_history():
    spender = next(iter(MAINNET_SPENDERS))
    service = botchain_service()
    result, rpc = await scan_botchain(rpc_handler([approval_log(spender)]), service=service)

    logs_calls = rpc.methods("eth_getLogs")
    bounds = [
        (int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16))
        for params in logs_calls
    ]
    assert len(bounds) == 24
    assert all(to_block - from_block + 1 == WINDOW_BLOCKS for from_block, to_block in bounds)
    assert min(from_block for from_block, _ in bounds) == WINDOW_START
    assert max(to_block for _, to_block in bounds) == LATEST
    assert result["scanned_blocks"] == {"from_block": WINDOW_START, "to_block": LATEST}
    assert result["coverage_reasons"]["allowances"] == (
        f"Approvals before block {WINDOW_START} not scanned"
    )
    service._web3_client._get_adapter.assert_not_called()


@pytest.mark.asyncio
async def test_mainnet_spenders_have_demo_risk_levels_and_limited_approvals_remain_low():
    known = next(iter(MAINNET_SPENDERS))
    known_result, _ = await scan_botchain(rpc_handler([approval_log(known)]))
    limited_result, _ = await scan_botchain(
        rpc_handler([approval_log(SPENDER, amount=hex(5 * 10**18))], allowance=5 * 10**18, balance=10 * 10**18)
    )

    [known_approval] = known_result["approvals"]
    [limited_approval] = limited_result["approvals"]
    assert known_approval["spender_label"] == "BDEX V2 Router02"
    assert known_approval["risk_level"] == "MEDIUM"
    assert known_approval["risk_reason"] == (
        "Unlimited approval to BDEX V2 Router02 — safe but excessive"
    )
    assert limited_approval["risk_level"] == "LOW"
    assert limited_approval["allowance"] == "5.00"
    assert limited_approval["value_at_risk_usd"] == 6.25


@pytest.mark.asyncio
async def test_unknown_unlimited_spender_is_high_and_codeless_address_is_named():
    info = {"name": "A" * 40, "symbol": "B" * 40, "decimals": 18, "total_supply": 1000}
    result, _ = await scan_botchain(
        rpc_handler([approval_log(SPENDER)], code="0x"),
        service=botchain_service(info=info),
    )

    [approval] = result["approvals"]
    [alert] = result["alerts"]
    assert approval["spender_label"] == "Unknown address"
    assert approval["risk_level"] == "HIGH"
    assert approval["risk_reason"] == "Unlimited approval to unknown address"
    assert approval["token_name"] == "A" * 23 + "…"
    assert approval["token_symbol"] == "B" * 23 + "…"
    assert alert["severity"] == "HIGH"
    assert alert["title"] == "Dangerous Approval: " + "B" * 23 + "…"
    assert "(" + "A" * 23 + "…" + ")" in alert["description"]
    assert "granted to an unknown address" in alert["description"]
    assert "This address can spend ALL" in alert["what_it_means"]
    assert f"Check the address {SPENDER} on the block explorer" in alert["what_you_can_do"]


def test_unknown_spender_wording_stays_unchanged_on_non_botchain():
    service = RescueService(MagicMock())
    risk_level, risk_reason = service._assess_approval_risk(
        SPENDER, int(UNLIMITED, 16), "Unknown Contract", 56,
    )
    approval = ApprovalInfo(
        token_address=TOKEN,
        token_name="Token",
        token_symbol="TKN",
        spender=SPENDER,
        spender_label="Unknown Contract",
        allowance="Unlimited",
        allowance_raw=int(UNLIMITED, 16),
        risk_level=risk_level,
        risk_reason=risk_reason,
        chain_id=56,
    )
    alert = service._generate_alert(approval)

    assert risk_reason == "Unlimited approval to unknown contract"
    assert alert.description == (
        f"Your wallet has an unlimited approval for TKN (Token) granted to an unknown contract "
        f"({SPENDER[:10]}...)."
    )
    assert alert.what_it_means == (
        "This contract can spend ALL of your TKN tokens at any time without further permission. "
        "If the contract is malicious or gets compromised, your tokens could be drained instantly."
    )
    assert alert.what_you_can_do[1] == f"Check the contract {SPENDER} on the block explorer"


@pytest.mark.asyncio
async def test_same_block_approval_uses_the_later_log_index_on_677():
    spender = next(iter(MAINNET_SPENDERS))
    logs = [
        approval_log(spender, amount=UNLIMITED, log_index="0x2"),
        approval_log(spender, amount="0x0", log_index="0x3"),
    ]
    result, _ = await scan_botchain(rpc_handler(logs))

    assert result["approvals"] == []


@pytest.mark.asyncio
async def test_botchain_price_api_prices_only_a_positive_price_routed_to_usdt():
    session = price_session(price_answer())
    service = RescueService(MagicMock())
    with patch("services.rescue_service.aiohttp.ClientSession", return_value=session):
        prices = await service._fetch_prices([TOKEN], BOTCHAIN)

    assert prices == {TOKEN: 2.5}
    (url, kwargs), = session.calls
    assert url == "https://dex-wallet.botchain.ai/api/graph/price"
    assert kwargs["params"] == {"token": TOKEN}
    assert "User-Agent" in kwargs["headers"]
    assert kwargs["timeout"].total == 10


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer,status,error",
    [
        (price_answer(price="0"), 200, None),
        (price_answer(path=[]), 200, None),
        (price_answer(path=[TOKEN, SPENDER]), 200, None),
        (price_answer(token=SPENDER), 200, None),
        ({"success": False}, 200, None),
        (price_answer(price=True), 200, None),
        (price_answer(price="NaN"), 200, None),
        (price_answer(), 503, None),
        (price_answer(), 200, aiohttp.ClientConnectionError("offline")),
        (price_answer(), 200, asyncio.TimeoutError()),
        ({}, 200, ValueError("bad response")),
    ],
)
async def test_botchain_price_source_fails_closed(answer, status, error):
    session = price_session(answer, status=status, error=error)
    service = RescueService(MagicMock())
    with patch("services.rescue_service.aiohttp.ClientSession", return_value=session):
        prices = await service._fetch_prices([TOKEN], BOTCHAIN)

    assert prices == {}
    assert TOKEN not in prices


@pytest.mark.asyncio
async def test_botchain_usdt_is_one_dollar_without_a_price_request():
    session = price_session({})
    service = RescueService(MagicMock())
    with patch("services.rescue_service.aiohttp.ClientSession", return_value=session):
        prices = await service._fetch_prices([BOTCHAIN_USDT], BOTCHAIN)

    assert prices == {BOTCHAIN_USDT: 1.0}
    assert session.calls == []


@pytest.mark.asyncio
async def test_unpriced_botchain_approval_has_no_value_at_risk():
    service = botchain_service()
    service._fetch_prices = AsyncMock(return_value={})
    spender = next(iter(MAINNET_SPENDERS))
    result, _ = await scan_botchain(
        rpc_handler([approval_log(spender)]), service=service,
    )

    [approval] = result["approvals"]
    assert approval["value_at_risk_usd"] is None
    assert result["coverage"]["prices"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("prefix", ["bot:", "botchain:"])
async def test_rescue_accepts_botchain_only_with_an_explicit_prefix(bot_module, monkeypatch, prefix):
    update = MagicMock()
    update.message.reply_text = AsyncMock()
    scan = AsyncMock()
    monkeypatch.setattr(bot_module, "_scan_approvals", scan)
    bot_module.web3_client.is_valid_address.return_value = True

    await bot_module.rescue_command(update, SimpleNamespace(args=[prefix + WALLET], user_data={}))

    scan.assert_awaited_once_with(update, WALLET, BOTCHAIN, botchain_approval=True)


@pytest.mark.asyncio
async def test_rescue_rejects_invalid_botchain_address_without_scanning(bot_module, monkeypatch):
    update = MagicMock()
    update.message.reply_text = AsyncMock()
    scan = AsyncMock()
    monkeypatch.setattr(bot_module, "_scan_approvals", scan)
    bot_module.web3_client.is_valid_address.side_effect = Web3.is_address

    await bot_module.rescue_command(
        update, SimpleNamespace(args=["bot:not-an-address"], user_data={}),
    )

    update.message.reply_text.assert_awaited_once_with("❌ Invalid address format.")
    scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_rescue_without_a_prefix_keeps_the_existing_chain_picker_path(bot_module, monkeypatch):
    update = MagicMock()
    update.message.reply_text = AsyncMock()
    ask = AsyncMock()
    scan = AsyncMock()
    monkeypatch.setattr(bot_module, "_ask_chain", ask)
    monkeypatch.setattr(bot_module, "_scan_approvals", scan)
    bot_module.web3_client.is_valid_address.return_value = True
    context = SimpleNamespace(args=[WALLET], user_data={})

    await bot_module.rescue_command(update, context)

    ask.assert_awaited_once_with(update, context, "r", WALLET)
    scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_botchain_prefix_does_not_enable_scan_or_token_commands(bot_module, monkeypatch):
    bot_module.web3_client.is_valid_address.side_effect = Web3.is_address
    scan = AsyncMock()
    token = AsyncMock()
    monkeypatch.setattr(bot_module, "scan_contract", scan)
    monkeypatch.setattr(bot_module, "check_token", token)

    for command in (bot_module.scan_command, bot_module.token_command):
        update = MagicMock()
        update.message.reply_text = AsyncMock()
        await command(update, SimpleNamespace(args=["bot:" + WALLET]))
        update.message.reply_text.assert_awaited_once_with("❌ Invalid address format.")

    scan.assert_not_awaited()
    token.assert_not_awaited()


@pytest.mark.asyncio
async def test_botchain_is_absent_from_the_picker_and_global_chain_lists(bot_module):
    from utils.chain_info import parse_chain_prefix

    assert parse_chain_prefix("bot:" + WALLET) == (None, "bot:" + WALLET)
    assert parse_chain_prefix("botchain:" + WALLET) == (None, "botchain:" + WALLET)
    assert set(bot_module.web3_client.get_supported_chain_ids()) == set(CHAIN_INFO)
    assert BOTCHAIN not in bot_module.PICKER_CHAIN_ORDER
    assert all(
        BOTCHAIN not in chain_ids
        for chain_ids in (CHAIN_INFO, CHAIN_PREFIXES.values(), PUBLIC_LOG_WINDOW_BLOCKS)
    )
    update = MagicMock()
    update.message.reply_text = AsyncMock()
    await bot_module._ask_chain(update, SimpleNamespace(user_data={}), "r", WALLET)
    buttons = update.message.reply_text.await_args.kwargs["reply_markup"].inline_keyboard
    assert all("677" not in button.callback_data for row in buttons for button in row)


def test_botchain_is_not_advertised_by_api(api_client):
    import api

    api.web3_client.get_supported_chain_ids.return_value = list(CHAIN_INFO)

    def validate_chain_id(chain_id):
        if chain_id not in CHAIN_INFO:
            raise UnsupportedChainError("unsupported")

    api.web3_client.validate_chain_id.side_effect = validate_chain_id
    api.container = SimpleNamespace(
        rescue_service=SimpleNamespace(scan_approvals=AsyncMock(return_value={"status": "ok"})),
        settings=SimpleNamespace(bscscan_api_key=""),
    )

    response = api_client.get("/api/health")
    rescue_response = api_client.get(f"/api/rescue/{WALLET}?chain_id=677")
    supported_rescue_response = api_client.get(f"/api/rescue/{WALLET}?chain_id=56")

    assert response.status_code == 200
    assert BOTCHAIN not in response.json()["supported_chains"]
    assert rescue_response.status_code == 400
    assert supported_rescue_response.status_code == 200
    api.container.rescue_service.scan_approvals.assert_awaited_once_with(
        WALLET, chain_id=56, etherscan_api_key="",
    )


@pytest.mark.asyncio
async def test_botchain_reply_shows_other_allowances_values_escaped_labels_and_capped_revoke_links(
    bot_module, monkeypatch,
):
    owner = "0x" + "abcdef0123456789abcdef0123456789abcdef01"
    known = next(iter(MAINNET_SPENDERS))
    approvals = []
    for index in range(11):
        risk = "LOW"
        spender = known
        if index == 0:
            risk, spender = "HIGH", SPENDER
        elif index == 1:
            risk = "MEDIUM"
        approvals.append({
            "token_address": f"0x{index + 1:040x}",
            "token_symbol": "`[bad](https://evil.example)" + "x" * 50 if index == 0 else "USDT",
            "spender": spender,
            "spender_label": "Unknown <spender>" if risk == "HIGH" else "BDEX V2 Router02",
            "risk_level": risk,
            "risk_reason": "reason [x](https://evil.example)",
            "allowance": "Unlimited" if risk != "LOW" else "250 USDT",
            "value_at_risk_usd": 12.36 if index == 0 else (
                0.25 if index == 2 else (None if index == 3 else 0.0)
            ),
        })
    result = {
        "total_approvals": len(approvals),
        "high_risk": 1,
        "medium_risk": 1,
        "status": "unknown",
        "coverage_reasons": {"allowances": "Approvals before block 1 not scanned"},
        "approvals": approvals,
        "alerts": [{"title": "Dangerous Approval: hostile_*", "description": "alert [x](https://evil.example)"}],
        "revoke_txs": [],
    }
    events = []
    status = SimpleNamespace(delete=AsyncMock(side_effect=lambda: events.append("delete")))

    async def reply(*args, **kwargs):
        events.append("reply")
        return status if len(events) == 1 else None

    reply_text = AsyncMock(side_effect=reply)
    update = SimpleNamespace(
        message=SimpleNamespace(reply_text=reply_text),
    )
    bot_module.web3_client.is_valid_address.side_effect = Web3.is_address
    bot_module.web3_client.to_checksum_address.side_effect = Web3.to_checksum_address
    bot_module.settings.bscscan_api_key = "configured-bsc-key"
    bot_module.settings.etherscan_api_key = ""
    bot_module.container.rescue_service.scan_approvals = AsyncMock(return_value=result)

    await bot_module._scan_approvals(update, owner, BOTCHAIN, botchain_approval=True)

    bot_module.container.rescue_service.scan_approvals.assert_awaited_once_with(
        owner, chain_id=BOTCHAIN, etherscan_api_key="", botchain_approval_scan=True,
    )
    text = "\n".join(call.args[0] for call in reply_text.await_args_list[1:])
    assert "**Chain:** BOT Chain\n" in text
    assert "**Other approvals:**" in text
    assert "USDT → BDEX V2 Router02 (allowance: 250 USDT) (value at risk: $0.25)" in text
    assert "(value at risk: $0.00)" not in text
    assert escape_untrusted(truncate_token_text(approvals[0]["token_symbol"])) in text
    assert escape_untrusted("Unknown <spender>") in text
    assert escape_untrusted("alert [x](https://evil.example)") in text

    links = re.findall(r"\[open revoke page\]\(([^)]+)\)", text)
    assert len(links) == 10
    queries = [parse_qs(urlsplit(link).query) for link in links]
    assert all(urlsplit(link).scheme == "https" and urlsplit(link).netloc == "botchain.gudman.xyz" for link in links)
    assert all(query["chain"] == ["677"] for query in queries)
    assert all(query["owner"] == [Web3.to_checksum_address(owner)] for query in queries)
    assert [query["token"] for query in queries[:2]] == [
        [approvals[0]["token_address"]],
        [approvals[1]["token_address"]],
    ]
    assert all(query["token"] not in [approvals[0]["token_address"], approvals[1]["token_address"]]
               for query in queries[2:])
    assert all(link.startswith(REVOKE_PAGE + "?") for link in links)
    assert "1 more approval(s) not listed; run /rescue again a few minutes after revoking these." in text
    assert "This bot has not revoked any approvals or submitted transactions." in text
    assert events == ["reply", "reply", "reply", "delete"]


@pytest.mark.asyncio
async def test_botchain_reply_send_failure_falls_back_when_progress_edit_fails(bot_module):
    result, _ = await scan_botchain(rpc_handler([]))
    replies = []
    status = SimpleNamespace(
        delete=AsyncMock(),
        edit_text=AsyncMock(side_effect=RuntimeError("cannot edit progress message")),
    )

    async def send_reply(text, **kwargs):
        replies.append(text)
        if len(replies) == 1:
            return status
        if len(replies) == 2:
            raise RuntimeError("reply send failed")

    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock(side_effect=send_reply)))
    bot_module.web3_client.is_valid_address.side_effect = Web3.is_address
    bot_module.web3_client.to_checksum_address.side_effect = Web3.to_checksum_address
    bot_module.settings.bscscan_api_key = ""
    bot_module.container.rescue_service.scan_approvals = AsyncMock(return_value=result)

    await bot_module._scan_approvals(update, WALLET, BOTCHAIN, botchain_approval=True)

    assert replies[-1] == "❌ Error scanning approvals. Please try again later."
    status.edit_text.assert_awaited_once_with(replies[-1])
    status.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_help_describes_botchain_approval_scanning_without_changing_supported_chains(bot_module):
    update = MagicMock()
    update.message.reply_text = AsyncMock()

    await bot_module.help_command(update, MagicMock())

    text = update.message.reply_text.await_args.args[0]
    assert "/rescue bot:<wallet>" in text
    assert "BDEX names, dollar values and revoke links" in text
    assert "BOT Chain has approval scanning only" in text
    assert "Supported: BSC, Ethereum, Base, Arbitrum, Polygon, opBNB, Optimism, Robinhood Chain" in text
