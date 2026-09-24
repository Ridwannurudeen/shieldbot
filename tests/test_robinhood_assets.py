"""The official Robinhood Chain token list and the impostor check, against a recorded copy of the list."""

import asyncio
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio
from aiohttp import web
from eth_abi import encode

import services.robinhood_assets as robinhood_assets
from services.robinhood_assets import (
    CACHE_TTL_SECONDS,
    RETRY_SECONDS,
    RobinhoodAssets,
    check_token,
    parse_official_assets,
    with_impostor_check,
)
from services.robinhood_simulation import USDG, WETH

# GET https://api.robinhood.com/rhj/assets on 2026-09-24, exactly as served.
RECORDED_TEXT = (Path(__file__).parent / "fixtures" / "robinhood_assets.json").read_text(
    encoding="utf-8"
)
RECORDED = json.loads(RECORDED_TEXT)
LISTED = parse_official_assets(RECORDED)
NVDA_ASSET = next(asset for asset in RECORDED["assets"] if asset["tokenSymbol"] == "NVDA")
NVDA = "0xd0601ce157db5bdc3162bbac2a2c8af5320d9eec"
AMD = "0x86923f96303d656e4aa86d9d42d1e57ad2023fdc"
TSLA = "0x322f0929c4625ed5bad873c95208d54e1c003b2d"
OTHER = "0x" + "ab" * 20
NO_MATCH = {
    "status": "none",
    "symbol": None,
    "official_address": None,
    "matched_by": None,
    "also": None,
    "reason": None,
    "list_size": 195,
}
UNKNOWN_LIST = {
    **NO_MATCH,
    "status": "unknown",
    "reason": "Official Robinhood token list unavailable",
    "list_size": None,
}
UNKNOWN_METADATA = {**NO_MATCH, "status": "unknown", "reason": "Token symbol or name unavailable"}


def test_the_recorded_list_maps_every_asset_to_its_4663_contract():
    assert len(LISTED) == len(RECORDED["assets"]) == 195
    assert LISTED[NVDA] == ("NVDA", "NVIDIA \N{BULLET} Robinhood Token")


# Tokens live on Robinhood Chain on 2026-09-24, found through GeckoTerminal's robinhood network. The
# official tokens' and the non-"none" tokens' symbol() and name() were also read by eth_call.
@pytest.mark.parametrize(
    "address, symbol, name, status, official",
    [
        (NVDA, "NVDA", "NVIDIA \N{BULLET} Robinhood Token", "official", "NVDA"),
        (
            "0xaf3d76f1834a1d425780943c99ea8a608f8a93f9",
            "AAPL",
            "Apple \N{BULLET} Robinhood Token",
            "official",
            "AAPL",
        ),
        (
            "0x1c2a482970ae6b6e5052a7a184c8aef19e0840be",
            "AMD",
            "Advanced Micro Dog",
            "collision",
            "AMD",
        ),
        ("0xf01ab9476afcaa0e0058c83cef2b4c30867abeeb", "AMD", "A Mini Dog", "collision", "AMD"),
        ("0x982732a974738b771b07a2588f1b38a968a11e18", "TESLAHOOD", "Tesla", "collision", "TSLA"),
        # An affixed ticker corroborated by the company name with "xStock" added.
        ("0xd16485b15d38daa99039e2526701025ad4410582", "TSLAx", "Tesla xStock", "impostor", "TSLA"),
        # The "shieldbot" token whose pool against the official NVDA opened on 2026-09-15.
        ("0x8adba5e2f8ebe8a6f8d9f4c8151fba7ce2328900", "SBOT", "shieldbot", "none", None),
        ("0xf51fb54de60f6e16252e852a5ed0e60b8307606a", "NVDAx3L", "NVDA 3x Long", "none", None),
        ("0x73a9999f6e9db138e1ae4595fde049a401161e18", "AAPLCAT", "Apple Cat", "none", None),
        ("0x7eab29f0749b9ca46fe07ac8f2a0a64d2e629c51", "BRCAT", "BRAINROT CAT", "none", None),
        (
            "0x1d4699d229141e9b8e3c75e934cf6049909760a4",
            "FLOKI",
            "Floki For Robinhood",
            "none",
            None,
        ),
        ("0x2e8c31162b855a2ffa90f6f8634643ad6f111e18", "AI", "Artificial Inu", "none", None),
    ],
)
def test_tokens_live_on_the_chain(address, symbol, name, status, official):
    result = check_token(address, symbol, name, LISTED)

    assert (result["status"], result["symbol"]) == (status, official)


def test_an_impostor_names_the_official_contract_and_how_it_matched():
    assert check_token(OTHER, "TSLAx", "Tesla xStock", LISTED) == {
        **NO_MATCH,
        "status": "impostor",
        "symbol": "TSLA",
        "official_address": TSLA,
        "matched_by": "symbol and name",
    }


@pytest.mark.parametrize(
    "symbol, name, official",
    [
        ("NVDA", "NVIDIA \N{BULLET} Robinhood Token", "NVDA"),
        ("NVDA", "NVIDIA", "NVDA"),
        ("NVDAX", "Nvidia Stock", "NVDA"),
        ("TSLA.d", "Tesla", "TSLA"),
        ("TSLAx", "Tesla", "TSLA"),
        ("TESLA", "Tesla", "TSLA"),
        ("P", "Everpure", "P"),
        ("USDG", "Global Dollar", "USDG"),
        ("WETH", "WETH", "WETH"),
    ],
)
def test_a_symbol_and_name_that_both_point_at_an_official_token_are_an_impostor(
    symbol, name, official
):
    result = check_token(OTHER, symbol, name, LISTED)

    assert (result["status"], result["symbol"], result["matched_by"]) == (
        "impostor",
        official,
        "symbol and name",
    )


@pytest.mark.parametrize(
    "name",
    [
        "Tesla \N{BULLET} Robinhood Token",
        "Robinhood Tesla",
        "Tesla Inc. Robinhood Token",
        "TESLA robinhood",
    ],
)
def test_a_name_claiming_robinhood_and_the_company_is_an_impostor(name):
    result = check_token(OTHER, "MOON", name, LISTED)

    assert (result["status"], result["symbol"], result["matched_by"]) == (
        "impostor",
        "TSLA",
        "name",
    )


@pytest.mark.parametrize(
    "symbol, name, official",
    [
        ("".join(chr(ord(letter) + 0xFEE0) for letter in "NVDA"), "Moon", "NVDA"),
        ("\N{GREEK CAPITAL LETTER NU}VD\N{GREEK CAPITAL LETTER ALPHA}", "Moon", "NVDA"),
        ("\N{CYRILLIC CAPITAL LETTER TE}SL\N{CYRILLIC CAPITAL LETTER A}", "Moon", "TSLA"),
        ("C0IN", "Moon", "COIN"),
        ("AAP1", "Moon", "AAPL"),
        ("T5LA", "Moon", "TSLA"),
        ("NVD\N{LATIN CAPITAL LETTER A WITH ACUTE}", "Moon", "NVDA"),
        (
            "MOON",
            "T\N{LATIN SMALL LETTER E WITH ACUTE}sl\N{LATIN SMALL LETTER A WITH ACUTE}",
            "TSLA",
        ),
        ("MOON", "\N{CYRILLIC CAPITAL LETTER TE}esla", "TSLA"),
        ("MOON", "Te5la Holdings", "TSLA"),
    ],
)
def test_a_match_that_needs_look_alike_folding_is_an_impostor(symbol, name, official):
    result = check_token(OTHER, symbol, name, LISTED)

    assert (result["status"], result["symbol"]) == ("impostor", official)


@pytest.mark.parametrize(
    "symbol, name, official, matched_by",
    [
        ("nvda", "Moon", "NVDA", "symbol"),
        ("NVDA-", "Moon", "NVDA", "symbol"),
        ("N.V.D.A", "Moon", "NVDA", "symbol"),
        ("NVDAX", "Moon", "NVDA", "symbol"),
        ("wNVDA", "Moon", "NVDA", "symbol"),
        ("tNVDA", "Moon", "NVDA", "symbol"),
        ("TSLAx", "Moon", "TSLA", "symbol"),
        ("TSLA.d", "Moon", "TSLA", "symbol"),
        ("TESLA", "Moon", "TSLA", "symbol"),
        ("USDG", "Moon", "USDG", "symbol"),
        ("WETH", "Moon", "WETH", "symbol"),
        ("MOON", "nvidia", "NVDA", "name"),
        ("MOON", "Tesla Stock", "TSLA", "name"),
        ("MOON", "Cloudflare, Inc. Class A common stock", "NET", "name"),
        ("MOON", "Global Dollar", "USDG", "name"),
        ("MOON", "Tesla Holdings", "TSLA", "name"),
    ],
)
def test_a_bare_ticker_or_company_name_is_a_collision(symbol, name, official, matched_by):
    result = check_token(OTHER, symbol, name, LISTED)

    assert (result["status"], result["symbol"], result["matched_by"]) == (
        "collision",
        official,
        matched_by,
    )


@pytest.mark.parametrize(
    "symbol, name",
    [
        ("P", "Moon"),
        ("\N{CYRILLIC CAPITAL LETTER ER}", "Moon"),
        ("TON", "Toncoin"),
        ("XP", "Moon"),
        ("TF", "Moon"),
        ("BAT", "Moon"),
        ("XNVDAX", "Moon"),
        ("NVDAS", "Moon"),
        ("MOON", "NVIDIA fan club"),
        ("MOON", "Run"),
        ("MOON", "Robinhood Token"),
        ("", ""),
    ],
)
def test_tokens_that_only_resemble_an_official_one_are_not_matched(symbol, name):
    assert check_token(OTHER, symbol, name, LISTED) == NO_MATCH


def test_the_symbols_official_is_named_first_and_the_names_is_also_reported():
    collision = check_token(OTHER, "AMD", "Tesla", LISTED)
    impostor = check_token(OTHER, "AMD", "Tesla \N{BULLET} Robinhood Token", LISTED)

    assert (collision["status"], collision["symbol"], collision["matched_by"]) == (
        "collision",
        "AMD",
        "symbol",
    )
    assert collision["also"] == {"symbol": "TSLA", "official_address": TSLA}
    assert (impostor["status"], impostor["symbol"], impostor["matched_by"]) == (
        "impostor",
        "TSLA",
        "name",
    )
    assert impostor["also"] == {"symbol": "AMD", "official_address": AMD}


def test_without_the_list_only_the_canonical_tokens_are_decided():
    assert check_token(USDG, None, None, None)["status"] == "official"
    assert check_token(WETH.upper().replace("0X", "0x"), None, None, None)["symbol"] == "WETH"
    assert check_token(OTHER, "USDG", "Global Dollar", None)["status"] == "impostor"
    assert check_token(OTHER, "NVDA", "NVIDIA", None) == UNKNOWN_LIST


@pytest.mark.parametrize("symbol, name", [(None, "Moon"), ("MOON", None), (None, None)])
def test_a_token_whose_symbol_or_name_could_not_be_read_is_unknown(symbol, name):
    assert check_token(OTHER, symbol, name, LISTED) == UNKNOWN_METADATA


def test_what_can_be_read_still_decides():
    assert check_token(OTHER, "NVDA", None, LISTED)["status"] == "collision"
    assert check_token(OTHER, None, "Tesla", LISTED)["status"] == "collision"
    assert (
        check_token(OTHER, "\N{GREEK CAPITAL LETTER NU}VDA", None, LISTED)["status"] == "impostor"
    )
    assert check_token(NVDA.upper().replace("0X", "0x"), None, None, LISTED)["status"] == "official"


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"assets": {}},
        {"assets": []},
        {"assets": [None, {**NVDA_ASSET, "tokenSymbol": ""}]},
        {"assets": [{**NVDA_ASSET, "deployments": [{"chainId": 1, "contractAddress": NVDA}]}]},
    ],
)
def test_a_list_without_any_4663_token_is_rejected(payload):
    with pytest.raises(ValueError):
        parse_official_assets(payload)


def test_malformed_entries_are_skipped_and_counted(caplog):
    malformed = [
        None,
        "junk",
        {**NVDA_ASSET, "tokenSymbol": ""},
        {**NVDA_ASSET, "tokenName": None},
        {**NVDA_ASSET, "deployments": None},
        {**NVDA_ASSET, "deployments": [{"chainId": 4663, "contractAddress": "0x123"}]},
    ]

    with caplog.at_level(logging.WARNING, logger="services.robinhood_assets"):
        parsed = parse_official_assets({"assets": [*malformed, *RECORDED["assets"]]})

    assert parsed == LISTED
    assert "skipped 6 malformed" in caplog.text


def test_deployments_on_other_chains_are_skipped():
    elsewhere = {
        **NVDA_ASSET,
        "tokenSymbol": "X",
        "deployments": [{"chainId": 1, "contractAddress": OTHER}],
    }

    assert parse_official_assets({"assets": [NVDA_ASSET, elsewhere]}) == {
        NVDA: ("NVDA", "NVIDIA \N{BULLET} Robinhood Token"),
    }


def test_an_impostor_flag_leads_the_critical_flags():
    scan = {"rug_probability": 40, "critical_flags": ["Low liquidity (<$10k)", "New pair (<24h)"]}
    check = check_token(OTHER, "NVDA", "NVIDIA", LISTED)

    labelled = with_impostor_check(scan, check)

    assert labelled == {
        **scan,
        "impostor_check": check,
        "critical_flags": [
            f"Impersonates official NVDA token; official contract {NVDA}",
            *scan["critical_flags"],
        ],
    }
    assert scan["critical_flags"] == ["Low liquidity (<$10k)", "New pair (<24h)"]


@pytest.mark.parametrize(
    "address, symbol, name, listed",
    [
        (NVDA, "NVDA", "NVIDIA", LISTED),
        (OTHER, "NVDA", "Moon", LISTED),
        (OTHER, "MOON", "Moon", LISTED),
        (OTHER, "MOON", "Moon", None),
    ],
)
def test_other_results_add_only_the_field(address, symbol, name, listed):
    check = check_token(address, symbol, name, listed)

    assert with_impostor_check({"critical_flags": ["New pair (<24h)"]}, check) == {
        "critical_flags": ["New pair (<24h)"],
        "impostor_check": check,
    }
    assert with_impostor_check({"rug_probability": 5}, check) == {
        "rug_probability": 5,
        "impostor_check": check,
    }


# --- The service against a local list and RPC --------------------------------------------------


def abi_string(text):
    return "0x" + encode(["string"], [text]).hex()


@pytest_asyncio.fixture
async def served(monkeypatch):
    """The asset list and a JSON-RPC endpoint on a local port, and a service using them on a set clock."""
    state = SimpleNamespace(
        list_status=200,
        list_body=RECORDED_TEXT,
        list_requests=0,
        rpc_status=200,
        rpc_reply=None,
        rpc_delay=0,
        rpc_requests=[],
        clock=1_000_000.0,
    )

    async def asset_list(request):
        state.list_requests += 1
        return web.Response(
            status=state.list_status, text=state.list_body, content_type="application/json"
        )

    async def rpc(request):
        state.rpc_requests.append(await request.json())
        await asyncio.sleep(state.rpc_delay)
        return web.json_response(state.rpc_reply, status=state.rpc_status)

    app = web.Application()
    app.router.add_get("/rhj/assets", asset_list)
    app.router.add_post("/rpc", rpc)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 0).start()
    url = "http://127.0.0.1:%d" % runner.addresses[0][1]
    monkeypatch.setattr(robinhood_assets, "OFFICIAL_ASSETS_URL", f"{url}/rhj/assets")
    monkeypatch.setattr(robinhood_assets, "time", SimpleNamespace(time=lambda: state.clock))
    state.service = RobinhoodAssets(f"{url}/rpc")
    try:
        yield state
    finally:
        await runner.cleanup()


def _shortened(count):
    return json.dumps({**RECORDED, "assets": RECORDED["assets"][:count]})


@pytest.mark.asyncio
async def test_the_list_is_fetched_again_only_once_it_is_six_hours_old(served):
    assert await served.service.listed() == LISTED
    served.clock += CACHE_TTL_SECONDS - 1
    await served.service.listed()
    assert served.list_requests == 1

    served.clock += 1
    await served.service.listed()
    assert served.list_requests == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status, body",
    [(503, RECORDED_TEXT), (200, "<html>"), (200, '{"assets": []}'), (200, _shortened(155))],
    ids=["http-503", "not-json", "no-tokens", "shrank-below-80-percent"],
)
async def test_a_failed_refresh_keeps_the_last_good_list_and_waits_before_retrying(
    served, status, body
):
    await served.service.listed()
    served.clock += CACHE_TTL_SECONDS
    served.list_status, served.list_body = status, body

    assert await served.service.listed() == LISTED
    served.clock += RETRY_SECONDS - 1
    assert await served.service.listed() == LISTED
    assert served.list_requests == 2

    served.clock += 1
    served.list_status, served.list_body = 200, RECORDED_TEXT
    assert await served.service.listed() == LISTED
    assert served.list_requests == 3


@pytest.mark.asyncio
async def test_a_list_that_shrank_by_at_most_a_fifth_replaces_the_last(served):
    await served.service.listed()
    served.clock += CACHE_TTL_SECONDS
    served.list_body = _shortened(156)

    assert len(await served.service.listed()) == 156


@pytest.mark.asyncio
async def test_an_oversized_list_is_not_read(served, monkeypatch):
    monkeypatch.setattr(robinhood_assets, "MAX_LIST_BYTES", len(RECORDED_TEXT.encode("utf-8")) - 1)

    assert await served.service.listed() is None


@pytest.mark.asyncio
async def test_without_a_good_list_checks_are_unknown(served):
    served.list_status = 503

    assert await served.service.listed() is None
    assert await served.service.check(OTHER, "MOON", "Moon") == UNKNOWN_LIST
    assert served.list_requests == 1


@pytest.mark.asyncio
async def test_symbol_and_name_are_read_in_one_batched_request(served):
    served.rpc_reply = [
        {"jsonrpc": "2.0", "id": 1, "result": abi_string("Advanced Micro Dog")},
        {"jsonrpc": "2.0", "id": 0, "result": abi_string("AMD")},
    ]

    result = await served.service.check_onchain(OTHER, 10)

    assert (result["status"], result["symbol"]) == ("collision", "AMD")
    (batch,) = served.rpc_requests
    assert [(call["method"], call["params"][0]) for call in batch] == [
        ("eth_call", {"to": OTHER, "data": "0x95d89b41"}),
        ("eth_call", {"to": OTHER, "data": "0x06fdde03"}),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status, reply",
    [
        (429, None),
        (200, {"jsonrpc": "2.0", "id": 0, "error": {"code": -32005, "message": "rate limited"}}),
        (
            200,
            [
                {"jsonrpc": "2.0", "id": 0, "error": {"code": 3, "message": "execution reverted"}},
                {"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted"}},
            ],
        ),
        (
            200,
            [
                {"jsonrpc": "2.0", "id": 0, "result": "0x"},
                {"jsonrpc": "2.0", "id": 1, "result": "0x"},
            ],
        ),
        (
            200,
            [
                {"jsonrpc": "2.0", "id": 0, "result": "0x1234"},
                {"jsonrpc": "2.0", "id": 1, "result": "nope"},
            ],
        ),
        (
            200,
            [
                {"jsonrpc": "2.0", "id": False, "result": abi_string("AMD")},
                {"jsonrpc": "2.0", "id": True, "result": abi_string("Advanced Micro Dog")},
            ],
        ),
    ],
    ids=["http-429", "rpc-error", "reverted", "no-code", "undecodable", "ids-not-integers"],
)
async def test_a_token_whose_metadata_cannot_be_read_is_unknown_unless_its_address_decides(
    served, status, reply
):
    served.rpc_status, served.rpc_reply = status, reply

    assert await served.service.check_onchain(OTHER, 10) == UNKNOWN_METADATA
    assert (await served.service.check_onchain(NVDA, 10))["status"] == "official"


@pytest.mark.asyncio
async def test_an_oversized_rpc_reply_is_not_read(served, monkeypatch):
    monkeypatch.setattr(robinhood_assets, "MAX_RPC_REPLY_BYTES", 64)
    served.rpc_reply = [
        {"jsonrpc": "2.0", "id": 0, "result": abi_string("AMD")},
        {"jsonrpc": "2.0", "id": 1, "result": abi_string("Advanced Micro Dog")},
    ]

    assert await served.service.check_onchain(OTHER, 10) == UNKNOWN_METADATA


@pytest.mark.asyncio
async def test_a_check_that_outlasts_its_time_is_unknown(served):
    served.rpc_delay = 1

    assert await served.service.check_onchain(OTHER, 0.05) == {
        **UNKNOWN_METADATA,
        "reason": "Official token check timed out",
        "list_size": None,
    }
