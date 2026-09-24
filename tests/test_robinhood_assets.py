"""The official Robinhood Chain token list and the impostor check, against a recorded copy of the list."""

import json
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
OTHER = "0x" + "ab" * 20
UNKNOWN_LIST = {
    "status": "unknown",
    "symbol": None,
    "official_address": None,
    "reason": "Official Robinhood token list unavailable",
}
UNKNOWN_METADATA = {**UNKNOWN_LIST, "reason": "Token symbol or name unavailable"}


def test_the_recorded_list_maps_every_asset_to_its_4663_contract():
    assert len(LISTED) == len(RECORDED["assets"]) == 195
    assert LISTED[NVDA] == ("NVDA", "NVIDIA \N{BULLET} Robinhood Token")


# Tokens live on Robinhood Chain on 2026-09-24, found through GeckoTerminal's robinhood network. The
# official and impostor tokens' symbol() and name() were also read by eth_call.
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
            "impostor",
            "AMD",
        ),
        ("0xf01ab9476afcaa0e0058c83cef2b4c30867abeeb", "AMD", "A Mini Dog", "impostor", "AMD"),
        ("0x982732a974738b771b07a2588f1b38a968a11e18", "TESLAHOOD", "Tesla", "impostor", "TSLA"),
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


def test_an_impostor_names_the_official_contract():
    assert check_token(OTHER, "AMD", "Advanced Micro Dog", LISTED) == {
        "status": "impostor",
        "symbol": "AMD",
        "official_address": AMD,
        "reason": None,
    }


@pytest.mark.parametrize(
    "symbol, name, official",
    [
        ("NVDA", "NVIDIA \N{BULLET} Robinhood Token", "NVDA"),
        ("nvda", "Moon", "NVDA"),
        ("NVDA-", "Moon", "NVDA"),
        ("N.V.D.A", "Moon", "NVDA"),
        ("NVDAX", "Moon", "NVDA"),
        ("wNVDA", "Moon", "NVDA"),
        ("tNVDA", "Moon", "NVDA"),
        ("".join(chr(ord(letter) + 0xFEE0) for letter in "NVDA"), "Moon", "NVDA"),
        ("\N{GREEK CAPITAL LETTER NU}VD\N{GREEK CAPITAL LETTER ALPHA}", "Moon", "NVDA"),
        ("\N{CYRILLIC CAPITAL LETTER TE}SL\N{CYRILLIC CAPITAL LETTER A}", "Moon", "TSLA"),
        ("C0IN", "Moon", "COIN"),
        ("MOON", "nvidia", "NVDA"),
        ("MOON", "Tesla \N{BULLET} Robinhood Token", "TSLA"),
        ("P", "Moon", "P"),
        ("USDG", "Moon", "USDG"),
        ("MOON", "Global Dollar", "USDG"),
        ("WETH", "Moon", "WETH"),
    ],
)
def test_look_alikes_of_an_official_token_are_impostors(symbol, name, official):
    result = check_token(OTHER, symbol, name, LISTED)

    assert (result["status"], result["symbol"]) == ("impostor", official)


@pytest.mark.parametrize(
    "symbol, name",
    [
        ("TON", "Toncoin"),
        ("XP", "Moon"),
        ("TF", "Moon"),
        ("BAT", "Moon"),
        ("XNVDAX", "Moon"),
        ("NVDAS", "Moon"),
        ("MOON", "NVIDIA fan club"),
        ("MOON", "Run"),
        ("", ""),
    ],
)
def test_tokens_that_only_resemble_an_official_one_are_not_impostors(symbol, name):
    assert check_token(OTHER, symbol, name, LISTED) == {
        "status": "none",
        "symbol": None,
        "official_address": None,
        "reason": None,
    }


def test_without_the_list_only_the_canonical_tokens_are_decided():
    assert check_token(USDG, None, None, None)["status"] == "official"
    assert check_token(WETH.upper().replace("0X", "0x"), None, None, None)["symbol"] == "WETH"
    assert check_token(OTHER, "USDG", "Moon", None)["symbol"] == "USDG"
    assert check_token(OTHER, "NVDA", "NVIDIA", None) == UNKNOWN_LIST


@pytest.mark.parametrize("symbol, name", [(None, "Moon"), ("MOON", None), (None, None)])
def test_a_token_whose_symbol_or_name_could_not_be_read_is_unknown(symbol, name):
    assert check_token(OTHER, symbol, name, LISTED) == UNKNOWN_METADATA


def test_what_can_be_read_still_decides():
    assert check_token(OTHER, "NVDA", None, LISTED)["status"] == "impostor"
    assert check_token(OTHER, None, "Tesla", LISTED)["status"] == "impostor"
    assert check_token(NVDA.upper().replace("0X", "0x"), None, None, LISTED)["status"] == "official"


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"assets": {}},
        {"assets": []},
        {"assets": [None]},
        {"assets": [NVDA_ASSET, "junk"]},
        {"assets": [{**NVDA_ASSET, "tokenSymbol": ""}]},
        {"assets": [{**NVDA_ASSET, "tokenName": None}]},
        {"assets": [{**NVDA_ASSET, "deployments": None}]},
        {
            "assets": [
                {**NVDA_ASSET, "deployments": [{"chainId": 4663, "contractAddress": "0x123"}]}
            ]
        },
        {"assets": [{**NVDA_ASSET, "deployments": [{"chainId": 1, "contractAddress": NVDA}]}]},
    ],
)
def test_a_malformed_or_empty_list_is_rejected(payload):
    with pytest.raises(ValueError):
        parse_official_assets(payload)


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
    scan = {
        "rug_probability": 40,
        "critical_flags": ["Low liquidity (<$10k)", "New pair (<24h)", "Mint function detected"],
    }
    check = check_token(OTHER, "NVDA", "Moon", LISTED)

    labelled = with_impostor_check(scan, check)

    assert labelled == {
        **scan,
        "impostor_check": check,
        "critical_flags": ["Impersonates official NVDA token", *scan["critical_flags"]],
    }
    assert scan["critical_flags"] == [
        "Low liquidity (<$10k)",
        "New pair (<24h)",
        "Mint function detected",
    ]


@pytest.mark.parametrize(
    "address, symbol, name, listed",
    [
        (NVDA, "NVDA", "NVIDIA", LISTED),
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
    [(503, RECORDED_TEXT), (200, "<html>"), (200, '{"assets": []}')],
    ids=["http-503", "not-json", "no-tokens"],
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

    result = await served.service.check_onchain(OTHER)

    assert (result["status"], result["symbol"]) == ("impostor", "AMD")
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
    ],
    ids=["http-429", "rpc-error", "reverted", "no-code", "undecodable"],
)
async def test_a_token_whose_metadata_cannot_be_read_is_unknown_unless_its_address_decides(
    served, status, reply
):
    served.rpc_status, served.rpc_reply = status, reply

    assert await served.service.check_onchain(OTHER) == UNKNOWN_METADATA
    assert (await served.service.check_onchain(NVDA))["status"] == "official"
