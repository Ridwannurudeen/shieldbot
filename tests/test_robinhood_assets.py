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
    RULES_VERSION,
    SHRUNK_LIST_CONFIRMATIONS,
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
    "pointer": None,
    "third_party": None,
    "canonical": False,
    "also": None,
    "reason": None,
    "list_size": 195,
    "rules": RULES_VERSION,
}
UNKNOWN_LIST = {
    **NO_MATCH,
    "status": "unknown",
    "reason": "Official Robinhood token list unavailable",
    "list_size": None,
}
UNKNOWN_METADATA = {**NO_MATCH, "status": "unknown", "reason": "Token symbol or name unavailable"}


def _match(symbol, name, listed=LISTED):
    result = check_token(OTHER, symbol, name, listed)
    return (
        result["status"],
        result["symbol"],
        result["matched_by"],
        result["pointer"],
        result["third_party"],
    )


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
        # The name's initials spell the ticker the symbol copies, which the collision line warns of.
        (
            "0x1c2a482970ae6b6e5052a7a184c8aef19e0840be",
            "AMD",
            "Advanced Micro Dog",
            "collision",
            "AMD",
        ),
        ("0xf01ab9476afcaa0e0058c83cef2b4c30867abeeb", "AMD", "A Mini Dog", "collision", "AMD"),
        # The company name and HOOD, Robinhood's own ticker, as the symbol.
        ("0x982732a974738b771b07a2588f1b38a968a11e18", "TESLAHOOD", "Tesla", "impostor", "TSLA"),
        # The xStock convention of another issuer.
        (
            "0xd16485b15d38daa99039e2526701025ad4410582",
            "TSLAx",
            "Tesla xStock",
            "collision",
            "TSLA",
        ),
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
    assert check_token(OTHER, "NVDA", "NVIDIA", LISTED) == {
        **NO_MATCH,
        "status": "impostor",
        "symbol": "NVDA",
        "official_address": NVDA,
        "matched_by": "symbol and name",
        "pointer": "ticker",
    }


@pytest.mark.parametrize(
    "symbol, name, official, pointer",
    [
        ("NVDA", "NVIDIA \N{BULLET} Robinhood Token", "NVDA", "ticker"),
        ("NVDA", "NVIDIA", "NVDA", "ticker"),
        ("NVDAX", "Nvidia Stock", "NVDA", "affix"),
        ("TSLAx", "Tesla", "TSLA", "affix"),
        ("TSLA", "Dinari Tesla", "TSLA", "ticker"),
        ("TSLA", "Tesla Wrapped", "TSLA", "ticker"),
        ("TSLA", "Tesla Backed", "TSLA", "ticker"),
        ("P", "Everpure", "P", "ticker"),
        ("NVDA", "NVIDIA Tokenized Stock", "NVDA", "ticker"),
        ("NVDA", "NVIDIA Tokenised Stock", "NVDA", "ticker"),
    ],
)
def test_a_ticker_and_a_name_pointing_at_the_same_official_token_are_an_impostor(
    symbol, name, official, pointer
):
    assert _match(symbol, name) == ("impostor", official, "symbol and name", pointer, None)


@pytest.mark.parametrize(
    "symbol, name, official",
    [
        ("TESLA", "Tesla", "TSLA"),
        ("CELSIUS", "Celsius", "CELH"),
        ("ZOOM", "Zoom", "ZM"),
        ("APPLE", "Apple", "AAPL"),
    ],
)
def test_the_company_name_as_symbol_and_name_is_one_signal_and_a_collision(symbol, name, official):
    assert _match(symbol, name) == ("collision", official, "symbol and name", "company", None)


@pytest.mark.parametrize(
    "symbol, name",
    [
        ("DJT", "Donald J Trump"),
        ("TEAM", "Together Everyone Achieves More"),
        ("SATS", "Stack All The Sats"),
        ("AMD", "Advanced Micro Dog"),
        ("NVDA", "New Venture Dog Army"),
    ],
)
def test_a_name_spelling_the_ticker_it_copies_is_a_collision(symbol, name):
    assert _match(symbol, name) == ("collision", symbol, "symbol and initials", "ticker", None)


@pytest.mark.parametrize(
    "symbol, name, matched_by, pointer",
    [
        ("MOON", "Tesla \N{BULLET} Robinhood Token", "name", "company"),
        ("MOON", "Robinhood Tesla", "name", "company"),
        ("MOON", "Tesla Inc. Robinhood Token", "name", "company"),
        ("MOON", "TESLA robinhood", "name", "company"),
        ("TSLA", "TSLA \N{BULLET} Robinhood Token", "symbol", "ticker"),
        ("TSLA", "Robinhood Token", "symbol", "ticker"),
        ("TESLAHOOD", "Moon", "symbol", "robinhood"),
        ("TSLARH", "Moon", "symbol", "robinhood"),
        ("TSLAx", "Tesla xStock \N{BULLET} Robinhood Token", "symbol and name", "affix"),
    ],
)
def test_a_symbol_or_name_claiming_robinhood_for_an_official_token_is_an_impostor(
    symbol, name, matched_by, pointer
):
    assert _match(symbol, name) == ("impostor", "TSLA", matched_by, pointer, None)


@pytest.mark.parametrize("symbol, name", [("APP", "Robinhood App"), ("COIN", "Robinhood Coin")])
def test_a_common_word_ticker_beside_robinhood_is_an_impostor_by_design(symbol, name):
    # The known false-positive surface of the Robinhood claim, kept so that TSLA "Robinhood Token" is caught.
    assert _match(symbol, name) == ("impostor", symbol, "symbol", "ticker", None)


@pytest.mark.parametrize(
    "symbol, name, official",
    [
        ("".join(chr(ord(letter) + 0xFEE0) for letter in "NVDA"), "Moon", "NVDA"),
        ("\N{GREEK CAPITAL LETTER NU}VD\N{GREEK CAPITAL LETTER ALPHA}", "Moon", "NVDA"),
        ("\N{CYRILLIC CAPITAL LETTER TE}SL\N{CYRILLIC CAPITAL LETTER A}", "Moon", "TSLA"),
        ("C0IN", "Moon", "COIN"),
        ("lNTC", "Moon", "INTC"),
        ("1NTC", "Moon", "INTC"),
        ("|NTC", "Moon", "INTC"),
        ("T5LA", "Moon", "TSLA"),
        ("NVD\N{LATIN CAPITAL LETTER A WITH ACUTE}", "Moon", "NVDA"),
        (
            "MOON",
            "T\N{LATIN SMALL LETTER E WITH ACUTE}sl\N{LATIN SMALL LETTER A WITH ACUTE}",
            "TSLA",
        ),
        ("MOON", "\N{CYRILLIC CAPITAL LETTER TE}esla", "TSLA"),
        ("MOON", "TesIa", "TSLA"),
        ("MOON", "NVlDlA", "NVDA"),
        ("MOON", "TE5LA HOLDINGS", "TSLA"),
        ("MOON", "TE5LA Holdings", "TSLA"),
    ],
)
def test_a_match_that_needs_look_alike_folding_is_an_impostor(symbol, name, official):
    result = check_token(OTHER, symbol, name, LISTED)

    assert (result["status"], result["symbol"], result["pointer"]) == (
        "impostor",
        official,
        "look-alike",
    )


@pytest.mark.parametrize(
    "symbol, name, official, matched_by, pointer",
    [
        ("nvda", "Moon", "NVDA", "symbol", "ticker"),
        ("NVDA-", "Moon", "NVDA", "symbol", "ticker"),
        ("N.V.D.A", "Moon", "NVDA", "symbol", "ticker"),
        ("NVDAX", "Moon", "NVDA", "symbol", "affix"),
        ("tNVDA", "Moon", "NVDA", "symbol", "affix"),
        ("TSLAx", "Moon", "TSLA", "symbol", "affix"),
        ("TESLA", "Moon", "TSLA", "symbol", "company"),
        ("MOON", "nvidia", "NVDA", "name", "company"),
        ("MOON", "Tesla Stock", "TSLA", "name", "company"),
        ("MOON", "Tesla, Inc. dShares", "TSLA", "name", "company"),
        ("MOON", "Wrapped Tesla", "TSLA", "name", "company"),
        ("MOON", "Cloudflare, Inc. Class A common stock", "NET", "name", "company"),
        ("MOON", "Tesla Holdings", "TSLA", "name", "company"),
        ("MOON", "SK hynix Inc. American Depositary Shares", "SKHY", "name", "company"),
        ("MOON", "Nebius Group", "NBIS", "name", "company"),
        ("MOON", "IREN Ltd", "IREN", "name", "company"),
        ("MOON", "ASML Holding N.V.", "ASML", "name", "company"),
    ],
)
def test_a_bare_ticker_or_company_name_is_a_collision(symbol, name, official, matched_by, pointer):
    assert _match(symbol, name) == ("collision", official, matched_by, pointer, None)


@pytest.mark.parametrize(
    "symbol, name, official, matched_by, convention",
    [
        ("TSLAx", "Tesla xStock", "TSLA", "symbol and name", "xStock"),
        ("TSLA.d", "Tesla, Inc. dShares", "TSLA", "symbol and name", "dShares"),
        ("TSLA.d", "Tesla", "TSLA", "symbol and name", "dShares"),
        ("TSLA.d", "Moon", "TSLA", "symbol", "dShares"),
        ("wNVDA", "Nvidia", "NVDA", "symbol and name", "Wrapped"),
        ("wNVDA", "Moon", "NVDA", "symbol", "Wrapped"),
        ("bTSLA", "Backed Tesla", "TSLA", "symbol and name", "Backed"),
        ("bTSLA", "Backed", "TSLA", "symbol", "Backed"),
    ],
)
def test_a_symbol_in_another_issuers_convention_is_a_third_party_collision(
    symbol, name, official, matched_by, convention
):
    assert _match(symbol, name) == ("collision", official, matched_by, "affix", convention)


@pytest.mark.parametrize(
    "symbol, name, status, matched_by, pointer",
    [
        ("WETH", "WETH", "impostor", "symbol and name", "ticker"),
        ("USDG", "Global Dollar", "impostor", "symbol and name", "ticker"),
        ("WETH", "Wrapped Ether", "collision", "symbol", "ticker"),
        ("wWETH", "Moon", "collision", "symbol", "affix"),
        ("USDG", "Moon", "collision", "symbol", "ticker"),
        ("MOON", "Global Dollar", "collision", "name", "company"),
    ],
)
def test_a_canonical_token_is_matched_as_canonical_and_never_third_party(
    symbol, name, status, matched_by, pointer
):
    result = check_token(OTHER, symbol, name, LISTED)

    assert (
        result["status"],
        result["matched_by"],
        result["pointer"],
        result["third_party"],
        result["canonical"],
    ) == (
        status,
        matched_by,
        pointer,
        None,
        True,
    )


@pytest.mark.parametrize(
    "symbol, name",
    [
        ("P", "Moon"),
        ("P", "Robinhood Token"),
        ("\N{CYRILLIC CAPITAL LETTER ER}", "Moon"),
        ("TON", "Toncoin"),
        ("XP", "Moon"),
        ("TF", "Moon"),
        ("BAT", "Moon"),
        ("XNVDAX", "Moon"),
        ("NVDAS", "Moon"),
        ("bTSLA", "Moon"),
        ("ILY", "Moon"),
        ("AAP1", "Moon"),
        ("lntc", "Moon"),
        ("MOON", "Te5la"),
        ("MOON", "Tesla X"),
        ("MOON", "NVIDIA fan club"),
        ("MOON", "Run"),
        ("MOON", "Robinhood Token"),
        ("MOON", "Nice Easy Trade"),
        ("", ""),
    ],
)
def test_tokens_that_only_resemble_an_official_one_are_not_matched(symbol, name):
    assert check_token(OTHER, symbol, name, LISTED) == NO_MATCH


def test_the_symbols_official_is_named_first_and_the_names_is_also_reported():
    collision = check_token(OTHER, "AMD", "Tesla", LISTED)
    claims = check_token(OTHER, "AMD", "Tesla \N{BULLET} Robinhood Token", LISTED)
    look_alike = check_token(OTHER, "AMD", "TesIa", LISTED)

    assert (collision["status"], collision["symbol"], collision["matched_by"]) == (
        "collision",
        "AMD",
        "symbol",
    )
    assert collision["also"] == {"symbol": "TSLA", "official_address": TSLA}
    # The name's Robinhood claim counts for the official the symbol points at too.
    assert (claims["status"], claims["symbol"], claims["matched_by"]) == (
        "impostor",
        "AMD",
        "symbol",
    )
    assert claims["also"] == {"symbol": "TSLA", "official_address": TSLA}
    # A stronger match by the name comes first.
    assert (look_alike["status"], look_alike["symbol"], look_alike["matched_by"]) == (
        "impostor",
        "TSLA",
        "name",
    )
    assert look_alike["also"] == {"symbol": "AMD", "official_address": AMD}


def test_without_the_list_only_the_canonical_tokens_are_decided():
    assert check_token(USDG, None, None, None)["status"] == "official"
    assert check_token(WETH.upper().replace("0X", "0x"), None, None, None)["symbol"] == "WETH"
    assert check_token(OTHER, "USDG", "Global Dollar", None)["status"] == "impostor"
    assert check_token(OTHER, "NVDA", "NVIDIA", None) == UNKNOWN_LIST


def test_an_official_or_canonical_address_is_marked_as_such():
    assert check_token(NVDA, None, None, LISTED)["canonical"] is False
    assert check_token(WETH, None, None, LISTED)["canonical"] is True


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


@pytest.mark.parametrize(
    "symbol, name, flag",
    [
        (
            "NVDA",
            "NVIDIA",
            f"Impersonates official NVDA token (Robinhood-issued); official contract {NVDA}",
        ),
        (
            "WETH",
            "WETH",
            f"Impersonates the canonical WETH of Robinhood Chain; canonical contract {WETH}",
        ),
    ],
)
def test_an_impostor_flag_leads_the_critical_flags(symbol, name, flag):
    scan = {"rug_probability": 40, "critical_flags": ["Low liquidity (<$10k)", "New pair (<24h)"]}
    check = check_token(OTHER, symbol, name, LISTED)

    labelled = with_impostor_check(scan, check)

    assert labelled == {
        **scan,
        "impostor_check": check,
        "critical_flags": [flag, *scan["critical_flags"]],
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
async def test_a_list_that_shrank_further_is_taken_once_fetched_at_the_same_size_three_times(
    served, caplog
):
    await served.service.listed()
    served.clock += CACHE_TTL_SECONDS
    served.list_body = _shortened(100)

    with caplog.at_level(logging.ERROR, logger="services.robinhood_assets"):
        sizes = []
        for _ in range(SHRUNK_LIST_CONFIRMATIONS):
            sizes.append(len(await served.service.listed()))
            served.clock += RETRY_SECONDS

    assert SHRUNK_LIST_CONFIRMATIONS == 3
    assert sizes == [195, 195, 100]
    assert caplog.text.count("shrank from 195 to 100 tokens") == 2


@pytest.mark.asyncio
async def test_a_shrunken_list_of_another_size_starts_the_count_again(served):
    await served.service.listed()
    for count in (100, 101, 100, 100):
        served.clock += CACHE_TTL_SECONDS
        served.list_body = _shortened(count)
        await served.service.listed()

    assert len(await served.service.listed()) == 195
    served.clock += CACHE_TTL_SECONDS
    assert len(await served.service.listed()) == 100


@pytest.mark.asyncio
async def test_a_failed_fetch_between_shrunken_lists_neither_counts_nor_resets(served):
    await served.service.listed()
    sizes = []
    for status in (200, 503, 200, 200):
        served.clock += CACHE_TTL_SECONDS
        served.list_status, served.list_body = status, _shortened(100)
        sizes.append(len(await served.service.listed()))

    assert sizes == [195, 195, 195, 100]
    assert served.list_requests == 5


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
        {"jsonrpc": "2.0", "id": 1, "result": abi_string("NVIDIA")},
        {"jsonrpc": "2.0", "id": 0, "result": abi_string("NVDA")},
    ]

    result = await served.service.check_onchain(OTHER, 10)

    assert (result["status"], result["symbol"]) == ("impostor", "NVDA")
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
                {"jsonrpc": "2.0", "id": False, "result": abi_string("NVDA")},
                {"jsonrpc": "2.0", "id": True, "result": abi_string("NVIDIA")},
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
        {"jsonrpc": "2.0", "id": 0, "result": abi_string("NVDA")},
        {"jsonrpc": "2.0", "id": 1, "result": abi_string("NVIDIA")},
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
