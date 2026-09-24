"""A liquidity lock that cannot be read is Unknown, never "not locked, rug pull risk"."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from adapters.base_chain import AERODROME_FACTORY, BaseChainAdapter
from adapters.evm_base import FACTORY_ABI, PAIR_ABI, SOLIDLY_FACTORY_ABI, EvmAdapter
from adapters.optimism import VELODROME_V2_FACTORY, OptimismAdapter
from scanner.token_scanner import TokenScanner

TOKEN = "0x" + "ab" * 20
QUOTE = "0x" + "cd" * 20
FACTORY = "0x" + "ef" * 20
PAIR = "0x" + "12" * 20
LOCKER = "0x" + "34" * 20
ZERO = "0x0000000000000000000000000000000000000000"


async def _direct(fn, *args):
    return fn(*args)


def _call(value=None, error=None):
    return MagicMock(call=MagicMock(return_value=value, side_effect=error))


def _wire(adapter, pair_lookup=lambda *args: _call(PAIR), balance_error=None):
    """Answer the factory lookup with pair_lookup(*args); the pair has 1000 LP, 600 in LOCKER."""
    adapter._call_with_retry = _direct
    factory, pair = MagicMock(), MagicMock()
    factory.functions.getPair.side_effect = pair_lookup
    factory.functions.getPool.side_effect = pair_lookup
    pair.functions.totalSupply.return_value = _call(1000)
    pair.functions.balanceOf.side_effect = lambda holder: _call(
        600 if holder.lower() == LOCKER else 0, balance_error
    )
    adapter.w3 = MagicMock()
    adapter.w3.eth.contract.side_effect = lambda address, abi: pair if abi is PAIR_ABI else factory
    return factory


def _bsc(**config):
    return EvmAdapter(
        56,
        "BSC",
        "https://rpc.invalid",
        quote_tokens=[("WBNB", QUOTE)],
        known_lockers={LOCKER: "PinkLock"},
        **config,
    )


@pytest.mark.asyncio
async def test_readable_lock_is_reported():
    adapter = _bsc(factory_address=FACTORY)
    _wire(adapter)
    result = await adapter.get_liquidity_info(TOKEN)
    assert result["is_locked"] is True
    assert result["lock_percentage"] == 60
    assert result["pair"] == PAIR and result["paired_with"] == "WBNB"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case,reason",
    [
        ("no_factory", "No pair factory configured for this chain"),
        ("no_pair", "No pair with a known quote token"),
        ("pair_lookup_error", "Liquidity lookup failed (TimeoutError)"),
        ("locker_read_error", "Liquidity lookup failed (TimeoutError)"),
    ],
)
async def test_unreadable_lock_is_unknown(case, reason):
    if case == "no_factory":
        adapter = _bsc()
    else:
        adapter = _bsc(factory_address=FACTORY)
        _wire(
            adapter,
            pair_lookup={
                "no_pair": lambda *args: _call(ZERO),
                "pair_lookup_error": lambda *args: _call(error=TimeoutError()),
            }.get(case, lambda *args: _call(PAIR)),
            balance_error=TimeoutError() if case == "locker_read_error" else None,
        )
    result = await adapter.get_liquidity_info(TOKEN)
    assert result == {
        "is_locked": None,
        "lock_percentage": None,
        "pair": None,
        "status": "unknown",
        "reason": reason,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter_class,factory_address",
    [(BaseChainAdapter, AERODROME_FACTORY), (OptimismAdapter, VELODROME_V2_FACTORY)],
)
async def test_solidly_chains_find_pools_with_get_pool(adapter_class, factory_address):
    stables = []

    def get_pool(token, quote, stable):
        def call():
            stables.append(stable)
            return PAIR if stable else ZERO

        return MagicMock(call=call)

    adapter = adapter_class(rpc_url="https://rpc.invalid")
    adapter._known_lockers = {LOCKER: "Locker"}
    factory = _wire(adapter, pair_lookup=get_pool)
    result = await adapter.get_liquidity_info(TOKEN)
    assert result["pair"] == PAIR and result["is_locked"] is True
    assert stables == [False, True]
    factory.functions.getPair.assert_not_called()
    factory_contract = adapter.w3.eth.contract.call_args_list[0].kwargs
    assert factory_contract["address"].lower() == factory_address.lower()
    assert factory_contract["abi"] is SOLIDLY_FACTORY_ABI


@pytest.mark.asyncio
async def test_uniswap_v2_chains_keep_get_pair():
    adapter = _bsc(factory_address=FACTORY)
    factory = _wire(adapter)
    await adapter.get_liquidity_info(TOKEN)
    factory.functions.getPool.assert_not_called()
    assert adapter.w3.eth.contract.call_args_list[0].kwargs["abi"] is FACTORY_ABI


def _scanner(liquidity):
    web3 = MagicMock()
    web3.get_liquidity_info = AsyncMock(return_value=liquidity)
    return TokenScanner(web3)


@pytest.mark.asyncio
async def test_token_scanner_reports_an_unknown_lock_as_unknown():
    liquidity = {
        "is_locked": None,
        "lock_percentage": None,
        "pair": None,
        "status": "unknown",
        "reason": "No pair with a known quote token",
    }
    result = {"checks": {}, "risks": []}
    assert await _scanner(liquidity)._check_liquidity(TOKEN, result) is False
    assert result["checks"]["liquidity_locked"] is None
    assert "liquidity_lock_percentage" not in result
    assert result["risks"] == ["Liquidity lock unknown: No pair with a known quote token"]


@pytest.mark.asyncio
async def test_token_scanner_still_warns_on_an_unlocked_pair():
    result = {"checks": {}, "risks": []}
    liquidity = {"is_locked": False, "lock_percentage": 0, "pair": PAIR}
    assert await _scanner(liquidity)._check_liquidity(TOKEN, result) is True
    assert result["checks"]["liquidity_locked"] is False
    assert result["risks"] == ["Liquidity is not locked - risk of rug pull"]


def test_an_unknown_lock_makes_the_safety_level_unknown():
    result = {
        "is_honeypot": False,
        "status": "ok",
        "buy_tax": 1,
        "sell_tax": 1,
        "checks": {
            "can_buy": True,
            "can_sell": True,
            "ownership_renounced": False,
            "liquidity_locked": None,
        },
    }
    assert TokenScanner(MagicMock())._calculate_safety_level(result) == "unknown"
