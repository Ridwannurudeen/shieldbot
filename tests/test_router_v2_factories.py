"""Every allowlisted Universal Router names the V2 factory its bytecode carries, and the adapter asks that
factory for the pool a mixed route pays (api._analyze_router_swap)."""

from unittest.mock import AsyncMock

import pytest

from adapters import arbitrum, base_chain, bsc, eth, opbnb, optimism, polygon, robinhood
from adapters.bsc import BscAdapter

MODULES = [arbitrum, base_chain, bsc, eth, opbnb, optimism, polygon, robinhood]
PANCAKESWAP_ROUTER = "0x1a0a18ac4becddbd6389559687d1a73d8927e416"
UNISWAP_ROUTER = "0xdc264714f68d84cf29bc605589405e78bdbe7c9f"
TOKEN_A = "0x" + "a1" * 20
TOKEN_B = "0x" + "b2" * 20
POOL = "0x" + "9f" * 20


@pytest.mark.parametrize("module", MODULES, ids=[module.__name__ for module in MODULES])
def test_every_universal_router_has_a_v2_factory(module):
    routers = {
        router for router, name in module.WHITELISTED_ROUTERS.items() if "Universal Router" in name
    }
    assert set(module.ROUTER_V2_FACTORIES) == routers


# Found in each router's bytecode, and for Uniswap's in universal-router's deploy parameters, on 2026-09-28.
@pytest.mark.parametrize(
    "module,router,factory",
    [
        (
            eth,
            "0x23617e59a5925b2a4bf75d73ff6711cd0b29de85",
            "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f",
        ),
        (
            base_chain,
            "0xd6145b2d3f379919e8cdeda7b97e37c4b2ca9c40",
            "0x8909dc15e40173ff4699343b6eb8132c65e18ec6",
        ),
        (
            arbitrum,
            "0x2d01411773c8c24805306e89a41f7855c3c4fe65",
            "0xf1d7cc64fb4452f05c498126312ebe29f30fbcf9",
        ),
        (
            optimism,
            "0xc09255d86db563cbc11c2fcf4a0c512e160111b4",
            "0x0c3c1c532f1e39edf36be9fe0be1410313e074bf",
        ),
        (
            polygon,
            "0xdc264714f68d84cf29bc605589405e78bdbe7c9f",
            "0x9e5a52f57b3038f1b8eee45f28b3c1967e22799c",
        ),
        (bsc, PANCAKESWAP_ROUTER, "0xca143ce32fe78f1f7019d7d551a6402fc5350c73"),
        (
            bsc,
            "0xdc264714f68d84cf29bc605589405e78bdbe7c9f",
            "0x8909dc15e40173ff4699343b6eb8132c65e18ec6",
        ),
        (
            opbnb,
            "0xb89a6778d1efe7a5b7096757a21b810cc2886fa1",
            "0x02a84c1b3bbd7401a5f7fa98a384ebc70bb5749e",
        ),
        (
            robinhood,
            "0x204faca1764b154221e35c0d20abb3c525710498",
            "0x8bceaa40b9acdfaedf85adf4ff01f5ad6517937f",
        ),
        (
            robinhood,
            "0x57fc55f719df19b4b90a03f9d78e1177d002e504",
            "0x02a84c1b3bbd7401a5f7fa98a384ebc70bb5749e",
        ),
    ],
)
def test_a_router_names_the_factory_its_bytecode_carries(module, router, factory):
    assert module.ROUTER_V2_FACTORIES[router] == factory


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "router,factory,pair,expected",
    [
        (PANCAKESWAP_ROUTER, bsc.PANCAKESWAP_V2_FACTORY, "0x" + "9F" * 20, POOL),
        (UNISWAP_ROUTER, bsc.UNISWAP_V2_FACTORY, "0x" + "9F" * 20, POOL),
        (
            PANCAKESWAP_ROUTER.upper().replace("0X", "0x"),
            bsc.PANCAKESWAP_V2_FACTORY,
            "0x" + "9F" * 20,
            POOL,
        ),
        (PANCAKESWAP_ROUTER, bsc.PANCAKESWAP_V2_FACTORY, "0x" + "00" * 20, None),
    ],
    ids=["pool", "another-routers-factory", "router-any-case", "no-pool"],
)
async def test_the_adapter_asks_the_routers_factory_for_the_pool(router, factory, pair, expected):
    """BSC's adapter looks pairs up in PancakeSwap's factory; a Uniswap router's pool is in Uniswap's."""
    adapter = BscAdapter(rpc_url="https://example.invalid")
    adapter._call_with_retry = AsyncMock(return_value=pair)

    assert await adapter.router_v2_pool(router, TOKEN_A, TOKEN_B) == expected
    lookup = adapter._call_with_retry.await_args.args[0]
    assert lookup.__self__.address.lower() == factory.lower()
    assert [arg.lower() for arg in lookup.__self__.args] == [TOKEN_A, TOKEN_B]


@pytest.mark.asyncio
async def test_a_router_without_a_factory_has_no_pool():
    adapter = BscAdapter(rpc_url="https://example.invalid")
    adapter._call_with_retry = AsyncMock()

    assert await adapter.router_v2_pool("0x" + "7e" * 20, TOKEN_A, TOKEN_B) is None
    adapter._call_with_retry.assert_not_awaited()
