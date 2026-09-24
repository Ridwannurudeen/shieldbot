"""One creation lookup per contract, shared by a scan's structural, payment and spender checks."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from adapters.evm_base import EvmAdapter

ADDRESS = "0x" + "1" * 40
DATED = {
    "tx_hash": "0x" + "a" * 64,
    "creator": "0x" + "2" * 40,
    "creation_time": "2026-09-22T00:00:00+00:00",
    "age_days": 2,
}


def _adapter(answer):
    adapter = EvmAdapter(56, "BSC", "https://rpc.invalid", etherscan_api_key="test-key")
    adapter._fetch_creation_info = AsyncMock(return_value=answer)
    return adapter


@pytest.mark.asyncio
async def test_a_dated_creation_is_fetched_once_and_copied_to_each_caller():
    adapter = _adapter(dict(DATED))
    first, second = await asyncio.gather(
        adapter.get_contract_creation_info(ADDRESS), adapter.get_contract_creation_info(ADDRESS)
    )
    first["age_days"] = 999
    third = await adapter.get_contract_creation_info(ADDRESS.upper().replace("0X", "0x"))
    assert second == third == DATED
    adapter._fetch_creation_info.assert_awaited_once_with(ADDRESS)
    assert adapter._creation_inflight == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer", [None, {**DATED, "creation_time": None, "age_days": None}], ids=["failed", "undated"]
)
async def test_a_failed_or_undated_creation_is_asked_again(answer):
    adapter = _adapter(answer)
    assert await adapter.get_contract_creation_info(ADDRESS) == answer
    await adapter.get_contract_creation_info(ADDRESS)
    assert adapter._fetch_creation_info.await_count == 2


@pytest.mark.asyncio
async def test_chains_do_not_share_creations():
    bsc = _adapter(dict(DATED))
    base = EvmAdapter(8453, "Base", "https://rpc.invalid")
    base._fetch_creation_info = AsyncMock(return_value=None)
    await bsc.get_contract_creation_info(ADDRESS)
    assert await base.get_contract_creation_info(ADDRESS) is None
