"""EvmAdapter.get_token_info: its four ERC-20 reads are in flight together, with the same answer and
the same error handling as when they ran one after another."""

import asyncio
import logging
import threading
import time
from unittest.mock import MagicMock

import pytest

from adapters.evm_base import EvmAdapter

ADDRESS = "0x" + "2" * 40
FIELDS = ("name", "symbol", "decimals", "totalSupply")
ANSWERS = {"name": "Tether USD", "symbol": "USDT", "decimals": 6, "totalSupply": 73_960_200 * 10**6}


def adapter_answering(answer):
    """An adapter whose contract answers each field's call() with ``answer(field)``."""
    adapter = EvmAdapter(56, "BSC", "https://rpc.invalid")
    adapter.w3 = MagicMock()
    functions = adapter.w3.eth.contract.return_value.functions
    for field in FIELDS:
        getattr(functions, field).return_value.call.side_effect = lambda field=field: answer(field)
    return adapter


@pytest.mark.asyncio
async def test_the_token_info_is_the_same_four_fields():
    adapter = adapter_answering(ANSWERS.__getitem__)

    assert await adapter.get_token_info(ADDRESS) == {
        "name": "Tether USD",
        "symbol": "USDT",
        "decimals": 6,
        "total_supply": 73_960_200.0,
    }


@pytest.mark.asyncio
async def test_the_four_reads_are_in_flight_together():
    # Each read waits until all four have started: reads sent one after another never get there.
    barrier = threading.Barrier(len(FIELDS), timeout=5)

    def answer(field):
        barrier.wait()
        return ANSWERS[field]

    started = time.monotonic()
    info = await adapter_answering(answer).get_token_info(ADDRESS)

    assert info["symbol"] == "USDT"
    assert time.monotonic() - started < 5


@pytest.mark.asyncio
@pytest.mark.parametrize("failing", FIELDS)
async def test_any_failed_read_loses_the_whole_answer_and_is_logged_once(caplog, failing):
    def answer(field):
        if field == failing:
            raise ValueError("execution reverted")
        return ANSWERS[field]

    caplog.set_level(logging.DEBUG, logger="adapters.evm_base")
    assert await adapter_answering(answer).get_token_info(ADDRESS) == {}
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert errors == ["[BSC] Error getting token info: ValueError"]


@pytest.mark.asyncio
async def test_of_two_failed_reads_the_earlier_field_is_the_one_logged(caplog):
    # decimals fails at once and symbol later, yet symbol comes first in the field order, as it did
    # when the reads ran one after another.
    def answer(field):
        if field == "decimals":
            raise ValueError("decimals reverted")
        if field == "symbol":
            time.sleep(0.2)
            raise KeyError("symbol")
        return ANSWERS[field]

    caplog.set_level(logging.DEBUG, logger="adapters.evm_base")
    assert await adapter_answering(answer).get_token_info(ADDRESS) == {}
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert errors == ["[BSC] Error getting token info: KeyError"]


@pytest.mark.asyncio
async def test_a_cancelled_read_is_not_swallowed():
    def answer(field):
        time.sleep(0.5)
        return ANSWERS[field]

    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.05):
            await adapter_answering(answer).get_token_info(ADDRESS)
