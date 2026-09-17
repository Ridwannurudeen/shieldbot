"""Retry logging in the shared EVM adapter must not expose exception text."""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from adapters.evm_base import EvmAdapter
from services.explorer_service import ExplorerResult


ADDRESS = "0x89e5db8b5aa49aa85ac63f691524311aeb649eba"
FUNDER = "0x" + "1" * 40
TX_HASH = "0x" + "a" * 64
TEST_KEY = "retry-log-test-key"


def _provider_error(status):
    return RuntimeError(f"{status} Server Error: https://rpc.invalid/?apikey={TEST_KEY}")


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["429", "502", "503"])
async def test_retry_warnings_log_class_and_attempts_without_exception_text(caplog, status):
    adapter = EvmAdapter(4663, "Robinhood Chain", "https://rpc.invalid")
    fn = MagicMock(side_effect=_provider_error(status))
    caplog.set_level(logging.DEBUG, logger="adapters.evm_base")
    with patch("adapters.evm_base.asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(RuntimeError):
            await adapter._call_with_retry(fn, retries=3, base_delay=1.0)
    assert fn.call_count == 3
    assert [call.args for call in sleep.await_args_list] == [(1.0,), (2.0,)]
    records = [r for r in caplog.records if r.name == "adapters.evm_base"]
    assert [r.levelno for r in records] == [logging.WARNING, logging.WARNING]
    assert TEST_KEY not in caplog.text
    assert "attempt 1/3" in caplog.text and "attempt 2/3" in caplog.text
    assert "RuntimeError" in caplog.text


@pytest.mark.asyncio
async def test_non_retriable_error_is_raised_without_retry_or_log(caplog):
    adapter = EvmAdapter(4663, "Robinhood Chain", "https://rpc.invalid")
    fn = MagicMock(side_effect=_provider_error("400"))
    caplog.set_level(logging.DEBUG, logger="adapters.evm_base")
    with patch("adapters.evm_base.asyncio.sleep", new_callable=AsyncMock) as sleep:
        with pytest.raises(RuntimeError):
            await adapter._call_with_retry(fn, retries=3, base_delay=1.0)
    assert fn.call_count == 1
    sleep.assert_not_awaited()
    assert TEST_KEY not in caplog.text


@pytest.mark.asyncio
async def test_creation_time_enrichment_retries_do_not_log_key(caplog):
    adapter = EvmAdapter(4663, "Robinhood Chain", "https://rpc.invalid")
    adapter._explorer_service = MagicMock()
    adapter._explorer_service.get_contract_creation_info = AsyncMock(
        return_value=ExplorerResult("known", data={"creator": FUNDER, "tx_hash": TX_HASH})
    )
    adapter.w3 = MagicMock()
    adapter.w3.eth.get_transaction.side_effect = _provider_error("429")
    caplog.set_level(logging.DEBUG, logger="adapters.evm_base")
    with patch("adapters.evm_base.asyncio.sleep", new_callable=AsyncMock):
        result = await adapter.get_contract_creation_info(ADDRESS)
    assert result["creator"] == FUNDER and result["creation_time"] is None
    assert adapter.w3.eth.get_transaction.call_count == 3
    assert TEST_KEY not in caplog.text
    assert "RuntimeError" in caplog.text
