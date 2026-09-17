"""Logging in the shared EVM adapter must not expose exception text."""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
import requests

from adapters.evm_base import EvmAdapter
from services.explorer_service import ExplorerResult


ADDRESS = "0x89e5db8b5aa49aa85ac63f691524311aeb649eba"
FUNDER = "0x" + "1" * 40
TX_HASH = "0x" + "a" * 64
TEST_KEY = "retry-log-test-key"
RPC_URL = f"https://rpc.invalid/v2/{TEST_KEY}"
FACTORY = "0x" + "2" * 40
QUOTE = "0x" + "3" * 40
PAIR = "0x" + "4" * 40


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


def _rpc_rate_limit():
    return requests.exceptions.HTTPError(
        f"429 Client Error: Too Many Requests for url: {RPC_URL}"
    )


def _fail_get_code(w3):
    w3.eth.get_code.side_effect = _rpc_rate_limit()
    return w3.eth.get_code


def _fail_contract_call(name):
    def fail(w3):
        call = getattr(w3.eth.contract.return_value.functions, name).return_value.call
        call.side_effect = _rpc_rate_limit()
        return call
    return fail


def _fail_pair_total_supply(w3):
    w3.eth.contract.return_value.functions.getPair.return_value.call.return_value = PAIR
    return _fail_contract_call("totalSupply")(w3)


@pytest.mark.asyncio
@pytest.mark.parametrize("method,fail", [
    ("is_contract", _fail_get_code),
    ("get_bytecode", _fail_get_code),
    ("get_token_info", _fail_contract_call("name")),
    ("get_ownership_info", _fail_contract_call("owner")),
    ("get_liquidity_info", _fail_pair_total_supply),
])
async def test_rpc_error_handlers_log_class_without_rpc_url(caplog, method, fail):
    adapter = EvmAdapter(
        4663, "Robinhood Chain", RPC_URL,
        quote_tokens=[("WETH", QUOTE)], factory_address=FACTORY,
    )
    adapter.w3 = MagicMock()
    failing_call = fail(adapter.w3)
    caplog.set_level(logging.DEBUG, logger="adapters.evm_base")
    with patch("adapters.evm_base.asyncio.sleep", new_callable=AsyncMock):
        await getattr(adapter, method)(ADDRESS)
    assert failing_call.call_count == 3
    assert TEST_KEY not in caplog.text
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and errors[0].endswith(": HTTPError")


@pytest.mark.asyncio
@pytest.mark.parametrize("method,prefix", [
    ("check_honeypot", "Error checking honeypot.is"),
    ("get_tax_info", "Error getting honeypot.is taxes"),
])
async def test_honeypot_errors_return_and_log_class_without_exception_text(caplog, method, prefix):
    adapter = EvmAdapter(56, "BSC", "https://rpc.invalid", honeypot_chain_id=56)
    error = aiohttp.ClientConnectionError(f"Cannot connect to host: {TEST_KEY}")
    caplog.set_level(logging.DEBUG, logger="adapters.evm_base")
    with patch("adapters.evm_base.aiohttp.ClientSession", side_effect=error):
        result = await getattr(adapter, method)(ADDRESS)
    assert result["status"] == "unknown"
    assert result["reason"] == f"{prefix}: ClientConnectionError"
    assert TEST_KEY not in caplog.text
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and errors[0].endswith(": ClientConnectionError")
