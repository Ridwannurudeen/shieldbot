"""The RPC retry decision uses structured error data, never exception text."""

import io
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests

from adapters.evm_base import EvmAdapter


TEST_KEY = "retry-classifier-key"
RPC_URL = f"https://rpc.invalid/v2/{TEST_KEY}"
ADDRESS = "0x4290000000000000000000000000000000000503"


def _provider_reply(status, error=None):
    """Patch requests so the installed web3 builds its own exception from an RPC reply."""

    def post(session, url, data=None, **kwargs):
        request = json.loads(data)
        body = {"jsonrpc": "2.0", "id": request["id"]}
        body.update({"error": error} if error else {"result": "0x"})
        response = requests.Response()
        response.status_code = status
        response.reason = "Provider reply"
        response.url = url
        response.encoding = "utf-8"
        response.raw = io.BytesIO(json.dumps(body).encode())
        return response

    return patch.object(requests.Session, "post", post)


async def _attempts(caplog, call, status, error=None):
    adapter = EvmAdapter(4663, "Robinhood Chain", RPC_URL)
    if call == "get_code":
        fn, args = MagicMock(side_effect=adapter.w3.eth.get_code), (ADDRESS,)
    else:
        fn, args = MagicMock(side_effect=adapter.w3.eth.call), ({"to": ADDRESS, "data": "0x"},)
    caplog.set_level(logging.DEBUG, logger="adapters.evm_base")
    with (
        _provider_reply(status, error),
        patch("time.sleep"),
        patch("adapters.evm_base.asyncio.sleep", new_callable=AsyncMock) as sleep,
    ):
        with pytest.raises(Exception) as raised:
            await adapter._call_with_retry(fn, *args, retries=3, base_delay=1.0)
    assert TEST_KEY not in caplog.text
    return fn.call_count, sleep.await_count, raised.value


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 502, 503])
async def test_transient_http_status_raised_by_web3_is_retried(caplog, status):
    attempts, sleeps, error = await _attempts(caplog, "get_code", status)
    assert isinstance(error, requests.exceptions.HTTPError)
    assert error.response.status_code == status
    assert (attempts, sleeps) == (3, 2)
    assert "HTTPError" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 403, 404, 500])
async def test_other_http_status_raised_by_web3_is_not_retried(caplog, status):
    attempts, sleeps, error = await _attempts(caplog, "get_code", status)
    assert isinstance(error, requests.exceptions.HTTPError)
    assert (attempts, sleeps) == (1, 0)


@pytest.mark.asyncio
async def test_json_rpc_rate_limit_code_raised_by_web3_is_retried(caplog):
    attempts, sleeps, _ = await _attempts(
        caplog,
        "get_code",
        200,
        {"code": -32005, "message": "request rate exceeded"},
    )
    assert (attempts, sleeps) == (3, 2)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "call, error",
    [
        ("get_code", {"code": -32602, "message": "invalid params: 429 502 503"}),
        ("get_code", {"code": -32601, "message": "the method eth_getCode does not exist (429)"}),
        ("get_code", {"code": -32000, "message": "header not found for 0x429503"}),
        ("call", {"code": 3, "message": "execution reverted: 429 Too Many Requests"}),
        ("call", {"code": -32000, "message": "execution reverted: HTTP 503"}),
    ],
)
async def test_deterministic_json_rpc_error_raised_by_web3_is_not_retried(caplog, call, error):
    attempts, sleeps, _ = await _attempts(caplog, call, 200, error)
    assert (attempts, sleeps) == (1, 0)


def _web3_6_rpc_error(code, message):
    # web3 6.15.1 RequestManager.formatted_response: ``raise ValueError(error)`` with the error object.
    return ValueError({"code": code, "message": message})


async def _direct_attempts(error):
    adapter = EvmAdapter(4663, "Robinhood Chain", RPC_URL)
    fn = MagicMock(side_effect=error)
    with patch("adapters.evm_base.asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(type(error)):
            await adapter._call_with_retry(fn, retries=3, base_delay=1.0)
    return fn.call_count


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error, attempts",
    [
        (_web3_6_rpc_error(-32005, "limit exceeded"), 3),
        (_web3_6_rpc_error(-32000, "429 Too Many Requests"), 1),
        (_web3_6_rpc_error(-32602, "invalid argument 0: 503"), 1),
        (ValueError("429 Too Many Requests"), 1),
        (RuntimeError(f"503 Service Unavailable for url: {RPC_URL}"), 1),
        (requests.exceptions.HTTPError(f"429 Client Error for url: {RPC_URL}"), 1),
    ],
)
async def test_retry_ignores_exception_text(error, attempts):
    assert await _direct_attempts(error) == attempts
