"""A GoPlus rate limit is retried with backoff before the result is cached as unknown."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import utils.scam_db as scam_module
from scanner.transaction_scanner import TransactionScanner
from utils.scam_db import ScamDatabase


ADDRESS = "0x1111111111111111111111111111111111111111"
TOKEN = {"is_honeypot": "1", "is_blacklisted": "0"}


@pytest.fixture(autouse=True)
def goplus_cache():
    scam_module._GOPLUS_CACHE.clear()
    yield
    scam_module._GOPLUS_CACHE.clear()


def _replies(*replies):
    """Serve one (status, payload) reply per request from a single mocked session."""
    responses = []
    for status, payload in replies:
        response = MagicMock(status=status)
        response.json = AsyncMock(return_value=payload)
        responses.append(response)
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(side_effect=responses)
    session.get.return_value.__aexit__ = AsyncMock(return_value=False)
    return session


async def _fetch(session, address=ADDRESS, chain_id=4663):
    with (
        patch("utils.scam_db.aiohttp.ClientSession") as factory,
        patch("utils.scam_db.asyncio.sleep", new_callable=AsyncMock) as sleep,
        patch("utils.scam_db.time.time", return_value=1000),
    ):
        factory.return_value.__aenter__ = AsyncMock(return_value=session)
        factory.return_value.__aexit__ = AsyncMock(return_value=False)
        result = await ScamDatabase.fetch_token_security(address, chain_id)
    return result, sleep


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply, reason",
    [
        ((429, {}), "GoPlus HTTP 429"),
        ((200, {"code": 4029, "result": {}}), "GoPlus returned code 4029"),
        ((200, {"code": 2, "result": {}}), "GoPlus returned code 2"),
    ],
)
async def test_rate_limited_reply_is_retried_with_backoff_then_cached_unknown(reply, reason):
    session = _replies(reply, reply, reply)
    result, sleep = await _fetch(session)
    assert session.get.call_count == 3
    assert [call.args for call in sleep.await_args_list] == [(0.5,), (1.0,)]
    assert result == {"status": "unknown", "reason": reason, "data": {}, "observed_at": 1000}
    # The genuine failure is still negative-cached for the 30 s window.
    cached, cached_sleep = await _fetch(session)
    assert cached == result
    assert session.get.call_count == 3
    cached_sleep.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "first",
    [
        (429, {}),
        (200, {"code": 4029, "result": {}}),
        (200, {"code": 2, "result": {}}),
    ],
)
async def test_retry_then_success_returns_the_token_data(first):
    session = _replies(first, (200, {"code": 1, "result": {ADDRESS: TOKEN}}))
    result, sleep = await _fetch(session)
    assert session.get.call_count == 2
    assert [call.args for call in sleep.await_args_list] == [(0.5,)]
    assert result == {"status": "ok", "reason": None, "data": TOKEN, "observed_at": 1000}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply, reason",
    [
        ((500, {}), "GoPlus HTTP 500"),
        ((404, {}), "GoPlus HTTP 404"),
        ((200, {"code": 0, "result": {}}), "GoPlus returned an unsuccessful response"),
        (
            (
                200,
                [],
            ),
            "GoPlus returned an unsuccessful response",
        ),
        ((200, {"code": 1, "message": "OK", "result": {}}), scam_module._GOPLUS_NO_DATA),
    ],
)
async def test_other_replies_are_not_retried(reply, reason):
    session = _replies(reply)
    result, sleep = await _fetch(session)
    assert session.get.call_count == 1
    sleep.assert_not_awaited()
    assert result == {"status": "unknown", "reason": reason, "data": {}, "observed_at": 1000}


@pytest.mark.asyncio
async def test_transport_failure_keeps_its_class_only_reason(caplog):
    session = MagicMock()
    session.get.side_effect = TimeoutError()
    result, sleep = await _fetch(session)
    assert result["reason"] == "GoPlus request failed (TimeoutError)"
    sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_exhausted_rate_limit_retries_leave_the_scan_unknown(mock_web3_client):
    reply = (429, {})
    session = _replies(reply, reply, reply)
    with (
        patch("utils.scam_db.aiohttp.ClientSession") as factory,
        patch("utils.scam_db.asyncio.sleep", new_callable=AsyncMock),
    ):
        factory.return_value.__aenter__ = AsyncMock(return_value=session)
        factory.return_value.__aexit__ = AsyncMock(return_value=False)
        result = await TransactionScanner(mock_web3_client).scan_address(ADDRESS, chain_id=56)
    assert session.get.call_count == 3
    assert result["status"] == "unknown"
    assert result["coverage"]["scam_database"] is False
    assert result["coverage_reasons"]["scam_database"] == "scam_database unknown: GoPlus HTTP 429"
    assert result["checks"]["scam_database_clean"] is None
