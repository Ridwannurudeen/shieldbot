"""A rescue scan sets its connections to the chain's RPC up once.

The approval history, allowance and balance reads share one aiohttp connector, so a connection
opened for the history is reused by the reads after it rather than set up again. Each read still
opens its own session over it, as before, so each keeps its own cookies. The scan closes the
connector however it ends. DexScreener, another host, keeps its own session and connector.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, call, patch

import aiohttp
import pytest

from services.rescue_service import (
    HISTORY_DEADLINE_SECONDS,
    NOTHING_READ_REASON,
    RPC_UNAVAILABLE_REASON,
    SCAN_DEADLINE_SECONDS,
    SCAN_TIMEOUT_REASON,
    RescueService,
)
from tests.test_rescue_bounded_history import (
    TOKEN,
    WALLET,
    FakeRpc,
    chain_handler,
    ok,
    rescue_service,
)
from tests.test_rescue_scan_deadline import ARCHIVE, CHUNK, DelayedRpc, archive_handler, delayed

_real_sleep = asyncio.sleep


@pytest.fixture
def connectors():
    """Each aiohttp.TCPConnector the rescue scan creates, with the arguments it was given. They are
    real connectors: only their creation is recorded."""
    real = aiohttp.TCPConnector
    created = []

    def create(*args, **kwargs):
        connector = real(*args, **kwargs)
        created.append((connector, args, kwargs))
        return connector

    with patch("services.rescue_service.aiohttp.TCPConnector", side_effect=create):
        yield created


async def scan(
    service, rpc, chain_id, history=HISTORY_DEADLINE_SECONDS, total=SCAN_DEADLINE_SECONDS
):
    """Run a scan whose sessions all answer through ``rpc``; returns the result and the session
    factory, whose calls show how each session was opened."""
    with (
        patch("services.rescue_service.aiohttp.ClientSession") as sessions,
        patch("services.rescue_service.asyncio.sleep", AsyncMock()),
        patch("services.rescue_service.HISTORY_DEADLINE_SECONDS", history),
        patch("services.rescue_service.SCAN_DEADLINE_SECONDS", total),
    ):
        sessions.return_value.__aenter__.return_value = rpc
        result = await asyncio.wait_for(service.scan_approvals(WALLET, chain_id), 5)
    return result, sessions


def only_connector(connectors):
    assert len(connectors) == 1
    connector, args, kwargs = connectors[0]
    # The defaults a ClientSession gives its own connector: 100 connections, no limit per host.
    assert (args, kwargs) == ((), {})
    return connector


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [42161, 4663])
async def test_a_public_rpc_scan_reads_history_allowances_and_balances_over_one_connector(
    connectors, chain_id
):
    result, sessions = await scan(rescue_service(), FakeRpc(chain_handler()), chain_id)

    connector = only_connector(connectors)
    # History, allowances, balances: a session each, none of them owning the connector.
    assert sessions.call_args_list == [call(connector=connector, connector_owner=False)] * 3
    assert connector.closed
    assert [(a["token_address"], a["risk_level"]) for a in result["approvals"]] == [(TOKEN, "HIGH")]


@pytest.mark.asyncio
async def test_a_logs_rpc_scan_reads_its_full_history_and_the_allowances_over_one_connector_too(
    connectors,
):
    latest = 2 * CHUNK + 10
    result, sessions = await scan(
        rescue_service(logs_rpc=ARCHIVE), FakeRpc(archive_handler(latest)), 56
    )

    connector = only_connector(connectors)
    assert sessions.call_args_list == [call(connector=connector, connector_owner=False)] * 3
    assert connector.closed
    assert result["status"] == "ok"
    assert result["scanned_blocks"] == {"from_block": 0, "to_block": latest}


@pytest.mark.asyncio
async def test_a_logs_rpc_falling_back_to_windows_keeps_the_same_connector(connectors):
    refused = (
        200,
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "limit exceeded"}},
    )
    windows_only = chain_handler()

    def handle(payload):
        if payload["method"] == "eth_getLogs":
            query = payload["params"][0]
            if int(query["toBlock"], 16) - int(query["fromBlock"], 16) + 1 > 10_000:
                return refused
        return windows_only(payload)

    result, sessions = await scan(rescue_service(logs_rpc=ARCHIVE), FakeRpc(handle), 56)

    connector = only_connector(connectors)
    # The full history, the recent windows, allowances and balances.
    assert sessions.call_args_list == [call(connector=connector, connector_owner=False)] * 4
    assert connector.closed
    assert [a["risk_level"] for a in result["approvals"]] == ["HIGH"]


@pytest.mark.asyncio
async def test_a_scan_that_finds_no_approval_closes_the_connector_as_it_returns(connectors):
    rpc = FakeRpc(chain_handler(logs=lambda to_b: ok([])))
    result, sessions = await scan(rescue_service(), rpc, 4663)

    connector = only_connector(connectors)
    assert sessions.call_args_list == [call(connector=connector, connector_owner=False)]
    assert connector.closed
    assert result["approvals"] == []


@pytest.mark.asyncio
async def test_a_scan_stopped_at_its_deadline_closes_the_connector(connectors):
    rpc = DelayedRpc(delayed(chain_handler(), 30, method="eth_call"))
    result, _ = await scan(rescue_service(), rpc, 4663, history=0.3, total=0.6)

    assert only_connector(connectors).closed
    assert result["coverage_reasons"] == {"allowances": SCAN_TIMEOUT_REASON}


@pytest.mark.asyncio
async def test_a_scan_that_read_nothing_by_its_history_deadline_closes_the_connector(connectors):
    rpc = DelayedRpc(delayed(chain_handler(), 30))
    result, _ = await scan(rescue_service(), rpc, 4663, history=0.2, total=1.0)

    assert only_connector(connectors).closed
    assert result["coverage_reasons"] == {"allowances": NOTHING_READ_REASON}


@pytest.mark.asyncio
async def test_a_scan_whose_rpc_raises_closes_the_connector(connectors):
    session = MagicMock()
    session.post.side_effect = RuntimeError("connection refused")
    result, _ = await scan(rescue_service(), session, 4663)

    assert only_connector(connectors).closed
    assert result["coverage_reasons"] == {"allowances": RPC_UNAVAILABLE_REASON}


@pytest.mark.asyncio
async def test_a_cancelled_scan_closes_the_connector(connectors):
    rpc = DelayedRpc(delayed(chain_handler(), 30))
    with (
        patch("services.rescue_service.aiohttp.ClientSession") as sessions,
        patch("services.rescue_service.asyncio.sleep", AsyncMock()),
    ):
        sessions.return_value.__aenter__.return_value = rpc
        task = asyncio.create_task(rescue_service().scan_approvals(WALLET, 4663))
        while not rpc.methods("eth_getLogs"):
            await _real_sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert only_connector(connectors).closed


@pytest.mark.asyncio
async def test_dexscreener_prices_keep_their_own_session_and_connector():
    session = MagicMock()
    session.get.return_value.__aenter__.return_value.json = AsyncMock(return_value=[])
    with patch("services.rescue_service.aiohttp.ClientSession") as sessions:
        sessions.return_value.__aenter__.return_value = session
        await RescueService(MagicMock())._fetch_prices([TOKEN], 56)

    assert sessions.call_args_list == [call()]
    session.get.assert_called_once()
