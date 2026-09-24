"""Rescue approval history through a public RPC is a bounded, rate-limit-aware window.

Robinhood Chain (4663) was the first chain read this way; every chain without a configured logs
RPC now is.
"""

import asyncio
import logging
import time
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from services.rescue_service import APPROVAL_TOPIC, RESULT_CACHE_SECONDS, RescueService

_real_sleep = asyncio.sleep

LATEST = 65_527_689  # measured 4663 head, 2026-09-17
WINDOW_START = LATEST - 240_000 + 1
RPC_URL = "https://rpc.invalid/v2/SECRET_KEY_4663"
WALLET = "0x" + "1" * 40
TOKEN = "0x" + "2" * 40
SPENDER = "0x" + "3" * 40
OWNER_TOPIC = "0x" + "0" * 24 + "1" * 40
UNLIMITED = "0x" + "f" * 64
APPROVAL_LOG = {
    "address": TOKEN,
    "topics": [APPROVAL_TOPIC, OWNER_TOPIC, "0x" + "0" * 24 + "3" * 40],
    "data": UNLIMITED,
    "blockNumber": hex(LATEST - 5),
}
RATE_LIMITED = (429, None)
LOG_LIMIT_ERROR = (
    200,
    {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32000,
            "message": "logs matched by query exceeds limit of 10000",
        },
    },
)


def ok(result):
    return 200, {"jsonrpc": "2.0", "id": 1, "result": result}


class FakeRpc:
    """aiohttp session stand-in that answers JSON-RPC posts and records concurrency."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []
        self.urls = set()
        self.in_flight = 0
        self.max_in_flight = 0

    def post(self, url, json, timeout):
        return _Exchange(self, url, json)

    def methods(self, method):
        return [payload["params"] for payload in self.calls if payload["method"] == method]


class _Exchange:
    def __init__(self, rpc, url, payload):
        self.rpc, self.url, self.payload = rpc, url, payload

    async def __aenter__(self):
        self.rpc.calls.append(self.payload)
        self.rpc.urls.add(self.url)
        self.rpc.in_flight += 1
        self.rpc.max_in_flight = max(self.rpc.max_in_flight, self.rpc.in_flight)
        await _real_sleep(0)
        status, body = self.rpc.handler(self.payload)
        return MagicMock(status=status, json=AsyncMock(return_value=body))

    async def __aexit__(self, *exc):
        self.rpc.in_flight -= 1


def chain_handler(logs=None, allowance=None, block_number=None):
    """Default answers: one unlimited approval in the newest window, known allowance and balance."""

    def handle(payload):
        method = payload["method"]
        if method == "eth_blockNumber":
            return block_number(payload) if block_number else ok(hex(LATEST))
        if method == "eth_getLogs":
            window_to = int(payload["params"][0]["toBlock"], 16)
            if logs:
                answer = logs(window_to)
                if answer is not None:
                    return answer
            return ok([APPROVAL_LOG] if window_to == LATEST else [])
        if payload["params"][0]["data"].startswith("0xdd62ed3e"):
            return allowance() if allowance else ok(UNLIMITED)
        return ok(hex(10**18))

    return handle


def rescue_service(**logs_rpcs):
    """A service reading every chain through its adapter's public RPC unless a logs RPC is given."""
    web3_client = MagicMock()
    web3_client._get_adapter.return_value.w3.provider.endpoint_uri = RPC_URL
    web3_client.get_token_info = AsyncMock(
        return_value={"name": "Token", "symbol": "TKN", "decimals": 18}
    )
    service = RescueService(web3_client, **logs_rpcs)
    service._fetch_prices = AsyncMock(return_value={TOKEN: 1.0})
    return service


async def scan(handler, chain_id=4663, service=None):
    service = service or rescue_service()
    rpc = FakeRpc(handler)
    sleep = AsyncMock()
    with (
        patch("services.rescue_service.aiohttp.ClientSession") as factory,
        patch("services.rescue_service.asyncio.sleep", sleep),
    ):
        factory.return_value.__aenter__.return_value = rpc
        result = await service.scan_approvals(WALLET, chain_id)
    return result, rpc, sleep


def window_bounds(rpc):
    return [
        (int(p[0]["fromBlock"], 16), int(p[0]["toBlock"], 16)) for p in rpc.methods("eth_getLogs")
    ]


@pytest.mark.asyncio
async def test_robinhood_scans_bounded_recent_window_and_marks_allowances_incomplete():
    result, rpc, sleep = await scan(chain_handler())

    windows = window_bounds(rpc)
    assert len(windows) == 24
    assert windows[0][1] == LATEST
    assert windows[-1][0] == WINDOW_START
    assert all(to_b - from_b + 1 <= 10_000 for from_b, to_b in windows)
    assert all(newer[0] == older[1] + 1 for newer, older in zip(windows, windows[1:]))
    assert all(p[0]["topics"] == [APPROVAL_TOPIC, OWNER_TOPIC] for p in rpc.methods("eth_getLogs"))
    assert rpc.max_in_flight == 4
    assert rpc.urls == {RPC_URL}
    sleep.assert_not_awaited()

    assert [(a["token_address"], a["spender"], a["risk_level"]) for a in result["approvals"]] == [
        (TOKEN, SPENDER, "HIGH"),
    ]
    assert result["status"] == "unknown"
    assert result["coverage"]["allowances"] is False
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {WINDOW_START} not scanned"
    }
    assert result["scanned_blocks"] == {"from_block": WINDOW_START, "to_block": LATEST}
    assert result["total_value_at_risk_usd"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [56, 1, 137, 42161, 10, 204])
async def test_chains_without_a_logs_rpc_read_the_same_bounded_recent_windows(chain_id):
    result, rpc, sleep = await scan(chain_handler(), chain_id)

    windows = window_bounds(rpc)
    assert len(windows) == 24
    assert windows[0][1] == LATEST and windows[-1][0] == WINDOW_START
    assert all(to_b - from_b + 1 == 10_000 for from_b, to_b in windows)
    assert rpc.max_in_flight == 4
    assert rpc.urls == {RPC_URL}
    assert result["chain_id"] == chain_id
    assert [a["risk_level"] for a in result["approvals"]] == ["HIGH"]
    assert result["status"] == "unknown"
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {WINDOW_START} not scanned"
    }
    assert result["scanned_blocks"] == {"from_block": WINDOW_START, "to_block": LATEST}


@pytest.mark.asyncio
async def test_base_public_rpc_windows_fit_its_2000_block_range():
    result, rpc, sleep = await scan(chain_handler(), 8453)

    windows = window_bounds(rpc)
    assert len(windows) == 24
    assert all(to_b - from_b + 1 == 2_000 for from_b, to_b in windows)
    assert result["scanned_blocks"] == {"from_block": LATEST - 48_000 + 1, "to_block": LATEST}


@pytest.mark.asyncio
async def test_logs_rpc_refusing_the_full_history_is_read_in_recent_windows_instead():
    archive = "https://archive.invalid"
    limit_exceeded = (
        200,
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "limit exceeded"}},
    )
    windows_only = chain_handler()

    def handle(payload):
        if payload["method"] == "eth_getLogs":
            query = payload["params"][0]
            if int(query["toBlock"], 16) - int(query["fromBlock"], 16) + 1 > 10_000:
                return limit_exceeded
        return windows_only(payload)

    result, rpc, sleep = await scan(handle, 56, rescue_service(logs_rpc=archive))

    assert rpc.urls == {archive}
    assert len(window_bounds(rpc)) == 50 + 24
    assert [(a["token_address"], a["risk_level"]) for a in result["approvals"]] == [(TOKEN, "HIGH")]
    assert result["status"] == "unknown"
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {WINDOW_START} not scanned"
    }
    assert result["scanned_blocks"] == {"from_block": WINDOW_START, "to_block": LATEST}


@pytest.mark.asyncio
async def test_rpc_serving_no_approval_history_reads_unknown_with_nothing_scanned():
    limit_exceeded = (
        200,
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "limit exceeded"}},
    )
    result, rpc, sleep = await scan(chain_handler(logs=lambda to_b: limit_exceeded), 56)

    assert len(window_bounds(rpc)) == 4
    assert result["approvals"] == []
    assert result["status"] == "unknown"
    assert result["coverage"]["allowances"] is False
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {LATEST + 1} not scanned"
    }
    assert result["scanned_blocks"] is None
    assert result["total_value_at_risk_usd"] is None


@pytest.mark.asyncio
async def test_a_wallet_scan_is_reused_for_a_short_time_per_chain():
    service = rescue_service()
    first, _, _ = await scan(chain_handler(), 4663, service)
    again, repeat_rpc, _ = await scan(chain_handler(), 4663, service)
    other, other_rpc, _ = await scan(chain_handler(), 42161, service)
    service._results.expire(time.monotonic() + RESULT_CACHE_SECONDS)
    fresh, fresh_rpc, _ = await scan(chain_handler(), 4663, service)

    assert again is first and repeat_rpc.calls == []
    assert other["chain_id"] == 42161 and other_rpc.calls
    assert fresh is not first and fresh_rpc.calls


@pytest.mark.asyncio
async def test_robinhood_rate_limited_window_backs_off_then_succeeds():
    answers = iter(
        [
            RATE_LIMITED,
            (
                200,
                {"jsonrpc": "2.0", "id": 1, "error": {"code": 429, "message": "Too Many Requests"}},
            ),
        ]
    )
    result, rpc, sleep = await scan(
        chain_handler(logs=lambda to_b: next(answers, None) if to_b == LATEST else None)
    )

    assert [to_b for _, to_b in window_bounds(rpc)].count(LATEST) == 3
    assert sleep.await_args_list == [call(1), call(2)]
    assert len(result["approvals"]) == 1
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {WINDOW_START} not scanned"
    }


@pytest.mark.asyncio
async def test_robinhood_error_with_rate_inside_a_word_is_not_retried():
    unrelated = (
        200,
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "separate state generated"}},
    )
    result, rpc, sleep = await scan(
        chain_handler(logs=lambda to_b: unrelated if to_b == LATEST else None)
    )

    assert [to_b for _, to_b in window_bounds(rpc)].count(LATEST) == 1
    sleep.assert_not_awaited()
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {LATEST + 1} not scanned"
    }


@pytest.mark.asyncio
async def test_robinhood_rate_limit_code_and_message_are_retried():
    answers = iter([
        (200, {"jsonrpc": "2.0", "id": 1, "error": {"code": 429, "message": "slow down"}}),
        (200, {"jsonrpc": "2.0", "id": 1, "error": {
            "code": -32005, "message": "Your app has exceeded its rate limit",
        }}),
    ])
    result, rpc, sleep = await scan(
        chain_handler(logs=lambda to_b: next(answers, None) if to_b == LATEST else None)
    )

    assert [to_b for _, to_b in window_bounds(rpc)].count(LATEST) == 3
    assert sleep.await_args_list == [call(1), call(2)]
    assert len(result["approvals"]) == 1
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {WINDOW_START} not scanned"
    }


@pytest.mark.asyncio
async def test_robinhood_window_rate_limited_after_retries_truncates_and_keeps_found_approvals(
    caplog,
):
    with caplog.at_level(logging.DEBUG):
        result, rpc, sleep = await scan(
            chain_handler(logs=lambda to_b: RATE_LIMITED if to_b == LATEST - 10_000 else None)
        )

    windows = window_bounds(rpc)
    assert [to_b for _, to_b in windows].count(LATEST - 10_000) == 3
    assert len(windows) == 6
    assert min(from_b for from_b, _ in windows) == LATEST - 40_000 + 1
    assert sleep.await_args_list == [call(1), call(2)]
    assert len(rpc.methods("eth_call")) == 2
    assert [a["token_address"] for a in result["approvals"]] == [TOKEN]
    assert result["status"] == "unknown"
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {LATEST - 9_999} not scanned"
    }
    assert "SECRET_KEY_4663" not in caplog.text
    assert "SECRET_KEY_4663" not in str(result)


@pytest.mark.asyncio
async def test_robinhood_log_limit_error_is_not_retried_and_never_reads_clean():
    result, rpc, sleep = await scan(
        chain_handler(logs=lambda to_b: LOG_LIMIT_ERROR if to_b == LATEST else None)
    )

    assert [to_b for _, to_b in window_bounds(rpc)].count(LATEST) == 1
    assert len(window_bounds(rpc)) == 4
    sleep.assert_not_awaited()
    assert result["approvals"] == []
    assert result["status"] == "unknown"
    assert result["coverage"]["allowances"] is False
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {LATEST + 1} not scanned"
    }


@pytest.mark.asyncio
async def test_robinhood_unavailable_allowance_is_unknown_and_reasons_combine():
    result, rpc, sleep = await scan(chain_handler(allowance=lambda: RATE_LIMITED))

    assert len(rpc.methods("eth_call")) == 3
    assert result["approvals"] == []
    assert result["status"] == "unknown"
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {WINDOW_START} not scanned; Allowance unavailable for 1 approval(s)",
    }


@pytest.mark.asyncio
async def test_unavailable_block_number_reads_unknown_without_scanning(caplog):
    methods = []

    def handle(payload):
        methods.append(payload["method"])
        return RATE_LIMITED

    with caplog.at_level(logging.DEBUG):
        result, rpc, sleep = await scan(handle)

    assert methods == ["eth_blockNumber"] * 3
    assert result["approvals"] == []
    assert result["status"] == "unknown"
    assert result["coverage_reasons"] == {
        "allowances": "Approval data unavailable from the chain's RPC"
    }
    assert result["scanned_blocks"] is None
    assert "SECRET_KEY_4663" not in caplog.text
    assert "SECRET_KEY_4663" not in str(result)


@pytest.mark.asyncio
async def test_bsc_rescue_keeps_full_history_chunks_concurrency_and_archive_rpc():
    latest = 50 * 49_999 + 10
    web3_client = MagicMock()
    web3_client._get_adapter.return_value.w3.provider.endpoint_uri = "https://public.invalid"
    service = RescueService(web3_client, logs_rpc="https://archive.invalid")
    in_flight = {"now": 0, "max": 0}

    async def fetch_chunk(session, rpc_url, topic0, topic1, from_b, to_b):
        in_flight["now"] += 1
        in_flight["max"] = max(in_flight["max"], in_flight["now"])
        await _real_sleep(0)
        in_flight["now"] -= 1
        return []

    service._fetch_log_chunk = AsyncMock(side_effect=fetch_chunk)
    rpc = FakeRpc(lambda payload: ok(hex(latest)))
    with patch("services.rescue_service.aiohttp.ClientSession") as factory:
        factory.return_value.__aenter__.return_value = rpc
        result = await service.scan_approvals(WALLET, 56)

    ranges = [(c.args[1], c.args[4], c.args[5]) for c in service._fetch_log_chunk.await_args_list]
    assert len(ranges) == 51
    assert ranges[0] == ("https://archive.invalid", hex(0), hex(49_998))
    assert ranges[1] == ("https://archive.invalid", hex(49_999), hex(99_997))
    assert ranges[-1] == ("https://archive.invalid", hex(50 * 49_999), hex(latest))
    assert in_flight["max"] == 50
    assert rpc.urls == {"https://archive.invalid"}
    assert result["status"] == "ok"
    assert result["coverage_reasons"] == {}
    assert result["scanned_blocks"] == {"from_block": 0, "to_block": latest}
