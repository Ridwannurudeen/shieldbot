"""An approval scan answers within a deadline and says which blocks it had read by then.

On 2026-09-26 production's BNB Chain scan answered nobody: its logs RPC was still being read
chunk by chunk when nginx and the extension gave up at 60 s. The scan now stops reading history at
HISTORY_DEADLINE_SECONDS, keeps the whole batches read by then, and the scan as a whole answers
within SCAN_DEADLINE_SECONDS or says it did not finish. Every fake here answers late or never.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.rescue_service import NOTHING_READ_REASON, SCAN_TIMEOUT_REASON
from tests.test_rescue_bounded_history import (
    APPROVAL_LOG,
    LATEST,
    TOKEN,
    WALLET,
    FakeRpc,
    _Exchange,
    chain_handler,
    ok,
    rescue_service,
    window_bounds,
)

_real_sleep = asyncio.sleep
ARCHIVE = "https://archive.invalid"
CHUNK = 49_999
WINDOW = 10_000


class DelayedRpc(FakeRpc):
    """FakeRpc whose handler is a coroutine function, so an answer can come late or never."""

    def post(self, url, json, timeout):
        return _DelayedExchange(self, url, json)


class _DelayedExchange(_Exchange):
    async def __aenter__(self):
        self.rpc.calls.append(self.payload)
        self.rpc.urls.add(self.url)
        self.rpc.in_flight += 1
        self.rpc.max_in_flight = max(self.rpc.max_in_flight, self.rpc.in_flight)
        status, body = await self.rpc.handler(self.payload)
        return MagicMock(status=status, json=AsyncMock(return_value=body))


def delayed(handler, seconds, method="eth_getLogs"):
    """``handler``'s answers, each answer to ``method`` arriving ``seconds`` late."""

    async def handle(payload):
        if payload["method"] == method:
            await _real_sleep(seconds)
        return handler(payload)

    return handle


def archive_handler(latest):
    """Answers for a logs RPC at ``latest``: one unlimited approval in the newest chunk."""
    newest_log = {**APPROVAL_LOG, "blockNumber": hex(latest - 5)}
    return chain_handler(
        logs=lambda to_b: ok([newest_log] if to_b == latest else []),
        block_number=lambda payload: ok(hex(latest)),
    )


async def scan(handler, chain_id, service, history=0.3, total=1.0):
    rpc = DelayedRpc(handler)
    with (
        patch("services.rescue_service.aiohttp.ClientSession") as factory,
        patch("services.rescue_service.asyncio.sleep", AsyncMock()),
        patch("services.rescue_service.HISTORY_DEADLINE_SECONDS", history, create=True),
        patch("services.rescue_service.SCAN_DEADLINE_SECONDS", total, create=True),
    ):
        factory.return_value.__aenter__.return_value = rpc
        started = time.perf_counter()
        # A scan without a deadline waits for every late answer; 5 s bounds it here.
        result = await asyncio.wait_for(service.scan_approvals(WALLET, chain_id), 5)
    return result, rpc, time.perf_counter() - started


@pytest.mark.asyncio
async def test_windows_that_never_answer_read_nothing_by_the_history_deadline():
    service = rescue_service()
    result, rpc, elapsed = await scan(delayed(chain_handler(), 30), 56, service)

    assert elapsed < 2
    assert rpc.methods("eth_blockNumber") == [[]]
    assert len(window_bounds(rpc)) == 4
    assert result["approvals"] == []
    assert result["status"] == "unknown"
    assert result["coverage"]["allowances"] is False
    assert result["coverage_reasons"] == {"allowances": NOTHING_READ_REASON}
    assert result["scanned_blocks"] is None
    assert result["total_value_at_risk_usd"] is None
    assert not service._results


@pytest.mark.asyncio
async def test_slow_windows_stop_at_the_history_deadline_and_coverage_names_the_blocks_read():
    service = rescue_service()
    result, rpc, elapsed = await scan(delayed(chain_handler(), 0.08), 56, service, history=0.3)

    assert elapsed < 1
    from_block = result["scanned_blocks"]["from_block"]
    read = (LATEST - from_block + 1) // WINDOW
    # Whole batches of 4 windows were kept: the batch in flight at the deadline was dropped.
    assert 4 <= read <= 20 and read % 4 == 0
    assert from_block == LATEST - WINDOW * read + 1
    assert read <= len(window_bounds(rpc)) <= read + 4
    assert [(a["token_address"], a["risk_level"]) for a in result["approvals"]] == [(TOKEN, "HIGH")]
    assert result["status"] == "unknown"
    assert result["coverage"]["allowances"] is False
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {from_block} not scanned"
    }
    assert result["scanned_blocks"] == {"from_block": from_block, "to_block": LATEST}
    assert result["total_value_at_risk_usd"] is None
    assert service._results[(56, WALLET)] is result


@pytest.mark.asyncio
async def test_a_logs_rpc_serving_chunks_slowly_keeps_the_newest_ones_read_by_the_deadline():
    latest = 100 * CHUNK + 10  # 101 chunks: two batches of 50 and one of 1
    service = rescue_service(logs_rpc=ARCHIVE)
    result, rpc, elapsed = await scan(
        delayed(archive_handler(latest), 0.1), 56, service, history=0.25
    )

    assert elapsed < 1
    assert rpc.max_in_flight == 50
    assert not any(to_b - from_b + 1 == WINDOW for from_b, to_b in window_bounds(rpc))
    from_block = result["scanned_blocks"]["from_block"]
    read = (latest - from_block + 1) // CHUNK
    assert read in (50, 100)
    assert from_block == latest - CHUNK * read + 1
    assert [(a["token_address"], a["risk_level"]) for a in result["approvals"]] == [(TOKEN, "HIGH")]
    assert result["status"] == "unknown"
    assert result["coverage"]["allowances"] is False
    assert result["coverage_reasons"] == {
        "allowances": f"Approvals before block {from_block} not scanned"
    }
    assert result["scanned_blocks"] == {"from_block": from_block, "to_block": latest}
    assert result["total_value_at_risk_usd"] is None


@pytest.mark.asyncio
async def test_a_logs_rpc_that_answered_no_chunk_by_the_deadline_is_not_read_again_in_windows():
    service = rescue_service(logs_rpc=ARCHIVE)
    result, rpc, elapsed = await scan(delayed(chain_handler(), 30), 56, service)

    assert elapsed < 2
    assert rpc.methods("eth_blockNumber") == [[]]
    windows = window_bounds(rpc)
    assert len(windows) == 50
    assert all(to_b - from_b + 1 == CHUNK for from_b, to_b in windows)
    assert result["approvals"] == []
    assert result["status"] == "unknown"
    assert result["coverage_reasons"] == {"allowances": NOTHING_READ_REASON}
    assert result["scanned_blocks"] is None
    assert not service._results


@pytest.mark.asyncio
async def test_a_full_history_read_within_the_deadline_is_complete():
    latest = 2 * CHUNK + 10
    service = rescue_service(logs_rpc=ARCHIVE)
    result, rpc, elapsed = await scan(
        delayed(archive_handler(latest), 0.01), 56, service, history=1.0
    )

    assert window_bounds(rpc) == [
        (latest - CHUNK + 1, latest),
        (latest - 2 * CHUNK + 1, latest - CHUNK),
        (0, 10),
    ]
    assert [(a["token_address"], a["risk_level"]) for a in result["approvals"]] == [(TOKEN, "HIGH")]
    assert result["status"] == "ok"
    assert result["coverage_reasons"] == {}
    assert result["scanned_blocks"] == {"from_block": 0, "to_block": latest}
    assert result["total_value_at_risk_usd"] == 1.0


@pytest.mark.asyncio
async def test_allowance_calls_that_never_answer_end_the_scan_at_its_deadline():
    service = rescue_service()
    result, rpc, elapsed = await scan(
        delayed(chain_handler(), 30, method="eth_call"), 4663, service, total=0.6
    )

    assert elapsed < 2
    assert len(window_bounds(rpc)) == 24
    assert rpc.methods("eth_call")
    assert result["approvals"] == []
    assert result["status"] == "unknown"
    assert result["coverage"]["allowances"] is False
    assert result["coverage_reasons"] == {"allowances": SCAN_TIMEOUT_REASON}
    assert result["scanned_blocks"] is None
    assert result["total_value_at_risk_usd"] is None
    assert not service._results
