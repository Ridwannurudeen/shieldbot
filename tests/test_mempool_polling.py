"""Mempool polling: how pending transactions are read, parsed and handed to the analysis."""

import asyncio
import json
import logging
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from hexbytes import HexBytes
from web3.datastructures import AttributeDict

from services import mempool_service
from services.mempool_service import ANALYSIS_YIELD_EVERY, MempoolMonitor, PendingTx
from utils.scam_db import ScamDatabase
from utils.web3_client import Web3Client

SENDER = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"
TOKEN = "0x" + "22" * 20
SPENDER = "0x" + "11" * 20
APPROVE_UNLIMITED = "0x095ea7b3" + "00" * 12 + SPENDER[2:] + "ff" * 32
# An RPC URL as production configures them, carrying a key that must never reach the logs.
RPC_URL = "https://rpc.example/secret-key"
EMPTY_TXPOOL = {"result": {"pending": {}}}


async def _chunks(body, size, error=None):
    for start in range(0, len(body), size):
        yield body[start:start + size]
    if error is not None:
        raise error


@contextmanager
def _serve_txpool(*answers):
    """Patch aiohttp so each txpool_content POST answers the next item.

    An item is a payload dict or raw bytes served with HTTP 200, an int served as the HTTP status with
    an empty body, an exception the POST raises, or a (bytes, exception) pair whose stream raises after
    the bytes. The session keeps every response built in `responses`.
    """
    def response_for(answer):
        if isinstance(answer, Exception):
            return answer
        error = None
        if isinstance(answer, tuple):
            answer, error = answer
        status = answer if isinstance(answer, int) else 200
        if isinstance(answer, int):
            body = b""
        elif isinstance(answer, bytes):
            body = answer
        else:
            body = json.dumps(answer).encode("utf-8")
        response = MagicMock(status=status)
        response.content.iter_chunked = lambda size: _chunks(body, size, error)
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=False)
        return response

    session = MagicMock()
    session.responses = [response_for(answer) for answer in answers]
    session.post.side_effect = list(session.responses)
    with patch("services.mempool_service.aiohttp.ClientSession") as client:
        client.return_value.__aenter__ = AsyncMock(return_value=session)
        yield session


def _w3_with_endpoint():
    w3 = MagicMock()
    w3.provider.endpoint_uri = RPC_URL
    return w3


def _pending_block(sealed=False):
    """A pending block as web3 returns it: AttributeDicts carrying HexBytes hashes and inputs.

    A genuine pending block has no hash and no miner yet. Some RPCs answer "pending" with the latest
    sealed block instead, which carries both.
    """
    return AttributeDict.recursive(
        {
            "hash": HexBytes(b"\xbb" * 32) if sealed else None,
            "miner": "0x" + "33" * 20 if sealed else None,
            "transactions": [
                {
                    "hash": HexBytes(b"\x01" * 32),
                    "from": SENDER,
                    "to": TOKEN,
                    "value": 0,
                    "gasPrice": 5,
                    "input": HexBytes(APPROVE_UNLIMITED),
                },
                # A plain transfer has an empty input.
                {
                    "hash": HexBytes(b"\x02" * 32),
                    "from": SENDER,
                    "to": TOKEN,
                    "value": 10**18,
                    "gasPrice": 6,
                    "input": HexBytes(b""),
                },
                # A contract creation has no recipient.
                {
                    "hash": HexBytes(b"\x03" * 32),
                    "from": SENDER,
                    "to": None,
                    "value": 0,
                    "gasPrice": 7,
                    "input": HexBytes("0x6080"),
                },
            ],
        }
    )


@pytest.mark.asyncio
async def test_only_chains_with_a_public_mempool_are_polled():
    client = Web3Client.__new__(Web3Client)
    client._adapters = {chain_id: MagicMock() for chain_id in (56, 1, 8453, 42161, 137, 10, 204, 4663)}
    monitor = MempoolMonitor(client)
    monitor._poll_pending = AsyncMock()

    await monitor.start()
    try:
        assert sorted(monitor.get_stats()["monitored_chains"]) == [1, 56, 137, 204]
        # Nothing has been read yet, so no chain counts as observed.
        assert monitor.get_stats()["unobservable_chains"] == [1, 56, 137, 204]
    finally:
        await monitor.stop()


def _fields(tx):
    return (tx.tx_hash, tx.from_addr, tx.to_addr, tx.value, tx.gas_price, tx.data, tx.chain_id)


@pytest.mark.asyncio
async def test_pending_block_fallback_parses_web3_attribute_dicts():
    w3 = MagicMock()
    w3.eth.get_block.return_value = _pending_block()

    txs = await MempoolMonitor(MagicMock())._get_pending_block(w3, 56)

    w3.eth.get_block.assert_called_once_with("pending", True)
    assert [_fields(tx) for tx in txs] == [
        ("0x" + "01" * 32, SENDER.lower(), TOKEN, 0, 5, APPROVE_UNLIMITED, 56),
        ("0x" + "02" * 32, SENDER.lower(), TOKEN, 10**18, 6, "0x", 56),
        ("0x" + "03" * 32, SENDER.lower(), "", 0, 7, "0x6080", 56),
    ]


@pytest.mark.asyncio
async def test_pending_block_fallback_feeds_the_analysis():
    client = MagicMock()
    w3 = client.get_web3.return_value = _w3_with_endpoint()
    w3.eth.get_block.return_value = _pending_block()
    # The approval's spender is on the loaded blacklist, so the analysis alerts on it.
    scam_db = ScamDatabase()
    scam_db.known_scams = {(None, SPENDER): {"source": "admin", "reports": 0, "expires_at": None}}
    counterparty = SimpleNamespace(allowlisted_name=lambda address, chain_id: None, cached=lambda address, chain_id: None)
    monitor = MempoolMonitor(client, scam_db=scam_db, counterparty=counterparty)

    with _serve_txpool(EMPTY_TXPOOL):
        await monitor._poll_pending(56)

    assert monitor.get_stats()["pending_count"] == {56: 3}
    assert monitor.get_stats()["unobservable_chains"] == []
    alerts = monitor.get_alerts()
    assert [(a["alert_type"], a["severity"], a["victim_tx"]) for a in alerts] == [
        ("suspicious_approval", "HIGH", "0x" + "01" * 32),
    ]


TXPOOL_WITH_ONE_TX = {"result": {"pending": {SENDER: {"7": {
    "hash": "0x" + "04" * 32, "from": SENDER, "to": TOKEN, "value": "0x0",
    "gasPrice": "0x5", "input": "0x",
}}}}}


@pytest.mark.asyncio
async def test_switching_between_the_txpool_and_the_pending_block_counts_nothing_twice():
    # A failed txpool read falls back to the pending block. The switch there and back must not drop
    # the pool's transactions and then count them again as new.
    client = MagicMock()
    w3 = client.get_web3.return_value = _w3_with_endpoint()
    w3.eth.get_block.return_value = _pending_block()
    monitor = MempoolMonitor(client)

    with _serve_txpool(TXPOOL_WITH_ONE_TX, 502, TXPOOL_WITH_ONE_TX, TXPOOL_WITH_ONE_TX):
        await monitor._poll_pending(56)  # the txpool: 04
        await monitor._poll_pending(56)  # the txpool fails, so the pending block: 01, 02, 03
        await monitor._poll_pending(56)  # the txpool again: 04 is not new
        assert monitor.get_stats()["total_pending_seen"] == 4
        await monitor._poll_pending(56)  # the same source twice: what left the pool is dropped

    assert monitor.get_stats()["pending_count"] == {56: 1}
    assert monitor.get_stats()["total_pending_seen"] == 4


@pytest.mark.asyncio
async def test_a_poll_drops_swap_queues_that_have_gone_quiet():
    client = MagicMock()
    client.get_web3.return_value = _w3_with_endpoint()
    monitor = MempoolMonitor(client)
    quiet, busy = (56, "0x" + "aa" * 20), (56, "0x" + "bb" * 20)
    for key, age, tx_hash in ((quiet, 31, "0x" + "05" * 32), (busy, 1, "0x" + "06" * 32)):
        monitor._swap_queue[key].append(PendingTx(
            tx_hash=tx_hash, from_addr=SENDER.lower(), to_addr=TOKEN, value=0, gas_price=1,
            data="0x", chain_id=56, seen_at=time.time() - age,
        ))
    monitor._reported_sandwiches[quiet].add(("0x" + "07" * 32, "0x" + "08" * 32))

    with _serve_txpool(TXPOOL_WITH_ONE_TX):
        await monitor._poll_pending(56)

    assert list(monitor._swap_queue) == [busy]
    assert quiet not in monitor._reported_sandwiches


TXPOOL_UNSUPPORTED = {"error": {"code": -32601, "message": "the method txpool_content does not exist"}}


@pytest.mark.asyncio
@pytest.mark.parametrize("txpool, pending_block", [
    (EMPTY_TXPOOL, _pending_block(sealed=True)),
    (TXPOOL_UNSUPPORTED, _pending_block(sealed=True)),
    (EMPTY_TXPOOL, TimeoutError("RPC timeout")),
    (aiohttp.ClientError("connection reset"), TimeoutError("RPC timeout")),
    (b"not json", TimeoutError("RPC timeout")),
], ids=[
    "empty-txpool-sealed-block", "txpool-unsupported-sealed-block", "empty-txpool-block-error", "both-fail",
    "malformed-txpool-block-error",
])
async def test_a_chain_whose_mempool_cannot_be_read_is_unobservable_until_it_can(txpool, pending_block):
    client = MagicMock()
    w3 = client.get_web3.return_value = _w3_with_endpoint()
    w3.eth.get_block.side_effect = [pending_block]
    monitor = MempoolMonitor(client)

    with _serve_txpool(txpool, TXPOOL_WITH_ONE_TX):
        await monitor._poll_pending(56)
        assert monitor.get_stats()["unobservable_chains"] == [56]
        assert monitor.get_stats()["pending_count"] == {}

        await monitor._poll_pending(56)
    assert monitor.get_stats()["unobservable_chains"] == []
    assert monitor.get_stats()["pending_count"] == {56: 1}


@pytest.mark.asyncio
async def test_a_genuine_empty_pending_block_is_an_observation():
    client = MagicMock()
    w3 = client.get_web3.return_value = _w3_with_endpoint()
    w3.eth.get_block.return_value = AttributeDict({"hash": None, "miner": None, "transactions": []})
    monitor = MempoolMonitor(client)
    monitor._unobservable_chains = {1}

    with _serve_txpool(EMPTY_TXPOOL):
        await monitor._poll_pending(1)

    assert monitor.get_stats()["unobservable_chains"] == []


@pytest.mark.asyncio
async def test_a_failed_poll_leaves_the_chain_unobservable():
    client = MagicMock()
    monitor = MempoolMonitor(client)
    monitor._get_txpool_content = AsyncMock(side_effect=RuntimeError("executor is shut down"))

    await monitor._poll_pending(56)

    assert monitor.get_stats()["unobservable_chains"] == [56]


@pytest.mark.asyncio
async def test_a_sealed_block_answered_for_pending_is_skipped_with_one_warning_per_chain(caplog):
    w3 = MagicMock()
    w3.eth.get_block.return_value = _pending_block(sealed=True)
    monitor = MempoolMonitor(MagicMock())

    with caplog.at_level(logging.WARNING, logger="services.mempool_service"):
        for _ in range(mempool_service.SEALED_MARK_AFTER + 1):
            assert await monitor._get_pending_block(w3, 56) is None
        for _ in range(mempool_service.SEALED_MARK_AFTER):
            assert await monitor._get_pending_block(w3, 204) is None

    warned = [r.args[0] for r in caplog.records if r.levelno == logging.WARNING]
    assert warned == [56, 204]
    # Once a chain is marked, its full block is not fetched again within the retry interval.
    assert w3.eth.get_block.call_count == 2 * mempool_service.SEALED_MARK_AFTER


@pytest.mark.asyncio
async def test_a_sealed_pending_chain_is_asked_again_after_the_retry_interval():
    # One sealed answer (a load-balanced RPC can have one odd backend) must not blind the chain
    # until the process restarts.
    w3 = MagicMock()
    marks_after = mempool_service.SEALED_MARK_AFTER
    w3.eth.get_block.side_effect = [_pending_block(sealed=True)] * marks_after + [_pending_block()]
    monitor = MempoolMonitor(MagicMock())

    for _ in range(marks_after):
        assert await monitor._get_pending_block(w3, 1) is None
    assert monitor._sealed_pending_until[1] > time.monotonic()
    monitor._sealed_pending_until[1] = time.monotonic() - 1  # the retry interval has passed
    txs = await monitor._get_pending_block(w3, 1)

    assert [tx.tx_hash for tx in txs] == ["0x" + "01" * 32, "0x" + "02" * 32, "0x" + "03" * 32]


@pytest.mark.asyncio
async def test_one_sealed_answer_before_any_pending_block_does_not_mark_the_chain(caplog):
    # After a restart Ethereum has not served a genuine block yet; one unlucky sealed answer then
    # must not cost the 10-minute mark.
    w3 = MagicMock()
    w3.eth.get_block.side_effect = [_pending_block(sealed=True), _pending_block()]
    monitor = MempoolMonitor(MagicMock())

    with caplog.at_level(logging.WARNING, logger="services.mempool_service"):
        assert await monitor._get_pending_block(w3, 1) is None
        assert len(await monitor._get_pending_block(w3, 1)) == 3

    assert w3.eth.get_block.call_count == 2
    assert 1 not in monitor._sealed_pending_until
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]


@pytest.mark.asyncio
async def test_a_run_of_sealed_answers_from_a_pending_block_chain_is_warned_about_once_per_run(caplog):
    # An RPC that served pending blocks and then turned to sealed answers leaves the chain unobserved;
    # that must reach the journal once per run, not on every poll and not never.
    warn_after = mempool_service.SEALED_WARN_AFTER
    sealed = _pending_block(sealed=True)
    w3 = MagicMock()
    answers = [_pending_block()] + [sealed] * (warn_after + 2) + [_pending_block()] + [sealed] * warn_after
    w3.eth.get_block.side_effect = answers
    monitor = MempoolMonitor(MagicMock())

    with caplog.at_level(logging.WARNING, logger="services.mempool_service"):
        for _ in answers:
            await monitor._get_pending_block(w3, 1)

    warned = [r.args for r in caplog.records if r.levelno == logging.WARNING]
    assert warned == [(1, warn_after), (1, warn_after)]
    assert 1 not in monitor._sealed_pending_until


@pytest.mark.asyncio
async def test_a_sealed_answer_from_a_chain_that_serves_pending_blocks_costs_one_poll(caplog):
    # Ethereum's load-balanced RPC answers 'pending' with a genuine block, and now and then with a sealed
    # one. That one answer observes nothing, but the next poll asks again instead of waiting 10 minutes.
    w3 = MagicMock()
    w3.eth.get_block.side_effect = [_pending_block(), _pending_block(sealed=True), _pending_block()]
    monitor = MempoolMonitor(MagicMock())

    with caplog.at_level(logging.WARNING, logger="services.mempool_service"):
        assert len(await monitor._get_pending_block(w3, 1)) == 3
        assert await monitor._get_pending_block(w3, 1) is None
        assert len(await monitor._get_pending_block(w3, 1)) == 3

    assert w3.eth.get_block.call_count == 3
    assert 1 not in monitor._sealed_pending_until
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]


@pytest.mark.asyncio
async def test_a_txpool_body_under_the_cap_is_parsed_into_pending_transactions(monkeypatch):
    parsed_on = []

    def recording_loads(body):
        parsed_on.append(threading.get_ident())
        return json.loads(body)

    monkeypatch.setattr(mempool_service, "json", SimpleNamespace(loads=recording_loads))
    monitor = MempoolMonitor(MagicMock())
    with _serve_txpool({"result": {"pending": {SENDER: {"7": {
        "hash": "0x" + "04" * 32, "from": SENDER, "to": TOKEN, "value": "0x10",
        "gasPrice": "0x5", "input": APPROVE_UNLIMITED,
    }}}}}) as session:
        txs = await monitor._get_txpool_content(_w3_with_endpoint(), 1)

    assert [_fields(tx) for tx in txs] == [
        ("0x" + "04" * 32, SENDER.lower(), TOKEN, 16, 5, APPROVE_UNLIMITED, 1),
    ]
    (url,), request = session.post.call_args.args, session.post.call_args.kwargs
    assert url == RPC_URL
    assert request["json"] == {"jsonrpc": "2.0", "id": 1, "method": "txpool_content", "params": []}
    # The same per-operation timeout as the web3 provider's requests session, and a cut for the whole
    # read so a slow-dripping RPC cannot hold the other chains' polls.
    assert (request["timeout"].sock_connect, request["timeout"].sock_read) == (10, 10)
    assert request["timeout"].total == 60
    assert monitor._txpool_oversized_until == {}
    # The body is parsed on an executor thread, never on the event loop's.
    assert parsed_on and threading.get_ident() not in parsed_on


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", [
    SimpleNamespace(endpoint_uri="wss://rpc.example/ws"),
    SimpleNamespace(endpoint_uri=None),
    SimpleNamespace(),
], ids=["websocket-endpoint", "no-endpoint", "no-endpoint-attribute"])
async def test_a_provider_without_an_http_endpoint_is_read_through_the_pending_block(provider):
    monitor = MempoolMonitor(MagicMock())
    with _serve_txpool() as session:
        assert await monitor._get_txpool_content(SimpleNamespace(provider=provider), 1) == []
    session.post.assert_not_called()


@pytest.mark.asyncio
async def test_an_oversized_txpool_body_is_abandoned_unparsed_and_marks_the_chain(monkeypatch, caplog):
    monkeypatch.setattr(mempool_service, "MAX_TXPOOL_BYTES", 1024)
    loads = MagicMock(side_effect=AssertionError("an oversized body must not be parsed"))
    monkeypatch.setattr(mempool_service, "json", SimpleNamespace(loads=loads))
    monitor = MempoolMonitor(MagicMock())
    # Three 64 KiB chunks; reading past the first would raise, so the mark proves the read stopped there.
    oversized = (b"{" + b" " * (3 * 64 * 1024), RuntimeError("read past the cap"))

    with _serve_txpool(oversized, oversized) as session, caplog.at_level(logging.DEBUG):
        assert await monitor._get_txpool_content(_w3_with_endpoint(), 1) == []
        assert session.responses[0].close.called
        assert set(monitor._txpool_oversized_until) == {1}
        # The chain is not asked for its txpool again.
        assert await monitor._get_txpool_content(_w3_with_endpoint(), 1) == []
    assert session.post.call_count == 1
    loads.assert_not_called()
    warned = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert [r.args for r in warned] == [(1, 1024, 600)]
    assert "secret-key" not in caplog.text and "rpc.example" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("sealed", [False, True], ids=["genuine-pending-block", "sealed-block"])
async def test_a_marked_chain_is_watched_through_its_pending_block(monkeypatch, sealed):
    monkeypatch.setattr(mempool_service, "MAX_TXPOOL_BYTES", 16)
    client = MagicMock()
    w3 = client.get_web3.return_value = _w3_with_endpoint()
    w3.eth.get_block.return_value = _pending_block(sealed=sealed)
    monitor = MempoolMonitor(client)

    with _serve_txpool(b"x" * 64) as session:
        await monitor._poll_pending(1)
        assert set(monitor._txpool_oversized_until) == {1}
        await monitor._poll_pending(1)

    assert session.post.call_count == 1
    assert monitor.get_stats()["unobservable_chains"] == ([1] if sealed else [])
    assert monitor.get_stats()["pending_count"] == ({} if sealed else {1: 3})


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [
    aiohttp.ClientError("connection reset"),
    TimeoutError("socket read timed out"),
    (b'{"result": {"pending": {', RuntimeError("stream closed")),
    502,
], ids=["post-error", "timeout", "mid-stream-error", "http-502"])
async def test_a_failed_txpool_read_does_not_wipe_the_pending_set(failure):
    client = MagicMock()
    w3 = client.get_web3.return_value = _w3_with_endpoint()
    w3.eth.get_block.side_effect = TimeoutError("RPC timeout")
    monitor = MempoolMonitor(client)

    with _serve_txpool(TXPOOL_WITH_ONE_TX, failure):
        await monitor._poll_pending(56)
        assert monitor.get_stats()["pending_count"] == {56: 1}
        await monitor._poll_pending(56)

    assert monitor.get_stats()["pending_count"] == {56: 1}
    assert monitor.get_stats()["unobservable_chains"] == [56]


@pytest.mark.asyncio
async def test_txpool_reads_never_log_the_rpc_url(monkeypatch, caplog):
    monkeypatch.setattr(mempool_service, "MAX_TXPOOL_BYTES", 16)
    client = MagicMock()
    w3 = client.get_web3.return_value = _w3_with_endpoint()
    w3.eth.get_block.side_effect = TimeoutError(f"timed out reading {RPC_URL}")
    monitor = MempoolMonitor(client)
    answers = [aiohttp.ClientError(f"cannot connect to {RPC_URL}"), 502, b"not json", b"{}" * 64]

    with _serve_txpool(*answers), caplog.at_level(logging.DEBUG):
        for _ in range(len(answers)):
            await monitor._poll_pending(1)

    assert set(monitor._txpool_oversized_until) == {1}
    assert caplog.records
    assert "secret-key" not in caplog.text and "rpc.example" not in caplog.text


@pytest.mark.asyncio
async def test_an_oversized_chain_is_asked_for_its_txpool_again_after_the_retry_interval(monkeypatch, caplog):
    monkeypatch.setattr(mempool_service, "MAX_TXPOOL_BYTES", 16)
    monitor = MempoolMonitor(MagicMock())

    with _serve_txpool(b"x" * 64, b"x" * 64) as session, caplog.at_level(
        logging.WARNING, logger="services.mempool_service"
    ):
        assert await monitor._get_txpool_content(_w3_with_endpoint(), 1) == []
        # Within the retry interval the chain is not asked again.
        assert await monitor._get_txpool_content(_w3_with_endpoint(), 1) == []
        assert session.post.call_count == 1
        monitor._txpool_oversized_until[1] = time.monotonic() - 1  # the interval has passed
        assert await monitor._get_txpool_content(_w3_with_endpoint(), 1) == []

    assert session.post.call_count == 2
    # Still too large: marked again, and warned about only once.
    assert monitor._txpool_oversized_until[1] > time.monotonic()
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1


@pytest.mark.asyncio
async def test_an_unreadable_txpool_is_warned_about_once_per_chain(caplog):
    monitor = MempoolMonitor(MagicMock())

    with _serve_txpool(403, 403, aiohttp.ClientError(f"cannot connect to {RPC_URL}"), 403), caplog.at_level(
        logging.WARNING, logger="services.mempool_service"
    ):
        for chain_id in (56, 56, 56, 204):
            assert await monitor._get_txpool_content(_w3_with_endpoint(), chain_id) == []

    warned = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert [r.args[0] for r in warned] == [56, 204]
    assert "secret-key" not in caplog.text and "rpc.example" not in caplog.text


@pytest.mark.asyncio
async def test_stop_logs_only_for_a_monitor_that_was_started(caplog):
    """The Telegram bot's container shuts down a monitor it never started."""
    client = Web3Client.__new__(Web3Client)
    client._adapters = {56: MagicMock()}
    never_started = MempoolMonitor(client)
    started = MempoolMonitor(client)
    started._poll_pending = AsyncMock()
    await started.start([56])

    with caplog.at_level(logging.INFO, logger="services.mempool_service"):
        await never_started.stop()
        assert "MempoolMonitor stopped" not in caplog.messages
        await started.stop()
        assert caplog.messages.count("MempoolMonitor stopped") == 1
    assert started._task is None


@pytest.mark.asyncio
async def test_each_chain_poll_logs_its_duration(caplog):
    monitor = MempoolMonitor(MagicMock())
    monitor._running = True
    monitor._monitored_chains = {56, 1}
    cycle_polled = asyncio.Event()

    async def poll(chain_id):
        if monitor._poll_pending.await_count == len(monitor._monitored_chains):
            cycle_polled.set()

    monitor._poll_pending = AsyncMock(side_effect=poll)
    with caplog.at_level(logging.DEBUG, logger="services.mempool_service"):
        loop_task = asyncio.create_task(monitor._monitor_loop())
        await asyncio.wait_for(cycle_polled.wait(), 5)
        # The loop logged the last chain and is now in its real 2 s sleep, which ends on cancel.
        loop_task.cancel()
        await loop_task

    polled = [r for r in caplog.records if r.msg == "Polled chain %s in %.2f s"]
    assert sorted(r.args[0] for r in polled) == [1, 56]
    assert all(r.levelno == logging.DEBUG and r.args[1] >= 0 for r in polled)


def _tx(tx_hash, chain_id=1, seen_at=None):
    """A plain transfer as the txpool reader builds it; seen_at defaults to now."""
    fields = dict(tx_hash=tx_hash, from_addr=SENDER.lower(), to_addr=TOKEN, value=0, gas_price=5, data="0x", chain_id=chain_id)
    return PendingTx(**fields) if seen_at is None else PendingTx(**fields, seen_at=seen_at)


HASH_1, HASH_2, HASH_3 = ("0x" + "0a" * 32, "0x" + "0b" * 32, "0x" + "0c" * 32)


@pytest.mark.asyncio
async def test_a_transaction_that_stays_in_the_pool_is_analysed_once_and_counted_once(monkeypatch):
    """Two loop cycles: HASH_1 has been in the pool for over a minute and stays, HASH_2 leaves, HASH_3 joins."""
    monitor = MempoolMonitor(MagicMock())
    monitor._running = True
    monitor._monitored_chains = {1}
    monitor._analyze_pending_tx = AsyncMock()
    stuck = _tx(HASH_1, seen_at=time.time() - 61)
    monitor._get_txpool_content = AsyncMock(side_effect=[
        [stuck, _tx(HASH_2)],
        [stuck, _tx(HASH_3)],
        asyncio.CancelledError(),
    ])
    monkeypatch.setattr("services.mempool_service.asyncio.sleep", AsyncMock())

    await monitor._monitor_loop()

    assert [call.args[0].tx_hash for call in monitor._analyze_pending_tx.await_args_list] == [HASH_1, HASH_2, HASH_3]
    assert monitor.get_stats()["total_pending_seen"] == 3
    assert monitor.get_stats()["pending_count"] == {1: 2}
    assert set(monitor._pending[1]) == {HASH_1, HASH_3}


@pytest.mark.asyncio
async def test_a_transaction_that_left_the_pool_is_dropped():
    monitor = MempoolMonitor(MagicMock())
    monitor._get_txpool_content = AsyncMock(side_effect=[[_tx(HASH_1), _tx(HASH_2)], [_tx(HASH_2)]])

    await monitor._poll_pending(1)
    assert monitor.get_stats()["pending_count"] == {1: 2}
    await monitor._poll_pending(1)

    assert monitor.get_stats()["pending_count"] == {1: 1}
    assert list(monitor._pending[1]) == [HASH_2]
    assert monitor.get_stats()["total_pending_seen"] == 2


@pytest.mark.asyncio
async def test_a_failed_poll_keeps_the_pending_set():
    """A poll that raises, or reads neither a txpool nor a pending block, is not an empty pool."""
    monitor = MempoolMonitor(MagicMock())
    monitor._get_txpool_content = AsyncMock(side_effect=[[_tx(HASH_1)], RuntimeError("RPC timeout"), []])
    monitor._get_pending_block = AsyncMock(return_value=None)

    await monitor._poll_pending(1)
    assert monitor.get_stats()["unobservable_chains"] == []
    for _ in range(2):
        await monitor._poll_pending(1)
        assert monitor.get_stats()["unobservable_chains"] == [1]
        assert monitor.get_stats()["pending_count"] == {1: 1}
    assert monitor.get_stats()["total_pending_seen"] == 1


@pytest.mark.asyncio
async def test_a_large_snapshot_lets_other_tasks_run_while_it_is_added():
    monitor = MempoolMonitor(MagicMock())
    monitor._get_txpool_content = AsyncMock(return_value=[_tx("0x" + f"{i:064x}") for i in range(20_000)])
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0)

    task = asyncio.create_task(ticker())
    try:
        await monitor._poll_pending(1)
    finally:
        task.cancel()

    assert monitor.get_stats()["pending_count"] == {1: 20_000}
    assert ticks >= 20_000 // ANALYSIS_YIELD_EVERY
