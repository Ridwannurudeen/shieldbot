"""Robinhood Chain (4663) launch discovery from launchpad and Uniswap creation events.

Every followed event was checked against a verified ABI and a live log on 2026-09-17:

- LONG: ``LaunchCreated`` from proxy 0x1eef016f22a943abc7dd11422edee9d235942104, whose
  EIP-1967 implementation 0x7b7b87fd1fb05864cd572c7306038552286c73d9 is the
  Sourcify-verified ``LongLaunchFactory``. LONG launches through Doppler.
- Doppler: ``Create`` from the Sourcify-verified DopplerHookInitializer
  0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544, which only emits it for calls from its
  ``airlock()``, the Doppler Airlock 0xeb7c034704ef8dcd2d32324c1545f62fb4ad0862. The Airlock
  itself has no verified ABI on Sourcify or reachable Blockscout, so it is not followed.
- Uniswap LiquidityLauncher: ``TokenCreated`` from the Sourcify-verified
  0x0000ffffbe8efe702c8703ae3477ff5de3d319c0.
- Catch-all: PoolManager ``Initialize`` and V2 factory ``PairCreated``.

A token is recorded once per chain under its most specific source. ``eth_getLogs`` on this
RPC reports ``blockTimestamp=0x0``, so timestamps come from block headers.

``run`` sweeps each source on its own cursor. ``poll`` is the fast path: once the cursors agree
and the confirmed head is close, a single ``eth_getLogs`` reads every source together with the
Swap events of the launches being triaged. With an RpcGuard every JSON-RPC call takes one request
of the shared 4663 budget, and HTTP 429/5xx statuses and transport failures feed its circuit breaker.
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import aiohttp
from eth_utils import keccak

from adapters.robinhood import POOL_MANAGER_ADDRESS, UNISWAP_V2_FACTORY, WETH_ADDRESS
from services.rpc_guard import CLOSED, HALF_OPEN, BreakerOpenError, is_failure_status

logger = logging.getLogger(__name__)

CHAIN_ID = 4663
# Measured 2026-09-17: blocks 65,511,959 to 65,526,359 spanned 1,447 s (0.100 s per block).
# 600 blocks is a 60 s reorg margin, small next to the hunter's 1,800 s sweep interval.
CONFIRMATIONS = 600
# Inclusive block span of one eth_getLogs request.
CHUNK_BLOCKS = 10_000
# A query the RPC rejects (for example "logs matched by query exceeds limit of 10000") is
# halved down to this floor. At the measured log density 500 blocks hold about ten logs,
# so a rejection at the floor is not a size problem and the source stops instead.
MIN_CHUNK_BLOCKS = 500
# A 1,800 s sweep interval accrues about 18,000 blocks, so a cursor that falls behind catches up.
MAX_BLOCKS_PER_SWEEP = 50_000
# The first sweep starts about one hour (36,000 blocks) behind the confirmed head.
BACKFILL_BLOCKS = 36_000
# Largest range the fast path reads in one combined query. A poll normally covers about 200
# blocks (20 s at 0.1 s per block). The combined query also returns every v4 Swap on the chain,
# and swap volume is what pushes a range towards the RPC's 10,000-log limit, so anything larger
# goes through the per-source sweep, which reads no swaps.
COMBINED_MAX_BLOCKS = 2_000
# eth_getBlockByNumber calls per batch request. The public RPC rate-limits every call in a batch,
# so a batch takes one request of the guard's budget per call. Measured on 2026-09-24 with batches
# sent about once a second: batches of 50 drew HTTP 429 within a few requests, up to four in a
# row, enough to open the breaker in the middle of a store; batches of 20 and of 10 drew none in
# thirty requests.
HEADER_BATCH = 10
MAX_ATTEMPTS = 4
REQUEST_INTERVAL = 0.5
QUOTE_ASSETS = frozenset({WETH_ADDRESS, "0x" + "0" * 40})
LAUNCHPAD_RANK = 3

_QUANTITY = re.compile(r"0x[0-9a-f]+")
_HASH = re.compile(r"0x[0-9a-f]{64}")
_ADDRESS_WORD = re.compile(r"0x0{24}([0-9a-f]{40})")
_RATE_LIMIT_TERMS = ("rate limit", "request rate", "too many requests", "busy", "timeout")


class LaunchDiscoveryError(RuntimeError):
    """An RPC read or log could not be trusted; the blocks involved stay unprocessed."""


class RpcUnavailableError(LaunchDiscoveryError):
    """The RPC did not answer within the retry budget, so a smaller query would not help."""


class WrongChainError(LaunchDiscoveryError):
    """The RPC answered for another chain, so nothing it reports about 4663 can be used."""


@dataclass(frozen=True)
class LaunchSource:
    name: str
    label: str
    rank: int
    address: str
    topic: str
    topic_count: int


def _topic(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


# Uniswap v4 PoolManager and V2 pair Swap events, as verified for the 4663 census
# (scripts/census_4663/events.py). A v4 Swap's first indexed topic is the pool id.
SWAP_V4_TOPIC = _topic("Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)")
SWAP_V2_TOPIC = _topic("Swap(address,uint256,uint256,uint256,uint256,address)")


SOURCES = (
    LaunchSource(
        "long",
        "LONG",
        5,
        "0x1eef016f22a943abc7dd11422edee9d235942104",
        _topic(
            "LaunchCreated(address,address,address,address,address,bytes32,uint48,uint48,string)"
        ),
        4,
    ),
    LaunchSource(
        "doppler",
        "Doppler",
        4,
        "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544",
        _topic("Create(address,address,address)"),
        4,
    ),
    LaunchSource(
        "liquidity_launcher",
        "Uniswap LiquidityLauncher",
        3,
        "0x0000ffffbe8efe702c8703ae3477ff5de3d319c0",
        _topic("TokenCreated(address)"),
        2,
    ),
    LaunchSource(
        "uniswap_v4",
        "Uniswap v4",
        2,
        POOL_MANAGER_ADDRESS,
        _topic("Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)"),
        4,
    ),
    LaunchSource(
        "uniswap_v2",
        "Uniswap V2",
        1,
        UNISWAP_V2_FACTORY,
        _topic("PairCreated(address,address,address,uint256)"),
        3,
    ),
)


def _quantity(value) -> int:
    if not isinstance(value, str) or not _QUANTITY.fullmatch(value):
        raise LaunchDiscoveryError("Malformed quantity")
    return int(value, 16)


def _hash(value) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value.lower()):
        raise LaunchDiscoveryError("Malformed hash")
    return value.lower()


def _word_address(value) -> str:
    match = _ADDRESS_WORD.fullmatch(value.lower()) if isinstance(value, str) else None
    if match is None:
        raise LaunchDiscoveryError("Malformed address word")
    return "0x" + match.group(1)


def _decode_log(source: LaunchSource, log, start: int, end: int) -> Tuple[List[str], Optional[str]]:
    """Return the token addresses and pool id or pair announced by one ``source`` log."""
    if (
        not isinstance(log, dict)
        or log.get("removed")
        or str(log.get("address", "")).lower() != source.address
    ):
        raise LaunchDiscoveryError("Unexpected log")
    topics = log.get("topics")
    if (
        not isinstance(topics, list)
        or len(topics) != source.topic_count
        or str(topics[0]).lower() != source.topic
    ):
        raise LaunchDiscoveryError("Unexpected log topics")
    if not start <= _quantity(log.get("blockNumber")) <= end:
        raise LaunchDiscoveryError("Log outside the requested range")
    _hash(log.get("transactionHash"))
    _hash(log.get("blockHash"))
    if source.name in ("long", "doppler"):
        return [_word_address(topics[2])], None
    if source.name == "liquidity_launcher":
        return [_word_address(topics[1])], None
    if source.name == "uniswap_v4":
        return [_word_address(topics[2]), _word_address(topics[3])], _hash(topics[1])
    data = log.get("data")
    if not isinstance(data, str) or len(data) != 2 + 64 * 2:
        raise LaunchDiscoveryError("Malformed PairCreated data")
    return [_word_address(topics[1]), _word_address(topics[2])], _word_address("0x" + data[2:66])


def _launch_records(decoded) -> List[Dict]:
    """Turn decoded logs into launch rows, excluding quote assets.

    A generic pool created in the same transaction as a launchpad event only supplies that
    launch's pool, so the launchpad's numeraire is not recorded as a launched token.
    """
    launchpad_tokens = {}
    for source, log, tokens, _ in decoded:
        if source.rank >= LAUNCHPAD_RANK:
            launchpad_tokens.setdefault(log["transactionHash"].lower(), set()).update(tokens)
    records = []
    for source, log, tokens, pool_id in decoded:
        tx_hash = log["transactionHash"].lower()
        launched = launchpad_tokens.get(tx_hash)
        for token in tokens:
            if token in QUOTE_ASSETS:
                continue
            if source.rank < LAUNCHPAD_RANK and launched is not None and token not in launched:
                continue
            records.append(
                {
                    "token_address": token,
                    "source": source.name,
                    "launchpad": source.label,
                    "source_rank": source.rank,
                    "pool_id": pool_id,
                    "block_number": int(log["blockNumber"], 16),
                    "block_hash": log["blockHash"].lower(),
                    "tx_hash": tx_hash,
                }
            )
    return records


def _split_combined(logs, start: int, end: int, pairs) -> Tuple[List, List[str]]:
    """Split one combined eth_getLogs result into decoded source logs and swapped pools.

    The query matches any requested address with any requested topic, so a pairing that is
    neither a source event nor a Swap is legitimately possible and skipped. A log from an address
    or topic that was never requested means the RPC answered another query, which is an error.
    """
    sources = {(source.address, source.topic): source for source in SOURCES}
    addresses = {source.address for source in SOURCES} | set(pairs)
    topics = {source.topic for source in SOURCES} | {SWAP_V4_TOPIC, SWAP_V2_TOPIC}
    decoded, swapped = [], []
    for log in logs:
        topic_list = log.get("topics") if isinstance(log, dict) else None
        if not isinstance(topic_list, list) or not topic_list:
            raise LaunchDiscoveryError("Unexpected log")
        address, topic = str(log.get("address", "")).lower(), str(topic_list[0]).lower()
        if address not in addresses or topic not in topics:
            raise LaunchDiscoveryError("Unexpected log")
        if (address, topic) in sources:
            source = sources[(address, topic)]
            decoded.append((source, log, *_decode_log(source, log, start, end)))
        elif log.get("removed"):
            continue
        elif topic == SWAP_V4_TOPIC and address == POOL_MANAGER_ADDRESS and len(topic_list) > 1:
            swapped.append(_hash(topic_list[1]))
        elif topic == SWAP_V2_TOPIC and address in pairs:
            swapped.append(address)
    return decoded, swapped


def _is_rate_limited(error) -> bool:
    """Match throttling by message; error codes here also cover query size limits."""
    if not isinstance(error, dict):
        return False
    message = str(error.get("message", "")).lower()
    return any(term in message for term in _RATE_LIMIT_TERMS)


class LaunchDiscovery:
    """Follow 4663 launch sources with persisted per-source block cursors."""

    def __init__(self, db, rpc_url: str, guard=None):
        self.db = db
        self.rpc_url = rpc_url
        self.guard = guard
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_request = 0.0
        self._chain_checked = False
        self._combined_failed = False

    async def run(self):
        """Run one bounded sweep over every source.

        A source whose log request fails stops at its last completed chunk. If a launch block
        cannot be confirmed against its canonical header, only the launches in older blocks are
        written and no cursor moves past that block.
        """
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            self._session = session
            await self._check_chain()
            await self._sweep(await self._confirmed_head())

    async def poll(self, pools=()) -> Dict:
        """Run one fast-path read and return the confirmed target, new launches and swap counts.

        ``pools`` are the Uniswap v4 pool ids and V2 pair addresses of launches being triaged.
        While every source cursor agrees and the confirmed head is at most COMBINED_MAX_BLOCKS
        ahead, one eth_getLogs reads all sources and those pools' Swap events (every v4 Swap is
        emitted by the PoolManager, which is already a source address). Swaps are counted for
        ``pools`` and for the pools of launches found in the same range. Otherwise the per-source
        sweep catches up and no swaps are counted; so it does when the RPC rejects the combined
        query or returns a log that cannot be trusted, and on the poll after the RPC gave up on
        one, so a query the RPC keeps failing is never repeated. The chain id is checked once per
        instance.
        """
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            self._session = session
            if not self._chain_checked:
                await self._check_chain()
                self._chain_checked = True
            target = await self._confirmed_head()
            cursors = {await self.db.get_launch_cursor(CHAIN_ID, source.name) for source in SOURCES}
            cursor = cursors.pop() if len(cursors) == 1 else None
            if cursor is not None and target <= cursor:
                return {"target": target, "launches": [], "swaps": {}}
            if cursor is None or target - cursor > COMBINED_MAX_BLOCKS or self._combined_failed:
                self._combined_failed = False
                return {"target": target, "launches": await self._sweep(target), "swaps": {}}
            pools = set(pools)
            pairs = sorted(pool for pool in pools if len(pool) == 42)
            try:
                logs = await self._combined_logs(cursor + 1, target, pairs)
                decoded, swapped = _split_combined(logs, cursor + 1, target, pairs)
            except RpcUnavailableError:
                self._combined_failed = True
                raise
            except LaunchDiscoveryError as exc:
                logger.warning("Launch discovery combined read rejected: %s", type(exc).__name__)
                return {"target": target, "launches": await self._sweep(target), "swaps": {}}
            records = await self._store(decoded, {source.name: (cursor, target) for source in SOURCES})
            pools.update(record["pool_id"] for record in records if record["pool_id"])
            counts = {}
            for pool in swapped:
                if pool in pools:
                    counts[pool] = counts.get(pool, 0) + 1
            return {"target": target, "launches": records, "swaps": counts}

    async def probe(self) -> bool:
        """Send the breaker's half-open probe, one eth_blockNumber; True if it closed the breaker.

        A probe that neither succeeds nor fails, or is cancelled, counts as failed so the breaker
        never stays half-open.
        """
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            self._session = session
            try:
                await self._call("eth_blockNumber", [], probe=True)
            except LaunchDiscoveryError as exc:
                logger.warning("Launch discovery probe failed: %s", type(exc).__name__)
            finally:
                if self.guard.state == HALF_OPEN:
                    self.guard.record_failure("probe inconclusive")
        return self.guard.state == CLOSED

    async def _check_chain(self):
        if _quantity(await self._call("eth_chainId", [])) != CHAIN_ID:
            raise WrongChainError("RPC is not Robinhood Chain")

    async def _confirmed_head(self) -> int:
        return _quantity(await self._call("eth_blockNumber", [])) - CONFIRMATIONS

    async def _sweep(self, target: int) -> List[Dict]:
        """Sweep every source from its own cursor towards ``target`` and store what it finds."""
        decoded = []
        progress = {}
        for source in SOURCES:
            cursor = await self.db.get_launch_cursor(CHAIN_ID, source.name)
            if cursor is None:
                cursor = target - BACKFILL_BLOCKS
                await self.db.set_launch_cursor(CHAIN_ID, source.name, cursor)
            end = min(target, cursor + MAX_BLOCKS_PER_SWEEP)
            logs, done = await self._sweep_source(source, cursor, end)
            decoded += logs
            progress[source.name] = (cursor, done)
        return await self._store(decoded, progress)

    async def _store(self, decoded, progress) -> List[Dict]:
        """Confirm launch blocks against canonical headers, then record launches and move cursors.

        ``progress`` maps each source to (previous cursor, last block covered without a gap).
        Headers are read oldest first. At the first launch block whose header cannot be read or
        does not match, the launches in older blocks are still recorded and every cursor stops
        short of that block, so the next read resumes there; then the error is raised. A range
        too large to confirm in one pass therefore still moves forward instead of being reread
        from the same cursor forever.
        """
        records = _launch_records(decoded)
        headers = {}
        failure = None
        try:
            await self._block_headers({record["block_number"] for record in records}, headers)
        except LaunchDiscoveryError as exc:
            failure = exc
        stop = None
        for record in sorted(records, key=lambda record: record["block_number"]):
            header = headers.get(record["block_number"])
            if header is None:
                stop = record["block_number"]
                break
            try:
                if _hash(header.get("hash")) != record["block_hash"]:
                    raise LaunchDiscoveryError("Log block is no longer canonical")
                record["block_timestamp"] = _quantity(header.get("timestamp"))
            except LaunchDiscoveryError as exc:
                stop, failure = record["block_number"], exc
                break
        confirmed = [record for record in records if stop is None or record["block_number"] < stop]
        for record in confirmed:
            del record["block_hash"]
        await self.db.upsert_discovered_launches(CHAIN_ID, confirmed)
        for name, (cursor, done) in progress.items():
            if stop is not None:
                done = min(done, stop - 1)
            if done > cursor:
                await self.db.set_launch_cursor(CHAIN_ID, name, done)
        if stop is not None:
            logger.warning(
                "Launch discovery stopped before block %d: %s", stop, type(failure).__name__
            )
            raise failure
        return confirmed

    async def _sweep_source(self, source: LaunchSource, cursor: int, end: int):
        """Read one source up to ``end``, halving a rejected query down to MIN_CHUNK_BLOCKS.

        Returns the decoded logs and the last block covered without a gap.
        """
        decoded = []
        done = cursor
        chunk = CHUNK_BLOCKS
        while done < end:
            start = done + 1
            upper = min(end, start + chunk - 1)
            try:
                decoded += await self._logs(source, start, upper)
            except RpcUnavailableError as exc:
                logger.warning(
                    "Launch discovery %s stopped at block %d: %s", source.name, start, type(exc).__name__
                )
                break
            except LaunchDiscoveryError as exc:
                if chunk <= MIN_CHUNK_BLOCKS:
                    logger.warning(
                        "Launch discovery %s stopped at block %d: %s", source.name, start, type(exc).__name__
                    )
                    break
                chunk = max(MIN_CHUNK_BLOCKS, chunk // 2)
                logger.warning(
                    "Launch discovery %s retrying block %d with %d blocks: %s",
                    source.name, start, chunk, type(exc).__name__,
                )
                continue
            done = upper
        return decoded, done

    async def _logs(self, source: LaunchSource, start: int, end: int):
        query = {
            "fromBlock": hex(start),
            "toBlock": hex(end),
            "address": source.address,
            "topics": [source.topic],
        }
        result = await self._call("eth_getLogs", [query])
        if not isinstance(result, list):
            raise LaunchDiscoveryError("Malformed eth_getLogs result")
        return [(source, log, *_decode_log(source, log, start, end)) for log in result]

    async def _combined_logs(self, start: int, end: int, pairs):
        query = {
            "fromBlock": hex(start),
            "toBlock": hex(end),
            "address": [source.address for source in SOURCES] + list(pairs),
            "topics": [[source.topic for source in SOURCES] + [SWAP_V4_TOPIC, SWAP_V2_TOPIC]],
        }
        result = await self._call("eth_getLogs", [query])
        if not isinstance(result, list):
            raise LaunchDiscoveryError("Malformed eth_getLogs result")
        return result

    async def _block_headers(self, numbers, headers: Dict[int, Dict]):
        """Read the headers of ``numbers`` into ``headers``, oldest first.

        Raises at the first header that cannot be read; the headers read before it stay in
        ``headers``.
        """
        ordered = sorted(numbers)
        for offset in range(0, len(ordered), HEADER_BATCH):
            batch = ordered[offset : offset + HEADER_BATCH]
            body = await self._request(
                [
                    {
                        "jsonrpc": "2.0",
                        "id": index,
                        "method": "eth_getBlockByNumber",
                        "params": [hex(number), False],
                    }
                    for index, number in enumerate(batch)
                ]
            )
            rows = {
                row.get("id"): row
                for row in (body if isinstance(body, list) else [])
                if isinstance(row, dict)
            }
            for index, number in enumerate(batch):
                header = rows.get(index, {}).get("result")
                if not isinstance(header, dict) or _quantity(header.get("number")) != number:
                    raise LaunchDiscoveryError("Missing or mismatched block header")
                headers[number] = header

    async def _call(self, method: str, params: list, probe: bool = False):
        body = await self._request(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, probe=probe
        )
        if not isinstance(body, dict) or "error" in body or body.get("result") is None:
            raise LaunchDiscoveryError(f"{method} returned no result")
        return body["result"]

    async def _request(self, payload, probe: bool = False):
        """POST with bounded exponential backoff on HTTP 429/5xx, transport and rate-limit errors.

        With a guard, every attempt first takes one request of the shared budget per JSON-RPC call
        it carries, and only structured outcomes reach the breaker: HTTP 429/5xx and transport exception classes are
        failures, a 200 answer is a success. A rate-limit error recognised by its message is
        retried but reported as neither. An open breaker ends the retries without sending, and
        a probe is a single attempt.
        """
        attempts = 1 if probe else MAX_ATTEMPTS
        calls = len(payload) if isinstance(payload, list) else 1
        for attempt in range(attempts):
            await self._pace(calls, probe)
            try:
                status, body = await self._post(payload)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
                self._report(type(exc).__name__)
                retry = True
            else:
                if is_failure_status(status):
                    self._report(f"HTTP {status}")
                if status != 200 and status != 429 and status < 500:
                    raise LaunchDiscoveryError(f"HTTP {status}")
                rows = body if isinstance(body, list) else [body]
                retry = status != 200 or any(
                    isinstance(row, dict) and _is_rate_limited(row.get("error")) for row in rows
                )
                if not retry:
                    self._report(None)
                    return body
            if attempt + 1 < attempts:
                await asyncio.sleep(2**attempt)
        raise RpcUnavailableError(f"RPC unavailable after {attempts} attempts")

    async def _pace(self, calls: int, probe: bool):
        if self.guard is None:
            wait = self._last_request + REQUEST_INTERVAL - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()
            return
        try:
            await self.guard.acquire(calls, probe=probe)
        except BreakerOpenError as exc:
            raise RpcUnavailableError("RPC breaker open") from exc

    def _report(self, failure: Optional[str]):
        if self.guard is None:
            return
        if failure is None:
            self.guard.record_success()
        else:
            self.guard.record_failure(failure)

    async def _post(self, payload):
        async with self._session.post(self.rpc_url, json=payload) as response:
            if response.status != 200:
                return response.status, None
            return response.status, await response.json(content_type=None)
