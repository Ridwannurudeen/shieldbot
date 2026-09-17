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

logger = logging.getLogger(__name__)

CHAIN_ID = 4663
# Measured 2026-09-17: blocks 65,511,959 to 65,526,359 spanned 1,447 s (0.100 s per block).
# 600 blocks is a 60 s reorg margin, small next to the hunter's 1,800 s sweep interval.
CONFIRMATIONS = 600
# Inclusive block span of one eth_getLogs request.
CHUNK_BLOCKS = 10_000
# A 1,800 s sweep interval accrues about 18,000 blocks, so a cursor that falls behind catches up.
MAX_BLOCKS_PER_SWEEP = 50_000
# The first sweep starts about one hour (36,000 blocks) behind the confirmed head.
BACKFILL_BLOCKS = 36_000
HEADER_BATCH = 50
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


def _is_rate_limited(error) -> bool:
    if not isinstance(error, dict):
        return False
    message = str(error.get("message", "")).lower()
    return error.get("code") == -32005 or any(term in message for term in _RATE_LIMIT_TERMS)


class LaunchDiscovery:
    """Follow 4663 launch sources with persisted per-source block cursors."""

    def __init__(self, db, rpc_url: str):
        self.db = db
        self.rpc_url = rpc_url
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_request = 0.0

    async def run(self):
        """Run one bounded sweep over every source.

        A source whose log request fails stops at its last completed chunk. If the launch
        blocks cannot be confirmed against canonical headers, nothing is written and no
        cursor moves.
        """
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            self._session = session
            if _quantity(await self._call("eth_chainId", [])) != CHAIN_ID:
                raise LaunchDiscoveryError("RPC is not Robinhood Chain")
            target = _quantity(await self._call("eth_blockNumber", [])) - CONFIRMATIONS
            decoded = []
            progress = {}
            for source in SOURCES:
                cursor = await self.db.get_launch_cursor(CHAIN_ID, source.name)
                if cursor is None:
                    cursor = target - BACKFILL_BLOCKS
                    await self.db.set_launch_cursor(CHAIN_ID, source.name, cursor)
                done = cursor
                end = min(target, cursor + MAX_BLOCKS_PER_SWEEP)
                for start in range(cursor + 1, end + 1, CHUNK_BLOCKS):
                    upper = min(end, start + CHUNK_BLOCKS - 1)
                    try:
                        decoded += await self._logs(source, start, upper)
                    except LaunchDiscoveryError as exc:
                        logger.warning(
                            "Launch discovery %s stopped at block %d: %s",
                            source.name,
                            start,
                            type(exc).__name__,
                        )
                        break
                    done = upper
                progress[source.name] = (cursor, done)

            records = _launch_records(decoded)
            headers = await self._block_headers({record["block_number"] for record in records})
            for record in records:
                header = headers[record["block_number"]]
                if _hash(header.get("hash")) != record.pop("block_hash"):
                    raise LaunchDiscoveryError("Log block is no longer canonical")
                record["block_timestamp"] = _quantity(header.get("timestamp"))
            await self.db.upsert_discovered_launches(CHAIN_ID, records)
            for name, (cursor, done) in progress.items():
                if done > cursor:
                    await self.db.set_launch_cursor(CHAIN_ID, name, done)

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

    async def _block_headers(self, numbers) -> Dict[int, Dict]:
        headers = {}
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
        return headers

    async def _call(self, method: str, params: list):
        body = await self._request({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        if not isinstance(body, dict) or "error" in body or body.get("result") is None:
            raise LaunchDiscoveryError(f"{method} returned no result")
        return body["result"]

    async def _request(self, payload):
        """POST with bounded exponential backoff on HTTP 429/5xx, transport and rate-limit errors."""
        for attempt in range(MAX_ATTEMPTS):
            wait = self._last_request + REQUEST_INTERVAL - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()
            try:
                status, body = await self._post(payload)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                retry = True
            else:
                if status != 200 and status != 429 and status < 500:
                    raise LaunchDiscoveryError(f"HTTP {status}")
                rows = body if isinstance(body, list) else [body]
                retry = status != 200 or any(
                    isinstance(row, dict) and _is_rate_limited(row.get("error")) for row in rows
                )
                if not retry:
                    return body
            if attempt + 1 < MAX_ATTEMPTS:
                await asyncio.sleep(2**attempt)
        raise LaunchDiscoveryError(f"RPC unavailable after {MAX_ATTEMPTS} attempts")

    async def _post(self, payload):
        async with self._session.post(self.rpc_url, json=payload) as response:
            if response.status != 200:
                return response.status, None
            return response.status, await response.json(content_type=None)
