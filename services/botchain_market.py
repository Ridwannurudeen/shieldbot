"""BOT Chain (677) market data from BDEX, in the shape DexService returns from DexScreener.

DexScreener lists no BOT Chain pair, so a token's market is read from BDEX itself:
  inventory  every V2 pair from the V2 factory's PairCreated logs and every V3 pool from the V3
             factory's PoolCreated logs, both over the full range with the factory address filter,
             kept for 10 minutes. The BDEX API's pools list is not the inventory: on 25 Oct 2026 it
             listed 53 of the 107 pools.
  amounts    the API's token amounts where it lists the pool; otherwise getReserves() on a V2 pair,
             and liquidity() plus both tokens' balanceOf(pool) on a V3 pool. A V3 pool whose
             liquidity() is 0 has no liquidity in range and counts as 0.
  prices     the BDEX price API, accepted only by parse_price_reply's rule; USDT is 1.
  liquidity  a pool's two sides valued at those prices. A side holding nothing is worth 0; a side
             that holds tokens no accepted price values leaves that pool's liquidity unknown. The
             headline is the deepest pool that could be valued, and its creation block dates the
             pair age.
  volume     the sum of the API's volumeUsd24 over every pool of the token, and unknown when any of
             them has no valid volume (an omitted pool has none).
  fdv        totalSupply times the price. The API's fdvUsd is not used: it is a pool's value (on
             the USDT/WBOT V3 pool 31.2M against the two sides' 31.2M, while USDT's supply alone is
             73.96M) and COW's two pools give it two different figures.

Every request has a 10 s timeout, at most two run at once, and only an HTTP 429 or a connection
error is asked once more after a backoff. A price reply, priced or not, is kept for 60 s (at most
512 tokens), so a scan repeated within a minute asks no price again; a failed price request is not
kept. A failure leaves the affected fields unknown with a reason
naming the source; token_market never raises. No holder data is read.
"""

import asyncio
import logging
import math
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import aiohttp
from cachetools import TTLCache
from eth_abi import decode
from eth_abi.exceptions import DecodingError
from eth_utils import keccak

logger = logging.getLogger(__name__)

API_BASE = "https://dex-wallet.botchain.ai/api/v1"
USDT = "0xababc7ddc03e501d190c676bf3d92ef0e6e87a3c"
V2_FACTORY = "0x117115f3b72c8d1989178089a67d0c26f8ee0aa3"
V3_FACTORY = "0x1c51c173323ec11bb4e3c4fd2314c225dc4b5419"
PAIR_CREATED_TOPIC = (
    "0x" + keccak(text="PairCreated(address,address,address,uint256)").hex()
)
POOL_CREATED_TOPIC = (
    "0x" + keccak(text="PoolCreated(address,address,uint24,int24,address)").hex()
)

GET_RESERVES = "0x0902f1ac"
LIQUIDITY = "0x1a686502"
BALANCE_OF = "0x70a08231"
DECIMALS = "0x313ce567"
TOTAL_SUPPLY = "0x18160ddd"
NAME = "0x06fdde03"
SYMBOL = "0x95d89b41"

REQUEST_TIMEOUT_SECONDS = 10
CONCURRENCY = 2
RETRY_BACKOFF_SECONDS = 1.0
POOLS_TTL_SECONDS = 60
PRICE_TTL_SECONDS = 60
PRICE_CACHE_SIZE = 512
INVENTORY_TTL_SECONDS = 600
POOLS_PAGE_SIZE = 100
RPC_BATCH_SIZE = 50
RPC_UNSUPPORTED = -32601

METRICS = (
    "price_usd",
    "liquidity_usd",
    "volume_24h",
    "price_change_24h",
    "fdv",
    "pair_age_hours",
)
# As in DexService: the 24h change feeds only the volatility flag, so it is not in coverage.
REQUIRED = tuple(field for field in METRICS if field != "price_change_24h")


@dataclass(frozen=True)
class Pool:
    address: str
    kind: str
    token0: str
    token1: str
    block: int


class SourceError(Exception):
    """A source gave no usable answer; the message names the source and why."""


def parse_price_reply(answer, token: str) -> Optional[float]:
    """The USD price in a BDEX price reply for ``token``, or None when the reply prices nothing.

    A price counts only when ``success`` is true, ``data.token`` is the token asked, ``data.path``
    is non empty and ends with USDT, and ``data.price`` is a finite number above 0. An unpriced
    token is answered with success true, price "0" and an empty path.
    """
    if not isinstance(answer, dict) or answer.get("success") is not True:
        return None
    data = answer.get("data")
    if not isinstance(data, dict):
        return None
    response_token = data.get("token")
    path = data.get("path")
    if (
        not isinstance(response_token, str)
        or response_token.lower() != token.lower()
        or not isinstance(path, list)
        or not path
        or not isinstance(path[-1], str)
        or path[-1].lower() != USDT
    ):
        return None
    raw_price = data.get("price")
    if isinstance(raw_price, bool):
        return None
    try:
        price = float(raw_price)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(price) or price <= 0:
        return None
    return price


def _number(value) -> Optional[float]:
    """A finite, non negative number from an API string, else None."""
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number >= 0 else None


def _address(word: str) -> str:
    return "0x" + word[-40:].lower()


def _word(address: str) -> str:
    return address[2:].rjust(64, "0")


def _decode(types: List[str], result) -> Optional[tuple]:
    if not isinstance(result, str) or not result.startswith("0x"):
        return None
    try:
        return decode(types, bytes.fromhex(result[2:]))
    except (DecodingError, ValueError):
        return None


def _parse_logs(rows, factory: str, topic: str, kind: str) -> List[Pool]:
    if not isinstance(rows, list):
        raise SourceError("BOT Chain RPC returned malformed logs")
    pools = []
    for log in rows:
        try:
            topics = log["topics"]
            if log["address"].lower() != factory or topics[0].lower() != topic:
                raise ValueError("log from another emitter")
            data = log["data"][2:]
            # PairCreated(token0, token1, pair, n): the pair is the first data word.
            # PoolCreated(token0, token1, fee, tickSpacing, pool): the pool is the second.
            word = data[0:64] if kind == "v2" else data[64:128]
            pools.append(
                Pool(
                    address=_address(word),
                    kind=kind,
                    token0=_address(topics[1]),
                    token1=_address(topics[2]),
                    block=int(log["blockNumber"], 16),
                )
            )
        except (KeyError, IndexError, TypeError, ValueError, AttributeError):
            raise SourceError("BOT Chain RPC returned malformed logs")
    return pools


class BotChainMarket:
    """Reads one BOT Chain token's BDEX market: liquidity, 24h volume, pair age, price and fdv."""

    def __init__(self, rpc_url: str, api_base: str = API_BASE):
        self._rpc_url = rpc_url
        self._api_base = api_base.rstrip("/")
        self._semaphore = asyncio.Semaphore(CONCURRENCY)
        self._inventory: Optional[List[Pool]] = None
        self._inventory_at = 0.0
        self._listed: Optional[Dict[str, dict]] = None
        self._listed_at = 0.0
        # Block timestamps never change, so a pool once dated stays dated.
        self._created_at: Dict[str, int] = {}
        # The module's clock, so the cache ages with time.monotonic as every other cache here.
        self._prices: TTLCache = TTLCache(
            maxsize=PRICE_CACHE_SIZE, ttl=PRICE_TTL_SECONDS, timer=lambda: time.monotonic()
        )

    async def token_market(self, token: str) -> dict:
        result = {
            "observed_at": time.time(),
            "token_name": None,
            "token_symbol": None,
            "price_usd": None,
            "liquidity_usd": None,
            "volume_24h": None,
            "price_change_24h": None,
            "fdv": None,
            "pair_age_hours": None,
            "volatility_flag": None,
            "low_liquidity_flag": None,
            "wash_trade_flag": None,
            "new_pair_flag": None,
            "status": "unknown",
            "reason": "BDEX market data unavailable",
            "coverage": {field: False for field in REQUIRED},
        }
        try:
            return await self._measure(token.lower(), result)
        except Exception as e:
            logger.error("BDEX market read failed for %s: %s", token, type(e).__name__)
            result["reason"] = f"BDEX market read failed: {type(e).__name__}"
            return result

    async def _measure(self, token: str, result: dict) -> dict:
        notes: List[str] = []
        async with aiohttp.ClientSession() as session:
            (
                (inventory, fresh, inventory_note),
                (listed, listed_note),
                (price, price_note),
            ) = await asyncio.gather(
                self._read_inventory(session),
                self._read_listed(session),
                self._read_price(session, token),
            )
            notes += [
                note for note in (inventory_note, listed_note, price_note) if note
            ]
            pools = (
                []
                if inventory is None
                else [pool for pool in inventory if token in (pool.token0, pool.token1)]
            )
            if inventory is not None and not pools:
                result["reason"] = "No BDEX pools for this token on BOT Chain"
                return result

            omitted = [
                pool for pool in pools if self._listed_amounts(listed, pool) is None
            ]
            reads = await self._read_chain(session, token, omitted, notes)

            amounts: Dict[str, Optional[Tuple[float, float]]] = {}
            for pool in pools:
                listed_amounts = self._listed_amounts(listed, pool)
                amounts[pool.address] = (
                    listed_amounts
                    if listed_amounts is not None
                    else self._chain_amounts(pool, reads)
                )

            prices = {token: price, USDT: 1.0}
            others = sorted(
                {
                    side
                    for pool in pools
                    if amounts[pool.address] is not None
                    for side, amount in zip(
                        (pool.token0, pool.token1), amounts[pool.address]
                    )
                    if amount > 0 and side not in prices
                }
            )
            other_prices = await asyncio.gather(
                *(self._read_price(session, side) for side in others)
            )
            for side, (side_price, _note) in zip(others, other_prices):
                prices[side] = side_price

            values = {
                pool.address: self._value(pool, amounts[pool.address], prices)
                for pool in pools
            }
            valued = [pool for pool in pools if values[pool.address] is not None]
            if len(valued) < len(pools):
                notes.append(
                    f"{len(pools) - len(valued)} of {len(pools)} BDEX pools could not be valued"
                )
            deepest = (
                max(valued, key=lambda pool: values[pool.address]) if valued else None
            )
            liquidity_usd = values[deepest.address] if deepest else None

            created_at = (
                await self._read_created_at(session, deepest, fresh, notes)
                if deepest
                else None
            )

        volume_24h = self._volume(pools, listed, notes) if pools else None
        pair_age_hours = (
            (time.time() - created_at) / 3600 if created_at is not None else None
        )
        fdv = None
        supply = reads.get((token, TOTAL_SUPPLY))
        decimals = reads.get((token, DECIMALS))
        if price is not None and supply is not None and decimals is not None:
            total = supply / 10**decimals * price
            fdv = total if math.isfinite(total) else None

        low_liquidity_flag = (
            liquidity_usd < 10_000 if liquidity_usd is not None else None
        )
        new_pair_flag = pair_age_hours < 24 if pair_age_hours is not None else None
        wash_trade_flag = (
            (
                liquidity_usd < 50_000
                and liquidity_usd > 0
                and volume_24h > liquidity_usd * 10
            )
            if liquidity_usd is not None and volume_24h is not None
            else None
        )

        result.update(
            {
                "token_name": reads.get((token, NAME)),
                "token_symbol": reads.get((token, SYMBOL)),
                "price_usd": price,
                "liquidity_usd": liquidity_usd,
                "volume_24h": volume_24h,
                "fdv": fdv,
                "pair_age_hours": round(pair_age_hours, 1)
                if pair_age_hours is not None
                else None,
                "low_liquidity_flag": low_liquidity_flag,
                "wash_trade_flag": wash_trade_flag,
                "new_pair_flag": new_pair_flag,
            }
        )
        coverage = {field: result[field] is not None for field in REQUIRED}
        missing = [field for field in METRICS if result[field] is None]
        reasons = (
            ["Missing BDEX fields: " + ", ".join(missing)] if missing else []
        ) + notes
        result.update(
            coverage=coverage,
            status="ok" if all(coverage.values()) else "unknown",
            reason="; ".join(reasons) if reasons else None,
        )
        return result

    async def _send(self, session, method: str, url: str, source: str, **kwargs):
        """One HTTP request under the shared bound; the decoded JSON body, else SourceError."""
        for attempt in range(2):
            retry = None
            try:
                async with self._semaphore:
                    request = session.post if method == "post" else session.get
                    async with request(
                        url,
                        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS),
                        **kwargs,
                    ) as response:
                        status = response.status
                        body = (
                            await response.json(content_type=None)
                            if status == 200
                            else None
                        )
            except asyncio.TimeoutError:
                raise SourceError(f"{source} timed out")
            except aiohttp.ClientConnectionError as e:
                retry = f"{source} connection failed ({type(e).__name__})"
            except (aiohttp.ClientError, ValueError) as e:
                raise SourceError(f"{source} reply unreadable ({type(e).__name__})")
            else:
                if status == 200:
                    return body
                if status != 429:
                    raise SourceError(f"{source} HTTP {status}")
                retry = f"{source} rate limited (HTTP 429)"
            if attempt == 0:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS)
        raise SourceError(retry)

    async def _rpc(self, session, calls: List[Tuple[str, list]]) -> List[dict]:
        """One JSON-RPC batch; its rows in request order."""
        body = [
            {"jsonrpc": "2.0", "id": index, "method": method, "params": params}
            for index, (method, params) in enumerate(calls)
        ]
        payload = await self._send(
            session, "post", self._rpc_url, "BOT Chain RPC", json=body
        )
        rows = payload if isinstance(payload, list) else [payload]
        if (
            len(rows) != len(body)
            or not all(isinstance(row, dict) for row in rows)
            or {row.get("id") for row in rows} != set(range(len(body)))
        ):
            raise SourceError("BOT Chain RPC reply malformed")
        by_id = {row["id"]: row for row in rows}
        return [by_id[index] for index in range(len(body))]

    async def _rpc_result(self, session, method: str, params: list):
        """One call's result; a JSON-RPC error raises SourceError naming the method."""
        (row,) = await self._rpc(session, [(method, params)])
        error = row.get("error")
        if error is not None:
            code = error.get("code") if isinstance(error, dict) else None
            if code == RPC_UNSUPPORTED:
                raise SourceError(f"BOT Chain RPC does not support {method}")
            raise SourceError(f"BOT Chain RPC {method} error {code}")
        return row.get("result")

    async def _read_inventory(
        self, session
    ) -> Tuple[Optional[List[Pool]], bool, Optional[str]]:
        """Every BDEX pool, whether the list is fresh, and a note when it is not."""
        if (
            self._inventory is not None
            and time.monotonic() - self._inventory_at < INVENTORY_TTL_SECONDS
        ):
            return self._inventory, True, None

        async def logs(factory: str, topic: str, kind: str) -> List[Pool]:
            rows = await self._rpc_result(
                session,
                "eth_getLogs",
                [
                    {
                        "address": factory,
                        "topics": [topic],
                        "fromBlock": "0x0",
                        "toBlock": "latest",
                    }
                ],
            )
            return _parse_logs(rows, factory, topic, kind)

        answers = await asyncio.gather(
            logs(V2_FACTORY, PAIR_CREATED_TOPIC, "v2"),
            logs(V3_FACTORY, POOL_CREATED_TOPIC, "v3"),
            return_exceptions=True,
        )
        failure = next(
            (answer for answer in answers if isinstance(answer, BaseException)), None
        )
        if failure is None:
            self._inventory = answers[0] + answers[1]
            self._inventory_at = time.monotonic()
            return self._inventory, True, None
        if not isinstance(failure, SourceError):
            raise failure
        if self._inventory is None:
            return None, False, f"BDEX pool list unavailable: {failure}"
        minutes = (time.monotonic() - self._inventory_at) / 60
        return (
            self._inventory,
            False,
            (
                f"BDEX pool list refresh failed ({failure}); using the list read {minutes:.0f} min earlier"
            ),
        )

    async def _read_listed(
        self, session
    ) -> Tuple[Optional[Dict[str, dict]], Optional[str]]:
        """The BDEX API's pools by address, read page by page until its total is reached."""
        if (
            self._listed is not None
            and time.monotonic() - self._listed_at < POOLS_TTL_SECONDS
        ):
            return self._listed, None
        listed: Dict[str, dict] = {}
        try:
            page = 1
            while True:
                answer = await self._send(
                    session,
                    "get",
                    f"{self._api_base}/pools",
                    "BDEX pools API",
                    params={
                        "page_num": page,
                        "page_size": POOLS_PAGE_SIZE,
                        "sort_by": "tvl",
                        "sort_order": "desc",
                    },
                )
                if not isinstance(answer, dict) or answer.get("success") is not True:
                    raise SourceError("BDEX pools API answered without success")
                rows = answer.get("data")
                total = (answer.get("meta") or {}).get("total")
                if not isinstance(rows, list) or type(total) is not int:
                    raise SourceError("BDEX pools API reply malformed")
                before = len(listed)
                for row in rows:
                    if isinstance(row, dict) and isinstance(row.get("poolId"), str):
                        listed[row["poolId"].lower()] = row
                if len(listed) >= total:
                    break
                # A page that adds no pool ends the read, so a repeating page cannot loop.
                if len(listed) == before:
                    raise SourceError(
                        f"BDEX pools API listed {len(listed)} of {total} pools"
                    )
                page += 1
        except SourceError as e:
            return None, f"BDEX pools list unavailable: {e}"
        self._listed = listed
        self._listed_at = time.monotonic()
        return listed, None

    async def _read_price(
        self, session, token: str
    ) -> Tuple[Optional[float], Optional[str]]:
        if token == USDT:
            return 1.0, None
        if token in self._prices:
            return self._prices[token]
        try:
            answer = await self._send(
                session,
                "get",
                f"{self._api_base}/price",
                "BDEX price API",
                params={"token": token},
            )
        except SourceError as e:
            return None, f"Price unknown: {e}"
        price = parse_price_reply(answer, token)
        note = (
            "Price unknown: BDEX prices no route from this token to USDT" if price is None else None
        )
        self._prices[token] = (price, note)
        return price, note

    @staticmethod
    def _listed_amounts(
        listed: Optional[Dict[str, dict]], pool: Pool
    ) -> Optional[Tuple[float, float]]:
        """The API's token amounts of a pool it lists with the inventory's token order, else None."""
        row = (listed or {}).get(pool.address)
        if (
            row is None
            or str(row.get("baseTokenAddress", "")).lower() != pool.token0
            or str(row.get("quoteTokenAddress", "")).lower() != pool.token1
        ):
            return None
        amount0 = _number(row.get("token0Amount"))
        amount1 = _number(row.get("token1Amount"))
        if amount0 is None or amount1 is None:
            return None
        return amount0, amount1

    async def _read_chain(
        self, session, token: str, omitted: List[Pool], notes: List[str]
    ) -> dict:
        """The token's metadata and each omitted pool's holdings, keyed by (contract, selector) or
        (token, pool) for a balance, in JSON-RPC batches. A read that failed is absent."""
        wanted: List[Tuple[tuple, str, str, List[str]]] = [
            ((token, DECIMALS), token, DECIMALS, ["uint8"]),
            ((token, TOTAL_SUPPLY), token, TOTAL_SUPPLY, ["uint256"]),
            ((token, NAME), token, NAME, ["string"]),
            ((token, SYMBOL), token, SYMBOL, ["string"]),
        ]
        sides = []
        for pool in omitted:
            if pool.kind == "v2":
                wanted.append(
                    (
                        (pool.address, GET_RESERVES),
                        pool.address,
                        GET_RESERVES,
                        ["uint112", "uint112", "uint32"],
                    )
                )
            else:
                wanted.append(
                    ((pool.address, LIQUIDITY), pool.address, LIQUIDITY, ["uint128"])
                )
                for side in (pool.token0, pool.token1):
                    wanted.append(
                        (
                            (side, pool.address),
                            side,
                            BALANCE_OF + _word(pool.address),
                            ["uint256"],
                        )
                    )
            sides += [pool.token0, pool.token1]
        for side in dict.fromkeys(sides):
            if side != token:
                wanted.append(((side, DECIMALS), side, DECIMALS, ["uint8"]))

        reads = {}
        failures = []
        error_codes = []
        chunks = [
            wanted[i : i + RPC_BATCH_SIZE]
            for i in range(0, len(wanted), RPC_BATCH_SIZE)
        ]

        async def read(chunk):
            try:
                rows = await self._rpc(
                    session,
                    [
                        ("eth_call", [{"to": to, "data": data}, "latest"])
                        for _key, to, data, _types in chunk
                    ],
                )
            except SourceError as e:
                failures.append(str(e))
                return
            for (key, _to, _data, types), row in zip(chunk, rows):
                error = row.get("error")
                if error is not None:
                    error_codes.append(error.get("code") if isinstance(error, dict) else None)
                    continue
                values = _decode(types, row.get("result"))
                if values is None:
                    continue
                if types == ["uint8"] and values[0] > 77:
                    continue
                reads[key] = values if len(values) > 1 else values[0]

        await asyncio.gather(*(read(chunk) for chunk in chunks))
        if failures:
            notes.append(f"BOT Chain reads failed: {failures[0]}")
        if error_codes:
            first = error_codes[0]
            cause = (
                "does not support eth_call"
                if first == RPC_UNSUPPORTED
                else f"answered eth_call error {first}"
            )
            notes.append(
                f"BOT Chain RPC {cause} on {len(error_codes)} of {len(wanted)} reads"
            )
        return reads

    @staticmethod
    def _chain_amounts(pool: Pool, reads: dict) -> Optional[Tuple[float, float]]:
        decimals0 = reads.get((pool.token0, DECIMALS))
        decimals1 = reads.get((pool.token1, DECIMALS))
        if decimals0 is None or decimals1 is None:
            return None
        if pool.kind == "v2":
            reserves = reads.get((pool.address, GET_RESERVES))
            if reserves is None:
                return None
            raw0, raw1 = reserves[0], reserves[1]
        else:
            liquidity = reads.get((pool.address, LIQUIDITY))
            if liquidity is None:
                return None
            if liquidity == 0:
                return 0.0, 0.0
            raw0 = reads.get((pool.token0, pool.address))
            raw1 = reads.get((pool.token1, pool.address))
            if raw0 is None or raw1 is None:
                return None
        return raw0 / 10**decimals0, raw1 / 10**decimals1

    @staticmethod
    def _value(
        pool: Pool, amounts: Optional[Tuple[float, float]], prices: dict
    ) -> Optional[float]:
        if amounts is None:
            return None
        total = 0.0
        for side, amount in zip((pool.token0, pool.token1), amounts):
            if amount == 0:
                continue
            price = prices.get(side)
            if price is None:
                return None
            total += amount * price
        return total if math.isfinite(total) else None

    async def _read_created_at(
        self, session, pool: Pool, fresh: bool, notes: List[str]
    ) -> Optional[int]:
        if pool.address in self._created_at:
            return self._created_at[pool.address]
        if not fresh:
            notes.append(
                "Pair age unknown: the pool was not dated before the pool list refresh failed"
            )
            return None
        try:
            block = await self._rpc_result(
                session, "eth_getBlockByNumber", [hex(pool.block), False]
            )
            timestamp = int(block["timestamp"], 16)
        except SourceError as e:
            notes.append(f"Pair age unknown: {e}")
            return None
        except (KeyError, TypeError, ValueError):
            notes.append("Pair age unknown: BOT Chain RPC returned a malformed block")
            return None
        self._created_at[pool.address] = timestamp
        return timestamp

    @staticmethod
    def _volume(
        pools: List[Pool], listed: Optional[Dict[str, dict]], notes: List[str]
    ) -> Optional[float]:
        """The 24h volume summed over every pool of the token, None if any pool has no valid volume."""
        volumes = [
            _number(((listed or {}).get(pool.address) or {}).get("volumeUsd24"))
            for pool in pools
        ]
        missing = sum(volume is None for volume in volumes)
        if missing:
            notes.append(
                f"24h volume unknown: no BDEX volume for {missing} of {len(pools)} pools"
            )
            return None
        total = sum(volumes)
        return total if math.isfinite(total) else None
