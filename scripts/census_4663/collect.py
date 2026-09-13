"""Bounded, resumable, read-only log collector for chain 4663."""

import argparse
import asyncio
import json
import logging
import os
import time

import aiohttp
import aiosqlite
from eth_utils import is_address

from .events import (
    CHAIN_ID,
    POOL_MANAGER,
    RPC_URL,
    TOPICS,
    V2_FACTORY,
    WETH,
    ZERO,
    decode_log,
)
from .storage import data_directory, initialize

logger = logging.getLogger(__name__)


class RpcError(RuntimeError):
    pass


class Rpc:
    def __init__(self, session, url=RPC_URL, rps=4):
        if rps <= 0:
            raise ValueError("Request rate must be positive")
        self.session = session
        self.url = url
        self.interval = 1 / rps
        self.next_request = 0.0
        self.request_id = 0
        self.lock = asyncio.Lock()

    async def _post(self, payload):
        for attempt in range(6):
            async with self.lock:
                await asyncio.sleep(max(0, self.next_request - time.monotonic()))
                self.next_request = time.monotonic() + self.interval
            try:
                async with self.session.post(
                    self.url, json=payload, timeout=aiohttp.ClientTimeout(total=45)
                ) as response:
                    if response.status in (413, 414):
                        raise RpcError("RPC response size limit")
                    response.raise_for_status()
                    return await response.json()
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                if attempt == 5:
                    raise RpcError(
                        f"RPC transport failed after 6 attempts ({type(exc).__name__})"
                    ) from exc
                logger.warning(
                    "RPC transport retry %s (%s)", attempt + 1, type(exc).__name__
                )
                await asyncio.sleep(2**attempt)

    async def batch(self, calls):
        results = []
        for offset in range(0, len(calls), 50):
            payload = []
            for method, params in calls[offset : offset + 50]:
                self.request_id += 1
                payload.append(
                    {
                        "jsonrpc": "2.0",
                        "id": self.request_id,
                        "method": method,
                        "params": params,
                    }
                )
            for attempt in range(6):
                response = await self._post(payload if len(payload) > 1 else payload[0])
                rows = response if isinstance(response, list) else [response]
                if any(
                    isinstance(row, dict)
                    and "error" in row
                    and any(
                        term in str(row["error"]).lower()
                        for term in ("rate", "too many requests", "busy", "timeout")
                    )
                    for row in rows
                ):
                    if attempt == 5:
                        raise RpcError("RPC throttling/server timeout after 6 attempts")
                    logger.warning("RPC server retry %s", attempt + 1)
                    await asyncio.sleep(2**attempt)
                    continue
                break
            if any(not isinstance(row, dict) for row in rows):
                raise RpcError("Malformed RPC response")
            by_id = {row.get("id"): row for row in rows}
            if len(by_id) != len(payload):
                raise RpcError("Incomplete or duplicate RPC response")
            for request in payload:
                row = by_id.get(request["id"], {})
                if "error" in row:
                    raise RpcError(str(row["error"]))
                if row.get("result") is None:
                    raise RpcError(f"Missing RPC result for {request['method']}")
                results.append(row["result"])
        return results

    async def call(self, method, params):
        return (await self.batch([(method, params)]))[0]

    async def logs(self, query):
        try:
            result = await self.call("eth_getLogs", [query])
            if not isinstance(result, list):
                raise RpcError("Malformed eth_getLogs result")
            return result
        except RpcError as exc:
            lower, upper = int(query["fromBlock"], 16), int(query["toBlock"], 16)
            if lower == upper or not any(
                term in str(exc).lower()
                for term in (
                    "range",
                    "size",
                    "too many results",
                    "more than",
                    "limit exceeded",
                    "exceeds limit",
                    "response too large",
                )
            ):
                raise
            middle = (lower + upper) // 2
            logger.warning("Splitting log range %s-%s: %s", lower, upper, exc)
            left = await self.logs({**query, "toBlock": hex(middle)})
            right = await self.logs({**query, "fromBlock": hex(middle + 1)})
            return left + right


class Collector:
    def __init__(
        self,
        rpc,
        db,
        confirmations=60,
        chunk_size=2000,
        v3_factory=None,
        header_rpc=None,
    ):
        if confirmations < 1 or chunk_size < 1:
            raise ValueError("Confirmations and chunk size must be positive")
        if v3_factory is not None and not is_address(v3_factory):
            raise ValueError("Invalid v3 factory address")
        self.rpc = rpc
        self.header_rpc = header_rpc if header_rpc is not None else rpc
        self.db = db
        self.confirmations = confirmations
        self.chunk_size = chunk_size
        self.v3_factory = v3_factory.lower() if v3_factory else ""

    async def _meta(self):
        async with self.db.execute("SELECT key, value FROM meta") as cursor:
            return dict(await cursor.fetchall())

    async def _headers(self, numbers):
        numbers = sorted(set(numbers))
        rows = await self.header_rpc.batch(
            [("eth_getBlockByNumber", [hex(n), False]) for n in numbers]
        )
        headers = {}
        for number, row in zip(numbers, rows):
            if not row or int(row["number"], 16) != number or not row.get("hash"):
                raise RpcError("Missing or mismatched block header")
            headers[number] = row
        if len(headers) != len(numbers):
            raise RpcError("Incomplete block headers")
        return headers

    async def _rewind(self, cursor):
        async with self.db.execute(
            "SELECT number, hash FROM blocks WHERE number >= ? ORDER BY number",
            (max(0, cursor - self.confirmations + 1),),
        ) as query:
            remembered = await query.fetchall()
        headers = await self._headers([row[0] for row in remembered])
        mismatches = [
            n
            for n, block_hash in remembered
            if headers[n]["hash"].lower() != block_hash
        ]
        if not mismatches:
            return cursor
        first = min(mismatches)
        # Find an actual common ancestor among durable earlier checkpoints. Deep
        # reorgs replay more than the window rather than retaining stale events.
        async with self.db.execute(
            "SELECT number, hash FROM blocks WHERE number < ? ORDER BY number DESC",
            (first,),
        ) as query:
            earlier = await query.fetchall()
        for number, block_hash in earlier:
            header = (await self._headers([number]))[number]
            if header["hash"].lower() == block_hash:
                first = number + 1
                break
        else:
            meta = await self._meta()
            first = int(meta["start_block"])
        logger.warning("Reorg detected; deleting and replaying from block %s", first)
        async with self.db.execute("BEGIN IMMEDIATE"):
            for statement in (
                "DELETE FROM events WHERE block_number >= ?",
                "DELETE FROM pools WHERE block_number >= ?",
                "DELETE FROM evidence WHERE block_number >= ?",
            ):
                await self.db.execute(statement, (first,))
            await self.db.execute("DELETE FROM blocks WHERE number >= ?", (first,))
            await self.db.execute(
                "UPDATE meta SET value = ? WHERE key = 'cursor'", (str(first - 1),)
            )
            await self.db.commit()
        return first - 1

    async def run_once(self, from_block=None, to_block=None):
        if int(await self.rpc.call("eth_chainId", []), 16) != CHAIN_ID:
            raise ValueError("RPC chain mismatch: expected chain 4663")
        if (
            self.header_rpc is not self.rpc
            and int(await self.header_rpc.call("eth_chainId", []), 16) != CHAIN_ID
        ):
            raise ValueError("Header RPC chain mismatch: expected chain 4663")
        meta = await self._meta()
        if meta and meta.get("chain_id") != str(CHAIN_ID):
            raise ValueError("Census database chain mismatch")
        if meta and meta.get("v3_factory", "") != self.v3_factory:
            raise ValueError("Cannot change v3 factory for an existing census")
        tip = int(await self.rpc.call("eth_blockNumber", []), 16)
        end = tip - self.confirmations
        if to_block is not None:
            end = min(end, to_block)
        if (
            from_block is not None
            and from_block < 0
            or to_block is not None
            and to_block < 0
        ):
            raise ValueError("Block numbers must not be negative")
        if from_block is not None and to_block is not None and from_block > to_block:
            raise ValueError("from-block must not exceed to-block")
        if "cursor" in meta:
            cursor = await self._rewind(int(meta["cursor"]))
            if from_block is not None and from_block != int(meta["start_block"]):
                raise ValueError("from-block differs from persisted census start")
            start = cursor + 1
        else:
            start = from_block if from_block is not None else max(0, end)
            cursor = start - 1
            await self.db.executemany(
                "INSERT INTO meta(key,value) VALUES (?,?)",
                [
                    ("chain_id", str(CHAIN_ID)),
                    ("v3_factory", self.v3_factory),
                    ("start_block", str(start)),
                    ("cursor", str(cursor)),
                ],
            )
            await self.db.commit()
        while start <= end:
            upper = min(end, start + self.chunk_size - 1)
            await self._chunk(start, upper)
            cursor = upper
            start = upper + 1
            logger.info("Collected through %s (target %s)", cursor, end)
        return cursor

    async def _chunk(self, start, end):
        async with self.db.execute(
            "SELECT hash FROM blocks WHERE number = ?", (start - 1,)
        ) as query:
            previous = await query.fetchone()
        boundaries = {end, start - 1} if previous else {end}
        before = await self._headers(boundaries)
        if previous and before[start - 1]["hash"].lower() != previous[0]:
            raise RpcError("Previous chunk block mismatch; resume to rewind the census")
        filters = [
            (
                POOL_MANAGER,
                "v4",
                [TOPICS[name] for name in ("Initialize", "ModifyLiquidity", "SwapV4")],
            ),
            (V2_FACTORY, "v2_factory", [TOPICS["PairCreated"]]),
        ]
        if self.v3_factory:
            filters.append((self.v3_factory, "v3_factory", [TOPICS["PoolCreated"]]))
        logs = []
        for address, source, topics in filters:
            found = await self.rpc.logs(
                {
                    "address": address,
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                    "topics": [topics],
                }
            )
            logs.extend((log, source) for log in found)
        async with self.db.execute("SELECT pool_key, source FROM pools") as query:
            known = dict(await query.fetchall())
        creations = []
        for log, source in logs:
            decoded = decode_log(log, source)
            if decoded and decoded["name"] in (
                "Initialize",
                "PairCreated",
                "PoolCreated",
            ):
                creations.append((log, decoded))
        pairs = sorted(
            {key for key, source in known.items() if source == "v2"}
            | {item["pool_key"] for _, item in creations if item["source"] == "v2"}
        )
        for offset in range(0, len(pairs), 100):
            found = await self.rpc.logs(
                {
                    "address": pairs[offset : offset + 100],
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                    "topics": [[TOPICS[name] for name in ("SwapV2", "Mint", "Sync")]],
                }
            )
            logs.extend((log, "v2") for log in found)
        tracked_v4 = {key for key, source in known.items() if source == "v4"} | {
            item["pool_key"] for _, item in creations if item["source"] == "v4"
        }
        logs = [
            (log, source)
            for log, source in logs
            if source != "v4"
            or log["topics"][0].lower() == TOPICS["Initialize"]
            or log["topics"][1].lower() in tracked_v4
        ]
        # eth_getLogs on this RPC can expose blockTimestamp=0x0 even when
        # receipt logs have a timestamp. Use canonical headers for event times.
        headers = await self._headers(
            {start, end}
            | {int(log["blockNumber"], 16) for log, _ in logs}
            | set(range(max(start, end - self.confirmations + 1), end + 1))
        )
        for log, source in logs:
            number = int(log["blockNumber"], 16)
            allowed = {
                "v4": [POOL_MANAGER],
                "v2_factory": [V2_FACTORY],
                "v3_factory": [self.v3_factory],
                "v2": pairs,
            }[source]
            if (
                not start <= number <= end
                or log.get("removed", False)
                or log["blockHash"].lower() != headers[number]["hash"].lower()
                or log["address"].lower() not in allowed
            ):
                raise RpcError("Log identity or block mismatch")
        tx_tokens = {}
        for log, decoded in creations:
            data = decoded["data"]
            tokens = [
                data[key]
                for key in (
                    ("currency0", "currency1")
                    if decoded["source"] == "v4"
                    else ("token0", "token1")
                )
            ]
            tx_tokens.setdefault(log["transactionHash"].lower(), set()).update(
                set(tokens) - {WETH, ZERO}
            )
        evidence = []
        tx_hashes = sorted(tx_tokens)
        results = await self.rpc.batch(
            [
                (method, [tx_hash])
                for tx_hash in tx_hashes
                for method in ("eth_getTransactionByHash", "eth_getTransactionReceipt")
            ]
        )
        for index, tx_hash in enumerate(tx_hashes):
            tx, receipt = results[2 * index : 2 * index + 2]
            number = int(receipt["blockNumber"], 16)
            if (
                number not in headers
                or receipt["blockHash"].lower() != headers[number]["hash"].lower()
                or tx["hash"].lower() != tx_hash
                or receipt["transactionHash"].lower() != tx_hash
                or tx["blockHash"].lower() != receipt["blockHash"].lower()
                or int(receipt["status"], 16) != 1
            ):
                raise RpcError("Creation transaction/receipt identity mismatch")
            receipt_logs = sorted(
                receipt["logs"], key=lambda log: int(log["logIndex"], 16)
            )
            receipt_by_index = {int(log["logIndex"], 16): log for log in receipt_logs}
            if len(receipt_by_index) != len(receipt_logs):
                raise RpcError("Duplicate receipt log index")
            for creation, _ in creations:
                if creation["transactionHash"].lower() != tx_hash:
                    continue
                matching = receipt_by_index.get(int(creation["logIndex"], 16))
                if matching is None or any(
                    matching[field] != creation[field]
                    for field in (
                        "address",
                        "topics",
                        "data",
                        "blockHash",
                        "transactionHash",
                    )
                ):
                    raise RpcError("Creation log missing or mismatched in receipt")
            for log in receipt_logs:
                if (
                    log["transactionHash"].lower() != tx_hash
                    or log["blockHash"].lower() != receipt["blockHash"].lower()
                    or int(log["blockNumber"], 16) != number
                    or log.get("removed", False)
                ):
                    raise RpcError("Receipt log identity mismatch")
            token_evidence = {}
            for token in sorted(tx_tokens[tx_hash]):
                transfers = [
                    log
                    for log in receipt_logs
                    if log["address"].lower() == token
                    and len(log["topics"]) == 3
                    and log["topics"][0].lower() == TOPICS["Transfer"]
                    and len(log["data"]) == 66
                ]
                mint = bool(transfers and int(transfers[0]["topics"][1], 16) == 0)
                token_evidence[token] = {
                    "first_transfer_mint": mint,
                    "launch_source": "atomic" if mint else "prior",
                }
            evidence.append(
                (
                    tx_hash,
                    number,
                    json.dumps(
                        {
                            "from": tx["from"].lower(),
                            "to": tx["to"].lower() if tx["to"] else None,
                            "emitters": sorted(
                                {log["address"].lower() for log in receipt_logs}
                            ),
                            "tokens": token_evidence,
                            "logs": receipt_logs,
                        }
                    ),
                )
            )
        # Re-read the upper boundary after all RPCs. Its hash commits to the
        # preceding chain and catches a reorg while this chunk was assembled.
        final = await self._headers(boundaries)
        if any(
            final[n]["hash"].lower() != before[n]["hash"].lower() for n in boundaries
        ) or (headers[end]["hash"].lower() != before[end]["hash"].lower()):
            raise RpcError("Chain changed during chunk; retry from durable cursor")
        pool_rows, event_rows = [], []
        ingested_at = time.time()
        for log, source in sorted(
            logs,
            key=lambda item: (
                int(item[0]["blockNumber"], 16),
                int(item[0]["logIndex"], 16),
            ),
        ):
            decoded = decode_log(log, source)
            if decoded is None:
                continue
            key, name, data = decoded["pool_key"], decoded["name"], decoded["data"]
            number = int(log["blockNumber"], 16)
            timestamp = int(headers[number]["timestamp"], 16)
            tx_hash = log["transactionHash"].lower()
            if name in ("Initialize", "PairCreated", "PoolCreated"):
                known[key] = decoded["source"]
                token0, token1 = (
                    (data["currency0"], data["currency1"])
                    if decoded["source"] == "v4"
                    else (data["token0"], data["token1"])
                )
                pool_rows.append(
                    (
                        key,
                        decoded["source"],
                        token0,
                        token1,
                        number,
                        timestamp,
                        tx_hash,
                        json.dumps(data),
                    )
                )
            if key in known:
                event_rows.append(
                    (
                        decoded["source"],
                        key,
                        name,
                        number,
                        timestamp,
                        tx_hash,
                        int(log["logIndex"], 16),
                        ingested_at,
                        json.dumps(data),
                    )
                )
        try:
            await self.db.execute("BEGIN IMMEDIATE")
            await self.db.executemany(
                "INSERT OR REPLACE INTO blocks VALUES (?,?,?)",
                [
                    (n, row["hash"].lower(), int(row["timestamp"], 16))
                    for n, row in headers.items()
                ],
            )
            await self.db.executemany(
                "INSERT INTO pools VALUES (?,?,?,?,?,?,?,?)", pool_rows
            )
            await self.db.executemany(
                "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)", event_rows
            )
            await self.db.executemany(
                "INSERT OR REPLACE INTO evidence VALUES (?,?,?)", evidence
            )
            await self.db.execute(
                "UPDATE meta SET value = ? WHERE key = 'cursor'", (str(end),)
            )
            await self.db.commit()
        except BaseException:
            await self.db.rollback()
            raise


async def run(args):
    directory = data_directory(args.data_dir)
    async with (
        aiohttp.ClientSession() as session,
        aiosqlite.connect(directory / "census.sqlite3") as db,
    ):
        await initialize(db)
        header_url = os.getenv("CENSUS_HEADER_RPC_URL")
        endpoint_rps = args.rps / 2 if header_url else args.rps
        collector = Collector(
            Rpc(session, os.getenv("CENSUS_RPC_URL", RPC_URL), endpoint_rps),
            db,
            args.confirmations,
            args.chunk_size,
            args.v3_factory,
            header_rpc=Rpc(session, header_url, endpoint_rps) if header_url else None,
        )
        while True:
            cursor = await collector.run_once(args.from_block, args.to_block)
            if not args.follow or args.to_block is not None and cursor >= args.to_block:
                print(
                    json.dumps(
                        {
                            "chain_id": CHAIN_ID,
                            "cursor": cursor,
                            "data_dir": str(directory),
                        }
                    )
                )
                return
            await asyncio.sleep(6)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--from-block", type=int)
    parser.add_argument("--to-block", type=int)
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--v3-factory")
    parser.add_argument("--confirmations", type=int, default=60)
    parser.add_argument("--chunk-size", type=int, default=2000)
    parser.add_argument("--rps", type=float, default=4)
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
