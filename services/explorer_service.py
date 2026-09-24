"""Sourcify v2 verification and Blockscout PRO contract enrichment."""

import asyncio
import os
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import aiohttp
from cachetools import TTLCache


# Public Blockscout instances that answer without an API key; other chains go through the keyed
# PRO gateway. optimism.blockscout.com redirects here, and requests do not follow redirects, so the
# map names the final host. scripts/check_blockscout_instances.py notices when an instance moves.
BLOCKSCOUT_INSTANCES = {
    8453: "https://base.blockscout.com",
    10: "https://explorer.optimism.io",
}


@dataclass(frozen=True)
class ExplorerResult:
    status: str
    data: dict | None = None
    reason: str | None = None
    provider: str = ""


def _is_address(value) -> bool:
    return (
        isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", value) is not None
    )


def _redact_api_key(value, api_key: str):
    if isinstance(value, str):
        return value.replace(api_key, "[REDACTED]")
    if isinstance(value, dict):
        return {
            _redact_api_key(key, api_key): _redact_api_key(item, api_key)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_api_key(item, api_key) for item in value]
    return value


class ExplorerService:
    """Cache provider responses for five minutes; pace each Blockscout host on its own.

    The PRO gateway and the public instances have separate rate limits, so a slow or rate-limited
    instance must not hold up the gateway's lookups, or the other way round.
    """

    def __init__(self):
        self._cache = TTLCache(maxsize=2048, ttl=300)
        self._blockscout_locks: dict[str, asyncio.Lock] = {}
        self._last_request: dict[str, float] = {}

    async def _request(self, provider: str, url: str, params: dict) -> ExplorerResult:
        cache_key = (
            url,
            tuple(
                sorted((key, value) for key, value in params.items() if key != "apikey")
            ),
        )
        if cache_key in self._cache:
            return self._cache[cache_key]
        host = urlsplit(url).hostname

        async def fetch():
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as session:
                    for attempt in range(3):
                        if provider == "blockscout":
                            delay = 0.21 - (
                                time.monotonic() - self._last_request.get(host, 0.0)
                            )
                            if delay > 0:
                                await asyncio.sleep(delay)
                            self._last_request[host] = time.monotonic()
                        # Redirects are not followed, not even to the same host: the gateway
                        # request carries the API key in its query string, the only redirect
                        # seen (optimism.blockscout.com) changes host, and an unfollowed one
                        # reads as an Unknown HTTP 30x rather than as data from elsewhere.
                        async with session.get(
                            url, params=params, allow_redirects=False
                        ) as response:
                            if (
                                response.status == 429
                                and provider == "blockscout"
                                and attempt < 2
                            ):
                                await asyncio.sleep(2**attempt)
                                continue
                            if response.status != 200:
                                return ExplorerResult(
                                    "unknown",
                                    reason=f"HTTP {response.status}",
                                    provider=provider,
                                )
                            data = await response.json()
                            if not isinstance(data, dict):
                                return ExplorerResult(
                                    "unknown",
                                    reason="Unexpected JSON shape",
                                    provider=provider,
                                )
                            api_key = params.get("apikey")
                            if api_key:
                                data = _redact_api_key(data, api_key)
                            return ExplorerResult("known", data=data, provider=provider)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
                return ExplorerResult(
                    "unknown", reason=type(exc).__name__, provider=provider
                )

        if provider == "blockscout":
            lock = self._blockscout_locks.get(host)
            if lock is None:
                lock = self._blockscout_locks[host] = asyncio.Lock()
            async with lock:
                if cache_key in self._cache:
                    return self._cache[cache_key]
                result = await fetch()
                self._cache[cache_key] = result
        else:
            result = await fetch()
            self._cache[cache_key] = result
        return result

    async def _blockscout(
        self, path: str, chain_id: int, params: dict | None = None
    ) -> ExplorerResult:
        instance = BLOCKSCOUT_INSTANCES.get(chain_id)
        if instance:
            return await self._request(
                "blockscout", f"{instance}/api/v2/{path}", params or {}
            )
        api_key = os.getenv("BLOCKSCOUT_API_KEY", "")
        if not api_key:
            return ExplorerResult(
                "unknown", reason="BLOCKSCOUT_API_KEY is missing", provider="blockscout"
            )
        return await self._request(
            "blockscout",
            f"https://api.blockscout.com/{chain_id}/api/v2/{path}",
            {**(params or {}), "apikey": api_key},
        )

    async def get_verification_status(
        self, address: str, chain_id: int
    ) -> ExplorerResult:
        if not _is_address(address):
            return ExplorerResult("unknown", reason="Invalid address")
        address = address.lower()
        sourcify = await self._request(
            "sourcify",
            f"https://sourcify.dev/server/v2/contract/{chain_id}/{address}",
            {},
        )
        if sourcify.status == "known":
            data = sourcify.data
            matches = ("match", "exact_match")
            if (
                data.get("chainId") == str(chain_id)
                and isinstance(data.get("address"), str)
                and data["address"].lower() == address
                and data.get("match") in matches
                and "creationMatch" in data
                and data["creationMatch"] in (*matches, None)
                and "runtimeMatch" in data
                and data["runtimeMatch"] in (*matches, None)
                and (
                    data["creationMatch"] in matches or data["runtimeMatch"] in matches
                )
            ):
                return ExplorerResult(
                    "verified", data={"match": data["match"]}, provider="sourcify"
                )
            sourcify = ExplorerResult(
                "unknown",
                reason="Missing or mismatched verification evidence",
                provider="sourcify",
            )

        blockscout = await self._blockscout(f"addresses/{address}", chain_id)
        if blockscout.status == "known":
            data = blockscout.data
            if (
                isinstance(data.get("hash"), str)
                and data["hash"].lower() == address
                and data.get("is_contract") is True
                and type(data.get("is_verified")) is bool
            ):
                return ExplorerResult(
                    "verified" if data["is_verified"] else "unverified",
                    provider="blockscout",
                )
            blockscout = ExplorerResult(
                "unknown",
                reason="Missing or mismatched contract verification evidence",
                provider="blockscout",
            )
        return ExplorerResult(
            "unknown",
            reason=f"Sourcify: {sourcify.reason}; Blockscout: {blockscout.reason}",
            provider="sourcify+blockscout",
        )

    async def get_contract_creation_info(
        self, address: str, chain_id: int
    ) -> ExplorerResult:
        if not _is_address(address):
            return ExplorerResult("unknown", reason="Invalid address")
        result = await self._blockscout(f"addresses/{address.lower()}", chain_id)
        if result.status == "unknown":
            return result
        data = result.data
        creator = data.get("creator_address_hash")
        tx_hash = data.get("creation_transaction_hash")
        if (
            isinstance(data.get("hash"), str)
            and data["hash"].lower() == address.lower()
            and data.get("is_contract") is True
            and data.get("creation_status") == "success"
            and _is_address(creator)
            and isinstance(tx_hash, str)
            and re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash)
        ):
            return ExplorerResult(
                "known",
                data={"creator": creator, "tx_hash": tx_hash},
                provider="blockscout",
            )
        return ExplorerResult(
            "unknown",
            reason="Missing or mismatched creation evidence",
            provider="blockscout",
        )

    async def get_first_funder(self, address: str, chain_id: int) -> ExplorerResult:
        """Earliest successful incoming native value across both histories, at most 3 pages each.

        Both histories must end within the cap; a recent subset cannot prove the first funder.
        """
        if not _is_address(address):
            return ExplorerResult("unknown", reason="Invalid address")
        address = address.lower()
        candidates = []
        for history in ("transactions", "internal-transactions"):
            params = {"filter": "to"}
            for page in range(3):
                result = await self._blockscout(
                    f"addresses/{address}/{history}", chain_id, params
                )
                if result.status == "unknown":
                    return result
                data = result.data
                if (
                    not isinstance(data.get("items"), list)
                    or "next_page_params" not in data
                ):
                    return ExplorerResult(
                        "unknown",
                        reason="Unexpected history JSON shape",
                        provider="blockscout",
                    )
                for tx in data["items"]:
                    if not isinstance(tx, dict):
                        return ExplorerResult(
                            "unknown",
                            reason="Unexpected transfer JSON shape",
                            provider="blockscout",
                        )
                    success = (
                        tx.get("status") == "ok"
                        if history == "transactions"
                        else tx.get("success") is True
                    )
                    failed = (
                        tx.get("status") == "error"
                        if history == "transactions"
                        else tx.get("success") is False
                    )
                    if failed:
                        continue
                    recipient = tx.get("to")
                    if history == "internal-transactions":
                        call_type = tx.get("type")
                        if call_type in ("delegatecall", "callcode", "staticcall"):
                            continue
                        if call_type in ("create", "create2"):
                            recipient = tx.get("created_contract")
                        elif call_type not in ("call", "selfdestruct"):
                            return ExplorerResult(
                                "unknown",
                                reason="Missing or unrecognised internal transaction type",
                                provider="blockscout",
                            )
                    sender = tx.get("from")
                    value = tx.get("value")
                    block = tx.get("block_number")
                    position = tx.get(
                        "position" if history == "transactions" else "transaction_index"
                    )
                    index = -1 if history == "transactions" else tx.get("index")
                    if (
                        not success
                        or not isinstance(recipient, dict)
                        or not _is_address(recipient.get("hash"))
                        or not isinstance(sender, dict)
                        or not _is_address(sender.get("hash"))
                        or not isinstance(value, str)
                        or re.fullmatch(r"[0-9]{1,78}", value) is None
                        or int(value) >= 2**256
                        or type(block) is not int
                        or block < 0
                        or type(position) is not int
                        or position < 0
                        or type(index) is not int
                        or (history == "internal-transactions" and index < 0)
                    ):
                        return ExplorerResult(
                            "unknown",
                            reason="Missing transfer evidence",
                            provider="blockscout",
                        )
                    if (
                        recipient["hash"].lower() == address
                        and sender["hash"].lower() != address
                        and int(value) > 0
                    ):
                        candidates.append(
                            (
                                (block, position, index),
                                {"funder": sender["hash"], "value": int(value)},
                            )
                        )
                cursor = data["next_page_params"]
                if cursor is None:
                    break
                if (
                    not isinstance(cursor, dict)
                    or not cursor
                    or any(type(v) not in (str, int) for v in cursor.values())
                ):
                    return ExplorerResult(
                        "unknown",
                        reason="Unexpected pagination cursor",
                        provider="blockscout",
                    )
                if page == 2:
                    return ExplorerResult(
                        "unknown",
                        reason="History page limit reached",
                        provider="blockscout",
                    )
                params = {**cursor, "filter": "to"}
        if not candidates:
            return ExplorerResult(
                "unknown",
                reason="No incoming native funding found",
                provider="blockscout",
            )
        return ExplorerResult(
            "known",
            data=min(candidates, key=lambda item: item[0])[1],
            provider="blockscout",
        )


explorer_service = ExplorerService()
