"""Sourcify v2 verification and Blockscout PRO contract enrichment."""

import asyncio
import os
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import aiohttp
from cachetools import TLRUCache

from core.unknown_ledger import unknown_ledger


# Public Blockscout instances that answer without an API key; other chains go through the keyed
# PRO gateway. optimism.blockscout.com redirects here, and requests do not follow redirects, so the
# map names the final host. scripts/check_blockscout_instances.py notices when an instance moves.
BLOCKSCOUT_INSTANCES = {
    8453: "https://base.blockscout.com",
    10: "https://explorer.optimism.io",
}


# An answer holds for five minutes; a failed lookup is asked again after 30 seconds, so one
# provider blip does not leave a contract Unknown for five minutes.
RESULT_TTL_SECONDS = 300
UNKNOWN_RESULT_TTL_SECONDS = 30


def _result_ttu(key, result, now):
    return now + (UNKNOWN_RESULT_TTL_SECONDS if result.status == "unknown" else RESULT_TTL_SECONDS)


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
    """Cache provider responses (five minutes, a failure 30 seconds); pace each Blockscout host.

    The PRO gateway and the public instances have separate rate limits, so a slow or rate-limited
    instance must not hold up the gateway's lookups, or the other way round.
    """

    def __init__(self):
        self._cache = TLRUCache(maxsize=2048, ttu=_result_ttu)
        self._blockscout_locks: dict[str, asyncio.Lock] = {}
        self._inflight: dict[tuple, asyncio.Task] = {}
        self._last_request: dict[str, float] = {}

    async def _request(
        self, provider: str, url: str, params: dict, chain_id: int
    ) -> ExplorerResult:
        cache_key = (
            url,
            tuple(
                sorted((key, value) for key, value in params.items() if key != "apikey")
            ),
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
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
                            # Sourcify answers 404 with a body naming the address when no
                            # contract is verified there: that body is the evidence.
                            if response.status != 200 and not (
                                provider == "sourcify" and response.status == 404
                            ):
                                return ExplorerResult(
                                    "unknown",
                                    reason=f"HTTP {response.status}",
                                    provider=provider,
                                )
                            # A 404 keeps its reason, so the Unknown ledger counts it as the
                            # provider having nothing for this address.
                            not_found = "HTTP 404" if response.status == 404 else None
                            data = await response.json()
                            if not isinstance(data, dict):
                                return ExplorerResult(
                                    "unknown",
                                    reason=not_found or "Unexpected JSON shape",
                                    provider=provider,
                                )
                            api_key = params.get("apikey")
                            if api_key:
                                data = _redact_api_key(data, api_key)
                            return ExplorerResult("known", data=data, reason=not_found, provider=provider)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
                return ExplorerResult(
                    "unknown", reason=type(exc).__name__, provider=provider
                )

        if provider == "blockscout":
            lock = self._blockscout_locks.get(host)
            if lock is None:
                lock = self._blockscout_locks[host] = asyncio.Lock()
            async with lock:
                cached = self._cache.get(cache_key)
                if cached is not None:
                    return cached
                return self._keep(provider, chain_id, cache_key, await fetch())
        # Concurrent callers for one URL (one address on one chain) share one request, so a hot
        # address has at most one live Sourcify lookup, cached and counted once. A caller that is
        # cancelled leaves it running for the others.
        flight_key = (asyncio.get_running_loop(), cache_key)
        if flight_key not in self._inflight:
            self._inflight[flight_key] = asyncio.create_task(
                self._settle(provider, chain_id, cache_key, flight_key, fetch())
            )
        return await asyncio.shield(self._inflight[flight_key])

    async def _settle(self, provider, chain_id, cache_key, flight_key, lookup) -> ExplorerResult:
        try:
            return self._keep(provider, chain_id, cache_key, await lookup)
        finally:
            self._inflight.pop(flight_key, None)

    def _keep(self, provider, chain_id, cache_key, result) -> ExplorerResult:
        """Cache a fetched reply and count it in the Unknown ledger."""
        self._cache[cache_key] = result
        unknown_ledger.record(
            provider,
            chain_id,
            "unknown" if result.reason == "HTTP 404"
            else "answered" if result.status == "known"
            else "failed",
        )
        return result

    def can_reach_blockscout(self, chain_id: int) -> bool:
        """Whether a Blockscout request can be sent for chain_id: a public instance serves it, or the
        PRO gateway's BLOCKSCOUT_API_KEY is set."""
        return chain_id in BLOCKSCOUT_INSTANCES or bool(os.getenv("BLOCKSCOUT_API_KEY", ""))

    async def _blockscout(
        self, path: str, chain_id: int, params: dict | None = None
    ) -> ExplorerResult:
        if not self.can_reach_blockscout(chain_id):
            return ExplorerResult(
                "unknown", reason="BLOCKSCOUT_API_KEY is missing", provider="blockscout"
            )
        instance = BLOCKSCOUT_INSTANCES.get(chain_id)
        if instance:
            return await self._request(
                "blockscout", f"{instance}/api/v2/{path}", params or {}, chain_id
            )
        return await self._request(
            "blockscout",
            f"https://api.blockscout.com/{chain_id}/api/v2/{path}",
            {**(params or {}), "apikey": os.getenv("BLOCKSCOUT_API_KEY")},
            chain_id,
        )

    async def get_sourcify_verification(
        self, address: str, chain_id: int
    ) -> ExplorerResult:
        """Sourcify's answer: verified, unverified (no match for this address on this chain), or
        unknown when the reply is missing or names another contract."""
        if not _is_address(address):
            return ExplorerResult("unknown", reason="Invalid address")
        address = address.lower()
        sourcify = await self._request(
            "sourcify",
            f"https://sourcify.dev/server/v2/contract/{chain_id}/{address}",
            {},
            chain_id,
        )
        if sourcify.status != "known":
            return sourcify
        data = sourcify.data
        matches = ("match", "exact_match")
        same_contract = (
            data.get("chainId") == str(chain_id)
            and isinstance(data.get("address"), str)
            and data["address"].lower() == address
            and "creationMatch" in data
            and "runtimeMatch" in data
        )
        if (
            same_contract
            and data.get("match") in matches
            and data["creationMatch"] in (*matches, None)
            and data["runtimeMatch"] in (*matches, None)
            and (data["creationMatch"] in matches or data["runtimeMatch"] in matches)
        ):
            return ExplorerResult(
                "verified", data={"match": data["match"]}, provider="sourcify"
            )
        if same_contract and "match" in data and data["match"] is None and (
            data["creationMatch"] is None and data["runtimeMatch"] is None
        ):
            return ExplorerResult("unverified", reason="not verified", provider="sourcify")
        return ExplorerResult(
            "unknown",
            reason="Missing or mismatched verification evidence",
            provider="sourcify",
        )

    async def get_verification_status(
        self, address: str, chain_id: int
    ) -> ExplorerResult:
        """Sourcify and Blockscout together: verified when either says so, unverified only when
        both say not, unknown otherwise."""
        if not _is_address(address):
            return ExplorerResult("unknown", reason="Invalid address")
        address = address.lower()
        sourcify = await self.get_sourcify_verification(address, chain_id)
        if sourcify.status == "verified":
            return sourcify

        blockscout = await self._blockscout(f"addresses/{address}", chain_id)
        if blockscout.status == "known":
            data = blockscout.data
            if (
                isinstance(data.get("hash"), str)
                and data["hash"].lower() == address
                and data.get("is_contract") is True
                and type(data.get("is_verified")) is bool
            ):
                if data["is_verified"] or sourcify.status == "unverified":
                    return ExplorerResult(
                        "verified" if data["is_verified"] else "unverified",
                        provider="blockscout",
                    )
                blockscout = ExplorerResult("unverified", reason="not verified", provider="blockscout")
            else:
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
