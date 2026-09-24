"""Official Robinhood Chain (4663) tokens, and a check for tokens that impersonate them.

Robinhood publishes the tokenised stocks it issues at OFFICIAL_ASSETS_URL. Fetched on 2026-09-24 it
listed 195 assets, each with a tokenSymbol, a tokenName of the form "<Company> • Robinhood Token"
(also the contract's on-chain name) and one chainId 4663 deployment with its contractAddress. The
list does not carry the chain's canonical WETH and USDG, so they are always added.

A token that is not at an official address impersonates an official token when its symbol matches
that token's symbol, or its name the company or full name. Matching ignores case, spacing and
punctuation, folds compatibility forms (NFKC) and Cyrillic and Greek letters drawn like Latin ones,
and reads a 0 as an O. A symbol of three or more characters also matches with one extra leading or
trailing x, w or t (NVDAX, wNVDA); shorter ones must match exactly, so TON, XP and TF are not read as
the official ON, P and F.

A check is official, impostor, none (no match against the complete list) or unknown: without the
list only the canonical tokens can be matched, and without a token's symbol and name only its
address can.
"""

import asyncio
import logging
import re
import time
import unicodedata
from typing import Dict, Optional, Tuple

import aiohttp
from eth_abi import decode
from eth_abi.exceptions import DecodingError

from services.launch_discovery import CHAIN_ID
from services.robinhood_simulation import USDG, WETH

logger = logging.getLogger(__name__)

OFFICIAL_ASSETS_URL = "https://api.robinhood.com/rhj/assets"
# Robinhood lists a stock at a time, so the list is refetched every six hours.
CACHE_TTL_SECONDS = 6 * 3600
# After a failed fetch the list is not asked for again for five minutes, so scans do not each wait on it.
RETRY_SECONDS = 300
TIMEOUT_SECONDS = 10
# Symbol and name as each contract returned them on 2026-09-24.
CANONICAL_TOKENS = {WETH: ("WETH", "WETH"), USDG: ("USDG", "Global Dollar")}
OFFICIAL_NAME_SUFFIX = " \N{BULLET} Robinhood Token"
AFFIXES = "xwt"
MIN_AFFIX_SYMBOL_LENGTH = 3
IMPOSTOR_FLAG = "Impersonates official {} token"
SYMBOL_SELECTOR = "0x95d89b41"
NAME_SELECTOR = "0x06fdde03"

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_NOT_ALPHANUMERIC = re.compile(r"[^a-z0-9]")
# Lower-case Cyrillic and Greek letters drawn like Latin ones, and the digit 0, by code point.
_LOOKALIKES = str.maketrans(
    {
        code: latin
        for latin, codes in {
            "a": (0x0430, 0x03B1),
            "b": (0x0432, 0x03B2),
            "c": (0x0441,),
            "d": (0x0501,),
            "e": (0x0435, 0x03B5),
            "h": (0x043D, 0x03B7),
            "i": (0x0456, 0x03B9),
            "j": (0x0458,),
            "k": (0x043A, 0x03BA),
            "m": (0x043C, 0x03BC),
            "n": (0x03BD,),
            "o": (0x043E, 0x03BF, 0x30),
            "p": (0x0440, 0x03C1),
            "q": (0x051B,),
            "s": (0x0455,),
            "t": (0x0442, 0x03C4),
            "w": (0x051D,),
            "x": (0x0445, 0x03C7),
            "y": (0x0443, 0x03C5, 0x04AF),
            "z": (0x03B6,),
        }.items()
        for code in codes
    }
)


def parse_official_assets(payload) -> Dict[str, Tuple[str, str]]:
    """Map each official 4663 contract address, lower-cased, to its (symbol, name).

    Raises ValueError for a list with any malformed entry or no 4663 token, so a changed or broken
    response never replaces a good list.
    """
    assets = payload.get("assets") if isinstance(payload, dict) else None
    if not isinstance(assets, list):
        raise ValueError("No asset list")
    tokens = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("Malformed asset")
        symbol, name, deployments = (
            asset.get("tokenSymbol"),
            asset.get("tokenName"),
            asset.get("deployments"),
        )
        if not (
            isinstance(symbol, str)
            and symbol
            and isinstance(name, str)
            and name
            and isinstance(deployments, list)
        ):
            raise ValueError("Malformed asset")
        for deployment in deployments:
            address = deployment.get("contractAddress") if isinstance(deployment, dict) else None
            if not isinstance(address, str) or not _ADDRESS.fullmatch(address):
                raise ValueError("Malformed deployment")
            if deployment.get("chainId") == CHAIN_ID:
                tokens[address.lower()] = (symbol, name)
    if not tokens:
        raise ValueError("No Robinhood Chain tokens listed")
    return tokens


def _normalize(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).casefold().translate(_LOOKALIKES)
    return _NOT_ALPHANUMERIC.sub("", folded)


def _symbol_matches(symbol: str, official: str) -> bool:
    """Whether a normalized symbol is an official one, or one with a single affix when that is long enough."""
    if not symbol:
        return False
    if symbol == official:
        return True
    if len(official) < MIN_AFFIX_SYMBOL_LENGTH or len(symbol) != len(official) + 1:
        return False
    return (symbol[0] in AFFIXES and symbol[1:] == official) or (
        symbol[-1] in AFFIXES and symbol[:-1] == official
    )


def _result(
    status: str,
    symbol: Optional[str] = None,
    official_address: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict:
    return {
        "status": status,
        "symbol": symbol,
        "official_address": official_address,
        "reason": reason,
    }


def check_token(
    address: str,
    symbol: Optional[str],
    name: Optional[str],
    listed: Optional[Dict[str, Tuple[str, str]]],
) -> Dict:
    """Classify a 4663 token against the official tokens ``listed`` (None when the list is unavailable).

    ``symbol`` and ``name`` are None when they could not be read. ``symbol`` in the result is the
    official token matched.
    """
    tokens = {**(listed or {}), **CANONICAL_TOKENS}
    address = address.lower()
    if address in tokens:
        return _result("official", tokens[address][0], address)
    observed_symbol = _normalize(symbol) if symbol is not None else ""
    observed_name = _normalize(name) if name is not None else ""
    for official_address, (official_symbol, official_name) in tokens.items():
        official = _normalize(official_symbol)
        names = {
            _normalize(official_name),
            _normalize(official_name.removesuffix(OFFICIAL_NAME_SUFFIX)),
        }
        if _symbol_matches(observed_symbol, official) or (observed_name and observed_name in names):
            return _result("impostor", official_symbol, official_address)
    if listed is None:
        return _result("unknown", reason="Official Robinhood token list unavailable")
    if symbol is None or name is None:
        return _result("unknown", reason="Token symbol or name unavailable")
    return _result("none")


def with_impostor_check(scan: Dict, check: Dict) -> Dict:
    """``scan`` with ``check`` as impostor_check and, for an impostor, its flag first among the critical flags."""
    labelled = {**scan, "impostor_check": check}
    if check["status"] == "impostor":
        labelled["critical_flags"] = [
            IMPOSTOR_FLAG.format(check["symbol"]),
            *scan.get("critical_flags", []),
        ]
    return labelled


def _decode_string(result) -> Optional[str]:
    """The string an eth_call returned, or None for a failed call or a reply that is not an ABI string."""
    if not isinstance(result, str) or not _HEX.fullmatch(result):
        return None
    try:
        return decode(["string"], bytes.fromhex(result[2:]))[0]
    except (DecodingError, ValueError):
        return None


class RobinhoodAssets:
    """Holds the official token list and checks 4663 tokens against it.

    The list is refetched once it is CACHE_TTL_SECONDS old. A failed fetch keeps the last good list;
    until one succeeds, checks that need it report unknown.
    """

    def __init__(self, rpc_url: str):
        self._rpc_url = rpc_url
        self._listed = None
        self._fetched_at = 0.0
        self._retry_at = 0.0
        self._lock = asyncio.Lock()

    async def listed(self) -> Optional[Dict[str, Tuple[str, str]]]:
        """The official tokens by address, or None while no fetch has succeeded."""
        async with self._lock:
            now = time.time()
            if now - self._fetched_at >= CACHE_TTL_SECONDS and now >= self._retry_at:
                try:
                    self._listed = await self._fetch()
                    self._fetched_at = time.time()
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
                    self._retry_at = time.time() + RETRY_SECONDS
                    logger.warning(
                        "Robinhood official token list fetch failed: %s", type(exc).__name__
                    )
        return self._listed

    async def _fetch(self) -> Dict[str, Tuple[str, str]]:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
        ) as session:
            async with session.get(OFFICIAL_ASSETS_URL) as response:
                if response.status != 200:
                    raise ValueError(f"HTTP {response.status}")
                payload = await response.json(content_type=None)
        return parse_official_assets(payload)

    async def check(self, address: str, symbol: Optional[str], name: Optional[str]) -> Dict:
        """Check a token whose symbol and name were already read; None where one could not be."""
        return check_token(address, symbol, name, await self.listed())

    async def check_onchain(self, address: str) -> Dict:
        """Read the token's symbol() and name() in one batched JSON-RPC request, then check it."""
        symbol, name = await self._read_metadata(address)
        return await self.check(address, symbol, name)

    async def _read_metadata(self, address: str) -> Tuple[Optional[str], Optional[str]]:
        body = [
            {
                "jsonrpc": "2.0",
                "id": index,
                "method": "eth_call",
                "params": [{"to": address, "data": selector}, "latest"],
            }
            for index, selector in enumerate((SYMBOL_SELECTOR, NAME_SELECTOR))
        ]
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
            ) as session:
                async with session.post(self._rpc_url, json=body) as response:
                    status = response.status
                    rows = await response.json(content_type=None) if status == 200 else None
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            logger.warning("Robinhood token metadata read failed: %s", type(exc).__name__)
            return None, None
        if not isinstance(rows, list):
            logger.warning(
                "Robinhood token metadata read failed: unexpected reply (HTTP %d)", status
            )
            return None, None
        results = {row.get("id"): row.get("result") for row in rows if isinstance(row, dict)}
        return _decode_string(results.get(0)), _decode_string(results.get(1))
