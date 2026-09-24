"""Official Robinhood Chain (4663) tokens, and a check for tokens that pass themselves off as them.

Robinhood publishes the tokenised stocks it issues at OFFICIAL_ASSETS_URL. Fetched on 2026-09-24 it
listed 195 assets, each with a tokenSymbol, a tokenName of the form "<Company> • Robinhood Token"
(also the contract's on-chain name) and one chainId 4663 deployment with its contractAddress. The
list does not carry the chain's canonical WETH and USDG, so they are always added.

A token at an official address is official. Any other token's symbol and name are compared with each
official token's ticker and company name. A company name drops a trailing Inc., Corp., Corporation,
Holdings, Class A, Common Stock, ETF or Trust, and a token's name may add token, stock, shares,
robinhood or rh to it ("Tesla Stock", "NVIDIA • Robinhood Token"). The symbol points at an official
token when it is the ticker; the ticker with one leading or trailing x, w or t or a separated suffix
(NVDAX, wNVDA, TSLA.d); the ticker or company with Robinhood's name or its ticker HOOD added
(TESLAHOOD); or the company name. The name points at it when it is the company name, and backs up a
symbol that points at it when its initials spell the ticker (AMD, "Advanced Micro Dog"). A ticker of
one or two characters takes no affix and never points on its own.

- impostor: the symbol and the name point at the same official token; or the symbol or name claims
  Robinhood besides the company; or a pointer only matches once look-alike characters are folded.
- collision: a pointer on its own, such as the same ticker under another name; or another issuer's
  tokenised stock, marked by its convention (xStock, dShares, Backed, Dinari, Wrapped; TSLA.d, wTSLA,
  or TSLAx named an xStock), which is reported as a third-party token.
- none: nothing points at an official token on the complete list.
- unknown: without the list only the canonical tokens can be matched, and without the token's
  symbol and name only its address.

Folding reads accents, compatibility forms and Cyrillic and Greek letters drawn like Latin ones as
those letters, then treats characters that pass for each other within a case as one: a lowercase l,
an uppercase I, 1 and |; an uppercase O and 0; an uppercase S and 5; an uppercase B and 8. An
uppercase L is never folded. An official ticker or name is compared in the case of the text it is
held against: upper or lower case when all of its letters are, else as written.

When the symbol and the name point at different official tokens the stronger match is reported, the
symbol's first between equals, and the other one as ``also``.
"""

import asyncio
import json
import logging
import re
import time
import unicodedata
from typing import Dict, List, Optional, Tuple

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
# The list was 163 KB on 2026-09-24, and a symbol() and name() reply is two short ABI strings.
MAX_LIST_BYTES = 1_000_000
MAX_RPC_REPLY_BYTES = 65_536
# A new list this much smaller than the last good one is taken to be truncated.
MIN_LIST_FRACTION = 0.8
# Symbol and name as each contract returned them on 2026-09-24.
CANONICAL_TOKENS = {WETH: ("WETH", "WETH"), USDG: ("USDG", "Global Dollar")}
AFFIXES = "xwt"
MIN_TICKER_LENGTH = 3
CORPORATE_SUFFIXES = (
    ("common", "stock"),
    ("class", "a"),
    ("inc",),
    ("corp",),
    ("corporation",),
    ("holdings",),
    ("etf",),
    ("trust",),
)
TOKEN_WORDS = frozenset({"token", "stock", "shares", "robinhood", "rh"})
# Words other issuers of tokenised stocks name theirs with ("Tesla xStock", "Tesla, Inc. dShares").
THIRD_PARTY_MARKERS = frozenset({"xstock", "dshares", "backed", "dinari", "wrapped"})
# Robinhood's name and its own stock ticker, as a symbol adds them to a ticker or company.
ROBINHOOD_MARKERS = ("robinhood", "hood", "rh")
IMPOSTOR_FLAG = "Impersonates official {} token; official contract {}"
SYMBOL_SELECTOR = "0x95d89b41"
NAME_SELECTOR = "0x06fdde03"

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_NOT_ALPHANUMERIC = re.compile(r"[^a-z0-9]+")
# A word: letters and digits of any script, and the | that can stand for an I.
_WORD = re.compile(r"(?:[^\W_]|\|)+")
# Cyrillic and Greek letters drawn like Latin ones, each mapped in its own case, by code point.
_LOOKALIKE_LETTERS = str.maketrans(
    {
        code: latin
        for latin, codes in {
            "A": (0x0410, 0x0391),
            "B": (0x0412, 0x0392),
            "C": (0x0421,),
            "E": (0x0415, 0x0395),
            "H": (0x041D, 0x0397),
            "I": (0x0406, 0x0399),
            "J": (0x0408,),
            "K": (0x041A, 0x039A),
            "M": (0x041C, 0x039C),
            "N": (0x039D,),
            "O": (0x041E, 0x039F),
            "P": (0x0420, 0x03A1),
            "S": (0x0405,),
            "T": (0x0422, 0x03A4),
            "X": (0x0425, 0x03A7),
            "Y": (0x0423, 0x03A5),
            "Z": (0x0396,),
            "a": (0x0430,),
            "c": (0x0441,),
            "d": (0x0501,),
            "e": (0x0435,),
            "i": (0x0456,),
            "j": (0x0458,),
            "o": (0x043E, 0x03BF),
            "p": (0x0440, 0x03C1),
            "q": (0x051B,),
            "s": (0x0455,),
            "v": (0x03BD,),
            "w": (0x051D,),
            "x": (0x0445, 0x03C7),
            "y": (0x0443, 0x04AF),
        }.items()
        for code in codes
    }
)
# Characters that pass for each other within a case, each class written as one character.
_CONFUSABLES = str.maketrans({"l": "1", "I": "1", "|": "1", "O": "0", "S": "5", "B": "8"})


def parse_official_assets(payload) -> Dict[str, Tuple[str, str]]:
    """Map each official 4663 contract address, lower-cased, to its (symbol, name).

    Malformed entries are skipped and counted. Raises ValueError when there is no asset list or no
    4663 token in it.
    """
    assets = payload.get("assets") if isinstance(payload, dict) else None
    if not isinstance(assets, list):
        raise ValueError("No asset list")
    tokens, skipped = {}, 0
    for asset in assets:
        if not isinstance(asset, dict):
            skipped += 1
            continue
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
            skipped += 1
            continue
        for deployment in deployments:
            address = deployment.get("contractAddress") if isinstance(deployment, dict) else None
            if not isinstance(address, str) or not _ADDRESS.fullmatch(address):
                skipped += 1
            elif deployment.get("chainId") == CHAIN_ID:
                tokens[address.lower()] = (symbol, name)
    if skipped:
        logger.warning("Robinhood official token list: skipped %d malformed entries", skipped)
    if not tokens:
        raise ValueError("No Robinhood Chain tokens listed")
    return tokens


def _plain(word: str) -> str:
    """A word as it plainly reads: lower-case Latin letters and digits."""
    return _NOT_ALPHANUMERIC.sub("", word.casefold())


def _folded(words: List[str]) -> str:
    """Words joined, with every look-alike character read as the one it passes for."""
    decomposed = unicodedata.normalize("NFD", unicodedata.normalize("NFKC", "".join(words)))
    unmarked = "".join(char for char in decomposed if not unicodedata.combining(char))
    return _NOT_ALPHANUMERIC.sub(
        "", unmarked.translate(_LOOKALIKE_LETTERS).translate(_CONFUSABLES).casefold()
    )


def _in_case_of(words: List[str], text: str) -> List[str]:
    """``words`` in upper or lower case when all of ``text``'s letters are, else as written."""
    if text.isupper():
        return [word.upper() for word in words]
    if text.islower():
        return [word.lower() for word in words]
    return words


def _company_words(words: List[str]) -> List[str]:
    """A name's words about its company: without legal suffixes, token words or other issuers' markers."""
    ignored = TOKEN_WORDS | THIRD_PARTY_MARKERS
    words = list(words)
    while True:
        plain = [_plain(word) for word in words]
        suffix = next(
            (
                suffix
                for suffix in CORPORATE_SUFFIXES
                if len(words) > len(suffix) and tuple(plain[-len(suffix) :]) == suffix
            ),
            None,
        )
        if suffix is not None:
            del words[-len(suffix) :]
        elif len(words) > 1 and plain[-1] in ignored:
            words.pop()
        else:
            return [word for word, plain_word in zip(words, plain) if plain_word not in ignored]


def _symbol_points(words: List[str], ticker: str, company: str) -> Optional[str]:
    """How a symbol's plain words name an official token: "ticker", "company", "robinhood", "affix" or None."""
    joined = "".join(words)
    if not joined:
        return None
    if joined == ticker:
        return "ticker"
    if joined == company:
        return "company"
    for base in (ticker, company):
        if len(base) >= MIN_TICKER_LENGTH and any(
            joined in (base + mark, mark + base) for mark in ROBINHOOD_MARKERS
        ):
            return "robinhood"
    if len(ticker) < MIN_TICKER_LENGTH:
        return None
    if len(joined) == len(ticker) + 1 and (
        (joined[0] in AFFIXES and joined[1:] == ticker)
        or (joined[-1] in AFFIXES and joined[:-1] == ticker)
    ):
        return "affix"
    return "affix" if len(words) > 1 and ticker in (words[0], words[-1]) else None


def _read_symbol(text: str) -> Dict:
    """A symbol as written, its words, and their plain forms."""
    words = _WORD.findall(text)
    return {"text": text, "words": words, "plain": [_plain(word) for word in words]}


def _read_name(text: str) -> Dict:
    """A name as written, its company words, their plain form and initials, and the markers it carries."""
    plain = {_plain(word) for word in _WORD.findall(text)}
    words = _company_words(_WORD.findall(text))
    return {
        "text": text,
        "words": words,
        "plain": "".join(_plain(word) for word in words),
        "initials": "".join(_plain(word)[:1] for word in words),
        "markers": plain & THIRD_PARTY_MARKERS,
        "robinhood": "robinhood" in plain,
    }


def _classify(
    symbol: Optional[Dict], name: Optional[Dict], official_symbol: str, official_name: str
):
    """(status, matched_by, third_party) of a token against one official token, or None when nothing points at it."""
    ticker_words = _WORD.findall(official_symbol)
    company_words = _company_words(_WORD.findall(official_name))
    ticker = "".join(_plain(word) for word in ticker_words)
    company = "".join(_plain(word) for word in company_words)
    by_symbol = None
    if symbol is not None:
        by_symbol = _symbol_points(symbol["plain"], ticker, company)
        folded = _folded(symbol["words"])
        if (
            by_symbol is None
            and folded
            and folded
            in (
                _folded(_in_case_of(ticker_words, symbol["text"])),
                _folded(_in_case_of(company_words, symbol["text"])),
            )
        ):
            by_symbol = "look-alike"
    by_name = None
    if name is not None and company:
        folded = _folded(name["words"])
        if name["plain"] == company:
            by_name = "company"
        elif folded and folded == _folded(_in_case_of(company_words, name["text"])):
            by_name = "look-alike"
    spelled = name is not None and len(ticker) >= MIN_TICKER_LENGTH and name["initials"] == ticker
    # A short ticker is too common to point on its own.
    symbol_alone = by_symbol is not None and not (
        len(ticker) < MIN_TICKER_LENGTH and by_symbol in ("ticker", "look-alike")
    )
    agree = by_symbol is not None and (by_name is not None or spelled)
    if not (symbol_alone or by_name or agree):
        return None
    matched_by = "symbol and name" if agree else "symbol" if symbol_alone else "name"
    look_alike = (symbol_alone and by_symbol == "look-alike") or by_name == "look-alike"
    claims_robinhood = by_symbol == "robinhood" or (by_name is not None and name["robinhood"])
    markers = name["markers"] if name is not None else set()
    # Another issuer's convention: a marker in the name, or wTSLA, TSLA.d, or TSLAx named an xStock.
    third_party = bool(markers) or (
        by_symbol is not None
        and (
            "".join(symbol["plain"]) == "w" + ticker
            or symbol["plain"] == [ticker, "d"]
            or ("xstock" in markers and "".join(symbol["plain"]) == ticker + "x")
        )
    )
    if look_alike or claims_robinhood:
        return "impostor", matched_by, False
    if third_party:
        return "collision", matched_by, True
    return ("impostor" if agree else "collision"), matched_by, False


def _result(
    status: str,
    symbol: Optional[str] = None,
    official_address: Optional[str] = None,
    matched_by: Optional[str] = None,
    third_party: bool = False,
    also: Optional[Dict] = None,
    reason: Optional[str] = None,
    list_size: Optional[int] = None,
) -> Dict:
    return {
        "status": status,
        "symbol": symbol,
        "official_address": official_address,
        "matched_by": matched_by,
        "third_party": third_party,
        "also": also,
        "reason": reason,
        "list_size": list_size,
    }


def check_token(
    address: str,
    symbol: Optional[str],
    name: Optional[str],
    listed: Optional[Dict[str, Tuple[str, str]]],
) -> Dict:
    """Classify a 4663 token against the official tokens ``listed`` (None when the list is unavailable).

    ``symbol`` and ``name`` are None when they could not be read. The result's ``symbol`` is the
    official token matched, ``third_party`` marks a collision in another issuer's convention, and
    ``list_size`` is the number of official tokens it was checked against.
    """
    tokens = {**(listed or {}), **CANONICAL_TOKENS}
    list_size = len(listed) if listed is not None else None
    address = address.lower()
    if address in tokens:
        return _result("official", tokens[address][0], address, list_size=list_size)
    read_symbol = _read_symbol(symbol) if symbol is not None else None
    read_name = _read_name(name) if name is not None else None
    matches = []
    for official_address, (official_symbol, official_name) in tokens.items():
        found = _classify(read_symbol, read_name, official_symbol, official_name)
        if found is not None:
            matches.append((found, official_symbol, official_address))
    if matches:
        # The strongest match first, and the one the symbol names first between equals.
        matches.sort(
            key=lambda match: (match[0][0] == "impostor", "symbol" in match[0][1]), reverse=True
        )
        ((status, matched_by, third_party), official_symbol, official_address), *others = matches
        also = {"symbol": others[0][1], "official_address": others[0][2]} if others else None
        return _result(
            status,
            official_symbol,
            official_address,
            matched_by,
            third_party,
            also,
            list_size=list_size,
        )
    if listed is None:
        return _result("unknown", reason="Official Robinhood token list unavailable")
    if symbol is None or name is None:
        return _result("unknown", reason="Token symbol or name unavailable", list_size=list_size)
    return _result("none", list_size=list_size)


def with_impostor_check(scan: Dict, check: Dict) -> Dict:
    """``scan`` with ``check`` as impostor_check and, for an impostor, its flag first among the critical flags."""
    labelled = {**scan, "impostor_check": check}
    if check["status"] == "impostor":
        labelled["critical_flags"] = [
            IMPOSTOR_FLAG.format(check["symbol"], check["official_address"]),
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


async def _read_capped(response, limit: int) -> bytes:
    """A response body of at most ``limit`` bytes; ValueError for a longer one."""
    body = b""
    while len(body) <= limit:
        chunk = await response.content.read(limit + 1 - len(body))
        if not chunk:
            return body
        body += chunk
    raise ValueError("Response too large")


class RobinhoodAssets:
    """Holds the official token list and checks 4663 tokens against it.

    The list is refetched once it is CACHE_TTL_SECONDS old. A failed fetch, or a list under
    MIN_LIST_FRACTION of the last good one, keeps the last good list; until one succeeds, checks
    that need it report unknown.
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
                    listed = await self._fetch()
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
                    self._retry_at = time.time() + RETRY_SECONDS
                    logger.warning(
                        "Robinhood official token list fetch failed: %s", type(exc).__name__
                    )
                else:
                    if self._listed is not None and len(listed) < MIN_LIST_FRACTION * len(
                        self._listed
                    ):
                        self._retry_at = time.time() + RETRY_SECONDS
                        logger.warning(
                            "Robinhood official token list shrank from %d to %d tokens; keeping the last good list",
                            len(self._listed),
                            len(listed),
                        )
                    else:
                        self._listed, self._fetched_at = listed, time.time()
        return self._listed

    async def _fetch(self) -> Dict[str, Tuple[str, str]]:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
        ) as session:
            async with session.get(OFFICIAL_ASSETS_URL) as response:
                if response.status != 200:
                    raise ValueError(f"HTTP {response.status}")
                body = await _read_capped(response, MAX_LIST_BYTES)
        return parse_official_assets(json.loads(body))

    async def check(self, address: str, symbol: Optional[str], name: Optional[str]) -> Dict:
        """Check a token whose symbol and name were already read; None where one could not be."""
        return check_token(address, symbol, name, await self.listed())

    async def check_onchain(self, address: str, timeout: float) -> Dict:
        """Read the token's symbol() and name() in one batched JSON-RPC request, then check it.

        A check still running after ``timeout`` seconds is unknown.
        """
        try:
            async with asyncio.timeout(timeout):
                symbol, name = await self._read_metadata(address)
                return await self.check(address, symbol, name)
        except TimeoutError:
            logger.warning("Robinhood official token check timed out")
            return _result("unknown", reason="Official token check timed out")

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
                    rows = (
                        json.loads(await _read_capped(response, MAX_RPC_REPLY_BYTES))
                        if status == 200
                        else None
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            logger.warning("Robinhood token metadata read failed: %s", type(exc).__name__)
            return None, None
        if not isinstance(rows, list):
            logger.warning(
                "Robinhood token metadata read failed: unexpected reply (HTTP %d)", status
            )
            return None, None
        # JSON true is not an id: in a dict it would stand in for 1.
        results = {
            row["id"]: row.get("result")
            for row in rows
            if isinstance(row, dict) and type(row.get("id")) is int
        }
        return _decode_string(results.get(0)), _decode_string(results.get(1))
