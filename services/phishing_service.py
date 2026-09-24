import asyncio
import json
import time
import logging
import aiohttp
import idna
from cachetools import TTLCache
from typing import Optional
from urllib.parse import quote, urlparse

from core.unknown_ledger import unknown_ledger

logger = logging.getLogger(__name__)

GOPLUS_PHISHING_URL = "https://api.gopluslabs.io/api/v1/phishing_site"
CACHE_TTL = 3600  # Cache results for 1 hour per domain
NO_VERDICT_TTL = 45  # During a GoPlus outage, ask about each domain at most this often
CACHE_MAXSIZE = 10_000  # Domains held at once; when full, expired then least recently used go first
# MetaMask's open phishing list (eth-phishing-detect, config version 2; about 100,000 domains on 2026-09-24).
METAMASK_CONFIG_URL = "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json"
METAMASK_REFRESH_SECONDS = 3600
# After a failed fetch the last good copy stays in use, and the list is asked for again this much sooner.
METAMASK_RETRY_SECONDS = 300
METAMASK_TIMEOUT_SECONDS = 60
# The list was about 2.8 MB on 2026-09-24; a body past this is refused rather than parsed.
METAMASK_MAX_BYTES = 64 * 1024 * 1024


def parse_metamask_config(payload) -> tuple:
    """(blocked domains, allowed domains, fuzzy targets, tolerance) from an eth-phishing-detect version 2 config.

    Raises ValueError for anything else, so a changed or broken response never replaces a good list.
    Entries with a path (sites.google.com/view/...) block a page, not a host; checks are cached per host,
    so they are left out.
    """
    if not isinstance(payload, dict) or payload.get("version") != 2:
        raise ValueError("Not a version 2 config")
    tolerance = payload.get("tolerance")
    if type(tolerance) is not int or tolerance < 0:
        raise ValueError("Malformed tolerance")
    lists = {}
    for name in ("blacklist", "whitelist", "fuzzylist"):
        entries = payload.get(name)
        if not isinstance(entries, list) or not all(isinstance(entry, str) for entry in entries):
            raise ValueError(f"Malformed {name}")
        lists[name] = [entry.lower().rstrip(".") for entry in entries if entry and "/" not in entry]
    if not lists["blacklist"]:
        raise ValueError("Empty blacklist")
    fuzzy = tuple((domain, _fuzzy_form(domain)) for domain in lists["fuzzylist"])
    return frozenset(lists["blacklist"]), frozenset(lists["whitelist"]), fuzzy, tolerance


def _parse_metamask_body(body: bytes) -> tuple:
    return parse_metamask_config(json.loads(body))


def _ascii_host(host: str) -> str:
    """A host in the ASCII (punycode) form the list uses, or as given when it is not a valid IDNA name."""
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError:
        return host


def _fuzzy_form(domain: str) -> str:
    """A domain without its top-level label, the form MetaMask's fuzzy match compares: metamask.io -> metamask."""
    return ".".join(domain.split(".")[:-1])


def _within_edits(source: str, target: str, limit: int) -> bool:
    """Whether the Levenshtein distance between two strings is at most `limit`."""
    if abs(len(source) - len(target)) > limit:
        return False
    previous = list(range(len(target) + 1))
    for i, left in enumerate(source, 1):
        current = [i]
        for j, right in enumerate(target, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (left != right)))
        previous = current
    return previous[-1] <= limit


class MetaMaskPhishingList:
    """MetaMask's eth-phishing-detect list, matched against a host the way its detector does.

    A host on the whitelist, or under a whitelisted domain, never matches. Otherwise a host on the
    blacklist, or under a blacklisted domain, is a "blocklist" match; and when the tolerance is above
    zero, a host whose name without its top-level label (and a leading "www.") is within that many edits
    of a fuzzylist domain's is a "fuzzy" match: a lookalike of that domain.
    """

    def __init__(self):
        self._lists = None  # the last good copy, from parse_metamask_config

    def match(self, host: str) -> Optional[dict]:
        """{"type": "blocklist" | "fuzzy", "domain": listed domain} when the list flags the host, else None."""
        if self._lists is None or not host:
            return None
        blocked, allowed, fuzzy, tolerance = self._lists
        host = _ascii_host(host.lower().rstrip("."))
        labels = host.split(".")
        suffixes = [".".join(labels[index:]) for index in range(len(labels))]
        if any(suffix in allowed for suffix in suffixes):
            return None
        for suffix in suffixes:
            if suffix in blocked:
                return {"type": "blocklist", "domain": suffix}
        if tolerance > 0:
            form = _fuzzy_form(host)
            form = form[4:] if form.startswith("www.") else form
            for domain, target in fuzzy:
                if _within_edits(form, target, tolerance):
                    return {"type": "fuzzy", "domain": domain}
        return None

    async def refresh(self) -> bool:
        """Fetch the list and replace the last good copy; on any failure keep that copy and return False.

        A body larger than METAMASK_MAX_BYTES is refused. The JSON is parsed in a worker thread, so a large
        list does not hold up the event loop.
        """
        kept = "keeping the last good copy" if self._lists is not None else "no copy loaded yet"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    METAMASK_CONFIG_URL, timeout=aiohttp.ClientTimeout(total=METAMASK_TIMEOUT_SECONDS)
                ) as resp:
                    if resp.status != 200:
                        logger.warning("MetaMask phishing list not refreshed (HTTP %d); %s", resp.status, kept)
                        return False
                    body = bytearray()
                    async for chunk in resp.content.iter_chunked(64 * 1024):
                        body.extend(chunk)
                        if len(body) > METAMASK_MAX_BYTES:
                            logger.error(
                                "MetaMask phishing list not refreshed (larger than %d bytes); %s",
                                METAMASK_MAX_BYTES, kept,
                            )
                            return False
            lists = await asyncio.to_thread(_parse_metamask_body, bytes(body))
        except Exception as e:
            logger.warning("MetaMask phishing list not refreshed (%s); %s", type(e).__name__, kept)
            return False
        self._lists = lists
        logger.info("MetaMask phishing list loaded: %d blocked domains", len(lists[0]))
        return True


class PhishingService:
    """Checks URLs against MetaMask's open phishing list and the GoPlus phishing site detection API.

    GoPlus results are cached by domain for CACHE_TTL seconds to avoid
    redundant API calls when a user navigates across pages on the same site.
    """

    def __init__(self):
        # domain -> (result_dict, expires_at); bounded so an outage cannot grow it without limit
        self._cache = TTLCache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)
        self.metamask = MetaMaskPhishingList()
        self._refresh_task = None

    def start(self):
        """Keep MetaMask's list in memory: fetched now, then hourly, and again sooner after a failed fetch."""
        if self._refresh_task is None:
            self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def stop(self):
        """Cancel the refresh loop and wait for it to finish."""
        task, self._refresh_task = self._refresh_task, None
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _refresh_loop(self):
        while True:
            loaded = await self.metamask.refresh()
            await asyncio.sleep(METAMASK_REFRESH_SECONDS if loaded else METAMASK_RETRY_SECONDS)

    async def check_url(self, url: str) -> dict:
        """Return phishing verdict for a URL.

        Returns:
            {
                "is_phishing": bool | None,
                "confidence": "high" | "low" | None,
                "source": "metamask" | "goplus" | "test" | None,
                "cached": bool,
                "match": {"type": "blocklist" | "fuzzy", "domain": str},  # only with source "metamask"
                "reason": str,  # only with is_phishing None
            }

        A host MetaMask's list flags is phishing, source "metamask", without asking GoPlus. Otherwise
        GoPlus decides. is_phishing None means no verdict: MetaMask's list does not flag the host and
        GoPlus could not be asked or gave no answer. It is held for NO_VERDICT_TTL seconds per domain,
        not CACHE_TTL, and then asked again.
        """
        cache_key = None
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if not domain:
                return self._no_verdict(None, "URL has no host")

            # Test trigger — only active when SHIELDBOT_TEST_MODE=1 env var is set.
            # Prevents griefing attacks via shared URLs with the test parameter.
            import os
            from urllib.parse import parse_qs
            if os.getenv("SHIELDBOT_TEST_MODE") and "_shieldbot_phishing_test" in parse_qs(parsed.query):
                return {
                    "is_phishing": True,
                    "confidence": "high",
                    "source": "test",
                    "cached": False,
                }

            # Strip port for cache key
            cache_key = domain.split(":")[0]

            listed = self.metamask.match(parsed.hostname)
            if listed is not None:
                # Not cached, so it is checked again on every page load: log quietly.
                logger.info("Phishing site on MetaMask's list: %s", parsed.hostname)
                return {
                    "is_phishing": True,
                    "confidence": "high",
                    "source": "metamask",
                    "cached": False,
                    "match": listed,
                }

            # Check in-memory cache
            cached = self._cache.get(cache_key)
            if cached is not None:
                result, expires_at = cached
                if time.time() < expires_at:
                    return {**result, "cached": True}

            # Call GoPlus phishing API
            encoded_url = quote(url, safe="")
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{GOPLUS_PHISHING_URL}?url={encoded_url}",
                    timeout=aiohttp.ClientTimeout(total=5),
                    headers={"Accept": "application/json"},
                ) as resp:
                    if resp.status != 200:
                        unknown_ledger.record("goplus_phishing", None, "failed")
                        logger.warning(
                            "GoPlus phishing API returned %s for %s", resp.status, domain
                        )
                        return self._no_verdict(cache_key, f"GoPlus HTTP {resp.status}")
                    data = await resp.json()

            result_data = data.get("result") if isinstance(data, dict) and data.get("code") == 1 else None
            # GoPlus returns "phishing_site": 1 (integer) or "is_phishing_site": "1" (string)
            # Handle both field names and both types defensively.
            raw = None
            if isinstance(result_data, dict):
                raw = result_data.get("phishing_site", result_data.get("is_phishing_site"))
            if raw not in (0, 1, "0", "1"):
                unknown_ledger.record("goplus_phishing", None, "unknown")
                return self._no_verdict(cache_key, "GoPlus returned no phishing verdict")
            is_phishing = int(raw) == 1
            unknown_ledger.record("goplus_phishing", None, "answered")

            result = {
                "is_phishing": is_phishing,
                "confidence": "high" if is_phishing else "low",
                "source": "goplus",
                "cached": False,
            }

            self._cache[cache_key] = (result, time.time() + CACHE_TTL)

            if is_phishing:
                logger.warning("Phishing site detected: %s", domain)

            return result

        except aiohttp.ClientError as e:
            unknown_ledger.record("goplus_phishing", None, "failed")
            logger.warning("GoPlus phishing check network error for %s: %s", url, type(e).__name__)
            return self._no_verdict(cache_key, f"GoPlus request failed ({type(e).__name__})")
        except Exception as e:
            unknown_ledger.record("goplus_phishing", None, "failed")
            logger.error("Phishing check failed for %s: %s", url, type(e).__name__)
            return self._no_verdict(cache_key, f"Phishing check failed ({type(e).__name__})")

    def _no_verdict(self, cache_key, reason: str) -> dict:
        """A no-verdict answer, held briefly for its domain so an outage is not re-asked per page."""
        result = {
            "is_phishing": None,
            "confidence": None,
            "source": None,
            "cached": False,
            "reason": reason,
        }
        if cache_key:
            self._cache[cache_key] = (result, time.time() + NO_VERDICT_TTL)
        return result
