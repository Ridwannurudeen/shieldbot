import time
import logging
import aiohttp
from cachetools import TTLCache
from urllib.parse import quote, urlparse

from core.unknown_ledger import unknown_ledger

logger = logging.getLogger(__name__)

GOPLUS_PHISHING_URL = "https://api.gopluslabs.io/api/v1/phishing_site"
CACHE_TTL = 3600  # Cache results for 1 hour per domain
NO_VERDICT_TTL = 45  # During a GoPlus outage, ask about each domain at most this often
CACHE_MAXSIZE = 10_000  # Domains held at once; when full, expired then least recently used go first


class PhishingService:
    """Checks URLs against the GoPlus phishing site detection API.

    Results are cached by domain for CACHE_TTL seconds to avoid
    redundant API calls when a user navigates across pages on the same site.
    """

    def __init__(self):
        # domain -> (result_dict, expires_at); bounded so an outage cannot grow it without limit
        self._cache = TTLCache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)

    async def check_url(self, url: str) -> dict:
        """Return phishing verdict for a URL.

        Returns:
            {
                "is_phishing": bool | None,
                "confidence": "high" | "low" | None,
                "source": "goplus" | "test" | None,
                "cached": bool,
                "reason": str,  # only with is_phishing None
            }

        is_phishing None means no verdict: GoPlus could not be asked or gave no answer. It is
        held for NO_VERDICT_TTL seconds per domain, not CACHE_TTL, and then asked again.
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
