import time
import logging
import aiohttp
from urllib.parse import quote, urlparse

logger = logging.getLogger(__name__)

GOPLUS_PHISHING_URL = "https://api.gopluslabs.io/api/v1/phishing_site"
CACHE_TTL = 3600  # Cache results for 1 hour per domain


class PhishingService:
    """Checks URLs against the GoPlus phishing site detection API.

    Results are cached by domain for CACHE_TTL seconds to avoid
    redundant API calls when a user navigates across pages on the same site.
    """

    def __init__(self):
        # domain -> (result_dict, expires_at)
        self._cache: dict[str, tuple[dict, float]] = {}

    async def check_url(self, url: str) -> dict:
        """Return phishing verdict for a URL.

        Returns:
            {
                "is_phishing": bool,
                "confidence": "high" | "low",
                "source": "goplus" | None,
                "cached": bool,
            }
        """
        defaults = {
            "is_phishing": False,
            "confidence": "low",
            "source": None,
            "cached": False,
        }

        try:
            domain = urlparse(url).netloc.lower()
            if not domain:
                return defaults

            # Strip port for cache key
            cache_key = domain.split(":")[0]

            # Check in-memory cache
            if cache_key in self._cache:
                result, expires_at = self._cache[cache_key]
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
                        logger.warning(
                            "GoPlus phishing API returned %s for %s", resp.status, domain
                        )
                        return defaults
                    data = await resp.json()

            result_data = data.get("result", {})
            # GoPlus returns "phishing_site": 1 (integer) or "is_phishing_site": "1" (string)
            # Handle both field names and both types defensively.
            raw = result_data.get("phishing_site", result_data.get("is_phishing_site", 0))
            is_phishing = int(raw) == 1

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
            logger.warning("GoPlus phishing check network error for %s: %s", url, e)
            return defaults
        except Exception as e:
            logger.error("Phishing check failed for %s: %s", url, e)
            return defaults
