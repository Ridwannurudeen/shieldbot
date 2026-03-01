import time
import logging
import aiohttp

logger = logging.getLogger(__name__)

CACHE_TTL = 3600  # 1 hour

# Token Sniffer uses numeric chain IDs matching EVM standard
SUPPORTED_CHAIN_IDS = {56, 1, 137, 42161, 8453, 10, 204}


class TokenSnifferService:
    """Fetches Token Sniffer Smell Test scores for unverified contracts.

    Only called as a fallback when a contract has no verified source code —
    GoPlus and Etherscan cannot analyze unverified bytecode, so Token Sniffer
    fills the gap by running its own static analysis pipeline.

    Score: 0–100 where 100 = safest, 0 = most dangerous (inverted vs ShieldScore).
    """

    def __init__(self, api_key: str = ""):
        self._api_key = api_key
        self._cache: dict[tuple, tuple[dict, float]] = {}
        self._session: aiohttp.ClientSession | None = None

    def is_enabled(self) -> bool:
        return bool(self._api_key)

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )
        return self._session

    async def fetch(self, address: str, chain_id: int = 56) -> dict:
        """Return Token Sniffer data for an address.

        Returns:
            {
                "score": int,           # 0-100 (100 = safe), None if unavailable
                "is_flagged": bool,
                "cached": bool,
            }
            Empty dict if service is disabled or chain not supported.
        """
        if not self.is_enabled():
            return {}

        if chain_id not in SUPPORTED_CHAIN_IDS:
            return {}

        cache_key = (address.lower(), chain_id)
        now = time.time()
        if cache_key in self._cache:
            data, expires_at = self._cache[cache_key]
            if now < expires_at:
                return {**data, "cached": True}

        url = f"https://tokensniffer.com/api/v2/tokens/{chain_id}/{address}"
        params = {"apikey": self._api_key, "include_metrics": "1"}

        try:
            session = await self._get_session()
            async with session.get(url, params=params) as resp:
                if resp.status == 429:
                    logger.warning("Token Sniffer rate limit hit for %s", address)
                    return {}
                if resp.status != 200:
                    logger.warning("Token Sniffer returned %s for %s", resp.status, address)
                    return {}
                raw = await resp.json()

            result = {
                "score": raw.get("score"),
                "is_flagged": bool(raw.get("is_flagged", False)),
                "cached": False,
            }
            self._cache[cache_key] = (result, now + CACHE_TTL)
            return result

        except aiohttp.ClientError as e:
            logger.warning("Token Sniffer network error for %s: %s", address, e)
            return {}
        except Exception as e:
            logger.error("Token Sniffer fetch failed for %s: %s", address, e)
            return {}

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
