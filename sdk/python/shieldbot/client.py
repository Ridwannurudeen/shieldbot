"""ShieldBot Python SDK — async client with local verdict caching."""

import time
import logging
from typing import Dict, Optional
from collections import OrderedDict

import httpx

from shieldbot.models import Verdict

logger = logging.getLogger(__name__)


class ShieldBotError(Exception):
    """Raised for non-transient API errors (4xx) that the caller must handle."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"ShieldBot API error {status_code}: {message}")

DEFAULT_BASE_URL = "https://api.shieldbotsecurity.online"


class ShieldBot:
    """Async ShieldBot client with local verdict cache and fail-cached mode."""

    def __init__(
        self,
        api_key: str,
        agent_id: str,
        base_url: str = DEFAULT_BASE_URL,
        cache_size: int = 10000,
        cache_ttl: int = 86400,
        fail_mode: str = "cached",
        timeout: float = 10.0,
    ):
        self.api_key = api_key
        self.agent_id = agent_id
        self.base_url = base_url.rstrip("/")
        self._cache_size = cache_size
        self._cache_ttl = cache_ttl
        self._fail_mode = fail_mode
        self._timeout = timeout
        self._cache: OrderedDict = OrderedDict()
        self._http: Optional[httpx.AsyncClient] = None

    def _get_http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=self.base_url,
                headers={"X-API-Key": self.api_key},
                timeout=self._timeout,
            )
        return self._http

    def _cache_key(self, to: str, chain_id: int) -> str:
        return f"{to.lower()}:{chain_id}"

    def _get_cached(self, key: str) -> Optional[Verdict]:
        if key in self._cache:
            entry = self._cache[key]
            if time.time() - entry["ts"] < self._cache_ttl:
                self._cache.move_to_end(key)
                return entry["verdict"]
            else:
                del self._cache[key]
        return None

    def _set_cached(self, key: str, verdict: Verdict):
        self._cache[key] = {"verdict": verdict, "ts": time.time()}
        if len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)

    def _fail_verdict(self, cache_key: str, to_addr: str) -> Verdict:
        """Return a fail-mode verdict (cached/open/closed) for transient errors."""
        if self._fail_mode == "cached":
            cached = self._get_cached(cache_key)
            if cached is not None:
                logger.info(f"Using cached verdict for {to_addr} (API unavailable)")
                return cached
        if self._fail_mode in ("open", "cached"):
            return Verdict(verdict="ALLOW", score=0, flags=["api_unavailable"])
        return Verdict(verdict="BLOCK", score=100, flags=["api_unavailable"])

    async def check(self, transaction: Dict) -> Verdict:
        """Check a transaction against the agent firewall.

        Args:
            transaction: Dict with keys: from, to, data (optional), value (optional), chain_id.

        Returns:
            Verdict with allowed/blocked status, score, flags, and evidence.
        """
        to_addr = transaction.get("to", "")
        chain_id = transaction.get("chain_id", 56)
        cache_key = self._cache_key(to_addr, chain_id)

        # Check local cache
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        # Make the HTTP request — catch only network/timeout errors
        try:
            http = self._get_http()
            resp = await http.post("/api/agent/firewall", json={
                "agent_id": self.agent_id,
                "transaction": transaction,
            })
        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.error(f"ShieldBot network error: {e}")
            return self._fail_verdict(cache_key, to_addr)

        # 200 OK — parse and cache the verdict
        if resp.status_code == 200:
            data = resp.json()
            verdict = Verdict(
                verdict=data["verdict"],
                score=data["score"],
                flags=data.get("flags", []),
                evidence=data.get("evidence"),
                policy_check=data.get("policy_check"),
                cached=data.get("cached", False),
                latency_ms=data.get("latency_ms", 0),
            )
            self._set_cached(cache_key, verdict)
            return verdict

        # 4xx client errors — non-transient, caller must handle
        if 400 <= resp.status_code < 500:
            raise ShieldBotError(resp.status_code, resp.text)

        # 5xx server errors — transient, use fail-mode
        logger.warning(f"ShieldBot API returned {resp.status_code}: {resp.text}")
        return self._fail_verdict(cache_key, to_addr)

    async def close(self):
        """Close the HTTP client."""
        if self._http:
            await self._http.aclose()
