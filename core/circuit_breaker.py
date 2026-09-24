"""Circuit breakers for the external data providers a scan asks.

There is one breaker per provider and chain, made on first use; chain None stands for a provider
whose request names no chain. Only chains in utils.chain_info.CHAIN_INFO get one, so a chain id
taken from a request can never add a breaker: a lookup on any other chain is sent unguarded, as
before.

A breaker opens after FAILURE_THRESHOLD failed lookups in a row. While it is open, check() raises
CircuitOpenError before anything is sent, and the provider's own error path turns that into the
same answer a timeout gives (unknown, None, no verdict), counted as failed in the Unknown ledger,
so every fail-closed rule downstream still fires. Once OPEN_SECONDS have passed, one lookup goes
through as a probe (half-open): an answer closes the breaker, a failure opens it for another
OPEN_SECONDS. A probe that never reports, because its scan was cancelled at the deadline, frees
the slot after OPEN_SECONDS.

A failed lookup is a timeout, a connection error, a reply that is not JSON, or HTTP 429 or 5xx.
Any other reply, a 404 or "no record" included, is the provider answering and ends a run of
failures, even when the caller cannot use the data in it.
A lookup that retries is counted once, by its last attempt. Time is time.monotonic. There are no
locks: use the breakers on the event loop only, never from a worker thread.
"""

import asyncio
import json
import logging
import time
from typing import Callable, Dict, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)

# The values the Tenderly breaker and the Robinhood Chain RPC guard already use. Scans run in
# parallel, so an outage opens the breaker within seconds, while a provider that fails one lookup
# in five almost never fails three in a row.
FAILURE_THRESHOLD = 3
OPEN_SECONDS = 60

# Exceptions that fail a lookup: aiohttp's connection, timeout and response errors (a reply without
# a JSON content type among them), asyncio's timeout, and a reply body that does not decode as
# JSON. Any other ValueError, TypeError or KeyError comes from a caller's own parsing of a reply
# that did arrive, such as float("n/a"): that lookup is Unknown, but the provider answered.
LOOKUP_ERRORS = (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError)

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"


class CircuitOpenError(RuntimeError):
    """The provider's breaker is open, so no request was sent."""


def is_failure_status(status: int) -> bool:
    """Throttling (429) and server errors (5xx) fail a lookup, as in services.rpc_guard."""
    return status == 429 or status >= 500


class CircuitBreaker:
    """Consecutive-failure breaker for one provider on one chain."""

    def __init__(self, name: str, clock: Callable[[], float] = time.monotonic):
        self.name = name
        self.state = CLOSED
        self._clock = clock
        self._failures = 0
        # When the breaker opened, or when its latest probe went out.
        self._since = 0.0

    def allow(self) -> bool:
        """Whether a request may be sent now; past OPEN_SECONDS, one probe is let through."""
        if self.state == CLOSED:
            return True
        if self._clock() < self._since + OPEN_SECONDS:
            return False
        self._since = self._clock()
        self._set_state(HALF_OPEN, "probe")
        return True

    def record_success(self):
        """The provider answered. Closes a half-open breaker; an open one waits for its probe."""
        self._failures = 0
        if self.state == HALF_OPEN:
            self._set_state(CLOSED, "probe answered")

    def record_failure(self, cause: str):
        """A lookup failed with ``cause``, an HTTP status or an exception class name, never text."""
        if self.state == HALF_OPEN:
            self._open(cause)
        elif self.state == CLOSED:
            self._failures += 1
            if self._failures >= FAILURE_THRESHOLD:
                self._open(cause)

    def _open(self, cause: str):
        self._failures = 0
        self._since = self._clock()
        self._set_state(OPEN, cause)

    def _set_state(self, state: str, cause: str):
        logger.warning("%s breaker %s -> %s (%s)", self.name, self.state, state, cause)
        self.state = state


class ProviderBreakers:
    """The breaker of each (chain, provider) pair, keyed like the Unknown ledger."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._breakers: Dict[Tuple[Optional[int], str], CircuitBreaker] = {}

    def _breaker(self, provider: str, chain_id: Optional[int]) -> Optional[CircuitBreaker]:
        """The breaker for this provider and chain; None for a chain outside CHAIN_INFO."""
        # Imported here: the utils package imports the chain adapters, which import this module.
        from utils.chain_info import CHAIN_INFO

        if chain_id is not None and chain_id not in CHAIN_INFO:
            return None
        key = (chain_id, provider)
        if key not in self._breakers:
            name = provider if chain_id is None else f"{provider}:{chain_id}"
            self._breakers[key] = CircuitBreaker(name, self._clock)
        return self._breakers[key]

    def check(self, provider: str, chain_id: Optional[int] = None):
        """Raise CircuitOpenError unless a request to this provider may be sent now."""
        breaker = self._breaker(provider, chain_id)
        if breaker is not None and not breaker.allow():
            raise CircuitOpenError(f"{breaker.name} breaker is {breaker.state}")

    def record_status(self, provider: str, chain_id: Optional[int], status: int):
        """Count a lookup that got an HTTP reply: failed on 429 or 5xx, answered on any other status."""
        breaker = self._breaker(provider, chain_id)
        if breaker is None:
            return
        if is_failure_status(status):
            breaker.record_failure(f"HTTP {status}")
        else:
            breaker.record_success()

    def record_error(self, provider: str, chain_id: Optional[int], exc: BaseException):
        """Count a lookup that raised. Only LOOKUP_ERRORS are failures: a CircuitOpenError sent
        nothing, and any other exception is not the provider's doing."""
        breaker = self._breaker(provider, chain_id)
        if breaker is not None and isinstance(exc, LOOKUP_ERRORS):
            breaker.record_failure(type(exc).__name__)

    def states(self) -> Dict[str, str]:
        """Each breaker made so far, by name, with its state."""
        return {breaker.name: breaker.state for breaker in self._breakers.values()}

    def clear(self):
        """Forget every breaker, so each starts closed again."""
        self._breakers.clear()


provider_breakers = ProviderBreakers()
