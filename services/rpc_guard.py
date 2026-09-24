"""Request budget and circuit breaker for the shared Robinhood Chain (4663) public RPC.

One RpcGuard paces every request ShieldBot's background work sends to that RPC: launch discovery
takes one request per JSON-RPC call (a batch of block headers takes one per header, since the RPC
rate-limits each call in a batch), the breaker's probe takes one, and hunter scans reserve their
worst-case request count up front. The budget is an average, not a per-second cap: over any window
at least one reservation long, the requests granted stay within the rate, while inside a shorter
window a burst of up to one reservation is allowed, since a scan's own requests are not paced one
by one.
The breaker trips on structured signals only: HTTP 429 or 5xx statuses and transport exception
classes, never message text. While it is open, callers get BreakerOpenError without a request
being sent, so their work waits instead of being recorded.
"""

import asyncio
import logging
import time

logger = logging.getLogger(__name__)

# Background 4663 RPC traffic, in HTTP requests per second, averaged over any window at least one
# reservation long (a burst of up to one reservation is allowed). Every call discovery sends,
# retries included, takes one request; a scan reserves its no-retry worst case. The public RPC is
# shared with the census collector, which already gets HTTP 429 at its own 4 req/s ceiling. One
# request per second keeps ShieldBot at a quarter of that while covering discovery (about
# 0.3 req/s: two requests per 20 s poll plus one header per new launch block, about three) and
# about two worst-case scans a minute.
RPC_BUDGET_RPS = 1.0
# Consecutive failed requests that open the breaker. A single 429 is a burst the retry backoff
# absorbs; three in a row, across at least three seconds of backoff, means the RPC keeps refusing.
BREAKER_FAILURE_THRESHOLD = 3
# The first cooldown; each failed probe doubles it up to the cap, and a successful probe resets it.
BREAKER_BASE_COOLDOWN_SECONDS = 60
BREAKER_MAX_COOLDOWN_SECONDS = 960

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"


class BreakerOpenError(RuntimeError):
    """The breaker is open: nothing was sent, and the work must wait rather than be recorded."""


def is_failure_status(status: int) -> bool:
    """Throttling (429) and server errors (5xx) count against the RPC; other statuses do not."""
    return status == 429 or status >= 500


class RpcGuard:
    """Paces requests to one RPC at ``rate`` per second and opens a breaker when it keeps failing."""

    def __init__(self, name: str, rate: float = RPC_BUDGET_RPS, clock=time.monotonic):
        self.name = name
        self.rate = rate
        self._clock = clock
        self.state = CLOSED
        self._next_slot = 0.0
        self._failures = 0
        self._cooldown = BREAKER_BASE_COOLDOWN_SECONDS
        self._opened_at = 0.0

    @property
    def probe_due(self) -> bool:
        """The breaker is open and its cooldown has passed, so one probe may go."""
        return self.state == OPEN and self._clock() >= self._opened_at + self._cooldown

    def get_stats(self) -> dict:
        """Current reservation pressure; a positive wait means the budget is occupied."""
        wait = max(0.0, self._next_slot - self._clock())
        return {
            "rate_rps": self.rate,
            "state": self.state,
            "wait_seconds": wait,
            "saturated": wait > 0,
        }

    async def acquire(self, cost: float, probe: bool = False):
        """Wait until ``cost`` requests fit the budget.

        Each grant pushes the next one back by cost / rate, so over any window the requests
        granted never exceed rate * window plus one grant: the rate holds as an average over
        windows of at least one reservation, and a burst of up to one reservation is allowed.
        Raises BreakerOpenError at once unless the breaker is closed, except for the single probe
        allowed once the cooldown has passed, and again if the breaker opened while this call was
        waiting; then nothing is sent, so the reservation goes back to the budget.
        """
        if probe:
            if not self.probe_due:
                raise BreakerOpenError(f"{self.name} RPC breaker is {self.state}")
            self._set_state(HALF_OPEN, "probe")
        elif self.state != CLOSED:
            raise BreakerOpenError(f"{self.name} RPC breaker is {self.state}")
        now = self._clock()
        start = max(now, self._next_slot)
        self._next_slot = start + cost / self.rate
        if start > now:
            await asyncio.sleep(start - now)
        if not probe and self.state != CLOSED:
            self._next_slot -= cost / self.rate
            raise BreakerOpenError(f"{self.name} RPC breaker is {self.state}")

    def record_success(self):
        """The RPC answered. Closes a half-open breaker; an open one waits for its probe."""
        self._failures = 0
        if self.state == HALF_OPEN:
            self._cooldown = BREAKER_BASE_COOLDOWN_SECONDS
            self._set_state(CLOSED, "probe succeeded")

    def record_failure(self, cause: str):
        """A request failed with ``cause``: an HTTP status or an exception class name, never text."""
        if self.state == HALF_OPEN:
            self._cooldown = min(self._cooldown * 2, BREAKER_MAX_COOLDOWN_SECONDS)
            self._open(cause)
        elif self.state == CLOSED:
            self._failures += 1
            if self._failures >= BREAKER_FAILURE_THRESHOLD:
                self._open(cause)

    def _open(self, cause: str):
        self._failures = 0
        self._opened_at = self._clock()
        self._set_state(OPEN, cause)

    def _set_state(self, state: str, cause: str):
        logger.warning(
            "%s RPC breaker %s -> %s (%s); cooldown %d s",
            self.name, self.state, state, cause, self._cooldown,
        )
        self.state = state
