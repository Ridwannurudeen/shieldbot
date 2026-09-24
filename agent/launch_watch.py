"""Fast Robinhood Chain (4663) launch watch: a short discovery loop feeding a triaged scan queue.

The hunter's 30-minute sweep surfaced a launch about half an hour late and scanned ten per sweep,
a few percent of them. This loop polls discovery every POLL_INTERVAL_SECONDS with one combined log
read (services.launch_discovery.LaunchDiscovery.poll) and spends the rest of each interval on
scans, all inside the shared 4663 RPC budget and behind its circuit breaker (services.rpc_guard).
While it runs it owns every 4663 launch and recheck; the sweep leaves them to it.

Triage. Measured on 2026-09-19 over 10,000 blocks: of 156 launches then 1 to 17 minutes old, 60
(38%) had traded, and 53 of those 60 had their first swap within 60 s of launch. A launch becomes
visible only once it is CONFIRMATIONS (60 s) deep, so by then a pool that will trade has usually
traded, and a swap proves the pool exists and holds liquidity, which a buy/sell simulation needs.
So:

- Only launches whose pool has swapped since launch are scanned, the busiest first, then the
  newest. The swaps come from the same combined read, so triage costs no extra request.
- A launch stays eligible for TRIAGE_WINDOW_BLOCKS after its block. Launches never scanned stay
  recorded as discovered-but-unscanned; nothing ever marks them clean.
- 4663 pairs the sweep finds due a recheck queue here and alternate with launch scans, so neither
  starves the other.
- A bounded set of confirmed guard subjects is remeasured oldest-first. Launches retain at least
  alternate scan slots, and general rechecks get a slot after at most one guard set of attempts.

Every scan goes through the hunter's outcome logic, including Hunter.rescan_guard_subject.
"""

import asyncio
import logging
import time
import traceback

from core.database import GUARD_WATCH_MAX_SUBJECTS
from services.launch_discovery import CHAIN_ID, LaunchDiscoveryError, WrongChainError
from services.rpc_guard import BREAKER_BASE_COOLDOWN_SECONDS, BREAKER_MAX_COOLDOWN_SECONDS, BreakerOpenError

logger = logging.getLogger(__name__)

# Discovery runs once per interval: a launch surfaces within CONFIRMATIONS (60 s) plus about one
# interval, and at two requests per poll plus one per new launch block's header (about three at
# the measured launch rate) discovery uses about 0.3 req/s of the budget.
POLL_INTERVAL_SECONDS = 20
# Fifteen minutes at 0.1 s per block. In the measurement above the latest first swap came 12.7
# minutes after launch, and the window bounds the swaps tracked to about 150 pools.
TRIAGE_WINDOW_BLOCKS = 9_000
# Unscanned launches read per selection, newest first; fifteen minutes hold about 150.
CANDIDATE_LIMIT = 500


class LaunchWatch:
    """Poll 4663 discovery on a short interval and scan triaged launches between polls."""

    def __init__(self, hunter, clock=time.monotonic):
        self.hunter = hunter
        self._clock = clock
        self._task = None
        self._pause = 0
        self._paused_until = 0.0
        self._target = None
        self._swaps = {}
        self._rechecks = {}
        self._last_job = None
        self._guard_attempted = set()
        self._guard_jobs_since_recheck = 0

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self):
        """Start the background loop."""
        if self.is_running:
            logger.warning("Launch watch already running, ignoring duplicate start")
            return
        self._task = asyncio.create_task(self._loop())
        logger.info("Launch watch started (poll=%ds)", POLL_INTERVAL_SECONDS)

    async def stop(self):
        """Cancel the background loop and wait for it to finish."""
        task, self._task = self._task, None
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        logger.info("Launch watch stopped")

    def queue_rechecks(self, pairs):
        """Queue 4663 watching pairs the sweep found due a recheck; each pair is queued once."""
        for pair in pairs:
            self._rechecks.setdefault(pair["pair_address"], pair)

    async def _loop(self):
        while True:
            started = self._clock()
            try:
                await self.cycle()
            except Exception as exc:
                logger.error(
                    "Launch watch cycle failed: %s\n%s",
                    type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
                )
            await asyncio.sleep(max(0.0, started + POLL_INTERVAL_SECONDS - self._clock()))

    async def cycle(self):
        """Poll discovery once, then scan until the next poll is due or nothing is eligible.

        Nothing runs while the RPC breaker is open; once its cooldown has passed, the hunter
        sends the one probe. A scan the breaker refuses is left pending, not recorded. An RPC
        that answers for another chain pauses all 4663 work, with the pause doubling from the
        breaker's base cooldown to its cap and one log line per pause.
        """
        if self._clock() < self._paused_until:
            return
        deadline = self._clock() + POLL_INTERVAL_SECONDS
        async with self.hunter.launch_lock:
            if not await self.hunter.rpc_ready():
                return
            investigation_id = f"launch-watch-{int(time.time())}"
            window = await self._window()
            try:
                polled = await self.hunter.discovery.poll(
                    pools={row["pool_id"] for row in window if row["pool_id"]}
                )
            except WrongChainError as exc:
                self._pause = (
                    min(self._pause * 2, BREAKER_MAX_COOLDOWN_SECONDS) if self._pause
                    else BREAKER_BASE_COOLDOWN_SECONDS
                )
                self._paused_until = self._clock() + self._pause
                logger.error("Launch watch paused %d s: %s", self._pause, type(exc).__name__)
                return
            except LaunchDiscoveryError as exc:
                logger.warning("Launch watch poll failed: %s", type(exc).__name__)
            else:
                self._pause = 0
                self._target = polled["target"]
                for pool, count in polled["swaps"].items():
                    self._swaps[pool] = self._swaps.get(pool, 0) + count
            window = await self._window()
            pools = {row["pool_id"] for row in window}
            self._swaps = {pool: count for pool, count in self._swaps.items() if pool in pools}
            while self._clock() < deadline:
                guards = await self.hunter.due_guard_subjects()
                # A failing oldest subject must not monopolize successive guard slots.
                # Keep the round across cycles: a budget wait often ends a cycle after one scan.
                self._guard_attempted.intersection_update(
                    row["subject"] for row in await self.hunter.db.get_guard_subjects(CHAIN_ID)
                )
                untried = [row for row in guards if row["subject"] not in self._guard_attempted]
                if guards and not untried:
                    self._guard_attempted.clear()
                    untried = guards
                job = self._next_job(window, untried)
                if job is None:
                    return
                kind, item = job
                try:
                    if kind == "launch":
                        await self.hunter.scan_launch(investigation_id, item)
                        window.remove(item)
                    elif kind == "guard":
                        await self.hunter.rescan_guard_subject(item)
                        self._guard_attempted.add(item["subject"])
                        self._guard_jobs_since_recheck += 1
                    else:
                        await self.hunter.recheck_pair(investigation_id, item)
                        del self._rechecks[item["pair_address"]]
                        self._guard_jobs_since_recheck = 0
                except BreakerOpenError:
                    return
                self._last_job = kind

    async def _window(self):
        """Unscanned launches whose block is inside the triage window, newest first."""
        if self._target is None:
            return []
        rows = await self.hunter.db.get_unscanned_launches(CHAIN_ID, CANDIDATE_LIMIT)
        return [row for row in rows if row["block_number"] > self._target - TRIAGE_WINDOW_BLOCKS]

    def _next_job(self, window, guards=()):
        """Give launches at least alternate slots; due guard scans precede general rechecks."""
        traded = [row for row in window if self._swaps.get(row["pool_id"], 0) > 0]
        launch = max(
            traded, key=lambda row: (self._swaps[row["pool_id"]], row["block_number"]), default=None
        )
        if guards and (launch is None or self._last_job == "launch"):
            # Even permanent guard failures yield a background slot after one capped
            # set of attempts, preserving the sweep's existing recheck lane.
            if not self._rechecks or (
                self._last_job != "guard" and self._guard_jobs_since_recheck < GUARD_WATCH_MAX_SUBJECTS
            ):
                return "guard", guards[0]
        if self._rechecks and (launch is None or self._last_job == "launch"):
            return "recheck", next(iter(self._rechecks.values()))
        if launch is not None:
            return "launch", launch
        return None
