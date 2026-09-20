"""Hunter — scheduled proactive threat sweep loop for ShieldBot's AI agent.

Runs periodic sweeps that:
1. Check watched deployers for new contracts
2. Recheck contracts previously scored WARN (31-70)
3. Discover new Robinhood Chain launches and scan the newest ones

For any flagged contract: auto-watches the deployer, generates an AI threat
narrative (when available), and stores the finding.

Every hunter scan is a background scan and runs under BACKGROUND_SCAN_DEADLINE_SECONDS.

Robinhood Chain (4663) work shares one RPC budget and circuit breaker (services.rpc_guard):
every 4663 scan reserves its worst-case request count first, and while the breaker is open no
4663 discovery or scan runs and nothing is recorded. When the fast launch watch
(agent.launch_watch) is running it owns all 4663 work, so the sweep leaves launches to it and
hands it the 4663 pairs due a recheck. Each final 4663 scan result, a launch's first scan or a
later recheck, goes to the optional verdict publisher.

Every public method is wrapped in try/except so it never crashes the caller.
"""

import asyncio
import json
import logging
import time
import traceback

from agent.prompts import HAIKU_MODEL, NARRATIVE_TEMPLATE
from core.extension_formatter import is_scan_incomplete
from core.registry import BACKGROUND_SCAN_DEADLINE_SECONDS
from services.launch_discovery import CHAIN_ID as LAUNCH_CHAIN_ID
from services.rpc_guard import CLOSED, BreakerOpenError

logger = logging.getLogger(__name__)

# Each scan runs every analyzer, so only the newest launches are scanned per sweep.
LAUNCH_SCANS_PER_SWEEP = 10
# One sweep rechecks at most this many tracked pairs, shared equally between the chains
# that have any, so no chain can starve another.
RECHECK_PAIRS_PER_SWEEP = 20
# Chain 4663 scans cannot reach full coverage yet, so those pairs would otherwise be
# rescanned every sweep forever. Six hours caps a pair at four rechecks a day.
RECHECK_MIN_INTERVAL_SECONDS = 6 * 3600
# Every scan makes several provider and RPC calls, and the public 4663 RPC is shared, so
# scans are spaced instead of running back to back. Thirty paced scans add a minute to a sweep.
SCAN_INTERVAL_SECONDS = 2.0
# Worst-case HTTP requests one 4663 scan sends to the RPC, retries aside, reserved from the shared
# budget before the scan starts. Structural lookups send up to 10: get_code twice, the creation
# transaction and its block, and owner() plus its raw re-read, each eth_call preceded by eth_chainId
# from web3's validation middleware (once on web3 6.15.1 per its source, twice on web3 7 as measured
# live). The buy/sell simulation sends up to 12: the pool lookup batch, V2 reserves, a block number
# and three Initialize log windows, then up to three pools simulated twice each.
SCAN_REQUEST_COST = 22
# Bound on the optional AI narrative for a finding. The narrative is a 200-token Haiku reply that
# normally returns in seconds; the advisor gives a 500-token interactive reply 30 s. Findings are
# written while launch_lock may be held, so a hung call holds it for at most one launch-watch poll
# interval (20 s) instead of the SDK's 600 s timeout with two retries. On timeout the finding is
# stored without a narrative.
NARRATIVE_TIMEOUT_SECONDS = 20


class Hunter:
    """Proactive scheduled threat sweeps."""

    def __init__(
        self, tools, db, ai_analyzer, sentinel, discovery=None, rpc_guard=None, verdict_publisher=None
    ):
        self.tools = tools
        self.db = db
        self.ai = ai_analyzer
        self.sentinel = sentinel
        self.discovery = discovery
        self.rpc_guard = rpc_guard
        self.verdict_publisher = verdict_publisher
        # The fast launch watch, when one is wired in; it owns 4663 work while it runs.
        self.launch_watch = None
        # Held while discovering or scanning 4663 launches, so the sweep and the watch never
        # scan the same launch.
        self.launch_lock = asyncio.Lock()
        self._task = None  # asyncio.Task for background loop
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, interval_seconds: int = 1800):
        """Start the background sweep loop (default: every 30 min)."""
        if self._running or (self._task and not self._task.done()):
            logger.warning("Hunter already running, ignoring duplicate start")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop(interval_seconds))
        logger.info("Hunter started (interval=%ds)", interval_seconds)

    async def stop(self):
        """Cancel the background task."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Hunter stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    async def rpc_ready(self) -> bool:
        """True when 4663 work may run. Once the breaker's cooldown has passed, sends its one probe."""
        guard = self.rpc_guard
        if guard is None or guard.state == CLOSED:
            return True
        if guard.probe_due and self.discovery is not None:
            return await self.discovery.probe()
        return False

    def _watch_running(self) -> bool:
        return self.launch_watch is not None and self.launch_watch.is_running

    async def _publish_verdict(self, chain_id: int, subject: str, result: dict):
        """Hand a final 4663 scan result to the verdict publisher, when one is wired in.

        A publisher failure never breaks a scan; it is logged by exception class only.
        """
        if self.verdict_publisher is None or chain_id != LAUNCH_CHAIN_ID:
            return
        try:
            await self.verdict_publisher.publish(chain_id, subject, result)
        except Exception as exc:
            logger.error(
                "Hunter: verdict publishing failed for %s: %s\n%s", subject,
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )

    async def _reserve_scan(self, chain_id: int):
        """Reserve a 4663 scan's worst-case requests; raises BreakerOpenError while the breaker is open."""
        if chain_id == LAUNCH_CHAIN_ID and self.rpc_guard is not None:
            await self.rpc_guard.acquire(SCAN_REQUEST_COST)

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def _loop(self, interval: int):
        """Main loop: sweep then sleep."""
        while self._running:
            try:
                await self.sweep()
            except Exception as exc:
                logger.error(
                    "Hunter sweep failed: %s\n%s",
                    type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
                )
            await asyncio.sleep(interval)

    async def sweep(self):
        """One complete hunt cycle.

        Returns a list of flagged contract addresses.
        Never raises — sub-method exceptions are caught individually.
        """
        investigation_id = f"sweep-{int(time.time())}"
        logger.info("Hunter sweep started: %s", investigation_id)

        flagged = []

        # Phase 1: check watched deployers
        try:
            flagged += await self._check_watched_deployers(investigation_id)
        except Exception as exc:
            logger.error(
                "Hunter: _check_watched_deployers failed: %s\n%s",
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )

        # Phase 2: recheck WARN contracts
        try:
            flagged += await self._recheck_warn_contracts(investigation_id)
        except Exception as exc:
            logger.error(
                "Hunter: _recheck_warn_contracts failed: %s\n%s",
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )

        # Phase 3: discover and scan new Robinhood Chain launches
        try:
            flagged += await self._scan_new_pairs(investigation_id)
        except Exception as exc:
            logger.error(
                "Hunter: _scan_new_pairs failed: %s\n%s",
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )

        # Housekeeping: prune stale chat history (>24h)
        try:
            await self.db.prune_old_chats()
        except Exception as exc:
            logger.error(
                "Hunter: chat pruning failed: %s\n%s",
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )

        logger.info(
            "Hunter sweep %s complete: %d flagged", investigation_id, len(flagged)
        )
        return flagged

    # ------------------------------------------------------------------
    # Phase 1: Watched deployer check
    # ------------------------------------------------------------------

    async def _check_watched_deployers(self, investigation_id: str):
        """Check each watched deployer for new contracts not yet tracked.

        In a full implementation this would query BSCScan for recent
        deployer transactions. For now this is a hook point that
        iterates watched deployers without taking action.
        """
        flagged = []
        deployers = await self.db.get_watched_deployers()
        # Cap at 200 deployers per sweep to prevent resource exhaustion
        for d in deployers[:200]:
            try:
                # Future: query BSCScan for recent contract creations by this deployer
                # and scan any that aren't already tracked.
                pass
            except Exception as exc:
                logger.error(
                    "Hunter: error checking deployer %s: %s\n%s",
                    d.get("deployer_address"),
                    type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
                )
        return flagged

    # ------------------------------------------------------------------
    # Phase 2: Recheck WARN contracts
    # ------------------------------------------------------------------

    async def _recheck_warn_contracts(self, investigation_id: str):
        """Recheck watching contracts, least recently checked first.

        Every chain holding watching pairs gets an equal share of RECHECK_PAIRS_PER_SWEEP,
        and a pair waits RECHECK_MIN_INTERVAL_SECONDS between rechecks, so no chain starves
        another and no pair is rescanned every sweep. Only a complete scan clears a
        contract; an incomplete one leaves it watching. 4663 pairs go last, since their scans
        wait on the shared RPC budget, or to the launch watch while it runs; one the open
        breaker refuses is skipped and stays due.
        """
        flagged = []
        chains = await self.db.get_recheck_chains("watching")
        if not chains:
            return flagged
        quota = max(1, RECHECK_PAIRS_PER_SWEEP // len(chains))
        checked_before = time.time() - RECHECK_MIN_INTERVAL_SECONDS
        pairs = []
        for chain in sorted(chains, key=lambda chain: chain == LAUNCH_CHAIN_ID):
            due = await self.db.get_recheck_pairs("watching", chain, quota, checked_before)
            if chain == LAUNCH_CHAIN_ID and self._watch_running():
                self.launch_watch.queue_rechecks(due)
            else:
                pairs += due
        for index, pair in enumerate(pairs[:RECHECK_PAIRS_PER_SWEEP]):
            if index > 0:
                await asyncio.sleep(SCAN_INTERVAL_SECONDS)
            try:
                if await self.recheck_pair(investigation_id, pair):
                    flagged.append(pair["token_address"])
            except BreakerOpenError:
                continue
        return flagged

    async def recheck_pair(self, investigation_id: str, pair) -> bool:
        """Rescan one watching pair on its own chain; True if the rescan blocked it.

        A 4663 pair the open breaker refuses raises BreakerOpenError before it is marked checked.
        """
        blocked = False
        published = False
        result = None
        try:
            chain_id = pair.get("chain_id", 56)
            await self._reserve_scan(chain_id)
            await self.db.mark_tracked_pair_checked(pair["pair_address"])
            result = await self.tools.scan_contract(
                pair["token_address"], chain_id=chain_id, deadline=BACKGROUND_SCAN_DEADLINE_SECONDS
            )
            risk_score = result.get("risk_score", result.get("rug_probability"))

            if risk_score is not None and risk_score >= 71:
                # Upgraded to BLOCK. The finding is stored first, so a reader never sees a
                # blocked pair without the evidence behind it.
                await self._log_finding(
                    investigation_id,
                    pair["token_address"],
                    pair.get("deployer"),
                    risk_score,
                    result,
                    "blocked",
                    chain_id=chain_id,
                )
                await self.db.update_tracked_pair_status(
                    pair["pair_address"], "blocked"
                )
                # Publish before the auto-watch: that insert can raise, and the verdict is already final.
                await self._publish_verdict(chain_id, pair["token_address"], result)
                published = True
                if pair.get("deployer"):
                    await self.tools.auto_watch_deployer(
                        pair["deployer"],
                        reason=f"auto: recheck upgrade {pair['token_address']} (score={risk_score})",
                    )
                blocked = True
            elif risk_score is not None and risk_score <= 30 and not is_scan_incomplete(result):
                # Cleared
                await self.db.update_tracked_pair_status(
                    pair["pair_address"], "cleared"
                )
            # else: still WARN, leave as watching
            # FINAL RECHECK VERDICT: the rescan's result supersedes the launch's earlier one.
            if not published:
                await self._publish_verdict(chain_id, pair["token_address"], result)
        except BreakerOpenError:
            raise
        except Exception as exc:
            logger.error(
                "Hunter: error rechecking %s: %s\n%s", pair.get("token_address"),
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )
            if result is not None and not published:
                # The rescan reached a verdict and the failure came after it, so that verdict is lost.
                logger.warning(
                    "Hunter: verdict for %s on chain %d not published: the recheck failed after scanning it",
                    pair.get("token_address"), pair.get("chain_id", 56),
                )
        return blocked

    # ------------------------------------------------------------------
    # Phase 3: New Robinhood Chain launches
    # ------------------------------------------------------------------

    async def _scan_new_pairs(self, investigation_id: str):
        """Discover Robinhood Chain launches, then scan the newest unscanned ones.

        BSC pair monitoring is not implemented, and without a discovery service this
        phase does nothing. Nor does it while the launch watch runs, since the watch owns
        4663 launches, or while the RPC breaker is open. Launches that are not blocked or
        cleared by a complete scan are tracked as watching so the recheck phase revisits
        them on their own chain.
        """
        if self.discovery is None or self._watch_running():
            return []
        async with self.launch_lock:
            if self._watch_running() or not await self.rpc_ready():
                return []
            try:
                await self.discovery.run()
            except Exception as exc:
                logger.error(
                    "Hunter: launch discovery failed: %s\n%s",
                    type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
                )

            flagged = []
            launches = await self.db.get_unscanned_launches(LAUNCH_CHAIN_ID, LAUNCH_SCANS_PER_SWEEP)
            for index, launch in enumerate(launches):
                if index > 0:
                    await asyncio.sleep(SCAN_INTERVAL_SECONDS)
                try:
                    if await self.scan_launch(investigation_id, launch) == "blocked":
                        flagged.append(launch["token_address"])
                except BreakerOpenError:
                    break
            return flagged

    async def scan_launch(self, investigation_id: str, launch) -> str:
        """Scan one discovered 4663 launch, record the outcome and return its status.

        The sweep and the launch watch both scan launches here. Raises BreakerOpenError, with
        nothing recorded, when the open breaker refuses the scan.
        """
        token = launch["token_address"]
        await self._reserve_scan(LAUNCH_CHAIN_ID)
        try:
            result = await self.tools.scan_contract(
                token, chain_id=LAUNCH_CHAIN_ID, deadline=BACKGROUND_SCAN_DEADLINE_SECONDS
            )
        except Exception as exc:
            logger.error(
                "Hunter: error scanning launch %s: %s\n%s", token,
                type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
            )
            await self.db.upsert_tracked_pair(token, token_address=token, chain_id=LAUNCH_CHAIN_ID)
            await self.db.record_launch_scan(LAUNCH_CHAIN_ID, token, "error", None)
            return "error"

        risk_score = result.get("risk_score", result.get("rug_probability"))
        if risk_score is not None and risk_score >= 71:
            status = "blocked"
            await self._log_finding(
                investigation_id, token, None, risk_score, result, status, chain_id=LAUNCH_CHAIN_ID
            )
        elif risk_score is None or is_scan_incomplete(result):
            status = "unknown"
        elif risk_score <= 30:
            status = "cleared"
        else:
            status = "watching"
        if status in ("unknown", "watching"):
            await self.db.upsert_tracked_pair(token, token_address=token, chain_id=LAUNCH_CHAIN_ID)
        await self.db.record_launch_scan(LAUNCH_CHAIN_ID, token, status, risk_score)
        # FINAL LAUNCH VERDICT: a launch's first scan result is final here; recheck_pair publishes
        # the results of later rescans.
        await self._publish_verdict(LAUNCH_CHAIN_ID, token, result)
        return status

    # ------------------------------------------------------------------
    # Finding logger
    # ------------------------------------------------------------------

    async def _log_finding(
        self, investigation_id, address, deployer, risk_score, evidence, action, chain_id=56
    ):
        """Store a finding and optionally generate AI narrative.

        The narrative is bounded by NARRATIVE_TIMEOUT_SECONDS; without it the finding is still stored.
        """
        narrative = None
        if self.ai and self.ai.is_available():
            try:
                prompt = NARRATIVE_TEMPLATE.format(
                    data=json.dumps(evidence, default=str)
                )
                narrative = await asyncio.wait_for(
                    self.ai.chat(
                        model=HAIKU_MODEL,
                        messages=[{"role": "user", "content": prompt}],
                        max_tokens=200,
                    ),
                    timeout=NARRATIVE_TIMEOUT_SECONDS,
                )
                narrative = narrative.strip()
            except Exception as exc:
                logger.warning(
                    "Hunter: AI narrative failed: %s\n%s",
                    type(exc).__name__, "".join(traceback.format_tb(exc.__traceback__)),
                )

        await self.db.insert_agent_finding(
            finding_type="hunter_sweep",
            investigation_id=investigation_id,
            address=address,
            deployer=deployer,
            chain_id=chain_id,
            risk_score=risk_score,
            narrative=narrative,
            evidence=evidence,
            action_taken=action,
        )
