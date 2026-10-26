"""Publishes ShieldBot verdicts: stores every evidence document and records configured chain verdicts on-chain.

Every process (API, hunter, bot) calls publish(), which only STORES the canonical evidence document
(core.verdict_evidence). When a chain's verdict registry is set, a row for that chain is stored as
`pending`: an outbox entry for ShieldBotVerdictRegistry.record().

Exactly one process sends: the API process starts one coordinator for all configured chains, or workers.py does
instead when BACKGROUND_WORKERS=external. Each chain has its own recorder key, sender lease, rate window and nonce
lock. The coordinator records pending rows oldest-first only while each chain's sender lease is held. No other code
path reads the keys, so the bot never sends. After signing, a send takes its chain's lease again and goes on only if
the lease is its own and still has a lock wait and PHASE_TIMEOUT_SECONDS to run; otherwise it discards what it signed
and returns the row to the queue. A send that passed that check can finish its broadcast before the lease can pass
to another drain.

A row is queued for the registry configured when it is stored, and it is only ever sent there: after the
registry address changes, a row queued for the old one is dropped (RegistryChanged) and deduplication only
compares rows queued for the new one, so every row names the contract that holds its record.

Each row moves through onchain_status:
  off          stored only (another chain, no registry configured, or its caller passed onchain=False)
  pending      waiting for the drain
  dropped      observation missing, stale, future-dated or superseded, or queued for another registry;
               never broadcast again
  deduplicated newer unchanged measurement retained for supersession; confirmed verdict still fresh
  sending      claimed by the drain; each transaction's hash, nonce and signed bytes are stored BEFORE it is broadcast
  submitted    the node accepted the transaction; no receipt arrived within the receipt timeout
  confirmed    the receipt shows success, so VerdictRecorded was emitted. This is the sequencer's (soft) finality;
               it becomes final on the parent chain once the sequencer posts the batch
  reverted     the receipt shows the call reverted
  failed       the node explicitly rejected the transaction and no receipt was found
  unconfirmed  the broadcast outcome is unknown (a transport error during the send, or a crash after storing)
               and no receipt was found

A row never records its verdict twice. Every transaction a row has broadcast is kept (verdict_transactions), and
every check looks up the receipts of ALL of them in one RPC batch, so a transaction that lands late is always
found. Before anything is broadcast for a row that already has transactions, under the nonce lock and in the same
batch as the nonce reads:
  a receipt for any of them    it is on-chain: the row is finished with that transaction, nothing is sent
  latest nonce <= the row's    that nonce is still unused, so our transaction there may still be mined. Only
    last nonce                 while the pending nonce equals it (otherwise wait), send the SAME stored bytes again
                               while their stored maxFeePerGas covers the base fee; without usable stored bytes,
                               or when the base fee has outgrown them, sign a replacement AT that nonce: at most
                               one transaction per nonce can be mined, and every hash is checked, so it never
                               records twice
  latest nonce > every nonce   each was used by a transaction that is not ours, so none of ours can ever be mined:
    the row used               sign a new transaction at the next nonce
The batch is one HTTP request, answered from one node's view, so a nonce it shows as used comes with the receipt of
whatever used it.

submitted, unconfirmed and failed rows are reconciled at start and whenever the drain is idle: once a row is
RECONCILE_AFTER_SECONDS old, one batched lookup (at most RECONCILE_BATCH rows, every transaction of each) marks it
confirmed or reverted, or queues it again while it has signed fewer than MAX_SEND_ATTEMPTS transactions (sending
the same bytes again does not count: it cannot record twice). A row at the cap is still looked up, every
RECONCILE_AFTER_SECONDS, so a transaction that lands late is reported.

Sending the same bytes again is not a new attempt (it cannot record twice), so a node that takes them without
ever sequencing them would otherwise only show up as INFO: after RESEND_ALARM_AFTER such broadcasts the drain logs
a WARNING naming the record and its transaction.

Claim before send: each claimed row's prepare -> store -> broadcast -> record outcome runs in a task shielded from
cancellation, and stop() lets it finish (for up to STOP_TIMEOUT_SECONDS) before the database closes. A row still
left `sending` (the process was killed, or the database failed) is recovered once it is RECONCILE_AFTER_SECONDS
old, which gives a lagging replica time to show a mined transaction: at start, after any drain error and whenever
the drain is idle. A mined transaction finishes it; otherwise it goes back to `pending` and the checks above
decide what, if anything, is sent. At MAX_SEND_ATTEMPTS transactions it is left `unconfirmed`.

The public 4663 RPC is shared, so the drain is bounded: at most MAX_RECORDS_PER_HOUR records (rows beyond that
wait as pending), one at a time under a nonce lock, a timeout on every request and phase, bounded retries with
backoff on rate limits, and exponential backoff of the drain after a failure that returns a row to pending.
The recorder key is never logged, echoed or stored.
"""

import asyncio
import json
import logging
import os
import re
import secrets
import socket
import time
import traceback
from collections import deque
from typing import Optional, Tuple

import aiohttp
from eth_abi import encode
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from core.verdict_evidence import Verdict, build_evidence, canonical_bytes

logger = logging.getLogger(__name__)

DEFAULT_RPC_URL = "https://rpc.mainnet.chain.robinhood.com"
CHAIN_CONFIG = {
    4663: ("ROBINHOOD", DEFAULT_RPC_URL, 1000),
    677: ("BOTCHAIN", "https://rpc.botchain.ai", 100),
}
# `cast sig "record(address,uint8,bytes32,uint64)"` = 0xf160da27
RECORD_SELECTOR = keccak(text="record(address,uint8,bytes32,uint64)")[:4]

# One 4663 scan reserves 23 requests of the watch's shared 1 rps RPC budget (services.rpc_guard,
# agent.hunter.SCAN_REQUEST_COST), so a saturated watch produces at most about 156 scans an hour, and an
# unchanged confirmed verdict only refreshes periodically. This covers that ceiling with room for drain cycles that
# re-send or wait, and costs the RPC about three requests each: 540 an hour, 0.15 rps beside the watch's 1.
MAX_RECORDS_PER_HOUR = 180
# Five minutes accommodates the 60 s simulation cache and normal scan/RPC latency, but
# prevents a backlogged outbox from presenting minutes-old permission as a new observation.
MAX_OBSERVATION_AGE_SECONDS = 300
# Refresh unchanged evidence once its measurement has aged five minutes. A newer measurement
# is required; reading the same cached answer again must not refresh the on-chain timestamp.
VERDICT_REFRESH_SECONDS = 300
RATE_WINDOW_SECONDS = 3600
# Repeated content can be suppressed against these anchors. Unresolved records need another chance;
# a genuinely newer measurement replaces pending work or periodically refreshes confirmed evidence.
SETTLED_STATUSES = ("pending", "sending", "confirmed")
# About 18x the 0.056 gwei base fee of a recorded 4663 block. Arbitrum chains ignore priority fees.
MAX_FEE_PER_GAS_WEI = 10**9
BOTCHAIN_MAX_GAS_PRICE_WEI = 50 * 10**9
# gas * max_fee reserves about 2.4x a record's real cost: 1,000 reservations cover roughly 2,400 records,
# about nine days at the 2026-10-09 rate.
# Arbitrum Nitro's eth_estimateGas includes the L1 data fee as gas, so leave room above the ~140k execution cost.
MAX_GAS_LIMIT = 1_000_000
RPC_ATTEMPTS = 3
RPC_BACKOFF_SECONDS = 1.0
RPC_TIMEOUT_SECONDS = 15
# Bounds each phase (the pre-sign reads, the broadcast) whatever the transport does.
PHASE_TIMEOUT_SECONDS = 60
# Robinhood Chain sequences a transaction within about a second, so one receipt lookup after a short wait.
RECEIPT_DELAY_SECONDS = 2.0
RECEIPT_TIMEOUT_SECONDS = 20
DRAIN_POLL_SECONDS = 10.0
DRAIN_BACKOFF_SECONDS = 5.0
DRAIN_MAX_BACKOFF_SECONDS = 60.0
# core.database opens every connection with PRAGMA busy_timeout=5000, so one write can wait this long for the lock.
DB_LOCK_WAIT_SECONDS = 5
# Unresolved records are looked at again only after this long, in batches, and re-sent a bounded number of times.
# Claim recovery uses the same age, so it must exceed the longest a live send goes without touching its row. The
# longest gap is the store's updated_at to the outcome's: PHASE_TIMEOUT_SECONDS for the broadcast, then
# RECEIPT_DELAY_SECONDS + RECEIPT_TIMEOUT_SECONDS for the receipts (82 s). Each row's updated_at is stamped as its
# write takes the lock, so a lock wait can shift the first stamp earlier and delay the second: count
# DB_LOCK_WAIT_SECONDS at both ends, for 92 s. Checked here as a raise rather than an assert, so it also holds
# under python -O.
RECONCILE_AFTER_SECONDS = 120
if RECONCILE_AFTER_SECONDS <= (
    PHASE_TIMEOUT_SECONDS + RECEIPT_DELAY_SECONDS + RECEIPT_TIMEOUT_SECONDS + 2 * DB_LOCK_WAIT_SECONDS
):
    raise RuntimeError("RECONCILE_AFTER_SECONDS must exceed the longest a live send leaves its row untouched")
RECONCILE_BATCH = 5
MAX_SEND_ATTEMPTS = 5
# stop() waits this long for a send under way to record its outcome.
STOP_TIMEOUT_SECONDS = 30
# Only the drain holding this lease in the database stores and broadcasts. The holder renews it every
# LEASE_RENEW_SECONDS and stops claiming rows once a renewal finds another holder, or before failed renewals could
# let it run out. Each send takes the lease again after signing and goes on only if the lease is its own and has at
# least DB_LOCK_WAIT_SECONDS + PHASE_TIMEOUT_SECONDS left to run. A holder that dies keeps the lease until
# LEASE_SECONDS after it last took it; a drain waiting for it asks again when it expires.
LEASE_SECONDS = 90.0
LEASE_RENEW_SECONDS = 15.0
# The lease a send has just taken must outlast what follows: the freshness reads, storing the transaction (one lock
# wait) and the broadcast phase. The reads take far less than the LEASE_SECONDS - DB_LOCK_WAIT_SECONDS -
# PHASE_TIMEOUT_SECONDS of headroom. Checked here as a raise, like RECONCILE_AFTER_SECONDS.
if LEASE_SECONDS <= DB_LOCK_WAIT_SECONDS + PHASE_TIMEOUT_SECONDS:
    raise RuntimeError("LEASE_SECONDS must exceed storing a transaction plus its broadcast phase")
# After this many consecutive waits on an earlier transaction, the drain says so loudly.
WAIT_ALARM_AFTER = 10
# After this many broadcasts of the same signed bytes, the drain says so loudly. Re-sends are at least
# RECONCILE_AFTER_SECONDS apart and Robinhood Chain sequences a transaction within about a second, so by the third
# the node has held those bytes for minutes: a lagging replica or a lost packet no longer explains it.
RESEND_ALARM_AFTER = 3

ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
QUANTITY_RE = re.compile(r"0x[0-9a-fA-F]+")


class RecordFailed(Exception):
    """An RPC step failed. `reason` is a class-only label, never provider text.

    `rejected` is True only when the node answered with a JSON-RPC error, which is a definite refusal.
    """

    def __init__(self, reason: str, rejected: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.rejected = rejected


class ObservationDropped(Exception):
    """The row became ineligible before a broadcast attempt; its disposition is already stored."""


class VerdictPublisher:
    """Stores verdict evidence and records it on the configured chain when enabled."""

    def __init__(
        self, db, rpc_url: Optional[str] = None, registry_address: Optional[str] = None,
        alert=None,
        chain_id: int = 4663,
    ):
        self._db = db
        if chain_id not in CHAIN_CONFIG:
            raise ValueError(f"unsupported verdict publisher chain: {chain_id}")
        self.chain_id = chain_id
        self._lease_name = f"verdict-drain:{chain_id}"
        self._env_prefix, default_rpc_url, self._low_balance_records = CHAIN_CONFIG[chain_id]
        self._rpc_url = rpc_url or os.getenv(f"{self._env_prefix}_RPC_URL") or default_rpc_url
        self._alert_callback = alert
        registry = (
            registry_address
            if registry_address is not None
            else os.getenv(f"{self._env_prefix}_VERDICT_REGISTRY", "")
        )
        self.registry = None
        self.recorder = None
        self._account = None
        self._nonce_lock = asyncio.Lock()
        self._sent_at = deque()
        self._tasks = set()
        self._drain_task = None
        self._drain_publishers = [self]
        self._wake = None
        self._lease_holder = f"{socket.gethostname()}:{os.getpid()}:{secrets.token_hex(4)}"
        # Set when the lease is lost, or when a send found it too short: the drain loop then returns before it
        # claims another row.
        self._lease_lost = False
        self._waits = 0
        self._low_funds_alerted = False
        self._failure_alerted = False
        # Per row, the bytes last broadcast again and how often in a row: {evidence_id: (tx_hash, count)}.
        self._resends = {}
        if not registry:
            logger.info(
                "%s verdict registry: disabled (set %s_VERDICT_REGISTRY to enable)",
                self._log_chain_name,
                self._env_prefix,
            )
            return
        try:
            self.registry = to_checksum_address(registry)
        except ValueError as e:
            logger.error(
                "%s verdict registry: disabled (invalid %s_VERDICT_REGISTRY: %s)",
                self._log_chain_name,
                self._env_prefix,
                type(e).__name__,
            )
            return
        logger.info("%s verdict registry: verdicts queued for %s", self._log_chain_name, self.registry)

    @property
    def _chain_name(self) -> str:
        from utils.chain_info import get_chain_name

        return get_chain_name(self.chain_id)

    @property
    def _log_chain_name(self) -> str:
        return "Robinhood" if self.chain_id == 4663 else self._chain_name

    @property
    def _alert_chain_label(self) -> str:
        return f"chain {self.chain_id}" if self.chain_id == 4663 else f"{self._chain_name} ({self.chain_id})"

    def is_onchain_enabled(self) -> bool:
        """True when this chain's verdicts are queued for the registry."""
        return self.registry is not None

    # ------------------------------------------------------------------
    # Storing (every process)
    # ------------------------------------------------------------------

    def publish_fire_and_forget(
        self, chain_id: int, subject: str, scan_result: dict, honeypot_data: Optional[dict] = None
    ) -> None:
        """Schedule publish() without waiting for it, for request paths that must not block."""
        self._spawn(self.publish(chain_id, subject, scan_result, honeypot_data))

    async def publish(
        self, chain_id: int, subject: str, scan_result: dict, honeypot_data: Optional[dict] = None,
        onchain: bool = True,
    ) -> Optional[dict]:
        """Store the evidence for one scan; a configured chain verdict is queued for the drain.

        With `onchain` False it is stored as `off`, like a verdict on another chain, and never sent.
        Returns the stored evidence id, hash, verdict and on-chain status, or None if nothing could be
        stored. Reusing the same measurement returns its record. A newer unchanged measurement is retained
        for supersession, but only refreshes a confirmed verdict after VERDICT_REFRESH_SECONDS.
        Never raises and never contacts the RPC.
        """
        if not isinstance(subject, str) or not ADDRESS_RE.fullmatch(subject):
            logger.warning("Verdict not published: subject is not an address")
            return None
        try:
            payload = build_evidence(chain_id, subject, scan_result, honeypot_data)
            canonical = canonical_bytes(payload)
            evidence_hash = "0x" + keccak(canonical).hex()
            queued = onchain and chain_id == self.chain_id and self.is_onchain_enabled()
            status = "pending" if queued else "off"
            if queued:
                previous = await self._db.get_newest_verdict_observation(
                    chain_id, payload["subject"], include_deduplicated=False, registry=self.registry
                )
                if previous is not None and _repeats(previous, payload):
                    if payload.get("observed_at", 0) <= json.loads(previous["canonical"])["observed_at"]:
                        return {
                            "evidence_id": previous["id"],
                            "evidence_hash": previous["evidence_hash"],
                            "verdict": previous["verdict"],
                            "onchain_status": previous["onchain_status"],
                        }
                    if previous["onchain_status"] == "confirmed":
                        status = "deduplicated"
            evidence_id = await self._db.insert_verdict_evidence(
                chain_id=chain_id,
                subject=payload["subject"],
                verdict=payload["verdict"],
                evidence_hash=evidence_hash,
                canonical=canonical.decode("utf-8"),
                observed_block=payload["observed_block"],
                onchain_status=status,
                registry=self.registry if queued else None,
            )
        except Exception as e:
            # The caller only sees None, so a dropped verdict has to name itself here.
            logger.error(
                "Verdict for %s on chain %d not published: %s\n%s",
                subject, chain_id, type(e).__name__,
                "".join(traceback.format_tb(e.__traceback__)),
            )
            return None
        if queued and self._wake is not None:
            self._wake.set()
        return {
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "verdict": payload["verdict"],
            "onchain_status": status,
        }

    def _spawn(self, coroutine) -> asyncio.Task:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _alert(self, text: str) -> None:
        if self._alert_callback is None:
            return
        self._spawn(self._alert_callback(text))

    # ------------------------------------------------------------------
    # Sending (the API process, or workers.py in its place)
    # ------------------------------------------------------------------

    def start(self, recorder_key: Optional[str] = None) -> None:
        """Start this publisher through the same coordinator used by the API and workers process."""
        self.start_publishers([self], recorder_key=recorder_key)

    def start_publishers(
        self, publishers: list["VerdictPublisher"], recorder_key: Optional[str] = None
    ) -> None:
        """Start one drain task for the configured chain publishers, in which each chain drains on its own."""
        if self._drain_task is not None:
            return
        enabled = []
        for publisher in publishers:
            if not publisher.is_onchain_enabled():
                continue
            key = (
                recorder_key
                if publisher is self and len(publishers) == 1 and recorder_key is not None
                else os.getenv(f"{publisher._env_prefix}_RECORDER_PRIVATE_KEY", "")
            )
            if not key:
                logger.warning(
                    "%s verdict registry: not sending (%s_RECORDER_PRIVATE_KEY is not set); verdicts stay pending",
                    publisher._log_chain_name,
                    publisher._env_prefix,
                )
                continue
            try:
                publisher._account = Account.from_key(key)
            except Exception as e:
                logger.error(
                    "%s verdict registry: not sending (invalid recorder key: %s)",
                    publisher._log_chain_name,
                    type(e).__name__,
                )
                continue
            publisher.recorder = publisher._account.address
            publisher._wake = asyncio.Event()
            logger.info("%s verdict registry: recorder ready %s", publisher._log_chain_name, publisher.recorder)
            enabled.append(publisher)
        self._drain_publishers = enabled
        if enabled:
            self._drain_task = asyncio.create_task(self._drain_each(enabled))

    def stop(self) -> "asyncio.Future":
        """Stop the drain now; returns an awaitable that finishes when sends already under way have finished.

        The drain loop is cancelled at once. Sends are shielded, so they run on; awaiting the result waits for them
        for at most STOP_TIMEOUT_SECONDS, which lets them record their outcome before the database closes. Then the
        sender lease is released if the database still names this process, unless a send is still under way: the
        lease then expires on its own.
        """
        drain_task, self._drain_task = self._drain_task, None
        if drain_task is not None:
            drain_task.cancel()
        return asyncio.ensure_future(self._stop_sending(drain_task))

    async def _stop_sending(self, drain_task: Optional[asyncio.Task]) -> None:
        # The cancelled drain ends first, so nothing below runs beside its last database call.
        if drain_task is not None:
            await asyncio.gather(drain_task, return_exceptions=True)
        # Each publisher's sends are waited for once, together, so a stop waits at most STOP_TIMEOUT_SECONDS.
        settling = list(dict.fromkeys([self, *self._drain_publishers]))
        await asyncio.gather(*(publisher._settle_sends() for publisher in settling))
        if drain_task is None or any(publisher._tasks for publisher in settling):
            return
        for publisher in self._drain_publishers:
            try:
                await publisher._db.release_sender_lease(publisher._lease_name, publisher._lease_holder)
            except Exception as e:
                logger.warning("%s verdict registry: sender lease not released: %s", publisher._log_chain_name, type(e).__name__)

    async def _settle_sends(self) -> None:
        tasks = list(self._tasks)
        if not tasks:
            return
        _, unfinished = await asyncio.wait(tasks, timeout=STOP_TIMEOUT_SECONDS)
        if unfinished:
            logger.warning(
                "Verdict drain stopped with %d send(s) still under way; their claims are resolved at the next start",
                len(unfinished),
            )

    async def _drain_each(self, publishers: list["VerdictPublisher"]) -> None:
        """Drain each chain on its own task, so a slow chain never holds up another's sends. When one drain ends,
        the others are stopped and its error, if any, is raised here."""
        drains = [asyncio.create_task(self._drain_publishers_loop([publisher])) for publisher in publishers]
        try:
            ended, _ = await asyncio.wait(drains, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for drain in drains:
                drain.cancel()
            await asyncio.gather(*drains, return_exceptions=True)
        for drain in ended:
            drain.result()

    async def _drain_publishers_loop(self, publishers: list["VerdictPublisher"]) -> None:
        retry_after = {publisher: 0.0 for publisher in publishers}
        backoffs = {publisher: 0.0 for publisher in publishers}
        lease_retry_after = {publisher: 0.0 for publisher in publishers}
        held = set()
        keepers = {}
        try:
            while True:
                now = time.monotonic()
                immediate = False
                for publisher in publishers:
                    if publisher in held or now < lease_retry_after[publisher]:
                        continue
                    try:
                        acquired, expiry = await publisher._take_lease()
                    except Exception as e:
                        if publisher.chain_id == 4663:
                            logger.error(
                                "Robinhood verdict registry: not sending, the sender lease could not be taken: %s",
                                type(e).__name__,
                            )
                        else:
                            logger.error(
                                "%s verdict registry: not sending, the sender lease could not be taken: %s",
                                publisher._log_chain_name,
                                type(e).__name__,
                            )
                        lease_retry_after[publisher] = now + LEASE_SECONDS
                        continue
                    if not acquired:
                        until_expiry = expiry - time.time()
                        if until_expiry > 0:
                            retry_delay = min(LEASE_SECONDS, until_expiry)
                        elif expiry > 0:
                            retry_delay = 0.01
                        else:
                            retry_delay = min(LEASE_SECONDS, DRAIN_POLL_SECONDS)
                        lease_retry_after[publisher] = now + retry_delay
                        continue
                    held.add(publisher)
                    lease_retry_after[publisher] = 0.0
                    publisher._lease_lost = False
                    logger.info("%s verdict registry: sending as recorder %s", publisher._log_chain_name, publisher.recorder)
                    keepers[publisher] = asyncio.create_task(publisher._keep_lease(expiry))
                    await publisher._recover_claims()
                    await publisher._reconcile()

                now = time.monotonic()
                for publisher in publishers:
                    if publisher not in held:
                        continue
                    keeper = keepers[publisher]
                    if publisher._lease_lost or keeper.done():
                        publisher._lease_lost = True
                        if publisher.chain_id == 4663:
                            logger.error(
                                "Robinhood verdict registry: stopped sending until this process holds the sender lease again"
                            )
                        else:
                            logger.error(
                                "%s verdict registry: stopped sending until this process holds the sender lease again",
                                publisher._log_chain_name,
                            )
                        held.remove(publisher)
                        keeper.cancel()
                        await asyncio.gather(keeper, return_exceptions=True)
                        keepers.pop(publisher)
                        publisher._lease_lost = False
                        lease_retry_after[publisher] = 0.0
                        continue
                    if now < retry_after[publisher]:
                        continue
                    publisher._wake.clear()
                    try:
                        outcome = await publisher.drain_once()
                    except Exception as e:
                        stack = "".join(traceback.format_tb(e.__traceback__))
                        if publisher.chain_id == 4663:
                            logger.error("Verdict drain failed: %s\n%s", type(e).__name__, stack)
                        else:
                            logger.error(
                                "%s verdict registry: drain failed: %s\n%s",
                                publisher._log_chain_name,
                                type(e).__name__,
                                stack,
                            )
                        outcome = "error"
                    if outcome == "error":
                        await publisher._recover_claims()
                    if publisher._lease_lost:
                        immediate = True
                        continue
                    if outcome in ("retry", "error"):
                        backoffs[publisher] = min(
                            max(backoffs[publisher] * 2, DRAIN_BACKOFF_SECONDS),
                            DRAIN_MAX_BACKOFF_SECONDS,
                        )
                        retry_after[publisher] = time.monotonic() + backoffs[publisher]
                    elif outcome == "capped":
                        retry_after[publisher] = time.monotonic() + publisher._rate_wait()
                    elif outcome == "done":
                        backoffs[publisher] = 0.0
                        immediate = True
                    else:
                        recovered = await publisher._recover_claims()
                        reconciled = await publisher._reconcile()
                        if recovered or reconciled:
                            immediate = True

                now = time.monotonic()
                waits = [0.0 if immediate else DRAIN_POLL_SECONDS]
                for publisher in publishers:
                    if publisher not in held:
                        waits.append(max(0.0, lease_retry_after[publisher] - now))
                    elif retry_after[publisher] > now:
                        waits.append(retry_after[publisher] - now)
                timeout = min(waits)
                wakes = [
                    asyncio.create_task(publisher._wake.wait())
                    for publisher in held
                    if retry_after[publisher] <= now and not publisher._lease_lost
                ]
                tasks = [*wakes, *(keepers[publisher] for publisher in held)]
                if tasks:
                    wake_set = set(wakes)
                    try:
                        await asyncio.wait(tasks, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
                    finally:
                        pending_wakes = [task for task in wake_set if not task.done()]
                        for task in pending_wakes:
                            task.cancel()
                        await asyncio.gather(*wakes, return_exceptions=True)
                else:
                    await asyncio.sleep(timeout)
        finally:
            for publisher, keeper in keepers.items():
                publisher._lease_lost = False
                keeper.cancel()
            await asyncio.gather(*keepers.values(), return_exceptions=True)

    async def _take_lease(self) -> Tuple[bool, float]:
        """Take or renew the sender lease. Returns whether this process holds it, and when it expires (Unix time)."""
        holder, expires_at = await self._db.take_sender_lease(
            self._lease_name, self._lease_holder, LEASE_SECONDS
        )
        # No holder: another drain released the lease between the take and its read; ask again.
        if holder is not None and holder != self._lease_holder:
            logger.warning(
                "%s verdict registry: not sending, %s holds the sender lease until %s UTC",
                self._log_chain_name,
                holder,
                time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(expires_at)),
            )
        return holder == self._lease_holder, expires_at

    async def _keep_lease(self, held_until: float) -> None:
        """Renew the lease every LEASE_RENEW_SECONDS. Returns once another drain holds it, or once the lease could
        run out before the next renewal fails, so the drain stops before the lease can pass to another drain.

        held_until is the lease's expiry in Unix time, as stored, so a clock step moves it with the clock every
        drain compares it against.
        """
        while True:
            await asyncio.sleep(LEASE_RENEW_SECONDS)
            if self._lease_running_out(held_until):
                return
            try:
                held, expires_at = await self._take_lease()
            except Exception as e:
                logger.error(
                    "%s verdict registry: sender lease not renewed: %s",
                    self._log_chain_name,
                    type(e).__name__,
                )
                if self._lease_running_out(held_until):
                    return
                continue
            if not held:
                return
            held_until = expires_at

    @staticmethod
    def _lease_running_out(held_until: float) -> bool:
        """True once a renewal that waits the whole DB_LOCK_WAIT_SECONDS for the lock and then fails would leave
        less than one renewal period of the lease."""
        return time.time() + DB_LOCK_WAIT_SECONDS >= held_until - LEASE_RENEW_SECONDS

    def _rate_wait(self) -> float:
        """Seconds until a send slot frees up in the MAX_RECORDS_PER_HOUR window, 0 if one is free."""
        now = time.monotonic()
        while self._sent_at and now - self._sent_at[0] >= RATE_WINDOW_SECONDS:
            self._sent_at.popleft()
        if len(self._sent_at) < MAX_RECORDS_PER_HOUR:
            return 0.0
        return RATE_WINDOW_SECONDS - (now - self._sent_at[0])

    async def drain_once(self) -> str:
        """Claim and record the oldest pending row.

        Returns "idle" (nothing pending), "capped" (rate cap reached; rows wait), "done" (the row reached a
        recorded outcome), "retry" (the row went back to pending: a failure before broadcasting, or an earlier
        transaction that may still land) or "error" (the send failed unexpectedly, for example in the database,
        and may have left the claim `sending`).
        """
        if self._account is None:
            return "idle"
        row = await self._db.claim_next_pending_verdict(self.chain_id)
        if row is None:
            return "idle"
        if await self._drop_ineligible(row):
            return "done"
        if self._rate_wait() > 0:
            await self._db.release_verdict_claim(row["id"])
            return "capped"
        self._sent_at.append(time.monotonic())
        # Shielded: cancelling the drain (stop()) never interrupts prepare -> store -> broadcast -> record outcome.
        return await asyncio.shield(self._spawn(self._send_safely(row)))

    async def _send_safely(self, row: dict) -> str:
        try:
            return await self._send(row)
        except Exception as e:
            logger.error(
                "Verdict send failed: %s\n%s",
                type(e).__name__,
                "".join(traceback.format_tb(e.__traceback__)),
            )
            return "error"

    async def _recover_claims(self) -> int:
        """Resolve rows left `sending` for RECONCILE_AFTER_SECONDS: finish the mined ones, queue the rest again.

        The delay gives a lagging replica time to show a transaction that was mined. A row queued again goes
        through the checks in _prepare, so it is never recorded twice. Returns how many rows were queued again.
        Never raises.
        """
        released = 0
        try:
            rows = await self._db.get_claimed_verdicts(
                self.chain_id, time.time() - RECONCILE_AFTER_SECONDS
            )
            transactions = await self._db.get_verdict_transactions([row["id"] for row in rows])
            for row in rows:
                hashes = _row_hashes(row, transactions.get(row["id"], []))
                status, tx_hash = None, None
                if hashes:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=RPC_TIMEOUT_SECONDS)
                    ) as session:
                        status, tx_hash = await self._mined(session, hashes)
                if status is not None:
                    await self._db.update_verdict_onchain(
                        row["id"], status, tx_hash=tx_hash, registry=self.registry
                    )
                elif not hashes or row["attempts"] < MAX_SEND_ATTEMPTS:
                    await self._db.release_verdict_claim(row["id"])
                    released += 1
                    status = "pending"
                else:
                    await self._db.update_verdict_onchain(
                        row["id"], "unconfirmed", tx_hash=row["tx_hash"], onchain_error="ClaimInterrupted"
                    )
                    status = "unconfirmed"
                logger.warning("Verdict claim %d was interrupted: %s", row["id"], status)
        except Exception as e:
            logger.error("Verdict claim recovery failed: %s", type(e).__name__)
        return released

    async def _reconcile(self) -> int:
        """Look up receipts for every transaction of old unresolved records; finish the mined ones.

        The rest are queued again while under MAX_SEND_ATTEMPTS; a row at the cap is only looked at again later.
        Returns how many rows were queued again. Never raises.
        """
        try:
            rows = await self._db.get_unresolved_verdicts(
                self.chain_id, time.time() - RECONCILE_AFTER_SECONDS, RECONCILE_BATCH
            )
            if not rows:
                return 0
            transactions = await self._db.get_verdict_transactions([row["id"] for row in rows])
            hashes = {row["id"]: _row_hashes(row, transactions.get(row["id"], [])) for row in rows}
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=RPC_TIMEOUT_SECONDS)
            ) as session:
                receipts = iter(
                    await asyncio.wait_for(
                        self._rpc(
                            session,
                            [("eth_getTransactionReceipt", [h]) for row in rows for h in hashes[row["id"]]],
                        ),
                        RECEIPT_TIMEOUT_SECONDS,
                    )
                )
            requeued = 0
            for row in rows:
                stored = await self._db.get_verdict_evidence(row["id"])
                mined = None
                for tx_hash in hashes[row["id"]]:
                    status = _receipt_outcome(next(receipts))
                    if status is not None and mined is None:
                        mined = status, tx_hash
                if mined is not None:
                    status, tx_hash = mined
                    await self._db.update_verdict_onchain(
                        row["id"], status, tx_hash=tx_hash, onchain_error=stored["onchain_error"]
                        if stored["onchain_status"] == "dropped" else None, registry=self.registry,
                    )
                    logger.info("Verdict record %d reconciled: %s", row["id"], status)
                elif stored["onchain_status"] == "dropped":
                    await self._db.touch_verdict(row["id"])
                elif row["attempts"] < MAX_SEND_ATTEMPTS:
                    await self._db.requeue_verdict(row["id"])
                    requeued += 1
                else:
                    await self._db.touch_verdict(row["id"])
            return requeued
        except Exception as e:
            logger.warning("Verdict reconciliation failed: %s", type(e).__name__)
            return 0

    async def _send(self, row: dict) -> str:
        evidence_id = row["id"]
        data = (
            "0x"
            + (
                RECORD_SELECTOR
                + encode(
                    ["address", "uint8", "bytes32", "uint64"],
                    [
                        row["subject"],
                        int(Verdict[row["verdict"]]),
                        bytes.fromhex(row["evidence_hash"][2:]),
                        row["observed_block"],
                    ],
                )
            ).hex()
        )
        transactions = (await self._db.get_verdict_transactions([evidence_id])).get(evidence_id, [])
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=RPC_TIMEOUT_SECONDS)
        ) as session:
            async with self._nonce_lock:
                if await self._drop_ineligible(row):
                    return "done"
                try:
                    prepared = await asyncio.wait_for(
                        self._prepare(session, row, transactions, data), PHASE_TIMEOUT_SECONDS
                    )
                except Exception as e:
                    # Nothing new has left this process, so returning the row to the queue is always safe.
                    reason = e.reason if isinstance(e, RecordFailed) else type(e).__name__
                    await self._db.release_verdict_claim(evidence_id)
                    self._note_wait(reason)
                    if reason in ("InsufficientFunds", "FeeCapExceeded") and not self._failure_alerted:
                        self._failure_alerted = True
                        detail = (
                            (
                                "the gas price is above the configured cap"
                                if self.chain_id == 677
                                else "the base fee is above the configured cap"
                            )
                            if reason == "FeeCapExceeded"
                            else "the recorder has insufficient funds"
                        )
                        self._alert(
                        f"*ShieldBot verdict recorder cannot record* on {self._alert_chain_label}: {reason}\n"
                            f"`{self.recorder}`\n"
                            f"{detail}; recording is paused; queued verdicts are retried and dropped "
                            f"once their observation is older than {MAX_OBSERVATION_AGE_SECONDS // 60} minutes"
                        )
                    logger.warning("Verdict record deferred: %s", reason)
                    return "retry"
                self._waits = 0
                self._failure_alerted = False
                if prepared[0] == "mined":
                    # One of the row's earlier transactions was mined after all; nothing is sent.
                    _, status, tx_hash = prepared
                    await self._db.update_verdict_onchain(
                        evidence_id, status, tx_hash=tx_hash, registry=self.registry
                    )
                    self._resends.pop(evidence_id, None)
                    logger.info("Verdict record %s by an earlier transaction: tx=%s", status, tx_hash)
                    return "done"
                # Only the lease holder stores and broadcasts, and only under a lease with a lock wait and the
                # broadcast phase still to run. Taken before the last freshness check, so no write separates that
                # check from the store.
                try:
                    held, expires_at = await self._take_lease()
                except Exception as e:
                    # The lease could not be written; the renewal loop's deadline still guards it, so only this row
                    # waits. What was signed is discarded; nothing has been stored or broadcast.
                    logger.error("Verdict record deferred: sender lease not renewed: %s", type(e).__name__)
                    await self._db.release_verdict_claim(evidence_id)
                    return "retry"
                if held and expires_at < time.time() + DB_LOCK_WAIT_SECONDS + PHASE_TIMEOUT_SECONDS:
                    logger.error("Verdict record deferred: the sender lease expires too soon for a broadcast")
                    held = False
                if not held:
                    # Refused: what was signed is discarded, and the drain stops claiming until it has taken the
                    # lease again.
                    self._lease_lost = True
                    await self._db.release_verdict_claim(evidence_id)
                    return "retry"
                if await self._drop_ineligible(row):
                    return "done"
                _, raw, nonce, max_fee = prepared
                tx_hash = "0x" + keccak(raw).hex()
                if any(transaction["tx_hash"] == tx_hash for transaction in transactions):
                    self._note_resend(evidence_id, tx_hash)
                # Stored, with its bytes and fee, before the broadcast, so every later check covers it.
                if not await self._db.set_verdict_tx_hash(
                    evidence_id, tx_hash, nonce, raw.hex(), max_fee
                ):
                    logger.error("Verdict record %d is no longer claimed; not broadcasting", evidence_id)
                    return "done"
                try:
                    await asyncio.wait_for(
                        self._rpc(session, [("eth_sendRawTransaction", ["0x" + raw.hex()])], row=row),
                        PHASE_TIMEOUT_SECONDS,
                    )
                    accepted, rejected, error = True, False, None
                except ObservationDropped:
                    return "done"
                except Exception as e:
                    # A JSON-RPC error is a definite refusal; anything else may have reached the node.
                    rejected = isinstance(e, RecordFailed) and e.rejected
                    accepted = False
                    error = e.reason if isinstance(e, RecordFailed) else type(e).__name__
            await asyncio.sleep(RECEIPT_DELAY_SECONDS)
            hashes = _row_hashes({"tx_hash": tx_hash}, transactions)
            status, mined_hash = await self._mined(session, hashes)
        if status is not None:
            tx_hash, error = mined_hash, None
        elif accepted:
            status = "submitted"
        elif rejected:
            status = "failed"
        else:
            status = "unconfirmed"
        await self._db.update_verdict_onchain(
            evidence_id, status, tx_hash=tx_hash, onchain_error=error, registry=self.registry
        )
        if status in ("confirmed", "reverted"):
            self._resends.pop(evidence_id, None)
        if error is None:
            logger.info("Verdict record %s: tx=%s subject=%s", status, tx_hash, row["subject"])
        else:
            logger.warning("Verdict record %s: %s", status, error)
        return "done"

    async def _drop_ineligible(self, row: dict) -> bool:
        stored = await self._db.get_verdict_evidence(row["id"])
        observed_at = json.loads(stored["canonical"]).get("observed_at")
        reason = None
        if (stored["registry"] or "").lower() != self.registry.lower():
            reason = "RegistryChanged"
        elif type(observed_at) is not int or observed_at <= 0:
            reason = "MissingObservationTime"
        else:
            # Any newer measurement supersedes this one, whichever registry it was queued for (or none).
            newest = await self._db.get_newest_verdict_observation(self.chain_id, row["subject"])
            # No awaited read may separate this clock check from the broadcast decision.
            now = time.time()
            if observed_at > now:
                reason = "FutureObservation"
            elif now - observed_at > MAX_OBSERVATION_AGE_SECONDS:
                reason = "StaleObservation"
            elif newest is not None and newest["id"] != row["id"]:
                reason = "SupersededObservation"
        if reason is None:
            return False
        await self._db.update_verdict_onchain(
            row["id"], "dropped", tx_hash=stored["tx_hash"], onchain_error=reason
        )
        self._resends.pop(row["id"], None)
        logger.warning("Verdict record %d dropped: %s", row["id"], reason)
        return True

    def _note_wait(self, reason: str) -> None:
        """Count consecutive waits on an earlier transaction and say so loudly when they go on."""
        if reason != "PreviousTransactionPending":
            return
        self._waits += 1
        if self._waits % WAIT_ALARM_AFTER == 0:
            logger.error(
                "Verdict drain has waited %d times in a row for an earlier transaction at the same nonce; "
                "check the recorder's pending transactions",
                self._waits,
            )

    def _note_resend(self, evidence_id: int, tx_hash: str) -> None:
        """Count broadcasts of the same signed bytes and say so loudly when a node never sequences them."""
        previous, count = self._resends.get(evidence_id, (None, 0))
        count = count + 1 if previous == tx_hash else 1
        self._resends[evidence_id] = (tx_hash, count)
        if count >= RESEND_ALARM_AFTER:
            logger.warning(
                "Verdict record %d has re-sent %s %d times with no receipt and no other transaction at its "
                "nonce; check whether the node forwards it",
                evidence_id, tx_hash, count,
            )

    async def _prepare(self, session, row: dict, transactions: list, data: str) -> tuple:
        """Decide what to broadcast for a claimed row, in one RPC batch read under the nonce lock.

        Returns ("mined", status, tx_hash) when one of the row's earlier transactions is on-chain, or
        ("send", raw transaction, nonce, maxFeePerGas). Raises RecordFailed when nothing can be sent safely now.
        """
        sender = self.recorder
        hashes = _row_hashes(row, transactions)
        calls = [
            ("eth_getTransactionCount", [sender, "pending"]),
            ("eth_getBlockByNumber", ["latest", False]),
            ("eth_estimateGas", [{"from": sender, "to": self.registry, "data": data}]),
            ("eth_getBalance", [sender, "latest"]),
        ]
        if self.chain_id == 677:
            calls.append(("eth_gasPrice", []))
        if hashes:
            calls.append(("eth_getTransactionCount", [sender, "latest"]))
            calls += [("eth_getTransactionReceipt", [tx_hash]) for tx_hash in hashes]
        results = await self._rpc(session, calls)
        nonce, estimate, balance = _quantity(results[0]), _quantity(results[2]), _quantity(results[3])
        block = results[1]
        base_fee = _quantity(block.get("baseFeePerGas")) if isinstance(block, dict) else None
        if None in (nonce, estimate, balance, base_fee):
            raise RecordFailed("MalformedRPCResponse")
        if hashes:
            latest_index = 4 if self.chain_id == 4663 else 5
            receipt_offset = latest_index + 1
            for tx_hash, receipt in zip(hashes, results[receipt_offset:]):
                status = _receipt_outcome(receipt)
                if status is not None:
                    return "mined", status, tx_hash
            latest = _quantity(results[latest_index])
            if latest is None:
                raise RecordFailed("MalformedRPCResponse")
            nonces = [transaction["nonce"] for transaction in transactions]
            if row["nonce"] is not None:
                nonces.append(row["nonce"])
            last = max(nonces)
            stored = []
            if latest <= last:
                # Nonce `last` is unused, so our transaction there may still be mined: anything sent now takes
                # nonce `last` too, and only while nothing is pending there.
                if nonce != last:
                    raise RecordFailed("PreviousTransactionPending")
                stored = [t for t in transactions if t["nonce"] == last and t["raw_tx"]]
                fee = stored[-1]["max_fee_per_gas"] if stored else None
                if self.chain_id == 4663 and fee is not None and fee >= base_fee:
                    return "send", bytes.fromhex(stored[-1]["raw_tx"]), last, fee
                # Without usable stored bytes (none kept, or a fee that is unknown or below the base fee, which
                # the node would refuse), sign a replacement at nonce `last` at the current fee: at most one
                # transaction per nonce can be mined, and every hash of the row is checked, so it never records
                # twice.
            # Every nonce the row used is taken, and no transaction of the row is mined, so none of them can
            # ever be: a new transaction at the next nonce is safe.
        if self.chain_id == 4663 and base_fee > MAX_FEE_PER_GAS_WEI:
            raise RecordFailed("FeeCapExceeded")
        gas = estimate * 6 // 5
        if gas > MAX_GAS_LIMIT:
            raise RecordFailed("GasCapExceeded")
        if self.chain_id == 677:
            gas_price = _quantity(results[4])
            if gas_price is None or gas_price <= 0:
                raise RecordFailed("MalformedRPCResponse")
            if gas_price > BOTCHAIN_MAX_GAS_PRICE_WEI:
                raise RecordFailed("FeeCapExceeded")
            if hashes and stored and stored[-1]["max_fee_per_gas"] is not None:
                minimum_bump = (stored[-1]["max_fee_per_gas"] * 110 + 99) // 100
                gas_price = max(gas_price, minimum_bump)
                if gas_price > BOTCHAIN_MAX_GAS_PRICE_WEI:
                    raise RecordFailed("FeeCapExceeded")
            max_fee = gas_price
        else:
            max_fee = min(base_fee * 2, MAX_FEE_PER_GAS_WEI)
        reservation = gas * max_fee
        if balance < self._low_balance_records * reservation and not self._low_funds_alerted:
            self._low_funds_alerted = True
            balance_eth = f"{balance // 10**18}.{balance % 10**18 * 1_000_000 // 10**18:06d}"
            from utils.chain_info import get_native_symbol

            native_symbol = get_native_symbol(self.chain_id)
            self._alert(
                f"*ShieldBot verdict recorder is running low* on {self._alert_chain_label}\n"
                f"`{self.recorder}`\n"
                f"Balance: {balance_eth} {native_symbol}; about {balance // reservation} records left "
                f"at the current fee reservation"
            )
        elif balance >= 2 * self._low_balance_records * reservation:
            self._low_funds_alerted = False
        if balance < reservation:
            raise RecordFailed("InsufficientFunds")
        transaction = {
                "chainId": self.chain_id,
                "nonce": nonce,
                "to": self.registry,
                "value": 0,
                "data": data,
                "gas": gas,
            }
        if self.chain_id == 677:
            transaction["gasPrice"] = max_fee
        else:
            transaction.update({
                "type": 2,
                "maxFeePerGas": max_fee,
                "maxPriorityFeePerGas": 0,
            })
        signed = self._account.sign_transaction(transaction)
        # eth-account renamed rawTransaction to raw_transaction; HexBytes.hex() changed prefix, so use bytes.
        raw = bytes(getattr(signed, "raw_transaction", None) or signed.rawTransaction)
        return "send", raw, nonce, max_fee

    async def _mined(self, session, hashes: list) -> tuple:
        """One bounded batch of receipt lookups: (status, tx_hash) of a mined transaction, else (None, None)."""
        try:
            receipts = await asyncio.wait_for(
                self._rpc(session, [("eth_getTransactionReceipt", [tx_hash]) for tx_hash in hashes]),
                RECEIPT_TIMEOUT_SECONDS,
            )
        except Exception as e:
            logger.warning("Verdict receipt unavailable: %s", type(e).__name__)
            return None, None
        for tx_hash, receipt in zip(hashes, receipts):
            status = _receipt_outcome(receipt)
            if status is not None:
                return status, tx_hash
        return None, None

    async def _rpc(self, session, calls: list, row: Optional[dict] = None) -> list:
        """POST one JSON-RPC request or batch and return each result in order.

        HTTP 429 and JSON-RPC rate-limit errors are retried with exponential backoff; any other failure raises
        RecordFailed with a class-only reason.
        """
        body = [
            {"jsonrpc": "2.0", "id": index, "method": method, "params": params}
            for index, (method, params) in enumerate(calls)
        ]
        for attempt in range(RPC_ATTEMPTS):
            if attempt:
                logger.warning(
                    "Verdict record RPC rate limited (attempt %d/%d)", attempt, RPC_ATTEMPTS
                )
                await asyncio.sleep(RPC_BACKOFF_SECONDS * 2 ** (attempt - 1))
            if row is not None and await self._drop_ineligible(row):
                raise ObservationDropped
            async with session.post(
                self._rpc_url, json=body if len(body) > 1 else body[0]
            ) as response:
                status = response.status
                payload = await response.json(content_type=None) if status == 200 else None
            if status == 429:
                continue
            if status != 200:
                raise RecordFailed(f"HTTP {status}")
            rows = payload if isinstance(payload, list) else [payload]
            if (
                len(rows) != len(body)
                or not all(isinstance(row, dict) for row in rows)
                or not all(type(row.get("id")) is int for row in rows)
                or {row.get("id") for row in rows} != set(range(len(body)))
            ):
                raise RecordFailed("MalformedRPCResponse")
            if any(_rate_limited(row.get("error")) for row in rows):
                continue
            by_id = {row["id"]: row for row in rows}
            results = []
            for index, (method, _) in enumerate(calls):
                row = by_id[index]
                if row.get("error") is not None:
                    code = row["error"].get("code") if isinstance(row["error"], dict) else None
                    raise RecordFailed(
                        f"{method} JSON-RPC error {code if type(code) is int else None}",
                        rejected=True,
                    )
                if "result" not in row:
                    raise RecordFailed("MalformedRPCResponse")
                results.append(row["result"])
            return results
        raise RecordFailed("RateLimited")


def _repeats(previous: dict, payload: dict) -> bool:
    """True when a stored verdict says the same as this one and is queued, being sent, or on-chain."""
    if previous["onchain_status"] not in SETTLED_STATUSES:
        return False
    stored = json.loads(previous["canonical"])
    observed_at = stored.get("observed_at", 0)
    if (
        payload.get("observed_at", 0) > observed_at
        and time.time() - observed_at >= VERDICT_REFRESH_SECONDS
    ):
        return False
    return _verdict_only(stored) == _verdict_only(payload)


# What two runs of the same measurement move, while the verdict they reach does not:
#   scanned_at                  the clock at the scan
#   observed_at                 the oldest contributing measurement's clock
#   observed_block              the block the simulation ran at
#   honeypot.simulation_block   the same block again
#   honeypot.reason             names that block ("... pool ... at block N: sell reverted: ...")
#   coverage_reasons            carries the same sentence for an incomplete scan
# What is left decides the verdict: verdict, status, coverage, rug_probability, and the honeypot's
# is_honeypot, can_buy, can_sell, buy_tax, sell_tax, simulation_failed and field_providers.
_MEASUREMENT_FIELDS = ("scanned_at", "observed_at", "observed_block", "coverage_reasons")
_HONEYPOT_MEASUREMENT_FIELDS = ("simulation_block", "reason")


def _verdict_only(payload: dict) -> dict:
    """An evidence document without how or when it was measured, so two scans of one token compare equal."""
    stripped = {
        key: value for key, value in payload.items() if key not in _MEASUREMENT_FIELDS
    }
    honeypot = stripped.get("honeypot")
    if isinstance(honeypot, dict):
        stripped["honeypot"] = {
            key: value for key, value in honeypot.items()
            if key not in _HONEYPOT_MEASUREMENT_FIELDS
        }
    return stripped


def _receipt_outcome(receipt) -> Optional[str]:
    """"confirmed" or "reverted" for a mined transaction's receipt, None when there is no usable receipt."""
    status = receipt.get("status") if isinstance(receipt, dict) else None
    return {"0x1": "confirmed", "0x0": "reverted"}.get(status)


def _quantity(value) -> Optional[int]:
    """A JSON-RPC hex quantity as an int, or None if it is not one."""
    if not isinstance(value, str) or not QUANTITY_RE.fullmatch(value):
        return None
    return int(value, 16)


def _rate_limited(error) -> bool:
    """True for a JSON-RPC error that signals rate limiting (HTTP-style 429 or -32005, or its usual wording)."""
    if not isinstance(error, dict):
        return False
    message = str(error.get("message", "")).lower()
    return (
        error.get("code") in (429, -32005)
        or "rate limit" in message
        or "too many requests" in message
    )


def _row_hashes(row: dict, transactions: list) -> list:
    """Every transaction hash a row has broadcast, oldest first, including the row's latest."""
    hashes = list(dict.fromkeys(transaction["tx_hash"] for transaction in transactions))
    if row.get("tx_hash") is not None and row["tx_hash"] not in hashes:
        hashes.append(row["tx_hash"])
    return hashes
