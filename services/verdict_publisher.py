"""Publishes ShieldBot verdicts: stores every evidence document and records Robinhood Chain verdicts on-chain.

Every process (API, hunter, bot) calls publish(), which only STORES the canonical evidence document
(core.verdict_evidence). When ROBINHOOD_VERDICT_REGISTRY is set, a Robinhood Chain (4663) row is stored as
`pending`: an outbox entry for ShieldBotVerdictRegistry.record().

Exactly one process sends: the API process calls start(), which reads ROBINHOOD_RECORDER_PRIVATE_KEY and runs a
drain that records pending rows oldest-first. With BACKGROUND_WORKERS=external workers.py calls it instead and
the API does not. No other code path reads the key, so the bot never sends. A drain sends only while it holds the
sender lease in the database, so two drains started by mistake on one database never race for the recorder's
nonces: the second waits until the first's lease expires.

Each row moves through onchain_status:
  off          stored only (another chain, or no registry configured)
  pending      waiting for the drain
  dropped      observation missing, stale, future-dated or superseded; never broadcast again
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
from typing import Optional

import aiohttp
from eth_abi import encode
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from core.verdict_evidence import Verdict, build_evidence, canonical_bytes

logger = logging.getLogger(__name__)

CHAIN_ID = 4663
DEFAULT_RPC_URL = "https://rpc.mainnet.chain.robinhood.com"
# `cast sig "record(address,uint8,bytes32,uint64)"` = 0xf160da27
RECORD_SELECTOR = keccak(text="record(address,uint8,bytes32,uint64)")[:4]

# One 4663 scan reserves 22 requests of the watch's shared 1 rps RPC budget (services.rpc_guard,
# agent.hunter.SCAN_REQUEST_COST), so a saturated watch produces at most about 163 scans an hour, and an
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
# Only the drain holding this lease in the database sends. The holder renews it every LEASE_RENEW_SECONDS, and
# stops sending once a renewal finds another holder, or once renewals have failed until less than one renewal
# period of the lease is left. A holder that dies keeps the lease until LEASE_SECONDS after its last renewal; a
# drain waiting for it asks again every LEASE_SECONDS.
LEASE_NAME = f"verdict-drain:{CHAIN_ID}"
LEASE_SECONDS = 60.0
LEASE_RENEW_SECONDS = 15.0
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
    """Stores verdict evidence; in the process that runs the drain, also records Robinhood Chain verdicts on-chain."""

    def __init__(self, db, rpc_url: Optional[str] = None, registry_address: Optional[str] = None):
        self._db = db
        self._rpc_url = rpc_url or os.getenv("ROBINHOOD_RPC_URL") or DEFAULT_RPC_URL
        registry = (
            registry_address
            if registry_address is not None
            else os.getenv("ROBINHOOD_VERDICT_REGISTRY", "")
        )
        self.registry = None
        self.recorder = None
        self._account = None
        self._nonce_lock = asyncio.Lock()
        self._sent_at = deque()
        self._tasks = set()
        self._drain_task = None
        self._wake = None
        self._lease_holder = None
        self._holds_lease = False
        # Set when the lease is lost: the drain loop then returns before it claims another row.
        self._lease_lost = False
        self._waits = 0
        # Per row, the bytes last broadcast again and how often in a row: {evidence_id: (tx_hash, count)}.
        self._resends = {}
        if not registry:
            logger.info(
                "Robinhood verdict registry: disabled (set ROBINHOOD_VERDICT_REGISTRY to enable)"
            )
            return
        try:
            self.registry = to_checksum_address(registry)
        except ValueError as e:
            logger.error(
                "Robinhood verdict registry: disabled (invalid ROBINHOOD_VERDICT_REGISTRY: %s)",
                type(e).__name__,
            )
            return
        logger.info("Robinhood verdict registry: verdicts queued for %s", self.registry)

    def is_onchain_enabled(self) -> bool:
        """True when Robinhood Chain verdicts are queued for the registry."""
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
        self, chain_id: int, subject: str, scan_result: dict, honeypot_data: Optional[dict] = None
    ) -> Optional[dict]:
        """Store the evidence for one scan; a Robinhood Chain verdict is queued for the drain.

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
            queued = chain_id == CHAIN_ID and self.is_onchain_enabled()
            status = "pending" if queued else "off"
            if queued:
                previous = await self._db.get_newest_verdict_observation(
                    chain_id, payload["subject"], include_deduplicated=False
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

    # ------------------------------------------------------------------
    # Sending (the API process, or workers.py in its place)
    # ------------------------------------------------------------------

    def start(self, recorder_key: Optional[str] = None) -> None:
        """Start the drain. Only the API process, or workers.py in its place, calls this: the one on-chain sender."""
        if self._drain_task is not None or not self.is_onchain_enabled():
            return
        key = (
            recorder_key
            if recorder_key is not None
            else os.getenv("ROBINHOOD_RECORDER_PRIVATE_KEY", "")
        )
        if not key:
            logger.warning(
                "Robinhood verdict registry: not sending (ROBINHOOD_RECORDER_PRIVATE_KEY is not set); "
                "verdicts stay pending"
            )
            return
        try:
            self._account = Account.from_key(key)
        except Exception as e:
            # An invalid key is an input boundary; the key or its error text is never logged.
            logger.error(
                "Robinhood verdict registry: not sending (invalid recorder key: %s)",
                type(e).__name__,
            )
            return
        self.recorder = self._account.address
        self._lease_holder = f"{socket.gethostname()}:{os.getpid()}:{secrets.token_hex(4)}"
        self._wake = asyncio.Event()
        self._drain_task = asyncio.create_task(self._drain_under_lease())

    def stop(self) -> "asyncio.Future":
        """Stop the drain now; returns an awaitable that finishes when sends already under way have finished.

        The drain loop is cancelled at once. Sends are shielded, so they run on; awaiting the result waits for them
        for at most STOP_TIMEOUT_SECONDS, which lets them record their outcome before the database closes. Then the
        sender lease is released, unless a send is still under way: the lease then expires on its own.
        """
        if self._drain_task is not None:
            self._drain_task.cancel()
            self._drain_task = None
        return asyncio.ensure_future(self._stop_sending())

    async def _stop_sending(self) -> None:
        await self._settle_sends()
        if not self._holds_lease or self._tasks:
            return
        self._holds_lease = False
        # Best effort: a lease that is not released expires within LEASE_SECONDS.
        try:
            await self._db.release_sender_lease(LEASE_NAME, self._lease_holder)
        except Exception as e:
            logger.warning("Robinhood verdict registry: sender lease not released: %s", type(e).__name__)

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

    async def _drain_under_lease(self) -> None:
        """Run the drain only while this process holds the sender lease, renewing it as the drain runs.

        The lease is renewed beside the drain rather than between its turns: one send can take longer than
        LEASE_SECONDS, and so can the drain's waits after a failure or at the rate cap. A drain that loses the lease
        finishes the send under way, if any, and returns before it claims another row; it is stopped that way
        rather than cancelled, so no write of its own is cut off between a statement and its commit. Then this
        process waits for the lease again.
        """
        while True:
            try:
                held_until = await self._take_lease()
            except Exception as e:
                logger.error(
                    "Robinhood verdict registry: not sending, the sender lease could not be taken: %s",
                    type(e).__name__,
                )
                held_until = None
            if held_until is None:
                await asyncio.sleep(LEASE_SECONDS)
                continue
            logger.info("Robinhood verdict registry: sending as recorder %s", self.recorder)
            drain = asyncio.create_task(self._drain_loop())
            try:
                await self._keep_lease(held_until)
                self._lease_lost = True
                self._wake.set()
                await drain
            finally:
                drain.cancel()
            self._lease_lost = False
            self._holds_lease = False
            logger.error("Robinhood verdict registry: stopped sending, this process no longer holds the sender lease")

    async def _take_lease(self) -> Optional[float]:
        """Take or renew the sender lease; the monotonic time it is held until, or None if another drain holds it."""
        asked_at = time.monotonic()
        holder, expires_at = await self._db.take_sender_lease(LEASE_NAME, self._lease_holder, LEASE_SECONDS)
        if holder != self._lease_holder:
            logger.warning(
                "Robinhood verdict registry: not sending, %s holds the sender lease until %s UTC; asking again in %d s",
                holder,
                time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(expires_at)),
                LEASE_SECONDS,
            )
            return None
        self._holds_lease = True
        return asked_at + LEASE_SECONDS

    async def _keep_lease(self, held_until: float) -> None:
        """Renew the lease every LEASE_RENEW_SECONDS. Returns once another drain holds it, or once failed renewals
        leave less than one renewal period of it, so the drain stops before the lease can pass to another."""
        while True:
            await asyncio.sleep(LEASE_RENEW_SECONDS)
            try:
                renewed = await self._take_lease()
            except Exception as e:
                logger.error("Robinhood verdict registry: sender lease not renewed: %s", type(e).__name__)
                if time.monotonic() >= held_until - LEASE_RENEW_SECONDS:
                    return
                continue
            if renewed is None:
                return
            held_until = renewed

    async def _drain_loop(self) -> None:
        await self._recover_claims()
        await self._reconcile()
        backoff = 0.0
        while not self._lease_lost:
            self._wake.clear()
            try:
                outcome = await self.drain_once()
            except Exception as e:
                logger.error(
                    "Verdict drain failed: %s\n%s",
                    type(e).__name__,
                    "".join(traceback.format_tb(e.__traceback__)),
                )
                outcome = "error"
            if outcome == "done":
                backoff = 0.0
            elif outcome in ("retry", "error"):
                if outcome == "error":
                    # A database failure can leave a claim `sending`; resolve old ones before going on.
                    await self._recover_claims()
                backoff = min(max(backoff * 2, DRAIN_BACKOFF_SECONDS), DRAIN_MAX_BACKOFF_SECONDS)
                await asyncio.sleep(backoff)
            elif outcome == "capped":
                await asyncio.sleep(self._rate_wait())
            else:
                released = await self._recover_claims()
                requeued = await self._reconcile()
                if not (released or requeued):
                    try:
                        await asyncio.wait_for(self._wake.wait(), DRAIN_POLL_SECONDS)
                    except asyncio.TimeoutError:
                        pass

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
        row = await self._db.claim_next_pending_verdict(CHAIN_ID)
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
            rows = await self._db.get_claimed_verdicts(CHAIN_ID, time.time() - RECONCILE_AFTER_SECONDS)
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
                    await self._db.update_verdict_onchain(row["id"], status, tx_hash=tx_hash)
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
                CHAIN_ID, time.time() - RECONCILE_AFTER_SECONDS, RECONCILE_BATCH
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
                        if stored["onchain_status"] == "dropped" else None
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
                    logger.warning("Verdict record deferred: %s", reason)
                    return "retry"
                self._waits = 0
                if prepared[0] == "mined":
                    # One of the row's earlier transactions was mined after all; nothing is sent.
                    _, status, tx_hash = prepared
                    await self._db.update_verdict_onchain(evidence_id, status, tx_hash=tx_hash)
                    self._resends.pop(evidence_id, None)
                    logger.info("Verdict record %s by an earlier transaction: tx=%s", status, tx_hash)
                    return "done"
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
            evidence_id, status, tx_hash=tx_hash, onchain_error=error
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
        if type(observed_at) is not int or observed_at <= 0:
            reason = "MissingObservationTime"
        else:
            newest = await self._db.get_newest_verdict_observation(CHAIN_ID, row["subject"])
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
            for tx_hash, receipt in zip(hashes, results[5:]):
                status = _receipt_outcome(receipt)
                if status is not None:
                    return "mined", status, tx_hash
            latest = _quantity(results[4])
            if latest is None:
                raise RecordFailed("MalformedRPCResponse")
            nonces = [transaction["nonce"] for transaction in transactions]
            if row["nonce"] is not None:
                nonces.append(row["nonce"])
            last = max(nonces)
            if latest <= last:
                # Nonce `last` is unused, so our transaction there may still be mined: anything sent now takes
                # nonce `last` too, and only while nothing is pending there.
                if nonce != last:
                    raise RecordFailed("PreviousTransactionPending")
                stored = [t for t in transactions if t["nonce"] == last and t["raw_tx"]]
                fee = stored[-1]["max_fee_per_gas"] if stored else None
                if fee is not None and fee >= base_fee:
                    return "send", bytes.fromhex(stored[-1]["raw_tx"]), last, fee
                # Without usable stored bytes (none kept, or a fee that is unknown or below the base fee, which
                # the node would refuse), sign a replacement at nonce `last` at the current fee: at most one
                # transaction per nonce can be mined, and every hash of the row is checked, so it never records
                # twice.
            # Every nonce the row used is taken, and no transaction of the row is mined, so none of them can
            # ever be: a new transaction at the next nonce is safe.
        if base_fee > MAX_FEE_PER_GAS_WEI:
            raise RecordFailed("FeeCapExceeded")
        gas = estimate * 6 // 5
        if gas > MAX_GAS_LIMIT:
            raise RecordFailed("GasCapExceeded")
        max_fee = min(base_fee * 2, MAX_FEE_PER_GAS_WEI)
        if balance < gas * max_fee:
            raise RecordFailed("InsufficientFunds")
        signed = self._account.sign_transaction(
            {
                "type": 2,
                "chainId": CHAIN_ID,
                "nonce": nonce,
                "to": self.registry,
                "value": 0,
                "data": data,
                "gas": gas,
                "maxFeePerGas": max_fee,
                "maxPriorityFeePerGas": 0,
            }
        )
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
