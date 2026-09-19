"""Publishes ShieldBot verdicts: stores every evidence document and records Robinhood Chain verdicts on-chain.

Every process (API, hunter, bot) calls publish(), which only STORES the canonical evidence document
(core.verdict_evidence). When ROBINHOOD_VERDICT_REGISTRY is set, a Robinhood Chain (4663) row is stored as
`pending`: an outbox entry for ShieldBotVerdictRegistry.record().

Exactly one process sends: the API process calls start(), which reads ROBINHOOD_RECORDER_PRIVATE_KEY and runs a
drain that records pending rows oldest-first. No other code path reads the key, so the bot never sends and two
processes can never race for the recorder's nonces.

Each row moves through onchain_status:
  off          stored only (another chain, or no registry configured)
  pending      waiting for the drain
  sending      claimed by the drain; the signed transaction's hash is stored BEFORE it is broadcast
  submitted    the node accepted the transaction; no receipt arrived within the receipt timeout
  confirmed    the receipt shows success, so VerdictRecorded was emitted
  reverted     the receipt shows the call reverted
  failed       the node explicitly rejected the signed transaction and no receipt was found, so it is
               treated as not broadcast
  unconfirmed  the broadcast outcome is unknown (a transport error during the send, or a crash after signing)
               and no receipt was found; never resent, because it may already be on-chain

Claim before send: a row left `sending` by a crash is recovered when the drain next starts. A row without a
tx hash was never signed and goes back to `pending`. A row with a tx hash may have been broadcast, so it is
only reconciled by one receipt lookup (confirmed, reverted, else unconfirmed) and never re-signed or resent.

The public 4663 RPC is shared, so the drain is bounded: at most MAX_RECORDS_PER_HOUR records (rows beyond that
wait as pending), one at a time under a nonce lock, a timeout on every request and phase, bounded retries with
backoff on rate limits, and exponential backoff of the drain after a failure that returns a row to pending.
The recorder key is never logged, echoed or stored.
"""

import asyncio
import logging
import os
import re
import time
import traceback
from collections import deque
from typing import Optional

import aiohttp
from eth_abi import encode
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from core.verdict_evidence import Verdict, build_evidence, canonical_bytes
from services.robinhood_simulation import _quantity, _rate_limited

logger = logging.getLogger(__name__)

CHAIN_ID = 4663
DEFAULT_RPC_URL = "https://rpc.mainnet.chain.robinhood.com"
# `cast sig "record(address,uint8,bytes32,uint64)"` = 0xf160da27
RECORD_SELECTOR = keccak(text="record(address,uint8,bytes32,uint64)")[:4]

MAX_RECORDS_PER_HOUR = 60
RATE_WINDOW_SECONDS = 3600
# About 18x the 0.056 gwei base fee of a recorded 4663 block. Arbitrum chains ignore priority fees.
MAX_FEE_PER_GAS_WEI = 10**9
MAX_GAS_LIMIT = 500_000
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
DRAIN_MAX_BACKOFF_SECONDS = 300.0

ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")


class RecordFailed(Exception):
    """An RPC step failed. `reason` is a class-only label, never provider text.

    `rejected` is True only when the node answered with a JSON-RPC error, which is a definite refusal.
    """

    def __init__(self, reason: str, rejected: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.rejected = rejected


class VerdictPublisher:
    """Stores verdict evidence; in the API process, also records Robinhood Chain verdicts on-chain."""

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
        stored. Never raises and never contacts the RPC.
        """
        if not isinstance(subject, str) or not ADDRESS_RE.fullmatch(subject):
            logger.warning("Verdict not published: subject is not an address")
            return None
        try:
            payload = build_evidence(
                chain_id, subject, scan_result, honeypot_data, int(time.time())
            )
            canonical = canonical_bytes(payload)
            evidence_hash = "0x" + keccak(canonical).hex()
            queued = chain_id == CHAIN_ID and self.is_onchain_enabled()
            status = "pending" if queued else "off"
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
            logger.error(
                "Verdict evidence not stored: %s\n%s",
                type(e).__name__,
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

    def _spawn(self, coroutine) -> None:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ------------------------------------------------------------------
    # Sending (the API process only)
    # ------------------------------------------------------------------

    def start(self, recorder_key: Optional[str] = None) -> None:
        """Start the drain. Only the API process calls this, which makes it the single on-chain sender."""
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
        self._wake = asyncio.Event()
        self._drain_task = asyncio.create_task(self._drain_loop())
        logger.info("Robinhood verdict registry: sending as recorder %s", self.recorder)

    def stop(self) -> None:
        """Stop the drain. A row interrupted mid-send is recovered by the next start()."""
        if self._drain_task is not None:
            self._drain_task.cancel()
            self._drain_task = None

    async def _drain_loop(self) -> None:
        try:
            await self._recover_claims()
        except Exception as e:
            logger.error("Verdict claim recovery failed: %s", type(e).__name__)
        backoff = 0.0
        while True:
            self._wake.clear()
            try:
                outcome = await self.drain_once()
            except Exception as e:
                logger.error(
                    "Verdict drain failed: %s\n%s",
                    type(e).__name__,
                    "".join(traceback.format_tb(e.__traceback__)),
                )
                outcome = "retry"
            if outcome == "done":
                backoff = 0.0
            elif outcome == "retry":
                backoff = min(max(backoff * 2, DRAIN_BACKOFF_SECONDS), DRAIN_MAX_BACKOFF_SECONDS)
                await asyncio.sleep(backoff)
            elif outcome == "capped":
                await asyncio.sleep(self._rate_wait())
            else:
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
        recorded outcome) or "retry" (a failure before signing returned the row to pending).
        """
        if self._account is None:
            return "idle"
        if self._rate_wait() > 0:
            return "capped"
        row = await self._db.claim_next_pending_verdict(CHAIN_ID)
        if row is None:
            return "idle"
        self._sent_at.append(time.monotonic())
        return await self._send(row)

    async def _recover_claims(self) -> None:
        """Resolve rows left `sending` by a previous process: re-queue unsigned ones, never resend signed ones."""
        for row in await self._db.get_claimed_verdicts(CHAIN_ID):
            if row["tx_hash"] is None:
                await self._db.release_verdict_claim(row["id"])
                logger.warning("Verdict claim %d was never signed; queued again", row["id"])
                continue
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=RPC_TIMEOUT_SECONDS)
            ) as session:
                status = await self._receipt_status(session, row["tx_hash"])
            await self._db.update_verdict_onchain(
                row["id"],
                status or "unconfirmed",
                tx_hash=row["tx_hash"],
                onchain_error=None if status else "ClaimInterrupted",
            )
            logger.warning(
                "Verdict claim %d was interrupted after signing: %s",
                row["id"],
                status or "unconfirmed",
            )

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
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=RPC_TIMEOUT_SECONDS)
        ) as session:
            async with self._nonce_lock:
                try:
                    raw = await asyncio.wait_for(self._sign(session, data), PHASE_TIMEOUT_SECONDS)
                except Exception as e:
                    # Nothing has left this process yet, so returning the row to the queue is always safe.
                    reason = e.reason if isinstance(e, RecordFailed) else type(e).__name__
                    await self._db.release_verdict_claim(evidence_id)
                    logger.warning("Verdict record deferred: %s", reason)
                    return "retry"
                tx_hash = "0x" + keccak(raw).hex()
                # Stored before the broadcast: from here on the row is only ever reconciled, never resent.
                await self._db.set_verdict_tx_hash(evidence_id, tx_hash)
                try:
                    await asyncio.wait_for(
                        self._rpc(session, [("eth_sendRawTransaction", ["0x" + raw.hex()])]),
                        PHASE_TIMEOUT_SECONDS,
                    )
                    accepted, rejected, error = True, False, None
                except Exception as e:
                    # A JSON-RPC error is a definite refusal; anything else may have reached the node.
                    rejected = isinstance(e, RecordFailed) and e.rejected
                    accepted = False
                    error = e.reason if isinstance(e, RecordFailed) else type(e).__name__
            await asyncio.sleep(RECEIPT_DELAY_SECONDS)
            status = await self._receipt_status(session, tx_hash)
        if status is not None:
            error = None
        elif accepted:
            status = "submitted"
        elif rejected:
            status, tx_hash = "failed", None
        else:
            status = "unconfirmed"
        await self._db.update_verdict_onchain(
            evidence_id, status, tx_hash=tx_hash, onchain_error=error
        )
        if error is None:
            logger.info("Verdict record %s: tx=%s subject=%s", status, tx_hash, row["subject"])
        else:
            logger.warning("Verdict record %s: %s", status, error)
        return "done"

    async def _sign(self, session, data: str) -> bytes:
        """Read the nonce, fee, gas and balance, then sign record(). Raises RecordFailed if it cannot."""
        sender = self.recorder
        nonce, block, estimate, balance = await self._rpc(
            session,
            [
                ("eth_getTransactionCount", [sender, "pending"]),
                ("eth_getBlockByNumber", ["latest", False]),
                ("eth_estimateGas", [{"from": sender, "to": self.registry, "data": data}]),
                ("eth_getBalance", [sender, "latest"]),
            ],
        )
        nonce, estimate, balance = _quantity(nonce), _quantity(estimate), _quantity(balance)
        base_fee = _quantity(block.get("baseFeePerGas")) if isinstance(block, dict) else None
        if None in (nonce, estimate, balance, base_fee):
            raise RecordFailed("MalformedRPCResponse")
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
        return bytes(getattr(signed, "raw_transaction", None) or signed.rawTransaction)

    async def _receipt_status(self, session, tx_hash: str) -> Optional[str]:
        """One bounded receipt lookup: "confirmed", "reverted", or None if there is no usable receipt."""
        try:
            [receipt] = await asyncio.wait_for(
                self._rpc(session, [("eth_getTransactionReceipt", [tx_hash])]),
                RECEIPT_TIMEOUT_SECONDS,
            )
        except Exception as e:
            logger.warning("Verdict receipt unavailable: %s", type(e).__name__)
            return None
        status = receipt.get("status") if isinstance(receipt, dict) else None
        return {"0x1": "confirmed", "0x0": "reverted"}.get(status)

    async def _rpc(self, session, calls: list) -> list:
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
