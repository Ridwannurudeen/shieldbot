"""Publishes ShieldBot verdicts: stores every evidence document and records Robinhood Chain verdicts on-chain.

publish() always stores the canonical evidence document (core.verdict_evidence) in the database. When both
ROBINHOOD_VERDICT_REGISTRY and ROBINHOOD_RECORDER_PRIVATE_KEY are set, a Robinhood Chain (4663) verdict is also
sent to ShieldBotVerdictRegistry.record() in the background, and the transaction hash or a class-only failure is
stored against the evidence. The recorder key is never logged, echoed or stored.

The public 4663 RPC is shared, so sending is bounded: at most MAX_RECORDS_PER_HOUR records per process, one at
a time under a nonce lock, with a timeout on every request and bounded retries with backoff on rate limits.
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
RECORD_TIMEOUT_SECONDS = 90

ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")


class RecordFailed(Exception):
    """A record() could not be sent. `reason` is a class-only label, never provider text."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class VerdictPublisher:
    """Stores verdict evidence and records Robinhood Chain verdicts in ShieldBotVerdictRegistry."""

    def __init__(
        self,
        db,
        rpc_url: Optional[str] = None,
        registry_address: Optional[str] = None,
        recorder_key: Optional[str] = None,
    ):
        self._db = db
        self._rpc_url = rpc_url or os.getenv("ROBINHOOD_RPC_URL") or DEFAULT_RPC_URL
        registry = (
            registry_address
            if registry_address is not None
            else os.getenv("ROBINHOOD_VERDICT_REGISTRY", "")
        )
        key = (
            recorder_key
            if recorder_key is not None
            else os.getenv("ROBINHOOD_RECORDER_PRIVATE_KEY", "")
        )
        self.registry = None
        self.recorder = None
        self._account = None
        self._nonce_lock = asyncio.Lock()
        self._sent_at = deque()
        self._tasks = set()
        if not (registry and key):
            logger.info(
                "Robinhood verdict registry: disabled (set ROBINHOOD_VERDICT_REGISTRY and "
                "ROBINHOOD_RECORDER_PRIVATE_KEY to enable)"
            )
            return
        try:
            self.registry = to_checksum_address(registry)
            self._account = Account.from_key(key)
        except Exception as e:
            # Invalid settings are an input boundary; the key or its error text is never logged.
            self.registry = self._account = None
            logger.error(
                "Robinhood verdict registry: disabled (invalid configuration: %s)", type(e).__name__
            )
            return
        self.recorder = self._account.address
        logger.info(
            "Robinhood verdict registry: enabled (registry=%s recorder=%s)",
            self.registry,
            self.recorder,
        )

    def is_onchain_enabled(self) -> bool:
        return self._account is not None

    def publish_fire_and_forget(
        self, chain_id: int, subject: str, scan_result: dict, honeypot_data: Optional[dict] = None
    ) -> None:
        """Schedule publish() without waiting for it, for request paths that must not block."""
        self._spawn(self.publish(chain_id, subject, scan_result, honeypot_data))

    async def publish(
        self, chain_id: int, subject: str, scan_result: dict, honeypot_data: Optional[dict] = None
    ) -> Optional[dict]:
        """Store the evidence for one scan; for Robinhood Chain, also record it on-chain in the background.

        Returns the stored evidence id, hash, verdict and on-chain status, or None if nothing could be
        stored. Never raises.
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
            registry, error = None, None
            if chain_id != CHAIN_ID or not self.is_onchain_enabled():
                status = "off"
            elif self._take_send_slot():
                status, registry = "pending", self.registry
            else:
                status, registry, error = "failed", self.registry, "RateCapExceeded"
            evidence_id = await self._db.insert_verdict_evidence(
                chain_id=chain_id,
                subject=payload["subject"],
                verdict=payload["verdict"],
                evidence_hash=evidence_hash,
                canonical=canonical.decode("utf-8"),
                observed_block=payload["observed_block"],
                onchain_status=status,
                registry=registry,
                onchain_error=error,
            )
        except Exception as e:
            logger.error(
                "Verdict evidence not stored: %s\n%s",
                type(e).__name__,
                "".join(traceback.format_tb(e.__traceback__)),
            )
            return None
        if error is not None:
            logger.warning("Verdict record not sent: %s", error)
        if status == "pending":
            self._spawn(
                self._record(
                    evidence_id,
                    payload["subject"],
                    Verdict[payload["verdict"]],
                    evidence_hash,
                    payload["observed_block"],
                )
            )
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

    def _take_send_slot(self) -> bool:
        """Reserve one of the MAX_RECORDS_PER_HOUR sends in the sliding window."""
        now = time.monotonic()
        while self._sent_at and now - self._sent_at[0] >= RATE_WINDOW_SECONDS:
            self._sent_at.popleft()
        if len(self._sent_at) >= MAX_RECORDS_PER_HOUR:
            return False
        self._sent_at.append(now)
        return True

    async def _record(
        self,
        evidence_id: int,
        subject: str,
        verdict: Verdict,
        evidence_hash: str,
        observed_block: int,
    ) -> None:
        tx_hash, status, error = None, "submitted", None
        try:
            tx_hash = await asyncio.wait_for(
                self._send_record(subject, verdict, evidence_hash, observed_block),
                RECORD_TIMEOUT_SECONDS,
            )
        except RecordFailed as e:
            status, error = "failed", e.reason
            logger.warning("Verdict record failed: %s", error)
        except Exception as e:
            status, error = "failed", type(e).__name__
            logger.error(
                "Verdict record failed: %s\n%s",
                type(e).__name__,
                "".join(traceback.format_tb(e.__traceback__)),
            )
        else:
            logger.info("Verdict recorded on Robinhood Chain: tx=%s subject=%s", tx_hash, subject)
        try:
            await self._db.update_verdict_onchain(
                evidence_id, status, tx_hash=tx_hash, onchain_error=error
            )
        except Exception as e:
            logger.error("Verdict record outcome not stored: %s", type(e).__name__)

    async def _send_record(
        self, subject: str, verdict: Verdict, evidence_hash: str, observed_block: int
    ) -> str:
        """Sign and send record(); return the transaction hash."""
        data = (
            "0x"
            + (
                RECORD_SELECTOR
                + encode(
                    ["address", "uint8", "bytes32", "uint64"],
                    [subject, int(verdict), bytes.fromhex(evidence_hash[2:]), observed_block],
                )
            ).hex()
        )
        sender = self.recorder
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=RPC_TIMEOUT_SECONDS)
        ) as session:
            async with self._nonce_lock:
                nonce, block, estimate = await self._rpc(
                    session,
                    [
                        ("eth_getTransactionCount", [sender, "pending"]),
                        ("eth_getBlockByNumber", ["latest", False]),
                        ("eth_estimateGas", [{"from": sender, "to": self.registry, "data": data}]),
                    ],
                )
                nonce, estimate = _quantity(nonce), _quantity(estimate)
                base_fee = (
                    _quantity(block.get("baseFeePerGas")) if isinstance(block, dict) else None
                )
                if nonce is None or estimate is None or base_fee is None:
                    raise RecordFailed("MalformedRPCResponse")
                if base_fee > MAX_FEE_PER_GAS_WEI:
                    raise RecordFailed("FeeCapExceeded")
                gas = estimate * 6 // 5
                if gas > MAX_GAS_LIMIT:
                    raise RecordFailed("GasCapExceeded")
                signed = self._account.sign_transaction(
                    {
                        "type": 2,
                        "chainId": CHAIN_ID,
                        "nonce": nonce,
                        "to": self.registry,
                        "value": 0,
                        "data": data,
                        "gas": gas,
                        "maxFeePerGas": min(base_fee * 2, MAX_FEE_PER_GAS_WEI),
                        "maxPriorityFeePerGas": 0,
                    }
                )
                # eth-account renamed rawTransaction to raw_transaction; HexBytes.hex() changed prefix, so use bytes.
                raw = bytes(getattr(signed, "raw_transaction", None) or signed.rawTransaction)
                await self._rpc(session, [("eth_sendRawTransaction", ["0x" + raw.hex()])])
        return "0x" + keccak(raw).hex()

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
                        f"{method} JSON-RPC error {code if type(code) is int else None}"
                    )
                if "result" not in row:
                    raise RecordFailed("MalformedRPCResponse")
                results.append(row["result"])
            return results
        raise RecordFailed("RateLimited")
