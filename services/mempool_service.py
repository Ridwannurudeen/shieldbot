"""Mempool monitoring v1 — detect sandwich attacks, frontrunning, and suspicious pending transactions."""

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set

import aiohttp
from web3 import Web3

logger = logging.getLogger(__name__)

# Chains whose RPC serves a public mempool through txpool_content. Base, Arbitrum, Optimism and
# Robinhood Chain reject txpool calls; their sequencers keep no public mempool to watch.
PENDING_TRANSACTION_CHAINS = frozenset({56, 1, 137, 204})


def supports_pending_transactions(chain_id: int) -> bool:
    return chain_id in PENDING_TRANSACTION_CHAINS


# New transactions analysed between yields to the event loop, so requests are served while a large
# first snapshot is added.
ANALYSIS_YIELD_EVERY = 256

# A txpool_content body larger than this is not parsed: json.loads holds the GIL for about a second
# per 80 MB, which freezes the event loop, and Ethereum's pool runs to that size. A chain whose pool
# exceeds the cap is watched through the node's pending block instead.
MAX_TXPOOL_BYTES = 8 * 1024 * 1024
# Per socket operation, matching the request timeout of the web3 provider (adapters/evm_base.py).
TXPOOL_TIMEOUT_SECONDS = 10
# A whole txpool read is cut here, so an RPC that drips its answer cannot hold the other chains' polls.
TXPOOL_READ_SECONDS = 60
# A chain marked oversized or sealed is asked again after this long, so one spike or one odd backend
# behind a load-balanced RPC does not leave the chain unobserved until the process restarts.
MARK_RETRY_SECONDS = 600

# Known DEX router selectors
SWAP_SELECTORS = {
    "0x38ed1739": "swapExactTokensForTokens",
    "0x8803dbee": "swapTokensForExactTokens",
    "0x7ff36ab5": "swapExactETHForTokens",
    "0x4a25d94a": "swapTokensForExactETH",
    "0x18cbafe5": "swapExactTokensForETH",
    "0xfb3bdb41": "swapETHForExactTokens",
    "0x5c11d795": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
    "0xb6f9de95": "swapExactETHForTokensSupportingFeeOnTransferTokens",
    "0x791ac947": "swapExactTokensForETHSupportingFeeOnTransferTokens",
    "0x04e45aaf": "exactInputSingle (V3)",
    "0xb858183f": "exactInput (V3)",
    "0x414bf389": "exactInputSingle (V3 legacy)",
}

# Where each swap keeps the token its sandwich queue is keyed on: the token traded against the chain's
# coin where the function name says which side that is (the last entry of a V2 `address[] path` for a
# coin-in swap, the first for a coin-out swap), else the output token: the last path entry of a
# token-to-token V2 swap, the `tokenOut` word of a V3 exactInputSingle, or the last 20 bytes of a V3
# exactInput packed path (20-byte tokens joined by 3-byte fees).
V2_PATH_TOKEN = {  # selector: (word holding the offset of `path`, index into the path)
    "0x38ed1739": (2, -1),  # swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline)
    "0x8803dbee": (2, -1),  # swapTokensForExactTokens(amountOut, amountInMax, path, to, deadline)
    "0x5c11d795": (2, -1),  # swapExactTokensForTokensSupportingFeeOnTransferTokens(amountIn, amountOutMin, path, to, deadline)
    "0x7ff36ab5": (1, -1),  # swapExactETHForTokens(amountOutMin, path, to, deadline)
    "0xfb3bdb41": (1, -1),  # swapETHForExactTokens(amountOut, path, to, deadline)
    "0xb6f9de95": (1, -1),  # swapExactETHForTokensSupportingFeeOnTransferTokens(amountOutMin, path, to, deadline)
    "0x4a25d94a": (2, 0),  # swapTokensForExactETH(amountOut, amountInMax, path, to, deadline)
    "0x18cbafe5": (2, 0),  # swapExactTokensForETH(amountIn, amountOutMin, path, to, deadline)
    "0x791ac947": (2, 0),  # swapExactTokensForETHSupportingFeeOnTransferTokens(amountIn, amountOutMin, path, to, deadline)
}
V3_EXACT_INPUT_SINGLE_SELECTORS = frozenset({"0x04e45aaf", "0x414bf389"})
V3_EXACT_INPUT_SELECTOR = "0xb858183f"
# A router swap has a handful of hops; a longer path is not one.
MAX_SWAP_PATH_LENGTH = 8

APPROVE_SELECTORS = {
    "0x095ea7b3": "approve",
    "0xa22cb465": "setApprovalForAll",
}

UNLIMITED_APPROVAL = 2**256 - 1
HIGH_APPROVAL = 2**128


@dataclass
class PendingTx:
    """A pending transaction in the mempool."""
    tx_hash: str
    from_addr: str
    to_addr: str
    value: int
    gas_price: int
    data: str
    chain_id: int
    seen_at: float = field(default_factory=time.time)


@dataclass
class MempoolAlert:
    """An alert generated from mempool analysis."""
    alert_type: str  # sandwich_frontrun, sandwich_backrun, frontrun, suspicious_approval
    severity: str  # HIGH, MEDIUM, LOW
    description: str
    victim_tx: Optional[str] = None
    attacker_tx: Optional[str] = None
    attacker_addr: Optional[str] = None
    target_token: Optional[str] = None
    chain_id: int = 56
    created_at: float = field(default_factory=time.time)


class MempoolMonitor:
    """Monitors pending transactions for sandwich attacks and frontrunning.

    Polls txpool_content on each chain and falls back to eth_getBlock('pending') where the RPC does
    not serve it. A pool larger than MAX_TXPOOL_BYTES is watched through the pending block as well:
    the transactions about to be mined rather than the whole pool.
    """

    def __init__(self, web3_client, db=None):
        self._web3_client = web3_client
        self._db = db
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # Recent pending txs by chain: {chain_id: {tx_hash: PendingTx}}
        self._pending: Dict[int, Dict[str, PendingTx]] = defaultdict(dict)
        # Where each chain's last snapshot came from: "txpool" or "block"
        self._pending_source: Dict[int, str] = {}

        # Recent swap txs for sandwich detection: {(chain_id, token): [PendingTx]}
        self._swap_queue: Dict[tuple, List[PendingTx]] = defaultdict(list)
        # Sandwiches already reported per queue key, as (front-run tx hash, victim tx hash)
        self._reported_sandwiches: Dict[tuple, Set[tuple]] = defaultdict(set)

        # The newest alerts; the deque drops the oldest past its cap.
        self._alerts: Deque[MempoolAlert] = deque(maxlen=1000)

        # Chains to monitor (only chains with txpool or pending block support)
        self._monitored_chains: Set[int] = set()
        # Chains whose RPC answered "pending" with a sealed block, until when (time.monotonic()) the
        # pending block is not asked for again. Warned about once per chain.
        self._sealed_pending_until: Dict[int, float] = {}
        # Chains whose txpool_content body passed MAX_TXPOOL_BYTES, until when they are read through
        # the pending block without asking for the txpool. Warned about once per chain.
        self._txpool_oversized_until: Dict[int, float] = {}
        # Chains whose txpool_content request failed or was refused, warned about once.
        self._txpool_warned: Set[int] = set()
        # Monitored chains whose last poll read neither a txpool nor a genuine pending block. Their
        # mempool is unknown, so they must not be reported as free of threats.
        self._unobservable_chains: Set[int] = set()

        # Stats: held in memory, so they restart from zero with the process.
        self._counting_since = time.time()
        self._stats = {
            'total_pending_seen': 0,
            'sandwiches_detected': 0,
            'frontruns_detected': 0,
            'suspicious_approvals': 0,
        }

    async def start(self, chain_ids: List[int] = None):
        """Start monitoring specified chains."""
        if self._running:
            return
        requested = self._web3_client.get_supported_chain_ids() if chain_ids is None else chain_ids
        for chain_id in requested:
            self._web3_client.validate_chain_id(chain_id)
        self._monitored_chains = {
            chain_id for chain_id in requested if supports_pending_transactions(chain_id)
        }
        # Until a chain's first poll reads something, nothing is known about its mempool.
        self._unobservable_chains = set(self._monitored_chains)
        if not self._monitored_chains:
            return
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info(f"MempoolMonitor started for chains: {self._monitored_chains}")

    async def stop(self):
        """Stop monitoring. A monitor that never started (the Telegram bot's) has nothing to stop."""
        if not self._task:
            return
        self._running = False
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None
        logger.info("MempoolMonitor stopped")

    async def _monitor_loop(self):
        """Main monitoring loop — polls pending transactions."""
        from utils.web3_client import UnsupportedChainError

        while self._running:
            try:
                for chain_id in self._monitored_chains:
                    started = time.monotonic()
                    await self._poll_pending(chain_id)
                    logger.debug("Polled chain %s in %.2f s", chain_id, time.monotonic() - started)
                await asyncio.sleep(2)  # Poll every 2 seconds
            except asyncio.CancelledError:
                break
            except UnsupportedChainError:
                raise
            except Exception as e:
                logger.error("MempoolMonitor error: %s", type(e).__name__)
                await asyncio.sleep(5)

    async def _poll_pending(self, chain_id: int):
        """Poll pending transactions for a chain."""
        w3 = self._web3_client.get_web3(chain_id)
        if not w3:
            return

        try:
            # Try txpool_content first (Geth nodes)
            source = "txpool"
            pending_txs = await self._get_txpool_content(w3, chain_id)
            if not pending_txs:
                # Fallback: get pending block
                source = "block"
                pending_txs = await self._get_pending_block(w3, chain_id)
            if pending_txs is None:
                self._unobservable_chains.add(chain_id)
                return
            self._unobservable_chains.discard(chain_id)

            # The pool is exactly this snapshot: what left it is dropped, what stayed keeps its entry,
            # and only what joined is counted and analysed, so a long-lived transaction is seen once.
            # A snapshot from the other source (one failed txpool read) is a different view of the
            # pool, so the poll that switches drops nothing; the next poll from the same source does.
            snapshot = {tx.tx_hash: tx for tx in pending_txs}
            pending = self._pending[chain_id]
            if self._pending_source.get(chain_id) == source:
                for tx_hash in [h for h in pending if h not in snapshot]:
                    del pending[tx_hash]
            self._pending_source[chain_id] = source
            added = 0
            for tx_hash, tx in snapshot.items():
                if tx_hash in pending:
                    continue
                pending[tx_hash] = tx
                self._stats['total_pending_seen'] += 1
                await self._analyze_pending_tx(tx)
                added += 1
                if added % ANALYSIS_YIELD_EVERY == 0:
                    await asyncio.sleep(0)

            # _check_sandwich prunes a swap queue only when a swap arrives on its key, so a queue
            # whose newest swap is past the 30 s window is dropped here, with its reported pairs.
            now = time.time()
            for key in [k for k, q in self._swap_queue.items() if not q or now - q[-1].seen_at >= 30]:
                del self._swap_queue[key]
                self._reported_sandwiches.pop(key, None)

        except Exception as e:
            self._unobservable_chains.add(chain_id)
            logger.debug("Pending poll failed for chain %s: %s", chain_id, type(e).__name__)

    async def _get_txpool_content(self, w3: Web3, chain_id: int) -> List[PendingTx]:
        """Fetch pending txs via txpool_content RPC; [] sends _poll_pending to the pending block.

        The body is streamed and abandoned as soon as it passes MAX_TXPOOL_BYTES, and the chain takes
        the pending-block route for MARK_RETRY_SECONDS before its txpool is asked for again: a pool
        that large is usually the chain's normal size, so asking every poll would download megabytes
        for nothing. A body under the cap is parsed and built in the executor. A provider without an
        HTTP endpoint, a failed or non-200 request and an oversized body all give [].
        """
        if self._txpool_oversized_until.get(chain_id, 0) > time.monotonic():
            return []
        endpoint = getattr(w3.provider, "endpoint_uri", None)
        if not isinstance(endpoint, str) or not endpoint.startswith(("http://", "https://")):
            return []
        body = bytearray()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    json={"jsonrpc": "2.0", "id": 1, "method": "txpool_content", "params": []},
                    timeout=aiohttp.ClientTimeout(
                        total=TXPOOL_READ_SECONDS,
                        sock_connect=TXPOOL_TIMEOUT_SECONDS,
                        sock_read=TXPOOL_TIMEOUT_SECONDS,
                    ),
                ) as resp:
                    if resp.status != 200:
                        self._warn_txpool_unreadable(chain_id, f"HTTP {resp.status}")
                        return []
                    async for chunk in resp.content.iter_chunked(64 * 1024):
                        body.extend(chunk)
                        if len(body) > MAX_TXPOOL_BYTES:
                            resp.close()
                            first = chain_id not in self._txpool_oversized_until
                            self._txpool_oversized_until[chain_id] = time.monotonic() + MARK_RETRY_SECONDS
                            if first:
                                logger.warning(
                                    "Chain %s's txpool is larger than %d bytes; it is watched through its "
                                    "pending block, and its txpool is asked for again every %d s",
                                    chain_id, MAX_TXPOOL_BYTES, MARK_RETRY_SECONDS,
                                )
                            return []
        except Exception as e:
            self._warn_txpool_unreadable(chain_id, type(e).__name__)
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._parse_txpool_content, bytes(body), chain_id)

    def _warn_txpool_unreadable(self, chain_id: int, reason: str):
        """Warn once per chain that its txpool_content could not be read; later failures log at debug.

        The reason is an HTTP status or an exception's type, never its text, which can hold the RPC URL.
        """
        if chain_id in self._txpool_warned:
            logger.debug("txpool_content read failed for chain %s: %s", chain_id, reason)
            return
        self._txpool_warned.add(chain_id)
        logger.warning(
            "Chain %s's txpool_content could not be read (%s); its pending block is read instead",
            chain_id, reason,
        )

    @staticmethod
    def _parse_txpool_content(body: bytes, chain_id: int) -> List[PendingTx]:
        txs = []
        try:
            pending = json.loads(body).get("result", {}).get("pending", {})
            for sender, nonces in pending.items():
                for nonce, tx_data in nonces.items():
                    txs.append(PendingTx(
                        tx_hash=tx_data.get("hash", ""),
                        from_addr=tx_data.get("from", "").lower(),
                        to_addr=(tx_data.get("to") or "").lower(),
                        value=int(tx_data.get("value", "0x0"), 16),
                        gas_price=int(tx_data.get("gasPrice", "0x0"), 16),
                        data=tx_data.get("input", "0x"),
                        chain_id=chain_id,
                    ))
        except Exception as e:
            logger.debug("txpool_content parse failed for chain %s: %s", chain_id, type(e).__name__)
            return []
        return txs

    async def _get_pending_block(self, w3: Web3, chain_id: int) -> Optional[List[PendingTx]]:
        """Fetch pending txs via eth_getBlockByNumber('pending').

        Returns None when no genuine pending block was read (the call failed, or the RPC answered
        with a sealed block), which leaves the chain's mempool unobserved.
        """
        if self._sealed_pending_until.get(chain_id, 0) > time.monotonic():
            return None
        txs = []
        try:
            loop = asyncio.get_event_loop()
            block = await loop.run_in_executor(
                None, w3.eth.get_block, 'pending', True
            )
            # Some RPCs (the public BNB Chain and opBNB ones) answer "pending" with a recent sealed
            # block. A genuine pending block has no hash yet; a sealed one holds only mined
            # transactions, which can no longer be front-run, so it is not read as a mempool.
            if block.get("hash") is not None:
                first = chain_id not in self._sealed_pending_until
                self._sealed_pending_until[chain_id] = time.monotonic() + MARK_RETRY_SECONDS
                if first:
                    logger.warning(
                        "Chain %s answers 'pending' with a sealed block; its pending-block fallback is "
                        "skipped and asked for again every %d s",
                        chain_id, MARK_RETRY_SECONDS,
                    )
                return None
            for tx in (block.get("transactions") or []):
                # web3 returns each transaction as an AttributeDict, which is a Mapping but not a dict.
                if isinstance(tx, Mapping):
                    txs.append(PendingTx(
                        tx_hash=Web3.to_hex(tx["hash"]) if isinstance(tx.get("hash"), bytes) else str(tx.get("hash", "")),
                        from_addr=(tx.get("from") or "").lower(),
                        to_addr=(tx.get("to") or "").lower(),
                        value=tx.get("value", 0),
                        gas_price=tx.get("gasPrice", 0),
                        # Web3.to_hex gives a 0x-prefixed string on every hexbytes version, and "0x" for the
                        # empty input of a plain transfer.
                        data=Web3.to_hex(tx["input"]) if isinstance(tx.get("input"), bytes) else str(tx.get("input", "0x")),
                        chain_id=chain_id,
                    ))
        except Exception:
            return None
        return txs

    async def _analyze_pending_tx(self, tx: PendingTx):
        """Analyze a single pending transaction for threats."""
        selector = tx.data[:10].lower() if len(tx.data) >= 10 else ""

        # Check for swap transactions (sandwich detection)
        if selector in SWAP_SELECTORS:
            token = self._extract_token_from_swap(tx.data)
            if token:
                key = (tx.chain_id, token)
                queue = self._swap_queue[key]
                # A transaction that left a snapshot and came back is analysed again; queued twice,
                # its two copies would pair up as a front-run and a back-run.
                if all(queued.tx_hash != tx.tx_hash for queued in queue):
                    queue.append(tx)
                    await self._check_sandwich(key, tx)

        # Check for suspicious approvals
        if selector in APPROVE_SELECTORS:
            await self._check_suspicious_approval(tx)

    def _extract_token_from_swap(self, data: str) -> Optional[str]:
        """The token a swap's sandwich queue is keyed on, or None when its calldata holds none.

        The selector's ABI says where the token is (V2_PATH_TOKEN and the V3 selectors), and a word
        keys a queue only when it is an address, so an amount, an ABI offset or a zero word never does.
        """
        selector = data[:10].lower()
        args = data[10:].lower()

        def word(index: int) -> Optional[int]:
            chunk = args[index * 64:(index + 1) * 64]
            return int(chunk, 16) if len(chunk) == 64 else None

        try:
            if selector in V2_PATH_TOKEN:
                offset_word, position = V2_PATH_TOKEN[selector]
                offset = word(offset_word)
                if offset is None or offset % 32:
                    return None
                length = word(offset // 32)
                if length is None or not 2 <= length <= MAX_SWAP_PATH_LENGTH:
                    return None
                token = word(offset // 32 + 1 + (length - 1 if position == -1 else 0))
            elif selector in V3_EXACT_INPUT_SINGLE_SELECTORS:
                token = word(1)
            elif selector == V3_EXACT_INPUT_SELECTOR:
                params = word(0)
                path = word(params // 32) if params is not None and params % 32 == 0 else None
                if path is None or path % 32:
                    return None
                start = (params + path) // 32
                length = word(start)
                longest = 20 + 23 * (MAX_SWAP_PATH_LENGTH - 1)
                if length is None or not 43 <= length <= longest or (length - 20) % 23:
                    return None
                packed = args[(start + 1) * 64:(start + 1) * 64 + length * 2]
                token = int(packed[-40:], 16) if len(packed) == length * 2 else None
            else:
                return None
        except ValueError:
            return None
        # An address word has its high 12 bytes zero, and no token lives below 2**64, where a plain
        # number, an ABI offset (0x20, 0x40, 0x60) or the zero word would be.
        if token is None or token >> 160 or token < 2**64:
            return None
        return f"0x{token:040x}"

    async def _check_sandwich(self, key: tuple, newest: PendingTx):
        """Report the sandwiches the newest swap on this key completes.

        A sandwich attack consists of:
        1. Attacker frontrun: large swap to move price
        2. Victim swap: executes at worse price
        3. Attacker backrun: reverse swap to capture profit

        Only the newest swap can be a back-run, so only its sender is tried as the attacker, and a
        (front-run, victim) pair is reported once however many back-runs follow it.
        """
        chain_id, token = key
        queue = self._swap_queue[key]

        # Prune old entries (> 30 seconds), and the reported pairs whose victim left the queue
        now = time.time()
        queue[:] = [tx for tx in queue if now - tx.seen_at < 30]
        live = {tx.tx_hash for tx in queue}
        reported = self._reported_sandwiches[key]
        reported.difference_update([pair for pair in reported if pair[1] not in live])

        attacker = newest.from_addr
        attacker_txs = [tx for tx in queue if tx.from_addr == attacker]
        if len(attacker_txs) < 2:
            return

        # Check if there's a victim tx between attacker's txs
        for victim_tx in queue:
            if victim_tx.from_addr == attacker:
                continue

            front = None
            back = None
            for atx in attacker_txs:
                if atx.gas_price > victim_tx.gas_price and atx.seen_at <= victim_tx.seen_at:
                    front = atx
                elif atx.seen_at > victim_tx.seen_at:
                    back = atx

            if front and back and (front.tx_hash, victim_tx.tx_hash) not in reported:
                reported.add((front.tx_hash, victim_tx.tx_hash))
                alert = MempoolAlert(
                    alert_type="sandwich_attack",
                    severity="HIGH",
                    description=(
                        f"Sandwich attack detected on {token[:10]}... — "
                        f"attacker {attacker[:10]}... front-running victim "
                        f"{victim_tx.from_addr[:10]}... with higher gas price"
                    ),
                    victim_tx=victim_tx.tx_hash,
                    attacker_tx=front.tx_hash,
                    attacker_addr=attacker,
                    target_token=token,
                    chain_id=chain_id,
                )
                self._add_alert(alert)
                self._stats['sandwiches_detected'] += 1
                logger.warning(f"Sandwich detected: {alert.description}")

    async def _check_suspicious_approval(self, tx: PendingTx):
        """Check for suspicious token approvals in pending transactions."""
        try:
            data = tx.data.replace("0x", "")
            if len(data) < 136:
                return

            selector = "0x" + data[:8]
            if selector == "0x095ea7b3":
                # approve(spender, amount)
                spender = "0x" + data[32:72][-40:]
                amount = int(data[72:136], 16)

                if amount >= UNLIMITED_APPROVAL:
                    alert = MempoolAlert(
                        alert_type="suspicious_approval",
                        severity="HIGH",
                        description=(
                            f"Unlimited token approval pending — "
                            f"{tx.from_addr[:10]}... approving {spender[:10]}... "
                            f"for unlimited tokens on contract {tx.to_addr[:10]}..."
                        ),
                        victim_tx=tx.tx_hash,
                        attacker_addr=spender,
                        target_token=tx.to_addr,
                        chain_id=tx.chain_id,
                    )
                    self._add_alert(alert)
                    self._stats['suspicious_approvals'] += 1
                elif amount >= HIGH_APPROVAL:
                    alert = MempoolAlert(
                        alert_type="suspicious_approval",
                        severity="MEDIUM",
                        description=(
                            f"Very large token approval pending — "
                            f"{tx.from_addr[:10]}... approving {spender[:10]}..."
                        ),
                        victim_tx=tx.tx_hash,
                        attacker_addr=spender,
                        target_token=tx.to_addr,
                        chain_id=tx.chain_id,
                    )
                    self._add_alert(alert)
                    self._stats['suspicious_approvals'] += 1
        except Exception as e:
            logger.debug("Approval analysis error: %s", type(e).__name__)

    def _add_alert(self, alert: MempoolAlert):
        """Add an alert; the deque drops the oldest past its cap."""
        self._alerts.append(alert)

    def get_alerts(self, chain_id: int = None, limit: int = 50) -> List[Dict]:
        """Get recent alerts, optionally filtered by chain."""
        if chain_id is not None:
            self._web3_client.validate_chain_id(chain_id)
            if not supports_pending_transactions(chain_id):
                raise ValueError("pending-transaction monitoring is not available on this chain")
        alerts = list(self._alerts)
        if chain_id is not None:
            alerts = [a for a in alerts if a.chain_id == chain_id]
        return [
            {
                'alert_type': a.alert_type,
                'severity': a.severity,
                'description': a.description,
                'victim_tx': a.victim_tx,
                'attacker_tx': a.attacker_tx,
                'attacker_addr': a.attacker_addr,
                'target_token': a.target_token,
                'chain_id': a.chain_id,
                'created_at': a.created_at,
            }
            for a in alerts[-limit:]
        ]

    def get_stats(self) -> Dict:
        """Get monitoring statistics."""
        return {
            **self._stats,
            'counting_since': self._counting_since,
            'monitored_chains': list(self._monitored_chains),
            'unobservable_chains': sorted(self._unobservable_chains),
            'pending_count': {
                cid: len(txs) for cid, txs in self._pending.items()
            },
            'active_alerts': len(self._alerts),
        }
