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

from services.counterparty_service import UnavailableCounterparty

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
# A chain that has never served a genuine pending block is marked sealed only after this many sealed
# answers in a row, so one unlucky answer after a restart costs a poll, not MARK_RETRY_SECONDS.
SEALED_MARK_AFTER = 3
# A chain that serves genuine pending blocks is warned about once per run of this many sealed answers.
SEALED_WARN_AFTER = 10

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

# Where each V2 swap keeps the offset of its `address[] path`: the swap sells path[0] and buys
# path[-1], and the coin-in and coin-out functions list the chain's wrapped coin at that end. A V3
# exactInputSingle names tokenIn and tokenOut in its first two words; a V3 exactInput packs its path
# as 20-byte tokens joined by 3-byte fees, so it sells the first 20 bytes and buys the last.
V2_PATH_OFFSET_WORD = {  # selector: word holding the offset of `path`
    "0x38ed1739": 2,  # swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline)
    "0x8803dbee": 2,  # swapTokensForExactTokens(amountOut, amountInMax, path, to, deadline)
    "0x5c11d795": 2,  # swapExactTokensForTokensSupportingFeeOnTransferTokens(amountIn, amountOutMin, path, to, deadline)
    "0x7ff36ab5": 1,  # swapExactETHForTokens(amountOutMin, path, to, deadline)
    "0xfb3bdb41": 1,  # swapETHForExactTokens(amountOut, path, to, deadline)
    "0xb6f9de95": 1,  # swapExactETHForTokensSupportingFeeOnTransferTokens(amountOutMin, path, to, deadline)
    "0x4a25d94a": 2,  # swapTokensForExactETH(amountOut, amountInMax, path, to, deadline)
    "0x18cbafe5": 2,  # swapExactTokensForETH(amountIn, amountOutMin, path, to, deadline)
    "0x791ac947": 2,  # swapExactTokensForETHSupportingFeeOnTransferTokens(amountIn, amountOutMin, path, to, deadline)
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


def _token_address(word: Optional[int]) -> Optional[str]:
    """A calldata word as a token address, or None when it is not one.

    An address word has its high 12 bytes zero, and no token lives below 2**64, where a plain
    number, an ABI offset (0x20, 0x40, 0x60) or the zero word would be.
    """
    if word is None or word >> 160 or word < 2**64:
        return None
    return f"0x{word:040x}"


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
class QueuedSwap:
    """A pending swap in a sandwich queue: the transaction and the tokens it sells and buys."""
    tx: PendingTx
    token_in: str
    token_out: str


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

    def __init__(self, web3_client, db=None, scam_db=None, counterparty=None):
        self._web3_client = web3_client
        self._db = db
        # What is already known about an approval's spender, read in memory: the chain adapters'
        # router allowlist and Permit2, the loaded blacklist, and the facts a scan fetched.
        self._scam_db = scam_db
        self._counterparty = counterparty if counterparty is not None else UnavailableCounterparty(web3_client)
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # Recent pending txs by chain: {chain_id: {tx_hash: PendingTx}}
        self._pending: Dict[int, Dict[str, PendingTx]] = defaultdict(dict)
        # Where each chain's last snapshot came from: "txpool" or "block"
        self._pending_source: Dict[int, str] = {}

        # Recent swaps for sandwich detection, in the order they were seen, per chain and unordered
        # token pair: {(chain_id, token, token): [QueuedSwap]}
        self._swap_queue: Dict[tuple, List[QueuedSwap]] = defaultdict(list)
        # Sandwiches already reported per queue key, as (front-run tx hash, victim tx hash)
        self._reported_sandwiches: Dict[tuple, Set[tuple]] = defaultdict(set)

        # The newest alerts; the deque drops the oldest past its cap.
        self._alerts: Deque[MempoolAlert] = deque(maxlen=1000)

        # Chains to monitor (only chains with txpool or pending block support)
        self._monitored_chains: Set[int] = set()
        # Chains that never served a genuine pending block and answered "pending" with a sealed one
        # SEALED_MARK_AFTER times in a row, until when (time.monotonic()) the pending block is not
        # asked for again. Warned about once per chain.
        self._sealed_pending_until: Dict[int, float] = {}
        # Chains whose RPC has answered "pending" with a genuine pending block at least once.
        self._genuine_pending_chains: Set[int] = set()
        # Sealed answers in a row per chain, reset by a genuine pending block.
        self._sealed_streak: Dict[int, int] = {}
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
            for key in [k for k, q in self._swap_queue.items() if not q or now - q[-1].tx.seen_at >= 30]:
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
                streak = self._sealed_streak[chain_id] = self._sealed_streak.get(chain_id, 0) + 1
                if chain_id in self._genuine_pending_chains:
                    # This RPC serves genuine pending blocks, so a sealed answer came from one backend
                    # of a load-balanced endpoint: this poll observes nothing and the next asks again.
                    if streak == SEALED_WARN_AFTER:
                        logger.warning(
                            "Chain %s has answered 'pending' with a sealed block %d times in a row; its "
                            "mempool is not observed until it serves a pending block again",
                            chain_id, streak,
                        )
                    else:
                        logger.debug("Chain %s answered 'pending' with a sealed block this poll", chain_id)
                    return None
                if streak < SEALED_MARK_AFTER:
                    return None
                first = chain_id not in self._sealed_pending_until
                self._sealed_pending_until[chain_id] = time.monotonic() + MARK_RETRY_SECONDS
                if first:
                    logger.warning(
                        "Chain %s answers 'pending' with a sealed block; its pending-block fallback is "
                        "skipped and asked for again every %d s",
                        chain_id, MARK_RETRY_SECONDS,
                    )
                return None
            self._sealed_streak[chain_id] = 0
            self._genuine_pending_chains.add(chain_id)
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
            tokens = self._swap_tokens(tx.data)
            if tokens:
                # Both legs of a sandwich and the victim between them trade one pair, whichever way.
                key = (tx.chain_id, *sorted(tokens))
                queue = self._swap_queue[key]
                # A transaction that left a snapshot and came back is analysed again; it is queued once.
                if all(queued.tx.tx_hash != tx.tx_hash for queued in queue):
                    swap = QueuedSwap(tx, *tokens)
                    queue.append(swap)
                    await self._check_sandwich(key, swap)

        # Check for suspicious approvals
        if selector in APPROVE_SELECTORS:
            await self._check_suspicious_approval(tx)

    def _swap_tokens(self, data: str) -> Optional[tuple]:
        """(token_in, token_out) from a swap's own ABI, or None when its calldata names no pair.

        The selector says where the tokens are (V2_PATH_OFFSET_WORD and the V3 selectors); each end
        counts only when its word is an address, so an amount, an ABI offset or a zero word never
        does, and a swap of a token for itself is no pair. Malformed calldata gives None: every
        read is bounds-checked and a chunk that is not hex is caught.
        """
        selector = data[:10].lower()
        args = data[10:].lower()

        def word(index: int) -> Optional[int]:
            chunk = args[index * 64:(index + 1) * 64]
            return int(chunk, 16) if len(chunk) == 64 else None

        try:
            if selector in V2_PATH_OFFSET_WORD:
                offset = word(V2_PATH_OFFSET_WORD[selector])
                if offset is None or offset % 32:
                    return None
                length = word(offset // 32)
                if length is None or not 2 <= length <= MAX_SWAP_PATH_LENGTH:
                    return None
                token_in, token_out = word(offset // 32 + 1), word(offset // 32 + length)
            elif selector in V3_EXACT_INPUT_SINGLE_SELECTORS:
                token_in, token_out = word(0), word(1)
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
                if len(packed) != length * 2:
                    return None
                token_in, token_out = int(packed[:40], 16), int(packed[-40:], 16)
            else:
                return None
        except ValueError:
            return None
        tokens = (_token_address(token_in), _token_address(token_out))
        if None in tokens or tokens[0] == tokens[1]:
            return None
        return tokens

    async def _check_sandwich(self, key: tuple, newest: QueuedSwap):
        """Report the sandwiches the newest swap on this pair completes as their back-run.

        A sandwich is, in the order the swaps were seen: the attacker's front-run, a swap by
        another sender in the same direction that the front-run outbid on gas price (the victim),
        and the attacker's back-run, the reverse trade. Only the newest swap can be a back-run, so
        only its sender is tried as the attacker, only the sender's reverse trades before the
        victim are tried as the front-run (the nearest one that outbid the victim), and a
        (front-run, victim) pair is reported once however many back-runs follow it. The back-run's
        gas price is not compared: it lands after the victim by construction. A sender that trades
        one way again and again (a DCA bot, an aggregator's solver) reverses nothing and is never
        an attacker, whoever trades between its swaps.
        """
        chain_id = key[0]
        queue = self._swap_queue[key]

        # Prune old entries (> 30 seconds), and the reported pairs whose victim left the queue
        now = time.time()
        queue[:] = [swap for swap in queue if now - swap.tx.seen_at < 30]
        live = {swap.tx.tx_hash for swap in queue}
        reported = self._reported_sandwiches[key]
        reported.difference_update([pair for pair in reported if pair[1] not in live])
        if not queue or queue[-1] is not newest:
            return

        attacker = newest.tx.from_addr
        # The front-run and the victim trade the reverse of the back-run.
        direction = (newest.token_out, newest.token_in)
        fronts = [
            (index, swap) for index, swap in enumerate(queue)
            if swap.tx.from_addr == attacker and (swap.token_in, swap.token_out) == direction
        ]
        if not fronts:
            return

        for victim_index, victim in enumerate(queue[:-1]):
            if victim.tx.from_addr == attacker or (victim.token_in, victim.token_out) != direction:
                continue
            front = next(
                (
                    swap for index, swap in reversed(fronts)
                    if index < victim_index and swap.tx.gas_price > victim.tx.gas_price
                ),
                None,
            )
            if front is None or (front.tx.tx_hash, victim.tx.tx_hash) in reported:
                continue
            reported.add((front.tx.tx_hash, victim.tx.tx_hash))
            alert = MempoolAlert(
                alert_type="sandwich_attack",
                severity="HIGH",
                description=(
                    f"Sandwich attack detected on {victim.token_out[:10]}... — "
                    f"attacker {attacker[:10]}... front-ran victim {victim.tx.from_addr[:10]}... "
                    f"buying {victim.token_out[:10]}... with {victim.token_in[:10]}... at a higher "
                    f"gas price, then reversed the trade"
                ),
                victim_tx=victim.tx.tx_hash,
                attacker_tx=front.tx.tx_hash,
                attacker_addr=attacker,
                target_token=victim.token_out,
                chain_id=chain_id,
            )
            self._add_alert(alert)
            self._stats['sandwiches_detected'] += 1
            logger.warning(f"Sandwich detected: {alert.description}")

    async def _check_suspicious_approval(self, tx: PendingTx):
        """Alert on a pending approve() whose spender the process already knows to be bad.

        An approval is evidence of an attack only through its spender: a confirmed scam address,
        an address GoPlus labels a drainer, or a wallet rather than a contract (the drainer
        pattern), read from what is loaded in memory. An unlimited approval to an unknown
        contract is not one, and an allowlisted router or Permit2 never is. The counter counts
        alerts only.
        """
        try:
            data = tx.data.replace("0x", "")
            if len(data) < 136:
                return

            selector = "0x" + data[:8]
            if selector == "0x095ea7b3":
                # approve(spender, amount); amount 0 is a revoke and grants nothing.
                spender = "0x" + data[32:72][-40:]
                amount = int(data[72:136], 16)
                if amount == 0:
                    return
                evidence = self._spender_evidence(spender, tx.chain_id)
                if evidence is None:
                    return
                grant = "unlimited" if amount >= UNLIMITED_APPROVAL else "limited"
                alert = MempoolAlert(
                    alert_type="suspicious_approval",
                    severity="HIGH",
                    description=(
                        f"Token approval pending to {evidence} — "
                        f"{tx.from_addr[:10]}... approving {spender[:10]}... "
                        f"for {grant} tokens on contract {tx.to_addr[:10]}..."
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

    def _spender_evidence(self, spender: str, chain_id: int) -> Optional[str]:
        """What marks this spender as an attacker, or None; nothing is looked up.

        The chain's allowlist answers first, so a router that anyone can file reports against
        is never alerted. A community blacklist entry is three reports anyone can manufacture,
        not evidence, so only an admin entry counts. The counterparty facts are those a scan
        already fetched for this spender on this chain, judged as the scanner judges them.
        """
        if self._counterparty.allowlisted_name(spender, chain_id):
            return None
        match = self._scam_db.local_match(spender, chain_id) if self._scam_db else None
        if match and match['severity'] == 'block':
            return "a confirmed scam address (ShieldBot blacklist)"
        facts = self._counterparty.cached(spender, chain_id)
        if facts is None:
            return None
        if facts["labels"]:
            source = f" ({facts['label_source']})" if facts["label_source"] else ""
            return f"an address flagged by GoPlus: {', '.join(facts['labels'])}{source}"
        if facts["is_contract"] is False or facts["delegated"]:
            return "a wallet, not a contract (drainer pattern)"
        return None

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
