"""Mempool monitoring v1 — detect sandwich attacks, frontrunning, and suspicious pending transactions."""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import aiohttp
from web3 import Web3

logger = logging.getLogger(__name__)

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

    Uses a polling approach to txpool_content/txpool_inspect RPCs.
    Falls back to eth_getBlock('pending') for chains without txpool support.
    """

    def __init__(self, web3_client, db=None):
        self._web3_client = web3_client
        self._db = db
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # Recent pending txs by chain: {chain_id: {tx_hash: PendingTx}}
        self._pending: Dict[int, Dict[str, PendingTx]] = defaultdict(dict)

        # Recent swap txs for sandwich detection: {(chain_id, token): [PendingTx]}
        self._swap_queue: Dict[tuple, List[PendingTx]] = defaultdict(list)

        # Active alerts
        self._alerts: List[MempoolAlert] = []
        self._max_alerts = 1000

        # Chains to monitor (only chains with txpool or pending block support)
        self._monitored_chains: Set[int] = set()

        # Stats
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
        self._running = True
        self._monitored_chains = set(chain_ids or [56, 1])
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info(f"MempoolMonitor started for chains: {self._monitored_chains}")

    async def stop(self):
        """Stop monitoring."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("MempoolMonitor stopped")

    async def _monitor_loop(self):
        """Main monitoring loop — polls pending transactions."""
        while self._running:
            try:
                for chain_id in self._monitored_chains:
                    await self._poll_pending(chain_id)
                    self._prune_stale(chain_id)
                await asyncio.sleep(2)  # Poll every 2 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"MempoolMonitor error: {e}")
                await asyncio.sleep(5)

    async def _poll_pending(self, chain_id: int):
        """Poll pending transactions for a chain."""
        w3 = self._web3_client.get_web3(chain_id)
        if not w3:
            return

        try:
            # Try txpool_content first (Geth nodes)
            pending_txs = await self._get_txpool_content(w3, chain_id)
            if not pending_txs:
                # Fallback: get pending block
                pending_txs = await self._get_pending_block(w3, chain_id)

            for tx in pending_txs:
                if tx.tx_hash not in self._pending[chain_id]:
                    self._pending[chain_id][tx.tx_hash] = tx
                    self._stats['total_pending_seen'] += 1
                    await self._analyze_pending_tx(tx)

        except Exception as e:
            logger.debug(f"Pending poll failed for chain {chain_id}: {e}")

    async def _get_txpool_content(self, w3: Web3, chain_id: int) -> List[PendingTx]:
        """Fetch pending txs via txpool_content RPC."""
        txs = []
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, w3.provider.make_request, "txpool_content", []
            )
            pending = result.get("result", {}).get("pending", {})
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
        except Exception:
            pass
        return txs

    async def _get_pending_block(self, w3: Web3, chain_id: int) -> List[PendingTx]:
        """Fetch pending txs via eth_getBlockByNumber('pending')."""
        txs = []
        try:
            loop = asyncio.get_event_loop()
            block = await loop.run_in_executor(
                None, w3.eth.get_block, 'pending', True
            )
            for tx in (block.get("transactions") or []):
                if isinstance(tx, dict):
                    txs.append(PendingTx(
                        tx_hash=tx.get("hash", b"").hex() if isinstance(tx.get("hash"), bytes) else str(tx.get("hash", "")),
                        from_addr=(tx.get("from") or "").lower(),
                        to_addr=(tx.get("to") or "").lower(),
                        value=tx.get("value", 0),
                        gas_price=tx.get("gasPrice", 0),
                        data=(tx.get("input") or "0x").hex() if isinstance(tx.get("input"), bytes) else str(tx.get("input", "0x")),
                        chain_id=chain_id,
                    ))
        except Exception:
            pass
        return txs

    async def _analyze_pending_tx(self, tx: PendingTx):
        """Analyze a single pending transaction for threats."""
        selector = tx.data[:10].lower() if len(tx.data) >= 10 else ""

        # Check for swap transactions (sandwich detection)
        if selector in SWAP_SELECTORS:
            token = self._extract_token_from_swap(tx.data)
            if token:
                key = (tx.chain_id, token)
                self._swap_queue[key].append(tx)
                await self._check_sandwich(key)

        # Check for suspicious approvals
        if selector in APPROVE_SELECTORS:
            await self._check_suspicious_approval(tx)

    def _extract_token_from_swap(self, data: str) -> Optional[str]:
        """Extract the target token address from swap calldata."""
        try:
            # Most swap functions have the path parameter containing token addresses
            # The last token in the path is typically the output token
            if len(data) < 74:
                return None
            # For V2 routers, path starts at different offsets depending on function
            # Simplified: extract first address parameter after selector
            raw = data.replace("0x", "")
            if len(raw) >= 72:
                # First address param (after selector) is often amountIn or similar
                # Second address param is often the token
                addr = "0x" + raw[32:72][-40:]
                if Web3.is_address(addr):
                    return addr.lower()
        except Exception:
            pass
        return None

    async def _check_sandwich(self, key: tuple):
        """Check for sandwich attack patterns in the swap queue.

        A sandwich attack consists of:
        1. Attacker frontrun: large swap to move price
        2. Victim swap: executes at worse price
        3. Attacker backrun: reverse swap to capture profit
        """
        chain_id, token = key
        queue = self._swap_queue[key]

        # Need at least 2 swaps in quick succession to detect
        if len(queue) < 2:
            return

        # Prune old entries (> 30 seconds)
        now = time.time()
        queue[:] = [tx for tx in queue if now - tx.seen_at < 30]

        if len(queue) < 2:
            return

        # Look for same-sender pairs (frontrun + backrun) around different-sender tx
        senders = defaultdict(list)
        for tx in queue:
            senders[tx.from_addr].append(tx)

        for attacker, attacker_txs in senders.items():
            if len(attacker_txs) < 2:
                continue

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

                if front and back:
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
            logger.debug(f"Approval analysis error: {e}")

    def _add_alert(self, alert: MempoolAlert):
        """Add an alert and maintain max size."""
        self._alerts.append(alert)
        if len(self._alerts) > self._max_alerts:
            self._alerts = self._alerts[-self._max_alerts:]

    def _prune_stale(self, chain_id: int):
        """Remove pending txs older than 60 seconds."""
        now = time.time()
        stale = [h for h, tx in self._pending[chain_id].items() if now - tx.seen_at > 60]
        for h in stale:
            del self._pending[chain_id][h]

    def get_alerts(self, chain_id: int = None, limit: int = 50) -> List[Dict]:
        """Get recent alerts, optionally filtered by chain."""
        alerts = self._alerts
        if chain_id:
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
            'monitored_chains': list(self._monitored_chains),
            'pending_count': {
                cid: len(txs) for cid, txs in self._pending.items()
            },
            'active_alerts': len(self._alerts),
        }
