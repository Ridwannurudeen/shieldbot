"""Rescue Mode — Tier 1 (alerts with explanations) and Tier 2 (pre-built revoke transactions).

Scans a wallet's active token approvals, identifies risky ones, and generates
ready-to-sign revocation transactions for one-click cleanup.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
from cachetools import TTLCache
from web3 import Web3

from utils.chain_info import get_dexscreener_slug

logger = logging.getLogger(__name__)

# ERC-20 Approval event topic
APPROVAL_TOPIC = Web3.keccak(text="Approval(address,address,uint256)").hex()

# ApprovalForAll event topic (ERC-721/1155)
APPROVAL_FOR_ALL_TOPIC = Web3.keccak(text="ApprovalForAll(address,address,bool)").hex()

# A chain without a configured logs RPC is read through its adapter's public RPC, which serves no
# archive history, so rescue reads only recent approval history there: 24 windows of 10,000
# blocks, newest first (240,000 blocks; about 6.7 hours on Robinhood Chain at ~0.1 s per block,
# whose public Blockscout API answers server clients with a Cloudflare challenge). Measured on
# 2026-09-24, the default public RPCs of Robinhood Chain, Arbitrum, Optimism and opBNB serve such
# windows and Base's serves 2,000 blocks at a time; BSC's answers "limit exceeded" to any range
# (re-measured 2026-09-26: every range from 10 to 10,000 blocks, at the head or 30M blocks back,
# within 1.2 s), and Ethereum's and Polygon's refuse a query without a contract address, so on
# those three nothing is read and the scan stays unknown.
RECENT_LOG_WINDOW_BLOCKS = 10_000
# Public RPCs that cap an eth_getLogs range below RECENT_LOG_WINDOW_BLOCKS, by chain.
PUBLIC_LOG_WINDOW_BLOCKS = {8453: 2_000}
RECENT_LOG_WINDOWS = 24
PUBLIC_RPC_CONCURRENCY = 4
PUBLIC_RPC_ATTEMPTS = 3
RATE_LIMIT_TERMS = ("rate limit", "rate-limit", "too many requests")

# A scan answers within SCAN_DEADLINE_SECONDS or says it did not finish: nginx closes the API's
# connection at 60 s (deploy/nginx-api.conf.example) and the extension's Health tab gives up at
# 60 s (extension/popup.js), so a scan that ran on answered nobody. On 2026-09-26 production's BSC
# scan did just that: with no deadline, a logs RPC's full history is 2,484 chunks at BSC's 124M
# blocks, each request allowed 15 s, and the window fallback adds up to 6 batches of 48 s. 30 s
# keeps the same headroom as the token scan's 25 s analyzer deadline (core/registry.py). The
# approval-history read gets HISTORY_DEADLINE_SECONDS of it: it keeps the batches read by then and
# coverage names the oldest block read, so the allowance, balance, price and metadata reads that
# follow keep at least 10 s.
SCAN_DEADLINE_SECONDS = 30
HISTORY_DEADLINE_SECONDS = 20
# Reason given when the scan as a whole did not finish within SCAN_DEADLINE_SECONDS.
SCAN_TIMEOUT_REASON = f"Approval scan did not finish within {SCAN_DEADLINE_SECONDS} s"

# A wallet's scan result is reused this long, so repeated calls do not re-run a history scan
# (a full archive scan sends thousands of requests), while a revoke still shows within minutes.
RESULT_CACHE_SECONDS = 120
# Reason given when the chain's RPC could not be read. It names no provider: errors from the RPC
# client can carry its URL.
RPC_UNAVAILABLE_REASON = "Approval data unavailable from the chain's RPC"
# Reason given when the RPC answered but served none of the recent approval history.
NOTHING_READ_REASON = "No approval history could be read from the chain's RPC"

UNLIMITED_THRESHOLD = 2**128
# Approvals above this (but below UNLIMITED_THRESHOLD) are considered "large"
HIGH_APPROVAL = 10**24  # ~1 million tokens at 18 decimals

# Known safe spenders by chain (major DEX routers, aggregators and lending protocols). Approvals to
# these are lower risk than to unknown contracts. An address is trusted only on the chains listed:
# the same address on another chain can hold other code or none. On 2026-09-24 every address held
# code on each chain it is listed under (eth_getCode on that chain's public RPC). Where a contract
# exposes one, its own getter also named the expected contract there: factory() with WETH() or
# WETH9() for the DEX routers (and positionManager() for the PancakeSwap Smart Router),
# defaultFactory() for Aerodrome and Velodrome, poolManager() for the Uniswap Universal Routers
# outside Ethereum, name() and underlying() for the Venus markets, and one owner() on every chain
# for KyberSwap and OpenOcean; the Ethereum Universal Router is in Uniswap's deploy-addresses list.
# 1inch documents its V6 router at the same address on every chain but zkSync; on each chain
# listed, V6 answers the same owner() as V5, whose code there is the same size as on Ethereum.
# Addresses holding other code on a chain are left off it: PancakeSwap V2 and ApeSwap on Ethereum,
# Uniswap V2 and the Universal Router on BSC, where Uniswap documents other addresses, and the
# PancakeSwap Smart Router on Base (no code on Arbitrum).
KNOWN_SAFE_SPENDERS = {
    56: {
        "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap V2",
        "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": "PancakeSwap Smart Router",
        "0x1b81d678ffb9c0263b24a97847620c99d213eb14": "PancakeSwap V3 Swap Router",
        "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": "SushiSwap",
        "0x111111125421ca6dc452d289314280a0f8842a65": "1inch V6",
        "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
        "0x3a6d8ca21d1cf76f653a67577fa0d27453350dd8": "Biswap Router",
        "0xcf0febd3f17cef5b47b0cd257acf6025c5bff3b7": "ApeSwap Router",
        "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap Meta Aggregation Router V2",
        "0x6352a56caadc4f1e25cd6c75970fa768a3304e64": "OpenOcean Exchange V2",
        "0x1a1ec25dc08e98e5e93f1104b5e5cdd298707d31": "MetaMask Swap Router",
        # Venus Protocol vToken markets: users approve these to supply assets
        "0xfd5840cd36d94d7229439859c0112a4185bc0255": "Venus Protocol (vUSDT)",
        "0x95c78222b3d6e262426483d42cfa53685a67ab9d": "Venus Protocol (vBUSD)",
        # Radiant Capital's lending pool (0xd50cf00b...) is left off: since the October 2024 hack its
        # implementation pulls approved funds (Revoke.cash's approval exploit list).
        "0xa625ab01b08ce023b2a342dbb12a16f2c8489a8f": "Alpaca Finance FairLaunch",
        "0x19609b03c976cca288fbdae5c21d4290e9a4add7": "Wombat Exchange Router",
        "0x4a364f8c717caad9a442737eb7b8a55cc6cf18d8": "Stargate Finance Router",
    },
    1: {
        "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": "PancakeSwap Smart Router",
        "0x1b81d678ffb9c0263b24a97847620c99d213eb14": "PancakeSwap V3 Swap Router",
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2",
        "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3",
        "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
        "0x111111125421ca6dc452d289314280a0f8842a65": "1inch V6",
        "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
        "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap Meta Aggregation Router V2",
        "0x6352a56caadc4f1e25cd6c75970fa768a3304e64": "OpenOcean Exchange V2",
    },
    8453: {
        "0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43": "Aerodrome Router",
        "0x2626664c2603336e57b271c5c0b26f421741e481": "Uniswap SwapRouter02",
        "0x6ff5693b99212da76ad316178a184ab56d299b43": "Uniswap Universal Router",
        "0x1b81d678ffb9c0263b24a97847620c99d213eb14": "PancakeSwap V3 Swap Router",
        "0x111111125421ca6dc452d289314280a0f8842a65": "1inch V6",
        "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
        "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap Meta Aggregation Router V2",
        "0x6352a56caadc4f1e25cd6c75970fa768a3304e64": "OpenOcean Exchange V2",
    },
    10: {
        "0xa062ae8a9c5e11aaa026fc2670b0d65ccc8b2858": "Velodrome Router",
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap SwapRouter02",
        "0x851116d9223fabed8e56c0e6b8ad0c31d98b3507": "Uniswap Universal Router",
        "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3",
        "0x111111125421ca6dc452d289314280a0f8842a65": "1inch V6",
        "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
        "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap Meta Aggregation Router V2",
        "0x6352a56caadc4f1e25cd6c75970fa768a3304e64": "OpenOcean Exchange V2",
    },
    42161: {
        "0xc873fecbd354f5a56e00e710b90ef4201db2448d": "Camelot Router",
        "0x1f721e2e82f6676fce4ea07a5958cf098d339e18": "Camelot V3 Swap Router",
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap SwapRouter02",
        "0xa51afafe0263b40edaef0df8781ea9aa03e381a3": "Uniswap Universal Router",
        "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3",
        "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": "SushiSwap",
        "0x1b81d678ffb9c0263b24a97847620c99d213eb14": "PancakeSwap V3 Swap Router",
        "0x111111125421ca6dc452d289314280a0f8842a65": "1inch V6",
        "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
        "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap Meta Aggregation Router V2",
        "0x6352a56caadc4f1e25cd6c75970fa768a3304e64": "OpenOcean Exchange V2",
    },
    137: {
        "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff": "QuickSwap Router",
        "0xf5b509bb0909a69b1c207e495f687a596c168e12": "QuickSwap V3 Swap Router",
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap SwapRouter02",
        "0x1095692a6237d83c6a72f3f5efedb9a670c49223": "Uniswap Universal Router",
        "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3",
        "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": "SushiSwap",
        "0x111111125421ca6dc452d289314280a0f8842a65": "1inch V6",
        "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
        "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap Meta Aggregation Router V2",
        "0x6352a56caadc4f1e25cd6c75970fa768a3304e64": "OpenOcean Exchange V2",
    },
}

# Stablecoins by chain — price = $1.00 without an API call, only on the chain they live on
STABLECOINS = {
    56: {
        "0x55d398326f99059ff775485246999027b3197955",  # BSC USDT
        "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",  # BSC USDC
        "0xe9e7cea3dedca5984780bafc599bd69add087d56",  # BUSD
        "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3",  # DAI on BSC
    },
    1: {
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # ETH USDC
        "0xdac17f958d2ee523a2206206994597c13d831ec7",  # ETH USDT
        "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
    },
}


def _known_spender(spender: str, chain_id: int) -> Optional[str]:
    """Label of a known safe spender on ``chain_id``, or None."""
    return KNOWN_SAFE_SPENDERS.get(chain_id, {}).get(spender)


def _is_rate_limited(error) -> bool:
    """Whether a JSON-RPC error asks the caller to slow down rather than rejecting the query."""
    if isinstance(error, dict):
        if error.get("code") == 429:
            return True
        error = error.get("message", "")
    text = str(error).lower()
    return any(term in text for term in RATE_LIMIT_TERMS)


@dataclass
class ApprovalInfo:
    """Information about a single token approval."""
    token_address: str
    token_name: str
    token_symbol: str
    spender: str
    spender_label: str
    allowance: str          # Human-readable current on-chain allowance
    allowance_raw: int      # Current on-chain allowance (verified via eth_call)
    risk_level: str         # HIGH, MEDIUM, LOW
    risk_reason: str
    chain_id: int
    balance_raw: int = 0
    value_at_risk_usd: Optional[float] = None
    revoke_tx: Optional[Dict[str, Any]] = None


@dataclass
class RescueAlert:
    """Tier 1 alert with explanation and recommended actions."""
    alert_type: str
    severity: str
    title: str
    description: str
    what_it_means: str
    what_you_can_do: List[str]
    affected_token: Optional[str] = None
    affected_spender: Optional[str] = None
    chain_id: int = 56


class RescueService:
    """Rescue Mode service — scans approvals and generates revoke transactions."""

    # Override with LOGS_RPC_URL (BSC default) or per-chain entries in logs_rpcs.
    _DEFAULT_LOGS_RPC = ""
    _DEXSCREENER_API = "https://api.dexscreener.com/tokens/v1"

    def __init__(
        self,
        web3_client,
        db=None,
        logs_rpc: str = "",
        logs_rpcs: Optional[Dict[int, str]] = None,
    ):
        self._web3_client = web3_client
        self._db = db
        # Backward-compat: logs_rpc treated as the BSC (chain 56) entry.
        rpcs: Dict[int, str] = dict(logs_rpcs or {})
        bsc_rpc = logs_rpc or self._DEFAULT_LOGS_RPC
        if bsc_rpc and 56 not in rpcs:
            rpcs[56] = bsc_rpc
        self._logs_rpcs: Dict[int, str] = rpcs
        # Kept for callers that still read it (read-only).
        self._logs_rpc = self._logs_rpcs.get(56, "")
        self._results = TTLCache(maxsize=1024, ttl=RESULT_CACHE_SECONDS)

    def approval_history(self, chain_id: int) -> Dict[str, Any]:
        """How much approval history a scan on chain_id reads: all of it from a configured logs RPC,
        or the newest windows from the chain's own RPC. Names no RPC, since its URL can carry a key."""
        if chain_id in self._logs_rpcs:
            return {"history": "full", "window_blocks": None}
        window = PUBLIC_LOG_WINDOW_BLOCKS.get(chain_id, RECENT_LOG_WINDOW_BLOCKS)
        return {"history": "recent", "window_blocks": window * RECENT_LOG_WINDOWS}

    def _rpc_for(self, chain_id: int) -> str:
        """Resolve archive RPC URL for a chain. Falls back to the registered adapter's RPC."""
        adapter = self._web3_client._get_adapter(chain_id) if self._web3_client else None
        url = self._logs_rpcs.get(chain_id)
        if url:
            return url
        if adapter is not None:
            provider = getattr(getattr(adapter, "w3", None), "provider", None)
            endpoint = getattr(provider, "endpoint_uri", None)
            if endpoint:
                return endpoint
        return ""

    async def scan_approvals(
        self, wallet_address: str, chain_id: int = 56, etherscan_api_key: str = ""
    ) -> Dict[str, Any]:
        """Scan a wallet's active token approvals and assess risk.

        Returns a dict with:
        - approvals: list of ApprovalInfo (verified on-chain, no false positives)
        - alerts: list of RescueAlert (Tier 1)
        - revoke_txs: list of pre-built revoke transactions (Tier 2)
        - total_value_at_risk_usd: aggregate USD value exposed (None when incomplete)
        - summary: risk summary
        - status, coverage, coverage_reasons: "unknown" when the approval history read, allowances,
          balances or prices are incomplete, including when the chain's RPC could not be read
        - scanned_blocks: the block range whose approval history was read, or None when none was

        The scan answers within SCAN_DEADLINE_SECONDS: the approval-history read stops at
        HISTORY_DEADLINE_SECONDS and keeps what it read by then, and a scan whose later steps did
        not finish either is "unknown" with SCAN_TIMEOUT_REASON.

        A result is reused for RESULT_CACHE_SECONDS per wallet and chain once some approval history
        was read. A scan that read none is not: that is often a passing timeout or rate limit, so
        the next call tries again.
        """
        wallet = wallet_address.lower()
        cached = self._results.get((chain_id, wallet))
        if cached is not None:
            return cached
        try:
            async with asyncio.timeout(SCAN_DEADLINE_SECONDS):
                approvals, coverage_reasons, scanned_blocks = await self._fetch_approvals(wallet, chain_id)
        except TimeoutError:
            logger.warning(
                "Approval scan on chain %s did not finish within %s s", chain_id, SCAN_DEADLINE_SECONDS
            )
            approvals, coverage_reasons, scanned_blocks = [], {"allowances": SCAN_TIMEOUT_REASON}, None
        except RuntimeError:
            approvals, coverage_reasons, scanned_blocks = [], {"allowances": RPC_UNAVAILABLE_REASON}, None

        alerts = []
        revoke_txs = []
        high_risk_count = 0
        medium_risk_count = 0
        total_value_at_risk = 0.0

        for approval in approvals:
            # Generate Tier 1 alert
            alert = self._generate_alert(approval)
            if alert:
                alerts.append(alert)

            # Generate Tier 2 revoke transaction
            if approval.risk_level in ("HIGH", "MEDIUM"):
                revoke_tx = self._build_revoke_tx(
                    wallet, approval.token_address, approval.spender, chain_id
                )
                approval.revoke_tx = revoke_tx
                revoke_txs.append({
                    'token': approval.token_address,
                    'token_symbol': approval.token_symbol,
                    'spender': approval.spender,
                    'spender_label': approval.spender_label,
                    'risk_level': approval.risk_level,
                    'value_at_risk_usd': approval.value_at_risk_usd,
                    'transaction': revoke_tx,
                })

            if approval.risk_level == "HIGH":
                high_risk_count += 1
            elif approval.risk_level == "MEDIUM":
                medium_risk_count += 1

            if approval.value_at_risk_usd:
                total_value_at_risk += approval.value_at_risk_usd

        result = {
            'wallet': wallet,
            'chain_id': chain_id,
            'total_approvals': len(approvals),
            'high_risk': high_risk_count,
            'medium_risk': medium_risk_count,
            'total_value_at_risk_usd': None if coverage_reasons else round(total_value_at_risk, 2),
            'approvals': [self._approval_to_dict(a) for a in approvals],
            'alerts': [self._alert_to_dict(a) for a in alerts],
            'revoke_txs': revoke_txs,
            'status': 'unknown' if coverage_reasons else 'ok',
            'coverage': {key: key not in coverage_reasons for key in ('allowances', 'balances', 'prices')},
            'coverage_reasons': coverage_reasons,
            'scanned_blocks': scanned_blocks,
            'scanned_at': time.time(),
        }
        if scanned_blocks is not None:
            self._results[(chain_id, wallet)] = result
        return result

    async def _fetch_approvals(
        self, wallet: str, chain_id: int, api_key: str = ""
    ) -> Tuple[List[ApprovalInfo], Dict[str, str], Optional[Dict[str, int]]]:
        """Fetch and verify active token approvals, with reasons for incomplete data.

        Also returns the block range whose approval history was read, or None when none was.
        Raises RuntimeError when the chain's RPC could not be read.

        Pipeline:
          1. eth_getLogs — the history from a configured logs RPC, newest first at CONCURRENCY=50,
             or the newest RECENT_LOG_WINDOWS windows from the chain's public RPC, or from the logs
             RPC when it served none of its chunks; the read stops at HISTORY_DEADLINE_SECONDS and
             keeps the blocks read by then
          2. Deduplicate to latest event per (token, spender)
          3. eth_call allowance() — verify each pair is still non-zero on-chain
          4. eth_call balanceOf() — get wallet's token balances
          5. DexScreener — fetch token prices for USD risk calculation
          6. Enrich with token metadata (parallelized)
        """
        from utils.web3_client import UnsupportedChainError

        approvals = []
        coverage_reasons: Dict[str, str] = {}
        rpc_url = self._rpc_for(chain_id)
        if not rpc_url:
            logger.warning(f"No logs RPC configured for chain {chain_id}")
            raise RuntimeError(f"Approval scan unavailable: no logs RPC configured for chain {chain_id}")
        public_rpc = chain_id not in self._logs_rpcs
        deadline = asyncio.get_running_loop().time() + HISTORY_DEADLINE_SECONDS
        try:
            if not public_rpc:
                budget = asyncio.timeout_at(deadline)
                try:
                    all_logs, scanned_from, latest = await self._fetch_all_approval_logs(
                        wallet, rpc_url, budget
                    )
                except UnsupportedChainError:
                    raise
                except Exception as e:
                    # Read what the logs RPC can serve instead, the rate-limit-aware way.
                    logger.warning("Full approval history unavailable: %s", type(e).__name__)
                    public_rpc = True
                else:
                    # A logs RPC that served none of its chunks is read that way too, unless the
                    # deadline stopped the read: then nothing more is asked of it.
                    public_rpc = scanned_from > latest and not budget.expired()
            if public_rpc:
                all_logs, scanned_from, latest = await self._fetch_recent_approval_logs(
                    wallet, rpc_url, PUBLIC_LOG_WINDOW_BLOCKS.get(chain_id, RECENT_LOG_WINDOW_BLOCKS),
                    asyncio.timeout_at(deadline),
                )
            if scanned_from > latest:
                coverage_reasons["allowances"] = NOTHING_READ_REASON
            elif scanned_from > 0:
                coverage_reasons["allowances"] = f"Approvals before block {scanned_from} not scanned"
            scanned_blocks = (
                {"from_block": scanned_from, "to_block": latest} if scanned_from <= latest else None
            )

            # Step 3: Keep latest event per (token, spender)
            latest_events: Dict[tuple, Dict] = {}
            for log in all_logs:
                try:
                    token = log["address"].lower()
                    topics = log.get("topics", [])
                    if len(topics) < 3:
                        continue
                    spender = "0x" + topics[2][-40:]
                    amount_hex = log.get("data", "0x0")
                    amount = int(amount_hex, 16) if amount_hex and amount_hex != "0x" else 0
                    block = int(log.get("blockNumber", "0x0"), 16)

                    key = (token, spender.lower())
                    existing = latest_events.get(key)
                    if not existing or block > existing["block"]:
                        latest_events[key] = {
                            "token": token,
                            "spender": spender.lower(),
                            "amount": amount,
                            "block": block,
                        }
                except (ValueError, IndexError, KeyError):
                    continue

            # Filter out already-revoked events before hitting the chain
            candidates = {k: v for k, v in latest_events.items() if v["amount"] > 0}
            if not candidates:
                return [], coverage_reasons, scanned_blocks

            # Step 4: Verify current on-chain allowances — eliminates false positives
            allowances = await self._verify_allowances(wallet, candidates, rpc_url, public_rpc)
            unresolved = [pair for pair, allowance in allowances.items() if allowance is None]
            if unresolved:
                reason = f"Allowance unavailable for {len(unresolved)} approval(s)"
                history_reason = coverage_reasons.get("allowances")
                coverage_reasons["allowances"] = f"{history_reason}; {reason}" if history_reason else reason
            verified = {pair: allowance for pair, allowance in allowances.items() if allowance}
            if not verified:
                return [], coverage_reasons, scanned_blocks

            # Step 5: Fetch wallet balances for value-at-risk calculation
            active_tokens = list({token for (token, _) in verified.keys()})
            balances = await self._fetch_balances(wallet, active_tokens, rpc_url, public_rpc)
            unresolved_balances = [token for token in active_tokens if token not in balances]
            if unresolved_balances:
                coverage_reasons["balances"] = f"Balance unavailable for {len(unresolved_balances)} token(s)"

            # Step 6: Fetch token prices (DexScreener, stablecoins hardcoded)
            prices = await self._fetch_prices(active_tokens, chain_id)
            unpriced = [
                token for token in active_tokens
                if (token not in balances or balances[token] > 0) and token not in prices
            ]
            if unpriced:
                coverage_reasons["prices"] = f"USD price unavailable for {len(unpriced)} token(s)"

            # Step 7: Enrich with token metadata — parallelized
            token_info_results = await asyncio.gather(
                *[self._web3_client.get_token_info(token, chain_id) for token in active_tokens],
                return_exceptions=True,
            )
            token_info_map: Dict[str, Dict] = {}
            for token, result in zip(active_tokens, token_info_results):
                if isinstance(result, Exception):
                    raise result
                if isinstance(result, dict):
                    token_info_map[token] = result
                else:
                    token_info_map[token] = {}

            # Build ApprovalInfo for each verified active approval
            for (token, spender), current_allowance in verified.items():
                token_info = token_info_map.get(token, {})
                name = token_info.get("name", "Unknown")
                symbol = token_info.get("symbol", "???")
                decimals = token_info.get("decimals", 18)

                spender_label = _known_spender(spender, chain_id) or "Unknown Contract"
                risk_level, risk_reason = self._assess_approval_risk(
                    spender, current_allowance, spender_label, chain_id
                )

                if current_allowance >= UNLIMITED_THRESHOLD:
                    allowance_str = "Unlimited"
                else:
                    try:
                        allowance_str = f"{current_allowance / (10 ** decimals):,.2f}"
                    except Exception:
                        allowance_str = str(current_allowance)

                # USD value at risk = min(allowance, balance) * price
                balance = balances.get(token, 0)
                price = prices.get(token)
                value_at_risk_usd = None
                if price is not None and balance > 0:
                    try:
                        at_risk_raw = min(current_allowance, balance)
                        at_risk_tokens = at_risk_raw / (10 ** decimals)
                        value_at_risk_usd = round(at_risk_tokens * price, 2)
                    except Exception:
                        pass

                approvals.append(
                    ApprovalInfo(
                        token_address=token,
                        token_name=name,
                        token_symbol=symbol,
                        spender=spender,
                        spender_label=spender_label,
                        allowance=allowance_str,
                        allowance_raw=current_allowance,
                        risk_level=risk_level,
                        risk_reason=risk_reason,
                        chain_id=chain_id,
                        balance_raw=balance,
                        value_at_risk_usd=value_at_risk_usd,
                    )
                )

        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Error fetching approvals: %s", type(e).__name__)
            raise RuntimeError("Approval scan unavailable") from e

        # Sort HIGH → MEDIUM → LOW, then by USD value at risk descending
        risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        approvals.sort(
            key=lambda a: (risk_order.get(a.risk_level, 3), -(a.value_at_risk_usd or 0))
        )
        return approvals, coverage_reasons, scanned_blocks

    async def _fetch_all_approval_logs(
        self, wallet: str, rpc_url: str, budget: asyncio.Timeout
    ) -> Tuple[list, int, int]:
        """Fetch Approval logs from the latest block of a logs RPC back towards genesis.

        Chunks of CHUNK_SIZE blocks are read newest first, CONCURRENCY at a time, until genesis, a
        batch in which a chunk stayed unavailable, or ``budget`` (an asyncio timeout, entered here)
        expires, when the batch in flight is dropped. The logs read before that are kept, so what
        was read has no gap.
        Returns those logs, the oldest block of the history read (the latest block plus one when
        nothing was read) and the latest block. Raises when the latest block could not be read.
        """
        from utils.web3_client import UnsupportedChainError

        CHUNK_SIZE = 49_999
        CONCURRENCY = 50
        topic0 = APPROVAL_TOPIC
        topic1 = "0x" + wallet.replace("0x", "").lower().zfill(64)

        async with aiohttp.ClientSession() as session:
            async with session.post(
                rpc_url,
                json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                bn_data = await resp.json()
            if "error" in bn_data or "result" not in bn_data:
                raise RuntimeError(f"eth_blockNumber failed: {bn_data.get('error', bn_data)}")
            latest = int(bn_data["result"], 16)
            chunks = [
                (max(to_b - CHUNK_SIZE + 1, 0), to_b) for to_b in range(latest, -1, -CHUNK_SIZE)
            ]

            logs: list = []
            scanned_from = latest + 1
            try:
                async with budget:
                    for i in range(0, len(chunks), CONCURRENCY):
                        batch = chunks[i: i + CONCURRENCY]
                        results = await asyncio.gather(
                            *[
                                self._fetch_log_chunk(
                                    session, rpc_url, topic0, topic1, hex(from_b), hex(to_b)
                                )
                                for from_b, to_b in batch
                            ],
                            return_exceptions=True,
                        )
                        gap = False
                        for (from_b, to_b), result in zip(batch, results):
                            if isinstance(result, UnsupportedChainError):
                                raise result
                            # Logs past a gap are left out, so the approvals match the blocks read.
                            if isinstance(result, list) and not gap:
                                logs.extend(result)
                                scanned_from = from_b
                            else:
                                gap = True
                        if gap:
                            break
            except TimeoutError:
                logger.warning(
                    "Approval history read stopped at its %s s deadline; blocks before %s not read",
                    HISTORY_DEADLINE_SECONDS, scanned_from,
                )
        return logs, scanned_from, latest

    async def _fetch_recent_approval_logs(
        self, wallet: str, rpc_url: str, window_blocks: int, budget: asyncio.Timeout
    ) -> Tuple[list, int, int]:
        """Fetch Approval logs from the newest RECENT_LOG_WINDOWS block windows of a public RPC.

        Windows of ``window_blocks`` are read newest first, PUBLIC_RPC_CONCURRENCY at a time.
        Scanning stops after a batch in which a window stayed unavailable, or when ``budget`` (an
        asyncio timeout, entered here) expires, when the batch in flight is dropped; the logs read
        before that are kept. Returns those logs, the oldest block of the history read without a
        gap (the latest block plus one when nothing was read) and the latest block. Raises when the
        latest block was not read before the budget expired.
        """
        topics = [APPROVAL_TOPIC, "0x" + wallet.replace("0x", "").lower().zfill(64)]
        async with aiohttp.ClientSession() as session:
            latest = None
            logs: list = []
            try:
                async with budget:
                    latest = int(await self._public_rpc(session, rpc_url, "eth_blockNumber", []), 16)
                    oldest = max(latest - window_blocks * RECENT_LOG_WINDOWS + 1, 0)
                    windows = [
                        (max(to_b - window_blocks + 1, oldest), to_b)
                        for to_b in range(latest, oldest - 1, -window_blocks)
                    ]
                    scanned_from = latest + 1
                    gap = False
                    for i in range(0, len(windows), PUBLIC_RPC_CONCURRENCY):
                        batch = windows[i: i + PUBLIC_RPC_CONCURRENCY]
                        results = await asyncio.gather(
                            *[
                                self._public_rpc(
                                    session, rpc_url, "eth_getLogs",
                                    [{"topics": topics, "fromBlock": hex(from_b), "toBlock": hex(to_b)}],
                                )
                                for from_b, to_b in batch
                            ],
                            return_exceptions=True,
                        )
                        for (from_b, to_b), result in zip(batch, results):
                            if isinstance(result, list):
                                # Logs past a gap are left out, so the approvals match the blocks read.
                                if not gap:
                                    logs.extend(result)
                                    scanned_from = from_b
                            else:
                                # Don't log `result` — aiohttp errors embed the RPC URL.
                                logger.warning(
                                    "Approval log window %s-%s unavailable: %s",
                                    from_b, to_b, type(result).__name__,
                                )
                                gap = True
                        if gap:
                            break
            except TimeoutError:
                if latest is None:
                    raise RuntimeError("Approval history unavailable before the scan deadline")
                logger.warning(
                    "Approval history read stopped at its %s s deadline; blocks before %s not read",
                    HISTORY_DEADLINE_SECONDS, scanned_from,
                )
        return logs, scanned_from, latest

    async def _public_rpc(
        self, session: aiohttp.ClientSession, rpc_url: str, method: str, params: list
    ) -> Any:
        """Make a JSON-RPC call to a rate-limited public RPC and return its result.

        HTTP 429 and rate-limit errors are retried with 1 s then 2 s backoff; the call raises when it
        fails or is still rate limited after PUBLIC_RPC_ATTEMPTS attempts.
        """
        for attempt in range(PUBLIC_RPC_ATTEMPTS):
            if attempt:
                await asyncio.sleep(2 ** (attempt - 1))
            async with session.post(
                rpc_url,
                json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 429:
                    continue
                if resp.status != 200:
                    raise RuntimeError("Public RPC request failed")
                data = await resp.json()
            error = data.get("error")
            if error is None:
                return data.get("result")
            if not _is_rate_limited(error):
                raise RuntimeError("Public RPC request returned an error")
        raise RuntimeError("Public RPC still rate limited")

    async def _public_eth_call(
        self, session: aiohttp.ClientSession, rpc_url: str, to: str, data: str
    ) -> Optional[int]:
        """eth_call through _public_rpc. A call that returned no data or stayed unavailable is None."""
        try:
            result = await self._public_rpc(
                session, rpc_url, "eth_call", [{"to": to, "data": data}, "latest"]
            )
            if not isinstance(result, str) or result in ("", "0x"):
                return None
            return int(result, 16)
        except Exception as e:
            logger.warning("Approval state call unavailable: %s", type(e).__name__)
            return None

    async def _fetch_log_chunk(
        self,
        session: aiohttp.ClientSession,
        rpc_url: str,
        topic0: str,
        topic1: str,
        from_b: str,
        to_b: str,
    ) -> list:
        """Fetch a single block-range chunk of Approval logs via eth_getLogs."""
        from utils.web3_client import UnsupportedChainError

        try:
            async with session.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_getLogs",
                    "params": [{"topics": [topic0, topic1], "fromBlock": from_b, "toBlock": to_b}],
                    "id": 1,
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError("Approval log request failed")
                data = await resp.json()
            if "error" in data or not isinstance(data.get("result"), list):
                raise RuntimeError("Approval logs unavailable")
            return data["result"]
        except UnsupportedChainError:
            raise
        except Exception as e:
            # Don't include `e` — aiohttp errors embed the RPC URL, which may carry an API key.
            logger.warning("Log chunk %s-%s failed: %s", from_b, to_b, type(e).__name__)
            raise

    async def _verify_allowances(
        self, wallet: str, candidates: Dict[tuple, Dict], rpc_url: str, public_rpc: bool = False
    ) -> Dict[tuple, Optional[int]]:
        """Batch-verify current on-chain allowances via eth_call.

        Eliminates false positives where approval events exist but the
        allowance has been consumed (spent) or explicitly revoked.
        Pairs whose allowance call returned no data map to None; on a public
        RPC, so do calls that stayed unavailable.
        """
        # allowance(address owner, address spender) → uint256
        selector = "0xdd62ed3e"
        owner_padded = wallet.replace("0x", "").lower().zfill(64)

        pairs = list(candidates.keys())
        verified: Dict[tuple, int] = {}
        CONCURRENCY = PUBLIC_RPC_CONCURRENCY if public_rpc else 50
        eth_call = self._public_eth_call if public_rpc else self._eth_call

        async with aiohttp.ClientSession() as session:
            for i in range(0, len(pairs), CONCURRENCY):
                batch = pairs[i: i + CONCURRENCY]
                tasks = []
                for (token, spender) in batch:
                    spender_padded = spender.replace("0x", "").lower().zfill(64)
                    calldata = f"{selector}{owner_padded}{spender_padded}"
                    tasks.append(eth_call(session, rpc_url, token, calldata))

                results = await asyncio.gather(*tasks, return_exceptions=True)
                for (token, spender), result in zip(batch, results):
                    if isinstance(result, Exception):
                        raise result
                    if result is None or (isinstance(result, int) and result > 0):
                        verified[(token, spender)] = result

        return verified

    async def _fetch_balances(
        self, wallet: str, tokens: List[str], rpc_url: str, public_rpc: bool = False
    ) -> Dict[str, int]:
        """Batch-fetch wallet token balances via eth_call, omitting calls that returned no data.

        On a public RPC, calls that stayed unavailable are omitted too.
        """
        # balanceOf(address owner) → uint256
        selector = "0x70a08231"
        owner_padded = wallet.replace("0x", "").lower().zfill(64)

        balances: Dict[str, int] = {}
        CONCURRENCY = PUBLIC_RPC_CONCURRENCY if public_rpc else 50
        eth_call = self._public_eth_call if public_rpc else self._eth_call

        async with aiohttp.ClientSession() as session:
            for i in range(0, len(tokens), CONCURRENCY):
                batch = tokens[i: i + CONCURRENCY]
                tasks = [
                    eth_call(session, rpc_url, token, f"{selector}{owner_padded}")
                    for token in batch
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for token, result in zip(batch, results):
                    if isinstance(result, Exception):
                        raise result
                    if isinstance(result, int):
                        balances[token] = result

        return balances

    async def _eth_call(
        self, session: aiohttp.ClientSession, rpc_url: str, to: str, data: str
    ) -> Optional[int]:
        """Make a single eth_call and return its integer result, or None when it returned no data."""
        from utils.web3_client import UnsupportedChainError

        try:
            async with session.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_call",
                    "params": [{"to": to, "data": data}, "latest"],
                    "id": 1,
                },
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError("Approval state request failed")
                data_resp = await resp.json()
            result = data_resp.get("result")
            if "error" in data_resp or not isinstance(result, str) or not result:
                raise RuntimeError("Approval state unavailable")
            if result == "0x":
                return None
            return int(result, 16)
        except UnsupportedChainError:
            raise
        except Exception as e:
            raise RuntimeError("Approval state unavailable") from e

    async def _fetch_prices(self, tokens: List[str], chain_id: int) -> Dict[str, float]:
        """Fetch token USD prices on ``chain_id`` from DexScreener (free, no API key needed).

        Stablecoins are hardcoded to $1.00 on their own chain. Only pairs on ``chain_id`` price a
        token, since the same address elsewhere can be another token, so DexScreener is asked
        for that chain alone: up to 30 tokens per request, one pair each. Asked without a chain,
        it shared 30 pairs among all the tokens and chains, so some tokens got none.
        """
        from utils.web3_client import UnsupportedChainError

        prices: Dict[str, float] = {}

        # Hardcode stablecoin prices
        for token in tokens:
            if token.lower() in STABLECOINS.get(chain_id, ()):
                prices[token] = 1.0

        slug = get_dexscreener_slug(chain_id)
        to_fetch = [t for t in tokens if t not in prices]
        if not to_fetch or not slug:
            return prices

        BATCH_SIZE = 30
        try:
            async with aiohttp.ClientSession() as session:
                for i in range(0, len(to_fetch), BATCH_SIZE):
                    batch = to_fetch[i: i + BATCH_SIZE]
                    url = f"{self._DEXSCREENER_API}/{slug}/{','.join(batch)}"
                    try:
                        async with session.get(
                            url, timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            pairs = await resp.json()

                        # Group pairs by base token address
                        token_pairs: Dict[str, list] = {}
                        batch_lower = [t.lower() for t in batch]
                        for pair in pairs:
                            base_addr = (pair.get("baseToken") or {}).get("address", "").lower()
                            if pair.get("chainId") == slug and base_addr in batch_lower:
                                token_pairs.setdefault(base_addr, []).append(pair)

                        for token in batch:
                            token_lower = token.lower()
                            pair_list = token_pairs.get(token_lower, [])
                            if pair_list:
                                # Pick highest-liquidity pair
                                pair_list.sort(
                                    key=lambda p: float(
                                        (p.get("liquidity") or {}).get("usd") or 0
                                    ),
                                    reverse=True,
                                )
                                price_str = pair_list[0].get("priceUsd")
                                if price_str:
                                    try:
                                        prices[token] = float(price_str)
                                    except (ValueError, TypeError):
                                        pass
                    except UnsupportedChainError:
                        raise
                    except Exception as e:
                        logger.warning("DexScreener batch %s failed: %s", i // BATCH_SIZE, type(e).__name__)
        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.warning("Price fetch failed: %s", type(e).__name__)

        return prices

    def _assess_approval_risk(
        self, spender: str, amount: int, spender_label: str, chain_id: int
    ) -> tuple:
        """Assess risk level for a token approval on ``chain_id``."""
        is_known_safe = _known_spender(spender.lower(), chain_id) is not None

        if amount >= UNLIMITED_THRESHOLD:
            if is_known_safe:
                return "MEDIUM", f"Unlimited approval to {spender_label} — safe but excessive"
            return "HIGH", "Unlimited approval to unknown contract"

        if amount >= HIGH_APPROVAL:
            if is_known_safe:
                return "LOW", f"Large approval to {spender_label}"
            return "MEDIUM", "Large approval to unknown contract"

        if is_known_safe:
            return "LOW", f"Normal approval to {spender_label}"
        return "LOW", "Normal approval amount"

    def _generate_alert(self, approval: ApprovalInfo) -> Optional[RescueAlert]:
        """Generate a Tier 1 alert for a risky approval."""
        if approval.risk_level == "LOW":
            return None

        if approval.risk_level == "HIGH":
            return RescueAlert(
                alert_type="dangerous_approval",
                severity="HIGH",
                title=f"Dangerous Approval: {approval.token_symbol}",
                description=(
                    f"Your wallet has an unlimited approval for {approval.token_symbol} "
                    f"({approval.token_name}) granted to an unknown contract "
                    f"({approval.spender[:10]}...)."
                ),
                what_it_means=(
                    "This contract can spend ALL of your "
                    f"{approval.token_symbol} tokens at any time without "
                    "further permission. If the contract is malicious or gets "
                    "compromised, your tokens could be drained instantly."
                ),
                what_you_can_do=[
                    f"Revoke this approval immediately using the revoke button below",
                    f"Check the contract {approval.spender} on the block explorer",
                    "If you don't recognize this approval, it may be from a phishing site",
                ],
                affected_token=approval.token_address,
                affected_spender=approval.spender,
                chain_id=approval.chain_id,
            )

        return RescueAlert(
            alert_type="excessive_approval",
            severity="MEDIUM",
            title=f"Excessive Approval: {approval.token_symbol}",
            description=(
                f"Your wallet has a large approval for {approval.token_symbol} "
                f"granted to {approval.spender_label} ({approval.spender[:10]}...)."
            ),
            what_it_means=(
                f"While {approval.spender_label} is a known protocol, unlimited "
                "approvals carry risk if the protocol gets exploited. Consider "
                "revoking and re-approving with exact amounts when needed."
            ),
            what_you_can_do=[
                "Revoke this approval and re-approve with exact amounts when trading",
                "Monitor the protocol for any security incidents",
            ],
            affected_token=approval.token_address,
            affected_spender=approval.spender,
            chain_id=approval.chain_id,
        )

    def _build_revoke_tx(
        self, wallet: str, token: str, spender: str, chain_id: int
    ) -> Dict[str, Any]:
        """Build a pre-signed revoke transaction (approve to 0)."""
        # ERC-20 approve(spender, 0) calldata
        approve_selector = "0x095ea7b3"
        spender_padded = spender.replace("0x", "").lower().zfill(64)
        amount_padded = "0" * 64

        return {
            'from': Web3.to_checksum_address(wallet),
            'to': Web3.to_checksum_address(token),
            'data': f"{approve_selector}{spender_padded}{amount_padded}",
            'value': '0x0',
            'chainId': hex(chain_id),
        }

    @staticmethod
    def _approval_to_dict(a: ApprovalInfo) -> Dict:
        return {
            'token_address': a.token_address,
            'token_name': a.token_name,
            'token_symbol': a.token_symbol,
            'spender': a.spender,
            'spender_label': a.spender_label,
            'allowance': a.allowance,
            'risk_level': a.risk_level,
            'risk_reason': a.risk_reason,
            'chain_id': a.chain_id,
            'value_at_risk_usd': a.value_at_risk_usd,
            'has_revoke_tx': a.revoke_tx is not None,
        }

    @staticmethod
    def _alert_to_dict(a: RescueAlert) -> Dict:
        return {
            'alert_type': a.alert_type,
            'severity': a.severity,
            'title': a.title,
            'description': a.description,
            'what_it_means': a.what_it_means,
            'what_you_can_do': a.what_you_can_do,
            'affected_token': a.affected_token,
            'affected_spender': a.affected_spender,
            'chain_id': a.chain_id,
        }
