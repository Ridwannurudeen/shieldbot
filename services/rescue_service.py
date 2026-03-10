"""Rescue Mode — Tier 1 (alerts with explanations) and Tier 2 (pre-built revoke transactions).

Scans a wallet's active token approvals, identifies risky ones, and generates
ready-to-sign revocation transactions for one-click cleanup.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import aiohttp
from web3 import Web3

logger = logging.getLogger(__name__)

# ERC-20 Approval event topic
APPROVAL_TOPIC = Web3.keccak(text="Approval(address,address,uint256)").hex()

# ApprovalForAll event topic (ERC-721/1155)
APPROVAL_FOR_ALL_TOPIC = Web3.keccak(text="ApprovalForAll(address,address,bool)").hex()

UNLIMITED_THRESHOLD = 2**128
# Approvals above this (but below UNLIMITED_THRESHOLD) are considered "large"
HIGH_APPROVAL = 10**24  # ~1 million tokens at 18 decimals

# Known safe spenders (major DEX routers, aggregators, and lending protocols)
# Approvals to these are lower risk than unknown contracts.
KNOWN_SAFE_SPENDERS = {
    # --- PancakeSwap ---
    "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap V2",
    "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": "PancakeSwap V3 Position Manager",
    "0x1b81d678ffb9c0263b24a97847620c99d213eb14": "PancakeSwap V3 Swap Router",

    # --- Uniswap ---
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",

    # --- SushiSwap ---
    "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": "SushiSwap",

    # --- 1inch ---
    "0x111111125421ca6dc452d289314280a0f8842a65": "1inch V6",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",

    # --- Biswap ---
    "0x3a6d8ca21d1cf76f653a67577fa0d27453350dd8": "Biswap Router",

    # --- ApeSwap ---
    "0xcf0febd3f17cef5b47b0cd257acf6025c5bff3b7": "ApeSwap Router",

    # --- KyberSwap ---
    "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap Meta Aggregation Router V2",

    # --- OpenOcean ---
    "0x6352a56caadc4f1e25cd6c75970fa768a3304e64": "OpenOcean Exchange V2",

    # --- MetaMask Swap Router (BSC) ---
    "0x1a1ec25dc08e98e5e93f1104b5e5cdd298707d31": "MetaMask Swap Router",

    # --- Venus Protocol (vToken contracts — users approve these to supply assets) ---
    "0xfd5840cd36d94d7229439859c0112a4185bc0255": "Venus Protocol (vUSDT)",
    "0x95c78222b3d6e262426483d42cfa53685a67ab9d": "Venus Protocol (vBUSD)",

    # --- Radiant Capital ---
    "0xd50cf00b6e600dd036ba8ef475677d816d6c4281": "Radiant Capital Lending Pool",

    # --- Alpaca Finance ---
    "0xa625ab01b08ce023b2a342dbb12a16f2c8489a8f": "Alpaca Finance FairLaunch",

    # --- Wombat Exchange ---
    "0x19609b03c976cca288fbdae5c21d4290e9a4add7": "Wombat Exchange Router",

    # --- Stargate Finance ---
    "0x4a364f8c717caad9a442737eb7b8a55cc6cf18d8": "Stargate Finance Router",
}

# Stablecoins — price = $1.00 without an API call
STABLECOINS = {
    "0x55d398326f99059ff775485246999027b3197955",  # BSC USDT
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",  # BSC USDC
    "0xe9e7cea3dedca5984780bafc599bd69add087d56",  # BUSD
    "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3",  # DAI on BSC
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # ETH USDC
    "0xdac17f958d2ee523a2206206994597c13d831ec7",  # ETH USDT
    "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
}


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

    # Override with LOGS_RPC_URL env var to set the archive node endpoint.
    _DEFAULT_LOGS_RPC = ""
    _DEXSCREENER_API = "https://api.dexscreener.com/latest/dex/tokens"

    def __init__(self, web3_client, db=None, logs_rpc: str = ""):
        self._web3_client = web3_client
        self._db = db
        self._logs_rpc = logs_rpc or self._DEFAULT_LOGS_RPC

    async def scan_approvals(
        self, wallet_address: str, chain_id: int = 56, etherscan_api_key: str = ""
    ) -> Dict[str, Any]:
        """Scan a wallet's active token approvals and assess risk.

        Returns a dict with:
        - approvals: list of ApprovalInfo (verified on-chain, no false positives)
        - alerts: list of RescueAlert (Tier 1)
        - revoke_txs: list of pre-built revoke transactions (Tier 2)
        - total_value_at_risk_usd: aggregate USD value exposed
        - summary: risk summary
        """
        wallet = wallet_address.lower()
        approvals = await self._fetch_approvals(wallet, chain_id)

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

        return {
            'wallet': wallet,
            'chain_id': chain_id,
            'total_approvals': len(approvals),
            'high_risk': high_risk_count,
            'medium_risk': medium_risk_count,
            'total_value_at_risk_usd': round(total_value_at_risk, 2),
            'approvals': [self._approval_to_dict(a) for a in approvals],
            'alerts': [self._alert_to_dict(a) for a in alerts],
            'revoke_txs': revoke_txs,
            'scanned_at': time.time(),
        }

    async def _fetch_approvals(
        self, wallet: str, chain_id: int, api_key: str = ""
    ) -> List[ApprovalInfo]:
        """Fetch and verify active token approvals.

        Pipeline:
          1. eth_getLogs — scan ALL BSC history at CONCURRENCY=50
          2. Deduplicate to latest event per (token, spender)
          3. eth_call allowance() — verify each pair is still non-zero on-chain
          4. eth_call balanceOf() — get wallet's token balances
          5. DexScreener — fetch token prices for USD risk calculation
          6. Enrich with token metadata (parallelized)
        """
        approvals = []
        try:
            async with aiohttp.ClientSession() as session:
                # Step 1: Get latest block
                async with session.post(
                    self._logs_rpc,
                    json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    bn_data = await resp.json()
                if "error" in bn_data or "result" not in bn_data:
                    raise RuntimeError(f"eth_blockNumber failed: {bn_data.get('error', bn_data)}")
                latest = int(bn_data["result"], 16)

            # Step 2: Scan ALL blocks from genesis with CONCURRENCY=50
            # ~1680 chunks on BSC / 50 concurrent = 34 batches ≈ 10-25s
            CHUNK_SIZE = 49_999
            CONCURRENCY = 50
            chunks = [
                (hex(b), hex(min(b + CHUNK_SIZE - 1, latest)))
                for b in range(0, latest + 1, CHUNK_SIZE)
            ]

            topic0 = APPROVAL_TOPIC
            topic1 = "0x" + wallet.replace("0x", "").lower().zfill(64)

            all_logs: list = []
            async with aiohttp.ClientSession() as session:
                for i in range(0, len(chunks), CONCURRENCY):
                    batch = chunks[i: i + CONCURRENCY]
                    batch_results = await asyncio.gather(
                        *[
                            self._fetch_log_chunk(session, topic0, topic1, from_b, to_b)
                            for from_b, to_b in batch
                        ],
                        return_exceptions=True,
                    )
                    for result in batch_results:
                        if isinstance(result, list):
                            all_logs.extend(result)

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
                return []

            # Step 4: Verify current on-chain allowances — eliminates false positives
            verified = await self._verify_allowances(wallet, candidates)
            if not verified:
                return []

            # Step 5: Fetch wallet balances for value-at-risk calculation
            active_tokens = list({token for (token, _) in verified.keys()})
            balances = await self._fetch_balances(wallet, active_tokens)

            # Step 6: Fetch token prices (DexScreener, stablecoins hardcoded)
            prices = await self._fetch_prices(active_tokens)

            # Step 7: Enrich with token metadata — parallelized
            token_info_results = await asyncio.gather(
                *[self._web3_client.get_token_info(token, chain_id) for token in active_tokens],
                return_exceptions=True,
            )
            token_info_map: Dict[str, Dict] = {}
            for token, result in zip(active_tokens, token_info_results):
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

                spender_label = KNOWN_SAFE_SPENDERS.get(spender, "Unknown Contract")
                risk_level, risk_reason = self._assess_approval_risk(
                    spender, current_allowance, spender_label
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

        except Exception as e:
            logger.error(f"Error fetching approvals: {e}", exc_info=True)

        # Sort HIGH → MEDIUM → LOW, then by USD value at risk descending
        risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        approvals.sort(
            key=lambda a: (risk_order.get(a.risk_level, 3), -(a.value_at_risk_usd or 0))
        )
        return approvals

    async def _fetch_log_chunk(
        self, session: aiohttp.ClientSession, topic0: str, topic1: str, from_b: str, to_b: str
    ) -> list:
        """Fetch a single block-range chunk of Approval logs via eth_getLogs."""
        try:
            async with session.post(
                self._logs_rpc,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_getLogs",
                    "params": [{"topics": [topic0, topic1], "fromBlock": from_b, "toBlock": to_b}],
                    "id": 1,
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                data = await resp.json()
            if "error" in data:
                logger.warning(f"eth_getLogs {from_b}-{to_b}: {data['error']}")
                return []
            return data.get("result", [])
        except Exception as e:
            logger.warning(f"Log chunk {from_b}-{to_b} failed: {e}")
            return []

    async def _verify_allowances(
        self, wallet: str, candidates: Dict[tuple, Dict]
    ) -> Dict[tuple, int]:
        """Batch-verify current on-chain allowances via eth_call.

        Eliminates false positives where approval events exist but the
        allowance has been consumed (spent) or explicitly revoked.
        """
        # allowance(address owner, address spender) → uint256
        selector = "0xdd62ed3e"
        owner_padded = wallet.replace("0x", "").lower().zfill(64)

        pairs = list(candidates.keys())
        verified: Dict[tuple, int] = {}
        CONCURRENCY = 50

        async with aiohttp.ClientSession() as session:
            for i in range(0, len(pairs), CONCURRENCY):
                batch = pairs[i: i + CONCURRENCY]
                tasks = []
                for (token, spender) in batch:
                    spender_padded = spender.replace("0x", "").lower().zfill(64)
                    calldata = f"{selector}{owner_padded}{spender_padded}"
                    tasks.append(self._eth_call(session, token, calldata))

                results = await asyncio.gather(*tasks, return_exceptions=True)
                for (token, spender), result in zip(batch, results):
                    if isinstance(result, int) and result > 0:
                        verified[(token, spender)] = result

        return verified

    async def _fetch_balances(
        self, wallet: str, tokens: List[str]
    ) -> Dict[str, int]:
        """Batch-fetch wallet token balances via eth_call."""
        # balanceOf(address owner) → uint256
        selector = "0x70a08231"
        owner_padded = wallet.replace("0x", "").lower().zfill(64)

        balances: Dict[str, int] = {}
        CONCURRENCY = 50

        async with aiohttp.ClientSession() as session:
            for i in range(0, len(tokens), CONCURRENCY):
                batch = tokens[i: i + CONCURRENCY]
                tasks = [
                    self._eth_call(session, token, f"{selector}{owner_padded}")
                    for token in batch
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for token, result in zip(batch, results):
                    if isinstance(result, int):
                        balances[token] = result

        return balances

    async def _eth_call(
        self, session: aiohttp.ClientSession, to: str, data: str
    ) -> int:
        """Make a single eth_call and return result as int (0 on error)."""
        try:
            async with session.post(
                self._logs_rpc,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_call",
                    "params": [{"to": to, "data": data}, "latest"],
                    "id": 1,
                },
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                data_resp = await resp.json()
            result = data_resp.get("result", "0x0")
            if not result or result == "0x":
                return 0
            return int(result, 16)
        except Exception:
            return 0

    async def _fetch_prices(self, tokens: List[str]) -> Dict[str, float]:
        """Fetch token USD prices from DexScreener (free, no API key needed).

        Stablecoins are hardcoded to $1.00.
        Up to 30 tokens per DexScreener request.
        """
        prices: Dict[str, float] = {}

        # Hardcode stablecoin prices
        for token in tokens:
            if token.lower() in STABLECOINS:
                prices[token] = 1.0

        to_fetch = [t for t in tokens if t not in prices]
        if not to_fetch:
            return prices

        BATCH_SIZE = 30
        try:
            async with aiohttp.ClientSession() as session:
                for i in range(0, len(to_fetch), BATCH_SIZE):
                    batch = to_fetch[i: i + BATCH_SIZE]
                    url = f"{self._DEXSCREENER_API}/{','.join(batch)}"
                    try:
                        async with session.get(
                            url, timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            data = await resp.json()

                        pairs = data.get("pairs") or []
                        # Group pairs by base token address
                        token_pairs: Dict[str, list] = {}
                        batch_lower = [t.lower() for t in batch]
                        for pair in pairs:
                            base_addr = (pair.get("baseToken") or {}).get("address", "").lower()
                            if base_addr in batch_lower:
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
                    except Exception as e:
                        logger.warning(f"DexScreener batch {i // BATCH_SIZE} failed: {e}")
        except Exception as e:
            logger.warning(f"Price fetch failed: {e}")

        return prices

    def _assess_approval_risk(
        self, spender: str, amount: int, spender_label: str
    ) -> tuple:
        """Assess risk level for a token approval."""
        is_known_safe = spender.lower() in KNOWN_SAFE_SPENDERS

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
