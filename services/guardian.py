"""Portfolio Guardian — wallet health monitoring, approval management, and alerts."""

import asyncio
import time
import logging
from typing import Dict, List, Optional

import aiohttp
from web3 import Web3
from eth_utils.crypto import keccak

logger = logging.getLogger(__name__)

# ERC20 Approval(address indexed owner, address indexed spender, uint256 value)
_APPROVAL_TOPIC = "0x" + keccak(b"Approval(address,address,uint256)").hex()

# Threshold above which an approval is considered "unlimited"
_UNLIMITED_THRESHOLD = 2 ** 200

# RPC pagination: 50K blocks per chunk, scan last ~90 days (~2.6M blocks on BSC)
_RPC_CHUNK = 50_000
_RPC_MAX_BLOCKS = 2_600_000
_RPC_CONCURRENCY = 5

# balanceOf(address) selector
_BALANCE_OF_SELECTOR = "0x70a08231"


class GuardianService:
    """Portfolio Guardian: wallet health monitoring, approval management, alerts."""

    WEIGHTS = {
        "dangerous_approvals": 0.35,
        "flagged_exposure": 0.25,
        "approval_staleness": 0.15,
        "concentration_risk": 0.15,
        "deployer_risk": 0.10,
    }

    def __init__(self, db, web3_client=None, cache=None, settings=None):
        self._db = db
        self._web3 = web3_client
        self._cache = cache
        self._settings = settings

    async def register_wallet(
        self, wallet_address: str, chain_id: int, owner_id: str, is_agent: bool = False
    ) -> Dict:
        """Register a wallet for monitoring."""
        return await self._db.register_guardian_wallet(wallet_address, chain_id, owner_id, is_agent)

    async def get_wallets(self, owner_id: str) -> List[Dict]:
        """List monitored wallets for an owner."""
        return await self._db.get_guardian_wallets(owner_id)

    _NO_DATA_SCORE = 50.0  # Neutral score when data is unavailable

    async def get_health(self, wallet_address: str, chain_id: int = 56) -> Dict:
        """Calculate wallet health score (0-100) with component breakdown."""
        wallet_address = wallet_address.lower()
        components = {}
        warnings = []

        # 1. Dangerous approvals (35% weight)
        approvals_unavailable = False
        approvals = await self._get_approval_data(wallet_address, chain_id)
        if approvals is None:
            approvals_unavailable = True
            components["dangerous_approvals"] = self._NO_DATA_SCORE
            warnings.append("Could not fetch approval data from block explorer")
            approvals = []  # safe default for downstream iteration
        elif not approvals:
            components["dangerous_approvals"] = 100  # genuinely no approvals = safe
        else:
            dangerous_count = sum(1 for a in approvals if a.get("risk_level") in ("critical", "high"))
            unlimited_count = sum(1 for a in approvals if a.get("is_unlimited"))
            danger_ratio = dangerous_count / len(approvals)
            components["dangerous_approvals"] = max(0, 100 - (danger_ratio * 100) - (unlimited_count * 10))

        dangerous_count = sum(1 for a in approvals if a.get("risk_level") in ("critical", "high"))
        unlimited_count = sum(1 for a in approvals if a.get("is_unlimited"))

        # Collect unique token addresses from approvals for downstream checks
        token_addrs = list({a["token_address"] for a in approvals if a.get("token_address")})

        # 2. Exposure to flagged tokens (25% weight) — uses approval tokens
        if approvals_unavailable:
            components["flagged_exposure"] = self._NO_DATA_SCORE
        else:
            flagged = await self._check_flagged_exposure_from_tokens(token_addrs, chain_id)
            if flagged is None:
                components["flagged_exposure"] = self._NO_DATA_SCORE
                warnings.append("Could not check flagged-token exposure")
            else:
                components["flagged_exposure"] = 100 - flagged

        # 3. Approval staleness (15% weight) — depends on approval data
        stale_count = 0
        if approvals_unavailable:
            components["approval_staleness"] = self._NO_DATA_SCORE
        else:
            stale_count = sum(
                1 for a in approvals
                if a.get("days_since_interaction", 0) > 30 and a.get("is_unlimited")
            )
            components["approval_staleness"] = max(0, 100 - stale_count * 15)

        # 4. Concentration risk (15% weight) — uses approval tokens
        if approvals_unavailable:
            components["concentration_risk"] = self._NO_DATA_SCORE
        else:
            concentration = await self._check_concentration_from_tokens(
                wallet_address, token_addrs, chain_id,
            )
            if concentration is None:
                components["concentration_risk"] = self._NO_DATA_SCORE
                warnings.append("Could not check concentration risk")
            else:
                components["concentration_risk"] = 100 - concentration

        # 5. Deployer risk (10% weight) — uses approval tokens
        if approvals_unavailable:
            components["deployer_risk"] = self._NO_DATA_SCORE
        else:
            deployer = await self._check_deployer_risk_from_tokens(token_addrs, chain_id)
            if deployer is None:
                components["deployer_risk"] = self._NO_DATA_SCORE
            else:
                components["deployer_risk"] = 100 - deployer

        # Clamp all to 0-100
        for k in components:
            components[k] = max(0.0, min(100.0, components[k]))

        composite = sum(components[k] * self.WEIGHTS[k] for k in self.WEIGHTS)

        if warnings:
            level = "unknown"
        elif composite >= 80:
            level = "excellent"
        elif composite >= 60:
            level = "good"
        elif composite >= 40:
            level = "fair"
        elif composite >= 20:
            level = "poor"
        else:
            level = "critical"

        # Update DB
        await self._db.update_guardian_health(wallet_address, chain_id, round(composite, 1))

        result = {
            "wallet_address": wallet_address,
            "chain_id": chain_id,
            "health_score": round(composite, 1),
            "level": level,
            "components": {k: round(v, 1) for k, v in components.items()},
            "total_approvals": len(approvals),
            "dangerous_approvals": dangerous_count,
            "stale_approvals": stale_count,
            "scanned_at": time.time(),
        }
        if warnings:
            result["warnings"] = warnings
        return result

    async def get_approvals(self, wallet_address: str, chain_id: int = 56) -> List[Dict]:
        """Get all token approvals, risk-ranked."""
        result = await self._get_approval_data(wallet_address.lower(), chain_id)
        return result if result is not None else []

    async def build_revoke_tx(self, wallet_address: str, approvals_to_revoke: List[Dict]) -> List[Dict]:
        """Build unsigned ERC20 approve(spender, 0) transactions."""
        transactions = []
        for approval in approvals_to_revoke:
            token_address = approval.get("token_address")
            spender = approval.get("spender")
            if not token_address or not spender:
                continue
            # ERC20 approve(spender, 0) calldata: 0x095ea7b3
            spender_padded = spender.lower().replace("0x", "").zfill(64)
            amount_padded = "0" * 64
            calldata = f"0x095ea7b3{spender_padded}{amount_padded}"
            transactions.append({
                "from": wallet_address,
                "to": token_address,
                "data": calldata,
                "value": "0",
                "description": f"Revoke {spender[:10]}... approval on {token_address[:10]}...",
            })
        return transactions

    async def get_alerts(self, wallet_address: str = None, limit: int = 50) -> List[Dict]:
        """Get recent alerts."""
        return await self._db.get_guardian_alerts(wallet_address, limit)

    async def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark alert as seen."""
        return await self._db.acknowledge_guardian_alert(alert_id)

    async def create_alert(
        self, wallet_address: str, chain_id: int, alert_type: str,
        severity: str, title: str, details: Dict = None,
    ) -> int:
        """Create a new alert."""
        return await self._db.create_guardian_alert(
            wallet_address, chain_id, alert_type, severity, title, details
        )

    # --- RPC helpers ---

    def _get_rpc_url(self, chain_id: int) -> Optional[str]:
        """Get the RPC URL for log queries on this chain."""
        if not self._settings:
            return None
        # Prefer dedicated logs RPC (archive node) for BSC
        if chain_id == 56:
            logs_rpc = getattr(self._settings, "logs_rpc_url", "")
            if logs_rpc:
                return logs_rpc
        mapping = {
            56: "bsc_rpc_url",
            1: "eth_rpc_url",
            8453: "base_rpc_url",
            42161: "arbitrum_rpc_url",
            137: "polygon_rpc_url",
            204: "opbnb_rpc_url",
            10: "optimism_rpc_url",
        }
        attr = mapping.get(chain_id, "bsc_rpc_url")
        return getattr(self._settings, attr, "") or None

    async def _rpc_get_logs(
        self, rpc_url: str, from_block: int, to_block: int, topics: List[str],
    ) -> Optional[List[Dict]]:
        """Single eth_getLogs RPC call. Returns None on failure."""
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getLogs",
            "params": [{
                "fromBlock": hex(from_block),
                "toBlock": hex(to_block),
                "topics": topics,
            }],
            "id": 1,
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    rpc_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    if "error" in data:
                        return None
                    result = data.get("result", [])
                    return result if isinstance(result, list) else None
        except Exception as exc:
            logger.debug("RPC getLogs failed (%d-%d): %s", from_block, to_block, exc)
            return None

    async def _rpc_block_number(self, rpc_url: str) -> Optional[int]:
        """Get latest block number via RPC."""
        payload = {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    rpc_url, json=payload, timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    return int(data["result"], 16)
        except Exception:
            return None

    async def _rpc_balance_of(self, rpc_url: str, token: str, wallet: str) -> Optional[int]:
        """Call balanceOf(wallet) on an ERC20 token via RPC."""
        wallet_padded = wallet.lower().replace("0x", "").zfill(64)
        calldata = f"{_BALANCE_OF_SELECTOR}{wallet_padded}"
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": Web3.to_checksum_address(token), "data": calldata}, "latest"],
            "id": 1,
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    rpc_url, json=payload, timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    if "error" in data:
                        return 0
                    raw = data.get("result", "0x0")
                    return int(raw, 16) if raw and raw != "0x" else 0
        except Exception:
            return 0

    # --- On-chain data methods ---

    async def _get_approval_data(self, wallet_address: str, chain_id: int) -> Optional[List[Dict]]:
        """Get ERC20 approval data via paginated eth_getLogs RPC.
        Returns None if data could not be fetched, [] if wallet has no approvals.
        """
        rpc_url = self._get_rpc_url(chain_id)
        if not rpc_url:
            return None
        try:
            latest = await self._rpc_block_number(rpc_url)
            if latest is None:
                return None

            # Pad wallet to 32 bytes for topic1 filter
            padded = "0x" + wallet_address.lower().replace("0x", "").zfill(64)
            topics = [_APPROVAL_TOPIC, padded]

            from_block = max(0, latest - _RPC_MAX_BLOCKS)
            all_logs = []
            sem = asyncio.Semaphore(_RPC_CONCURRENCY)

            async def fetch_chunk(start: int, end: int):
                async with sem:
                    return await self._rpc_get_logs(rpc_url, start, end, topics)

            # Build chunk ranges
            tasks = []
            b = from_block
            while b <= latest:
                end = min(b + _RPC_CHUNK - 1, latest)
                tasks.append(fetch_chunk(b, end))
                b = end + 1

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    all_logs.extend(r)

            # Parse logs into approvals
            approvals = []
            now = time.time()
            for log in all_logs:
                topics_list = log.get("topics", [])
                if len(topics_list) < 3:
                    continue
                token_address = log.get("address", "").lower()
                spender = "0x" + topics_list[2][-40:].lower()
                raw_amount = log.get("data", "0x0")
                try:
                    amount = int(raw_amount, 16) if raw_amount else 0
                except (ValueError, TypeError):
                    amount = 0
                is_unlimited = amount > _UNLIMITED_THRESHOLD

                # Block timestamp — RPC logs use hex timeStamp or blockNumber
                block_ts = 0
                ts_raw = log.get("timeStamp") or log.get("timestamp")
                if ts_raw:
                    try:
                        block_ts = int(ts_raw, 16) if isinstance(ts_raw, str) else int(ts_raw)
                    except (ValueError, TypeError):
                        pass
                days_since = (now - block_ts) / 86400 if block_ts > 0 else 0

                # Cross-reference spender risk (24h TTL — Guardian is historical)
                risk_level = "low"
                try:
                    score_data = await self._db.get_contract_score(spender, chain_id, max_age_seconds=86400)
                    if score_data:
                        rs = score_data.get("risk_score", 0)
                        if rs >= 70:
                            risk_level = "critical"
                        elif rs >= 50:
                            risk_level = "high"
                        elif rs >= 30:
                            risk_level = "medium"
                except Exception:
                    pass

                approvals.append({
                    "token_address": token_address,
                    "spender": spender,
                    "amount": str(amount),
                    "is_unlimited": is_unlimited,
                    "risk_level": risk_level,
                    "days_since_interaction": round(days_since, 1),
                })

            # Sort by risk severity
            risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            approvals.sort(key=lambda a: risk_order.get(a["risk_level"], 4))
            return approvals
        except Exception as exc:
            logger.debug("_get_approval_data failed: %s", exc)
            return None

    async def _check_flagged_exposure_from_tokens(
        self, token_addrs: List[str], chain_id: int,
    ) -> Optional[float]:
        """Risk points from tokens in approval data that are flagged (0-100)."""
        if not token_addrs:
            return 0.0
        try:
            risk_points = 0.0
            for token_addr in token_addrs:
                try:
                    score_data = await self._db.get_contract_score(token_addr, chain_id, max_age_seconds=86400)
                    if score_data and score_data.get("risk_score", 0) >= 70:
                        risk_points += 20
                except Exception:
                    pass
            return min(100.0, risk_points)
        except Exception as exc:
            logger.debug("_check_flagged_exposure failed: %s", exc)
            return None

    async def _check_concentration_from_tokens(
        self, wallet_address: str, token_addrs: List[str], chain_id: int,
    ) -> Optional[float]:
        """Risk points from portfolio concentration via HHI (0-100)."""
        if not token_addrs:
            return 0.0
        rpc_url = self._get_rpc_url(chain_id)
        if not rpc_url:
            return None
        try:
            # Fetch balances concurrently
            tasks = [self._rpc_balance_of(rpc_url, t, wallet_address) for t in token_addrs[:20]]
            balances_raw = await asyncio.gather(*tasks, return_exceptions=True)
            balances = [b for b in balances_raw if isinstance(b, int) and b > 0]
            if not balances:
                return 0.0
            total = sum(balances)
            if total == 0:
                return 0.0
            hhi = sum((b / total) ** 2 for b in balances)
            return min(100.0, hhi * 100)
        except Exception as exc:
            logger.debug("_check_concentration failed: %s", exc)
            return None

    async def _check_deployer_risk_from_tokens(
        self, token_addrs: List[str], chain_id: int,
    ) -> Optional[float]:
        """Risk points from tokens with flagged deployers (0-100)."""
        if not token_addrs:
            return 0.0
        try:
            risk_points = 0.0
            for token_addr in token_addrs:
                try:
                    if not hasattr(self._db, "get_deployer"):
                        continue
                    deployer_info = await self._db.get_deployer(token_addr, chain_id)
                    if not deployer_info:
                        continue
                    deployer_addr = deployer_info.get("deployer_address", "")
                    if not deployer_addr:
                        continue
                    if not hasattr(self._db, "get_watched_deployer"):
                        continue
                    watched = await self._db.get_watched_deployer(deployer_addr)
                    if watched:
                        risk_points += 25
                except Exception:
                    pass
            return min(100.0, risk_points)
        except Exception as exc:
            logger.debug("_check_deployer_risk failed: %s", exc)
            return None
