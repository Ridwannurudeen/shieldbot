"""Portfolio Guardian — wallet health monitoring, approval management, and alerts."""

import time
import logging
from typing import Dict, List, Optional

import aiohttp
from eth_utils.crypto import keccak

logger = logging.getLogger(__name__)

# ERC20 Approval(address indexed owner, address indexed spender, uint256 value)
_APPROVAL_TOPIC = "0x" + keccak(b"Approval(address,address,uint256)").hex()

# Threshold above which an approval is considered "unlimited"
_UNLIMITED_THRESHOLD = 2 ** 200


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

        # 2. Exposure to flagged tokens (25% weight)
        flagged = await self._check_flagged_exposure(wallet_address, chain_id)
        if flagged is None:
            components["flagged_exposure"] = self._NO_DATA_SCORE
            warnings.append("Could not fetch token list for flagged-exposure check")
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

        # 4. Concentration risk (15% weight)
        concentration = await self._check_concentration(wallet_address, chain_id)
        if concentration is None:
            components["concentration_risk"] = self._NO_DATA_SCORE
            warnings.append("Could not fetch token list for concentration check")
        else:
            components["concentration_risk"] = 100 - concentration

        # 5. Deployer risk (10% weight)
        deployer = await self._check_deployer_risk(wallet_address, chain_id)
        if deployer is None:
            components["deployer_risk"] = self._NO_DATA_SCORE
            warnings.append("Could not fetch token list for deployer-risk check")
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
        return await self._get_approval_data(wallet_address.lower(), chain_id)

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

    # --- Private helpers ---

    def _get_api_key(self, chain_id: int) -> str:
        """Get the Etherscan v2 API key for a given chain."""
        if not self._settings:
            return ""
        fallback = getattr(self._settings, "bscscan_api_key", "")
        mapping = {
            56: "bscscan_api_key",
            1: "etherscan_api_key",
            8453: "basescan_api_key",
            42161: "arbiscan_api_key",
            137: "polygonscan_api_key",
            204: "opbnbscan_api_key",
            10: "optimism_api_key",
        }
        attr = mapping.get(chain_id, "bscscan_api_key")
        return getattr(self._settings, attr, "") or fallback

    async def _explorer_api(self, chain_id: int, **params) -> Optional[Dict]:
        """Call Etherscan v2 API. Returns parsed JSON, or None on failure."""
        api_key = self._get_api_key(chain_id)
        if not api_key:
            return None
        params["chainid"] = chain_id
        params["apikey"] = api_key
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.etherscan.io/v2/api",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    return data if isinstance(data, dict) else None
        except Exception as exc:
            logger.debug("Explorer API call failed (chain %s): %s", chain_id, exc)
            return None

    # --- On-chain data methods ---

    async def _get_approval_data(self, wallet_address: str, chain_id: int) -> Optional[List[Dict]]:
        """Get ERC20 approval data from on-chain logs via Etherscan v2.
        Returns None if data could not be fetched, [] if wallet has no approvals.
        """
        try:
            # Pad wallet to 32 bytes for topic1 filter
            padded = "0x" + wallet_address.lower().replace("0x", "").zfill(64)
            data = await self._explorer_api(
                chain_id,
                module="logs",
                action="getLogs",
                topic0=_APPROVAL_TOPIC,
                topic1=padded,
                fromBlock="0",
                toBlock="99999999",
                topic0_1_opr="and",
            )
            if data is None:
                return None
            logs = data.get("result", [])
            if not isinstance(logs, list):
                return None

            approvals = []
            now = time.time()
            for log in logs:
                topics = log.get("topics", [])
                if len(topics) < 3:
                    continue
                token_address = log.get("address", "").lower()
                spender = "0x" + topics[2][-40:].lower()
                raw_amount = log.get("data", "0x0")
                try:
                    amount = int(raw_amount, 16) if raw_amount else 0
                except (ValueError, TypeError):
                    amount = 0
                is_unlimited = amount > _UNLIMITED_THRESHOLD

                # Compute days since this log (block timestamp is hex)
                try:
                    block_ts = int(log.get("timeStamp", "0x0"), 16)
                    days_since = (now - block_ts) / 86400 if block_ts > 0 else 0
                except (ValueError, TypeError):
                    days_since = 0

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

    async def _check_flagged_exposure(self, wallet_address: str, chain_id: int) -> Optional[float]:
        """Risk points from flagged token holdings (0-100). None if data unavailable."""
        try:
            data = await self._explorer_api(
                chain_id,
                module="account",
                action="tokenlist",
                address=wallet_address,
            )
            if data is None:
                return None
            tokens = data.get("result", [])
            if not isinstance(tokens, list):
                return None
            risk_points = 0.0
            for token in tokens:
                token_addr = (token.get("contractAddress") or "").lower()
                if not token_addr:
                    continue
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

    async def _check_concentration(self, wallet_address: str, chain_id: int) -> Optional[float]:
        """Risk points from portfolio concentration via HHI (0-100). None if data unavailable."""
        try:
            data = await self._explorer_api(
                chain_id,
                module="account",
                action="tokenlist",
                address=wallet_address,
            )
            if data is None:
                return None
            tokens = data.get("result", [])
            if not isinstance(tokens, list):
                return None
            if len(tokens) == 0:
                return 0.0
            balances = []
            for token in tokens:
                raw = token.get("balance", "0")
                try:
                    balances.append(int(raw))
                except (ValueError, TypeError):
                    balances.append(0)
            total = sum(balances)
            if total == 0:
                return 0.0
            hhi = sum((b / total) ** 2 for b in balances)
            return min(100.0, hhi * 100)
        except Exception as exc:
            logger.debug("_check_concentration failed: %s", exc)
            return None

    async def _check_deployer_risk(self, wallet_address: str, chain_id: int) -> Optional[float]:
        """Risk points from tokens with flagged deployers (0-100). None if data unavailable."""
        try:
            data = await self._explorer_api(
                chain_id,
                module="account",
                action="tokenlist",
                address=wallet_address,
            )
            if data is None:
                return None
            tokens = data.get("result", [])
            if not isinstance(tokens, list):
                return None
            risk_points = 0.0
            for token in tokens:
                token_addr = (token.get("contractAddress") or "").lower()
                if not token_addr:
                    continue
                try:
                    # Check if deployer is watched
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
