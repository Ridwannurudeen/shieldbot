"""Portfolio Guardian — wallet health monitoring, approval management, and alerts.

Delegates on-chain approval scanning to RescueService (full-chain scan,
on-chain verification, price enrichment) instead of rolling its own RPC queries.
"""

import time
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class GuardianService:
    """Portfolio Guardian: wallet health monitoring, approval management, alerts."""

    WEIGHTS = {
        "dangerous_approvals": 0.35,
        "flagged_exposure": 0.25,
        "approval_staleness": 0.15,
        "concentration_risk": 0.15,
        "deployer_risk": 0.10,
    }

    def __init__(self, db, web3_client=None, cache=None, settings=None, rescue_service=None):
        self._db = db
        self._web3 = web3_client
        self._cache = cache
        self._settings = settings
        self._rescue = rescue_service

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

        # 4. Concentration risk (15% weight) — uses USD values from rescue data
        if approvals_unavailable:
            components["concentration_risk"] = self._NO_DATA_SCORE
        else:
            concentration = self._check_concentration_from_approvals(approvals)
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

        # Aggregate USD value at risk
        total_value_at_risk = sum(
            a.get("value_at_risk_usd") or 0 for a in approvals
        )

        result = {
            "wallet_address": wallet_address,
            "chain_id": chain_id,
            "health_score": round(composite, 1),
            "level": level,
            "components": {k: round(v, 1) for k, v in components.items()},
            "total_approvals": len(approvals),
            "dangerous_approvals": dangerous_count,
            "stale_approvals": stale_count,
            "total_value_at_risk_usd": round(total_value_at_risk, 2),
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

    # --- Approval data via rescue_service ---

    async def _get_approval_data(self, wallet_address: str, chain_id: int) -> Optional[List[Dict]]:
        """Get ERC20 approval data via rescue_service (full-chain scan + on-chain verification).

        Returns None if data could not be fetched, [] if wallet has no approvals.
        """
        if not self._rescue:
            return None
        try:
            scan_result = await self._rescue.scan_approvals(wallet_address, chain_id)
            raw_approvals = scan_result.get("approvals", [])

            approvals = []
            for a in raw_approvals:
                # Map rescue risk levels (uppercase) to guardian levels (lowercase)
                risk_level = self._map_risk_level(a.get("risk_level", "LOW"))

                # Overlay DB contract score — may upgrade risk
                spender = a.get("spender", "")
                try:
                    score_data = await self._db.get_contract_score(
                        spender, chain_id, max_age_seconds=86400,
                    )
                    if score_data:
                        rs = score_data.get("risk_score", 0)
                        if rs >= 70:
                            risk_level = "critical"
                        elif rs >= 50 and risk_level not in ("critical",):
                            risk_level = "high"
                except Exception:
                    pass

                is_unlimited = a.get("allowance") == "Unlimited"

                approvals.append({
                    "token_address": a.get("token_address", ""),
                    "spender": spender,
                    "spender_label": a.get("spender_label", ""),
                    "token_name": a.get("token_name", ""),
                    "token_symbol": a.get("token_symbol", ""),
                    "allowance": a.get("allowance", "0"),
                    "is_unlimited": is_unlimited,
                    "risk_level": risk_level,
                    "risk_reason": a.get("risk_reason", ""),
                    "value_at_risk_usd": a.get("value_at_risk_usd"),
                    "days_since_interaction": 0,
                })

            # Sort by risk severity
            risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            approvals.sort(key=lambda x: risk_order.get(x["risk_level"], 4))
            return approvals
        except Exception as exc:
            logger.error("_get_approval_data via rescue failed: %s", exc, exc_info=True)
            return None

    @staticmethod
    def _map_risk_level(rescue_level: str) -> str:
        """Map rescue service risk levels (uppercase) to guardian levels (lowercase)."""
        return {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(rescue_level, "low")

    # --- Health sub-checks ---

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

    @staticmethod
    def _check_concentration_from_approvals(approvals: List[Dict]) -> float:
        """Risk points from portfolio concentration using USD values (0-100).

        Uses value_at_risk_usd from rescue data per unique token to compute HHI.
        """
        if not approvals:
            return 0.0
        # Aggregate max USD value per token (multiple approvals for same token)
        token_values: Dict[str, float] = {}
        for a in approvals:
            token = a.get("token_address", "")
            usd = a.get("value_at_risk_usd") or 0
            if token and usd > 0:
                token_values[token] = max(token_values.get(token, 0), usd)
        if not token_values:
            return 0.0
        values = list(token_values.values())
        total = sum(values)
        if total == 0:
            return 0.0
        hhi = sum((v / total) ** 2 for v in values)
        return min(100.0, hhi * 100)

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
