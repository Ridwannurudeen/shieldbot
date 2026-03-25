"""Portfolio Guardian — wallet health monitoring, approval management, and alerts."""

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

    def __init__(self, db, web3_client=None, cache=None):
        self._db = db
        self._web3 = web3_client
        self._cache = cache

    async def register_wallet(
        self, wallet_address: str, chain_id: int, owner_id: str, is_agent: bool = False
    ) -> Dict:
        """Register a wallet for monitoring."""
        return await self._db.register_guardian_wallet(wallet_address, chain_id, owner_id, is_agent)

    async def get_wallets(self, owner_id: str) -> List[Dict]:
        """List monitored wallets for an owner."""
        return await self._db.get_guardian_wallets(owner_id)

    async def get_health(self, wallet_address: str, chain_id: int = 56) -> Dict:
        """Calculate wallet health score (0-100) with component breakdown."""
        wallet_address = wallet_address.lower()
        components = {}

        # 1. Dangerous approvals (35% weight) — stub until on-chain reading
        approvals = await self._get_approval_data(wallet_address, chain_id)
        dangerous_count = sum(1 for a in approvals if a.get("risk_level") in ("critical", "high"))
        unlimited_count = sum(1 for a in approvals if a.get("is_unlimited"))
        if not approvals:
            components["dangerous_approvals"] = 100
        else:
            danger_ratio = dangerous_count / len(approvals)
            components["dangerous_approvals"] = max(0, 100 - (danger_ratio * 100) - (unlimited_count * 10))

        # 2. Exposure to flagged tokens (25% weight)
        components["flagged_exposure"] = 100 - (await self._check_flagged_exposure(wallet_address, chain_id))

        # 3. Approval staleness (15% weight)
        stale_count = sum(
            1 for a in approvals
            if a.get("days_since_interaction", 0) > 30 and a.get("is_unlimited")
        )
        components["approval_staleness"] = max(0, 100 - stale_count * 15)

        # 4. Concentration risk (15% weight)
        components["concentration_risk"] = 100 - (await self._check_concentration(wallet_address, chain_id))

        # 5. Deployer risk (10% weight)
        components["deployer_risk"] = 100 - (await self._check_deployer_risk(wallet_address, chain_id))

        # Clamp all to 0-100
        for k in components:
            components[k] = max(0.0, min(100.0, components[k]))

        composite = sum(components[k] * self.WEIGHTS[k] for k in self.WEIGHTS)

        if composite >= 80:
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

        return {
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

    # --- Private stubs (full on-chain reading in future) ---

    async def _get_approval_data(self, wallet_address: str, chain_id: int) -> List[Dict]:
        """Get approval data. Returns empty until on-chain reading is built."""
        return []

    async def _check_flagged_exposure(self, wallet_address: str, chain_id: int) -> float:
        """Risk points from flagged token holdings. Returns 0 until on-chain reading."""
        return 0.0

    async def _check_concentration(self, wallet_address: str, chain_id: int) -> float:
        """Risk points from portfolio concentration. Returns 0 until on-chain reading."""
        return 0.0

    async def _check_deployer_risk(self, wallet_address: str, chain_id: int) -> float:
        """Risk points from risky deployer holdings. Returns 0 until on-chain reading."""
        return 0.0
