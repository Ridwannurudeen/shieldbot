"""
Transaction Simulator (Tenderly)
Simulates transactions to predict reverts, asset changes, and warnings.
Gracefully disables if no API key is configured.
"""
import logging
import os
from typing import Optional, Dict, Any, List

import httpx

logger = logging.getLogger(__name__)

TENDERLY_API_BASE = "https://api.tenderly.co/api/v1"


class TenderlySimulator:
    """Async transaction simulation using Tenderly API."""

    def __init__(self):
        self.api_key = os.getenv("TENDERLY_API_KEY", "")
        self.project_id = os.getenv("TENDERLY_PROJECT_ID", "")
        self.client = httpx.AsyncClient(timeout=15.0)
        self.enabled = bool(self.api_key and self.project_id)

        if not self.enabled:
            logger.warning("Transaction simulation disabled (no Tenderly API key)")
        else:
            logger.info("Tenderly simulation enabled")

    async def close(self):
        await self.client.aclose()

    def is_enabled(self) -> bool:
        return self.enabled

    async def simulate_transaction(
        self,
        to_address: str,
        from_address: str,
        value: str = "0",
        data: str = "0x",
        chain_id: int = 56,
    ) -> Optional[Dict[str, Any]]:
        """
        Simulate transaction and predict outcome.
        Returns dict: {success, revert_reason, gas_used, warnings, asset_deltas}
        or None if disabled/failed.
        """
        if not self.enabled:
            return None

        try:
            result = await self._tenderly_simulate(
                to_address, from_address, value, data, chain_id
            )

            if not result:
                return None

            tx_info = result.get("transaction", {})
            success = tx_info.get("status", False)
            revert_reason = tx_info.get("error_message")
            gas_used = tx_info.get("gas_used", 0)

            asset_deltas = self._parse_asset_changes(result, from_address)
            warnings = self._generate_warnings(result, asset_deltas)

            return {
                "success": success,
                "revert_reason": revert_reason,
                "gas_used": gas_used,
                "asset_deltas": asset_deltas,
                "warnings": warnings,
            }

        except Exception as e:
            logger.error(f"Transaction simulation failed: {e}")
            return None

    async def _tenderly_simulate(
        self,
        to_address: str,
        from_address: str,
        value: str,
        data: str,
        chain_id: int,
    ) -> Optional[dict]:
        """Call Tenderly simulation API."""
        try:
            url = f"{TENDERLY_API_BASE}/account/{self.project_id}/project/shieldbot/simulate"

            headers = {
                "X-Access-Key": self.api_key,
                "Content-Type": "application/json",
            }

            # Parse value — handle hex or decimal
            try:
                if value.startswith("0x") or value.startswith("0X"):
                    value_int = int(value, 16)
                else:
                    value_int = int(value)
            except (ValueError, TypeError):
                value_int = 0

            payload = {
                "network_id": str(chain_id),
                "from": from_address.lower(),
                "to": to_address.lower(),
                "input": data,
                "value": value_int,
                "gas": 8000000,
                "gas_price": 0,
                "save": False,
                "simulation_type": "quick",
            }

            response = await self.client.post(url, json=payload, headers=headers)

            if response.status_code != 200:
                logger.error(f"Tenderly simulation failed: {response.status_code} {response.text}")
                return None

            return response.json()

        except Exception as e:
            logger.error(f"Tenderly API error: {e}")
            return None

    def _parse_asset_changes(self, result: dict, from_address: str) -> List[Dict[str, Any]]:
        """Parse asset balance changes from simulation result."""
        asset_deltas = []

        balance_changes = result.get("transaction", {}).get("balance_diff", [])

        for change in balance_changes:
            address = change.get("address", "").lower()

            if address != from_address.lower():
                continue

            if "dirty" in change:
                for token_addr, delta in change["dirty"].items():
                    balance_change = delta.get("balance")
                    if balance_change:
                        asset_deltas.append({
                            "token_address": token_addr.lower(),
                            "token_symbol": "UNKNOWN",
                            "balance_change": str(balance_change),
                        })

        return asset_deltas

    def _generate_warnings(self, result: dict, asset_deltas: List[Dict]) -> List[str]:
        """Generate warnings based on simulation analysis."""
        warnings = []

        for delta in asset_deltas:
            try:
                change = int(delta["balance_change"])
                if change < 0:
                    warnings.append(f"Asset outflow detected: {delta['token_symbol']}")
            except (ValueError, TypeError):
                pass

        state_changes = result.get("transaction", {}).get("state_diff", [])
        if len(state_changes) > 50:
            warnings.append("Excessive state changes (possible reentrancy)")

        calls = result.get("transaction", {}).get("calls", [])
        for call in calls:
            if not call.get("status", True):
                warnings.append(f"Subcall failed to {call.get('to', 'unknown')}")

        return warnings
