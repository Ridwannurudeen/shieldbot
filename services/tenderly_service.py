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

            # State override: give sender 1000 BNB so simulation never fails on insufficient funds
            state_objects = {
                from_address.lower(): {
                    "balance": hex(1000 * 10**18),
                }
            }

            payload = {
                "network_id": str(chain_id),
                "from": from_address.lower(),
                "to": to_address.lower(),
                "input": data,
                "value": value_int,
                "gas": 8000000,
                "gas_price": 0,
                "save": False,
                "simulation_type": "full",
                "state_objects": state_objects,
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
        """Parse asset balance changes from simulation result.

        Uses transaction.asset_changes (full simulation) with balance_diff as
        fallback for native-only transactions.
        """
        asset_deltas = []
        wallet = from_address.lower()
        tx = result.get("transaction", {})

        raw_changes = tx.get("asset_changes") or []
        tx_info = tx.get("transaction_info", {})
        balance_diff = tx.get("balance_diff") or []
        logger.info(f"Tenderly asset_changes={len(raw_changes)} balance_diff={len(balance_diff)} tx_info_keys={list(tx_info.keys())}")
        ti_changes = tx_info.get("asset_changes") or []
        ti_balance_diff = tx_info.get("balance_diff") or []
        logger.info(f"Tenderly transaction_info: asset_changes={len(ti_changes)} balance_diff={len(ti_balance_diff)}")
        if ti_changes:
            logger.info(f"transaction_info asset_changes sample: {ti_changes[:2]}")

        # Primary: structured asset_changes from full simulation
        for change in raw_changes:
            frm = (change.get("from") or "").lower()
            to = (change.get("to") or "").lower()
            if frm != wallet and to != wallet:
                continue

            info = change.get("asset_info") or change.get("token_info") or {}
            symbol = info.get("symbol") or info.get("ticker") or "?"
            try:
                decimals = int(info.get("decimals") or 18)
            except (ValueError, TypeError):
                decimals = 18
            try:
                raw = int(change.get("raw_amount") or change.get("amount") or 0)
            except (ValueError, TypeError):
                raw = 0
            amount = raw / (10 ** decimals)
            dollar = change.get("dollar_value") or ""

            direction = "out" if frm == wallet else "in"
            sign = "-" if direction == "out" else "+"
            display = f"{sign}{amount:,.4f} {symbol}"
            if dollar:
                try:
                    display += f" (≈${float(dollar):,.2f})"
                except (ValueError, TypeError):
                    pass

            asset_deltas.append({
                "token_symbol": symbol,
                "display": display,
                "direction": direction,
                "amount": amount,
                "dollar_value": dollar,
            })

        if asset_deltas:
            return asset_deltas

        # Fallback: native token balance_diff for simple ETH/BNB sends.
        # Tenderly balance_diff format: [{address, original: "0xHEX", dirty: "0xHEX"}]
        def _parse_hex(v: Any) -> int:
            s = str(v or "0")
            return int(s, 16) if s.startswith(("0x", "0X")) else int(s)

        for change in tx.get("balance_diff", []):
            if (change.get("address") or "").lower() != wallet:
                continue
            try:
                balance_change = _parse_hex(change.get("dirty")) - _parse_hex(change.get("original"))
            except (ValueError, TypeError):
                continue
            if balance_change == 0:
                continue
            amount = abs(balance_change) / 10**18
            direction = "out" if balance_change < 0 else "in"
            sign = "-" if direction == "out" else "+"
            display = f"{sign}{amount:,.4f} BNB"
            asset_deltas.append({
                "token_symbol": "BNB",
                "display": display,
                "direction": direction,
                "amount": amount,
                "dollar_value": "",
            })

        return asset_deltas

    def _generate_warnings(self, result: dict, asset_deltas: List[Dict]) -> List[str]:
        """Generate warnings based on simulation analysis."""
        warnings = []

        for delta in asset_deltas:
            if delta.get("direction") == "out":
                warnings.append(f"Asset outflow detected: {delta['token_symbol']}")

        state_changes = result.get("transaction", {}).get("state_diff") or []
        if len(state_changes) > 50:
            warnings.append("Excessive state changes (possible reentrancy)")

        calls = result.get("transaction", {}).get("calls") or []
        for call in calls:
            if not call.get("status", True):
                warnings.append(f"Subcall failed to {call.get('to', 'unknown')}")

        return warnings
