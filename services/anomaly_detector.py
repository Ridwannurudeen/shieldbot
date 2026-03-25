"""Agent behavior anomaly detection with peer-group comparison."""

import json
import math
import time
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Behavioral baseline building and drift detection for AI agents."""

    BASELINE_PERIOD_HOURS = 72
    ALERT_INDIVIDUAL_THRESHOLD = 2.0  # standard deviations
    VALUE_SPIKE_MULTIPLIER = 5.0
    FREQUENCY_SPIKE_MULTIPLIER = 3.0

    DANGEROUS_METHODS = {
        "0x095ea7b3": "approve",
        "0xf2fde38b": "transferOwnership",
        "0x715018a6": "renounceOwnership",
        "0xa9059cbb": "transfer",
        "0x23b872dd": "transferFrom",
    }

    def __init__(self, db):
        self._db = db

    async def update_baseline(self, agent_id: str, event: Dict):
        """Add a transaction event to the agent's behavioral baseline.

        event: {timestamp, tx_value_usd, target_address, method_selector, gas_used, chain_id, verdict}
        """
        row = await self._db.get_anomaly_baseline(agent_id)
        if row and row.get("baseline_data"):
            try:
                baseline = json.loads(row["baseline_data"]) if isinstance(row["baseline_data"], str) else row["baseline_data"]
            except (json.JSONDecodeError, TypeError):
                baseline = None
        else:
            baseline = None

        if not baseline:
            baseline = {
                "agent_id": agent_id,
                "started_at": time.time(),
                "ready": False,
                "tx_count": 0,
                "hourly_counts": {},
                "values": [],
                "contracts": {},
                "methods": {},
                "gas_values": [],
                "chains": {},
            }

        now = event.get("timestamp", time.time())
        hour_key = str(int(now / 3600))

        baseline["tx_count"] = baseline.get("tx_count", 0) + 1

        hourly = baseline.get("hourly_counts", {})
        hourly[hour_key] = hourly.get(hour_key, 0) + 1
        # Cap to last 720 hours (30 days) to prevent unbounded growth
        if len(hourly) > 720:
            sorted_keys = sorted(hourly.keys())
            for old_key in sorted_keys[:-720]:
                del hourly[old_key]
        baseline["hourly_counts"] = hourly

        values = baseline.get("values", [])
        values.append(event.get("tx_value_usd", 0))
        baseline["values"] = values[-200:]

        contracts = baseline.get("contracts", {})
        target = (event.get("target_address") or "").lower()
        if target:
            contracts[target] = contracts.get(target, 0) + 1
        # Cap to top 500 contracts by count to prevent unbounded growth
        if len(contracts) > 500:
            sorted_contracts = sorted(contracts.items(), key=lambda x: x[1], reverse=True)[:500]
            contracts = dict(sorted_contracts)
        baseline["contracts"] = contracts

        methods = baseline.get("methods", {})
        selector = (event.get("method_selector") or "")[:10]
        if selector:
            methods[selector] = methods.get(selector, 0) + 1
        baseline["methods"] = methods

        gas_values = baseline.get("gas_values", [])
        gas = event.get("gas_used", 0)
        if gas and gas > 0:
            gas_values.append(gas)
        baseline["gas_values"] = gas_values[-200:]

        chains = baseline.get("chains", {})
        chain_id = str(event.get("chain_id", 56))
        chains[chain_id] = chains.get(chain_id, 0) + 1
        baseline["chains"] = chains

        elapsed_hours = (now - baseline.get("started_at", now)) / 3600
        baseline["ready"] = elapsed_hours >= self.BASELINE_PERIOD_HOURS and baseline["tx_count"] >= 10

        await self._db.upsert_anomaly_baseline(agent_id, json.dumps(baseline), baseline["ready"])

    async def check_anomaly(self, agent_id: str, event: Dict) -> Optional[Dict]:
        """Check if event is anomalous. Returns alert dict or None."""
        row = await self._db.get_anomaly_baseline(agent_id)
        if not row or not row.get("baseline_ready"):
            return None

        try:
            baseline = json.loads(row["baseline_data"]) if isinstance(row.get("baseline_data"), str) else row
        except (json.JSONDecodeError, TypeError):
            return None

        alerts = []

        value_alert = self._check_value_spike(event, baseline)
        if value_alert:
            alerts.append(value_alert)

        freq_alert = self._check_frequency_spike(event, baseline)
        if freq_alert:
            alerts.append(freq_alert)

        contract_alert = self._check_new_contract(event, baseline)
        if contract_alert:
            alerts.append(contract_alert)

        method_alert = self._check_method_anomaly(event, baseline)
        if method_alert:
            alerts.append(method_alert)

        if not alerts:
            return None

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        alerts.sort(key=lambda a: severity_order.get(a.get("severity", "low"), 3))
        return alerts[0]

    async def get_baseline(self, agent_id: str) -> Optional[Dict]:
        """Get current baseline data for an agent."""
        row = await self._db.get_anomaly_baseline(agent_id)
        if not row:
            return None
        try:
            data = json.loads(row["baseline_data"]) if isinstance(row.get("baseline_data"), str) else row
            data["baseline_ready"] = row.get("baseline_ready", False)
            return data
        except (json.JSONDecodeError, TypeError):
            return None

    def _check_value_spike(self, event: Dict, baseline: Dict) -> Optional[Dict]:
        """Check for 5x+ normal transaction value."""
        values = baseline.get("values", [])
        if len(values) < 5:
            return None

        avg_value = sum(values) / len(values)
        if avg_value <= 0:
            return None

        variance = sum((v - avg_value) ** 2 for v in values) / len(values)
        std_dev = math.sqrt(variance) if variance > 0 else 0

        current_value = event.get("tx_value_usd", 0)
        if current_value <= 0:
            return None

        if std_dev > 0:
            z_score = (current_value - avg_value) / std_dev
        else:
            z_score = 0 if current_value == avg_value else float('inf')

        if z_score > self.ALERT_INDIVIDUAL_THRESHOLD and current_value > avg_value * self.VALUE_SPIKE_MULTIPLIER:
            return {
                "alert_type": "value_spike",
                "severity": "high",
                "title": f"Value spike: ${current_value:.2f} vs avg ${avg_value:.2f}",
                "details": {
                    "current_value": current_value,
                    "average_value": round(avg_value, 2),
                    "z_score": round(z_score, 2),
                    "multiplier": round(current_value / avg_value, 1),
                },
            }
        return None

    def _check_frequency_spike(self, event: Dict, baseline: Dict) -> Optional[Dict]:
        """Check for 3x+ normal transaction rate."""
        hourly = baseline.get("hourly_counts", {})
        if len(hourly) < 3:
            return None

        counts = list(hourly.values())
        avg_hourly = sum(counts) / len(counts)
        if avg_hourly <= 0:
            return None

        now = event.get("timestamp", time.time())
        current_hour = str(int(now / 3600))
        current_count = hourly.get(current_hour, 0) + 1

        if current_count > avg_hourly * self.FREQUENCY_SPIKE_MULTIPLIER:
            return {
                "alert_type": "frequency_spike",
                "severity": "high",
                "title": f"Frequency spike: {current_count} tx/hr vs avg {avg_hourly:.1f}",
                "details": {
                    "current_hourly_rate": current_count,
                    "average_hourly_rate": round(avg_hourly, 1),
                    "multiplier": round(current_count / avg_hourly, 1),
                },
            }
        return None

    def _check_new_contract(self, event: Dict, baseline: Dict) -> Optional[Dict]:
        """Check if agent is interacting with unknown contracts."""
        known_contracts = set(baseline.get("contracts", {}).keys())
        target = (event.get("target_address") or "").lower()

        if target and target not in known_contracts and len(known_contracts) > 20:
            return {
                "alert_type": "new_contract_burst",
                "severity": "medium",
                "title": f"Interaction with unknown contract {target[:10]}...",
                "details": {
                    "new_contract": target,
                    "known_contracts": len(known_contracts),
                },
            }
        return None

    def _check_method_anomaly(self, event: Dict, baseline: Dict) -> Optional[Dict]:
        """Check for unusual function calls."""
        selector = (event.get("method_selector") or "")[:10]
        known_methods = baseline.get("methods", {})

        if selector in self.DANGEROUS_METHODS and selector not in known_methods:
            return {
                "alert_type": "method_anomaly",
                "severity": "high",
                "title": f"First-time dangerous call: {self.DANGEROUS_METHODS[selector]}()",
                "details": {
                    "method": self.DANGEROUS_METHODS[selector],
                    "selector": selector,
                    "never_called_before": True,
                },
            }
        return None
