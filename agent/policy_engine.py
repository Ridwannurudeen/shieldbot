"""Threshold-based policy engine for agent transaction firewall."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PolicyVerdict:
    """Result of evaluating an agent's policy against a transaction."""
    verdict: str  # "ALLOW" | "WARN" | "BLOCK"
    checks: Dict[str, str] = field(default_factory=dict)
    failed_checks: List[str] = field(default_factory=list)
    needs_owner_approval: bool = False
    all_passed: bool = False


# Safe defaults when policy fields are missing
DEFAULTS = {
    "mode": "threshold",
    "auto_allow_below": 25,
    "auto_block_above": 70,
    "max_spend_per_tx_usd": 1000,
    "max_spend_daily_usd": 10000,
    "max_slippage": 0.10,
    "always_allow": [],
    "always_block": [],
    "timeout_action": "block",
    "fail_mode": "cached_then_block",
}


class AgentPolicyEngine:
    """Evaluates agent policies using a threshold model.

    - auto_allow_below: transactions scoring below this pass automatically.
    - auto_block_above: transactions scoring above this are blocked.
    - Middle range: asks the owner for approval.
    - Explicit allowlist/blocklist override everything.
    - Spending limits and slippage caps are hard gates.
    """

    def _get(self, policy: dict, key: str):
        """Get policy value with fallback to defaults."""
        return policy.get(key, DEFAULTS.get(key))

    def evaluate(
        self,
        policy: Dict,
        risk_score: float,
        target_address: str,
        tx_value_usd: float = 0,
        daily_spend_usd: float = 0,
        simulated_slippage: float = None,
    ) -> PolicyVerdict:
        """Evaluate a transaction against an agent's policy."""
        checks = {}
        failed = []
        target_lower = target_address.lower()

        # 1. Explicit lists (highest priority)
        always_allow = [a.lower() for a in (self._get(policy, "always_allow") or [])]
        always_block = [a.lower() for a in (self._get(policy, "always_block") or [])]

        if target_lower in always_block:
            checks["contract_list"] = "fail — blocklist match"
            return PolicyVerdict(
                verdict="BLOCK", checks=checks,
                failed_checks=["contract_list"],
            )

        if target_lower in always_allow:
            checks["contract_list"] = "pass — allowlist match"
            return PolicyVerdict(
                verdict="ALLOW", checks=checks, all_passed=True,
            )

        checks["contract_list"] = "pass — no list match"

        # 2. Spending limits (hard gates)
        max_per_tx = self._get(policy, "max_spend_per_tx_usd")
        if tx_value_usd > max_per_tx:
            checks["spending_limit"] = f"fail — ${tx_value_usd:.2f} > ${max_per_tx:.2f} limit"
            failed.append("spending_limit")
        else:
            checks["spending_limit"] = f"pass — ${tx_value_usd:.2f} <= ${max_per_tx:.2f}"

        max_daily = self._get(policy, "max_spend_daily_usd")
        if (daily_spend_usd + tx_value_usd) > max_daily:
            checks["daily_limit"] = f"fail — ${daily_spend_usd + tx_value_usd:.2f} > ${max_daily:.2f} daily limit"
            failed.append("daily_limit")
        else:
            checks["daily_limit"] = f"pass — ${daily_spend_usd + tx_value_usd:.2f} <= ${max_daily:.2f}"

        # 3. Slippage cap
        max_slip = self._get(policy, "max_slippage")
        if simulated_slippage is not None and simulated_slippage > max_slip:
            checks["slippage_cap"] = f"fail — {simulated_slippage:.1%} > {max_slip:.1%}"
            failed.append("slippage_cap")
        elif simulated_slippage is not None:
            checks["slippage_cap"] = f"pass — {simulated_slippage:.1%} <= {max_slip:.1%}"
        else:
            checks["slippage_cap"] = "skip — no simulation data"

        # Hard gate failures → BLOCK regardless of score
        if failed:
            checks["risk_threshold"] = "skip — hard gate failed"
            return PolicyVerdict(
                verdict="BLOCK", checks=checks, failed_checks=failed,
            )

        # 4. Risk threshold
        allow_below = self._get(policy, "auto_allow_below")
        block_above = self._get(policy, "auto_block_above")

        if risk_score < allow_below:
            checks["risk_threshold"] = f"pass — score {risk_score} < {allow_below}"
            return PolicyVerdict(
                verdict="ALLOW", checks=checks, all_passed=True,
            )

        if risk_score > block_above:
            checks["risk_threshold"] = f"fail — score {risk_score} > {block_above}"
            failed.append("risk_threshold")
            return PolicyVerdict(
                verdict="BLOCK", checks=checks, failed_checks=failed,
            )

        # Middle range → ask owner
        checks["risk_threshold"] = f"warn — score {risk_score} in [{allow_below}, {block_above}]"
        return PolicyVerdict(
            verdict="WARN", checks=checks,
            needs_owner_approval=True,
        )
