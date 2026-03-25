"""MCP resource definitions — read-only data endpoints.

Resources expose ShieldBot data that MCP clients can read/subscribe to.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resource definitions
# ---------------------------------------------------------------------------

RESOURCE_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "uri": "shieldbot://threat-feed",
        "name": "Threat Feed",
        "description": "Recent threats discovered by ShieldBot's autonomous agents (Hunter/Sentinel).",
        "mimeType": "application/json",
    },
    {
        "uri": "shieldbot://agent/{agent_id}/health",
        "name": "Agent Health",
        "description": "Policy configuration and recent firewall verdicts for a registered agent.",
        "mimeType": "application/json",
    },
    {
        "uri": "shieldbot://wallet/{address}/guardian",
        "name": "Wallet Guardian",
        "description": "Wallet approval health and guardian status. (Stub — full in V3.2.)",
        "mimeType": "application/json",
    },
]


# ---------------------------------------------------------------------------
# Resource readers
# ---------------------------------------------------------------------------

async def read_resource(container, uri: str) -> Optional[Dict]:
    """Read a resource by URI. Returns content dict or None if not found."""
    if uri == "shieldbot://threat-feed":
        return await _read_threat_feed(container)

    if uri.startswith("shieldbot://agent/") and uri.endswith("/health"):
        # Extract agent_id from shieldbot://agent/{agent_id}/health
        parts = uri.split("/")
        if len(parts) >= 4:
            agent_id = parts[3]
            return await _read_agent_health(container, agent_id)

    if uri.startswith("shieldbot://wallet/") and uri.endswith("/guardian"):
        parts = uri.split("/")
        if len(parts) >= 4:
            address = parts[3]
            return await _read_wallet_guardian(container, address)

    return None


async def _read_threat_feed(container) -> Dict:
    """Read recent agent findings as a threat feed."""
    findings = await container.db.get_agent_findings(limit=50)

    threats = []
    for f in findings:
        threats.append({
            "address": f.get("address"),
            "deployer": f.get("deployer"),
            "chain_id": f.get("chain_id"),
            "risk_score": f.get("risk_score"),
            "finding_type": f.get("finding_type"),
            "narrative": f.get("narrative"),
            "created_at": f.get("created_at"),
        })

    return {
        "uri": "shieldbot://threat-feed",
        "mimeType": "application/json",
        "text": threats,
    }


async def _read_agent_health(container, agent_id: str) -> Dict:
    """Read agent policy and recent verdicts."""
    policy = await container.db.get_agent_policy(agent_id)
    if not policy:
        return {
            "uri": f"shieldbot://agent/{agent_id}/health",
            "mimeType": "application/json",
            "text": {"error": "Agent not registered", "agent_id": agent_id},
        }

    history = await container.db.get_agent_firewall_history(agent_id, limit=20)

    return {
        "uri": f"shieldbot://agent/{agent_id}/health",
        "mimeType": "application/json",
        "text": {
            "agent_id": agent_id,
            "policy": policy.get("policy", {}),
            "owner_address": policy.get("owner_address"),
            "recent_verdicts": history,
        },
    }


async def _read_wallet_guardian(container, address: str) -> Dict:
    """Stub: wallet guardian resource. Full in V3.2."""
    return {
        "uri": f"shieldbot://wallet/{address}/guardian",
        "mimeType": "application/json",
        "text": {
            "wallet_address": address,
            "approvals": [],
            "guardian_active": False,
            "note": "Wallet Guardian not yet implemented. Coming in V3.2.",
        },
    }
