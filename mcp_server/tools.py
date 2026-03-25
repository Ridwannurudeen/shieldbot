"""MCP tool definitions — 8 tools wrapping ShieldBot security services.

Each tool has a name, description, JSON Schema input definition, and an
async handler that delegates to the ServiceContainer.
"""

import logging
import re
from typing import Any, Dict, List

from core.analyzer import AnalysisContext

logger = logging.getLogger(__name__)

_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

# --- Injection detection patterns (basic regex for V3.1 stub) ---
_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE), "instruction_override"),
    (re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE), "role_hijack"),
    (re.compile(r"system\s*:\s*", re.IGNORECASE), "system_prompt_inject"),
    (re.compile(r"<\|?(system|im_start|endoftext)\|?>", re.IGNORECASE), "token_boundary_inject"),
    (re.compile(r"do\s+not\s+follow\s+(your|the)\s+(rules|instructions)", re.IGNORECASE), "instruction_override"),
    (re.compile(r"pretend\s+(you|that)\s+", re.IGNORECASE), "role_hijack"),
]


def _validate_address(addr: str) -> str:
    if not _ADDRESS_RE.match(addr):
        raise ValueError(f"Invalid address: {addr}")
    return addr.lower()


# ---------------------------------------------------------------------------
# Tool schema definitions
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "scan_contract",
        "description": "Run all ShieldBot analyzers on a contract address and return a composite risk score with flags and risk level.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Contract address (0x...)"},
                "chain_id": {"type": "integer", "description": "Chain ID (default 56 = BNB Chain)", "default": 56},
            },
            "required": ["address"],
        },
    },
    {
        "name": "simulate_transaction",
        "description": "Simulate a transaction via Tenderly to predict asset changes, approvals granted, and gas estimate before execution.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "from": {"type": "string", "description": "Sender address"},
                "to": {"type": "string", "description": "Recipient / contract address"},
                "data": {"type": "string", "description": "Transaction calldata (hex)"},
                "value": {"type": "string", "description": "Value in wei (default '0')", "default": "0"},
                "chain_id": {"type": "integer", "description": "Chain ID (default 56)", "default": 56},
            },
            "required": ["from", "to", "data"],
        },
    },
    {
        "name": "check_deployer",
        "description": "Look up the deployer of a contract and return their deployment history and flagged contract count.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Contract address to check deployer for"},
                "chain_id": {"type": "integer", "description": "Chain ID (default 56)", "default": 56},
            },
            "required": ["address"],
        },
    },
    {
        "name": "check_agent_reputation",
        "description": "Look up the trust score and transaction history for an agent registered with ShieldBot's firewall.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "Agent identifier (e.g. 'agent:123')"},
            },
            "required": ["agent_id"],
        },
    },
    {
        "name": "check_approval_risk",
        "description": "Scan a wallet for risky token approvals. (Stub — full implementation in V3.2 Guardian.)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "wallet_address": {"type": "string", "description": "Wallet address to scan"},
                "chain_id": {"type": "integer", "description": "Chain ID (default 56)", "default": 56},
            },
            "required": ["wallet_address"],
        },
    },
    {
        "name": "scan_for_injection",
        "description": "Detect prompt injection patterns in text content. (Basic regex in V3.1, full ML in V3.4.)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "Text content to scan for injection attempts"},
                "depth": {
                    "type": "string",
                    "enum": ["fast", "thorough"],
                    "description": "Scan depth (default 'fast')",
                    "default": "fast",
                },
            },
            "required": ["content"],
        },
    },
    {
        "name": "query_threat_graph",
        "description": "Check if an address is connected to known threat clusters. (Stub — full graph in V3.5.)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address to check"},
                "chain_id": {"type": "integer", "description": "Chain ID (default 56)", "default": 56},
                "max_depth": {"type": "integer", "description": "Max traversal depth (default 2)", "default": 2},
            },
            "required": ["address"],
        },
    },
    {
        "name": "get_threat_feed",
        "description": "Retrieve the latest flagged contracts and threats from ShieldBot's agent findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Number of results (default 20, max 100)", "default": 20},
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool handler implementations
# ---------------------------------------------------------------------------

async def handle_scan_contract(container, params: Dict) -> Dict:
    """Run all analyzers on a contract and return composite risk score."""
    address = _validate_address(params["address"])
    chain_id = params.get("chain_id", 56)

    ctx = AnalysisContext(address=address, chain_id=chain_id)
    results = await container.registry.run_all(ctx)
    score_data = container.risk_engine.compute_from_results(results)

    return {
        "verdict": score_data.get("risk_level", "UNKNOWN"),
        "score": score_data.get("risk_score", 0),
        "flags": score_data.get("flags", []),
        "risk_level": score_data.get("risk_level", "UNKNOWN"),
        "categories": score_data.get("category_scores", {}),
    }


async def handle_simulate_transaction(container, params: Dict) -> Dict:
    """Simulate a transaction via Tenderly."""
    from_addr = params["from"]
    to_addr = params["to"]
    data = params.get("data", "0x")
    value = params.get("value", "0")
    chain_id = params.get("chain_id", 56)

    if not container.tenderly_simulator.is_enabled():
        return {
            "error": "Tenderly simulation not configured",
            "asset_changes": [],
            "approvals_granted": [],
            "gas_estimate": 0,
        }

    result = await container.tenderly_simulator.simulate_transaction(
        to_address=to_addr,
        from_address=from_addr,
        value=value,
        data=data,
        chain_id=chain_id,
    )

    if result is None:
        return {
            "error": "Simulation failed",
            "asset_changes": [],
            "approvals_granted": [],
            "gas_estimate": 0,
        }

    return {
        "asset_changes": result.get("asset_deltas", []),
        "approvals_granted": result.get("warnings", []),
        "gas_estimate": result.get("gas_used", 0),
    }


async def handle_check_deployer(container, params: Dict) -> Dict:
    """Look up deployer history for a contract."""
    address = _validate_address(params["address"])
    chain_id = params.get("chain_id", 56)

    summary = await container.db.get_deployer_risk_summary(address, chain_id)
    if summary is None:
        return {
            "deployer": None,
            "funded_by": None,
            "contracts_deployed": 0,
            "flagged_count": 0,
            "note": "Deployer not yet indexed for this contract",
        }

    return {
        "deployer": summary.get("deployer_address"),
        "funded_by": summary.get("funded_by"),
        "contracts_deployed": summary.get("total_contracts", 0),
        "flagged_count": summary.get("high_risk_contracts", 0),
    }


async def handle_check_agent_reputation(container, params: Dict) -> Dict:
    """Look up agent trust score from firewall history."""
    agent_id = params["agent_id"]

    policy = await container.db.get_agent_policy(agent_id)
    if not policy:
        return {
            "agent_id": agent_id,
            "trust_score": None,
            "total_transactions": 0,
            "block_rate": 0.0,
            "note": "Agent not registered",
        }

    history = await container.db.get_agent_firewall_history(agent_id, limit=1000)
    total = len(history)
    blocked = sum(1 for h in history if h.get("verdict") == "BLOCK")
    block_rate = (blocked / total) if total > 0 else 0.0

    # Simple trust heuristic: 100 - block_rate*100, floored at 0
    trust_score = max(0, round(100 - block_rate * 100, 1))

    return {
        "agent_id": agent_id,
        "trust_score": trust_score,
        "total_transactions": total,
        "block_rate": round(block_rate, 4),
    }


async def handle_check_approval_risk(container, params: Dict) -> Dict:
    """Stub: wallet approval risk scan. Full implementation in V3.2 Guardian."""
    wallet = _validate_address(params["wallet_address"])
    return {
        "wallet_address": wallet,
        "chain_id": params.get("chain_id", 56),
        "approvals": [],
        "risk_summary": "Approval scanning not yet implemented. Coming in V3.2 (Guardian).",
    }


async def handle_scan_for_injection(container, params: Dict) -> Dict:
    """Basic regex-based prompt injection detection."""
    content = params.get("content", "")
    depth = params.get("depth", "fast")

    detections = []
    for pattern, label in _INJECTION_PATTERNS:
        matches = pattern.findall(content)
        if matches:
            detections.append({
                "type": label,
                "count": len(matches),
            })

    clean = len(detections) == 0
    if detections:
        risk_level = "HIGH" if len(detections) >= 3 else "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "clean": clean,
        "risk_level": risk_level,
        "detections": detections,
        "depth": depth,
        "note": "Basic regex detection (V3.1). ML-based detection coming in V3.4.",
    }


async def handle_query_threat_graph(container, params: Dict) -> Dict:
    """Stub: threat graph query. Full implementation in V3.5."""
    address = _validate_address(params["address"])
    return {
        "address": address,
        "chain_id": params.get("chain_id", 56),
        "connected_to_cluster": False,
        "cluster_id": None,
        "edges": [],
        "note": "Threat graph not yet implemented. Coming in V3.5.",
    }


async def handle_get_threat_feed(container, params: Dict) -> Dict:
    """Retrieve latest flagged contracts from agent findings."""
    limit = min(max(params.get("limit", 20), 1), 100)

    findings = await container.db.get_agent_findings(limit=limit)

    threats = []
    for f in findings:
        threats.append({
            "address": f.get("address"),
            "risk_score": f.get("risk_score"),
            "flags": f.get("evidence", {}).get("flags", []) if isinstance(f.get("evidence"), dict) else [],
            "found_at": f.get("created_at"),
            "finding_type": f.get("finding_type"),
            "narrative": f.get("narrative"),
        })

    return {"threats": threats}


# ---------------------------------------------------------------------------
# Tool dispatcher
# ---------------------------------------------------------------------------

_HANDLERS = {
    "scan_contract": handle_scan_contract,
    "simulate_transaction": handle_simulate_transaction,
    "check_deployer": handle_check_deployer,
    "check_agent_reputation": handle_check_agent_reputation,
    "check_approval_risk": handle_check_approval_risk,
    "scan_for_injection": handle_scan_for_injection,
    "query_threat_graph": handle_query_threat_graph,
    "get_threat_feed": handle_get_threat_feed,
}


async def execute_tool(container, tool_name: str, params: Dict) -> Dict:
    """Dispatch a tool call to the appropriate handler.

    Returns the tool result dict or raises ValueError for unknown tools.
    """
    handler = _HANDLERS.get(tool_name)
    if handler is None:
        raise ValueError(f"Unknown tool: {tool_name}")
    return await handler(container, params or {})
