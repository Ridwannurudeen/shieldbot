"""MCP tool definitions — 9 tools wrapping ShieldBot security services.

Each tool has a name, description, JSON Schema input definition, and an
async handler that delegates to the ServiceContainer.
"""

import logging
import re
from typing import Any, Dict, List

from core.analyzer import AnalysisContext
from core.extension_formatter import format_extension_alert
from services.launch_discovery import CHAIN_ID as LAUNCH_CHAIN_ID

logger = logging.getLogger(__name__)

_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_WEI_RE = re.compile(r"0[xX][0-9a-fA-F]+|[0-9]+")
_CHAIN_ID_DESCRIPTION = (
    "Chain ID of the chain the address or transaction is on; required, there is no default. "
    "Every chain ShieldBot supports is accepted, including 56 = BNB Chain and 4663 = Robinhood Chain; "
    "an unsupported chain ID is rejected."
)

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


def _require(params: Dict, name: str) -> str:
    value = params.get(name)
    if value is None:
        raise ValueError(f"Missing required argument: {name}")
    if not isinstance(value, str):
        raise ValueError(f"Invalid argument: {name} must be a string")
    return value


def _validate_chain_id(container, chain_id) -> int:
    if type(chain_id) is not int:
        raise ValueError("Invalid argument: chain_id must be an integer")
    return container.web3_client.validate_chain_id(chain_id)


def _require_chain_id(container, params: Dict) -> int:
    # A default chain would analyse an address from another chain on that chain, where it can look clean.
    if params.get("chain_id") is None:
        raise ValueError(
            "Missing required argument: chain_id (the chain the address or transaction is on, "
            "for example 56 = BNB Chain or 4663 = Robinhood Chain)"
        )
    return _validate_chain_id(container, params["chain_id"])


# ---------------------------------------------------------------------------
# Tool schema definitions
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "scan_contract",
        "description": (
            "Run all ShieldBot analyzers on a contract address and return a composite risk score with flags and risk level. "
            "Incomplete provider coverage is never reported as safe: the result then has status 'unknown', "
            "verdict 'UNKNOWN', risk_display 'Unknown (incomplete provider coverage)' and coverage_reasons naming the missing data."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Contract address (0x...)"},
                "chain_id": {"type": "integer", "description": _CHAIN_ID_DESCRIPTION},
            },
            "required": ["address", "chain_id"],
        },
    },
    {
        "name": "simulate_transaction",
        "description": (
            "Simulate a transaction via Tenderly and return success, revert reason, asset changes, warnings, and gas estimate. "
            "Approval changes are not measured and are returned as null. When simulation is not configured or fails, "
            "the result has status 'unknown', coverage_reasons naming why, and null measurements."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "from": {"type": "string", "description": "Sender address"},
                "to": {"type": "string", "description": "Recipient / contract address"},
                "data": {"type": "string", "description": "Transaction calldata (hex)"},
                "value": {"type": "string", "description": "Value in wei (default '0')", "default": "0"},
                "chain_id": {"type": "integer", "description": _CHAIN_ID_DESCRIPTION},
            },
            "required": ["from", "to", "data", "chain_id"],
        },
    },
    {
        "name": "check_deployer",
        "description": (
            "Look up the deployer of a contract and return their deployment history and flagged contract count. "
            "A contract whose deployer is not indexed yet returns status 'unknown' with coverage_reasons and null counts, never zero."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Contract address to check deployer for"},
                "chain_id": {"type": "integer", "description": _CHAIN_ID_DESCRIPTION},
            },
            "required": ["address", "chain_id"],
        },
    },
    {
        "name": "check_agent_reputation",
        "description": (
            "Look up the trust score and transaction history for an agent registered with ShieldBot's firewall. "
            "An unregistered agent, or one with no firewall history, returns status 'unknown' with coverage_reasons "
            "and a null trust_score."
        ),
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
        "description": "Approval risk checking is not implemented in MCP. Returns status 'unknown' and coverage_reasons; approvals are null, never a safety verdict.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "wallet_address": {"type": "string", "description": "Wallet address to scan"},
                "chain_id": {"type": "integer", "description": _CHAIN_ID_DESCRIPTION},
            },
            "required": ["wallet_address", "chain_id"],
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
        "description": "Threat graph querying is not implemented in MCP. Returns status 'unknown' and coverage_reasons; connections are null, never a safety verdict.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address to check"},
                "chain_id": {"type": "integer", "description": _CHAIN_ID_DESCRIPTION},
                "max_depth": {"type": "integer", "description": "Max traversal depth (default 2)", "default": 2},
            },
            "required": ["address", "chain_id"],
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
    {
        "name": "get_robinhood_launches",
        "description": (
            "Read-only. List recent Robinhood Chain (chain 4663) token launches discovered by ShieldBot, newest first, "
            "each with its latest scan outcome: blocked, watching, cleared, unknown (scan incomplete) or not_scanned. "
            "unknown and not_scanned have status 'unknown' with coverage_reasons and are never safe. "
            "scan.status is authoritative: 'ok' only for a complete scan; per-field coverage is present only "
            "for blocked launches. Page with next_cursor."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain_id": {
                    "type": "integer",
                    "description": "Chain ID (default 4663 = Robinhood Chain, the only chain with launch discovery)",
                    "default": 4663,
                },
                "limit": {"type": "integer", "description": "Number of results (default 20, max 100)", "default": 20},
                "cursor": {"type": "string", "description": "next_cursor from the previous page (optional)"},
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool handler implementations
# ---------------------------------------------------------------------------

async def handle_scan_contract(container, params: Dict) -> Dict:
    """Run all analyzers on a contract and return composite risk score."""
    address = _validate_address(_require(params, "address"))
    chain_id = _require_chain_id(container, params)

    ctx = AnalysisContext(address=address, chain_id=chain_id)
    results = await container.registry.run_all(ctx)
    score_data = container.risk_engine.compute_from_results(results)

    alert = format_extension_alert(score_data)
    return {
        "verdict": "UNKNOWN" if alert["status"] == "unknown" else score_data.get("risk_level", "UNKNOWN"),
        "score": score_data["rug_probability"],
        "flags": score_data.get("critical_flags", []),
        "status": alert["status"],
        "coverage": score_data.get("coverage", {}),
        "coverage_reasons": alert["coverage_reasons"],
        "confidence": score_data.get("confidence_level"),
        "risk_display": alert["risk_display"],
        "risk_level": score_data.get("risk_level", "UNKNOWN"),
        "categories": score_data.get("category_scores", {}),
    }


async def handle_simulate_transaction(container, params: Dict) -> Dict:
    """Simulate a transaction via Tenderly."""
    from_addr = _validate_address(_require(params, "from"))
    to_addr = _validate_address(_require(params, "to"))
    data = _require(params, "data")
    value = params.get("value", "0")
    # The simulator replaces an unparseable value with 0, which would simulate a different transaction.
    if not isinstance(value, str) or not _WEI_RE.fullmatch(value):
        raise ValueError("Invalid argument: value must be a decimal or 0x-prefixed hex amount of wei")
    chain_id = _require_chain_id(container, params)

    if not container.tenderly_simulator.is_enabled():
        return {
            "error": "Tenderly simulation not configured",
            "status": "unknown",
            "coverage": {"simulation": 0},
            "coverage_reasons": {"simulation": "Tenderly simulation not configured"},
            "asset_changes": None,
            "approvals_granted": None,
            "gas_estimate": None,
            "warnings": None,
            "success": None,
            "revert_reason": None,
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
            "status": "unknown",
            "coverage": {"simulation": 0},
            "coverage_reasons": {"simulation": "Simulation failed"},
            "asset_changes": None,
            "approvals_granted": None,
            "gas_estimate": None,
            "warnings": None,
            "success": None,
            "revert_reason": None,
        }

    return {
        "asset_changes": result.get("asset_deltas"),
        "approvals_granted": None,
        "gas_estimate": result.get("gas_used"),
        "warnings": result.get("warnings"),
        "success": result.get("success"),
        "revert_reason": result.get("revert_reason"),
    }


async def handle_check_deployer(container, params: Dict) -> Dict:
    """Look up deployer history for a contract."""
    address = _validate_address(_require(params, "address"))
    chain_id = _require_chain_id(container, params)

    summary = await container.db.get_deployer_risk_summary(address, chain_id)
    if summary is None:
        return {
            "deployer": None,
            "funded_by": None,
            "contracts_deployed": None,
            "flagged_count": None,
            "status": "unknown",
            "coverage": {"deployer": 0},
            "coverage_reasons": {"deployer": "Deployer not yet indexed for this contract"},
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
    agent_id = _require(params, "agent_id")

    policy = await container.db.get_agent_policy(agent_id)
    if not policy:
        return {
            "agent_id": agent_id,
            "trust_score": None,
            "total_transactions": None,
            "block_rate": None,
            "status": "unknown",
            "coverage": {"history": 0},
            "coverage_reasons": {"history": "Agent not registered"},
            "note": "Agent not registered",
        }

    history = await container.db.get_agent_firewall_history(agent_id, limit=1000)
    total = len(history)
    if total == 0:
        return {
            "agent_id": agent_id,
            "trust_score": None,
            "total_transactions": 0,
            "block_rate": None,
            "status": "unknown",
            "coverage": {"history": 0},
            "coverage_reasons": {"history": "No firewall history for this agent"},
        }
    blocked = sum(1 for h in history if h.get("verdict") == "BLOCK")
    block_rate = blocked / total

    # Simple trust heuristic: 100 - block_rate*100, floored at 0
    trust_score = max(0, round(100 - block_rate * 100, 1))

    return {
        "agent_id": agent_id,
        "trust_score": trust_score,
        "total_transactions": total,
        "block_rate": round(block_rate, 4),
    }


async def handle_check_approval_risk(container, params: Dict) -> Dict:
    """Report unavailable MCP approval coverage without claiming no approvals."""
    wallet = _validate_address(_require(params, "wallet_address"))
    return {
        "wallet_address": wallet,
        "chain_id": _require_chain_id(container, params),
        "approvals": None,
        "status": "unknown",
        "coverage": {"approvals": 0},
        "coverage_reasons": {"approvals": "Approval risk checking is not implemented in MCP"},
        "risk_summary": "Unknown: approvals were not checked.",
    }


async def handle_scan_for_injection(container, params: Dict) -> Dict:
    """Basic regex-based prompt injection detection."""
    content = _require(params, "content")
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
    """Report unavailable MCP graph coverage without claiming no connections."""
    address = _validate_address(_require(params, "address"))
    return {
        "address": address,
        "chain_id": _require_chain_id(container, params),
        "connected_to_cluster": None,
        "cluster_id": None,
        "edges": None,
        "status": "unknown",
        "coverage": {"threat_graph": 0},
        "coverage_reasons": {"threat_graph": "Threat graph querying is not implemented in MCP"},
        "note": "Unknown: threat connections were not checked.",
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


async def handle_get_robinhood_launches(container, params: Dict) -> Dict:
    """Recent launches with their latest scan outcome, from the query behind /api/launches."""
    chain_id = _validate_chain_id(container, params.get("chain_id", LAUNCH_CHAIN_ID))
    limit = min(max(params.get("limit", 20), 1), 100)
    if chain_id != LAUNCH_CHAIN_ID:
        return {
            "launches": [],
            "count": 0,
            "chain_id": chain_id,
            "next_cursor": None,
            "discovery_unavailable": "Launch discovery is not available on this chain",
        }
    launches, next_cursor = await container.db.get_launch_feed(chain_id, limit, params.get("cursor"))
    return {"launches": launches, "count": len(launches), "chain_id": chain_id, "next_cursor": next_cursor}


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
    "get_robinhood_launches": handle_get_robinhood_launches,
}


async def execute_tool(container, tool_name: str, params: Dict) -> Dict:
    """Dispatch a tool call to the appropriate handler.

    Returns the tool result dict or raises ValueError for unknown tools.
    """
    handler = _HANDLERS.get(tool_name)
    if handler is None:
        raise ValueError(f"Unknown tool: {tool_name}")
    return await handler(container, params or {})
