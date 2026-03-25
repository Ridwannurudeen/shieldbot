"""MCP prompt definitions — reusable prompt templates for MCP clients.

Prompts provide structured templates that MCP clients can fill in with
arguments and present to the user or feed to an LLM.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt definitions
# ---------------------------------------------------------------------------

PROMPT_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "security-analysis",
        "description": "Analyze the security posture of a transaction or contract, including risk scoring, honeypot detection, and deployer history.",
        "arguments": [
            {
                "name": "transaction_hash",
                "description": "Transaction hash to analyze (optional if contract_address is provided)",
                "required": False,
            },
            {
                "name": "contract_address",
                "description": "Contract address to analyze (optional if transaction_hash is provided)",
                "required": False,
            },
        ],
    },
    {
        "name": "agent-evaluation",
        "description": "Evaluate the trustworthiness and behavior of a registered ShieldBot agent based on its firewall history and policy configuration.",
        "arguments": [
            {
                "name": "agent_id",
                "description": "Agent identifier to evaluate (e.g. 'agent:123')",
                "required": True,
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# Prompt renderers
# ---------------------------------------------------------------------------

def get_prompt(name: str, arguments: Optional[Dict[str, str]] = None) -> Optional[Dict]:
    """Render a prompt template with the given arguments.

    Returns a dict with 'description' and 'messages' (list of role/content pairs)
    suitable for LLM consumption, or None if the prompt name is unknown.
    """
    arguments = arguments or {}

    if name == "security-analysis":
        return _render_security_analysis(arguments)
    elif name == "agent-evaluation":
        return _render_agent_evaluation(arguments)

    return None


def _render_security_analysis(args: Dict[str, str]) -> Dict:
    """Render the security-analysis prompt."""
    tx_hash = args.get("transaction_hash", "")
    contract_addr = args.get("contract_address", "")

    target_description = ""
    tool_calls = []

    if contract_addr:
        target_description += f"Contract: {contract_addr}\n"
        tool_calls.append(
            f'1. Use the `scan_contract` tool with address="{contract_addr}" to get the risk score.\n'
            f'2. Use the `check_deployer` tool with address="{contract_addr}" to check deployer history.'
        )
    if tx_hash:
        target_description += f"Transaction: {tx_hash}\n"
        tool_calls.append(
            f'3. If you have the transaction details, use `simulate_transaction` to check for hidden asset changes.'
        )

    if not target_description:
        target_description = "No specific target provided. Ask the user for a contract address or transaction hash."

    user_content = (
        f"Perform a comprehensive security analysis on the following target:\n\n"
        f"{target_description}\n"
        f"Steps:\n"
        f"{''.join(tool_calls) if tool_calls else 'Ask the user to provide a contract address or transaction hash.'}\n\n"
        f"After gathering data, provide:\n"
        f"- Overall risk verdict (SAFE / CAUTION / DANGER)\n"
        f"- Key risk flags identified\n"
        f"- Deployer reputation assessment\n"
        f"- Recommended action for the user"
    )

    return {
        "description": "Comprehensive security analysis of a contract or transaction",
        "messages": [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": user_content,
                },
            },
        ],
    }


def _render_agent_evaluation(args: Dict[str, str]) -> Dict:
    """Render the agent-evaluation prompt."""
    agent_id = args.get("agent_id", "unknown")

    user_content = (
        f"Evaluate the trustworthiness and behavior of agent '{agent_id}' using ShieldBot data.\n\n"
        f"Steps:\n"
        f'1. Use `check_agent_reputation` with agent_id="{agent_id}" to get trust score and history.\n'
        f'2. Read the resource `shieldbot://agent/{agent_id}/health` for policy details and recent verdicts.\n\n'
        f"After gathering data, provide:\n"
        f"- Trust score assessment (what does the score mean?)\n"
        f"- Block rate analysis (is this agent frequently hitting risky contracts?)\n"
        f"- Policy configuration review (is the policy too permissive or too strict?)\n"
        f"- Recommendation: should other agents/users trust this agent?"
    )

    return {
        "description": f"Evaluate trustworthiness of agent {agent_id}",
        "messages": [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": user_content,
                },
            },
        ],
    }
