"""
Transaction Calldata Decoder
Decodes function selectors and parameters from raw transaction calldata
"""

import logging
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Known function selectors (first 4 bytes of keccak256 hash)
KNOWN_SELECTORS: Dict[str, Dict] = {
    # Token approvals (high risk)
    "095ea7b3": {
        "name": "approve",
        "signature": "approve(address,uint256)",
        "params": ["address", "uint256"],
        "category": "approval",
        "risk": "high",
    },
    "a22cb465": {
        "name": "setApprovalForAll",
        "signature": "setApprovalForAll(address,bool)",
        "params": ["address", "bool"],
        "category": "approval",
        "risk": "critical",
    },
    "39509351": {
        "name": "increaseAllowance",
        "signature": "increaseAllowance(address,uint256)",
        "params": ["address", "uint256"],
        "category": "approval",
        "risk": "high",
    },
    # Token transfers
    "a9059cbb": {
        "name": "transfer",
        "signature": "transfer(address,uint256)",
        "params": ["address", "uint256"],
        "category": "transfer",
        "risk": "medium",
    },
    "23b872dd": {
        "name": "transferFrom",
        "signature": "transferFrom(address,address,uint256)",
        "params": ["address", "address", "uint256"],
        "category": "transfer",
        "risk": "medium",
    },
    # DEX swaps
    "38ed1739": {
        "name": "swapExactTokensForTokens",
        "signature": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
        "params": ["uint256", "uint256", "address[]", "address", "uint256"],
        "category": "swap",
        "risk": "low",
    },
    "7ff36ab5": {
        "name": "swapExactETHForTokens",
        "signature": "swapExactETHForTokens(uint256,address[],address,uint256)",
        "params": ["uint256", "address[]", "address", "uint256"],
        "category": "swap",
        "risk": "low",
    },
    "18cbafe5": {
        "name": "swapExactTokensForETH",
        "signature": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
        "params": ["uint256", "uint256", "address[]", "address", "uint256"],
        "category": "swap",
        "risk": "low",
    },
    "5c11d795": {
        "name": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
        "signature": "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
        "params": ["uint256", "uint256", "address[]", "address", "uint256"],
        "category": "swap",
        "risk": "low",
    },
    "fb3bdb41": {
        "name": "swapETHForExactTokens",
        "signature": "swapETHForExactTokens(uint256,address[],address,uint256)",
        "params": ["uint256", "address[]", "address", "uint256"],
        "category": "swap",
        "risk": "low",
    },
    # Liquidity
    "e8e33700": {
        "name": "addLiquidity",
        "signature": "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
        "params": ["address", "address", "uint256", "uint256", "uint256", "uint256", "address", "uint256"],
        "category": "liquidity",
        "risk": "low",
    },
    "baa2abde": {
        "name": "removeLiquidity",
        "signature": "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
        "params": ["address", "address", "uint256", "uint256", "uint256", "address", "uint256"],
        "category": "liquidity",
        "risk": "low",
    },
    # Mint / Burn
    "40c10f19": {
        "name": "mint",
        "signature": "mint(address,uint256)",
        "params": ["address", "uint256"],
        "category": "supply",
        "risk": "high",
    },
    "42966c68": {
        "name": "burn",
        "signature": "burn(uint256)",
        "params": ["uint256"],
        "category": "supply",
        "risk": "medium",
    },
    # Claim patterns (often used in phishing)
    "4e71d92d": {
        "name": "claim",
        "signature": "claim()",
        "params": [],
        "category": "claim",
        "risk": "medium",
    },
    "aad3ec96": {
        "name": "claim",
        "signature": "claim(address,uint256)",
        "params": ["address", "uint256"],
        "category": "claim",
        "risk": "medium",
    },
}

# Whitelisted routers on BSC — transactions to these are lower risk
WHITELISTED_ROUTERS: Dict[str, str] = {
    # PancakeSwap
    "0x10ED43C718714eb63d5aA57B78B54704E256024E".lower(): "PancakeSwap V2 Router",
    "0x13f4EA83D0bd40E75C8222255bc855a974568Dd4".lower(): "PancakeSwap V3 Smart Router",
    "0x1a0A18AC4BECDdbd6389559687d1A73d8927E416".lower(): "PancakeSwap Universal Router",
    "0xd9C500DfF816a1Da21A48A732d3498Bf09dc9AEB".lower(): "PancakeSwap Universal Router 2",
    # 1inch
    "0x1111111254EEB25477B68fb85Ed929f73A960582".lower(): "1inch V5 Router",
    "0x111111125421cA6dc452d289314280a0f8842A65".lower(): "1inch V6 Router",
}

# Max uint256 — used to detect unlimited approvals
MAX_UINT256 = (1 << 256) - 1
# Threshold: anything above 10^30 is effectively unlimited
UNLIMITED_THRESHOLD = 10**30


class CalldataDecoder:
    """Decode raw transaction calldata into human-readable form."""

    def decode(self, calldata: str) -> Dict:
        """
        Decode calldata and return structured info.

        Args:
            calldata: Hex string of transaction data (with or without 0x prefix)

        Returns:
            dict with keys: selector, function_name, signature, category, risk,
                            params, is_approval, is_unlimited_approval, raw
        """
        if not calldata or calldata in ("0x", "0X", ""):
            return {
                "selector": None,
                "function_name": "Native Transfer",
                "signature": None,
                "category": "transfer",
                "risk": "low",
                "params": {},
                "is_approval": False,
                "is_unlimited_approval": False,
                "raw": calldata or "0x",
            }

        data = calldata[2:] if calldata.startswith("0x") else calldata
        if len(data) < 8:
            return {
                "selector": data,
                "function_name": "Unknown (truncated)",
                "signature": None,
                "category": "unknown",
                "risk": "high",
                "params": {},
                "is_approval": False,
                "is_unlimited_approval": False,
                "raw": calldata,
            }

        selector = data[:8].lower()
        params_hex = data[8:]

        known = KNOWN_SELECTORS.get(selector)

        if known:
            decoded_params = self._decode_params(known["params"], params_hex)
            is_approval = known["category"] == "approval"
            is_unlimited = False

            if is_approval and "uint256" in known["params"]:
                idx = known["params"].index("uint256")
                amount = decoded_params.get(f"param_{idx}")
                if amount is not None and amount >= UNLIMITED_THRESHOLD:
                    is_unlimited = True

            # Check for disguised calls
            disguised = self._check_disguised(selector, known)

            result = {
                "selector": selector,
                "function_name": known["name"],
                "signature": known["signature"],
                "category": known["category"],
                "risk": known["risk"],
                "params": decoded_params,
                "is_approval": is_approval,
                "is_unlimited_approval": is_unlimited,
                "raw": calldata,
            }

            if disguised:
                result["disguised_warning"] = disguised

            return result
        else:
            return {
                "selector": selector,
                "function_name": f"Unknown (0x{selector})",
                "signature": None,
                "category": "unknown",
                "risk": "high",
                "params": self._extract_raw_params(params_hex),
                "is_approval": False,
                "is_unlimited_approval": False,
                "raw": calldata,
            }

    def is_whitelisted_target(self, to_address: str, chain_id: int = 56) -> Optional[str]:
        """
        Check if the target address is a whitelisted router.

        Args:
            to_address: Target contract address.
            chain_id: Chain ID to check against. Currently only BSC (56) has
                      a router list; other chains return None.

        Returns:
            Router name if whitelisted, None otherwise.
        """
        if not to_address:
            return None
        # For now, all whitelisted routers are BSC. Future adapters will
        # register their own routers via chain_adapter.get_whitelisted_routers().
        if chain_id != 56:
            return None
        return WHITELISTED_ROUTERS.get(to_address.lower())

    def _decode_params(self, param_types: list, params_hex: str) -> Dict:
        """Decode ABI-encoded parameters (simplified — handles address and uint256)."""
        decoded = {}
        offset = 0

        for i, ptype in enumerate(param_types):
            chunk = params_hex[offset:offset + 64]
            if len(chunk) < 64:
                break

            if ptype == "address":
                decoded[f"param_{i}"] = "0x" + chunk[24:]
            elif ptype == "uint256":
                try:
                    decoded[f"param_{i}"] = int(chunk, 16)
                except ValueError:
                    decoded[f"param_{i}"] = chunk
            elif ptype == "bool":
                decoded[f"param_{i}"] = int(chunk, 16) != 0
            else:
                decoded[f"param_{i}"] = chunk

            offset += 64

        return decoded

    def _extract_raw_params(self, params_hex: str) -> Dict:
        """Extract raw 32-byte words from unknown calldata."""
        params = {}
        for i in range(0, min(len(params_hex), 64 * 8), 64):
            chunk = params_hex[i:i + 64]
            if len(chunk) == 64:
                params[f"word_{i // 64}"] = chunk
        return params

    def _check_disguised(self, selector: str, known: Dict) -> Optional[str]:
        """
        Detect if a function name seems benign but the selector matches
        a dangerous operation. Returns warning string or None.
        """
        # Known disguised patterns: a function named claimReward / claimAirdrop
        # but with a selector that actually matches transferFrom or approve
        dangerous_selectors = {"23b872dd", "095ea7b3", "a22cb465"}
        benign_names = {"claim", "claimReward", "claimAirdrop", "getReward", "withdraw"}

        if selector in dangerous_selectors and known["name"] in benign_names:
            return (
                f"Function named '{known['name']}' has selector 0x{selector} "
                f"which matches '{KNOWN_SELECTORS[selector]['signature']}' — possible disguised call"
            )
        return None


def format_approval_summary(decoded: Dict, token_symbol: str = "tokens") -> str:
    """Format a human-readable summary of an approval transaction."""
    if not decoded.get("is_approval"):
        return ""

    spender = decoded["params"].get("param_0", "Unknown")
    if decoded["is_unlimited_approval"]:
        return f"UNLIMITED {token_symbol} approval to {spender}"

    amount = decoded["params"].get("param_1", "Unknown")
    if isinstance(amount, int):
        return f"Approving {amount} {token_symbol} to {spender}"

    return f"Approval to {spender}"
