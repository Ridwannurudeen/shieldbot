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
    # Permit patterns (EIP-2612, Permit2, DAI-style)
    "d505accf": {
        "name": "permit",
        "signature": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "params": ["address", "address", "uint256", "uint256", "uint256"],
        "category": "approval",
        "risk": "high",
    },
    "2b67b570": {
        "name": "permit (Permit2)",
        "signature": "permit(address,((address,uint160,uint48,uint48),address,uint256))",
        "params": ["address"],
        "category": "approval",
        "risk": "high",
    },
    "30f28b7a": {
        "name": "permit (Permit2 batch)",
        "signature": "permit(address,((address,uint160,uint48,uint48)[],address,uint256))",
        "params": ["address"],
        "category": "approval",
        "risk": "high",
    },
    "8fcbaf0c": {
        "name": "permit (DAI-style)",
        "signature": "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
        "params": ["address", "address", "uint256", "uint256", "bool"],
        "category": "approval",
        "risk": "high",
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

            # Check for suspicious parameter patterns
            disguised = self._check_disguised(selector, decoded_params)

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
                "risk": "medium",
                "params": self._extract_raw_params(params_hex),
                "is_approval": False,
                "is_unlimited_approval": False,
                "raw": calldata,
            }

    def is_whitelisted_target(self, to_address: str, chain_id: int = 56, adapter=None) -> Optional[str]:
        """
        Check if the target address is a whitelisted router.

        Args:
            to_address: Target contract address.
            chain_id: Chain ID to check against.
            adapter: Optional chain adapter with get_whitelisted_routers().
                     If provided, uses the adapter's router list for that chain.

        Returns:
            Router name if whitelisted, None otherwise.
        """
        if not to_address:
            return None

        addr_lower = to_address.lower()

        # Use chain adapter's router list if available
        if adapter is not None:
            routers = adapter.get_whitelisted_routers()
            return routers.get(addr_lower)

        # Fallback: BSC hardcoded routers (backward compat)
        if chain_id == 56:
            return WHITELISTED_ROUTERS.get(addr_lower)

        return None

    def _decode_params(self, param_types: list, params_hex: str) -> Dict:
        """Decode ABI-encoded parameters (simplified — handles address, uint256, bool, address[])."""
        decoded: Dict[str, object] = {}

        if not params_hex:
            return decoded

        # Split calldata into 32-byte words
        words = [params_hex[i:i + 64] for i in range(0, len(params_hex), 64)]

        for i, ptype in enumerate(param_types):
            if i >= len(words):
                break

            word = words[i]

            if ptype == "address":
                decoded[f"param_{i}"] = "0x" + word[24:]
            elif ptype == "uint256":
                try:
                    decoded[f"param_{i}"] = int(word, 16)
                except ValueError:
                    decoded[f"param_{i}"] = word
            elif ptype == "bool":
                try:
                    decoded[f"param_{i}"] = int(word, 16) != 0
                except ValueError:
                    decoded[f"param_{i}"] = False
            elif ptype == "address[]":
                # Dynamic array: word is offset (bytes) from start of params
                try:
                    offset_bytes = int(word, 16)
                    if offset_bytes % 32 != 0:
                        raise ValueError("Invalid address[] offset")
                    start = offset_bytes // 32
                    if start >= len(words):
                        raise ValueError("Offset out of range")
                    length = int(words[start], 16)
                    addrs = []
                    for j in range(length):
                        idx = start + 1 + j
                        if idx >= len(words):
                            break
                        addr_word = words[idx]
                        addrs.append("0x" + addr_word[24:])
                    decoded[f"param_{i}"] = addrs
                except Exception:
                    decoded[f"param_{i}"] = []
            else:
                decoded[f"param_{i}"] = word

        return decoded

    def _extract_raw_params(self, params_hex: str) -> Dict:
        """Extract raw 32-byte words from unknown calldata."""
        params = {}
        for i in range(0, min(len(params_hex), 64 * 8), 64):
            chunk = params_hex[i:i + 64]
            if len(chunk) == 64:
                params[f"word_{i // 64}"] = chunk
        return params

    def _check_disguised(self, selector: str, decoded_params: Dict) -> Optional[str]:
        """
        Detect suspicious parameter patterns within known dangerous functions.

        Note: selector-to-name disguising is not detectable from calldata alone
        (the 4-byte selector IS the identity). Instead, we flag suspicious
        parameter values that indicate malicious intent.
        """
        # transferFrom where from == to — self-drain pattern used in phishing
        if selector == "23b872dd":
            frm = decoded_params.get("param_0", "")
            to = decoded_params.get("param_1", "")
            if frm and to and isinstance(frm, str) and isinstance(to, str):
                if frm.lower() == to.lower():
                    return "transferFrom with identical from/to addresses — possible self-drain pattern"

        # approve/increaseAllowance to zero address — invalid and suspicious
        if selector in ("095ea7b3", "39509351"):
            spender = decoded_params.get("param_0", "")
            if isinstance(spender, str) and spender.lower() in (
                "0x0000000000000000000000000000000000000000",
                "0x",
            ):
                return "Approval to zero address — likely invalid or malicious transaction"

        # setApprovalForAll with operator == zero address
        if selector == "a22cb465":
            operator = decoded_params.get("param_0", "")
            if isinstance(operator, str) and operator.lower() == (
                "0x0000000000000000000000000000000000000000"
            ):
                return "setApprovalForAll to zero address — invalid transaction"

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
