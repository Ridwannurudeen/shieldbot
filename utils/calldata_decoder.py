"""
Transaction Calldata Decoder
Decodes function selectors and parameters from raw transaction calldata
"""

import logging
from typing import Dict, List, Optional, Tuple

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
    # Universal Router (PancakeSwap / Uniswap)
    "3593564c": {
        "name": "execute",
        "signature": "execute(bytes,bytes[],uint256)",
        "params": ["bytes", "bytes[]", "uint256"],
        "category": "swap",
        "risk": "low",
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
        "signature": "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
        "params": ["address"],
        "category": "approval",
        "risk": "high",
    },
    "2a2d80d1": {
        "name": "permit (Permit2 batch)",
        "signature": "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)",
        "params": ["address"],
        "category": "approval",
        "risk": "high",
    },
    "30f28b7a": {
        "name": "permitTransferFrom (Permit2)",
        "signature": "permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)",
        "params": ["address"],
        "category": "approval",
        "risk": "high",
    },
    "edd9444b": {
        "name": "permitTransferFrom (Permit2 batch)",
        "signature": "permitTransferFrom(((address,uint256)[],uint256,uint256),(address,uint256)[],address,bytes)",
        "params": [],
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

# Universal Router command numbers (Uniswap universal-router Commands.sol; PancakeSwap's routers are
# forks that share 0x00 to 0x0e). The top bit only lets a command revert. Routers read a command through
# different masks (Uniswap V2.1 0x7f, PancakeSwap 0x3f, Uniswap V1.2 0x1f): every command accepted here
# reads the same through all three, and one with any other bit set is refused.
UR_COMMAND_MASK = 0x7F
UR_V3_SWAPS = (0x00, 0x01)
UR_V2_SWAPS = (0x08, 0x09)
UR_V2_SWAP_EXACT_IN = 0x08
UR_EXACT_IN_SWAPS = (0x00, 0x08)
UR_V4_SWAP = 0x10
# Commands that move funds to the address in the given word of their input: PERMIT2_TRANSFER_FROM,
# SWEEP, TRANSFER, WRAP_ETH and UNWRAP_WETH.
UR_RECIPIENT_WORD = {0x02: 1, 0x04: 1, 0x05: 1, 0x0B: 0, 0x0C: 0}
UR_PAY_PORTION, UR_PAY_PORTION_FULL_PRECISION = 0x06, 0x07
UR_PERMIT2_PERMIT = 0x0A
UR_BALANCE_CHECK_ERC20 = 0x0E
# Recipients that keep funds with the caller: the sender, or the router between commands.
UR_MSG_SENDER = "0x" + "0" * 39 + "1"
UR_ADDRESS_THIS = "0x" + "0" * 39 + "2"
# Shares paid to other addresses (an interface fee) may reach 1% in all: 1e16 where 1e18 is the whole,
# as PAY_PORTION_FULL_PRECISION counts. PAY_PORTION counts basis points, 1e14 each.
UR_MAX_FOREIGN_PORTION = 10**16
# The actions the V4 router runs (v4-periphery V4Router._handleAction; any other reverts): the swaps that
# name the currencies, those that move no funds to a named address (SETTLE, SETTLE_ALL, TAKE_ALL), and
# those that move funds to the address in the given word of their params (TAKE, TAKE_PORTION).
V4_SWAP_ACTIONS = (0x06, 0x07, 0x08, 0x09)
V4_PLAIN_ACTIONS = (0x0B, 0x0C, 0x0F)
V4_RECIPIENT_WORD = {0x0E: 1, 0x10: 1}
V4_TAKE = 0x0E


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

    def decode_universal_router_path(
        self, calldata: str, sender: str = "", router: str = "", v4: bool = False
    ) -> Tuple[List[str], Optional[str], List[Tuple[str, str, str]]]:
        """
        Decode the tokens a Universal Router execute(bytes,bytes[],uint256) call swaps, and check that it
        sends nothing to anyone but `sender`.

        The Universal Router encodes swap instructions as:
          commands: packed bytes where each byte is a command type
          inputs:   bytes[] where inputs[i] is the ABI-encoded params for commands[i]

        V2 commands (0x08 / 0x09) encode the path as address[].
        V3 commands (0x00 / 0x01) encode the path as packed bytes (token+fee+token...).
        V4_SWAP (0x10) encodes the V4 router's actions and their params (_decode_v4_ur_input); `v4` says
        the router is a Uniswap Universal Router V2 or later, as older routers and PancakeSwap's use
        0x10 for other commands.

        Every command must be one checked here: a swap, a sweep, transfer, wrap or unwrap whose
        recipient is the sender or the router itself, portions of up to 1% in all paid to anyone, a
        Permit2 permit for the router itself, or a balance check. Anything else, a sub-plan or a bridge
        deposit among them, is refused, and so is a swap whose tokens cannot be read.

        One exception is Uniswap's mixed route: an exact-in swap, or a V4 TAKE, may pay its output to the
        pool the next command swaps from (_next_v2_path). The decoder cannot tell a pool from any other
        address, so it returns each such (pool, token_a, token_b) for the caller to confirm is the
        router's V2 pool for them.

        Returns (the tokens of every swap command, each once, in the order the commands name them,
        None, the pools to confirm), or ([], why the call was refused, []).
        """
        undecodable = "Token path could not be decoded"
        try:
            data = calldata[2:] if calldata.startswith("0x") else calldata
            if len(data) < 8 or data[:8].lower() != "3593564c":
                return [], undecodable, []

            params = data[8:].lower()
            words = [params[i:i + 64] for i in range(0, len(params), 64)]
            if len(words) < 3:
                return [], undecodable, []

            # words[0] = byte offset from params start → commands length word
            # words[1] = byte offset from params start → inputs count word
            # words[2] = deadline
            ptr_cmds = int(words[0], 16) // 32
            ptr_inputs = int(words[1], 16) // 32

            if ptr_cmds >= len(words) or ptr_inputs >= len(words):
                return [], undecodable, []

            # --- Decode commands bytes ---
            cmds_len = int(words[ptr_cmds], 16)
            if cmds_len == 0:
                return [], undecodable, []
            cmds_words = (cmds_len + 31) // 32
            cmds_hex = "".join(words[ptr_cmds + 1: ptr_cmds + 1 + cmds_words])
            if len(cmds_hex) < cmds_len * 2:
                return [], undecodable, []
            commands = bytes.fromhex(cmds_hex[:cmds_len * 2])

            # ABI bytes[] encoding: [count][offset_0 ... offset_n][elem_0_len][elem_0_data]...
            inputs_count = int(words[ptr_inputs], 16)
            if inputs_count < len(commands):
                return [], undecodable, []
            own = {UR_MSG_SENDER, UR_ADDRESS_THIS, sender.lower()} - {""}
            path: List[str] = []
            pools: List[Tuple[str, str, str]] = []
            foreign_share = 0
            for i, byte in enumerate(commands):
                cmd = byte & UR_COMMAND_MASK
                elem_hex = self._abi_bytes_element(words, ptr_inputs + 1, i)
                iw = [elem_hex[j:j + 64] for j in range(0, len(elem_hex), 64)]
                if cmd in UR_V2_SWAPS or cmd in UR_V3_SWAPS:
                    decode = self._decode_v3_ur_input if cmd in UR_V3_SWAPS else self._decode_v2_ur_input
                    tokens = decode(elem_hex)
                    if not tokens:
                        return [], undecodable, []
                    recipient = "0x" + iw[0][24:]
                    if recipient not in own:
                        next_path = self._next_v2_path(words, ptr_inputs, commands, i) if cmd in UR_EXACT_IN_SWAPS else []
                        if len(next_path) < 2 or next_path[0] != tokens[-1].lower():
                            return [], f"Its funds go to {recipient}, not the sender", []
                        pools.append((recipient, next_path[0], next_path[1]))
                    path += tokens
                elif cmd == UR_V4_SWAP and v4:
                    next_path = self._next_v2_path(words, ptr_inputs, commands, i)
                    tokens, refusal, v4_pools = self._decode_v4_ur_input(elem_hex, own, next_path)
                    if refusal:
                        return [], refusal, []
                    if not tokens:
                        return [], undecodable, []
                    path += tokens
                    pools += v4_pools
                elif cmd in UR_RECIPIENT_WORD:
                    recipient = "0x" + iw[UR_RECIPIENT_WORD[cmd]][24:]
                    if recipient not in own:
                        return [], f"Its funds go to {recipient}, not the sender", []
                elif cmd in (UR_PAY_PORTION, UR_PAY_PORTION_FULL_PRECISION):
                    recipient = "0x" + iw[1][24:]
                    if recipient not in own:
                        foreign_share += int(iw[2], 16) * (10**14 if cmd == UR_PAY_PORTION else 1)
                        if foreign_share > UR_MAX_FOREIGN_PORTION:
                            return [], f"It pays more than 1% of its tokens to other addresses, {recipient} among them", []
                elif cmd == UR_PERMIT2_PERMIT:
                    # abi.encode(PermitSingle(PermitDetails(token, amount, expiration, nonce), spender,
                    # sigDeadline), bytes signature): the spender is the fifth word.
                    spender = "0x" + iw[4][24:]
                    if spender != router.lower():
                        return [], f"Its Permit2 permit is for {spender}, not the router", []
                elif cmd != UR_BALANCE_CHECK_ERC20:
                    return [], f"It runs router command 0x{cmd:02x}, which ShieldBot does not check", []
            if not path:
                return [], undecodable, []
            return list(dict.fromkeys(token.lower() for token in path)), None, pools

        except Exception:
            return [], undecodable, []

    def _next_v2_path(self, words: List[str], ptr_inputs: int, commands: bytes, index: int) -> List[str]:
        """The lowercase path of the command after `index` when it is a V2_SWAP_EXACT_IN that may not
        revert, else [].

        Command `index` is the first leg of Uniswap's mixed route when it pays its output token, the
        path's first, straight to the pool that command swaps from. The router swaps all its V2 factory's
        pool for the path's first two tokens holds beyond its reserves, with whatever the command's
        amountIn adds, and pays it to that command's recipient, which is checked like any other.
        """
        if index + 1 >= len(commands) or commands[index + 1] != UR_V2_SWAP_EXACT_IN:
            return []
        return [
            token.lower()
            for token in self._decode_v2_ur_input(self._abi_bytes_element(words, ptr_inputs + 1, index + 1))
        ]

    @staticmethod
    def _abi_bytes_element(words: List[str], first_offset_word: int, index: int) -> str:
        """Hex of element `index` of an ABI bytes[] whose offset words start at `first_offset_word`.

        Each offset counts bytes from the first offset word, not from the count word before it.
        """
        start = first_offset_word + int(words[first_offset_word + index], 16) // 32
        length = int(words[start], 16)
        return "".join(words[start + 1: start + 1 + (length + 31) // 32])[:length * 2]

    def _decode_v2_ur_input(self, input_hex: str) -> List[str]:
        """
        Decode address[] path from V2_SWAP_EXACT_IN/OUT input:
          abi.encode(address recipient, uint256 amountIn, uint256 amountOutMin,
                     address[] path, bool payerIsUser)
        """
        try:
            iw = [input_hex[i:i + 64] for i in range(0, len(input_hex), 64)]
            if len(iw) < 5:
                return []
            # iw[3] = byte offset to address[] from start of iw
            path_word = int(iw[3], 16) // 32
            if path_word >= len(iw):
                return []
            path_len = int(iw[path_word], 16)
            addrs = []
            for j in range(path_len):
                idx = path_word + 1 + j
                if idx >= len(iw):
                    break
                addrs.append("0x" + iw[idx][24:])
            return addrs
        except Exception:
            return []

    def _decode_v3_ur_input(self, input_hex: str) -> List[str]:
        """
        Decode packed bytes path from V3_SWAP_EXACT_IN/OUT input:
          abi.encode(address recipient, uint256 amountIn, uint256 amountOutMin,
                     bytes path, bool payerIsUser)
        V3 path packing: tokenIn(20B) + fee(3B) + tokenMid*(20B+3B) + tokenOut(20B)
        """
        try:
            iw = [input_hex[i:i + 64] for i in range(0, len(input_hex), 64)]
            if len(iw) < 5:
                return []
            # iw[3] = byte offset to bytes path from start of iw
            path_word = int(iw[3], 16) // 32
            if path_word >= len(iw):
                return []
            path_len_bytes = int(iw[path_word], 16)
            path_words = (path_len_bytes + 31) // 32
            path_hex = "".join(iw[path_word + 1: path_word + 1 + path_words])
            path_hex = path_hex[:path_len_bytes * 2]

            # Minimum single-hop path: 20 + 3 + 20 = 43 bytes = 86 hex chars
            if len(path_hex) < 86:
                return []

            addrs = []
            pos = 0
            while pos + 40 <= len(path_hex):
                addrs.append("0x" + path_hex[pos:pos + 40])
                pos += 40
                if pos + 6 <= len(path_hex):
                    pos += 6  # skip 3-byte fee tier
                else:
                    break
            return addrs if len(addrs) >= 2 else []
        except Exception:
            return []

    def _decode_v4_ur_input(
        self, input_hex: str, own: set, next_path: List[str]
    ) -> Tuple[List[str], Optional[str], List[Tuple[str, str, str]]]:
        """
        Decode the tokens of a V4_SWAP input: abi.encode(bytes actions, bytes[] params), the V4 router's
        actions (v4-periphery Actions) and the ABI-encoded params of each.

        A swap's params struct holds dynamic fields, so it starts with the offset of its struct:
          SWAP_EXACT_IN_SINGLE / SWAP_EXACT_OUT_SINGLE (0x06 / 0x08): (PoolKey poolKey, bool zeroForOne,
            ...), the PoolKey's currency0 and currency1 in its first two words;
          SWAP_EXACT_IN (0x07): (Currency currencyIn, PathKey[] path, ...), each PathKey's first word its
            intermediate currency, in swap order;
          SWAP_EXACT_OUT (0x09): (Currency currencyOut, PathKey[] path, ...), the path read from the input
            currency to the one before currencyOut.
        TAKE and TAKE_PORTION pay the address in their params, which must be one of `own`, except that a
        TAKE of `next_path`'s first currency may pay the pool the next command swaps from
        (_next_v2_path), returned for the caller to confirm; SETTLE, SETTLE_ALL and TAKE_ALL pay no one
        else. Any other action, which the V4 router does not run, is refused.
        Native ETH (address 0) is not a token and is left out.

        Returns (the tokens, None, the pools to confirm), ([], None, []) when no swap action is read, or
        ([], why it was refused, []).
        """
        try:
            iw = [input_hex[i:i + 64] for i in range(0, len(input_hex), 64)]
            ptr_actions = int(iw[0], 16) // 32
            ptr_params = int(iw[1], 16) // 32
            actions_len = int(iw[ptr_actions], 16)
            actions = bytes.fromhex(
                "".join(iw[ptr_actions + 1: ptr_actions + 1 + (actions_len + 31) // 32])[:actions_len * 2]
            )
            if int(iw[ptr_params], 16) < len(actions):
                return [], None, []

            currencies: List[str] = []
            pools: List[Tuple[str, str, str]] = []
            for i, action in enumerate(actions):
                if action in V4_PLAIN_ACTIONS:
                    continue
                param_hex = self._abi_bytes_element(iw, ptr_params + 1, i)
                pw = [param_hex[j:j + 64] for j in range(0, len(param_hex), 64)]
                if action in V4_RECIPIENT_WORD:
                    recipient = "0x" + pw[V4_RECIPIENT_WORD[action]][24:]
                    if recipient not in own:
                        currency = "0x" + pw[0][24:]
                        if action != V4_TAKE or len(next_path) < 2 or next_path[0] != currency:
                            return [], f"Its funds go to {recipient}, not the sender", []
                        pools.append((recipient, next_path[0], next_path[1]))
                    continue
                if action not in V4_SWAP_ACTIONS:
                    return [], f"It runs V4 action 0x{action:02x}, which ShieldBot does not check", []
                base = int(pw[0], 16) // 32
                if action in (0x06, 0x08):
                    currency0, currency1 = "0x" + pw[base][24:], "0x" + pw[base + 1][24:]
                    zero_for_one = int(pw[base + 5], 16) == 1
                    currencies += [currency0, currency1] if zero_for_one else [currency1, currency0]
                else:
                    head = "0x" + pw[base][24:]
                    path_word = base + int(pw[base + 1], 16) // 32
                    hops = [
                        "0x" + pw[path_word + 1 + int(pw[path_word + 1 + j], 16) // 32][24:]
                        for j in range(int(pw[path_word], 16))
                    ]
                    currencies += [head, *hops] if action == 0x07 else [*hops, head]
            return [currency for currency in currencies if int(currency, 16) != 0], None, pools
        except Exception:
            return [], None, []

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


# --- Dynamic Selector Resolution via OpenChain API ---
import time
import aiohttp

_selector_cache: Dict[str, tuple] = {}  # selector -> (function_name | None, timestamp)
_SELECTOR_CACHE_TTL = 86400  # 24h — selectors never change
_SELECTOR_CACHE_MAX = 5000


async def resolve_selector(selector: str) -> Optional[str]:
    """
    Resolve an unknown function selector to its name via OpenChain API.
    Returns the function name (e.g. "transferTo") or None.
    Results are cached for 24h. Failures cached as None to avoid repeated lookups.
    """
    if not selector or len(selector) != 8:
        return None

    sel_lower = selector.lower()

    # Check cache
    cached = _selector_cache.get(sel_lower)
    if cached and (time.time() - cached[1]) < _SELECTOR_CACHE_TTL:
        return cached[0]

    resolved_name = None
    try:
        url = f"https://api.openchain.xyz/signature-database/v1/lookup?function=0x{sel_lower}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = data.get("result", {}).get("function", {}).get(f"0x{sel_lower}", [])
                    if results and len(results) > 0:
                        full_sig = results[0].get("name", "")
                        # Extract just the function name from "transferTo(address,bytes)"
                        resolved_name = full_sig.split("(")[0] if full_sig else None
    except Exception:
        pass  # Never block the response — cache None on failure

    # Cache result (even None to avoid repeated failed lookups)
    if len(_selector_cache) >= _SELECTOR_CACHE_MAX:
        oldest_key = min(_selector_cache, key=lambda k: _selector_cache[k][1])
        del _selector_cache[oldest_key]
    _selector_cache[sel_lower] = (resolved_name, time.time())

    return resolved_name
