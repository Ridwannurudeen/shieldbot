"""Buy-then-sell simulation for Robinhood Chain (4663) tokens over eth_simulateV1.

Every selector, command byte, action id and struct layout here comes from contracts verified on
Sourcify for chain 4663 and was exercised by live eth_simulateV1 runs:
- Universal Router 0x8876...0904: Commands.sol, Dispatcher.sol and the bundled v4-periphery V4Router,
  whose ExactInputSingleParams/ExactOutputSingleParams carry minHopPriceX36 before hookData.
- PoolManager 0x8366...0951 ABI and v4-core StateLibrary (pools mapping at slot 6).
- Permit2 0x0000...8BA3: IAllowanceTransfer.approve and solmate SafeTransferLib revert strings.
- Uniswap V2 Router02 0x89e5...9eba: swap functions, TransferHelper and UniswapV2Library strings,
  and the IUniswapV2Pair Swap event it bundles.
- Doppler DopplerHookInitializer 0x4e34...a544: the getState(address) public getter.
- Paxos USDG implementation 0x6818...6f8f (behind the EIP-1967 proxy 0x5fc5...d168): the balanceData
  storage layout, confirmed by a live eth_call that read an overridden balance back exactly.
"""

import asyncio
import logging
import re
import secrets
from dataclasses import dataclass
from decimal import Decimal
from typing import Optional

import aiohttp
from cachetools import TTLCache
from eth_abi import decode, encode
from eth_abi.exceptions import DecodingError, EncodingError
from eth_utils import keccak

from adapters.robinhood import (
    PERMIT2_ADDRESS,
    POOL_MANAGER_ADDRESS,
    UNISWAP_V2_FACTORY,
    UNISWAP_V2_ROUTER,
    UNISWAP_V4_UNIVERSAL_ROUTER,
    WETH_ADDRESS,
)

logger = logging.getLogger(__name__)

NATIVE = "0x" + "0" * 40
UNIVERSAL_ROUTER = UNISWAP_V4_UNIVERSAL_ROUTER.lower()
POOL_MANAGER = POOL_MANAGER_ADDRESS.lower()
PERMIT2 = PERMIT2_ADDRESS.lower()
WETH = WETH_ADDRESS.lower()
V2_FACTORY = UNISWAP_V2_FACTORY.lower()
V2_ROUTER = UNISWAP_V2_ROUTER.lower()
DOPPLER_HOOK_INITIALIZER = "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544"
# Paxos USDG keeps balanceData, a mapping(address => TokenAccountData), at slot 1, and TokenAccountData
# packs `uint64 balance` into the lowest 8 bytes, so a stateDiff of that slot funds a buyer with USDG.
USDG = "0x5fc5360d0400a0fd4f2af552add042d716f1d168"
USDG_BALANCE_SLOT = 1
# With traceTransfers, eth_simulateV1 reports native ETH movements as Transfer logs from this address.
NATIVE_TRANSFER_LOG_ADDRESS = "0x" + "e" * 40
LIQUIDITY_LAUNCHER_FEE = 2500
LIQUIDITY_LAUNCHER_TICK_SPACING = 25

MAX_POOLS = 3
LOG_WINDOW_BLOCKS = 10_000
MAX_LOG_WINDOWS = 3
SUPPLY_FRACTION = 1_000_000
BUY_BUDGET_WEI = 10 * 10**18
# 1,000,000 USDG (6 decimals); it must fit TokenAccountData.balance, a uint64.
USDG_BUY_BUDGET = 10**12
BALANCE_OVERRIDE_WEI = 100 * 10**18
# A zero sell output proves a trap only when rounding cannot explain it. Swap math rounds away at
# most a few wei, so after a buy costing at least 1 gwei a zero output means the round trip lost
# over 99.9999999% of its value, which no legitimate fee takes. A cheaper buy (the whole supply
# priced under 0.001 ETH, since the buy is a millionth of it) is a dust or rugged pool: unknown.
MIN_TRAP_COST_WEI = 10**9
# The same bar for a USDG-quoted pool, in USDG base units (6 decimals): after a buy costing at least 1 USDG,
# a zero output means over 99.9999% of the value was lost, which a few units of rounding cannot explain.
USDG_MIN_TRAP_COST = 10**6
RPC_ATTEMPTS = 3
RPC_BACKOFF_SECONDS = 1.0
RPC_TIMEOUT_SECONDS = 30
CACHE_TTL_SECONDS = 60

MAX_UINT256 = 2**256 - 1
MAX_UINT160 = 2**160 - 1
MAX_UINT48 = 2**48 - 1
ROUTES = ("v4-native", "v4-weth", "v4-doppler", "v2")

V4_SWAP = 0x10
SWAP_EXACT_IN_SINGLE = 0x06
SWAP_EXACT_OUT_SINGLE = 0x08
SETTLE = 0x0B
SETTLE_ALL = 0x0C
TAKE_ALL = 0x0F
POOL_KEY = "(address,address,uint24,int24,address)"
SINGLE_SWAP = f"({POOL_KEY},bool,uint128,uint128,uint256,bytes)"
DOPPLER_STATE = ["address", "uint256", "address", "bytes", "uint8", POOL_KEY, "int24"]
POOLS_SLOT = 6

ADDRESS_RE = re.compile(r"0x[0-9a-f]{40}")
HEX_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
QUANTITY_RE = re.compile(r"0x[0-9a-fA-F]+")
TRANSFER_TOPIC = "0x" + keccak(text="Transfer(address,address,uint256)").hex()
SWAP_TOPIC = "0x" + keccak(text="Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)").hex()
# IUniswapV2Pair.Swap(sender, amount0In, amount1In, amount0Out, amount1Out, to), Router02 bundle.
V2_SWAP_TOPIC = "0x" + keccak(text="Swap(address,uint256,uint256,uint256,uint256,address)").hex()
INITIALIZE_TOPIC = (
    "0x"
    + keccak(text="Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)").hex()
)


def _selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


ERROR_STRING = _selector("Error(string)")
PANIC = _selector("Panic(uint256)")
WRAPPED_ERROR = _selector("WrappedError(address,bytes4,bytes,bytes)")
HOOK_CALL_FAILED = _selector("HookCallFailed()")
SWAP_AMOUNT_CANNOT_BE_ZERO = _selector("SwapAmountCannotBeZero()")
KNOWN_ERRORS = {
    _selector(signature): signature.split("(")[0]
    for signature in (
        # Universal Router, Dispatcher, Lock, Payments, Permit2Payments
        "ExecutionFailed(uint256,bytes)",
        "ETHNotAccepted()",
        "TransactionDeadlinePassed()",
        "LengthMismatch()",
        "InvalidEthSender()",
        "InvalidCommandType(uint256)",
        "BalanceTooLow()",
        "ContractLocked()",
        "InsufficientToken()",
        "InsufficientETH()",
        "InvalidPortion()",
        "FromAddressIsNotOwner()",
        # v4-periphery BaseActionsRouter, SafeCallback, CalldataDecoder, DeltaResolver, V4Router
        "InputLengthMismatch()",
        "UnsupportedAction(uint256)",
        "NotPoolManager()",
        "SliceOutOfBounds()",
        "DeltaNotPositive(address)",
        "DeltaNotNegative(address)",
        "InsufficientBalance()",
        "V4TooLittleReceived(uint256,uint256)",
        "V4TooMuchRequested(uint256,uint256)",
        "V4TooLittleReceivedPerHopSingle(uint256,uint256)",
        "V4TooMuchRequestedPerHopSingle(uint256,uint256)",
        "InvalidHopPriceLength()",
        "SafeCastOverflow()",
        # Permit2 AllowanceTransfer
        "AllowanceExpired(uint256)",
        "InsufficientAllowance(uint256)",
        "UnsafeCast()",
        # PoolManager ABI and v4-core Hooks, CurrencyLibrary
        "AlreadyUnlocked()",
        "CurrenciesOutOfOrderOrEqual(address,address)",
        "CurrencyNotSettled()",
        "DelegateCallNotAllowed()",
        "InvalidCaller()",
        "ManagerLocked()",
        "MustClearExactPositiveDelta()",
        "NonzeroNativeValue()",
        "PoolNotInitialized()",
        "ProtocolFeeCurrencySynced()",
        "ProtocolFeeTooLarge(uint24)",
        "SwapAmountCannotBeZero()",
        "TickSpacingTooLarge(int24)",
        "TickSpacingTooSmall(int24)",
        "UnauthorizedDynamicLPFeeUpdate()",
        "HookCallFailed()",
        "InvalidHookResponse()",
        "HookDeltaExceedsSwapAmount()",
        "NativeTransferFailed()",
        "ERC20TransferFailed()",
    )
}
# The router's revert when the token refuses transferFrom (Permit2 solmate SafeTransferLib; V2 TransferHelper).
TOKEN_REFUSED = {
    "v4-native": "TRANSFER_FROM_FAILED",
    "v4-weth": "TRANSFER_FROM_FAILED",
    "v4-doppler": "TRANSFER_FROM_FAILED",
    "v2": "TransferHelper: TRANSFER_FROM_FAILED",
}


class SimulationUnavailable(Exception):
    """The RPC could not provide a usable answer; the result is unknown."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Pool:
    route: str
    numeraire: str
    key: Optional[tuple] = None
    pair: Optional[str] = None


def _fresh_address() -> str:
    return "0x" + secrets.token_hex(20)


def _calldata(signature: str, types: list, values: list) -> bytes:
    return _selector(signature) + encode(types, values)


def _call(sender: str, to: str, data: bytes, value: int = 0) -> dict:
    call = {"from": sender, "to": to, "data": "0x" + data.hex()}
    if value:
        call["value"] = hex(value)
    return call


def _pool_id(key: tuple) -> bytes:
    return keccak(encode(["address", "address", "uint24", "int24", "address"], list(key)))


def _pool_label(pool: Pool) -> str:
    return pool.pair if pool.route == "v2" else "0x" + _pool_id(pool.key).hex()


def _universal_router_swap(actions: list, params: list) -> bytes:
    unlock = encode(["bytes", "bytes[]"], [bytes(actions), params])
    return _calldata(
        "execute(bytes,bytes[],uint256)",
        ["bytes", "bytes[]", "uint256"],
        [bytes([V4_SWAP]), [unlock], MAX_UINT256],
    )


def call_labels(pool: Pool) -> list:
    labels = []
    if _pays_token(pool):
        labels = (["fund"] if pool.numeraire == WETH else []) + ["fund_approve", "fund_permit"]
    labels += ["buy", "delivered"]
    if pool.route == "v2":
        return labels + ["pool_before_sell", "approve", "sell", "after_sell", "pool_after_sell", "transfer"]
    return labels + ["approve", "permit", "sell", "after_sell", "transfer"]


def build_simulation_request(
    pool: Pool, token: str, amount: int, buyer: str, receiver: str, sell_amount: Optional[int] = None
) -> dict:
    """Buy exactly `amount` tokens, then sell `sell_amount` of them (default: all of `amount`)."""
    token = token.lower()
    sell_amount = amount if sell_amount is None else sell_amount
    budget = USDG_BUY_BUDGET if pool.numeraire == USDG else BUY_BUDGET_WEI
    if pool.route == "v2":
        spender = V2_ROUTER
        buy = _call(
            buyer,
            V2_ROUTER,
            _calldata(
                "swapETHForExactTokens(uint256,address[],address,uint256)",
                ["uint256", "address[]", "address", "uint256"],
                [amount, [WETH, token], buyer, MAX_UINT256],
            ),
            BUY_BUDGET_WEI,
        )
        sell = _call(
            buyer,
            V2_ROUTER,
            _calldata(
                "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
                ["uint256", "uint256", "address[]", "address", "uint256"],
                [sell_amount, 0, [token, WETH], buyer, MAX_UINT256],
            ),
        )
    else:
        spender = PERMIT2
        token_is_currency0 = pool.key[0] == token
        buy = _call(
            buyer,
            UNIVERSAL_ROUTER,
            _universal_router_swap(
                [SWAP_EXACT_OUT_SINGLE, SETTLE_ALL, TAKE_ALL],
                [
                    encode(
                        [SINGLE_SWAP],
                        [(pool.key, not token_is_currency0, amount, budget, 0, b"")],
                    ),
                    encode(["address", "uint256"], [pool.numeraire, budget]),
                    encode(["address", "uint256"], [token, 0]),
                ],
            ),
            budget if pool.numeraire == NATIVE else 0,
        )
        # SETTLE before the swap so the swap spends exactly what the pool manager received
        # (amountIn 0 = OPEN_DELTA); a fee-on-transfer token then cannot fail with CurrencyNotSettled.
        sell = _call(
            buyer,
            UNIVERSAL_ROUTER,
            _universal_router_swap(
                [SETTLE, SWAP_EXACT_IN_SINGLE, TAKE_ALL],
                [
                    encode(["address", "uint256", "bool"], [token, sell_amount, True]),
                    encode([SINGLE_SWAP], [(pool.key, token_is_currency0, 0, 0, 0, b"")]),
                    encode(["address", "uint256"], [pool.numeraire, 0]),
                ],
            ),
        )

    def balance(account):
        return _call(buyer, token, _calldata("balanceOf(address)", ["address"], [account]))

    def approve(asset, target):
        return _call(
            buyer,
            asset,
            _calldata("approve(address,uint256)", ["address", "uint256"], [target, MAX_UINT256]),
        )

    def permit(asset):
        return _call(
            buyer,
            PERMIT2,
            _calldata(
                "approve(address,address,uint160,uint48)",
                ["address", "address", "uint160", "uint48"],
                [asset, UNIVERSAL_ROUTER, MAX_UINT160, MAX_UINT48],
            ),
        )

    steps = {
        "fund": _call(buyer, WETH, _selector("deposit()"), BUY_BUDGET_WEI),
        "fund_approve": approve(pool.numeraire, PERMIT2),
        "fund_permit": permit(pool.numeraire),
        "buy": buy,
        "delivered": balance(buyer),
        "approve": approve(token, spender),
        "permit": permit(token),
        "sell": sell,
        "after_sell": balance(buyer),
        "transfer": _call(
            buyer,
            token,
            _calldata(
                "transfer(address,uint256)", ["address", "uint256"], [receiver, sell_amount // 2]
            ),
        ),
    }
    if pool.route == "v2":
        steps["pool_before_sell"] = balance(pool.pair)
        steps["pool_after_sell"] = balance(pool.pair)
    overrides = {buyer: {"balance": hex(BALANCE_OVERRIDE_WEI)}}
    if pool.numeraire == USDG:
        slot = keccak(encode(["address", "uint256"], [buyer, USDG_BALANCE_SLOT]))
        overrides[USDG] = {"stateDiff": {"0x" + slot.hex(): "0x" + budget.to_bytes(32, "big").hex()}}
    return {
        "blockStateCalls": [
            {
                "stateOverrides": overrides,
                "calls": [steps[label] for label in call_labels(pool)],
            }
        ],
        "traceTransfers": True,
        "validation": False,
    }


def tax_percent(sent: int, received: int) -> Optional[float]:
    if sent <= 0 or received < 0 or received > sent:
        return None
    return float(round(Decimal(sent - received) * 100 / Decimal(sent), 4))


def _quantity(value) -> Optional[int]:
    if not isinstance(value, str) or not QUANTITY_RE.fullmatch(value):
        return None
    return int(value, 16)


def _hex_bytes(value) -> Optional[bytes]:
    if not isinstance(value, str) or not HEX_RE.fullmatch(value):
        return None
    return bytes.fromhex(value[2:])


def _succeeded(call: dict) -> bool:
    return call.get("status") == "0x1"


def _uint(call: dict) -> Optional[int]:
    data = _hex_bytes(call.get("returnData"))
    if not _succeeded(call) or data is None or len(data) != 32:
        return None
    return int.from_bytes(data, "big")


def _revert_bytes(call: dict) -> bytes:
    error = call.get("error")
    data = _hex_bytes(error.get("data")) if isinstance(error, dict) else None
    return data or b""


def _error_string(data: bytes) -> Optional[str]:
    if data[:4] != ERROR_STRING:
        return None
    try:
        return decode(["string"], data[4:])[0]
    except DecodingError:
        return None


def _wrapped_error(data: bytes) -> Optional[tuple]:
    """Decode v4-core CustomRevert.WrappedError(target, selector, reason, details)."""
    body = data[4:]
    if data[:4] != WRAPPED_ERROR or len(body) < 4 * 32:
        return None

    def dynamic(slot):
        offset = int.from_bytes(body[slot * 32 : slot * 32 + 32], "big")
        if offset + 32 > len(body):
            return None
        length = int.from_bytes(body[offset : offset + 32], "big")
        if offset + 32 + length > len(body):
            return None
        return body[offset + 32 : offset + 32 + length]

    reason, details = dynamic(2), dynamic(3)
    if reason is None or details is None:
        return None
    return "0x" + body[12:32].hex(), body[32:36], reason, details


def _describe_revert(data: bytes) -> str:
    if not data:
        return "empty revert data"
    message = _error_string(data)
    if message is not None:
        return f'Error("{message}")'
    if data[:4] == PANIC and len(data) == 36:
        return f"Panic(0x{int.from_bytes(data[4:], 'big'):x})"
    wrapped = _wrapped_error(data)
    if wrapped is not None:
        return f"WrappedError from {wrapped[0]} ({_describe_revert(wrapped[2])})"
    if data[:4] in KNOWN_ERRORS:
        return KNOWN_ERRORS[data[:4]]
    return f"unrecognized revert data 0x{data[:4].hex()}"


def _sell_trap(pool: Pool, data: bytes) -> Optional[str]:
    """Return why a reverted sell proves holders cannot sell, or None when it is not attributable."""
    message = _error_string(data)
    if message == TOKEN_REFUSED[pool.route]:
        return f'the token refused the transfer to the pool (Error("{message}"))'
    if pool.route == "v2" and message == "UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT":
        return f'the pair received no tokens (Error("{message}"))'
    if pool.route != "v2" and data[:4] == SWAP_AMOUNT_CANNOT_BE_ZERO:
        return "the pool manager was credited no tokens (SwapAmountCannotBeZero)"
    wrapped = _wrapped_error(data)
    if (
        wrapped is not None
        and pool.route != "v2"
        and pool.key[4] != NATIVE
        and wrapped[0] == pool.key[4]
        and wrapped[3][:4] == HOOK_CALL_FAILED
    ):
        return f"pool hook {wrapped[0]} reverted ({_describe_revert(wrapped[2])})"
    return None


def _pays_token(pool: Pool) -> bool:
    return pool.route != "v2" and pool.numeraire != NATIVE


def _sell_output(pool: Pool, logs, buyer: str) -> Optional[int]:
    if not isinstance(logs, list):
        return None
    source = pool.numeraire if _pays_token(pool) else NATIVE_TRANSFER_LOG_ADDRESS
    recipient = "0x" + "0" * 24 + buyer[2:]
    total = 0
    for log in logs:
        topics = log.get("topics") if isinstance(log, dict) else None
        if (
            isinstance(topics, list)
            and len(topics) == 3
            and str(log.get("address", "")).lower() == source
            and str(topics[0]).lower() == TRANSFER_TOPIC
            and str(topics[2]).lower() == recipient
        ):
            value = _hex_bytes(log.get("data"))
            if value is None or len(value) != 32:
                return None
            total += int.from_bytes(value, "big")
    return total


def _pool_swap(pool: Pool, token: str, logs) -> Optional[tuple]:
    """Signed (token, numeraire) amounts of the router's swap with the pool, positive when the router
    received them, from the pool's own Swap event. None unless exactly one such event is present."""
    if not isinstance(logs, list):
        return None
    if pool.route == "v2":
        emitter, prefix, words = pool.pair, [V2_SWAP_TOPIC], 4
    else:
        # Only the router's swap: hook-internal swaps in the same pool have the hook as sender.
        router = "0x" + "0" * 24 + UNIVERSAL_ROUTER[2:]
        emitter, prefix, words = POOL_MANAGER, [SWAP_TOPIC, "0x" + _pool_id(pool.key).hex(), router], 6
    matches = [
        log
        for log in logs
        if isinstance(log, dict)
        and str(log.get("address", "")).lower() == emitter
        and isinstance(log.get("topics"), list)
        and [str(topic).lower() for topic in log["topics"][: len(prefix)]] == prefix
    ]
    data = _hex_bytes(matches[0].get("data")) if len(matches) == 1 else None
    if data is None or len(data) != words * 32:
        return None
    try:
        if pool.route == "v2":
            in0, in1, out0, out1 = decode(["uint256"] * 4, data)
            amount0, amount1, token_is_currency0 = out0 - in0, out1 - in1, token < WETH
        else:
            amount0, amount1 = decode(["int128", "int128"], data[:64])
            token_is_currency0 = pool.key[0] == token
    except DecodingError:
        return None
    return (amount0, amount1) if token_is_currency0 else (amount1, amount0)


def _traces_native_transfers(call: dict) -> bool:
    return any(
        isinstance(log, dict) and str(log.get("address", "")).lower() == NATIVE_TRANSFER_LOG_ADDRESS
        for log in call.get("logs") or []
    )


def _outcome(pool: Pool, reason: str, block: Optional[int] = None) -> dict:
    return {
        "retry_sell_amount": None,
        "route": pool.route,
        "pool": _pool_label(pool),
        "block": block,
        "is_honeypot": None,
        "can_buy": None,
        "can_sell": None,
        "buy_tax": None,
        "sell_tax": None,
        "reason": reason,
    }


def evaluate_simulation(
    pool: Pool, token: str, amount: int, buyer: str, result, sell_amount: Optional[int] = None
) -> dict:
    token = token.lower()
    sell_amount = amount if sell_amount is None else sell_amount
    labels = call_labels(pool)
    block = result[0] if isinstance(result, list) and result and isinstance(result[0], dict) else {}
    calls = block.get("calls")
    number = _quantity(block.get("number"))
    if (
        not isinstance(calls, list)
        or len(calls) != len(labels)
        or not all(isinstance(call, dict) for call in calls)
        or number is None
    ):
        return _outcome(pool, "Malformed eth_simulateV1 result")
    call = dict(zip(labels, calls))
    outcome = _outcome(pool, "", number)
    for label in ("fund", "fund_approve", "fund_permit"):
        if label in call and not _succeeded(call[label]):
            outcome["reason"] = (
                f"WETH funding step {label} reverted: {_describe_revert(_revert_bytes(call[label]))}"
            )
            return outcome
    if not _succeeded(call["buy"]):
        outcome["reason"] = f"buy reverted: {_describe_revert(_revert_bytes(call['buy']))}"
        return outcome
    balances = {
        label: _uint(call[label])
        for label in ("delivered", "pool_before_sell", "after_sell", "pool_after_sell")
        if label in call
    }
    if any(value is None for value in balances.values()):
        outcome["reason"] = "token balance reads failed"
        return outcome
    delivered = balances["delivered"]
    bought = _pool_swap(pool, token, call["buy"].get("logs"))
    if bought is None or bought[0] > amount:
        outcome["reason"] = "Malformed eth_simulateV1 buy logs"
        return outcome
    payout, cost = bought[0], -bought[1]
    if payout < amount:
        # The deployed V4Router never checks that an exact-output swap filled, so a pool too shallow for
        # `amount` pays out less without reverting. That measures the pool, not the token.
        outcome["reason"] = f"pool paid out only {payout} of {amount} token units; too illiquid to size a buy"
        return outcome
    # The pool paid out exactly `amount`, so any shortfall was taken in the token transfer.
    outcome["buy_tax"] = tax_percent(payout, delivered)
    if delivered == 0:
        outcome["can_buy"] = False
        outcome["reason"] = "buy succeeded but delivered no tokens"
        return outcome
    outcome["can_buy"] = True
    if delivered != sell_amount:
        # A transfer-taxed token delivers less than the pool paid out; one sized follow-up can sell
        # exactly that balance. A follow-up that is still short stays unknown.
        if sell_amount == amount and delivered < payout:
            outcome["retry_sell_amount"] = delivered
        outcome["reason"] = (
            f"sell not sizeable in one request: bought {amount} token units but received {delivered}"
        )
        return outcome
    for label in ("approve", "permit"):
        if label in call and not _succeeded(call[label]):
            outcome["reason"] = (
                f"sell {label} reverted: {_describe_revert(_revert_bytes(call[label]))}"
            )
            return outcome
    if not _succeeded(call["sell"]):
        data = _revert_bytes(call["sell"])
        trap = _sell_trap(pool, data)
        transfer = call["transfer"]
        attribution = (
            "a plain transfer of half the tokens to a fresh address succeeded"
            if _succeeded(transfer)
            else f"a plain transfer to a fresh address also reverted ({_describe_revert(_revert_bytes(transfer))})"
        )
        if trap is None:
            outcome["reason"] = (
                f"sell reverted with an unattributed error ({_describe_revert(data)}); {attribution}"
            )
        else:
            outcome.update(
                can_sell=False, is_honeypot=True, reason=f"sell reverted: {trap}; {attribution}"
            )
        return outcome
    if not _pays_token(pool) and not _traces_native_transfers(call["buy"]):
        # The sell output of a native pool is only visible as a traceTransfers log, so without that
        # evidence a sell returning nothing is indistinguishable from an untraced transfer.
        outcome["reason"] = "native transfer tracing unavailable; the sell output cannot be measured"
        return outcome
    output = _sell_output(pool, call["sell"].get("logs"), buyer)
    sold = _pool_swap(pool, token, call["sell"].get("logs"))
    if output is None:
        outcome["reason"] = "Malformed eth_simulateV1 sell logs"
        return outcome
    sent = delivered - balances["after_sell"]
    if pool.route == "v2":
        received = balances["pool_after_sell"] - balances["pool_before_sell"]
    else:
        # Pool hooks can move the token through the PoolManager during the swap, so its balance delta is
        # not the transfer amount; the router's Swap event states exactly what the settle credited.
        received = None if sold is None else -sold[0]
    sell_tax = None if received is None else tax_percent(sent, received)
    if output == 0:
        # Only the sell's own Swap event shows the swap ran. A hook runs after that event and can take
        # the payout, but in a hookless pool nothing sits between the payout and the seller, so a
        # hookless pool must itself have paid nothing; otherwise the trace is missing a transfer.
        hooked = pool.route != "v2" and pool.key[4] != NATIVE
        if sold is None or (not hooked and sold[1] > 0):
            outcome["reason"] = "Malformed eth_simulateV1 sell logs"
            return outcome
        usdg = pool.numeraire == USDG
        if cost < (USDG_MIN_TRAP_COST if usdg else MIN_TRAP_COST_WEI):
            outcome["reason"] = (
                f"sell of {sent} token units returned zero output, but the buy cost only {cost} "
                f"{'USDG units' if usdg else 'wei'}, too little to rule out rounding"
            )
            return outcome
        outcome.update(
            sell_tax=sell_tax,
            can_sell=False,
            is_honeypot=True,
            reason=f"sell of {sent} token units returned zero output",
        )
        return outcome
    outcome.update(
        sell_tax=sell_tax,
        can_sell=True,
        is_honeypot=sell_tax is not None and sell_tax >= 100,
        reason=(
            f"buy and sell succeeded: sold {sent} token units for {output} "
            + {USDG: "USDG units", WETH: "wei WETH"}.get(pool.numeraire, "wei ETH")
            + ("" if sell_tax is not None else "; sell tax unmeasurable")
        ),
    )
    return outcome


def aggregate_outcomes(outcomes: list, notes: list) -> dict:
    """Combine per-pool outcomes worst-case: a proven trap is never masked by a sellable pool."""

    def worst(field):
        values = [outcome[field] for outcome in outcomes if outcome[field] is not None]
        return max(values) if values else None

    def verdict(field, bad):
        values = {outcome[field] for outcome in outcomes}
        if bad in values:
            return bad
        return (not bad) if (not bad) in values else None

    can_sell = verdict("can_sell", False)
    is_honeypot = verdict("is_honeypot", True)
    parts = list(notes)
    for outcome in outcomes:
        where = f" at block {outcome['block']}" if outcome["block"] is not None else ""
        parts.append(f"{outcome['route']} pool {outcome['pool']}{where}: {outcome['reason']}")
    blocks = [outcome["block"] for outcome in outcomes if outcome["block"] is not None]
    return {
        "is_honeypot": is_honeypot,
        "can_buy": verdict("can_buy", False),
        "can_sell": can_sell,
        "buy_tax": worst("buy_tax"),
        "sell_tax": worst("sell_tax"),
        "simulation_block": max(blocks) if blocks else None,
        "reason": "; ".join(parts) or "No simulation result",
    }


def _rate_limited(error) -> bool:
    if not isinstance(error, dict):
        return False
    message = str(error.get("message", "")).lower()
    return (
        error.get("code") in (429, -32005)
        or "rate limit" in message
        or "too many requests" in message
    )


def _call_result(row: dict) -> Optional[bytes]:
    return None if "error" in row else _hex_bytes(row.get("result"))


class RobinhoodSimulator:
    """Runs and caches one buy/sell simulation per token."""

    def __init__(self, rpc_url: str):
        self._rpc_url = rpc_url
        self._cache = TTLCache(maxsize=1024, ttl=CACHE_TTL_SECONDS)
        self._inflight = {}

    async def simulate(self, token: str) -> dict:
        token = token.lower()
        cached = self._cache.get(token)
        if cached is not None:
            return cached
        flight_key = (asyncio.get_running_loop(), token)
        if flight_key not in self._inflight:
            self._inflight[flight_key] = asyncio.create_task(self._simulate(token, flight_key))
        return await asyncio.shield(self._inflight[flight_key])

    async def _simulate(self, token: str, flight_key: tuple) -> dict:
        try:
            result = await self._run(token)
        except SimulationUnavailable as e:
            logger.warning("Robinhood simulation unavailable: %s", type(e).__name__)
            result = aggregate_outcomes([], [e.reason])
        except Exception as e:
            logger.error("Robinhood simulation failed: %s", type(e).__name__)
            result = aggregate_outcomes([], [f"Simulation RPC request failed ({type(e).__name__})"])
        finally:
            self._inflight.pop(flight_key, None)
        self._cache[token] = result
        return result

    async def _run(self, token: str) -> dict:
        if not ADDRESS_RE.fullmatch(token):
            return aggregate_outcomes([], ["Invalid token address"])
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=RPC_TIMEOUT_SECONDS)
        ) as session:
            amount, pools, notes = await self._discover(session, token)
            outcomes = []
            for pool in pools:
                outcome = await self._simulate_pool(session, pool, token, amount)
                if outcome["retry_sell_amount"]:
                    sized = await self._simulate_pool(
                        session, pool, token, amount, outcome["retry_sell_amount"]
                    )
                    # A follow-up that could not run leaves the first attempt's buy verdict standing.
                    outcome = sized if sized["can_buy"] is not None else outcome
                outcomes.append(outcome)
        return aggregate_outcomes(outcomes, notes)

    async def _simulate_pool(
        self, session, pool: Pool, token: str, amount: int, sell_amount: Optional[int] = None
    ) -> dict:
        buyer, receiver = _fresh_address(), _fresh_address()
        try:
            request = build_simulation_request(pool, token, amount, buyer, receiver, sell_amount)
        except EncodingError as e:
            return _outcome(pool, f"Simulation request could not be encoded ({type(e).__name__})")
        try:
            rows = await self._request(session, [("eth_simulateV1", [request, "latest"])])
            error = rows[0].get("error")
            if error is not None:
                code = error.get("code") if isinstance(error, dict) else None
                if code == -32601 or "does not exist" in str(error).lower():
                    raise SimulationUnavailable("eth_simulateV1 unsupported by the RPC")
                raise SimulationUnavailable(f"eth_simulateV1 failed (JSON-RPC error {code})")
            return evaluate_simulation(
                pool, token, amount, buyer, rows[0].get("result"), sell_amount
            )
        except SimulationUnavailable as e:
            return _outcome(pool, e.reason)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning("Robinhood simulation request failed: %s", type(e).__name__)
            return _outcome(pool, f"Simulation RPC request failed ({type(e).__name__})")

    async def _request(self, session, calls: list) -> list:
        """POST one JSON-RPC request or batch; retry HTTP 429 and JSON-RPC rate limits with backoff."""
        body = [
            {"jsonrpc": "2.0", "id": index, "method": method, "params": params}
            for index, (method, params) in enumerate(calls)
        ]
        reason = "RPC rate limited"
        for attempt in range(RPC_ATTEMPTS):
            async with session.post(
                self._rpc_url, json=body if len(body) > 1 else body[0]
            ) as response:
                status = response.status
                payload = await response.json(content_type=None) if status == 200 else None
            if status == 200:
                rows = payload if isinstance(payload, list) else [payload]
                if (
                    len(rows) != len(body)
                    or not all(isinstance(row, dict) for row in rows)
                    or {row.get("id") for row in rows} != set(range(len(body)))
                ):
                    raise SimulationUnavailable("Malformed RPC response")
                if not any(_rate_limited(row.get("error")) for row in rows):
                    by_id = {row["id"]: row for row in rows}
                    return [by_id[index] for index in range(len(body))]
                reason = "RPC rate limited (JSON-RPC rate limit error)"
            elif status == 429:
                reason = "RPC rate limited (HTTP 429)"
            else:
                raise SimulationUnavailable(f"RPC HTTP {status}")
            if attempt < RPC_ATTEMPTS - 1:
                logger.warning(
                    "Robinhood simulation RPC rate limited (attempt %d/%d)",
                    attempt + 1,
                    RPC_ATTEMPTS,
                )
                await asyncio.sleep(RPC_BACKOFF_SECONDS * 2**attempt)
        raise SimulationUnavailable(f"{reason} after {RPC_ATTEMPTS} attempts")

    async def _discover(self, session, token: str) -> tuple:
        """Find at most MAX_POOLS supported pools; notes explain everything skipped."""
        launcher_key = (
            NATIVE,
            token,
            LIQUIDITY_LAUNCHER_FEE,
            LIQUIDITY_LAUNCHER_TICK_SPACING,
            NATIVE,
        )
        slot = keccak(_pool_id(launcher_key) + POOLS_SLOT.to_bytes(32, "big"))
        supply, pair, state, slot0 = (
            _call_result(row)
            for row in await self._request(
                session,
                [
                    (
                        "eth_call",
                        [{"to": token, "data": "0x" + _selector("totalSupply()").hex()}, "latest"],
                    ),
                    (
                        "eth_call",
                        [
                            {
                                "to": V2_FACTORY,
                                "data": "0x"
                                + _calldata(
                                    "getPair(address,address)",
                                    ["address", "address"],
                                    [token, WETH],
                                ).hex(),
                            },
                            "latest",
                        ],
                    ),
                    (
                        "eth_call",
                        [
                            {
                                "to": DOPPLER_HOOK_INITIALIZER,
                                "data": "0x"
                                + _calldata("getState(address)", ["address"], [token]).hex(),
                            },
                            "latest",
                        ],
                    ),
                    (
                        "eth_call",
                        [
                            {
                                "to": POOL_MANAGER,
                                "data": "0x"
                                + _calldata("extsload(bytes32)", ["bytes32"], [slot]).hex(),
                            },
                            "latest",
                        ],
                    ),
                ],
            )
        )
        if supply is None or len(supply) != 32:
            return 0, [], ["totalSupply() unavailable; cannot size a buy"]
        amount = int.from_bytes(supply, "big") // SUPPLY_FRACTION
        if amount == 0:
            return 0, [], ["Token supply too small to size a buy"]
        pools, notes = [], []

        if pair is None or len(pair) != 32:
            notes.append("V2 pair lookup failed")
        elif int.from_bytes(pair, "big"):
            pair_address = "0x" + pair[12:].hex()
            rows = await self._request(
                session,
                [
                    (
                        "eth_call",
                        [
                            {"to": pair_address, "data": "0x" + _selector("getReserves()").hex()},
                            "latest",
                        ],
                    )
                ],
            )
            reserves = _call_result(rows[0])
            if reserves is None or len(reserves) != 96:
                notes.append(f"V2 pair {pair_address} reserves lookup failed")
            elif int.from_bytes(reserves[:32], "big") and int.from_bytes(reserves[32:64], "big"):
                pools.append(Pool("v2", NATIVE, pair=pair_address))
            else:
                notes.append(f"V2 pair {pair_address} has no reserves")

        if state is None:
            notes.append("Doppler pool lookup failed")
        else:
            try:
                numeraire, _, _, _, status, key, _ = decode(DOPPLER_STATE, state)
            except DecodingError:
                status = 0
                notes.append("Doppler pool lookup returned undecodable data")
            if status:
                key = (key[0].lower(), key[1].lower(), key[2], key[3], key[4].lower())
                numeraire = numeraire.lower()
                if key[4] != DOPPLER_HOOK_INITIALIZER or {token, numeraire} != {key[0], key[1]}:
                    notes.append("Doppler pool state is inconsistent with the token")
                elif numeraire in (NATIVE, WETH, USDG):
                    pools.append(Pool("v4-doppler", numeraire, key=key))
                else:
                    notes.append(
                        f"unsupported route: Doppler pool 0x{_pool_id(key).hex()} numeraire {numeraire} "
                        "cannot be funded in one simulation"
                    )

        if slot0 is None or len(slot0) != 32:
            notes.append("LiquidityLauncher pool lookup failed")
        elif int.from_bytes(slot0, "big") & MAX_UINT160:
            pools.append(Pool("v4-native", NATIVE, key=launcher_key))

        if not pools:
            pools = await self._scan_initialize_logs(session, token, notes)
        if not pools:
            notes.append("No supported pool found")
        pools.sort(key=lambda pool: ROUTES.index(pool.route))
        for pool in pools[MAX_POOLS:]:
            notes.append(
                f"{pool.route} pool {_pool_label(pool)} not simulated (cap of {MAX_POOLS} pools)"
            )
        return amount, pools[:MAX_POOLS], notes

    async def _scan_initialize_logs(self, session, token: str, notes: list) -> list:
        rows = await self._request(session, [("eth_blockNumber", [])])
        head = _quantity(rows[0].get("result"))
        if head is None:
            notes.append("Block number unavailable; Initialize logs not scanned")
            return []
        pools, keys, scanned_from = [], set(), head + 1
        for window in range(MAX_LOG_WINDOWS):
            to_block = head - window * LOG_WINDOW_BLOCKS
            if to_block < 0:
                break
            from_block = max(0, to_block - LOG_WINDOW_BLOCKS + 1)
            query = {
                "address": POOL_MANAGER,
                "fromBlock": hex(from_block),
                "toBlock": hex(to_block),
                "topics": [INITIALIZE_TOPIC],
            }
            logs = (await self._request(session, [("eth_getLogs", [query])]))[0].get("result")
            if not isinstance(logs, list):
                notes.append(f"Initialize log lookup failed for blocks {from_block}-{to_block}")
                break
            scanned_from = from_block
            for log in logs:
                pool, note = _pool_from_initialize(log, token)
                if pool is not None and pool.key not in keys:
                    keys.add(pool.key)
                    pools.append(pool)
                elif note is not None:
                    notes.append(note)
            if pools:
                break
        if scanned_from <= head:
            notes.append(f"Initialize logs scanned over blocks {scanned_from}-{head}")
        return pools


def _pool_from_initialize(log, token: str) -> tuple:
    topics = log.get("topics") if isinstance(log, dict) else None
    data = _hex_bytes(log.get("data")) if isinstance(log, dict) else None
    if (
        not isinstance(topics, list)
        or len(topics) != 4
        or str(topics[0]).lower() != INITIALIZE_TOPIC
        or data is None
        or len(data) != 5 * 32
        or not all(isinstance(topic, str) and len(topic) == 66 for topic in topics)
    ):
        return None, None
    currency0, currency1 = ("0x" + topic[-40:].lower() for topic in topics[2:])
    if token not in (currency0, currency1):
        return None, None
    try:
        fee, tick_spacing, hooks, _, _ = decode(
            ["uint24", "int24", "address", "uint160", "int24"], data
        )
    except DecodingError:
        return None, None
    key = (currency0, currency1, fee, tick_spacing, hooks.lower())
    other = currency1 if currency0 == token else currency0
    if key[4] == NATIVE and other in (NATIVE, WETH):
        # A hookless pool needs no extra encoding, and WETH is funded as for a Doppler WETH pool.
        return Pool("v4-native" if other == NATIVE else "v4-weth", other, key=key), None
    if key[4] == DOPPLER_HOOK_INITIALIZER and other in (NATIVE, WETH, USDG):
        return Pool("v4-doppler", other, key=key), None
    return None, (
        f"unsupported route: v4 pool 0x{_pool_id(key).hex()} "
        f"(currencies {currency0}/{currency1}, hooks {key[4]})"
    )
