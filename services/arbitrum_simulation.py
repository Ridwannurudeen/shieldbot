"""Buy-then-sell simulation for Arbitrum One (42161) tokens over eth_simulateV1.

honeypot.is does not serve Arbitrum One, and GoPlus reports no buy or sell tax for new tokens there, so
no provider said whether an Arbitrum token can be sold and every Arbitrum token scan ended unknown. This
simulates a buy and a sell as services/robinhood_simulation.py does on Robinhood Chain, under the same
rules, whose helpers it reuses: a token is a honeypot only on evidence attributable to it, anything else
leaves the result unknown, and pools are combined worst case (aggregate_outcomes). Unlike there, a trap
is flagged only when one confirmation re-run reproduces it (CONFIRMATION_DELAY_SECONDS).

Every address, struct layout and revert string here was read on 2026-09-29 from the contracts' verified
Arbiscan source and their getters:
- WETH 0x82aF...Bab1.
- Uniswap V3 factory 0x1F98...F984 and its UniswapV3Pool: the Swap event, and 'IIA' when a swap pays the
  pool less than it is owed, which a fee-on-transfer token always does.
- SwapRouter02 0x68b3...Fc45 (factory() the V3 factory, WETH9() the WETH): its ExactInputSingleParams and
  ExactOutputSingleParams carry no deadline, and its TransferHelper reverts 'STF'. Its factoryV2() is
  0x5C69...aA6f, Ethereum's Uniswap V2 factory and not Arbitrum's, so it swaps V3 pools only.
- Uniswap V2 Router02 0x4752...aD24 (factory 0xf1D7...bcf9) and SushiSwap's Router02 0x1b02...7506
  (factory 0xc35D...74C4), both WETH() the WETH: TransferHelper reverts
  'TransferHelper: TRANSFER_FROM_FAILED'.
Sells pay WETH, never native ETH, so every output is an ERC-20 Transfer log and nothing depends on an RPC
tracing native transfers. publicnode's Arbitrum RPC answers eth_simulateV1; Arbitrum's own RPC and drpc
answer "method handler crashed", which leaves the result unknown.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional

import aiohttp
from cachetools import TTLCache
from eth_abi import decode
from eth_abi.exceptions import DecodingError, EncodingError
from eth_utils import keccak

from adapters.robinhood import SIMULATION_PROVIDER
from core.unknown_ledger import unknown_ledger
from services.honeypot_service import SELL_TAX_EXTREME
from services.robinhood_simulation import (
    ADDRESS_RE,
    BALANCE_OVERRIDE_WEI,
    BUY_BUDGET_WEI,
    CACHE_TTL_SECONDS,
    MAX_POOLS,
    MAX_UINT256,
    MIN_TRAP_COST_WEI,
    RPC_ATTEMPTS,
    RPC_BACKOFF_SECONDS,
    RPC_TIMEOUT_SECONDS,
    SUPPLY_FRACTION,
    TRANSFER_TOPIC,
    V2_SWAP_TOPIC,
    SimulationUnavailable,
    _call,
    _call_result,
    _calldata,
    _describe_revert,
    _error_string,
    _fresh_address,
    _hex_bytes,
    _node_error,
    _quantity,
    _rate_limited,
    _revert_bytes,
    _reverted,
    _selector,
    _succeeded,
    _uint,
    aggregate_outcomes,
    tax_percent,
)

logger = logging.getLogger(__name__)

CHAIN_ID = 42161
WETH = "0x82af49447d8a07e3bd95bd0d56f35241523fbab1"
V3_FACTORY = "0x1f98431c8ad98523631ae4a59f267346ea31f984"
SWAP_ROUTER_02 = "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45"
V3_FEES = (100, 500, 3000, 10_000)
# V2 route: (factory, its Router02).
V2_ROUTES = {
    "uniswap-v2": (
        "0xf1d7cc64fb4452f05c498126312ebe29f30fbcf9",
        "0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24",
    ),
    "sushiswap-v2": (
        "0xc35dadb65012ec5796536bd9864ed8773abc74c4",
        "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506",
    ),
}
# UniswapV3Pool.Swap(sender, recipient, amount0, amount1, sqrtPriceX96, liquidity, tick); amounts are
# signed from the pool's side, positive when the pool received them.
V3_SWAP_TOPIC = (
    "0x" + keccak(text="Swap(address,address,int256,int256,uint160,uint128,int24)").hex()
)
# The router's revert when the token refuses the seller's transfer to the pool.
TOKEN_REFUSED = {
    "v3": "STF",
    "uniswap-v2": "TransferHelper: TRANSFER_FROM_FAILED",
    "sushiswap-v2": "TransferHelper: TRANSFER_FROM_FAILED",
}
V3_UNDERPAID = "IIA"
EXACT_SINGLE = "(address,address,uint24,address,uint256,uint256,uint160)"
# A trap is flagged only when one re-run, which two common launch rules cannot trip, reproduces it. A
# separately funded payer pays for the buy, which the router still delivers to the buyer, so a
# same-block rule keyed on tx.origin (as in the launch "transferDelay" template) finds no earlier
# transfer by the seller's origin; and the sell calls run in a second simulated block an hour later, so
# a rule timed on block.timestamp has lapsed. A rule keyed on block.number is not defeated: measured on
# publicnode's Arbitrum RPC on 2026-09-29, block.timestamp and the L2 block number advance in the later
# simulated block, but Solidity's block.number, which on Arbitrum is the L1 block number, does not, and
# an override of it by +300 fails with -38026 "too many blocks".
CONFIRMATION_DELAY_SECONDS = 3600
CONFIRMATION_RUN = "a re-run whose buy a separate address paid and whose sell ran an hour later"
# A confirmation's first block holds the buy and the balance it delivered; the second, the rest.
BUY_CALLS = 2


@dataclass(frozen=True)
class Pool:
    route: str  # "v3", "uniswap-v2" or "sushiswap-v2"
    address: str  # the V3 pool or the V2 pair
    fee: Optional[int] = None  # the V3 fee tier
    liquidity: int = 0  # the pool's WETH balance, for ordering

    @property
    def router(self) -> str:
        return SWAP_ROUTER_02 if self.route == "v3" else V2_ROUTES[self.route][1]


def call_labels(pool: Pool) -> list:
    if pool.route == "v3":
        return ["buy", "delivered", "approve", "sell", "after_sell", "transfer"]
    return [
        "buy",
        "delivered",
        "pool_before_sell",
        "approve",
        "sell",
        "after_sell",
        "pool_after_sell",
        "transfer",
    ]


def build_simulation_request(
    pool: Pool,
    token: str,
    amount: int,
    buyer: str,
    receiver: str,
    sell_amount: Optional[int] = None,
    confirmation: Optional[tuple] = None,
) -> dict:
    """Buy exactly `amount` tokens with ETH, then sell `sell_amount` of them (default: all of `amount`)
    for WETH. A confirmation (payer, sell_time) has `payer` pay for the buy, which is still delivered to
    the buyer, and runs the sell calls in a second block at `sell_time`."""
    token = token.lower()
    sell_amount = amount if sell_amount is None else sell_amount
    payer = buyer if confirmation is None else confirmation[0]
    if pool.route == "v3":
        buy = _call(
            payer,
            SWAP_ROUTER_02,
            _calldata(
                f"exactOutputSingle({EXACT_SINGLE})",
                [EXACT_SINGLE],
                [(WETH, token, pool.fee, buyer, amount, BUY_BUDGET_WEI, 0)],
            ),
            BUY_BUDGET_WEI,
        )
        sell = _call(
            buyer,
            SWAP_ROUTER_02,
            _calldata(
                f"exactInputSingle({EXACT_SINGLE})",
                [EXACT_SINGLE],
                [(token, WETH, pool.fee, buyer, sell_amount, 0, 0)],
            ),
        )
    else:
        buy = _call(
            payer,
            pool.router,
            _calldata(
                "swapETHForExactTokens(uint256,address[],address,uint256)",
                ["uint256", "address[]", "address", "uint256"],
                [amount, [WETH, token], buyer, MAX_UINT256],
            ),
            BUY_BUDGET_WEI,
        )
        sell = _call(
            buyer,
            pool.router,
            _calldata(
                "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
                ["uint256", "uint256", "address[]", "address", "uint256"],
                [sell_amount, 0, [token, WETH], buyer, MAX_UINT256],
            ),
        )

    def balance(account):
        return _call(buyer, token, _calldata("balanceOf(address)", ["address"], [account]))

    steps = {
        "buy": buy,
        "delivered": balance(buyer),
        "pool_before_sell": balance(pool.address),
        "approve": _call(
            buyer,
            token,
            _calldata(
                "approve(address,uint256)", ["address", "uint256"], [pool.router, MAX_UINT256]
            ),
        ),
        "sell": sell,
        "after_sell": balance(buyer),
        "pool_after_sell": balance(pool.address),
        "transfer": _call(
            buyer,
            token,
            _calldata(
                "transfer(address,uint256)", ["address", "uint256"], [receiver, sell_amount // 2]
            ),
        ),
    }
    calls = [steps[label] for label in call_labels(pool)]
    funded = {buyer: {"balance": hex(BALANCE_OVERRIDE_WEI)}}
    if confirmation is None:
        blocks = [{"stateOverrides": funded, "calls": calls}]
    else:
        blocks = [
            {
                "stateOverrides": {**funded, payer: {"balance": hex(BALANCE_OVERRIDE_WEI)}},
                "calls": calls[:BUY_CALLS],
            },
            {"blockOverrides": {"time": hex(confirmation[1])}, "calls": calls[BUY_CALLS:]},
        ]
    return {"blockStateCalls": blocks, "validation": False}


def _pool_swap(pool: Pool, token: str, logs, recipient: Optional[str] = None) -> Optional[tuple]:
    """Signed (token, WETH) amounts the pool received in the call, negative when it paid them out, from
    its own Swap event, whose third topic is the address it paid. None unless exactly one such event
    (paying `recipient`, when given) is present."""
    if not isinstance(logs, list):
        return None
    topic, words = (V3_SWAP_TOPIC, 5) if pool.route == "v3" else (V2_SWAP_TOPIC, 4)
    paid = None if recipient is None else "0x" + "0" * 24 + recipient[2:]
    matches = [
        log
        for log in logs
        if isinstance(log, dict)
        and str(log.get("address", "")).lower() == pool.address
        and isinstance(log.get("topics"), list)
        and log["topics"]
        and str(log["topics"][0]).lower() == topic
        and (paid is None or (len(log["topics"]) == 3 and str(log["topics"][2]).lower() == paid))
    ]
    data = _hex_bytes(matches[0].get("data")) if len(matches) == 1 else None
    if data is None or len(data) != words * 32:
        return None
    try:
        if pool.route == "v3":
            amount0, amount1 = decode(["int256", "int256"], data[:64])
        else:
            in0, in1, out0, out1 = decode(["uint256"] * 4, data)
            amount0, amount1 = in0 - out0, in1 - out1
    except DecodingError:
        return None
    return (amount0, amount1) if token < WETH else (amount1, amount0)


def _sell_output(logs, buyer: str) -> Optional[int]:
    """The WETH the seller received in the call, from WETH Transfer logs."""
    if not isinstance(logs, list):
        return None
    recipient = "0x" + "0" * 24 + buyer[2:]
    total = 0
    for log in logs:
        topics = log.get("topics") if isinstance(log, dict) else None
        if (
            isinstance(topics, list)
            and len(topics) == 3
            and str(log.get("address", "")).lower() == WETH
            and str(topics[0]).lower() == TRANSFER_TOPIC
            and str(topics[2]).lower() == recipient
        ):
            value = _hex_bytes(log.get("data"))
            if value is None or len(value) != 32:
                return None
            total += int.from_bytes(value, "big")
    return total


def _sell_trap(pool: Pool, data: bytes) -> Optional[str]:
    """Return why a reverted sell proves holders cannot sell, or None when it is not attributable."""
    message = _error_string(data)
    if message == TOKEN_REFUSED[pool.route]:
        return f'the token refused the transfer to the pool (Error("{message}"))'
    if pool.route != "v3" and message == "UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT":
        return f'the pair received no tokens (Error("{message}"))'
    return None


def _outcome(
    pool: Pool,
    reason: str,
    block: Optional[int] = None,
    simulation_failed: bool = False,
    rpc_failed: bool = False,
) -> dict:
    """simulation_failed and rpc_failed as in services/robinhood_simulation.py."""
    return {
        "retry_sell_amount": None,
        "route": pool.route,
        "pool": pool.address,
        "block": block,
        "is_honeypot": None,
        "can_buy": None,
        "can_sell": None,
        "buy_tax": None,
        "sell_tax": None,
        "simulation_failed": simulation_failed,
        "rpc_failed": rpc_failed,
        # The attributable evidence of a trap, which a confirmation re-run must reproduce.
        "trap": None,
        "reason": reason,
    }


def evaluate_simulation(
    pool: Pool,
    token: str,
    amount: int,
    buyer: str,
    result,
    sell_amount: Optional[int] = None,
    confirmation: bool = False,
) -> dict:
    token = token.lower()
    sell_amount = amount if sell_amount is None else sell_amount
    labels = call_labels(pool)
    sizes = [BUY_CALLS, len(labels) - BUY_CALLS] if confirmation else [len(labels)]
    if not (
        isinstance(result, list)
        and len(result) == len(sizes)
        and all(
            isinstance(block, dict)
            and isinstance(block.get("calls"), list)
            and len(block["calls"]) == size
            and all(isinstance(call, dict) for call in block["calls"])
            and _quantity(block.get("number")) is not None
            for block, size in zip(result, sizes)
        )
    ):
        return _outcome(pool, "Malformed eth_simulateV1 result", rpc_failed=True)
    call = dict(zip(labels, [call for block in result for call in block["calls"]]))
    outcome = _outcome(pool, "", _quantity(result[0]["number"]))
    if not _succeeded(call["buy"]):
        outcome["reason"] = f"buy reverted: {_describe_revert(_revert_bytes(call['buy']))}"
        return outcome
    balances = {
        label: _uint(call[label])
        for label in ("delivered", "pool_before_sell", "after_sell", "pool_after_sell")
        if label in call
    }
    if any(value is None for value in balances.values()):
        outcome["simulation_failed"] = True
        outcome["reason"] = "token balance reads failed"
        return outcome
    delivered = balances["delivered"]
    bought = _pool_swap(pool, token, call["buy"].get("logs"))
    if bought is None or -bought[0] > amount:
        outcome["simulation_failed"] = True
        outcome["reason"] = "Malformed eth_simulateV1 buy logs"
        return outcome
    payout, cost = -bought[0], bought[1]
    if payout < amount:
        outcome["reason"] = (
            f"pool paid out only {payout} of {amount} token units; too illiquid to size a buy"
        )
        return outcome
    # The pool paid out exactly `amount`, so any shortfall was taken in the token transfer.
    outcome["buy_tax"] = tax_percent(payout, delivered)
    if outcome["buy_tax"] is None:
        outcome["simulation_failed"] = True
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
    if not _succeeded(call["approve"]):
        outcome["reason"] = (
            f"sell approve reverted: {_describe_revert(_revert_bytes(call['approve']))}"
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
        if trap is not None:
            outcome.update(
                can_sell=False,
                is_honeypot=True,
                trap=trap,
                reason=f"sell reverted: {trap}; {attribution}",
            )
        elif pool.route == "v3" and _error_string(data) == V3_UNDERPAID:
            # A token that takes a fee on transfer pays the pool less than the swap owes it, which a V3
            # pool refuses whatever the token intends: a limit of the pool, not proof of a trap.
            outcome["reason"] = (
                f'sell reverted: the pool was paid less than it was owed (Error("{V3_UNDERPAID}")), '
                f"as for any fee-on-transfer token sold into a V3 pool; {attribution}"
            )
        else:
            outcome["reason"] = (
                f"sell reverted with an unattributed error ({_describe_revert(data)}); {attribution}"
            )
        return outcome
    output = _sell_output(call["sell"].get("logs"), buyer)
    # The seller's swap is the one paying the seller: a token that swaps its collected tokens back
    # through the pool inside the seller's transfer adds a Swap of its own, which pays someone else.
    sold = _pool_swap(pool, token, call["sell"].get("logs"), buyer)
    if output is None:
        outcome["simulation_failed"] = True
        outcome["reason"] = "Malformed eth_simulateV1 sell logs"
        return outcome
    sent = delivered - balances["after_sell"]
    # The pool's own Swap event states the tokens the sell paid it. A V2 pair's balance change is not
    # that amount when the token swaps back through the pair, or moves tokens in or out of it, inside
    # its sell.
    received = None if sold is None else sold[0]
    sell_tax = None if received is None else tax_percent(sent, received)
    if output == 0:
        # Only the sell's own Swap event shows the swap ran, and a pool that paid out WETH must have
        # sent it to the seller; otherwise the trace is missing a transfer.
        if sold is None or sold[1] < 0:
            outcome["simulation_failed"] = True
            outcome["reason"] = "Malformed eth_simulateV1 sell logs"
            return outcome
        if cost < MIN_TRAP_COST_WEI:
            outcome["reason"] = (
                f"sell of {sent} token units returned zero output, but the buy cost only {cost} wei, "
                "too little to rule out rounding"
            )
            return outcome
        outcome.update(
            sell_tax=sell_tax,
            can_sell=False,
            is_honeypot=True,
            trap="zero output",
            reason=f"sell of {sent} token units returned zero output",
        )
        return outcome
    outcome.update(
        sell_tax=sell_tax,
        can_sell=True,
        is_honeypot=sell_tax is not None and sell_tax >= 100,
        reason=(
            f"buy and sell succeeded: sold {sent} token units for {output} wei WETH"
            + ("" if sell_tax is not None else "; sell tax unmeasurable")
        ),
    )
    return outcome


def _confirm_trap(first: dict, confirmation: dict) -> dict:
    """A trap stands when the confirmation re-run reproduces it, or cannot run (the one run's evidence,
    as before). Any other re-run leaves the sell unknown, never sellable: the first run may have met a
    launch rule the re-run avoided, or the re-run may have missed the trap. A trap seen once is a failed
    simulation, which scores nothing and leaves the sell unknown, so no other provider's answer can make the
    sell look safe."""
    where = f" at block {confirmation['block']}" if confirmation["block"] is not None else ""
    if confirmation["rpc_failed"]:
        return {
            **first,
            "reason": f"{first['reason']}; {CONFIRMATION_RUN} could not run ({confirmation['reason']})",
        }
    if confirmation["trap"] == first["trap"]:
        return {**first, "reason": f"{first['reason']}; reproduced by {CONFIRMATION_RUN}{where}"}
    return {
        **first,
        "is_honeypot": None,
        "can_sell": None,
        "sell_tax": None,
        "trap": None,
        "simulation_failed": True,
        "reason": (
            f"the trap did not reproduce, so sellability is left unknown; first run: {first['reason']}; "
            f"{CONFIRMATION_RUN}{where}: {confirmation['reason']}"
        ),
    }


def _eth_call(to: str, data: bytes) -> tuple:
    return ("eth_call", [{"to": to, "data": "0x" + data.hex()}, "latest"])


def _address(data: Optional[bytes]) -> Optional[str]:
    return "0x" + data[12:].hex() if data is not None and len(data) == 32 else None


class ArbitrumSimulator:
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
        # Discovery and every pool attempt contribute evidence; retain the oldest read time.
        observed_at = time.time()
        try:
            result = await self._run(token)
        except SimulationUnavailable as e:
            logger.warning("Arbitrum simulation unavailable: %s", type(e).__name__)
            result = aggregate_outcomes([], [e.reason])
            # The simulation could not run, so it cannot say the token sells; nor can GoPlus.
            result["rpc_failed"] = True
            unknown_ledger.record(SIMULATION_PROVIDER, CHAIN_ID, "failed")
        except Exception as e:
            logger.error("Arbitrum simulation failed: %s", type(e).__name__)
            result = aggregate_outcomes([], [f"Simulation RPC request failed ({type(e).__name__})"])
            result["rpc_failed"] = True
            unknown_ledger.record(SIMULATION_PROVIDER, CHAIN_ID, "failed")
        else:
            # It ran. Undecided, it failed when the RPC could not simulate a pool, and is unknown when a
            # pool could not be decided or no supported pool was found.
            decided = result["is_honeypot"] is not None and not result.get("simulation_failed")
            unknown_ledger.record(
                SIMULATION_PROVIDER,
                CHAIN_ID,
                "answered" if decided else "failed" if result.get("rpc_failed") else "unknown",
            )
        finally:
            self._inflight.pop(flight_key, None)
        result["observed_at"] = observed_at
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
            unconfirmed = False
            for pool in pools:
                outcome = await self._simulate_pool(session, pool, token, amount)
                sell_amount = None
                if outcome["retry_sell_amount"]:
                    sized = await self._simulate_pool(
                        session, pool, token, amount, outcome["retry_sell_amount"]
                    )
                    # A follow-up that could not run leaves the first attempt's buy verdict standing.
                    if sized["can_buy"] is not None:
                        sell_amount = outcome["retry_sell_amount"]
                        outcome = sized
                    elif sized["simulation_failed"] or sized["rpc_failed"]:
                        outcome["simulation_failed"] = sized["simulation_failed"]
                        outcome["rpc_failed"] = sized["rpc_failed"]
                        outcome["reason"] += f"; sized follow-up: {sized['reason']}"
                if outcome["trap"] is not None:
                    confirmation = await self._simulate_pool(
                        session, pool, token, amount, sell_amount, confirm=True
                    )
                    outcome = _confirm_trap(outcome, confirmation)
                    unconfirmed = unconfirmed or outcome["trap"] is None
                outcomes.append(outcome)
        # Pools are ordered by the WETH they hold. When the deepest one sells at a tax at or below the
        # analyzer's extreme line, another pool refusing the sell proves neither a honeypot nor a safe
        # token: it can be that pool's own restriction (a common launch-limit template exempts only
        # the token's registered pair from a same-block check) or a trap for whoever buys there. The
        # token is left unknown, marked as a simulation that failed: the trap is evidence, so a
        # GoPlus answer cannot settle sellability instead. A trapped deepest pool is never cleared
        # by a shallower one.
        deepest = outcomes[0] if outcomes else None
        cleared = False
        if (
            deepest is not None
            and deepest["can_sell"] is True
            and (deepest["sell_tax"] is None or deepest["sell_tax"] <= SELL_TAX_EXTREME)
        ):
            tax = "unmeasured" if deepest["sell_tax"] is None else f"{deepest['sell_tax']:g}%"
            for outcome in outcomes[1:]:
                if outcome["is_honeypot"] is True:
                    cleared = True
                    outcome.update(is_honeypot=None, can_sell=None, simulation_failed=True)
                    outcome["reason"] += (
                        f"; not counted as a trap because the pool holding the most WETH, "
                        f"{deepest['pool']}, sold (sell tax {tax}), so sellability is left unknown"
                    )
        result = aggregate_outcomes(outcomes, notes)
        if cleared:
            result.update(is_honeypot=None, can_sell=None)
        if unconfirmed:
            # A trap one run showed and its re-run did not may still catch whoever buys in that pool,
            # so no other pool makes the token clean; a trap confirmed elsewhere still stands.
            if result["is_honeypot"] is False:
                result["is_honeypot"] = None
            if result["can_sell"] is True:
                result["can_sell"] = None
        return result

    async def _simulate_pool(
        self,
        session,
        pool: Pool,
        token: str,
        amount: int,
        sell_amount: Optional[int] = None,
        confirm: bool = False,
    ) -> dict:
        """One simulation of the pool; with `confirm`, the confirmation re-run of a trap."""
        buyer, receiver = _fresh_address(), _fresh_address()
        try:
            headers = await self._request(session, [("eth_getBlockByNumber", ["latest", False])])
            header = headers[0].get("result")
            source_block = _quantity(header.get("number")) if isinstance(header, dict) else None
            if source_block is None:
                raise SimulationUnavailable("Simulation source block header unavailable")
            confirmation = None
            if confirm:
                # blockOverrides take an absolute time: an hour after the source block's.
                source_time = _quantity(header.get("timestamp"))
                if source_time is None:
                    raise SimulationUnavailable("Simulation source block time unavailable")
                confirmation = (_fresh_address(), source_time + CONFIRMATION_DELAY_SECONDS)
            request = build_simulation_request(
                pool, token, amount, buyer, receiver, sell_amount, confirmation
            )
            rows = await self._request(session, [("eth_simulateV1", [request, hex(source_block)])])
            error = rows[0].get("error")
            if error is not None:
                code = error.get("code") if isinstance(error, dict) else None
                if code == -32601 or "does not exist" in str(error).lower():
                    raise SimulationUnavailable("eth_simulateV1 unsupported by the RPC")
                raise SimulationUnavailable(f"eth_simulateV1 failed (JSON-RPC error {code})")
            try:
                outcome = evaluate_simulation(
                    pool, token, amount, buyer, rows[0].get("result"), sell_amount, confirm
                )
            except Exception as e:
                logger.error("Arbitrum simulation result could not be evaluated: %s", type(e).__name__)
                return _outcome(
                    pool,
                    f"Simulation result could not be evaluated ({type(e).__name__})",
                    block=source_block,
                    simulation_failed=True,
                )
            # eth_simulateV1 returns synthetic blocks after the real source header.
            outcome["block"] = source_block
            return outcome
        except EncodingError as e:
            return _outcome(
                pool,
                f"Simulation request could not be encoded ({type(e).__name__})",
                simulation_failed=True,
            )
        except SimulationUnavailable as e:
            return _outcome(pool, e.reason, rpc_failed=True)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning("Arbitrum simulation request failed: %s", type(e).__name__)
            return _outcome(
                pool, f"Simulation RPC request failed ({type(e).__name__})", rpc_failed=True
            )

    async def _request(self, session, calls: list) -> list:
        """POST one JSON-RPC request or batch. A row the node answered with an error of its own (a timeout
        under load, an internal error) sends the whole batch once more, after RPC_BACKOFF_SECONDS, so
        one transient error does not leave the scan unknown and every row still comes from one answer. A
        revert is the call's own answer and is not asked again."""
        rows = await self._post(session, calls)
        errors = [
            _node_error(row) for row in rows if row.get("error") is not None and not _reverted(row["error"])
        ]
        if errors:
            # The code only: a node's error message can carry the RPC URL, and with it an API key.
            logger.warning(
                "Arbitrum simulation RPC answered an error (%s); asking once more",
                ", ".join(dict.fromkeys(errors)),
            )
            await asyncio.sleep(RPC_BACKOFF_SECONDS)
            rows = await self._post(session, calls)
        return rows

    async def _post(self, session, calls: list) -> list:
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
                    or not all(type(row.get("id")) is int for row in rows)
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
                    "Arbitrum simulation RPC rate limited (attempt %d/%d)",
                    attempt + 1,
                    RPC_ATTEMPTS,
                )
                await asyncio.sleep(RPC_BACKOFF_SECONDS * 2**attempt)
        raise SimulationUnavailable(f"{reason} after {RPC_ATTEMPTS} attempts")

    async def _discover(self, session, token: str) -> tuple:
        """Find the MAX_POOLS pools pairing the token with WETH that hold the most WETH, on Uniswap V3,
        Uniswap V2 and SushiSwap; notes explain everything skipped."""
        if token == WETH:
            return 0, [], ["WETH is the asset every simulated trade is priced in"]
        candidates = [("v3", V3_FACTORY, fee) for fee in V3_FEES] + [
            (route, factory, None) for route, (factory, _) in V2_ROUTES.items()
        ]
        lookups = [_eth_call(token, _selector("totalSupply()"))] + [
            _eth_call(
                factory,
                _calldata(
                    "getPool(address,address,uint24)",
                    ["address", "address", "uint24"],
                    [token, WETH, fee],
                )
                if fee is not None
                else _calldata("getPair(address,address)", ["address", "address"], [token, WETH]),
            )
            for _, factory, fee in candidates
        ]
        rows = await self._request(session, lookups)
        # totalSupply() reverts, legitimately, on a contract that is not a token; the getters do not.
        supply = _call_result(rows[0], "totalSupply()", may_revert=True)
        if supply is None or len(supply) != 32:
            return 0, [], ["totalSupply() unavailable; cannot size a buy"]
        amount = int.from_bytes(supply, "big") // SUPPLY_FRACTION
        if amount == 0:
            return 0, [], ["Token supply too small to size a buy"]
        notes, found = [], []
        for (route, _, fee), row in zip(candidates, rows[1:]):
            label = f"{route} {fee / 10_000:g}% pool" if fee is not None else f"{route} pair"
            address = _address(_call_result(row, label))
            if address is None:
                notes.append(f"{label} lookup failed")
            elif int(address, 16):
                found.append(Pool(route, address, fee))
        pools = []
        if found:
            rows = await self._request(
                session,
                [
                    _eth_call(WETH, _calldata("balanceOf(address)", ["address"], [pool.address]))
                    for pool in found
                ],
            )
            for pool, row in zip(found, rows):
                balance = _call_result(row, f"{pool.route} pool {pool.address} WETH balance")
                if len(balance) != 32:
                    notes.append(f"{pool.route} pool {pool.address} WETH balance lookup failed")
                elif int.from_bytes(balance, "big"):
                    pools.append(
                        Pool(pool.route, pool.address, pool.fee, int.from_bytes(balance, "big"))
                    )
                else:
                    notes.append(f"{pool.route} pool {pool.address} holds no WETH")
        if not pools:
            notes.append(
                "No supported pool found (Uniswap V3, Uniswap V2 or SushiSwap, paired with WETH)"
            )
        pools.sort(key=lambda pool: pool.liquidity, reverse=True)
        for pool in pools[MAX_POOLS:]:
            notes.append(
                f"{pool.route} pool {pool.address} not simulated (cap of {MAX_POOLS} pools)"
            )
        return amount, pools[:MAX_POOLS], notes
