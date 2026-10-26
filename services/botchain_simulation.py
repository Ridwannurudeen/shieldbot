"""Buy-then-sell simulation for BOT Chain (677) tokens on BDEX over eth_simulateV1.

honeypot.is and GoPlus do not serve BOT Chain, so no provider says whether a BOT Chain token can be
sold. This simulates a buy and a sell on BDEX as services/arbitrum_simulation.py does on Arbitrum One,
under the same rules, whose helpers it reuses: a token is a honeypot only on evidence attributable to
it, anything else leaves the result unknown, pools are combined worst case (aggregate_outcomes), and a
trap is flagged only when one confirmation re-run reproduces it (CONFIRMATION_DELAY_SECONDS).

Sizing is pool aware, not supply based. Discovery reads each pool's WBOT depth, the pair's WBOT reserve
(getReserves) on V2 and the pool's WBOT balance on V3, and the buy spends exactly
min(BUY_CAP_WEI, depth // DEPTH_DIVISOR), that is min(0.5 BOT, depth / 50), as native value, which the
router wraps into WBOT: swapExactETHForTokens on V2, exactInputSingle on V3. A pool shallower than
MIN_POOL_DEPTH_WEI is not simulated. A first run makes the buy and reads the balance it delivered; a
second run, sized to that balance, makes the same buy and sells exactly it. Buy tax is the pool's Swap
payout against the balance delivered; sell tax is the balance the sell sent against the tokens the
pool's Swap says it received.

Every address, struct layout and revert string here was read on 2026-10-25 from the contracts' verified
source on scan.botchain.ai and their getters:
- WBOT 0xD545...bd30, the WETH() of the V2 router and the WETH9() of the V3 router.
- BDEX V2 factory 0x1171...0AA3 and Router02 0x1414...9e76 (factory() the V2 factory): its pair's Swap
  event is Uniswap V2's, its TransferHelper reverts 'TransferHelper::transferFrom: transferFrom failed'
  and its library 'BotDexV2Library: INSUFFICIENT_INPUT_AMOUNT'.
- BDEX V3 factory 0x1C51...5419 and its UniswapV3Pool: the Swap event, and 'IIA' when a swap pays the
  pool less than it is owed, which a fee-on-transfer token always does.
- The V3 router 0x0703...3929 is the original SwapRouter, not SwapRouter02: its ExactInputSingleParams
  carry a uint256 deadline after the recipient, and its TransferHelper reverts 'STF'.
Sells pay WBOT, never native BOT, so every output is an ERC-20 Transfer log and nothing depends on the
RPC tracing native transfers.
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
from services.explorer_service import BACKGROUND, _Lane
from services.honeypot_service import SELL_TAX_EXTREME
from services.robinhood_simulation import (
    ADDRESS_RE,
    BALANCE_OVERRIDE_WEI,
    CACHE_TTL_SECONDS,
    MAX_UINT256,
    MIN_TRAP_COST_WEI,
    SIM_RPC_TIMEOUT_SECONDS,
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
    _quantity,
    _rate_limited,
    _revert_bytes,
    _selector,
    _succeeded,
    _uint,
    aggregate_outcomes,
    tax_percent,
)

logger = logging.getLogger(__name__)

CHAIN_ID = 677
RPC_URL = "https://rpc.botchain.ai"
WBOT = "0xd5452816194a3784dba983426cce7c122f4abd30"
V3_FACTORY = "0x1c51c173323ec11bb4e3c4fd2314c225dc4b5419"
V3_ROUTER = "0x07032d47a1b9f8460cbee9dc17c1d3e438693929"
# The fee tiers BDEX V3 pools were created with (PoolCreated logs on 2026-10-25: 5, 12 and 7 pools).
V3_FEES = (500, 3000, 10_000)
# V2 route: (factory, its Router02).
V2_ROUTES = {
    "BDEX": (
        "0x117115f3b72c8d1989178089a67d0c26f8ee0aa3",
        "0x1414ed29fdfd322c3c0a830330ed982e2d629e76",
    ),
}
# Each eth_simulateV1 takes about 2 s on rpc.botchain.ai, so two pools, each with a first run, a sized
# run and a confirmation, fit the interactive deadline; one request gives up after 12 s.
MAX_POOLS = 2
RPC_TIMEOUT_SECONDS = 12
# Simulations admitted and not finished: the one holding the lane and those waiting for it. A run takes
# several seconds at about 2 s a call, so a token waiting behind more would miss the firewall's 7.5 s and
# the bot's 25 s deadlines anyway; a new token at the cap is left unknown without a simulation.
# Background work counts every simulation in progress, a user only users', so background work never
# fills a user's slot.
MAX_SIMULATIONS = 4
BUY_CAP_WEI = 5 * 10**17
DEPTH_DIVISOR = 50
# 0.05 BOT. A shallower pool would size a buy under 0.001 BOT, where swap rounding can pass for a tax;
# most such pools on BDEX are freshly created tokens with no liquidity at all.
MIN_POOL_DEPTH_WEI = 5 * 10**16
# UniswapV3Pool.Swap(sender, recipient, amount0, amount1, sqrtPriceX96, liquidity, tick); amounts are
# signed from the pool's side, positive when the pool received them.
V3_SWAP_TOPIC = (
    "0x"
    + keccak(text="Swap(address,address,int256,int256,uint160,uint128,int24)").hex()
)
# The router's revert when the token refuses the seller's transfer to the pool.
TOKEN_REFUSED = {
    "v3": "STF",
    "BDEX": "TransferHelper::transferFrom: transferFrom failed",
}
V2_NO_INPUT = "BotDexV2Library: INSUFFICIENT_INPUT_AMOUNT"
V3_UNDERPAID = "IIA"
# The original SwapRouter's ExactInputSingleParams: tokenIn, tokenOut, fee, recipient, deadline, amountIn,
# amountOutMinimum, sqrtPriceLimitX96.
EXACT_SINGLE = "(address,address,uint24,address,uint256,uint256,uint256,uint160)"
# A trap is flagged only when one re-run, which two common launch rules cannot trip, reproduces it. A
# separately funded payer pays for the buy, which the router still delivers to the buyer, so a
# same-block rule keyed on tx.origin finds no earlier transfer by the seller's origin; and the sell
# calls run in a second simulated block an hour later, so a rule timed on block.timestamp has lapsed.
# Measured on rpc.botchain.ai on 2026-10-25: the later block's header and Multicall3's
# getCurrentBlockTimestamp() both read the source block's time plus 3600.
CONFIRMATION_DELAY_SECONDS = 3600
CONFIRMATION_RUN = (
    "a re-run whose buy a separate address paid and whose sell ran an hour later"
)
# A first run, and a confirmation's first block, hold the buy and the balance it delivered.
BUY_CALLS = 2


@dataclass(frozen=True)
class Pool:
    route: str  # "v3" or "BDEX"
    address: str  # the V3 pool or the V2 pair
    fee: Optional[int] = None  # the V3 fee tier
    liquidity: int = 0  # the pool's WBOT depth, for ordering and sizing

    @property
    def router(self) -> str:
        return V3_ROUTER if self.route == "v3" else V2_ROUTES[self.route][1]


def buy_amount(depth: int) -> int:
    """The WBOT, in wei, a buy in a pool holding `depth` WBOT spends."""
    return min(BUY_CAP_WEI, depth // DEPTH_DIVISOR)


def call_labels(pool: Pool, first_run: bool = False) -> list:
    if first_run:
        return ["buy", "delivered"]
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
    """Buy with exactly `amount` wei of BOT, then sell `sell_amount` tokens for WBOT; without
    `sell_amount`, the first run: only the buy and the balance it delivered. A confirmation (payer,
    sell_time) has `payer` pay for the buy, which is still delivered to the buyer, and runs the sell
    calls in a second block at `sell_time`."""
    token = token.lower()
    payer = buyer if confirmation is None else confirmation[0]
    if pool.route == "v3":
        buy = _call(
            payer,
            V3_ROUTER,
            _calldata(
                f"exactInputSingle({EXACT_SINGLE})",
                [EXACT_SINGLE],
                [(WBOT, token, pool.fee, buyer, MAX_UINT256, amount, 0, 0)],
            ),
            amount,
        )
    else:
        buy = _call(
            payer,
            pool.router,
            _calldata(
                "swapExactETHForTokens(uint256,address[],address,uint256)",
                ["uint256", "address[]", "address", "uint256"],
                [0, [WBOT, token], buyer, MAX_UINT256],
            ),
            amount,
        )

    def balance(account):
        return _call(
            buyer, token, _calldata("balanceOf(address)", ["address"], [account])
        )

    steps = {"buy": buy, "delivered": balance(buyer)}
    if sell_amount is not None:
        if pool.route == "v3":
            sell = _call(
                buyer,
                V3_ROUTER,
                _calldata(
                    f"exactInputSingle({EXACT_SINGLE})",
                    [EXACT_SINGLE],
                    [(token, WBOT, pool.fee, buyer, MAX_UINT256, sell_amount, 0, 0)],
                ),
            )
        else:
            sell = _call(
                buyer,
                pool.router,
                _calldata(
                    "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
                    ["uint256", "uint256", "address[]", "address", "uint256"],
                    [sell_amount, 0, [token, WBOT], buyer, MAX_UINT256],
                ),
            )
        steps.update(
            pool_before_sell=balance(pool.address),
            approve=_call(
                buyer,
                token,
                _calldata(
                    "approve(address,uint256)",
                    ["address", "uint256"],
                    [pool.router, MAX_UINT256],
                ),
            ),
            sell=sell,
            after_sell=balance(buyer),
            pool_after_sell=balance(pool.address),
            transfer=_call(
                buyer,
                token,
                _calldata(
                    "transfer(address,uint256)",
                    ["address", "uint256"],
                    [receiver, sell_amount // 2],
                ),
            ),
        )
    calls = [steps[label] for label in call_labels(pool, sell_amount is None)]
    funded = {buyer: {"balance": hex(BALANCE_OVERRIDE_WEI)}}
    if confirmation is None:
        blocks = [{"stateOverrides": funded, "calls": calls}]
    else:
        blocks = [
            {
                "stateOverrides": {
                    **funded,
                    payer: {"balance": hex(BALANCE_OVERRIDE_WEI)},
                },
                "calls": calls[:BUY_CALLS],
            },
            {
                "blockOverrides": {"time": hex(confirmation[1])},
                "calls": calls[BUY_CALLS:],
            },
        ]
    return {"blockStateCalls": blocks, "validation": False}


def _pool_swap(
    pool: Pool, token: str, logs, recipient: Optional[str] = None
) -> Optional[tuple]:
    """Signed (token, WBOT) amounts the pool received in the call, negative when it paid them out, from
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
        and (
            paid is None
            or (len(log["topics"]) == 3 and str(log["topics"][2]).lower() == paid)
        )
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
    return (amount0, amount1) if token < WBOT else (amount1, amount0)


def _sell_output(logs, buyer: str) -> Optional[int]:
    """The WBOT the seller received in the call, from WBOT Transfer logs."""
    if not isinstance(logs, list):
        return None
    recipient = "0x" + "0" * 24 + buyer[2:]
    total = 0
    for log in logs:
        topics = log.get("topics") if isinstance(log, dict) else None
        if (
            isinstance(topics, list)
            and len(topics) == 3
            and str(log.get("address", "")).lower() == WBOT
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
    if pool.route != "v3" and message == V2_NO_INPUT:
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
    labels = call_labels(pool, sell_amount is None)
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
        outcome["reason"] = (
            f"buy reverted: {_describe_revert(_revert_bytes(call['buy']))}"
        )
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
    if bought is None or bought[0] > 0 or bought[1] > amount:
        outcome["simulation_failed"] = True
        outcome["reason"] = "Malformed eth_simulateV1 buy logs"
        return outcome
    payout, cost = -bought[0], bought[1]
    if cost < amount or payout == 0:
        outcome["reason"] = (
            f"pool took {cost} of {amount} wei WBOT and paid out {payout} token units; "
            "too illiquid to size a buy"
        )
        return outcome
    # The pool's Swap states what it paid out, so any shortfall was taken in the token transfer.
    outcome["buy_tax"] = tax_percent(payout, delivered)
    if outcome["buy_tax"] is None:
        outcome["simulation_failed"] = True
    if delivered == 0:
        outcome["can_buy"] = False
        outcome["reason"] = "buy succeeded but delivered no tokens"
        return outcome
    outcome["can_buy"] = True
    if sell_amount is None:
        # The buy spends a fixed amount of WBOT, so the balance it delivers is known only now; one sized
        # follow-up sells exactly that balance.
        outcome["retry_sell_amount"] = delivered
        outcome["reason"] = (
            f"bought {delivered} token units for {amount} wei WBOT (the pool paid out {payout}); "
            "the sell was not simulated in this run"
        )
        return outcome
    if delivered != sell_amount:
        outcome["reason"] = (
            f"sell not sizeable in one request: sized to sell {sell_amount} token units but received "
            f"{delivered}"
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
        # Only the sell's own Swap event shows the swap ran, and a pool that paid out WBOT must have
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
            f"buy and sell succeeded: sold {sent} token units for {output} wei WBOT"
            + ("" if sell_tax is not None else "; sell tax unmeasurable")
        ),
    )
    return outcome


def _confirm_trap(first: dict, confirmation: dict) -> dict:
    """A trap stands when the confirmation re-run reproduces it, or cannot run (the one run's evidence,
    as before). Any other re-run leaves the sell unknown, never sellable: the first run may have met a
    launch rule the re-run avoided, or the re-run may have missed the trap. A trap seen once is a failed
    simulation, which scores nothing and leaves the sell unknown, so no other provider's answer can settle the
    sell instead."""
    where = (
        f" at block {confirmation['block']}"
        if confirmation["block"] is not None
        else ""
    )
    if confirmation["rpc_failed"]:
        return {
            **first,
            "reason": f"{first['reason']}; {CONFIRMATION_RUN} could not run ({confirmation['reason']})",
        }
    if confirmation["trap"] == first["trap"]:
        return {
            **first,
            "reason": f"{first['reason']}; reproduced by {CONFIRMATION_RUN}{where}",
        }
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


def _simulation_rows(rows: list) -> list:
    """The eth_simulateV1 answer, or SimulationUnavailable naming why the node gave none."""
    error = rows[0].get("error")
    if error is not None:
        code = error.get("code") if isinstance(error, dict) else None
        if code == -32601 or "does not exist" in str(error).lower():
            raise SimulationUnavailable("eth_simulateV1 unsupported by the RPC")
        raise SimulationUnavailable(f"eth_simulateV1 failed (JSON-RPC error {code})")
    return rows


class BotChainSimulator:
    """Runs and caches one buy/sell simulation per token."""

    def __init__(self, rpc_url: str = RPC_URL, sim_rpc_url: Optional[str] = None):
        self._rpc_url = rpc_url
        self._sim_rpc_url = sim_rpc_url or None
        self.chain_id = CHAIN_ID
        self._cache = TTLCache(maxsize=1024, ttl=CACHE_TTL_SECONDS)
        self._inflight = {}
        # One simulation at a time, so the RPC never serves two at once (four in parallel each took two
        # to three times as long). A waiting simulation a user is waiting on goes before waiting
        # background ones, as on the explorer's Blockscout lane.
        self._lane = _Lane()
        # Tokens whose background simulation a user has since joined: they take a user's turn.
        self._promoted = set()
        # Flights a background caller started that no user has joined: they hold no user's slot.
        self._background = set()

    async def simulate(self, token: str) -> dict:
        token = token.lower()
        cached = self._cache.get(token)
        if cached is not None:
            return cached
        loop = asyncio.get_running_loop()
        flight_key = (loop, token)
        background = BACKGROUND.get()
        if flight_key not in self._inflight:
            # Only this loop's simulations can finish, so only they hold a slot. Background work counts
            # every simulation in progress; a user counts only users', since the lane takes users first.
            in_progress = sum(
                key[0] is loop and (background or key not in self._background)
                for key in self._inflight
            )
            if in_progress >= MAX_SIMULATIONS:
                # Not cached, so the token is simulated once a simulation in progress finishes.
                result = aggregate_outcomes(
                    [],
                    [
                        f"Simulation not run: {MAX_SIMULATIONS} simulations already in progress"
                    ],
                )
                # The simulation could not run, so it cannot say the token sells.
                result["rpc_failed"] = True
                result["observed_at"] = time.time()
                unknown_ledger.record(SIMULATION_PROVIDER, self.chain_id, "unknown")
                return result
            self._inflight[flight_key] = asyncio.create_task(
                self._simulate(token, flight_key)
            )
            if background:
                self._background.add(flight_key)
        elif not background:
            self._promoted.add(token)
            self._lane.promote(token)
            self._background.discard(flight_key)
        return await asyncio.shield(self._inflight[flight_key])

    async def _simulate(self, token: str, flight_key: tuple) -> dict:
        # Discovery and every pool attempt contribute evidence; retain the oldest read time.
        observed_at = time.time()
        try:
            async with self._lane.hold(
                BACKGROUND.get() and token not in self._promoted, token
            ):
                result = await self._run(token)
        except SimulationUnavailable as e:
            logger.warning("BOT Chain simulation unavailable: %s", type(e).__name__)
            result = aggregate_outcomes([], [e.reason])
            # The simulation could not run, so it cannot say the token sells.
            result["rpc_failed"] = True
            unknown_ledger.record(SIMULATION_PROVIDER, self.chain_id, "failed")
        except Exception as e:
            logger.error("BOT Chain simulation failed: %s", type(e).__name__)
            result = aggregate_outcomes(
                [], [f"Simulation RPC request failed ({type(e).__name__})"]
            )
            result["rpc_failed"] = True
            unknown_ledger.record(SIMULATION_PROVIDER, self.chain_id, "failed")
        else:
            # It ran. Undecided, it failed when the RPC could not simulate a pool, and is unknown when a
            # pool could not be decided or no supported pool was found.
            decided = result["is_honeypot"] is not None and not result.get(
                "simulation_failed"
            )
            unknown_ledger.record(
                SIMULATION_PROVIDER,
                self.chain_id,
                "answered"
                if decided
                else "failed"
                if result.get("rpc_failed")
                else "unknown",
            )
        finally:
            self._inflight.pop(flight_key, None)
            self._promoted.discard(token)
            self._background.discard(flight_key)
        result["observed_at"] = observed_at
        self._cache[token] = result
        return result

    async def _run(self, token: str) -> dict:
        if not ADDRESS_RE.fullmatch(token):
            return aggregate_outcomes([], ["Invalid token address"])
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=RPC_TIMEOUT_SECONDS)
        ) as session:
            pools, notes, source = await self._discover(session, token)
            outcomes = []
            unconfirmed = False
            for pool in pools:
                amount = buy_amount(pool.liquidity)
                outcome = await self._simulate_pool(
                    session, pool, token, amount, source
                )
                sell_amount = None
                if outcome["retry_sell_amount"]:
                    sized = await self._simulate_pool(
                        session,
                        pool,
                        token,
                        amount,
                        source,
                        outcome["retry_sell_amount"],
                    )
                    # A follow-up that could not decide leaves the first run's buy verdict standing.
                    if sized["can_buy"] is not None:
                        sell_amount = outcome["retry_sell_amount"]
                        outcome = sized
                    else:
                        if sized["simulation_failed"] or sized["rpc_failed"]:
                            outcome["simulation_failed"] = sized["simulation_failed"]
                            outcome["rpc_failed"] = sized["rpc_failed"]
                        outcome["reason"] += f"; sized follow-up: {sized['reason']}"
                if outcome["trap"] is not None:
                    confirmation = await self._simulate_pool(
                        session, pool, token, amount, source, sell_amount, confirm=True
                    )
                    outcome = _confirm_trap(outcome, confirmation)
                    unconfirmed = unconfirmed or outcome["trap"] is None
                outcomes.append(outcome)
        # Pools are ordered by the WBOT they hold. When the deepest one sells at a tax at or below the
        # analyzer's extreme line, another pool refusing the sell proves neither a honeypot nor a clean
        # token: it can be that pool's own restriction (a common launch-limit template exempts only
        # the token's registered pair from a same-block check) or a trap for whoever buys there. The
        # token is left unknown, marked as a simulation that failed: the trap is evidence, so another
        # provider's answer cannot settle sellability instead. A trapped deepest pool is never cleared
        # by a shallower one.
        deepest = outcomes[0] if outcomes else None
        cleared = False
        if (
            deepest is not None
            and deepest["can_sell"] is True
            and (deepest["sell_tax"] is None or deepest["sell_tax"] <= SELL_TAX_EXTREME)
        ):
            tax = (
                "unmeasured"
                if deepest["sell_tax"] is None
                else f"{deepest['sell_tax']:g}%"
            )
            for outcome in outcomes[1:]:
                if outcome["is_honeypot"] is True:
                    cleared = True
                    outcome.update(
                        is_honeypot=None, can_sell=None, simulation_failed=True
                    )
                    outcome["reason"] += (
                        f"; not counted as a trap because the pool holding the most WBOT, "
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
        source: tuple,
        sell_amount: Optional[int] = None,
        confirm: bool = False,
    ) -> dict:
        """One simulation of the pool at the source (block, time); with `confirm`, the confirmation
        re-run of a trap."""
        source_block, source_time = source
        buyer, receiver = _fresh_address(), _fresh_address()
        try:
            confirmation = None
            if confirm:
                # blockOverrides take an absolute time: an hour after the source block's.
                confirmation = (
                    _fresh_address(),
                    source_time + CONFIRMATION_DELAY_SECONDS,
                )
            request = build_simulation_request(
                pool, token, amount, buyer, receiver, sell_amount, confirmation
            )
            calls = [("eth_simulateV1", [request, hex(source_block)])]
            rows = None
            if self._sim_rpc_url:
                try:
                    rows = _simulation_rows(await self._sim_request(session, calls))
                except (
                    SimulationUnavailable,
                    aiohttp.ClientError,
                    asyncio.TimeoutError,
                ) as e:
                    logger.warning(
                        "BOT Chain simulation provider fallback: %s", type(e).__name__
                    )
            if rows is None:
                rows = _simulation_rows(await self._request(session, calls))
            try:
                outcome = evaluate_simulation(
                    pool,
                    token,
                    amount,
                    buyer,
                    rows[0].get("result"),
                    sell_amount,
                    confirm,
                )
            except Exception as e:
                logger.error(
                    "BOT Chain simulation result could not be evaluated: %s",
                    type(e).__name__,
                )
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
        except aiohttp.ClientError as e:
            logger.warning("BOT Chain simulation request failed: %s", type(e).__name__)
            return _outcome(
                pool,
                f"Simulation RPC request failed ({type(e).__name__})",
                rpc_failed=True,
            )

    async def _request(self, session, calls: list) -> list:
        """POST one JSON-RPC request or batch to the RPC. Nothing is asked again after a timeout, a rate
        limit or an error row of the node's own, which leave the result unknown: at about 2 s a call a
        retry would cost the scan its deadline. A connection the server reset is asked once more."""
        for attempt in range(2):
            try:
                return await self._post(session, calls)
            except asyncio.TimeoutError:
                raise SimulationUnavailable(
                    f"RPC request timed out after {RPC_TIMEOUT_SECONDS} s"
                ) from None
            except (aiohttp.ServerDisconnectedError, aiohttp.ClientOSError) as e:
                if attempt or isinstance(e, aiohttp.ClientConnectorError):
                    raise
                logger.warning(
                    "BOT Chain simulation RPC connection reset; asking once more"
                )

    async def _sim_request(self, session, calls: list) -> list:
        return await self._post(
            session, calls, url=self._sim_rpc_url, timeout=SIM_RPC_TIMEOUT_SECONDS
        )

    async def _post(self, session, calls: list, url=None, timeout=None) -> list:
        """POST one JSON-RPC request or batch; a rate limit is an answer of its own, not retried."""
        body = [
            {"jsonrpc": "2.0", "id": index, "method": method, "params": params}
            for index, (method, params) in enumerate(calls)
        ]
        async with session.post(
            self._rpc_url if url is None else url,
            json=body if len(body) > 1 else body[0],
            **({"timeout": aiohttp.ClientTimeout(total=timeout)} if timeout else {}),
        ) as response:
            status = response.status
            try:
                payload = (
                    await response.json(content_type=None) if status == 200 else None
                )
            except ValueError as e:
                raise SimulationUnavailable("Malformed RPC response") from e
        if status == 429:
            raise SimulationUnavailable("RPC rate limited (HTTP 429)")
        if status != 200:
            raise SimulationUnavailable(f"RPC HTTP {status}")
        rows = payload if isinstance(payload, list) else [payload]
        if (
            len(rows) != len(body)
            or not all(isinstance(row, dict) for row in rows)
            or not all(type(row.get("id")) is int for row in rows)
            or {row.get("id") for row in rows} != set(range(len(body)))
        ):
            raise SimulationUnavailable("Malformed RPC response")
        if any(_rate_limited(row.get("error")) for row in rows):
            raise SimulationUnavailable("RPC rate limited (JSON-RPC rate limit error)")
        by_id = {row["id"]: row for row in rows}
        return [by_id[index] for index in range(len(body))]

    async def _discover(self, session, token: str) -> tuple:
        """Find the MAX_POOLS BDEX pools pairing the token with WBOT that hold the most WBOT, and the
        source block (number, time) to simulate them at; notes explain everything skipped."""
        if token == WBOT:
            return [], ["WBOT is the asset every simulated trade is priced in"], None
        candidates = [("v3", V3_FACTORY, fee) for fee in V3_FEES] + [
            (route, factory, None) for route, (factory, _) in V2_ROUTES.items()
        ]
        lookups = [_eth_call(token, _selector("totalSupply()"))] + [
            _eth_call(
                factory,
                _calldata(
                    "getPool(address,address,uint24)",
                    ["address", "address", "uint24"],
                    [token, WBOT, fee],
                )
                if fee is not None
                else _calldata(
                    "getPair(address,address)", ["address", "address"], [token, WBOT]
                ),
            )
            for _, factory, fee in candidates
        ]
        rows = await self._request(session, lookups)
        # totalSupply() reverts, legitimately, on a contract that is not a token; the getters do not.
        supply = _call_result(rows[0], "totalSupply()", may_revert=True)
        if supply is None or len(supply) != 32:
            return (
                [],
                ["totalSupply() unavailable; the address is not simulated as a token"],
                None,
            )
        if int.from_bytes(supply, "big") == 0:
            return [], ["Token supply is zero"], None
        notes, found = [], []
        for (route, _, fee), row in zip(candidates, rows[1:]):
            label = (
                f"{route} {fee / 10_000:g}% pool"
                if fee is not None
                else f"{route} pair"
            )
            address = _address(_call_result(row, label))
            if address is None:
                notes.append(f"{label} lookup failed")
            elif int(address, 16):
                found.append(Pool(route, address, fee))
        if not found:
            notes.append(
                "No supported pool found (BDEX V3 or BDEX V2, paired with WBOT)"
            )
            return [], notes, None
        rows = await self._request(
            session,
            [
                _eth_call(
                    WBOT, _calldata("balanceOf(address)", ["address"], [pool.address])
                )
                if pool.route == "v3"
                else _eth_call(pool.address, _selector("getReserves()"))
                for pool in found
            ]
            + [("eth_getBlockByNumber", ["latest", False])],
        )
        pools = []
        for pool, row in zip(found, rows):
            depth = _call_result(row, f"{pool.route} pool {pool.address} WBOT depth")
            if pool.route == "v3":
                depth = int.from_bytes(depth, "big") if len(depth) == 32 else None
            elif len(depth) == 96:
                # A pair's tokens are sorted by address, so WBOT is token0 when it sorts first.
                reserve0, reserve1, _ = decode(["uint112", "uint112", "uint32"], depth)
                depth = reserve0 if WBOT < token else reserve1
            else:
                depth = None
            if depth is None:
                notes.append(
                    f"{pool.route} pool {pool.address} WBOT depth lookup failed"
                )
            elif depth == 0:
                notes.append(f"{pool.route} pool {pool.address} holds no WBOT")
            elif depth < MIN_POOL_DEPTH_WEI:
                notes.append(
                    f"{pool.route} pool {pool.address} holds {depth} wei WBOT, under the "
                    f"{MIN_POOL_DEPTH_WEI} wei minimum depth; not simulated"
                )
            else:
                pools.append(Pool(pool.route, pool.address, pool.fee, depth))
        if not pools:
            notes.append("No supported pool with enough WBOT depth")
            return [], notes, None
        header = rows[-1].get("result")
        source = (
            (_quantity(header.get("number")), _quantity(header.get("timestamp")))
            if isinstance(header, dict)
            else (None, None)
        )
        if None in source:
            raise SimulationUnavailable("Simulation source block header unavailable")
        pools.sort(key=lambda pool: pool.liquidity, reverse=True)
        for pool in pools[MAX_POOLS:]:
            notes.append(
                f"{pool.route} pool {pool.address} not simulated (cap of {MAX_POOLS} pools)"
            )
        return pools[:MAX_POOLS], notes, source
