"""Mempool analysis: which tokens a swap trades, how sandwiches are reported, which approvals are alerted, how alerts are kept."""

import random
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import services.counterparty_service as counterparty_module
from adapters.eth import EthAdapter
from services.counterparty_service import PERMIT2, CounterpartyService, unknown_facts
from services.mempool_service import MempoolAlert, MempoolMonitor, PendingTx
from utils.scam_db import ScamDatabase
from utils.web3_client import Web3Client

WETH = "0x" + "aa" * 20
TOKEN = "0x" + "bb" * 20
USDC = "0x" + "cc" * 20
RECIPIENT = "0x" + "dd" * 20
DEADLINE = 1_800_000_000

SWAP_EXACT_TOKENS_FOR_TOKENS = "0x38ed1739"
SWAP_EXACT_ETH_FOR_TOKENS = "0x7ff36ab5"
SWAP_EXACT_TOKENS_FOR_ETH = "0x18cbafe5"
EXACT_INPUT_SINGLE = "0x04e45aaf"
EXACT_INPUT = "0xb858183f"
APPROVE = "0x095ea7b3"


def _word(value: int) -> str:
    return f"{value:064x}"


def _address(addr: str) -> str:
    return _word(int(addr, 16))


def _v2(selector: str, amounts, path_words) -> str:
    """V2 router calldata: the amounts, the offset of `path`, `to`, `deadline`, then the path array."""
    head_words = len(amounts) + 3
    head = [_word(a) for a in amounts] + [
        _word(head_words * 32),
        _address(RECIPIENT),
        _word(DEADLINE),
    ]
    return selector + "".join(head) + _word(len(path_words)) + "".join(path_words)


def _v3_exact_input(path_bytes: bytes) -> str:
    """exactInput((bytes path, address recipient, uint256 amountIn, uint256 amountOutMinimum))."""
    padded = path_bytes.hex().ljust(-(-len(path_bytes) // 32) * 64, "0")
    return (
        EXACT_INPUT
        + _word(0x20)
        + _word(0x80)
        + _address(RECIPIENT)
        + _word(10**18)
        + _word(0)
        + _word(len(path_bytes))
        + padded
    )


FEE = (3000).to_bytes(3, "big")
V3_PACKED_PATH = bytes.fromhex(WETH[2:]) + FEE + bytes.fromhex(TOKEN[2:])
V3_PACKED_THREE_HOP = bytes.fromhex(WETH[2:]) + FEE + bytes.fromhex(USDC[2:]) + FEE + bytes.fromhex(TOKEN[2:])


def _v3_single(token_in: str, token_out: str) -> str:
    """exactInputSingle((tokenIn, tokenOut, fee, recipient, amountIn, amountOutMinimum, sqrtPriceLimitX96))."""
    return (
        EXACT_INPUT_SINGLE + token_in + token_out + _word(3000) + _address(RECIPIENT)
        + _word(10**18) + _word(0) + _word(0)
    )


@pytest.mark.parametrize(
    "data, tokens",
    [
        (EXACT_INPUT + _word(0x20), None),
        (_v2(SWAP_EXACT_ETH_FOR_TOKENS, [0], [_address(WETH), _address(TOKEN)]), (WETH, TOKEN)),
        (
            _v2(SWAP_EXACT_TOKENS_FOR_TOKENS, [100 * 10**18, 0], [_address(USDC), _address(TOKEN)]),
            (USDC, TOKEN),
        ),
        (_v2(SWAP_EXACT_TOKENS_FOR_ETH, [10**18, 0], [_address(TOKEN), _address(WETH)]), (TOKEN, WETH)),
        (
            _v2(SWAP_EXACT_ETH_FOR_TOKENS, [1], [_address(WETH), _address(USDC), _address(TOKEN)]),
            (WETH, TOKEN),
        ),
        (_v3_single(_address(WETH), _address(TOKEN)), (WETH, TOKEN)),
        (_v3_single(_address(TOKEN), _address(USDC)), (TOKEN, USDC)),
        (_v3_exact_input(V3_PACKED_PATH), (WETH, TOKEN)),
        (_v3_exact_input(V3_PACKED_THREE_HOP), (WETH, TOKEN)),
        (
            SWAP_EXACT_ETH_FOR_TOKENS
            + _word(0)
            + _word(0x80)
            + _address(RECIPIENT)
            + _word(DEADLINE),
            None,
        ),
        (_v2(SWAP_EXACT_ETH_FOR_TOKENS, [0], [_address(WETH), _word(2**200)]), None),
        (_v2(SWAP_EXACT_ETH_FOR_TOKENS, [0], [_address(WETH), _word(1)]), None),
        (_v2(SWAP_EXACT_TOKENS_FOR_TOKENS, [1, 0], [_word(0x20), _address(TOKEN)]), None),
        (_v2(SWAP_EXACT_TOKENS_FOR_TOKENS, [1, 0], [_address(TOKEN), _address(TOKEN)]), None),
        (_v3_single(_word(0x20), _address(TOKEN)), None),
        (EXACT_INPUT_SINGLE + _address(WETH), None),
        (APPROVE + _address(RECIPIENT) + _word(2**256 - 1), None),
        ("0x", None),
    ],
    ids=[
        "v3-exact-input-offset-word-only",
        "eth-in-v2-with-a-zero-amount-word",
        "token-to-token-v2-with-a-round-amount-word",
        "eth-out-v2-sells-the-token",
        "three-hop-eth-in-v2-keys-the-ends",
        "v3-exact-input-single",
        "v3-exact-input-single-token-to-token",
        "v3-exact-input-packed-path",
        "v3-exact-input-three-hop-packed-path",
        "v2-path-offset-beyond-the-calldata",
        "v2-path-end-is-not-an-address",
        "v2-path-end-is-a-small-integer",
        "v2-path-start-is-an-offset-word",
        "v2-path-sells-a-token-for-itself",
        "v3-token-in-is-an-offset-word",
        "v3-exact-input-single-truncated",
        "not-a-swap-selector",
        "plain-transfer",
    ],
)
def test_a_swap_decodes_the_tokens_it_sells_and_buys_from_its_own_abi_or_not_at_all(data, tokens):
    assert MempoolMonitor(MagicMock())._swap_tokens(data) == tokens


ATTACKER = "0x" + "01" * 20
VICTIM = "0x" + "02" * 20
BYSTANDER = "0x" + "03" * 20
BUY_TOKEN = _v2(SWAP_EXACT_ETH_FOR_TOKENS, [0], [_address(WETH), _address(TOKEN)])
SELL_TOKEN = _v2(SWAP_EXACT_TOKENS_FOR_ETH, [10**18, 0], [_address(TOKEN), _address(WETH)])
USDC_FOR_TOKEN = _v2(SWAP_EXACT_TOKENS_FOR_TOKENS, [10**18, 0], [_address(USDC), _address(TOKEN)])
TOKEN_FOR_USDC = _v2(SWAP_EXACT_TOKENS_FOR_TOKENS, [10**18, 0], [_address(TOKEN), _address(USDC)])


def _swap(
    tx_hash: str, sender: str, gas_price: int, seen_at: float, data: str = BUY_TOKEN
) -> PendingTx:
    return PendingTx(
        tx_hash=tx_hash,
        from_addr=sender,
        to_addr=RECIPIENT,
        value=0,
        gas_price=gas_price,
        data=data,
        chain_id=56,
        seen_at=seen_at,
    )


def _sandwich_alerts(monitor) -> list:
    return [
        (a["alert_type"], a["attacker_tx"], a["victim_tx"], a["attacker_addr"], a["target_token"], a["chain_id"])
        for a in monitor.get_alerts()
    ]


@pytest.mark.asyncio
async def test_a_sandwich_is_reported_once_per_attacker_and_victim_transaction():
    monitor = MempoolMonitor(MagicMock())
    now = time.time()
    front = _swap("0x" + "a1" * 32, ATTACKER, gas_price=10, seen_at=now - 4)  # buys TOKEN
    victim = _swap("0x" + "b1" * 32, VICTIM, gas_price=5, seen_at=now - 3)  # buys TOKEN
    back = _swap("0x" + "a2" * 32, ATTACKER, gas_price=10, seen_at=now - 2, data=SELL_TOKEN)

    for tx in (front, victim, back):
        await monitor._analyze_pending_tx(tx)
    alerts = monitor.get_alerts()
    assert _sandwich_alerts(monitor) == [
        ("sandwich_attack", front.tx_hash, victim.tx_hash, ATTACKER, TOKEN, 56),
    ]
    assert alerts[0]["severity"] == "HIGH"
    assert f"front-ran victim {VICTIM[:10]}... buying {TOKEN[:10]}... with {WETH[:10]}..." in alerts[0]["description"]

    # A later back-run by the same attacker and an unrelated swap re-check the queue; the pair is not reported again.
    await monitor._analyze_pending_tx(
        _swap("0x" + "a3" * 32, ATTACKER, gas_price=10, seen_at=now - 1, data=SELL_TOKEN)
    )
    await monitor._analyze_pending_tx(_swap("0x" + "c1" * 32, BYSTANDER, gas_price=5, seen_at=now))

    assert monitor.get_alerts() == alerts
    assert monitor.get_stats()["sandwiches_detected"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("front_data, back_data, bought", [
    (BUY_TOKEN, SELL_TOKEN, TOKEN),
    (SELL_TOKEN, BUY_TOKEN, WETH),
    (USDC_FOR_TOKEN, TOKEN_FOR_USDC, TOKEN),
    (TOKEN_FOR_USDC, USDC_FOR_TOKEN, USDC),
], ids=["buy-sandwich", "sell-sandwich", "token-to-token", "token-to-token-reverse"])
async def test_a_front_run_in_the_victim_direction_and_a_reverse_back_run_are_a_sandwich(front_data, back_data, bought):
    # The victim trades as the front-run does; target_token is what the victim buys. Both legs of a
    # token-to-token sandwich meet on the pair's one queue.
    monitor = MempoolMonitor(MagicMock())
    now = time.time()
    front = _swap("0x" + "a1" * 32, ATTACKER, gas_price=10, seen_at=now - 4, data=front_data)
    victim = _swap("0x" + "b1" * 32, VICTIM, gas_price=5, seen_at=now - 3, data=front_data)
    back = _swap("0x" + "a2" * 32, ATTACKER, gas_price=10, seen_at=now - 2, data=back_data)

    for tx in (front, victim, back):
        await monitor._analyze_pending_tx(tx)

    assert _sandwich_alerts(monitor) == [
        ("sandwich_attack", front.tx_hash, victim.tx_hash, ATTACKER, bought, 56),
    ]
    assert len(monitor._swap_queue) == 1
    assert monitor.get_stats()["sandwiches_detected"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("front_data, victim_data, back_data", [
    (BUY_TOKEN, BUY_TOKEN, BUY_TOKEN),
    (SELL_TOKEN, SELL_TOKEN, SELL_TOKEN),
    (USDC_FOR_TOKEN, USDC_FOR_TOKEN, USDC_FOR_TOKEN),
    (SELL_TOKEN, BUY_TOKEN, BUY_TOKEN),
    (BUY_TOKEN, SELL_TOKEN, SELL_TOKEN),
], ids=[
    "three-buys", "three-sells", "three-token-to-token", "sell-then-buy-around-a-buyer",
    "buy-then-sell-around-a-seller",
])
async def test_attacker_swaps_that_do_not_reverse_a_trade_in_the_victim_direction_are_not_a_sandwich(
    front_data, victim_data, back_data
):
    monitor = MempoolMonitor(MagicMock())
    now = time.time()
    swaps = (
        _swap("0x" + "a1" * 32, ATTACKER, gas_price=10, seen_at=now - 4, data=front_data),
        _swap("0x" + "b1" * 32, VICTIM, gas_price=5, seen_at=now - 3, data=victim_data),
        _swap("0x" + "a2" * 32, ATTACKER, gas_price=10, seen_at=now - 2, data=back_data),
    )

    for tx in swaps:
        await monitor._analyze_pending_tx(tx)

    assert monitor.get_alerts() == []
    assert monitor.get_stats()["sandwiches_detected"] == 0


@pytest.mark.asyncio
async def test_repeated_same_direction_swaps_by_one_sender_around_others_are_never_flagged():
    # A DCA bot, or an aggregator's solver, sells USDC for TOKEN every second at a high gas price
    # while other senders trade the pair both ways between its swaps (the DAI and USDT pattern seen
    # on Polygon). It never reverses a trade of its own, so it is no attacker.
    monitor = MempoolMonitor(MagicMock())
    base = time.time() - 20
    others = [(VICTIM, USDC_FOR_TOKEN), (BYSTANDER, TOKEN_FOR_USDC)]

    for i in range(12):
        await monitor._analyze_pending_tx(
            _swap("0x" + f"{0xa000 + i:064x}", ATTACKER, gas_price=50, seen_at=base + i, data=USDC_FOR_TOKEN)
        )
        sender, data = others[i % 2]
        await monitor._analyze_pending_tx(
            _swap("0x" + f"{0xb000 + i:064x}", sender, gas_price=5, seen_at=base + i + 0.5, data=data)
        )

    assert monitor.get_alerts() == []
    assert monitor.get_stats()["sandwiches_detected"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("front_gas, victim_gas, back_gas, flagged", [
    (10, 5, 1, True),
    (6, 5, 5, True),
    (5, 5, 10, False),
    (4, 5, 10, False),
], ids=["front-outbids-and-back-run-gas-is-irrelevant", "front-outbids-by-one", "front-ties", "front-underbids"])
async def test_only_a_front_run_that_outbids_the_victim_is_a_sandwich(front_gas, victim_gas, back_gas, flagged):
    # The front-run must land before the victim, so it must pay more gas; the back-run lands after
    # the victim by construction, so its gas price is not compared.
    monitor = MempoolMonitor(MagicMock())
    now = time.time()
    front = _swap("0x" + "a1" * 32, ATTACKER, gas_price=front_gas, seen_at=now - 4)
    victim = _swap("0x" + "b1" * 32, VICTIM, gas_price=victim_gas, seen_at=now - 3)
    back = _swap("0x" + "a2" * 32, ATTACKER, gas_price=back_gas, seen_at=now - 2, data=SELL_TOKEN)

    for tx in (front, victim, back):
        await monitor._analyze_pending_tx(tx)

    assert _sandwich_alerts(monitor) == (
        [("sandwich_attack", front.tx_hash, victim.tx_hash, ATTACKER, TOKEN, 56)] if flagged else []
    )


@pytest.mark.asyncio
async def test_the_nearest_outbidding_front_run_before_the_victim_is_the_one_reported():
    # Two front-runs by the attacker precede the victim; the later one is the front-run, and the
    # earlier one is not reported as a second sandwich.
    monitor = MempoolMonitor(MagicMock())
    now = time.time()
    first = _swap("0x" + "a0" * 32, ATTACKER, gas_price=10, seen_at=now - 5)
    front = _swap("0x" + "a1" * 32, ATTACKER, gas_price=10, seen_at=now - 4)
    victim = _swap("0x" + "b1" * 32, VICTIM, gas_price=5, seen_at=now - 3)
    back = _swap("0x" + "a2" * 32, ATTACKER, gas_price=10, seen_at=now - 2, data=SELL_TOKEN)

    for tx in (first, front, victim, back):
        await monitor._analyze_pending_tx(tx)

    assert _sandwich_alerts(monitor) == [
        ("sandwich_attack", front.tx_hash, victim.tx_hash, ATTACKER, TOKEN, 56),
    ]


@pytest.mark.asyncio
async def test_a_trade_the_attacker_already_reversed_is_not_the_front_run_of_a_later_victim():
    # A bot that buys and sells in turn around other people's trades had closed its position before the
    # later buyer traded, so that buyer was not sandwiched: the front-run is the attacker's latest swap
    # before the victim, whichever way it traded.
    monitor = MempoolMonitor(MagicMock())
    now = time.time()
    buy = _swap("0x" + "a1" * 32, ATTACKER, gas_price=10, seen_at=now - 5)
    victim = _swap("0x" + "b1" * 32, VICTIM, gas_price=5, seen_at=now - 4)
    sell = _swap("0x" + "a2" * 32, ATTACKER, gas_price=10, seen_at=now - 3, data=SELL_TOKEN)
    later_buyer = _swap("0x" + "c1" * 32, BYSTANDER, gas_price=5, seen_at=now - 2)
    sell_again = _swap("0x" + "a3" * 32, ATTACKER, gas_price=10, seen_at=now - 1, data=SELL_TOKEN)

    for tx in (buy, victim, sell, later_buyer, sell_again):
        await monitor._analyze_pending_tx(tx)

    assert _sandwich_alerts(monitor) == [
        ("sandwich_attack", buy.tx_hash, victim.tx_hash, ATTACKER, TOKEN, 56),
    ]


@pytest.mark.asyncio
async def test_two_hundred_same_pair_swaps_report_each_pair_once():
    monitor = MempoolMonitor(MagicMock())
    recorded = []
    add_alert = monitor._add_alert
    monitor._add_alert = lambda alert: (recorded.append(alert), add_alert(alert))
    rng = random.Random(1)
    base = time.time() - 20
    swaps = [
        _swap(
            "0x" + f"{i:064x}",
            "0x" + f"{i % 80:040x}",
            gas_price=rng.randint(1, 100),
            seen_at=base + i * 0.05,
            data=rng.choice((BUY_TOKEN, SELL_TOKEN)),
        )
        for i in range(200)
    ]

    for tx in swaps:
        await monitor._analyze_pending_tx(tx)

    pairs = [(a.attacker_tx, a.victim_tx) for a in recorded]
    assert pairs and len(pairs) == len(set(pairs))
    assert monitor.get_stats()["sandwiches_detected"] == len(pairs)


@pytest.mark.asyncio
async def test_a_swap_seen_again_is_queued_once():
    # A transaction that leaves a snapshot and returns is analysed again; its second copy joins no
    # queue and reports nothing.
    monitor = MempoolMonitor(MagicMock())
    now = time.time()
    front = _swap("0x" + "a1" * 32, ATTACKER, gas_price=10, seen_at=now - 4)
    victim = _swap("0x" + "b1" * 32, VICTIM, gas_price=5, seen_at=now - 3)
    back = _swap("0x" + "a2" * 32, ATTACKER, gas_price=10, seen_at=now - 2, data=SELL_TOKEN)
    again = _swap(back.tx_hash, ATTACKER, gas_price=10, seen_at=now - 1, data=SELL_TOKEN)

    for tx in (front, victim, back, again):
        await monitor._analyze_pending_tx(tx)

    (queue,) = monitor._swap_queue.values()
    assert [swap.tx.tx_hash for swap in queue] == [front.tx_hash, victim.tx_hash, back.tx_hash]
    assert monitor.get_stats()["sandwiches_detected"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [
    SWAP_EXACT_ETH_FOR_TOKENS,
    SWAP_EXACT_ETH_FOR_TOKENS + "zz" * 64,
    SWAP_EXACT_ETH_FOR_TOKENS + _word(0) + _word(2**255),
    _v2(SWAP_EXACT_ETH_FOR_TOKENS, [0], [_address(WETH)]),
    _v2(SWAP_EXACT_ETH_FOR_TOKENS, [0], [_address(WETH), _address(WETH)]),
    _v2(SWAP_EXACT_ETH_FOR_TOKENS, [0], [_address(WETH), _address(TOKEN)])[:-20],
    EXACT_INPUT_SINGLE + _address(WETH),
    EXACT_INPUT + _word(0x20) + _word(0x80) + _address(RECIPIENT) + _word(1) + _word(0) + _word(43) + "ab" * 10,
    EXACT_INPUT + _word(2**255) + _word(0x80),
    "0x" + "ff" * 3,
], ids=[
    "selector-only", "not-hex", "path-offset-beyond-the-calldata", "one-entry-path",
    "same-token-both-ends", "truncated-path", "truncated-v3-single", "short-packed-path",
    "v3-params-offset-beyond-the-calldata", "three-bytes",
])
async def test_malformed_swap_calldata_never_raises_and_queues_nothing(data):
    monitor = MempoolMonitor(MagicMock())

    await monitor._analyze_pending_tx(_swap("0x" + "e1" * 32, ATTACKER, gas_price=1, seen_at=time.time(), data=data))

    assert monitor._swap_queue == {}
    assert monitor.get_alerts() == []


def _approval_alert(index: int, chain_id: int = 56) -> MempoolAlert:
    return MempoolAlert(
        alert_type="suspicious_approval",
        severity="HIGH",
        description=f"approval {index}",
        victim_tx="0x" + f"{index:064x}",
        chain_id=chain_id,
    )


def test_the_newest_thousand_alerts_are_kept_and_read_newest_last():
    monitor = MempoolMonitor(MagicMock())
    assert monitor.get_alerts() == []
    for index in range(1_200):
        monitor._add_alert(_approval_alert(index, chain_id=1 if index % 2 else 56))

    assert monitor.get_stats()["active_alerts"] == 1_000
    assert [a["description"] for a in monitor.get_alerts(limit=3)] == [
        "approval 1197",
        "approval 1198",
        "approval 1199",
    ]
    assert len(monitor.get_alerts()) == 50
    on_bsc = monitor.get_alerts(chain_id=56, limit=1_000)
    assert len(on_bsc) == 500 and on_bsc[-1]["description"] == "approval 1198"
    assert set(on_bsc[0]) == {
        "alert_type",
        "severity",
        "description",
        "victim_tx",
        "attacker_tx",
        "attacker_addr",
        "target_token",
        "chain_id",
        "created_at",
    }


# --- Approvals: only a spender the process already knows to be bad is alerted --------------------

PANCAKESWAP_V2_ROUTER = "0x10ed43c718714eb63d5aa57b78b54704e256024e"
UNISWAP_V2_ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
SPENDER = "0x" + "55" * 20
OWNER = "0x" + "66" * 20
UNLIMITED = 2**256 - 1


@pytest.fixture(autouse=True)
def facts_cache():
    counterparty_module._FACTS_CACHE.clear()
    yield counterparty_module._FACTS_CACHE
    counterparty_module._FACTS_CACHE.clear()


def _approve(spender: str, amount: int, chain_id: int = 56, index: int = 0) -> PendingTx:
    return PendingTx(
        tx_hash="0x" + f"{index + 1:064x}",
        from_addr=OWNER,
        to_addr=TOKEN,
        value=0,
        gas_price=5,
        data=APPROVE + _address(spender) + _word(amount),
        chain_id=chain_id,
    )


def _blacklist(entries) -> ScamDatabase:
    """The in-memory blacklist as load_blacklist fills it; every lookup it could make is recorded."""
    scam_db = ScamDatabase()
    scam_db.known_scams = {
        (None, address): {"source": source, "reports": reports, "expires_at": None}
        for address, source, reports in entries
    }
    scam_db.check_address = AsyncMock()
    scam_db.fetch_address_security = AsyncMock()
    return scam_db


def _wired_monitor(blacklist=()):
    """A monitor wired like the container's: the scanner's counterparty service and blacklist.

    The web3 stub answers the allowlist from memory and records every read it is asked for.
    """
    adapter = SimpleNamespace(
        get_whitelisted_routers=lambda: {PANCAKESWAP_V2_ROUTER: "PancakeSwap V2 Router"}
    )
    web3 = SimpleNamespace(
        _get_adapter=MagicMock(return_value=adapter),
        get_bytecode=AsyncMock(),
        is_verified_contract=AsyncMock(),
        get_contract_creation_info=AsyncMock(),
    )
    scam_db = _blacklist(blacklist)
    counterparty = CounterpartyService(web3, scam_db)
    counterparty.fetch = AsyncMock()
    return MempoolMonitor(web3, scam_db=scam_db, counterparty=counterparty), web3, scam_db, counterparty


def _assert_no_lookup(web3, scam_db, counterparty):
    """The monitor runs over every pending approval on four chains: it never asks a provider."""
    for mock in (
        web3.get_bytecode,
        web3.is_verified_contract,
        web3.get_contract_creation_info,
        scam_db.check_address,
        scam_db.fetch_address_security,
        counterparty.fetch,
    ):
        assert mock.mock_calls == []


def _facts(**overrides) -> dict:
    return {
        **unknown_facts(SPENDER),
        "is_contract": True,
        "delegated": False,
        "is_verified": True,
        "age_days": 400,
        "labels": [],
        "coverage": {"code": True, "verification": True, "age": True, "labels": True},
        "reason": None,
        **overrides,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id, spender", [
    (56, PANCAKESWAP_V2_ROUTER),
    (1, UNISWAP_V2_ROUTER),
    (56, PERMIT2),
    (1, PERMIT2),
], ids=["pancakeswap-v2-on-bsc", "uniswap-v2-on-ethereum", "permit2-on-bsc", "permit2-on-ethereum"])
async def test_an_unlimited_approval_to_an_allowlisted_spender_is_never_an_alert(chain_id, spender):
    # The chain adapters' own allowlist, as the scanner reads it; a blacklist entry for a router
    # (anyone can file reports) does not outrank it.
    client = Web3Client()
    client.register_adapter(EthAdapter())
    scam_db = _blacklist([(spender, "admin", 0)])
    monitor = MempoolMonitor(client, scam_db=scam_db)

    await monitor._analyze_pending_tx(_approve(spender, UNLIMITED, chain_id=chain_id))

    assert monitor.get_alerts() == []
    assert monitor.get_stats()["suspicious_approvals"] == 0
    assert scam_db.check_address.mock_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("amount, wording", [(UNLIMITED, "unlimited"), (10**18, "limited")])
async def test_an_approval_to_a_confirmed_scam_address_is_a_high_alert(amount, wording):
    monitor, web3, scam_db, counterparty = _wired_monitor(blacklist=[(SPENDER, "admin", 0)])
    approval = _approve(SPENDER, amount)

    await monitor._analyze_pending_tx(approval)

    (alert,) = monitor.get_alerts()
    assert (alert["alert_type"], alert["severity"], alert["chain_id"]) == ("suspicious_approval", "HIGH", 56)
    assert (alert["victim_tx"], alert["attacker_tx"], alert["attacker_addr"], alert["target_token"]) == (
        approval.tx_hash, None, SPENDER, TOKEN,
    )
    assert "confirmed scam address" in alert["description"]
    assert f" for {wording} tokens" in alert["description"]
    assert monitor.get_stats()["suspicious_approvals"] == 1
    _assert_no_lookup(web3, scam_db, counterparty)


@pytest.mark.asyncio
async def test_a_community_reported_spender_is_not_a_public_alert():
    # Three reports can be manufactured by anyone; the public feed names no attacker on them.
    monitor, *_ = _wired_monitor(blacklist=[(SPENDER, "community", 3)])

    await monitor._analyze_pending_tx(_approve(SPENDER, UNLIMITED))

    assert monitor.get_alerts() == []
    assert monitor.get_stats()["suspicious_approvals"] == 0


@pytest.mark.asyncio
async def test_a_revoke_grants_nothing_and_is_not_an_alert():
    monitor, *_ = _wired_monitor(blacklist=[(SPENDER, "admin", 0)])

    await monitor._analyze_pending_tx(_approve(SPENDER, 0))

    assert monitor.get_alerts() == []
    assert monitor.get_stats()["suspicious_approvals"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("facts, severity, wording", [
    (_facts(is_contract=False, is_verified=None, age_days=None), "HIGH", "a wallet, not a contract"),
    (_facts(delegated=True, is_verified=None, age_days=None), "HIGH", "a wallet, not a contract"),
    (_facts(labels=["phishing_activities", "blacklist_doubt"], label_source="SlowMist,GoPlus"), "HIGH", "phishing_activities, blacklist_doubt (SlowMist,GoPlus)"),
    (_facts(), None, None),
    (_facts(is_verified=False, age_days=2), None, None),
    (None, None, None),
], ids=[
    "cached-wallet", "cached-delegated-wallet", "cached-goplus-labels", "cached-verified-contract",
    "cached-unverified-young-contract", "uncached",
])
async def test_cached_counterparty_facts_decide_the_alert_without_a_lookup(facts_cache, facts, severity, wording):
    # The facts a scan already fetched for this spender (five-minute cache) are read in memory. An
    # unverified or unknown contract is a risk, not evidence of an attack: no public alert.
    monitor, web3, scam_db, counterparty = _wired_monitor()
    if facts is not None:
        facts_cache[(56, SPENDER)] = facts

    await monitor._analyze_pending_tx(_approve(SPENDER, UNLIMITED))

    alerts = monitor.get_alerts()
    if severity is None:
        assert alerts == []
    else:
        (alert,) = alerts
        assert (alert["severity"], alert["attacker_addr"]) == (severity, SPENDER)
        assert wording in alert["description"]
    assert monitor.get_stats()["suspicious_approvals"] == len(alerts)
    _assert_no_lookup(web3, scam_db, counterparty)


@pytest.mark.asyncio
async def test_the_approval_counter_counts_alerts_only(facts_cache):
    scam = "0x" + "77" * 20
    monitor, web3, scam_db, counterparty = _wired_monitor(blacklist=[(scam, "admin", 0)])
    facts_cache[(56, SPENDER)] = _facts(is_contract=False, is_verified=None, age_days=None)
    unknown = "0x" + "88" * 20

    for index, spender in enumerate((PANCAKESWAP_V2_ROUTER, unknown, scam, SPENDER, unknown)):
        await monitor._analyze_pending_tx(_approve(spender, UNLIMITED, index=index))

    assert [a["attacker_addr"] for a in monitor.get_alerts()] == [scam, SPENDER]
    assert monitor.get_stats()["suspicious_approvals"] == 2
    _assert_no_lookup(web3, scam_db, counterparty)
