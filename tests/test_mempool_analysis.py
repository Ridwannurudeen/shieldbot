"""Mempool analysis: which token a swap is keyed on, how sandwiches are reported, how alerts are kept."""

import random
import time
from unittest.mock import MagicMock

import pytest

from services.mempool_service import MempoolAlert, MempoolMonitor, PendingTx

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


V3_PACKED_PATH = bytes.fromhex(WETH[2:]) + (3000).to_bytes(3, "big") + bytes.fromhex(TOKEN[2:])


@pytest.mark.parametrize(
    "data, token",
    [
        (EXACT_INPUT + _word(0x20), None),
        (_v2(SWAP_EXACT_ETH_FOR_TOKENS, [0], [_address(WETH), _address(TOKEN)]), TOKEN),
        (
            _v2(SWAP_EXACT_TOKENS_FOR_TOKENS, [100 * 10**18, 0], [_address(WETH), _address(TOKEN)]),
            TOKEN,
        ),
        (_v2(SWAP_EXACT_TOKENS_FOR_ETH, [10**18, 0], [_address(TOKEN), _address(WETH)]), TOKEN),
        (
            _v2(SWAP_EXACT_ETH_FOR_TOKENS, [1], [_address(WETH), _address(USDC), _address(TOKEN)]),
            TOKEN,
        ),
        (
            EXACT_INPUT_SINGLE
            + _address(WETH)
            + _address(TOKEN)
            + _word(3000)
            + _address(RECIPIENT)
            + _word(10**18)
            + _word(0)
            + _word(0),
            TOKEN,
        ),
        (_v3_exact_input(V3_PACKED_PATH), TOKEN),
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
        (APPROVE + _address(RECIPIENT) + _word(2**256 - 1), None),
        ("0x", None),
    ],
    ids=[
        "v3-exact-input-offset-word-only",
        "eth-in-v2-with-a-zero-amount-word",
        "token-to-token-v2-with-a-round-amount-word",
        "eth-out-v2-keys-the-sold-token",
        "three-hop-eth-in-v2",
        "v3-exact-input-single-keys-token-out",
        "v3-exact-input-packed-path",
        "v2-path-offset-beyond-the-calldata",
        "v2-path-entry-is-not-an-address",
        "v2-path-entry-is-a-small-integer",
        "not-a-swap-selector",
        "plain-transfer",
    ],
)
def test_a_swap_is_keyed_on_a_token_from_its_own_abi_or_not_at_all(data, token):
    assert MempoolMonitor(MagicMock())._extract_token_from_swap(data) == token


ATTACKER = "0x" + "01" * 20
VICTIM = "0x" + "02" * 20
BYSTANDER = "0x" + "03" * 20
BUY_TOKEN = _v2(SWAP_EXACT_ETH_FOR_TOKENS, [0], [_address(WETH), _address(TOKEN)])


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


@pytest.mark.asyncio
async def test_a_sandwich_is_reported_once_per_attacker_and_victim_transaction():
    monitor = MempoolMonitor(MagicMock())
    now = time.time()
    front = _swap("0x" + "a1" * 32, ATTACKER, gas_price=10, seen_at=now - 4)
    victim = _swap("0x" + "b1" * 32, VICTIM, gas_price=5, seen_at=now - 3)
    back = _swap("0x" + "a2" * 32, ATTACKER, gas_price=10, seen_at=now - 2)

    for tx in (front, victim, back):
        await monitor._analyze_pending_tx(tx)
    alerts = monitor.get_alerts()
    assert [
        (
            a["alert_type"],
            a["attacker_tx"],
            a["victim_tx"],
            a["attacker_addr"],
            a["target_token"],
            a["chain_id"],
        )
        for a in alerts
    ] == [
        ("sandwich_attack", front.tx_hash, victim.tx_hash, ATTACKER, TOKEN, 56),
    ]

    # A later back-run by the same attacker and an unrelated swap re-check the queue; the pair is not reported again.
    await monitor._analyze_pending_tx(
        _swap("0x" + "a3" * 32, ATTACKER, gas_price=10, seen_at=now - 1)
    )
    await monitor._analyze_pending_tx(_swap("0x" + "c1" * 32, BYSTANDER, gas_price=5, seen_at=now))

    assert monitor.get_alerts() == alerts
    assert monitor.get_stats()["sandwiches_detected"] == 1


@pytest.mark.asyncio
async def test_two_hundred_same_key_swaps_report_each_pair_once():
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
        )
        for i in range(200)
    ]

    for tx in swaps:
        await monitor._analyze_pending_tx(tx)

    pairs = [(a.attacker_tx, a.victim_tx) for a in recorded]
    assert pairs and len(pairs) == len(set(pairs))
    assert monitor.get_stats()["sandwiches_detected"] == len(pairs)


@pytest.mark.asyncio
async def test_a_swap_seen_again_is_not_its_own_back_run():
    # A transaction that leaves a snapshot and returns is analysed again; queued twice, its two
    # copies would pair up as a front-run and a back-run around the victim between them.
    monitor = MempoolMonitor(MagicMock())
    now = time.time()
    front = _swap("0x" + "a1" * 32, ATTACKER, gas_price=10, seen_at=now - 4)
    victim = _swap("0x" + "b1" * 32, VICTIM, gas_price=5, seen_at=now - 3)
    again = _swap(front.tx_hash, ATTACKER, gas_price=10, seen_at=now - 1)

    for tx in (front, victim, again):
        await monitor._analyze_pending_tx(tx)

    assert monitor.get_alerts() == []
    assert monitor.get_stats()["sandwiches_detected"] == 0


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
