"""The Universal Router path decoder reads every V2, V3 and V4 swap command, so the firewall scans every
token a swap touches; a swap command it cannot read fails the whole path rather than leaving a token out."""

import json
from pathlib import Path

import pytest
from eth_abi import encode

from utils.calldata_decoder import CalldataDecoder

DECODER = CalldataDecoder()
SWAPS = json.loads(
    (Path(__file__).parent / "fixtures" / "universal_router_v4_swaps.json").read_text(
        encoding="utf-8"
    )
)["swaps"]

TOKEN_A = "0x" + "a1" * 20
TOKEN_B = "0x" + "b2" * 20
TOKEN_C = "0x" + "c3" * 20
NATIVE = "0x" + "00" * 20
NO_HOOKS = "0x" + "00" * 20
V3_SWAP_EXACT_IN, PERMIT2_PERMIT, V4_SWAP, ALLOW_REVERT = 0x00, 0x0A, 0x10, 0x80
SWAP_EXACT_IN_SINGLE, SWAP_EXACT_IN, SWAP_EXACT_OUT, SETTLE_ALL, TAKE_ALL = (
    0x06,
    0x07,
    0x09,
    0x0C,
    0x0F,
)
POOL_KEY = "(address,address,uint24,int24,address)"
PATH_KEY = "(address,uint24,int24,address,bytes)"


def execute(commands, inputs):
    return (
        "0x3593564c"
        + encode(["bytes", "bytes[]", "uint256"], [bytes(commands), inputs, 2**32]).hex()
    )


def v3_input(*tokens):
    path = b"".join(bytes.fromhex(token[2:]) + (500).to_bytes(3, "big") for token in tokens[:-1])
    path += bytes.fromhex(tokens[-1][2:])
    return encode(
        ["address", "uint256", "uint256", "bytes", "bool"], [TOKEN_A, 10**18, 0, path, True]
    )


def v4_input(actions, params):
    return encode(["bytes", "bytes[]"], [bytes(actions), params])


def single(currency0, currency1, zero_for_one):
    return encode(
        [f"({POOL_KEY},bool,uint128,uint128,bytes)"],
        [((currency0, currency1, 500, 10, NO_HOOKS), zero_for_one, 10**18, 0, b"")],
    )


def multi(head, *hops):
    """SWAP_EXACT_IN's or SWAP_EXACT_OUT's params: the head currency, then the path's intermediate currencies."""
    path = [(hop, 500, 10, NO_HOOKS, b"") for hop in hops]
    return encode([f"(address,{PATH_KEY}[],uint128,uint128)"], [(head, path, 10**18, 0)])


def settle_all(currency):
    return encode(["address", "uint256"], [currency, 10**18])


@pytest.mark.parametrize("swap", SWAPS, ids=[swap["tx"] for swap in SWAPS])
def test_real_v4_swaps_decode_to_the_tokens_they_move(swap):
    assert (
        sorted(DECODER.decode_universal_router_path("0x" + swap["calldata_hex"])) == swap["tokens"]
    )


def test_native_eth_is_not_a_token():
    calldata = execute(
        [V4_SWAP], [v4_input([SWAP_EXACT_IN_SINGLE], [single(NATIVE, TOKEN_A, True)])]
    )
    assert DECODER.decode_universal_router_path(calldata) == [TOKEN_A]


def test_a_single_swap_is_read_in_its_direction():
    calldata = execute(
        [V4_SWAP], [v4_input([SWAP_EXACT_IN_SINGLE], [single(TOKEN_A, TOKEN_B, False)])]
    )
    assert DECODER.decode_universal_router_path(calldata) == [TOKEN_B, TOKEN_A]


@pytest.mark.parametrize(
    "action,params,expected",
    [
        (SWAP_EXACT_IN, multi(TOKEN_A, TOKEN_B, TOKEN_C), [TOKEN_A, TOKEN_B, TOKEN_C]),
        (SWAP_EXACT_OUT, multi(TOKEN_C, TOKEN_A, TOKEN_B), [TOKEN_A, TOKEN_B, TOKEN_C]),
    ],
)
def test_a_multi_hop_swap_names_every_currency_from_input_to_output(action, params, expected):
    calldata = execute(
        [V4_SWAP],
        [
            v4_input(
                [action, SETTLE_ALL, TAKE_ALL], [params, settle_all(TOKEN_A), settle_all(TOKEN_C)]
            )
        ],
    )
    assert DECODER.decode_universal_router_path(calldata) == expected


def test_every_swap_command_is_read_not_only_the_first():
    calldata = execute(
        [PERMIT2_PERMIT, V3_SWAP_EXACT_IN, V4_SWAP | ALLOW_REVERT],
        [
            b"\x00" * 32,
            v3_input(TOKEN_A, TOKEN_B),
            v4_input([SWAP_EXACT_IN_SINGLE], [single(TOKEN_B, TOKEN_C, True)]),
        ],
    )
    assert DECODER.decode_universal_router_path(calldata) == [TOKEN_A, TOKEN_B, TOKEN_C]


@pytest.mark.parametrize(
    "v4",
    [
        v4_input([SETTLE_ALL, TAKE_ALL], [settle_all(TOKEN_B), settle_all(TOKEN_C)]),
        b"\x01",
    ],
    ids=["no-swap-action", "unreadable"],
)
def test_a_swap_command_that_cannot_be_read_fails_the_whole_path(v4):
    calldata = execute([V3_SWAP_EXACT_IN, V4_SWAP], [v3_input(TOKEN_A, TOKEN_B), v4])
    assert DECODER.decode_universal_router_path(calldata) == []


def test_a_call_without_a_swap_command_has_no_path():
    assert DECODER.decode_universal_router_path(execute([PERMIT2_PERMIT], [b"\x00" * 32])) == []
