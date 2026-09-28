"""The Universal Router path decoder reads every V2, V3 and V4 swap command, so the firewall scans every
token a swap touches; a swap command it cannot read fails the whole path rather than leaving a token out.
A call that runs a command it does not check, or that sends funds to anyone but the sender, is refused
with the reason, so the router's name never vouches for it."""

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
SENDER = "0x" + "5e" * 20
ROUTER = "0x" + "7e" * 20
ATTACKER = "0x" + "ad" * 20
MSG_SENDER = "0x" + "00" * 19 + "01"
ADDRESS_THIS = "0x" + "00" * 19 + "02"
UNDECODABLE = "Token path could not be decoded"

(
    V3_SWAP_EXACT_IN,
    PERMIT2_TRANSFER_FROM,
    SWEEP,
    TRANSFER,
    PAY_PORTION,
    PAY_PORTION_FULL_PRECISION,
) = (
    0x00,
    0x02,
    0x04,
    0x05,
    0x06,
    0x07,
)
V2_SWAP_EXACT_IN, PERMIT2_PERMIT, WRAP_ETH, UNWRAP_WETH, BALANCE_CHECK_ERC20 = (
    0x08,
    0x0A,
    0x0B,
    0x0C,
    0x0E,
)
V4_SWAP, EXECUTE_SUB_PLAN, ACROSS_V4_DEPOSIT_V3, ALLOW_REVERT = 0x10, 0x21, 0x40, 0x80
SWAP_EXACT_IN_SINGLE, SWAP_EXACT_IN, SWAP_EXACT_OUT = 0x06, 0x07, 0x09
SETTLE_ALL, TAKE, TAKE_ALL, TAKE_PORTION, TAKE_PAIR, V4_SWEEP = 0x0C, 0x0E, 0x0F, 0x10, 0x11, 0x14
POOL_KEY = "(address,address,uint24,int24,address)"
PATH_KEY = "(address,uint24,int24,address,bytes)"


def execute(commands, inputs):
    return (
        "0x3593564c"
        + encode(["bytes", "bytes[]", "uint256"], [bytes(commands), inputs, 2**32]).hex()
    )


def decode(calldata, v4=True):
    return DECODER.decode_universal_router_path(calldata, SENDER, ROUTER, v4=v4)


def v3_input(*tokens, recipient=MSG_SENDER):
    path = b"".join(bytes.fromhex(token[2:]) + (500).to_bytes(3, "big") for token in tokens[:-1])
    path += bytes.fromhex(tokens[-1][2:])
    return encode(
        ["address", "uint256", "uint256", "bytes", "bool"], [recipient, 10**18, 0, path, True]
    )


def v2_input(*tokens, recipient=MSG_SENDER):
    return encode(
        ["address", "uint256", "uint256", "address[]", "bool"],
        [recipient, 10**18, 0, list(tokens), True],
    )


def permit_input(spender):
    """PERMIT2_PERMIT's input: abi.encode(PermitSingle(PermitDetails, spender, sigDeadline), signature)."""
    return encode(
        ["((address,uint160,uint48,uint48),address,uint256)", "bytes"],
        [((TOKEN_A, 2**160 - 1, 2**40, 0), spender, 2**40), b"\x01" * 65],
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


def take(currency, recipient):
    return encode(["address", "address", "uint256"], [currency, recipient, 0])


def v4_swap_then(action, params):
    """A V4_SWAP input whose swap is readable, followed by `action`."""
    return v4_input([SWAP_EXACT_IN_SINGLE, action], [single(TOKEN_A, TOKEN_B, True), params])


@pytest.mark.parametrize("swap", SWAPS, ids=[swap["tx"] for swap in SWAPS])
def test_real_v4_swaps_decode_to_the_tokens_they_move(swap):
    tokens, refusal = DECODER.decode_universal_router_path(
        "0x" + swap["calldata_hex"], swap["sender"], swap["router"], v4=True
    )
    assert (sorted(tokens), refusal) == (swap["tokens"], None)


def test_native_eth_is_not_a_token():
    calldata = execute(
        [V4_SWAP], [v4_input([SWAP_EXACT_IN_SINGLE], [single(NATIVE, TOKEN_A, True)])]
    )
    assert decode(calldata) == ([TOKEN_A], None)


def test_a_single_swap_is_read_in_its_direction():
    calldata = execute(
        [V4_SWAP], [v4_input([SWAP_EXACT_IN_SINGLE], [single(TOKEN_A, TOKEN_B, False)])]
    )
    assert decode(calldata) == ([TOKEN_B, TOKEN_A], None)


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
    assert decode(calldata) == (expected, None)


def test_every_swap_command_is_read_not_only_the_first():
    calldata = execute(
        [PERMIT2_PERMIT, V3_SWAP_EXACT_IN, V2_SWAP_EXACT_IN, V4_SWAP | ALLOW_REVERT],
        [
            permit_input(ROUTER),
            v3_input(TOKEN_A, TOKEN_B),
            v2_input(TOKEN_B, TOKEN_C, recipient=ADDRESS_THIS),
            v4_input([SWAP_EXACT_IN_SINGLE], [single(TOKEN_C, NATIVE, True)]),
        ],
    )
    assert decode(calldata) == ([TOKEN_A, TOKEN_B, TOKEN_C], None)


@pytest.mark.parametrize(
    "command,command_input",
    [
        (V4_SWAP, v4_input([SETTLE_ALL, TAKE_ALL], [settle_all(TOKEN_B), settle_all(TOKEN_C)])),
        (V4_SWAP, v4_input([SWAP_EXACT_IN_SINGLE], [single(NATIVE, NATIVE, True)])),
        (V4_SWAP, b"\x01"),
        (V3_SWAP_EXACT_IN, v3_input(TOKEN_C)),
        (V2_SWAP_EXACT_IN, v2_input()),
    ],
    ids=[
        "v4-no-swap-action",
        "v4-native-only",
        "v4-unreadable",
        "v3-one-token-path",
        "v2-empty-path",
    ],
)
def test_a_swap_command_that_cannot_be_read_fails_the_whole_path(command, command_input):
    calldata = execute([V3_SWAP_EXACT_IN, command], [v3_input(TOKEN_A, TOKEN_B), command_input])
    assert decode(calldata) == ([], UNDECODABLE)


def test_a_call_without_a_swap_command_has_no_path():
    assert decode(execute([PERMIT2_PERMIT], [permit_input(ROUTER)])) == ([], UNDECODABLE)


def test_a_command_without_an_input_fails_the_path():
    calldata = (
        "0x3593564c"
        + encode(
            ["bytes", "bytes[]", "uint256"],
            [bytes([V3_SWAP_EXACT_IN, SWEEP]), [v3_input(TOKEN_A, TOKEN_B)], 2**32],
        ).hex()
    )
    assert decode(calldata) == ([], UNDECODABLE)


@pytest.mark.parametrize(
    "command,command_input",
    [
        (
            EXECUTE_SUB_PLAN,
            encode(
                ["bytes", "bytes[]"],
                [
                    bytes([SWEEP]),
                    [encode(["address", "address", "uint256"], [TOKEN_B, ATTACKER, 0])],
                ],
            ),
        ),
        (ACROSS_V4_DEPOSIT_V3, b"\x00" * 64),
        (EXECUTE_SUB_PLAN | ALLOW_REVERT, encode(["bytes", "bytes[]"], [b"", []])),
    ],
    ids=["sub-plan", "bridge-deposit", "sub-plan-allowed-to-revert"],
)
def test_a_command_the_decoder_does_not_check_refuses_the_call(command, command_input):
    calldata = execute([V3_SWAP_EXACT_IN, command], [v3_input(TOKEN_A, TOKEN_B), command_input])
    code = command & 0x7F
    assert decode(calldata) == (
        [],
        f"It runs router command 0x{code:02x}, which ShieldBot does not check",
    )


def test_the_mask_keeps_the_seventh_bit():
    """0x40 is a bridge deposit on a current router, not a V3 swap with a flag set."""
    calldata = execute([0x40], [v3_input(TOKEN_A, TOKEN_B)])
    assert decode(calldata) == ([], "It runs router command 0x40, which ShieldBot does not check")


FUND_MOVES = {
    "v3-swap": lambda to: (V3_SWAP_EXACT_IN, v3_input(TOKEN_B, TOKEN_C, recipient=to)),
    "v2-swap": lambda to: (V2_SWAP_EXACT_IN, v2_input(TOKEN_B, TOKEN_C, recipient=to)),
    "permit2-transfer-from": lambda to: (
        PERMIT2_TRANSFER_FROM,
        encode(["address", "address", "uint160"], [TOKEN_B, to, 1]),
    ),
    "sweep": lambda to: (SWEEP, encode(["address", "address", "uint256"], [TOKEN_B, to, 0])),
    "transfer": lambda to: (TRANSFER, encode(["address", "address", "uint256"], [TOKEN_B, to, 1])),
    "wrap-eth": lambda to: (WRAP_ETH, encode(["address", "uint256"], [to, 0])),
    "unwrap-weth": lambda to: (UNWRAP_WETH, encode(["address", "uint256"], [to, 0])),
    "v4-take": lambda to: (V4_SWAP, v4_swap_then(TAKE, take(TOKEN_B, to))),
    "v4-take-portion": lambda to: (
        V4_SWAP,
        v4_swap_then(TAKE_PORTION, encode(["address", "address", "uint256"], [TOKEN_B, to, 1])),
    ),
}


@pytest.mark.parametrize("move", FUND_MOVES, ids=list(FUND_MOVES))
def test_funds_sent_to_anyone_but_the_sender_refuse_the_call(move):
    command, command_input = FUND_MOVES[move](ATTACKER)
    calldata = execute([V3_SWAP_EXACT_IN, command], [v3_input(TOKEN_A, TOKEN_B), command_input])
    assert decode(calldata) == ([], f"Its funds go to {ATTACKER}, not the sender")


@pytest.mark.parametrize("recipient", [SENDER, MSG_SENDER, ADDRESS_THIS])
@pytest.mark.parametrize("move", FUND_MOVES, ids=list(FUND_MOVES))
def test_funds_kept_with_the_sender_or_the_router_are_allowed(move, recipient):
    """The sender is matched in any letter case."""
    command, command_input = FUND_MOVES[move](recipient)
    calldata = execute([V3_SWAP_EXACT_IN, command], [v3_input(TOKEN_A, TOKEN_B), command_input])
    tokens, refusal = DECODER.decode_universal_router_path(
        calldata, "0x" + SENDER[2:].upper(), ROUTER, v4=True
    )
    assert (tokens[:2], refusal) == ([TOKEN_A, TOKEN_B], None)


def portion(command, share, recipient=ATTACKER):
    return command, encode(["address", "address", "uint256"], [TOKEN_B, recipient, share])


@pytest.mark.parametrize(
    "portions,refused",
    [
        ([portion(PAY_PORTION, 100)], False),
        ([portion(PAY_PORTION, 101)], True),
        ([portion(PAY_PORTION_FULL_PRECISION, 10**16)], False),
        ([portion(PAY_PORTION_FULL_PRECISION, 10**16 + 1)], True),
        ([portion(PAY_PORTION, 60), portion(PAY_PORTION, 60)], True),
        ([portion(PAY_PORTION, 50), portion(PAY_PORTION_FULL_PRECISION, 5 * 10**15)], False),
        (
            [
                portion(PAY_PORTION, 10_000, recipient=MSG_SENDER),
                portion(PAY_PORTION, 10_000, recipient=SENDER),
            ],
            False,
        ),
    ],
    ids=[
        "1%",
        "over-1%",
        "1%-full-precision",
        "over-1%-full-precision",
        "two-shares-over-1%",
        "two-shares-1%",
        "own",
    ],
)
def test_other_addresses_may_take_up_to_one_percent_in_all(portions, refused):
    calldata = execute(
        [V3_SWAP_EXACT_IN] + [command for command, _ in portions],
        [v3_input(TOKEN_A, TOKEN_B)] + [command_input for _, command_input in portions],
    )
    expected = f"It pays more than 1% of its tokens to other addresses, {ATTACKER} among them"
    assert decode(calldata) == (([], expected) if refused else ([TOKEN_A, TOKEN_B], None))


def test_a_permit_for_anyone_but_the_router_refuses_the_call():
    calldata = execute(
        [PERMIT2_PERMIT, V3_SWAP_EXACT_IN], [permit_input(ATTACKER), v3_input(TOKEN_A, TOKEN_B)]
    )
    assert decode(calldata) == ([], f"Its Permit2 permit is for {ATTACKER}, not the router")


def test_a_balance_check_is_allowed():
    check = encode(["address", "address", "uint256"], [SENDER, TOKEN_B, 1])
    calldata = execute([V3_SWAP_EXACT_IN, BALANCE_CHECK_ERC20], [v3_input(TOKEN_A, TOKEN_B), check])
    assert decode(calldata) == ([TOKEN_A, TOKEN_B], None)


def test_an_older_router_does_not_read_command_0x10_as_a_v4_swap():
    calldata = execute(
        [V4_SWAP], [v4_input([SWAP_EXACT_IN_SINGLE], [single(TOKEN_A, TOKEN_B, True)])]
    )
    assert decode(calldata, v4=False) == (
        [],
        "It runs router command 0x10, which ShieldBot does not check",
    )


@pytest.mark.parametrize(
    "action,params",
    [
        (TAKE_PAIR, encode(["address", "address", "address"], [TOKEN_A, TOKEN_B, SENDER])),
        (V4_SWEEP, encode(["address", "address"], [TOKEN_B, SENDER])),
    ],
    ids=["take-pair", "sweep"],
)
def test_a_v4_action_the_router_does_not_run_refuses_the_call(action, params):
    calldata = execute([V4_SWAP], [v4_swap_then(action, params)])
    assert decode(calldata) == (
        [],
        f"It runs V4 action 0x{action:02x}, which ShieldBot does not check",
    )
