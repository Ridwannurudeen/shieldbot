"""ABI-shaped census logs, encoded independently from the decoder definitions."""

from eth_abi import encode
from eth_utils import keccak
import pytest

from scripts.census_4663.events import POOL_MANAGER, TOPICS, decode_log


TOKEN = "0x" + "12" * 20
OTHER = "0x" + "34" * 20
PAIR = "0x" + "56" * 20
POOL_ID = "0x" + "ab" * 32


def encoded(types, values):
    return "0x" + encode(types, values).hex()


def log_fixture(signature, indexed_types, indexed_values, types, values):
    # JSON-RPC log envelope and indexed layout from the upstream Uniswap ABIs.
    return {
        "address": POOL_MANAGER,
        "topics": ["0x" + keccak(text=signature).hex()]
        + [
            encoded([kind], [value])
            for kind, value in zip(indexed_types, indexed_values)
        ],
        "data": encoded(types, values),
        "blockNumber": "0x3b768a0",
        "blockHash": "0x" + "cd" * 32,
        "transactionHash": "0x" + "ef" * 32,
        "transactionIndex": "0x2",
        "logIndex": "0x7",
        "removed": False,
    }


def test_decode_v4_initialize_indexed_currencies_and_signed_tick():
    log = log_fixture(
        "Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)",
        ["bytes32", "address", "address"],
        [bytes.fromhex(POOL_ID[2:]), TOKEN, OTHER],
        ["uint24", "int24", "address", "uint160", "int24"],
        [3000, 60, PAIR, 2**96, -120],
    )

    result = decode_log(log, "v4")

    assert result == {
        "name": "Initialize",
        "pool_key": POOL_ID,
        "source": "v4",
        "data": {
            "fee": 3000,
            "tick_spacing": 60,
            "hooks": PAIR,
            "sqrt_price_x96": 2**96,
            "tick": -120,
            "pool_id": POOL_ID,
            "currency0": TOKEN,
            "currency1": OTHER,
        },
    }


def test_decode_v4_liquidity_removal_keeps_signed_delta_and_range():
    log = log_fixture(
        "ModifyLiquidity(bytes32,address,int24,int24,int256,bytes32)",
        ["bytes32", "address"],
        [bytes.fromhex(POOL_ID[2:]), TOKEN],
        ["int24", "int24", "int256", "bytes32"],
        [-887220, 887220, -(2**100), b"\x00" * 32],
    )

    result = decode_log(log, "v4")

    assert result["name"] == "ModifyLiquidity"
    assert result["data"]["tick_lower"] == -887220
    assert result["data"]["tick_upper"] == 887220
    assert result["data"]["liquidity_delta"] == -(2**100)
    assert result["data"]["sender"] == TOKEN
    assert result["data"]["salt"] == "0x" + "00" * 32


def test_decode_v4_swap_keeps_opposite_signed_amounts():
    log = log_fixture(
        "Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)",
        ["bytes32", "address"],
        [bytes.fromhex(POOL_ID[2:]), TOKEN],
        ["int128", "int128", "uint160", "uint128", "int24", "uint24"],
        [-(10**18), 10**20, 2**96, 2**100, -30, 3000],
    )

    result = decode_log(log, "v4")

    assert result["name"] == "Swap"
    assert result["pool_key"] == POOL_ID
    assert result["data"]["amount0"] == -(10**18)
    assert result["data"]["amount1"] == 10**20
    assert result["data"]["tick"] == -30


def test_decode_v2_pair_creation_and_count():
    log = log_fixture(
        "PairCreated(address,address,address,uint256)",
        ["address", "address"],
        [TOKEN, OTHER],
        ["address", "uint256"],
        [PAIR, 42398],
    )

    assert decode_log(log, "v2_factory") == {
        "name": "PairCreated",
        "pool_key": PAIR,
        "source": "v2",
        "data": {"pair": PAIR, "pair_count": 42398, "token0": TOKEN, "token1": OTHER},
    }


@pytest.mark.parametrize(
    "signature,indexed_types,indexed_values,types,values,name,expected",
    [
        (
            "Swap(address,uint256,uint256,uint256,uint256,address)",
            ["address", "address"],
            [TOKEN, OTHER],
            ["uint256"] * 4,
            [10**18, 0, 0, 10**20],
            "Swap",
            {
                "amount0_in": 10**18,
                "amount1_in": 0,
                "amount0_out": 0,
                "amount1_out": 10**20,
            },
        ),
        (
            "Mint(address,uint256,uint256)",
            ["address"],
            [TOKEN],
            ["uint256", "uint256"],
            [10**18, 10**20],
            "Mint",
            {"amount0": 10**18, "amount1": 10**20},
        ),
        (
            "Sync(uint112,uint112)",
            [],
            [],
            ["uint112", "uint112"],
            [10**18, 10**20],
            "Sync",
            {"reserve0": 10**18, "reserve1": 10**20},
        ),
    ],
)
def test_decode_v2_pair_activity(
    signature, indexed_types, indexed_values, types, values, name, expected
):
    log = log_fixture(signature, indexed_types, indexed_values, types, values)
    log["address"] = PAIR

    assert decode_log(log, "v2") == {
        "name": name,
        "pool_key": PAIR,
        "source": "v2",
        "data": expected,
    }


def test_decode_optional_v3_factory():
    log = log_fixture(
        "PoolCreated(address,address,uint24,int24,address)",
        ["address", "address", "uint24"],
        [TOKEN, OTHER, 500],
        ["int24", "address"],
        [10, PAIR],
    )

    assert decode_log(log, "v3_factory") == {
        "name": "PoolCreated",
        "pool_key": PAIR,
        "source": "v3",
        "data": {
            "token0": TOKEN,
            "token1": OTHER,
            "fee": 500,
            "tick_spacing": 10,
            "pool": PAIR,
        },
    }


@pytest.mark.parametrize(
    "mutation", ["missing_topic", "short_topic", "short_data", "extra_data"]
)
def test_malformed_known_event_is_not_silently_discarded(mutation):
    log = log_fixture("Sync(uint112,uint112)", [], [], ["uint112", "uint112"], [1, 2])
    if mutation == "missing_topic":
        log["topics"].append(encoded(["address"], [TOKEN]))
    elif mutation == "short_topic":
        log["topics"] = [
            TOPICS["Initialize"],
            "0x12",
            encoded(["address"], [TOKEN]),
            encoded(["address"], [OTHER]),
        ]
        log["data"] = encoded(
            ["uint24", "int24", "address", "uint160", "int24"],
            [3000, 60, PAIR, 2**96, 0],
        )
    elif mutation == "short_data":
        log["data"] = log["data"][:-2]
    else:
        log["data"] += "00" * 32

    with pytest.raises(ValueError, match="Malformed"):
        decode_log(log, "v4" if mutation == "short_topic" else "v2")


def test_unknown_topic_is_ignored_but_unknown_source_errors():
    log = log_fixture("Unrelated(uint256)", [], [], ["uint256"], [1])
    assert decode_log(log, "v4") is None
    with pytest.raises(ValueError, match="Unsupported event source"):
        decode_log(log, "unregistered")
