"""Canonical Uniswap event decoding; addresses and identifiers are lowercase."""

from eth_abi import decode
from eth_utils import keccak

CHAIN_ID = 4663
RPC_URL = "https://rpc.mainnet.chain.robinhood.com"
POOL_MANAGER = "0x8366a39cc670b4001a1121b8f6a443a643e40951"
V2_FACTORY = "0x8bceaa40b9acdfaedf85adf4ff01f5ad6517937f"
WETH = "0x0bd7d308f8e1639fab988df18a8011f41eacad73"
ZERO = "0x" + "0" * 40

# Source ABIs (indexed fields verified against these interfaces):
# https://github.com/Uniswap/v4-core/blob/main/src/interfaces/IPoolManager.sol
# https://github.com/Uniswap/v2-core/blob/master/contracts/interfaces/IUniswapV2Factory.sol
# https://github.com/Uniswap/v2-core/blob/master/contracts/interfaces/IUniswapV2Pair.sol
# https://github.com/Uniswap/v3-core/blob/main/contracts/interfaces/IUniswapV3Factory.sol
SIGNATURES = {
    "Initialize": "Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)",
    "ModifyLiquidity": "ModifyLiquidity(bytes32,address,int24,int24,int256,bytes32)",
    "SwapV4": "Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)",
    "PairCreated": "PairCreated(address,address,address,uint256)",
    "SwapV2": "Swap(address,uint256,uint256,uint256,uint256,address)",
    "Mint": "Mint(address,uint256,uint256)",
    "Sync": "Sync(uint112,uint112)",
    "PoolCreated": "PoolCreated(address,address,uint24,int24,address)",
    "Transfer": "Transfer(address,address,uint256)",
}
TOPICS = {name: "0x" + keccak(text=sig).hex() for name, sig in SIGNATURES.items()}


def decode_log(log, source):
    topics = [topic.lower() for topic in log["topics"]]
    if not topics:
        return None
    definitions = {
        "v4": {
            "Initialize": (
                4,
                ["uint24", "int24", "address", "uint160", "int24"],
                ["fee", "tick_spacing", "hooks", "sqrt_price_x96", "tick"],
            ),
            "ModifyLiquidity": (
                3,
                ["int24", "int24", "int256", "bytes32"],
                ["tick_lower", "tick_upper", "liquidity_delta", "salt"],
            ),
            "SwapV4": (
                3,
                ["int128", "int128", "uint160", "uint128", "int24", "uint24"],
                ["amount0", "amount1", "sqrt_price_x96", "liquidity", "tick", "fee"],
            ),
        },
        "v2_factory": {
            "PairCreated": (3, ["address", "uint256"], ["pair", "pair_count"])
        },
        "v2": {
            "SwapV2": (
                3,
                ["uint256"] * 4,
                ["amount0_in", "amount1_in", "amount0_out", "amount1_out"],
            ),
            "Mint": (2, ["uint256", "uint256"], ["amount0", "amount1"]),
            "Sync": (1, ["uint112", "uint112"], ["reserve0", "reserve1"]),
        },
        "v3_factory": {
            "PoolCreated": (4, ["int24", "address"], ["tick_spacing", "pool"])
        },
    }
    if source not in definitions:
        raise ValueError(f"Unsupported event source: {source}")
    for name, (count, types, fields) in definitions[source].items():
        if topics[0] != TOPICS[name]:
            continue
        if len(topics) != count or len(bytes.fromhex(log["data"][2:])) != 32 * len(
            types
        ):
            raise ValueError(f"Malformed {name} log")
        for topic in topics:
            if len(bytes.fromhex(topic[2:])) != 32:
                raise ValueError(f"Malformed {name} topic")
        data = dict(zip(fields, decode(types, bytes.fromhex(log["data"][2:]))))
        data = {
            key: "0x" + value.hex() if isinstance(value, bytes) else value
            for key, value in data.items()
        }
        if source == "v4":
            pool_key = topics[1]
            data["pool_id"] = pool_key
            if name == "Initialize":
                data["currency0"] = decode(["address"], bytes.fromhex(topics[2][2:]))[0]
                data["currency1"] = decode(["address"], bytes.fromhex(topics[3][2:]))[0]
            else:
                data["sender"] = decode(["address"], bytes.fromhex(topics[2][2:]))[0]
        elif source in ("v2_factory", "v3_factory"):
            data["token0"] = decode(["address"], bytes.fromhex(topics[1][2:]))[0]
            data["token1"] = decode(["address"], bytes.fromhex(topics[2][2:]))[0]
            pool_key = data["pair" if source == "v2_factory" else "pool"]
            if source == "v3_factory":
                data["fee"] = decode(["uint24"], bytes.fromhex(topics[3][2:]))[0]
        else:
            pool_key = log["address"].lower()
        return {
            "name": "Swap" if name in ("SwapV4", "SwapV2") else name,
            "pool_key": pool_key,
            "source": source.replace("_factory", ""),
            "data": data,
        }
    return None
