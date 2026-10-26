"""Record the BOT Chain simulator's JSON-RPC exchanges against https://rpc.botchain.ai at one block.

Read only: eth_call, eth_getBlockByNumber and eth_simulateV1, each POST with a 30 s timeout and the
User-Agent shieldbot-r2. Every "latest" the simulator asks for is sent as the base block, and its random
buyer, receiver and payer are the three fixed addresses RECORDING.md proves empty at that block. Hex
runs of 64 or more digits are written with an underscore after every 32 digits (see `encode`), so no
fixture line holds a 64 digit hex literal; tests/test_botchain_simulation.py removes them on load.

Usage, from the repository root: python tests/fixtures/botchain_simulation/record.py <base block number>
"""

import asyncio
import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from eth_abi import decode  # noqa: E402

from services import botchain_simulation  # noqa: E402
from services.botchain_simulation import (  # noqa: E402
    CONFIRMATION_DELAY_SECONDS,
    RPC_URL,
    BotChainSimulator,
    Pool,
)

HERE = Path(__file__).parent
BUYER = "0xb07b07b07b07b07b07b07b07b07b07b07b07b001"
RECEIVER = "0xb07b07b07b07b07b07b07b07b07b07b07b07b002"
PAYER = "0xb07b07b07b07b07b07b07b07b07b07b07b07b003"
LONG_HEX = re.compile(r"0x[0-9a-fA-F]{64,}")

CASES = {
    "cow": "0x5af9a0e7472134a6a5ad02a7d327e83ddd24b337",
    "usdt": "0xababc7ddc03e501d190c676bf3d92ef0e6e87a3c",
    "lk2e": "0x04bbf9ec920e8996bb96e5c451f621e5df6d9999",
    "no_pool": "0x68caea9104419203cf8b8f0b222e75709b97bfc6",
}


def encode(value):
    if isinstance(value, dict):
        return {key: encode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [encode(item) for item in value]
    if isinstance(value, str):
        return LONG_HEX.sub(_split, value)
    return value


def _split(match):
    digits = match.group()[2:]
    return "0x" + "_".join(digits[i : i + 32] for i in range(0, len(digits), 32))


def at_block(params, block_tag):
    return [block_tag if param == "latest" else param for param in params]


def rpc(body):
    request = urllib.request.Request(
        RPC_URL,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "shieldbot-r2"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def recorder(block_tag, exchanges):
    async def post(session, calls, url=None, timeout=None):
        body = [
            {
                "jsonrpc": "2.0",
                "id": index,
                "method": method,
                "params": at_block(params, block_tag),
            }
            for index, (method, params) in enumerate(calls)
        ]
        started = time.monotonic()
        payload = rpc(body if len(body) > 1 else body[0])
        print(f"  {', '.join(method for method, _ in calls)}: {time.monotonic() - started:.2f} s")
        rows = payload if isinstance(payload, list) else [payload]
        rows = sorted(rows, key=lambda row: row["id"])
        exchanges.append({"calls": [list(call) for call in calls], "response": rows})
        return rows

    return post


def addresses():
    return patch.object(
        botchain_simulation, "_fresh_address", side_effect=[BUYER, RECEIVER, PAYER] * 20
    )


async def record_case(name, token, block_tag):
    exchanges = []
    simulator = BotChainSimulator()
    simulator._post = recorder(block_tag, exchanges)
    with addresses():
        result = await simulator.simulate(token)
    result.pop("observed_at")
    return {"token": token, "exchanges": exchanges, "result": result}


async def record_confirmation(block_tag, cow):
    """A confirmation run on COW's pool, the deepest found, sized to the balance the first run delivered."""
    exchanges = []
    simulator = BotChainSimulator()
    simulator._post = recorder(block_tag, exchanges)
    discovery = cow["exchanges"][1]["calls"]
    header = cow["exchanges"][1]["response"][-1]["result"]
    source = (int(header["number"], 16), int(header["timestamp"], 16))
    pool_address = discovery[0][1][0]["to"]
    token = cow["token"]
    reserves = decode(
        ["uint112", "uint112", "uint32"],
        bytes.fromhex(cow["exchanges"][1]["response"][0]["result"][2:]),
    )
    depth = reserves[0] if botchain_simulation.WBOT < token else reserves[1]
    pool = Pool("BDEX", pool_address, None, depth)
    first = cow["exchanges"][2]["response"][0]["result"][0]["calls"][1]["returnData"]
    sell_amount = int(first, 16)
    with patch.object(
        botchain_simulation, "_fresh_address", side_effect=[BUYER, RECEIVER, PAYER]
    ):
        outcome = await simulator._simulate_pool(
            None,
            pool,
            token,
            botchain_simulation.buy_amount(depth),
            source,
            sell_amount,
            confirm=True,
        )
    return {
        "token": token,
        "pool": pool_address,
        "depth": depth,
        "sell_amount": sell_amount,
        "source": list(source),
        "sell_time": source[1] + CONFIRMATION_DELAY_SECONDS,
        "exchanges": exchanges,
        "outcome": outcome,
    }


async def main(block):
    block_tag = hex(block)
    recorded = {}
    for name, token in CASES.items():
        recorded[name] = await record_case(name, token, block_tag)
        (HERE / f"{name}.json").write_text(
            json.dumps(encode(recorded[name]), indent=1) + "\n", encoding="utf-8"
        )
        print(name, recorded[name]["result"]["reason"])
    confirmation = await record_confirmation(block_tag, recorded["cow"])
    (HERE / "cow_confirmation.json").write_text(
        json.dumps(encode(confirmation), indent=1) + "\n", encoding="utf-8"
    )
    print("cow_confirmation", confirmation["outcome"]["reason"])


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1], 0)))
