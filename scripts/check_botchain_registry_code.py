#!/usr/bin/env python3
"""Check that the BOT Chain verdict registry runs this repository's source, while BOT Chain's
explorer cannot verify it.

Read-only network check, run by hand from the repo root after building the contracts:

    (cd contracts/base && forge build) && python -m scripts.check_botchain_registry_code

Reads the registry's runtime code on BOT Chain (677) and on Robinhood Chain (4663) through each
adapter's RPC, compares both with the deployedBytecode Foundry built from
contracts/base/src/ShieldBotVerdictRegistry.sol, and reads Sourcify's match for the Robinhood Chain
copy. The contract has no immutables, so the comparison is byte for byte, metadata hash included.
Prints the result as JSON and exits 1 unless both chains run the built code and Sourcify reports an
exact match for creation and runtime code.
"""

import json
import sys
from pathlib import Path

import requests
from web3 import Web3

from adapters.botchain import BotChainAdapter
from adapters.robinhood import RobinhoodAdapter

REGISTRY = "0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138"
ARTIFACT = (
    Path(__file__).resolve().parent.parent
    / "contracts/base/out/ShieldBotVerdictRegistry.sol/ShieldBotVerdictRegistry.json"
)
SOURCIFY_URL = f"https://sourcify.dev/server/v2/contract/4663/{REGISTRY}"


def main():
    built = json.loads(ARTIFACT.read_text(encoding="utf-8"))["deployedBytecode"][
        "object"
    ]
    built_code = bytes.fromhex(built.removeprefix("0x"))
    chains = []
    for adapter in (BotChainAdapter(), RobinhoodAdapter()):
        code = bytes(adapter.w3.eth.get_code(REGISTRY))
        chains.append(
            {
                "chain_id": adapter.chain_id,
                "code_size": len(code),
                "code_keccak": Web3.keccak(code).hex(),
                "matches_build": code == built_code,
            }
        )
    sourcify = requests.get(SOURCIFY_URL, timeout=30).json()
    exact = (
        sourcify.get("creationMatch") == sourcify.get("runtimeMatch") == "exact_match"
    )
    json.dump(
        {
            "registry": REGISTRY,
            "build_keccak": Web3.keccak(built_code).hex(),
            "chains": chains,
            "sourcify_4663": {
                "creationMatch": sourcify.get("creationMatch"),
                "runtimeMatch": sourcify.get("runtimeMatch"),
                "url": SOURCIFY_URL,
            },
        },
        sys.stdout,
        indent=2,
    )
    print()
    return 0 if exact and all(chain["matches_build"] for chain in chains) else 1


if __name__ == "__main__":
    sys.exit(main())
