#!/usr/bin/env python3
"""Check that the public Blockscout instances still date contracts on Base and Optimism.

Read-only network check, run by hand from the repo root:

    python -m scripts.check_blockscout_instances

Looks up native USDC on each chain through the adapter's own path (the explorer service for the
creation transaction, then the chain's RPC for its block time) and exits 1 unless the creation time
is the known one. An instance that moves answers with a redirect, which the explorer service does
not follow, so a move shows up here as a missing creation.
"""

import asyncio
import sys
from datetime import datetime, timezone

from adapters.base_chain import BaseChainAdapter
from adapters.optimism import OptimismAdapter

# Native USDC on each chain and the timestamp of its creation block, read on 2026-09-24.
KNOWN_CREATIONS = (
    (BaseChainAdapter, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "2023-08-18T18:36:29+00:00"),
    (OptimismAdapter, "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "2022-11-14T19:15:18+00:00"),
)


async def main():
    failed = False
    for adapter_class, token, created in KNOWN_CREATIONS:
        adapter = adapter_class()
        info = await adapter.get_contract_creation_info(token)
        expected_age = (datetime.now(timezone.utc) - datetime.fromisoformat(created)).days
        ok = (
            info is not None
            and info["creation_time"] == created
            and info["age_days"] == expected_age
        )
        print(
            f"{adapter.chain_name} ({adapter.chain_id}) USDC {token}: {'OK' if ok else 'FAIL'} {info}"
        )
        failed = failed or not ok
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
