#!/usr/bin/env python3
"""Check that every allowlisted router and liquidity locker has contract code on its chain.

Read-only network check (eth_getCode through each adapter's RPC), run by hand from the repo root:

    python -m scripts.check_allowlist_code > tests/fixtures/allowlist_code.json

Prints every checked address as JSON, the format of the offline test's fixture, and exits 1 when
any address has no code. The burn and dead addresses in the locker lists hold burned LP tokens
and have no code by design, so they are not checked.
"""

import json
import sys
import time
from datetime import datetime, timezone

from web3 import Web3

from adapters.arbitrum import ArbitrumAdapter
from adapters.base_chain import BaseChainAdapter
from adapters.bsc import BscAdapter
from adapters.eth import EthAdapter
from adapters.evm_base import BURN_ADDRESSES
from adapters.opbnb import OpBNBAdapter
from adapters.optimism import OptimismAdapter
from adapters.polygon import PolygonAdapter
from adapters.robinhood import RobinhoodAdapter

ADAPTERS = (
    BscAdapter,
    OpBNBAdapter,
    EthAdapter,
    BaseChainAdapter,
    ArbitrumAdapter,
    PolygonAdapter,
    OptimismAdapter,
    RobinhoodAdapter,
)
# Public RPCs refuse bursts: mainnet.base.org answered 429 to back-to-back calls.
REQUEST_SPACING_SECONDS = 1.0


def allowlisted(adapter):
    """(address, kind, label) for every router and non-burn locker the adapter trusts."""
    rows = [
        (address, "router", label) for address, label in adapter.get_whitelisted_routers().items()
    ]
    rows += [
        (address, "locker", label)
        for address, label in adapter._known_lockers.items()
        if address not in BURN_ADDRESSES
    ]
    return rows


def main():
    rows = []
    for adapter in (adapter_class() for adapter_class in ADAPTERS):
        for address, kind, label in allowlisted(adapter):
            code = adapter.w3.eth.get_code(Web3.to_checksum_address(address))
            time.sleep(REQUEST_SPACING_SECONDS)
            rows.append(
                {
                    "chain_id": adapter.chain_id,
                    "address": address,
                    "kind": kind,
                    "label": label,
                    "code_size": len(code),
                }
            )
    json.dump(
        {
            "checked_on": datetime.now(timezone.utc).date().isoformat(),
            "addresses": rows,
        },
        sys.stdout,
        indent=2,
    )
    print()
    missing = [row for row in rows if row["code_size"] == 0]
    for row in missing:
        print(
            f"NO CODE on chain {row['chain_id']}: {row['kind']} {row['label']} {row['address']}",
            file=sys.stderr,
        )
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
