"""utils/chain_info.py CHAIN_INFO is the one table of chain facts the Python code reads.

The chain lists the services keep are derived from it. Each derived value is pinned here to the
literal it replaced, so an edit to CHAIN_INFO that changes what a service does fails here first.
"""

import pytest

from tests.test_bot_app import bot_module  # noqa: F401  (pytest fixture)
from utils.chain_info import CHAIN_INFO

FIELDS = {
    "name",
    "explorer_url",
    "dexscreener_slug",
    "native_symbol",
    "explorer_backend",
    "blockscout_instance",
    "pending_transactions",
    "token_sniffer",
    "public_log_window_blocks",
    "picker_order",
}


def test_every_chain_states_every_fact():
    for chain_id, info in CHAIN_INFO.items():
        assert set(info) == FIELDS, chain_id


def test_explorer_backends():
    from adapters.evm_base import _get_explorer_backend

    assert {chain_id: _get_explorer_backend(chain_id) for chain_id in CHAIN_INFO} == {
        1: "etherscan",
        56: "etherscan",
        8453: "etherscan_blockscout",
        42161: "etherscan",
        137: "etherscan",
        10: "etherscan_blockscout",
        204: "etherscan",
        4663: "sourcify_blockscout",
    }
    with pytest.raises(ValueError, match="Unsupported explorer chain: 999"):
        _get_explorer_backend(999)


def test_blockscout_instances():
    from services.explorer_service import BLOCKSCOUT_INSTANCES

    assert BLOCKSCOUT_INSTANCES == {
        8453: "https://base.blockscout.com",
        10: "https://explorer.optimism.io",
    }


def test_pending_transaction_chains():
    from services.mempool_service import PENDING_TRANSACTION_CHAINS

    assert PENDING_TRANSACTION_CHAINS == frozenset({56, 1, 137, 204})
    assert isinstance(PENDING_TRANSACTION_CHAINS, frozenset)


def test_token_sniffer_chains():
    from services.token_sniffer_service import SUPPORTED_CHAIN_IDS

    assert SUPPORTED_CHAIN_IDS == {56, 1, 137, 42161, 8453, 10, 204}


def test_public_log_windows():
    from services.rescue_service import PUBLIC_LOG_WINDOW_BLOCKS

    assert PUBLIC_LOG_WINDOW_BLOCKS == {8453: 2_000, 42161: 500_000}


def test_picker_chain_order(bot_module):
    orders = [info["picker_order"] for info in CHAIN_INFO.values()]
    assert len(orders) == len(set(orders))
    assert bot_module.PICKER_CHAIN_ORDER == (1, 56, 204, 8453, 42161, 137, 10, 4663)
