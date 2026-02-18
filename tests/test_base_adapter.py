"""Tests for Base chain adapter."""

from adapters.base_chain import BaseChainAdapter, WHITELISTED_ROUTERS


def test_base_adapter_chain_id():
    adapter = BaseChainAdapter(rpc_url="https://mainnet.base.org")
    assert adapter.chain_id == 8453


def test_base_adapter_chain_name():
    adapter = BaseChainAdapter(rpc_url="https://mainnet.base.org")
    assert adapter.chain_name == "Base"


def test_base_whitelisted_routers():
    adapter = BaseChainAdapter(rpc_url="https://mainnet.base.org")
    routers = adapter.get_whitelisted_routers()
    # Aerodrome should be present
    aerodrome = "0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43".lower()
    assert aerodrome in routers
    assert "Aerodrome" in routers[aerodrome]


def test_base_adapter_honeypot_chain_id():
    adapter = BaseChainAdapter(rpc_url="https://mainnet.base.org")
    assert adapter._honeypot_chain_id == 8453
