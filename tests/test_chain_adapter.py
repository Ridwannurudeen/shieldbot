"""Tests for ChainAdapter interface and BscAdapter."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from adapters.bsc import BscAdapter, WHITELISTED_ROUTERS, KNOWN_LOCKERS


class TestBscAdapterProperties:
    def test_chain_id(self):
        adapter = BscAdapter(rpc_url="https://bsc-dataseed1.binance.org/")
        assert adapter.chain_id == 56

    def test_chain_name(self):
        adapter = BscAdapter(rpc_url="https://bsc-dataseed1.binance.org/")
        assert adapter.chain_name == "BSC"

    def test_whitelisted_routers(self):
        adapter = BscAdapter(rpc_url="https://bsc-dataseed1.binance.org/")
        routers = adapter.get_whitelisted_routers()
        assert "0x10ed43c718714eb63d5aa57b78b54704e256024e" in routers
        assert routers["0x10ed43c718714eb63d5aa57b78b54704e256024e"] == "PancakeSwap V2 Router"


class TestBscConstants:
    def test_known_lockers_has_burn_address(self):
        assert '0x0000000000000000000000000000000000000000' in KNOWN_LOCKERS

    def test_whitelisted_routers_count(self):
        assert len(WHITELISTED_ROUTERS) == 6


class TestCalldataDecoderChainId:
    def test_whitelisted_target_bsc(self):
        from utils.calldata_decoder import CalldataDecoder
        decoder = CalldataDecoder()
        result = decoder.is_whitelisted_target(
            "0x10ED43C718714eb63d5aA57B78B54704E256024E", chain_id=56
        )
        assert result == "PancakeSwap V2 Router"

    def test_whitelisted_target_other_chain_returns_none(self):
        from utils.calldata_decoder import CalldataDecoder
        decoder = CalldataDecoder()
        result = decoder.is_whitelisted_target(
            "0x10ED43C718714eb63d5aA57B78B54704E256024E", chain_id=1
        )
        assert result is None

    def test_whitelisted_target_default_chain_id(self):
        from utils.calldata_decoder import CalldataDecoder
        decoder = CalldataDecoder()
        # Default chain_id=56 should work
        result = decoder.is_whitelisted_target(
            "0x10ED43C718714eb63d5aA57B78B54704E256024E"
        )
        assert result == "PancakeSwap V2 Router"
