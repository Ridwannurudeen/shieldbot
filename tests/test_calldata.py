"""Tests for utils/calldata_decoder.py — selector decoding, router whitelist, raw fallback."""

import pytest
from utils.calldata_decoder import CalldataDecoder, WHITELISTED_ROUTERS


@pytest.fixture
def decoder():
    return CalldataDecoder()


class TestKnownSelectors:
    def test_approve_selector(self, decoder):
        # approve(address, uint256)
        spender = "0000000000000000000000001234567890abcdef1234567890abcdef12345678"
        amount = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        calldata = "0x095ea7b3" + spender + amount
        result = decoder.decode(calldata)

        assert result["selector"] == "095ea7b3"
        assert result["function_name"] == "approve"
        assert result["category"] == "approval"
        assert result["is_approval"] is True
        assert result["is_unlimited_approval"] is True

    def test_approve_limited_amount(self, decoder):
        spender = "0000000000000000000000001234567890abcdef1234567890abcdef12345678"
        # 1000 tokens (small amount, not unlimited)
        amount = "00000000000000000000000000000000000000000000000000000000000003e8"
        calldata = "0x095ea7b3" + spender + amount
        result = decoder.decode(calldata)

        assert result["is_approval"] is True
        assert result["is_unlimited_approval"] is False

    def test_transfer_selector(self, decoder):
        recipient = "0000000000000000000000001234567890abcdef1234567890abcdef12345678"
        amount = "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
        calldata = "0xa9059cbb" + recipient + amount
        result = decoder.decode(calldata)

        assert result["function_name"] == "transfer"
        assert result["category"] == "transfer"
        assert result["is_approval"] is False

    def test_swap_exact_eth_for_tokens(self, decoder):
        # Just the selector + some padding
        calldata = "0x7ff36ab5" + "0" * 256
        result = decoder.decode(calldata)

        assert result["function_name"] == "swapExactETHForTokens"
        assert result["category"] == "swap"
        assert result["risk"] == "low"


class TestWhitelistedRouters:
    def test_pancakeswap_v2_whitelisted(self, decoder):
        router = "0x10ED43C718714eb63d5aA57B78B54704E256024E"
        name = decoder.is_whitelisted_target(router)
        assert name == "PancakeSwap V2 Router"

    def test_pancakeswap_v3_whitelisted(self, decoder):
        router = "0x13f4EA83D0bd40E75C8222255bc855a974568Dd4"
        name = decoder.is_whitelisted_target(router)
        assert name == "PancakeSwap V3 Smart Router"

    def test_1inch_v5_whitelisted(self, decoder):
        router = "0x1111111254EEB25477B68fb85Ed929f73A960582"
        name = decoder.is_whitelisted_target(router)
        assert name == "1inch V5 Router"

    def test_unknown_address_not_whitelisted(self, decoder):
        assert decoder.is_whitelisted_target("0xdeadbeef12345678") is None

    def test_none_address(self, decoder):
        assert decoder.is_whitelisted_target(None) is None


class TestUnknownSelector:
    def test_unknown_selector_raw_fallback(self, decoder):
        calldata = "0xdeadbeef" + "ab" * 32
        result = decoder.decode(calldata)

        assert result["selector"] == "deadbeef"
        assert result["function_name"].startswith("Unknown")
        assert result["category"] == "unknown"
        assert result["risk"] == "high"
        # Should have raw word params
        assert "word_0" in result["params"]

    def test_empty_calldata(self, decoder):
        result = decoder.decode("0x")
        assert result["function_name"] == "Native Transfer"
        assert result["category"] == "transfer"
        assert result["risk"] == "low"

    def test_none_calldata(self, decoder):
        result = decoder.decode(None)
        assert result["function_name"] == "Native Transfer"

    def test_truncated_calldata(self, decoder):
        result = decoder.decode("0xdead")
        assert result["function_name"] == "Unknown (truncated)"
        assert result["risk"] == "high"
