"""Tests for Telegram multichain support and chain_info utilities."""

import pytest
from utils.chain_info import (
    get_chain_name,
    get_explorer_url,
    get_dexscreener_slug,
    get_native_symbol,
    parse_chain_prefix,
)


class TestParseChainPrefix:
    """Tests for parse_chain_prefix()."""

    def test_eth_prefix(self):
        chain_id, address = parse_chain_prefix("eth:0xabc123")
        assert chain_id == 1
        assert address == "0xabc123"

    def test_base_prefix(self):
        chain_id, address = parse_chain_prefix("base:0xdef456")
        assert chain_id == 8453
        assert address == "0xdef456"

    def test_bsc_prefix(self):
        chain_id, address = parse_chain_prefix("bsc:0x123456")
        assert chain_id == 56
        assert address == "0x123456"

    def test_bnb_alias(self):
        chain_id, address = parse_chain_prefix("bnb:0x789")
        assert chain_id == 56
        assert address == "0x789"

    def test_no_prefix(self):
        chain_id, address = parse_chain_prefix("0xabc123")
        assert chain_id is None
        assert address == "0xabc123"

    def test_unknown_prefix(self):
        chain_id, address = parse_chain_prefix("sol:0xabc123")
        assert chain_id is None
        assert address == "sol:0xabc123"

    def test_case_insensitive(self):
        chain_id, address = parse_chain_prefix("ETH:0xabc")
        assert chain_id == 1
        assert address == "0xabc"

    def test_whitespace_handling(self):
        chain_id, address = parse_chain_prefix("  eth : 0xabc  ")
        assert chain_id == 1
        assert address == "0xabc"

    def test_opbnb_prefix(self):
        chain_id, address = parse_chain_prefix("opbnb:0xabc")
        assert chain_id == 204
        assert address == "0xabc"


class TestChainInfoHelpers:
    """Tests for chain info helper functions."""

    def test_get_chain_name_bsc(self):
        assert get_chain_name(56) == "BSC"

    def test_get_chain_name_eth(self):
        assert get_chain_name(1) == "Ethereum"

    def test_get_chain_name_base(self):
        assert get_chain_name(8453) == "Base"

    def test_get_chain_name_unknown(self):
        assert get_chain_name(999) == "Chain 999"

    def test_explorer_url_bsc(self):
        assert get_explorer_url(56) == "https://bscscan.com"

    def test_explorer_url_eth(self):
        assert get_explorer_url(1) == "https://etherscan.io"

    def test_explorer_url_base(self):
        assert get_explorer_url(8453) == "https://basescan.org"

    def test_dexscreener_slug_bsc(self):
        assert get_dexscreener_slug(56) == "bsc"

    def test_dexscreener_slug_eth(self):
        assert get_dexscreener_slug(1) == "ethereum"

    def test_dexscreener_slug_base(self):
        assert get_dexscreener_slug(8453) == "base"

    def test_native_symbol_bsc(self):
        assert get_native_symbol(56) == "BNB"

    def test_native_symbol_eth(self):
        assert get_native_symbol(1) == "ETH"

    def test_native_symbol_base(self):
        assert get_native_symbol(8453) == "ETH"

    def test_native_symbol_opbnb(self):
        assert get_native_symbol(204) == "BNB"
