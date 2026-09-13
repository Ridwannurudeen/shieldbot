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


@pytest.fixture
def bot_chain_functions():
    import ast
    from pathlib import Path
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from utils.web3_client import Web3Client

    # Load the real menu handlers without importing the optional Telegram package.
    tree = ast.parse(Path('bot.py').read_text(encoding='utf-8'))
    names = {'_get_user_chain_id', 'chain_command', 'button_callback', 'help_command'}
    module = ast.Module(body=[node for node in tree.body if isinstance(
        node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names], type_ignores=[])
    client = Web3Client.__new__(Web3Client)
    client._adapters = {56: MagicMock(), 4663: MagicMock()}
    namespace = {
        'Update': object,
        'ContextTypes': SimpleNamespace(DEFAULT_TYPE=object),
        'InlineKeyboardButton': lambda text, **kwargs: SimpleNamespace(text=text, **kwargs),
        'InlineKeyboardMarkup': lambda keyboard: SimpleNamespace(inline_keyboard=keyboard),
        'web3_client': client,
        'get_chain_name': get_chain_name,
        'parse_chain_prefix': parse_chain_prefix,
    }
    exec(compile(module, 'bot.py', 'exec'), namespace)
    return namespace


@pytest.mark.asyncio
async def test_bot_menu_uses_registered_chains(bot_chain_functions):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    context = SimpleNamespace(user_data={}, args=[])
    await bot_chain_functions['chain_command'](update, context)
    keyboard = update.message.reply_text.call_args.kwargs['reply_markup'].inline_keyboard
    assert [row[0].callback_data for row in keyboard] == ['chain_56', 'chain_4663']


@pytest.mark.asyncio
@pytest.mark.parametrize('selection', ['chain_999999', 'chain_invalid'])
async def test_bot_rejects_unregistered_chain_selection(bot_chain_functions, selection):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    query = SimpleNamespace(data=selection, answer=AsyncMock(), edit_message_text=AsyncMock())
    context = SimpleNamespace(user_data={'chain_id': 56})
    await bot_chain_functions['button_callback'](SimpleNamespace(callback_query=query), context)
    assert context.user_data['chain_id'] == 56
    assert 'Supported' in query.edit_message_text.call_args.args[0]


@pytest.mark.parametrize('prefix', ['robinhood', 'rh'])
def test_robinhood_prefix(prefix):
    assert parse_chain_prefix(prefix + ':0xabc') == (4663, '0xabc')


def test_robinhood_metadata():
    assert get_chain_name(4663) == 'Robinhood Chain'
    assert get_explorer_url(4663) == 'https://robinhoodchain.blockscout.com'
    assert get_dexscreener_slug(4663) == 'robinhood'
    assert get_native_symbol(4663) == 'ETH'


@pytest.mark.parametrize('lookup', [get_explorer_url, get_dexscreener_slug, get_native_symbol])
def test_unknown_chain_metadata_does_not_fall_back(lookup):
    assert lookup(999999) is None


@pytest.mark.asyncio
@pytest.mark.parametrize('argument,expected', [('999999', 56), ('invalid', 56), ('1', 56), ('4663', 4663), ('rh', 4663)])
async def test_chain_command_validates_argument(bot_chain_functions, argument, expected):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    context = SimpleNamespace(user_data={'chain_id': 56}, args=[argument])
    await bot_chain_functions['chain_command'](update, context)
    assert context.user_data['chain_id'] == expected
    message = update.message.reply_text.call_args.args[0]
    assert ('Switched' if expected == 4663 else 'Supported') in message


@pytest.mark.asyncio
async def test_bot_help_lists_registry(bot_chain_functions):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    await bot_chain_functions['help_command'](update, SimpleNamespace())
    message = update.message.reply_text.call_args.args[0]
    assert 'Supported: BSC, Robinhood Chain' in message
    assert 'Supported: BSC, Ethereum' not in message
