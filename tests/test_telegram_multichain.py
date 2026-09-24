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
    from unittest.mock import AsyncMock, MagicMock
    import asyncio
    from utils.web3_client import UnsupportedChainError, Web3Client
    from core.extension_formatter import is_scan_incomplete
    from services.mempool_service import supports_pending_transactions

    # Load the real menu handlers without importing the optional Telegram package.
    tree = ast.parse(Path('bot.py').read_text(encoding='utf-8'))
    names = {'_get_user_chain_id', 'chain_command', 'button_callback', 'help_command',
             'scan_contract', 'check_token', 'handle_address', '_handle_advisor_chat',
             'threats_command', 'rescue_command', '_scan_buttons', '_token_buttons',
             'scan_command', 'token_command', 'error_handler'}
    module = ast.Module(body=[node for node in tree.body if isinstance(
        node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names], type_ignores=[])
    client = Web3Client.__new__(Web3Client)
    client._adapters = {56: MagicMock(), 4663: MagicMock()}
    client.get_token_info = AsyncMock(return_value={})
    client.is_token_contract = AsyncMock(return_value=False)
    services = MagicMock()
    services.registry.run_all = AsyncMock(return_value=[])
    services.advisor.chat = AsyncMock(return_value={'text': 'Analysis complete.'})
    services.rescue_service.scan_approvals = AsyncMock(return_value={})
    ai = MagicMock()
    ai.generate_forensic_report = AsyncMock(return_value='Analysis')
    recorder = MagicMock()
    recorder.is_available.return_value = False
    namespace = {
        'asyncio': asyncio,
        'is_scan_incomplete': is_scan_incomplete,
        'UnsupportedChainError': UnsupportedChainError,
        'logger': MagicMock(),
        'container': services,
        'ai_analyzer': ai,
        'risk_engine': MagicMock(compute_from_results=MagicMock(return_value={
            'status': 'ok', 'coverage': {'structural': 1, 'honeypot': 1},
            'risk_level': 'LOW', 'rug_probability': 0,
        })),
        'onchain_recorder': recorder,
        'base_attestor': recorder,
        'tx_scanner': SimpleNamespace(scan_address=AsyncMock(return_value={})),
        'token_scanner': SimpleNamespace(check_token=AsyncMock(return_value={})),
        '_get_cached': MagicMock(return_value=None),
        '_set_cache': MagicMock(),
        'format_full_report': MagicMock(return_value='Report'),
        'get_explorer_url': get_explorer_url,
        'get_dexscreener_slug': get_dexscreener_slug,
        'Update': object,
        'ContextTypes': SimpleNamespace(DEFAULT_TYPE=object),
        'InlineKeyboardButton': lambda text, **kwargs: SimpleNamespace(text=text, **kwargs),
        'InlineKeyboardMarkup': lambda keyboard: SimpleNamespace(inline_keyboard=keyboard),
        'web3_client': client,
        'get_chain_name': get_chain_name,
        'parse_chain_prefix': parse_chain_prefix,
        'supports_pending_transactions': supports_pending_transactions,
        '_fetch_mempool_data': AsyncMock(return_value=([], {})),
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


@pytest.mark.parametrize('chain_id', [999999, 1])
def test_bot_rejects_stale_saved_chain(bot_chain_functions, chain_id):
    from types import SimpleNamespace
    from utils.web3_client import UnsupportedChainError
    with pytest.raises(UnsupportedChainError):
        bot_chain_functions['_get_user_chain_id'](SimpleNamespace(user_data={'chain_id': chain_id}))


@pytest.mark.asyncio
@pytest.mark.parametrize('handler', ['scan_contract', 'check_token'])
async def test_bot_rejects_chain_before_cache_and_scan(bot_chain_functions, handler):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from utils.web3_client import UnsupportedChainError
    ns = bot_chain_functions
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    with pytest.raises(UnsupportedChainError):
        await ns[handler](update, '0x' + 'a' * 40, chain_id=999999)
    ns['_get_cached'].assert_not_called()
    ns['container'].registry.run_all.assert_not_called()
    ns['web3_client'].get_token_info.assert_not_called()
    ns['tx_scanner'].scan_address.assert_not_called()
    ns['token_scanner'].check_token.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('handler', ['scan_contract', 'check_token'])
async def test_bot_never_falls_back_on_routing_error(bot_chain_functions, handler):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from utils.web3_client import UnsupportedChainError
    ns = bot_chain_functions
    ns['container'].registry.run_all.side_effect = UnsupportedChainError('Chain removed')
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    with pytest.raises(UnsupportedChainError):
        await ns[handler](update, '0x' + 'a' * 40, chain_id=4663)
    ns['tx_scanner'].scan_address.assert_not_called()
    ns['token_scanner'].check_token.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('handler', ['scan_contract', 'check_token'])
async def test_bot_forensic_context_names_selected_chain(bot_chain_functions, handler):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    ns = bot_chain_functions
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    await ns[handler](update, '0x' + 'a' * 40, chain_id=4663)
    data = ns['ai_analyzer'].generate_forensic_report.call_args.args[1]
    assert data['chain_id'] == 4663
    assert data['chain_name'] == 'Robinhood Chain'


@pytest.mark.asyncio
async def test_bot_advisor_receives_selected_chain(bot_chain_functions):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    ns = bot_chain_functions
    update = SimpleNamespace(message=SimpleNamespace(text='Explain liquidity', reply_text=AsyncMock()),
                             effective_user=SimpleNamespace(id=123))
    await ns['handle_address'](update, SimpleNamespace(user_data={'chain_id': 4663}))
    ns['container'].advisor.chat.assert_awaited_once_with('tg-123', 'Explain liquidity', chain_id=4663)


@pytest.mark.asyncio
@pytest.mark.parametrize('argument', ['typo', '999999', 'eth'])
async def test_bot_threats_rejects_unknown_selection_before_query(bot_chain_functions, argument):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    ns = bot_chain_functions
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    await ns['threats_command'](update, SimpleNamespace(args=[argument]))
    ns['_fetch_mempool_data'].assert_not_awaited()
    assert 'Unsupported' in update.message.reply_text.call_args.args[0]


@pytest.mark.asyncio
async def test_bot_rejects_removed_prefix_before_saving_or_providers(bot_chain_functions):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from utils.web3_client import UnsupportedChainError
    ns = bot_chain_functions
    update = SimpleNamespace(message=SimpleNamespace(text='eth:0x' + 'a' * 40, reply_text=AsyncMock()))
    context = SimpleNamespace(user_data={'chain_id': 56})
    with pytest.raises(UnsupportedChainError):
        await ns['handle_address'](update, context)
    assert context.user_data['chain_id'] == 56
    ns['web3_client'].is_token_contract.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('handler', ['scan_command', 'token_command', 'rescue_command'])
@pytest.mark.parametrize('argument,chain_id', [('0x' + 'a' * 40, 999999), ('eth:0x' + 'a' * 40, 56)])
async def test_bot_commands_reject_unregistered_chain(bot_chain_functions, handler, argument, chain_id):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from utils.web3_client import UnsupportedChainError
    ns = bot_chain_functions
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    context = SimpleNamespace(args=[argument], user_data={'chain_id': chain_id})
    with pytest.raises(UnsupportedChainError):
        await ns[handler](update, context)
    ns['container'].registry.run_all.assert_not_called()
    ns['container'].rescue_service.scan_approvals.assert_not_called()
    update.message.reply_text.assert_not_called()


@pytest.mark.asyncio
async def test_bot_menu_allows_replacing_removed_saved_chain(bot_chain_functions):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    await bot_chain_functions['chain_command'](update, SimpleNamespace(args=[], user_data={'chain_id': 999999}))
    keyboard = update.message.reply_text.call_args.kwargs['reply_markup'].inline_keyboard
    assert [row[0].callback_data for row in keyboard] == ['chain_56', 'chain_4663']
    assert all('(current)' not in row[0].text for row in keyboard)


@pytest.mark.asyncio
async def test_bot_error_handler_reports_unsupported_chain(bot_chain_functions):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from utils.web3_client import UnsupportedChainError
    message = SimpleNamespace(reply_text=AsyncMock())
    await bot_chain_functions['error_handler'](SimpleNamespace(effective_message=message),
                                             SimpleNamespace(error=UnsupportedChainError('Unsupported chain ID 999999')))
    message.reply_text.assert_awaited_once_with('Unsupported chain ID 999999')


@pytest.fixture
def bot_report_functions(bot_chain_functions):
    import ast
    from pathlib import Path
    from core.extension_formatter import is_scan_incomplete
    from core.telegram_formatter import format_full_report
    tree = ast.parse(Path('bot.py').read_text(encoding='utf-8'))
    names = {'format_scan_result', 'format_token_result'}
    module = ast.Module(body=[node for node in tree.body if isinstance(node, ast.FunctionDef)
                             and node.name in names], type_ignores=[])
    bot_chain_functions['is_scan_incomplete'] = is_scan_incomplete
    bot_chain_functions['format_full_report'] = format_full_report
    exec(compile(module, 'bot.py', 'exec'), bot_chain_functions)
    return bot_chain_functions


@pytest.mark.parametrize('formatter', ['format_scan_result', 'format_token_result'])
@pytest.mark.parametrize('failed_simulation', [False, True])
def test_legacy_bot_unknown_values_never_look_safe(bot_report_functions, formatter, failed_simulation):
    result = {
        'address': '0x' + 'a' * 40, 'status': 'unknown', 'risk_level': 'low',
        'safety_level': 'safe', 'risk_score': 0, 'confidence': 50,
        'coverage': {'structural': 1, 'honeypot': 0.5},
        'is_verified': None, 'contract_age_days': None, 'is_honeypot': None,
        'buy_tax': None, 'sell_tax': None, 'simulation_failed': failed_simulation,
        'checks': {'can_buy': None, 'can_sell': None, 'ownership_renounced': None,
                   'liquidity_locked': None, 'verified_source': None},
        'ai_risk_score': {'risk_score': 0, 'risk_level': 'SAFE', 'recommendation': 'SAFE'},
        'ai_analysis': 'SAFE', 'forensic_report': 'SAFE',
    }
    report = bot_report_functions[formatter](result)
    assert 'Unknown' in report
    for unsafe in ('SAFE', '0/100', 'Not a honeypot', 'not verified', 'Buy: 0%', 'Sell: 0%', '❌ Can Sell'):
        assert unsafe not in report


@pytest.mark.parametrize('formatter', ['format_scan_result', 'format_token_result'])
def test_legacy_bot_complete_results_keep_scores(bot_report_functions, formatter):
    result = {'address': '0x' + 'a' * 40, 'status': 'ok', 'risk_level': 'low',
              'safety_level': 'safe', 'risk_score': 0, 'confidence': 100,
              'coverage': {'structural': 1, 'honeypot': 1}, 'is_verified': True,
              'is_honeypot': False, 'buy_tax': 0, 'sell_tax': 0,
              'checks': {'can_buy': True, 'can_sell': True}}
    report = bot_report_functions[formatter](result)
    assert '0/100' in report
    if formatter == 'format_token_result':
        assert 'SAFE' in report and 'Not a honeypot' in report


@pytest.mark.parametrize('buttons,expected_count', [('_scan_buttons', 1), ('_token_buttons', 0)])
def test_bot_omits_buttons_without_chain_metadata(bot_chain_functions, buttons, expected_count):
    keyboard = bot_chain_functions[buttons]('0xabc', 999999).inline_keyboard
    assert len(keyboard) == expected_count


@pytest.mark.parametrize('status,coverage', [('unknown', {'honeypot': 0}),
                                           ('ok', {'honeypot': 0.5}), ('ok', {})])
def test_formatters_preserve_incomplete_coverage(status, coverage):
    from core.extension_formatter import format_extension_alert
    from core.telegram_formatter import format_full_report
    result = {'status': status, 'coverage': coverage, 'rug_probability': 0,
              'risk_level': 'LOW', 'coverage_reasons': {'honeypot': 'Simulation failed'}}
    alert = format_extension_alert(result)
    assert alert['risk_classification'] != 'SAFE'
    assert alert['status'] == 'unknown'
    assert alert['coverage'] == coverage
    assert alert['risk_display'].startswith('Unknown')
    report = format_full_report(result, {}, {}, {}, {'simulation_failed': True,
                              'is_honeypot': None, 'can_sell': None}, ai_analysis='SAFE')
    assert 'SAFE' not in report and 'Generally Safe' not in report
    assert 'Rug Probability:* 0%' not in report


def test_telegram_failed_simulation_overrides_raw_sellability():
    from core.telegram_formatter import format_full_report
    result = {'status': 'unknown', 'coverage': {'honeypot': 0.8},
              'rug_probability': 90, 'risk_level': 'HIGH'}
    report = format_full_report(result, {}, {}, {}, {'simulation_failed': True,
                              'is_honeypot': False, 'can_sell': True})
    assert 'Sellability: Unknown' in report
    assert 'Not Honeypot' not in report
    assert 'Rug probability 90%' not in report


@pytest.mark.asyncio
@pytest.mark.parametrize('handler', ['scan_contract', 'check_token'])
async def test_bot_caches_uncertainty_and_does_not_attest_as_low(bot_chain_functions, handler):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    ns = bot_chain_functions
    coverage = {'structural': 1, 'honeypot': 0.5}
    ns['risk_engine'].compute_from_results.return_value = {
        'status': 'unknown', 'coverage': coverage, 'coverage_reasons': {'honeypot': 'Simulation failed'},
        'risk_level': 'LOW', 'rug_probability': 0,
    }
    recorder = ns['onchain_recorder']
    recorder.is_available.return_value = True
    recorder.record_scan_fire_and_forget = AsyncMock()
    recorder.attest_fire_and_forget = AsyncMock()
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    await ns[handler](update, '0x' + 'a' * 40, chain_id=4663)
    cached = ns['_set_cache'].call_args.args[2]
    assert cached['status'] == 'unknown'
    assert cached['coverage'] == coverage
    assert cached['risk_level'] == 'unknown'
    ns['ai_analyzer'].generate_forensic_report.assert_not_called()
    recorder.record_scan_fire_and_forget.assert_not_called()
    recorder.attest_fire_and_forget.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('handler', ['scan_contract', 'check_token'])
async def test_bot_records_a_complete_scan_without_promising_it_on_chain(bot_chain_functions, handler):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    ns = bot_chain_functions
    recorder = ns['onchain_recorder']
    recorder.is_available.return_value = True
    recorder.record_scan_fire_and_forget = AsyncMock()
    recorder.attest_fire_and_forget = AsyncMock()
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    await ns[handler](update, '0x' + 'a' * 40, chain_id=56)
    recorder.record_scan_fire_and_forget.assert_awaited_once()
    assert 'On-chain recording' not in update.message.reply_text.call_args.args[0]


@pytest.mark.asyncio
@pytest.mark.parametrize('handler', ['scan_contract', 'check_token'])
async def test_bot_legacy_fallback_cache_cannot_store_safe_unknown(bot_report_functions, handler):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    ns = bot_report_functions
    ns['container'].registry.run_all.side_effect = RuntimeError('Unavailable')
    raw = {'address': '0x' + 'a' * 40, 'risk_level': 'low', 'safety_level': 'safe',
           'status': 'unknown', 'coverage': {'honeypot': 0}, 'is_verified': None}
    ns['tx_scanner'].scan_address.return_value = raw
    ns['token_scanner'].check_token.return_value = raw
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    await ns[handler](update, raw['address'], chain_id=4663)
    cached = ns['_set_cache'].call_args.args[2]
    assert cached['risk_level'] == 'unknown'
    assert cached['safety_level'] == 'unknown'


@pytest.mark.asyncio
async def test_bot_legacy_fallback_renders_confirmed_eoa_as_low(bot_report_functions, mock_web3_client):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from scanner.transaction_scanner import TransactionScanner
    ns = bot_report_functions
    ns['container'].registry.run_all.side_effect = RuntimeError('Unavailable')
    mock_web3_client.is_contract.return_value = False
    scanner = TransactionScanner(mock_web3_client)
    scanner.scam_db.check_address = AsyncMock(return_value=[])
    ns['tx_scanner'] = scanner
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    await ns['scan_contract'](update, '0x' + 'a' * 40, chain_id=56)
    cached = ns['_set_cache'].call_args.args[2]
    assert (cached['status'], cached['risk_level']) == ('ok', 'low')
    report = update.message.reply_text.call_args.args[0]
    assert '🟢 LOW' in report
    assert '5/100' in report
    assert 'UNKNOWN' not in report


def test_formatter_partial_flag_prevents_safe():
    from core.extension_formatter import format_extension_alert
    alert = format_extension_alert({'status': 'ok', 'partial': True,
                                   'coverage': {'honeypot': 1}, 'risk_level': 'LOW',
                                   'rug_probability': 0})
    assert alert['status'] == 'unknown'
    assert alert['risk_classification'] != 'SAFE'


@pytest.mark.asyncio
@pytest.mark.parametrize('scan_data', [{'status': 'unknown'}, {'risk_score': 0, 'risk_level': 'LOW'}])
async def test_bot_advisor_hides_uncovered_safety_claim(bot_chain_functions, scan_data):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    ns = bot_chain_functions
    ns['container'].advisor.chat.return_value = {'text': 'SAFE', 'scan_data': scan_data}
    typing = SimpleNamespace(edit_text=AsyncMock())
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock(return_value=typing)),
                             effective_user=SimpleNamespace(id=123))
    await ns['_handle_advisor_chat'](update, 'Scan this', chain_id=4663)
    rendered = typing.edit_text.call_args.args[0]
    assert isinstance(rendered, str)
    assert 'Unknown' in rendered and 'SAFE' not in rendered


@pytest.mark.asyncio
@pytest.mark.parametrize('handler,formatter', [('scan_contract', 'format_scan_result'),
                                               ('check_token', 'format_token_result')])
async def test_bot_cached_incomplete_composite_report_is_served_intact(bot_report_functions, handler, formatter):
    import ast
    import time
    from pathlib import Path
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock
    ns = bot_report_functions
    ns['web3_client'].get_token_info.return_value = {'name': 'Probe Token', 'symbol': 'PROBE'}
    ns['risk_engine'].compute_from_results.return_value = {
        'status': 'unknown', 'coverage': {'structural': 1, 'honeypot': 0},
        'coverage_reasons': {'honeypot': 'Simulation failed'}, 'risk_level': 'MEDIUM', 'rug_probability': 0,
    }
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock()))
    await ns[handler](update, '0x' + 'a' * 40, chain_id=4663)
    stored = ns['_set_cache'].call_args.args[2]

    scan_type = 'contract' if handler == 'scan_contract' else 'token'
    tree = ast.parse(Path('bot.py').read_text(encoding='utf-8'))
    cache = {'time': time, 'CACHE_TTL': 300, 'logger': MagicMock(),
             '_scan_cache': {f'{scan_type}:key': {'timestamp': time.time(), 'result': stored}}}
    exec(compile(ast.Module(body=[node for node in tree.body if isinstance(node, ast.FunctionDef)
                                  and node.name == '_get_cached'], type_ignores=[]), 'bot.py', 'exec'), cache)
    assert cache['_get_cached']('key', scan_type) is stored

    rendered = ns[formatter](stored)
    assert rendered == stored['composite_report']
    assert 'Probe Token (PROBE)' in rendered
    assert 'Unknown' in rendered and 'Generally Safe' not in rendered


def test_bot_legacy_cache_without_coverage_is_miss():
    import ast
    import time
    from pathlib import Path
    from unittest.mock import MagicMock
    tree = ast.parse(Path('bot.py').read_text(encoding='utf-8'))
    module = ast.Module(body=[node for node in tree.body if isinstance(node, ast.FunctionDef)
                             and node.name == '_get_cached'], type_ignores=[])
    ns = {'time': time, 'CACHE_TTL': 300, 'logger': MagicMock(), '_scan_cache': {
        'contract:0xabc': {'timestamp': time.time(), 'result': {'composite_report': 'SAFE', 'risk_level': 'low'}}}}
    exec(compile(module, 'bot.py', 'exec'), ns)
    assert ns['_get_cached']('0xabc', 'contract') is None


def test_formatter_requires_known_completion_status():
    from core.extension_formatter import format_extension_alert
    alert = format_extension_alert({'coverage': {'honeypot': 1}, 'rug_probability': 0, 'risk_level': 'LOW'})
    assert alert['status'] == 'unknown'


@pytest.mark.asyncio
@pytest.mark.parametrize('complete', [True, False], ids=['complete', 'incomplete'])
async def test_bot_rescue_lower_risk_count_requires_complete_scan(bot_chain_functions, complete):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    ns = bot_chain_functions
    ns['settings'] = SimpleNamespace(bscscan_api_key='', etherscan_api_key='')
    result = {'total_approvals': 3, 'high_risk': 0, 'medium_risk': 0,
              'approvals': [], 'alerts': [], 'revoke_txs': [],
              'status': 'ok', 'coverage': {'allowances': True, 'balances': True, 'prices': True}}
    if not complete:
        result.update(status='unknown', coverage={'approval_prices': 0},
                      coverage_reasons={'approval_prices': 'Token price unavailable'})
    ns['container'].rescue_service.scan_approvals.return_value = result
    status_msg = SimpleNamespace(delete=AsyncMock(), edit_text=AsyncMock())
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock(side_effect=[status_msg, None])))
    context = SimpleNamespace(args=['0x' + 'b' * 40], user_data={'chain_id': 4663})
    await ns['rescue_command'](update, context)
    text = update.message.reply_text.call_args.args[0]
    assert 'Safe: 3' not in text and 'look safe' not in text
    if complete:
        assert 'Lower risk: 3' in text
        assert 'No high- or medium-risk approvals found among the approvals checked.' in text
    else:
        assert 'Unconfirmed: 3' in text
        assert 'No high- or medium-risk approvals found' not in text
        assert 'incomplete' in text and 'Token price unavailable' in text


@pytest.mark.asyncio
@pytest.mark.parametrize('handler', ['rescue_command', 'threats_command', 'campaign_command',
                                     'scan_contract', 'check_token', '_handle_advisor_chat', 'error_handler'])
async def test_bot_never_sends_or_logs_provider_error_text(bot_chain_functions, handler):
    import ast
    from pathlib import Path
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    ns = bot_chain_functions
    tree = ast.parse(Path('bot.py').read_text(encoding='utf-8'))
    extra = {'campaign_command'}
    exec(compile(ast.Module(body=[node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
                                  and node.name in extra], type_ignores=[]), 'bot.py', 'exec'), ns)
    error = RuntimeError('https://rpc.example/v2/SYNTHETIC_KEY_123')
    ns['settings'] = SimpleNamespace(bscscan_api_key='', etherscan_api_key='')
    ns['container'].rescue_service.scan_approvals.side_effect = error
    ns['_fetch_mempool_data'].side_effect = error
    ns['container'].campaign_service.get_entity_graph = AsyncMock(side_effect=error)
    ns['container'].registry.run_all.side_effect = error
    ns['container'].advisor.chat.side_effect = error
    ns['tx_scanner'].scan_address.side_effect = error
    ns['token_scanner'].check_token.side_effect = error
    status_msg = SimpleNamespace(edit_text=AsyncMock(), delete=AsyncMock())
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock(return_value=status_msg)),
                             effective_user=SimpleNamespace(id=1), effective_message=None)
    address = '0x' + 'a' * 40
    if handler in ('scan_contract', 'check_token'):
        await ns[handler](update, address, chain_id=56)
    elif handler == '_handle_advisor_chat':
        await ns[handler](update, 'hello', chain_id=56)
    elif handler == 'error_handler':
        await ns[handler](update, SimpleNamespace(error=error))
    else:
        args = [] if handler == 'threats_command' else [address]
        await ns[handler](update, SimpleNamespace(args=args, user_data={'chain_id': 56}))
    sent = [str(call) for mock in (update.message.reply_text, status_msg.edit_text) for call in mock.call_args_list]
    logged = [str(call) for call in ns['logger'].method_calls]
    assert logged
    assert all('SYNTHETIC_KEY_123' not in text for text in sent + logged)


@pytest.mark.asyncio
async def test_bot_campaign_preserves_routing_error(bot_chain_functions):
    import ast
    from pathlib import Path
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from utils.web3_client import UnsupportedChainError
    ns = bot_chain_functions
    tree = ast.parse(Path('bot.py').read_text(encoding='utf-8'))
    exec(compile(ast.Module(body=[node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
                                  and node.name == 'campaign_command'], type_ignores=[]), 'bot.py', 'exec'), ns)
    error = UnsupportedChainError('Unsupported chain ID 999999')
    ns['container'].campaign_service.get_entity_graph = AsyncMock(side_effect=error)
    status_msg = SimpleNamespace(edit_text=AsyncMock(), delete=AsyncMock())
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock(return_value=status_msg)))
    with pytest.raises(UnsupportedChainError) as exc:
        await ns['campaign_command'](update, SimpleNamespace(args=['0x' + 'a' * 40], user_data={}))
    assert exc.value is error
    status_msg.edit_text.assert_not_called()
