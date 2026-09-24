"""Approval scan wording must describe the checked scope without promising safety."""

import ast
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from core.extension_formatter import is_scan_incomplete
from core.telegram_formatter import escape_markdown
from utils.web3_client import UnsupportedChainError


@pytest.fixture
def rescue_bot():
    tree = ast.parse(Path('bot.py').read_text(encoding='utf-8'))
    handler = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
                   and node.name == 'rescue_command')
    module = ast.parse('from __future__ import annotations')
    module.body.append(handler)
    scan = AsyncMock()
    namespace = {
        'container': SimpleNamespace(rescue_service=SimpleNamespace(scan_approvals=scan)),
        'settings': SimpleNamespace(bscscan_api_key='', etherscan_api_key=''),
        'web3_client': SimpleNamespace(validate_chain_id=lambda value: value, is_valid_address=lambda _: True),
        'parse_chain_prefix': lambda value: (None, value),
        '_get_user_chain_id': lambda _: 4663,
        'get_chain_name': lambda _: 'Robinhood Chain',
        'is_scan_incomplete': is_scan_incomplete,
        'escape_markdown': escape_markdown,
        'UnsupportedChainError': UnsupportedChainError,
        'logger': logging.getLogger(__name__),
    }
    exec(compile(module, 'bot.py', 'exec'), namespace)
    progress = SimpleNamespace(delete=AsyncMock(), edit_text=AsyncMock())
    update = SimpleNamespace(message=SimpleNamespace(reply_text=AsyncMock(return_value=progress)))
    context = SimpleNamespace(args=['0x' + 'a' * 40])
    scan.return_value = {
        'total_approvals': 1, 'high_risk': 0, 'medium_risk': 0,
        'status': 'ok', 'coverage': {'allowances': True, 'balances': True, 'prices': True},
        'coverage_reasons': {}, 'approvals': [], 'revoke_txs': [],
    }
    return namespace['rescue_command'], scan, update, context


@pytest.mark.asyncio
async def test_complete_approval_scan_limits_negative_finding(rescue_bot):
    handler, scan, update, context = rescue_bot
    await handler(update, context)
    text = update.message.reply_text.call_args.args[0]
    assert 'No high- or medium-risk approvals found among the approvals checked.' in text
    assert 'ERC-20 allowances' in text
    assert 'approval amounts and known-spender labels' in text
    assert 'does not audit spender contracts, NFT approvals, or off-chain signatures' in text
    assert 'Lower risk: 1' in text
    assert 'All approvals look safe' not in text
    assert 'no action needed' not in text
    assert 'Safe:' not in text
    scan.assert_awaited_once_with(context.args[0], chain_id=4663, etherscan_api_key='')


@pytest.mark.asyncio
@pytest.mark.parametrize('scan_state', [
    {'status': 'unknown', 'coverage_reasons': {'history': 'Recent history only'}},
    {'status': 'ok', 'coverage': {'allowances': False}},
    {'status': 'ok', 'coverage': {}},
    {'status': None},
    {'partial': True},
])
async def test_incomplete_approval_scan_never_claims_no_risks(rescue_bot, scan_state):
    handler, scan, update, context = rescue_bot
    scan.return_value.update(scan_state)
    await handler(update, context)
    text = update.message.reply_text.call_args.args[0]
    assert 'Scan incomplete' in text
    assert 'Unconfirmed: 1' in text
    assert 'No high- or medium-risk approvals found' not in text
    assert 'All approvals look safe' not in text
    assert 'Lower risk:' not in text


@pytest.mark.asyncio
@pytest.mark.parametrize('incomplete', [False, True])
async def test_revocation_handoff_never_implies_execution(rescue_bot, incomplete):
    handler, scan, update, context = rescue_bot
    scan.return_value.update(high_risk=1, revoke_txs=[{'transaction': {'data': '0x'}}])
    if incomplete:
        scan.return_value['status'] = 'unknown'
    await handler(update, context)
    text = update.message.reply_text.call_args.args[0]
    assert 'This bot has not revoked any approvals or submitted transactions.' in text
    assert 'Review the token, spender and chain in your wallet or' in text
    assert 'then sign and submit any revocation yourself.' in text
    assert ('Scan incomplete' in text) is incomplete


def test_rescue_negative_finding_uses_shared_incomplete_guard():
    tree = ast.parse(Path('bot.py').read_text(encoding='utf-8'))
    handler = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
                   and node.name == 'rescue_command')
    assignment = next(node for node in ast.walk(handler) if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == 'incomplete'
                              for target in node.targets))
    assert ast.unparse(assignment.value) == 'is_scan_incomplete(result)'
    negative_finding = next(node for node in ast.walk(handler) if isinstance(node, ast.If)
                            and any(isinstance(value, ast.Constant) and isinstance(value.value, str)
                                    and 'No high- or medium-risk approvals found' in value.value
                                    for statement in node.body for value in ast.walk(statement)))
    assert any(isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)
               and isinstance(node.operand, ast.Name) and node.operand.id == 'incomplete'
               for node in ast.walk(negative_finding.test))
