"""Offline checks that subscription discovery only advertises implemented endpoints."""

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.asyncio
@pytest.mark.parametrize('chains', [None, [56, 4663]])
async def test_threat_subscriptions_only_advertise_available_endpoints(chains):
    source = Path(__file__).resolve().parent.parent / 'api.py'
    tree = ast.parse(source.read_text(encoding='utf-8'))
    endpoint = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == 'threat_subscribe_info'
    )
    endpoint.decorator_list = []
    namespace = {
        'web3_client': None if chains is None else SimpleNamespace(
            get_supported_chain_ids=lambda: chains,
        ),
    }
    exec(compile(ast.Module(body=[endpoint], type_ignores=[]), str(source), 'exec'), namespace)

    response = await namespace['threat_subscribe_info']()

    assert response['endpoints'] == {
        'rest_polling': '/api/threats/feed?since=<unix_timestamp>',
    }
    assert response['supported_chains'] == (chains or [])
