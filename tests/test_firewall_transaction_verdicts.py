"""Firewall verdicts through the real six analyzers, registry and engine, on /api/firewall and the
agent firewall. Only the network is replaced: the RPC client, GoPlus, DexScreener, the honeypot
service and Ethos answer with the inputs recorded in benchmark_safe_inputs.json.

A transaction's verdict must not move when address scans stop counting analyzers that measured
nothing. `EXPECTED` was computed by running `_verdict` at 5690690 (origin/main before that change),
not typed by hand; the agent firewall at 5690690 gave its analyzers no transaction, and its
verdicts for these three requests are the same.
"""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from eth_abi import encode
from fastapi import FastAPI
from fastapi.testclient import TestClient
from web3 import Web3

from adapters import bsc
from analyzers import (
    BehavioralAnalyzer,
    HoneypotAnalyzer,
    IntentMismatchAnalyzer,
    MarketAnalyzer,
    SignaturePermitAnalyzer,
    StructuralAnalyzer,
)
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine
from services.contract_service import ContractService
from services.ethos_service import neutral_reputation
from utils.calldata_decoder import CalldataDecoder
from utils.scam_db import ScamDatabase

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "benchmark_safe_inputs.json").read_text(encoding="utf-8")
)
ENTRIES = {entry["address"].lower(): entry for entry in FIXTURE["entries"]}
CAKE = "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82"
BUSD = "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56"
ROUTER = "0x10ED43C718714eb63d5aA57B78B54704E256024E"
SENDER = "0x" + "5e" * 20
# A fresh wallet: no code, no Ethos profile.
EOA = "0x" + "7a" * 20
TOKENS = {CAKE.lower(), BUSD.lower()}

REQUESTS = {
    "erc20_transfer": {
        "to": CAKE, "value": "0",
        "data": "0xa9059cbb" + encode(["address", "uint256"], [EOA, 10**18]).hex(),
    },
    "router_swap": {
        "to": ROUTER, "value": "0",
        "data": "0x38ed1739" + encode(
            ["uint256", "uint256", "address[]", "address", "uint256"],
            [10**18, 1, [CAKE, BUSD], SENDER, 2**40],
        ).hex(),
    },
    "native_send": {"to": EOA, "value": str(10**17), "data": "0x"},
}


PAYABLE_ROUTER_SWAP = {
    "to": ROUTER,
    "value": str(10**18),
    "data": "0x7ff36ab5" + encode(
        ["uint256", "address[]", "address", "uint256"],
        [1, [CAKE, BUSD], SENDER, 2**40],
    ).hex(),
}


def _entry(address):
    return ENTRIES.get(address.lower())


def _code(address):
    entry = _entry(address)
    if entry is None:
        return "0x"
    return "0x" + "".join("63" + sig for sig in entry["bytecode_patterns"] or []) or "0x6080"


def _web3(verification=(True, None)):
    adapter = SimpleNamespace(
        get_whitelisted_routers=lambda: {ROUTER.lower(): "PancakeSwap V2 Router"},
        get_known_lockers=lambda: bsc.KNOWN_LOCKERS,
    )
    return SimpleNamespace(
        is_valid_address=Web3.is_address,
        to_checksum_address=Web3.to_checksum_address,
        validate_chain_id=lambda chain_id: None,
        _get_adapter=lambda chain_id: adapter,
        get_bytecode=AsyncMock(side_effect=lambda address, chain_id=56: _code(address)),
        is_contract=AsyncMock(side_effect=lambda address, chain_id=56: _entry(address) is not None),
        is_token_contract=AsyncMock(side_effect=lambda address, chain_id=56: address.lower() in TOKENS),
        is_verified_contract=AsyncMock(return_value=verification),
        get_contract_creation_info=AsyncMock(return_value={"age_days": 1000}),
        get_ownership_info=AsyncMock(
            side_effect=lambda address, chain_id=56: (_entry(address) or {}).get("ownership")
        ),
        get_token_info=AsyncMock(return_value={}),
        router_v2_pool=AsyncMock(return_value=None),
        supports_honeypot_simulation=lambda chain_id: False,
    )


def _registry(web3):
    def recorded(field):
        return AsyncMock(side_effect=lambda address, chain_id=56: dict((_entry(address) or {}).get(field) or {}))

    registry = AnalyzerRegistry()
    registry.register(StructuralAnalyzer(ContractService(web3, ScamDatabase())))
    registry.register(MarketAnalyzer(SimpleNamespace(fetch_token_market_data=recorded("market"))))
    registry.register(BehavioralAnalyzer(SimpleNamespace(fetch_wallet_reputation=AsyncMock(
        side_effect=lambda address: dict((_entry(address) or {}).get("ethos") or neutral_reputation())
    ))))
    registry.register(HoneypotAnalyzer(SimpleNamespace(fetch_honeypot_data=recorded("honeypot"))))
    registry.register(IntentMismatchAnalyzer(web3))
    registry.register(SignaturePermitAnalyzer())
    return registry


async def _goplus(address, chain_id=56):
    entry = _entry(address)
    return entry["goplus"] if entry else {"status": "ok", "reason": None, "data": {}}


async def _api_response(monkeypatch, request, verification=(True, None)):
    import api

    web3 = _web3(verification)
    services = SimpleNamespace(
        web3_client=web3,
        db=SimpleNamespace(
            get_contract_score=AsyncMock(return_value=None),
            get_deployer_risk_summary=AsyncMock(return_value=None),
            upsert_contract_score=AsyncMock(),
        ),
        registry=_registry(web3),
        policy_engine=None, indexer=None, counterparty_service=None,
        settings=SimpleNamespace(policy_mode="BALANCED", reporter_hash_secret=""),
    )
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", web3)
    monkeypatch.setattr(api, "scam_db", ScamDatabase())
    monkeypatch.setattr(api, "calldata_decoder", CalldataDecoder())
    monkeypatch.setattr(api, "risk_engine", RiskEngine())
    monkeypatch.setattr(api, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False))
    monkeypatch.setattr(api, "greenfield_service", None)
    monkeypatch.setattr(api, "ai_analyzer", SimpleNamespace(is_available=lambda: False))
    monkeypatch.setattr(api, "_token_cache", {})
    return await api.firewall(
        api.FirewallRequest(sender=SENDER, chainId=56, **request), SimpleNamespace(headers={}),
    )


async def _api_verdict(monkeypatch, request, verification=(True, None)):
    response = await _api_response(monkeypatch, request, verification)
    shield = response["shield_score"]
    return {
        "score": response["risk_score"], "classification": response["classification"],
        "status": response["status"], "risk_level": shield.get("risk_level"),
        "category_scores": shield.get("category_scores"),
    }


def _agent_verdict(request, verification=(True, None)):
    from agent.firewall import create_agent_firewall_router

    web3 = _web3(verification)
    container = SimpleNamespace(
        db=SimpleNamespace(
            get_agent_policy=AsyncMock(return_value={
                "agent_id": "agent:1", "registered_by_key": "k1",
                "policy": {"auto_allow_below": 25, "auto_block_above": 70},
            }),
            get_agent_daily_spend=AsyncMock(return_value=0),
            record_agent_firewall_event=AsyncMock(),
            record_agent_spend=AsyncMock(),
            get_contract_score=AsyncMock(return_value=None),
            upsert_contract_score=AsyncMock(),
        ),
        cache=SimpleNamespace(get_verdict=AsyncMock(return_value=None), set_verdict=AsyncMock()),
        auth_manager=SimpleNamespace(
            validate_key=AsyncMock(return_value={"key_id": "k1"}),
            check_rate_limit=AsyncMock(return_value=True),
        ),
        registry=_registry(web3),
        risk_engine=RiskEngine(),
        web3_client=web3,
        tenderly_simulator=SimpleNamespace(is_enabled=lambda: False),
        calldata_decoder=CalldataDecoder(),
    )
    app = FastAPI()
    app.include_router(create_agent_firewall_router(container), prefix="/api/agent")
    response = TestClient(app).post("/api/agent/firewall", headers={"X-API-Key": "sb_test"}, json={
        "agent_id": "agent:1",
        "transaction": {"from": SENDER, "chain_id": 56, **request},
    })
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "score": body["score"], "risk_level": body["risk_level"], "verdict": body["verdict"],
        "status": body["status"], "category_scores": body["category_scores"],
    }


async def _verdict(monkeypatch, path, case, verification=(True, None)):
    with patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock(side_effect=_goplus)), \
            patch("services.contract_service.BSCSCAN_DELAY", 0):
        request = PAYABLE_ROUTER_SWAP if case == "payable_router_swap" else REQUESTS[case]
        if path == "api":
            return await _api_verdict(monkeypatch, request, verification)
        return _agent_verdict(request, verification)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verification", [(True, None), (None, None)], ids=["verified", "explorer-timeout"]
)
async def test_a_payable_allowlisted_router_swap_matches_the_api_path(monkeypatch, verification):
    api_result = await _verdict(monkeypatch, "api", "payable_router_swap", verification)
    agent_result = await _verdict(monkeypatch, "agent", "payable_router_swap", verification)

    assert api_result == {
        "score": 6.4,
        "classification": "SAFE",
        "status": "ok",
        "risk_level": "LOW",
        "category_scores": {
            "structural": 20,
            "market": 0,
            "behavioral": 0,
            "honeypot": 0,
            "intent": 0.0,
            "signature": 0,
        },
    }
    assert agent_result == {
        "score": 6.4,
        "risk_level": "LOW",
        "verdict": "ALLOW",
        "status": "ok",
        "category_scores": {
            "structural": 20,
            "market": 0,
            "behavioral": 0,
            "honeypot": 0,
            "intent": 0.0,
            "signature": 0,
        },
    }


# Printed by running _verdict for each case at 5690690.
EXPECTED = {('agent', 'erc20_transfer'): {'category_scores': {'behavioral': 0,
                                                   'honeypot': 0,
                                                   'intent': 0,
                                                   'market': 0,
                                                   'signature': 0,
                                                   'structural': 20},
                               'risk_level': 'LOW',
                               'score': 6.4,
                               'status': 'ok',
                               'verdict': 'ALLOW'},
 ('agent', 'native_send'): {'category_scores': {'behavioral': 0,
                                                'honeypot': 0.0,
                                                'intent': 0,
                                                'market': 0.0,
                                                'signature': 0,
                                                'structural': 50},
                            'risk_level': 'LOW',
                            'score': 23.5,
                            'status': 'ok',
                            'verdict': 'ALLOW'},
 ('agent', 'router_swap'): {'category_scores': {'behavioral': 0,
                                                'honeypot': 0.0,
                                                'intent': 0,
                                                'market': 0.0,
                                                'signature': 0,
                                                'structural': 0},
                            'risk_level': 'LOW',
                            'score': 0.0,
                            'status': 'ok',
                            'verdict': 'ALLOW'},
 ('api', 'erc20_transfer'): {'category_scores': {'behavioral': 0,
                                                 'honeypot': 0,
                                                 'intent': 0.0,
                                                 'market': 0,
                                                 'signature': 0,
                                                 'structural': 20},
                             'classification': 'SAFE',
                             'risk_level': 'LOW',
                             'score': 6.4,
                             'status': 'ok'},
 ('api', 'native_send'): {'category_scores': {'behavioral': 0,
                                              'honeypot': 0.0,
                                              'intent': 0,
                                              'market': 0.0,
                                              'signature': 0,
                                              'structural': 50},
                          'classification': 'SAFE',
                          'risk_level': 'LOW',
                          'score': 23.5,
                          'status': 'ok'},
 ('api', 'router_swap'): {'category_scores': {'behavioral': 0,
                                              'honeypot': 0,
                                              'intent': 0.0,
                                              'market': 0,
                                              'signature': 0,
                                              'structural': 20},
                          'classification': 'SAFE',
                          'risk_level': 'LOW',
                          'score': 6.4,
                          'status': 'ok'}}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["api", "agent"])
@pytest.mark.parametrize("case", list(REQUESTS))
async def test_a_transactions_verdict_is_unchanged(monkeypatch, path, case):
    assert await _verdict(monkeypatch, path, case) == EXPECTED[(path, case)]
