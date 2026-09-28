"""Tests for router swap analysis to ensure no whitelist bypass."""

import json
from pathlib import Path

import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from eth_abi import encode

from core import verdicts
from core.analyzer import AnalyzerResult
from core.policy import PolicyEngine
from core.risk_engine import RiskEngine
from tests.test_strict_cache import _firewall, strict_api  # noqa: F401  (pytest fixture)
from utils.calldata_decoder import CalldataDecoder
from utils.web3_client import Web3Client


@pytest.mark.asyncio
async def test_router_swap_analysis_blocks_high_risk_token():
    import api as api_module

    # Build calldata for swapExactTokensForTokens with address[] path
    addr1 = "0x1111111111111111111111111111111111111111"
    addr2 = "0x2222222222222222222222222222222222222222"
    recipient = "0x3333333333333333333333333333333333333333"
    payload = encode(
        ["uint256", "uint256", "address[]", "address", "uint256"],
        [1, 1, [addr1, addr2], recipient, 123],
    ).hex()
    calldata = "0x38ed1739" + payload

    decoded = CalldataDecoder().decode(calldata)

    class DummyRegistry:
        async def run_all(self, ctx):
            return [
                AnalyzerResult(
                    name="structural",
                    weight=1.0,
                    score=90.0,
                    flags=["High risk"],
                    data={"is_verified": False},
                )
            ]

    class DummyPolicy:
        def apply(self, results, risk_output, mode_override=None):
            return risk_output

    api_module.container = SimpleNamespace(
        registry=DummyRegistry(),
        policy_engine=DummyPolicy(),
    )
    api_module.risk_engine = RiskEngine()
    chain_registry = Web3Client.__new__(Web3Client)
    chain_registry._adapters = {56: SimpleNamespace()}
    api_module.web3_client = SimpleNamespace(
        validate_chain_id=chain_registry.validate_chain_id,
        is_valid_address=lambda a: True,
        to_checksum_address=lambda a: a,
        is_verified_contract=AsyncMock(return_value=False),
    )
    api_module.tenderly_simulator = SimpleNamespace(is_enabled=lambda: False)

    req = api_module.FirewallRequest(
        to="0xrouter",
        sender=recipient,
        value="0x0",
        data=calldata,
        chainId=56,
    )

    resp = await api_module._analyze_router_swap(
        req=req,
        to_addr="0xrouter",
        from_addr=recipient,
        decoded=decoded,
        whitelisted="Router",
        value_bnb=0.0,
    )

    assert resp is not None
    assert resp["classification"] == "BLOCK_RECOMMENDED"


WBNB = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
TOKEN = "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82"


def _swap_results(contract_age_known):
    structural = {
        "is_contract": True, "is_verified": True, "contract_age_days": 900 if contract_age_known else None,
        "ownership_renounced": True, "scam_matches": [],
        "coverage": {"is_verified": True, "contract_age_days": contract_age_known, "scam_database": True},
    }
    # DexScreener gave liquidity but no pair age or price change: informational gaps.
    market = {
        "liquidity_usd": 5_000_000, "pair_age_hours": None, "price_change_24h": None, "status": "unknown",
        "reason": "Incomplete DexScreener data",
        "coverage": {"liquidity_usd": True, "pair_age_hours": False, "price_change_24h": False},
    }
    honeypot = {
        "is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0, "status": "ok",
        "coverage": {field: True for field in ("is_honeypot", "can_buy", "can_sell", "buy_tax", "sell_tax")},
    }
    return [
        AnalyzerResult("structural", 0.32, 0, data=structural),
        AnalyzerResult("market", 0.20, 0, data=market),
        AnalyzerResult("behavioral", 0.16, 0, data={"reputation_score": 50}),
        AnalyzerResult("honeypot", 0.12, 0, data=honeypot),
        AnalyzerResult("intent", 0.12, 0, data={"status": "ok", "coverage": {"selector_verification": True}}),
        AnalyzerResult("signature", 0.08, 0, data={"has_typed_data": False}),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("contract_age_known, blocked", [(True, False), (False, True)])
async def test_strict_router_swap_blocks_only_on_a_required_gap(monkeypatch, contract_age_known, blocked):
    import api as api_module
    from core.policy import PolicyEngine

    class Registry:
        async def run_all(self, ctx):
            # WBNB is complete everywhere; the token's contract age is what the case varies.
            return _swap_results(ctx.address != TOKEN or contract_age_known)

    chain_registry = Web3Client.__new__(Web3Client)
    chain_registry._adapters = {56: SimpleNamespace()}
    monkeypatch.setattr(api_module, "container", SimpleNamespace(
        registry=Registry(), policy_engine=PolicyEngine("BALANCED"),
    ))
    monkeypatch.setattr(api_module, "risk_engine", RiskEngine())
    monkeypatch.setattr(api_module, "web3_client", SimpleNamespace(
        validate_chain_id=chain_registry.validate_chain_id,
        is_valid_address=lambda a: True,
        to_checksum_address=lambda a: a,
        is_verified_contract=AsyncMock(return_value=(True, None)),
    ))
    monkeypatch.setattr(api_module, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False))
    payload = encode(["uint256", "address[]", "address", "uint256"], [1, [WBNB, TOKEN], "0x" + "2" * 40, 123])
    calldata = "0x7ff36ab5" + payload.hex()
    req = api_module.FirewallRequest(to="0x" + "1" * 40, sender="0x" + "2" * 40, value=hex(10**17), data=calldata)

    resp = await api_module._analyze_router_swap(
        req, req.to, req.sender, CalldataDecoder().decode(calldata), "PancakeSwap V2 Router", 0.1,
        policy_override="STRICT",
    )

    assert (resp["classification"] == "BLOCK_RECOMMENDED") is blocked
    assert resp["policy_mode"] == "STRICT"
    assert resp["failed_sources"] == (["structural"] if blocked else [])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "server_mode, header, mode",
    [("BALANCED", None, "BALANCED"), ("BALANCED", "STRICT", "STRICT"), ("STRICT", None, "STRICT")],
    ids=["balanced", "strict-header", "strict-server"],
)
async def test_a_swap_whose_path_tokens_were_not_analysed_answers_in_the_requests_policy_mode(
    strict_api, monkeypatch, server_mode, header, mode  # noqa: F811
):
    api, services = strict_api
    services.policy_engine = PolicyEngine(server_mode)
    # A trusted router's swap whose token path cannot be decoded.
    monkeypatch.setattr(api, "calldata_decoder", SimpleNamespace(
        decode=lambda data: {"selector": "deadbeef", "function_name": "multicall", "category": "swap", "params": {}},
        is_whitelisted_target=lambda *args, **kwargs: "PancakeSwap Router",
    ))
    request = SimpleNamespace(headers={"X-Policy-Mode": header} if header else {}, state=SimpleNamespace())

    response = await _firewall(api, request)

    services.registry.run_all.assert_not_awaited()
    assert (response["policy_mode"], response["status"], response["coverage"]) == (mode, "unknown", {"token_path": 0})
    if mode == "STRICT":
        assert (response["classification"], response["risk_score"], response["shield_score"]["risk_level"]) == (
            verdicts.BLOCK_RECOMMENDED,
            verdicts.STRICT_BLOCK_SCORE,
            verdicts.HIGH,
        )
        assert response["danger_signals"][0].startswith("Policy override")
    else:
        assert (response["classification"], response["shield_score"]["risk_level"]) == (
            verdicts.CAUTION,
            verdicts.UNKNOWN,
        )
        assert verdicts.classify(response["risk_score"]) == verdicts.CAUTION
        assert not any(signal.startswith("Policy override") for signal in response["danger_signals"])
    assert response["shield_score"]["overall"] == response["raw_checks"]["risk_score_heuristic"] == response["risk_score"]


V4_SWAP = json.loads(
    (Path(__file__).parent / "fixtures" / "universal_router_v4_swaps.json").read_text(encoding="utf-8")
)["swaps"][0]
ATTACKER = "0x" + "ad" * 20


@pytest.mark.parametrize(
    "recipient, expected",
    [
        ("0x" + "ab" * 20, ([WBNB, TOKEN], None, [])),
        (ATTACKER, ([], f"Its tokens go to {ATTACKER}, not the sender", [])),
    ],
    ids=["sender", "someone-else"],
)
def test_a_v2_router_swap_must_pay_its_sender(recipient, expected):
    import api as api_module

    payload = encode(["uint256", "address[]", "address", "uint256"], [1, [WBNB, TOKEN], recipient, 123])
    decoded = CalldataDecoder().decode("0x7ff36ab5" + payload.hex())

    assert api_module._extract_swap_path(decoded, sender="0x" + "Ab" * 20) == expected


@pytest.mark.parametrize(
    "router_name, refusal",
    [
        ("Uniswap Universal Router V2.1.2", None),
        ("Uniswap Universal Router V1.2", "It runs router command 0x10, which ShieldBot does not check"),
        ("PancakeSwap Universal Router", "It runs router command 0x10, which ShieldBot does not check"),
    ],
)
def test_only_a_uniswap_v2_universal_router_reads_command_0x10_as_a_v4_swap(monkeypatch, router_name, refusal):
    import api as api_module

    monkeypatch.setattr(api_module, "calldata_decoder", CalldataDecoder())
    path, reason, pools = api_module._extract_swap_path(
        {"selector": "3593564c"}, "0x" + V4_SWAP["calldata_hex"], V4_SWAP["sender"], V4_SWAP["router"], router_name,
    )

    assert (reason, pools) == (refusal, [])
    assert (sorted(path) == V4_SWAP["tokens"]) is (refusal is None)


@pytest.mark.asyncio
async def test_a_router_swap_that_pays_someone_else_is_not_judged_by_its_tokens(monkeypatch):
    import api as api_module

    registry = SimpleNamespace(run_all=AsyncMock())
    chain_registry = Web3Client.__new__(Web3Client)
    chain_registry._adapters = {56: SimpleNamespace()}
    monkeypatch.setattr(api_module, "container", SimpleNamespace(
        registry=registry, policy_engine=PolicyEngine("BALANCED"),
    ))
    monkeypatch.setattr(api_module, "risk_engine", RiskEngine())
    monkeypatch.setattr(api_module, "web3_client", SimpleNamespace(
        validate_chain_id=chain_registry.validate_chain_id,
        is_valid_address=lambda a: True,
        to_checksum_address=lambda a: a,
    ))
    payload = encode(["uint256", "address[]", "address", "uint256"], [1, [WBNB, TOKEN], ATTACKER, 123])
    calldata = "0x7ff36ab5" + payload.hex()
    req = api_module.FirewallRequest(to="0x" + "1" * 40, sender="0x" + "2" * 40, value=hex(10**17), data=calldata)

    resp = await api_module._analyze_router_swap(
        req, req.to, req.sender, CalldataDecoder().decode(calldata), "PancakeSwap V2 Router", 0.1,
    )

    registry.run_all.assert_not_awaited()
    assert resp["classification"] == verdicts.CAUTION
    assert resp["coverage_reasons"] == {"token_path": f"Its tokens go to {ATTACKER}, not the sender"}
    assert resp["danger_signals"] == [
        f"Swap via trusted router (PancakeSwap V2 Router) but its tokens go to {ATTACKER}, not the sender"
        " — token safety unverified"
    ]


MIXED_ROUTE = json.loads(
    (Path(__file__).parent / "fixtures" / "universal_router_mixed_routes.json").read_text(encoding="utf-8")
)["swaps"][0]
POOL, POOL_TOKEN_A, POOL_TOKEN_B = MIXED_ROUTE["pools"][0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pool_lookup, refusal",
    [
        (AsyncMock(return_value=POOL), None),
        (AsyncMock(return_value=ATTACKER), f"Its funds go to {POOL}, not the sender"),
        (AsyncMock(return_value=None), f"Its funds go to {POOL}, not the sender"),
        (
            AsyncMock(side_effect=TimeoutError()),
            f"Could not confirm that {POOL} is the pool of its next swap (TimeoutError)",
        ),
    ],
    ids=["confirmed", "another-pool", "no-pool", "lookup-failed"],
)
async def test_a_mixed_route_pays_only_a_pool_its_router_confirms(monkeypatch, pool_lookup, refusal):
    import api as api_module

    registry = SimpleNamespace(run_all=AsyncMock(side_effect=lambda ctx: _swap_results(True)))
    chain_registry = Web3Client.__new__(Web3Client)
    chain_registry._adapters = {1: SimpleNamespace()}
    monkeypatch.setattr(api_module, "container", SimpleNamespace(
        registry=registry, policy_engine=PolicyEngine("BALANCED"),
    ))
    monkeypatch.setattr(api_module, "risk_engine", RiskEngine())
    monkeypatch.setattr(api_module, "calldata_decoder", CalldataDecoder())
    monkeypatch.setattr(api_module, "web3_client", SimpleNamespace(
        validate_chain_id=chain_registry.validate_chain_id,
        is_valid_address=lambda a: True,
        to_checksum_address=lambda a: a,
        is_verified_contract=AsyncMock(return_value=(True, None)),
        router_v2_pool=pool_lookup,
    ))
    monkeypatch.setattr(api_module, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False))
    calldata = "0x" + MIXED_ROUTE["calldata_hex"]
    req = api_module.FirewallRequest(to=MIXED_ROUTE["router"], sender=MIXED_ROUTE["sender"], value="0x0", data=calldata, chainId=1)

    resp = await api_module._analyze_router_swap(
        req, req.to, req.sender, CalldataDecoder().decode(calldata), "Uniswap Universal Router V2.1.2", 0.0,
    )

    pool_lookup.assert_awaited_once_with(MIXED_ROUTE["router"], POOL_TOKEN_A, POOL_TOKEN_B, chain_id=1)
    if refusal is None:
        assert registry.run_all.await_count == len(MIXED_ROUTE["tokens"])
        assert "token_path" not in resp["coverage"]
    else:
        registry.run_all.assert_not_awaited()
        assert resp["coverage_reasons"] == {"token_path": refusal}
