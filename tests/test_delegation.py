"""EIP-7702 delegations: a type 0x04 transaction's authorization list hands the sender's account to
each delegate's code. Every delegation is Block Recommended, and the verdict names each delegate
in full with what is known of it (verified, age); facts that cannot be looked up leave it Unknown.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from analyzers.intent import IntentMismatchAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.extension_formatter import format_extension_alert
from core.risk_engine import RiskEngine
from services.counterparty_service import judge_delegate
from tests.test_consumer_unknowns import consumer_api  # noqa: F401

DELEGATE = "0x" + "7" * 40
SENDER = "0x" + "b" * 40


def _facts(**overrides):
    return {
        "address": DELEGATE,
        "allowlisted": None,
        "is_contract": True,
        "delegated": False,
        "is_verified": True,
        "age_days": 400,
        "labels": [],
        "label_source": "",
        "coverage": {"code": True, "verification": True, "age": True, "labels": True},
        "reason": None,
        "observed_at": 0,
        **overrides,
    }


@pytest.mark.parametrize(
    "facts, floor, unknown, text",
    [
        (_facts(), 90, False, "a verified contract, 400 days old"),
        (_facts(age_days=3), 100, False, "a verified contract, 3 days old"),
        (_facts(is_verified=False, age_days=90), 100, False, "an unverified contract, 90 days old"),
        (
            _facts(is_contract=False, is_verified=None, age_days=None),
            100,
            False,
            "a wallet, not a contract",
        ),
        (
            _facts(delegated=True, is_verified=None, age_days=None),
            100,
            False,
            "a delegated wallet, not a contract",
        ),
        (
            _facts(labels=["stealing_attack"], label_source="goplus"),
            100,
            False,
            "flagged by GoPlus: stealing_attack",
        ),
        (_facts(is_verified=None), 100, True, "verification unknown"),
        (_facts(age_days=None), 100, True, "a verified contract of unknown age"),
        (_facts(is_contract=None, labels=None), 100, True, "verified contract"),
    ],
    ids=[
        "verified-old",
        "verified-new",
        "unverified",
        "wallet",
        "delegated",
        "labelled",
        "verification-unknown",
        "age-unknown",
        "code-and-labels-unknown",
    ],
)
def test_every_delegation_is_block_recommended_and_says_what_the_delegate_is(
    facts, floor, unknown, text
):
    got_floor, flag, got_unknown = judge_delegate(DELEGATE, facts)
    assert got_floor == floor
    assert got_floor >= 71
    assert got_unknown is unknown
    assert DELEGATE in flag
    assert text in flag, flag


def _service(facts):
    return SimpleNamespace(
        allowlisted_name=lambda address, chain_id: None, fetch=AsyncMock(return_value=facts)
    )


async def _intent(service, calldata="0x", value="0x0", authorizations=None):
    return await IntentMismatchAnalyzer(None, service).analyze(
        AnalysisContext(
            address=SENDER,
            chain_id=1,
            from_address=SENDER,
            is_token=False,
            extra={
                "calldata": calldata,
                "value": value,
                "is_contract": False,
                "authorization_list": authorizations,
            },
        )
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "calldata", ["0x", "0xe8eda9df" + "0" * 256], ids=["no-call-data", "with-a-call"]
)
async def test_a_delegation_sets_a_block_floor_on_the_intent_result(calldata):
    service = _service(_facts(is_verified=False, age_days=90))
    result = await _intent(
        service, calldata, authorizations=[{"address": DELEGATE, "chainId": "0x1"}]
    )
    assert result.data["floor"] == 100
    assert result.flags[0].startswith("EIP-7702 delegation")
    assert DELEGATE in result.flags[0]
    assert result.data["status"] == "ok"
    assert result.data["coverage"]["delegate"] is True
    service.fetch.assert_awaited_once_with(DELEGATE, 1)


@pytest.mark.asyncio
async def test_a_delegate_whose_facts_are_unknown_leaves_the_result_unknown():
    service = _service(
        _facts(is_verified=None, reason="Spender facts unknown: verification (explorer)")
    )
    result = await _intent(service, authorizations=[{"address": DELEGATE}])
    assert result.data["floor"] == 100
    assert result.data["status"] == "unknown"
    assert result.data["coverage"]["delegate"] is False
    assert "verification (explorer)" in result.data["reason"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorizations",
    [
        [{"address": "not an address"}],
        [{}],
        ["0x" + "7" * 40],
        [],
    ],
    ids=["bad-address", "no-address", "not-an-object", "empty-list"],
)
async def test_a_delegation_that_cannot_be_read_is_unknown_and_blocked(authorizations):
    service = _service(_facts())
    result = await _intent(service, authorizations=authorizations)
    assert result.data["floor"] == 100
    assert result.data["status"] == "unknown"
    assert result.data["coverage"]["delegate"] is False
    service.fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_without_an_authorization_list_a_native_transfer_is_unchanged():
    service = _service(_facts())
    result = await _intent(service)
    assert result.data == {"intent": "native_transfer"}
    assert result.score == 0
    service.fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_verified_delegate_still_makes_the_verdict_block_recommended():
    result = await _intent(_service(_facts()), authorizations=[{"address": DELEGATE}])
    output = RiskEngine().compute_from_results(
        [
            AnalyzerResult("structural", 0.5, 0, data={"is_contract": False, "coverage": {}}),
            result,
        ],
        is_token=False,
    )
    alert = format_extension_alert(output)
    assert alert["risk_classification"] == "BLOCK_RECOMMENDED"
    assert alert["top_flags"][0].startswith("EIP-7702 delegation")


@pytest.mark.asyncio
async def test_the_firewall_passes_the_authorization_list_and_never_serves_a_cached_verdict(
    consumer_api,
):  # noqa: F811
    api, services = consumer_api
    api.risk_engine.compute_from_results.return_value = {
        "rug_probability": 90, "risk_level": "HIGH", "risk_archetype": "unknown", "critical_flags": [],
        "confidence_level": 50, "category_scores": {}, "coverage": {"intent": 1}, "coverage_reasons": {}, "status": "ok",
    }
    services.db.get_contract_score = AsyncMock(
        return_value={"category_scores": {"_scan_metadata": {"coverage": {"x": 1}}}}
    )
    authorizations = [{"address": DELEGATE}]
    req = api.FirewallRequest(to=SENDER, sender=SENDER, authorizationList=authorizations)
    await api.firewall(req, SimpleNamespace(headers={}))
    ctx = services.registry.run_all.await_args.args[0]
    assert ctx.extra["authorization_list"] == authorizations
    services.db.get_contract_score.assert_not_awaited()
    services.db.upsert_contract_score.assert_not_awaited()


def test_the_firewall_accepts_at_most_sixteen_authorizations(consumer_api):  # noqa: F811
    api, _ = consumer_api
    with pytest.raises(ValueError):
        api.FirewallRequest(
            to=SENDER, sender=SENDER, authorizationList=[{"address": DELEGATE}] * 17
        )


@pytest.mark.asyncio
async def test_the_rpc_proxy_passes_the_authorization_list_to_the_analyzers():
    from rpc.proxy import RPCProxy

    container = SimpleNamespace(
        web3_client=SimpleNamespace(
            validate_chain_id=lambda chain_id: chain_id,
            get_web3=lambda chain_id: SimpleNamespace(
                provider=SimpleNamespace(endpoint_uri="https://rpc.example")
            ),
            get_bytecode=AsyncMock(return_value="0x"),
            is_token_contract=AsyncMock(return_value=False),
            is_verified_contract=AsyncMock(return_value=(False, None)),
        ),
        registry=SimpleNamespace(run_all=AsyncMock(return_value=[])),
        risk_engine=SimpleNamespace(
            compute_from_results=lambda results, is_token: {
                "risk_level": "HIGH",
                "rug_probability": 100,
            }
        ),
    )
    proxy = RPCProxy(container)
    authorizations = [{"address": DELEGATE, "chainId": "0x1", "nonce": "0x0"}]
    result = await proxy.handle_request(
        1,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendTransaction",
            "params": [
                {"to": SENDER, "from": SENDER, "value": "0x0", "authorizationList": authorizations}
            ],
        },
    )
    ctx = container.registry.run_all.await_args.args[0]
    assert ctx.extra["authorization_list"] == authorizations
    assert result["error"]["code"] == -32003
