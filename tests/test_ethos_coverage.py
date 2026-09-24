"""An Ethos outage must leave behavioural coverage unknown, never neutral and covered."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from analyzers.behavioral import BehavioralAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.risk_engine import RiskEngine
from services.ethos_service import EthosService


WALLET = "0x" + "b" * 40
SECRET = "ETHOS-SECRET-9d41"
NEUTRAL = {
    "observed_at": 1000,
    "reputation_score": 50,
    "ethos_raw_score": None,
    "trust_level": "unknown",
    "scam_flags": [],
    "linked_wallets": [],
    "vouch_count": 0,
    "review_stats": {},
    "low_reputation_flag": False,
    "severe_reputation_flag": False,
}
PROFILE = {
    "score": 1400,
    "status": "SLASHED",
    "stats": {
        "vouch": {"received": {"count": 3}},
        "review": {"received": {"positive": 2, "negative": 5}},
    },
}
CONTRACT = {
    "is_contract": True,
    "is_verified": True,
    "contract_age_days": 400,
    "ownership_renounced": None,
}
HONEYPOT = {"is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0}
MARKET = {"liquidity_usd": 50000, "pair_age_hours": 100}


def _http(status=200, payload=None, error=None):
    response = MagicMock(status=status)
    response.json = AsyncMock(return_value=payload)
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    session.get.return_value.__aexit__ = AsyncMock(return_value=False)
    if error is not None:
        session.get.side_effect = error
    factory = patch("services.ethos_service.aiohttp.ClientSession")
    return factory, session


async def _fetch(status=200, payload=None, error=None):
    factory, session = _http(status, payload, error)
    with factory as http, patch("services.ethos_service.time.time", return_value=1000):
        http.return_value.__aenter__ = AsyncMock(return_value=session)
        http.return_value.__aexit__ = AsyncMock(return_value=False)
        return await EthosService().fetch_wallet_reputation(WALLET)


@pytest.mark.asyncio
async def test_missing_profile_stays_neutral_and_covered():
    assert await _fetch(status=404) == NEUTRAL


@pytest.mark.asyncio
async def test_successful_profile_numbers_are_unchanged():
    assert await _fetch(payload=PROFILE) == {
        "observed_at": 1000,
        "reputation_score": 50.0,
        "ethos_raw_score": 1400,
        "trust_level": "medium",
        "scam_flags": ["Profile slashed on Ethos", "5 negative reviews"],
        "linked_wallets": [],
        "vouch_count": 3,
        "review_stats": {"positive": 2, "negative": 5},
        "low_reputation_flag": False,
        "severe_reputation_flag": False,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 429, 500, 503])
async def test_non_404_error_status_is_unknown(status):
    data = await _fetch(status=status)
    assert data == {**NEUTRAL, "status": "unknown", "reason": f"Ethos HTTP {status}"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error, name",
    [
        (asyncio.TimeoutError(), "TimeoutError"),
        (
            aiohttp.ClientConnectionError(f"Cannot connect to host {SECRET}"),
            "ClientConnectionError",
        ),
    ],
)
async def test_timeout_or_exception_is_unknown_with_class_only_reason(caplog, error, name):
    with caplog.at_level(logging.DEBUG):
        data = await _fetch(error=error)
    assert data == {**NEUTRAL, "status": "unknown", "reason": f"Ethos request failed ({name})"}
    assert SECRET not in caplog.text
    assert SECRET not in repr(data)


@pytest.mark.asyncio
async def test_malformed_success_body_is_unknown():
    data = await _fetch(payload=["not", "a", "profile"])
    assert data["status"] == "unknown"
    assert data["reason"] == "Ethos request failed (AttributeError)"


def _analyzer(data):
    service = SimpleNamespace(fetch_wallet_reputation=AsyncMock(return_value=data))
    return BehavioralAnalyzer(service)


@pytest.mark.asyncio
async def test_behavioral_analyzer_flags_unknown_reputation():
    unknown = {**NEUTRAL, "status": "unknown", "reason": "Ethos HTTP 500"}
    result = await _analyzer(unknown).analyze(AnalysisContext("0x" + "a" * 40, from_address=WALLET))
    assert result.score == 0
    assert result.flags == ["Behavioral data unknown: Ethos HTTP 500"]
    assert result.data is unknown


@pytest.mark.asyncio
async def test_behavioral_analyzer_success_is_unchanged():
    data = {**NEUTRAL, "severe_reputation_flag": True, "scam_flags": ["Profile slashed on Ethos"]}
    result = await _analyzer(data).analyze(AnalysisContext("0x" + "a" * 40, from_address=WALLET))
    assert (result.score, result.flags) == (
        90,
        ["Severe reputation warning", "Ethos scam flags present"],
    )


async def _both_entry_points(ethos, is_token):
    behavioral = await _analyzer(ethos).analyze(
        AnalysisContext("0x" + "a" * 40, from_address=WALLET, is_token=is_token)
    )
    if is_token:
        market = AnalyzerResult("market", 0.25, 0, data=MARKET)
        honeypot = AnalyzerResult("honeypot", 0.15, 0, data=HONEYPOT)
    else:
        market = AnalyzerResult(
            "market", 0.25, 0, data={"skipped": True, "reason": "non-token contract"}
        )
        honeypot = AnalyzerResult(
            "honeypot", 0.15, 0, data={"skipped": True, "reason": "non-token contract"}
        )
    registry = RiskEngine().compute_from_results(
        [AnalyzerResult("structural", 0.4, 0, data=CONTRACT), market, behavioral, honeypot],
        is_token=is_token,
    )
    direct = RiskEngine().compute_composite_risk(
        CONTRACT, HONEYPOT, MARKET, ethos, is_token=is_token
    )
    return direct, registry


@pytest.mark.asyncio
@pytest.mark.parametrize("is_token", [True, False])
async def test_unknown_reputation_makes_both_entry_points_unknown(is_token):
    unknown = {**NEUTRAL, "status": "unknown", "reason": "Ethos request failed (TimeoutError)"}
    for risk in await _both_entry_points(unknown, is_token):
        assert risk["status"] == "unknown"
        assert risk["coverage"]["behavioral"] == 0
        assert risk["coverage_reasons"]["behavioral"] == "Ethos request failed (TimeoutError)"
        assert risk["category_scores"]["behavioral"] is None
        assert risk["risk_level"] != "LOW"
        assert risk["risk_archetype"] != "legitimate"


@pytest.mark.asyncio
@pytest.mark.parametrize("is_token", [True, False])
async def test_missing_profile_keeps_both_entry_points_covered(is_token):
    for risk in await _both_entry_points(dict(NEUTRAL), is_token):
        assert risk["status"] == "ok"
        assert risk["coverage"]["behavioral"] == 1
        assert risk["risk_level"] == "LOW"
        assert risk["risk_archetype"] == "legitimate"


@pytest.fixture
def fallback_firewall(monkeypatch):
    import api

    web3 = MagicMock()
    web3.is_valid_address.return_value = True
    web3.to_checksum_address.side_effect = lambda address: address
    web3.is_token_contract = AsyncMock(return_value=True)
    web3.is_verified_contract = AsyncMock(return_value=(True, None))
    monkeypatch.setattr(api, "container", None)
    monkeypatch.setattr(api, "web3_client", web3)
    monkeypatch.setattr(
        api,
        "calldata_decoder",
        SimpleNamespace(
            decode=MagicMock(return_value={"selector": None}),
            is_whitelisted_target=MagicMock(return_value=None),
        ),
    )
    monkeypatch.setattr(api, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False))
    monkeypatch.setattr(api, "ai_analyzer", SimpleNamespace(is_available=lambda: False))
    monkeypatch.setattr(api, "greenfield_service", None)
    monkeypatch.setattr(api, "risk_engine", RiskEngine())
    monkeypatch.setattr(
        api,
        "contract_service",
        SimpleNamespace(fetch_contract_data=AsyncMock(return_value=CONTRACT)),
    )
    monkeypatch.setattr(
        api,
        "honeypot_service",
        SimpleNamespace(fetch_honeypot_data=AsyncMock(return_value=HONEYPOT)),
    )
    monkeypatch.setattr(
        api, "dex_service", SimpleNamespace(fetch_token_market_data=AsyncMock(return_value=MARKET))
    )
    monkeypatch.setattr(
        api,
        "tx_scanner",
        SimpleNamespace(scan_address=AsyncMock(side_effect=AssertionError("legacy scanner"))),
    )
    monkeypatch.setattr(
        api,
        "token_scanner",
        SimpleNamespace(check_token=AsyncMock(side_effect=AssertionError("legacy scanner"))),
    )
    monkeypatch.setattr(api, "ethos_service", EthosService())
    return api


async def _firewall(api, status):
    factory, session = _http(status=status)
    with factory as http:
        http.return_value.__aenter__ = AsyncMock(return_value=session)
        http.return_value.__aexit__ = AsyncMock(return_value=False)
        request = api.FirewallRequest(to="0x" + "a" * 40, sender=WALLET, chainId=56)
        return await api.firewall(request, SimpleNamespace(headers={}))


@pytest.mark.asyncio
async def test_firewall_reputation_outage_is_unknown_not_safe(fallback_firewall):
    response = await _firewall(fallback_firewall, 503)
    assert response["status"] == "unknown"
    assert response["classification"] != "SAFE"
    assert response["coverage_reasons"]["behavioral"] == "Ethos HTTP 503"
    assert response["risk_display"].startswith("Unknown")
    assert response["partial"] is True


@pytest.mark.asyncio
async def test_firewall_missing_reputation_profile_stays_safe(fallback_firewall):
    response = await _firewall(fallback_firewall, 404)
    assert response["status"] == "ok"
    assert response["classification"] == "SAFE"
    assert response["coverage"]["behavioral"] == 1


TARGET = "0x" + "a" * 40
SPENDER = "0x" + "5" * 40
RECIPIENT = "0x" + "d" * 40


def _word(value):
    return format(value, "064x") if isinstance(value, int) else value[2:].rjust(64, "0")


def _call(selector, *args):
    return "0x" + selector + "".join(_word(arg) for arg in args)


MAX = 2**256 - 1
SCORED = [
    ("approve", _call("095ea7b3", SPENDER, MAX)),
    ("increaseAllowance", _call("39509351", SPENDER, 1)),
    ("setApprovalForAll", _call("a22cb465", SPENDER, 1)),
    ("permit", _call("d505accf", WALLET, SPENDER, MAX, 1, 27, 0, 0)),
    ("dai-permit", _call("8fcbaf0c", WALLET, SPENDER, 0, 1, 1, 27, 0, 0)),
]
NOT_SCORED = [
    ("transfer", _call("a9059cbb", RECIPIENT, 1)),
    ("transferFrom", _call("23b872dd", WALLET, RECIPIENT, 1)),
    ("swap", "0x7ff36ab5" + "0" * 256),
    ("claim", "0x4e71d92d"),
    ("unknown", "0xdeadbeef"),
]


def _counterparty_analyzer(data):
    service = SimpleNamespace(fetch_wallet_reputation=AsyncMock(return_value=data))
    return BehavioralAnalyzer(service), service


def _ctx(calldata):
    return AnalysisContext(TARGET, from_address=WALLET, extra={"calldata": calldata})


@pytest.mark.asyncio
@pytest.mark.parametrize("calldata", [c for _, c in SCORED], ids=[n for n, _ in SCORED])
async def test_approval_family_scores_the_spender(calldata):
    analyzer, service = _counterparty_analyzer(dict(NEUTRAL))
    result = await analyzer.analyze(_ctx(calldata))
    service.fetch_wallet_reputation.assert_awaited_once_with(SPENDER)
    assert result.data["counterparty"] == SPENDER


@pytest.mark.asyncio
async def test_native_send_scores_the_recipient_never_the_sender():
    analyzer, service = _counterparty_analyzer(dict(NEUTRAL))
    result = await analyzer.analyze(_ctx("0x"))
    service.fetch_wallet_reputation.assert_awaited_once_with(TARGET)
    assert result.data["counterparty"] == TARGET


@pytest.mark.asyncio
@pytest.mark.parametrize("calldata", [c for _, c in NOT_SCORED], ids=[n for n, _ in NOT_SCORED])
async def test_other_calls_are_neutral_and_covered_without_a_lookup(calldata):
    analyzer, service = _counterparty_analyzer(dict(NEUTRAL))
    with patch("services.ethos_service.time.time", return_value=1000):
        result = await analyzer.analyze(_ctx(calldata))
    service.fetch_wallet_reputation.assert_not_awaited()
    assert result.data == {**NEUTRAL, "counterparty": None, "status": "ok"}
    assert (result.score, result.flags) == (0, [])
    risk = RiskEngine().compute_from_results([result])
    assert risk["coverage"]["behavioral"] == 1


@pytest.mark.asyncio
async def test_token_transfer_to_a_severe_reputation_does_not_leak_into_the_token_row():
    # The verdict for a transfer is cached under the token, so the recipient's reputation
    # must not change it.
    severe = {**NEUTRAL, "severe_reputation_flag": True, "scam_flags": ["Profile slashed on Ethos"]}
    transfer = await _counterparty_analyzer(severe)[0].analyze(_ctx(NOT_SCORED[0][1]))
    neutral = await _counterparty_analyzer(dict(NEUTRAL))[0].analyze(_ctx("0x"))
    results = [
        AnalyzerResult("structural", 0.4, 20, data=CONTRACT),
        AnalyzerResult("market", 0.25, 0, data=MARKET),
        AnalyzerResult("honeypot", 0.15, 0, data=HONEYPOT),
    ]
    with_transfer = RiskEngine().compute_from_results(results + [transfer])
    with_neutral = RiskEngine().compute_from_results(results + [neutral])
    assert transfer.score == 0
    assert with_transfer["rug_probability"] == with_neutral["rug_probability"] == 8


@pytest.mark.asyncio
async def test_firewall_fallback_scores_the_same_counterparty(fallback_firewall):
    approve = {
        "selector": "095ea7b3", "category": "approval", "function_name": "approve",
        "params": {"param_0": SPENDER, "param_1": MAX},
        "is_approval": True, "is_unlimited_approval": True,
    }
    fallback_firewall.calldata_decoder.decode.return_value = approve
    factory, session = _http(status=404)
    with factory as http:
        http.return_value.__aenter__ = AsyncMock(return_value=session)
        http.return_value.__aexit__ = AsyncMock(return_value=False)
        request = fallback_firewall.FirewallRequest(to=TARGET, sender=WALLET, chainId=56)
        await fallback_firewall.firewall(request, SimpleNamespace(headers={}))
    assert session.get.call_count == 1
    assert session.get.call_args.args[0].endswith(f"address:{SPENDER}")
