"""Only a CONFIRMED absence of bytecode may escalate a failed simulation to 80."""

import pytest

from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine


MARKET = {"liquidity_usd": 50000, "pair_age_hours": 100, "fdv": 200000, "volume_24h": 2000}
ETHOS = {"reputation_score": 80}


def _contract(is_contract):
    data = {"is_contract": is_contract, "is_verified": True, "ownership_renounced": None}
    if is_contract is not False:
        data["contract_age_days"] = 400
    return data


def _honeypot(simulation_failed):
    # Shape produced by analyzers/honeypot.py for a honeypot.is reply.
    data = {
        "is_honeypot": False,
        "buy_tax": 0,
        "sell_tax": 0,
        "can_buy": True,
        "can_sell": None if simulation_failed else True,
        "simulation_failed": simulation_failed,
    }
    data["coverage"] = {
        field: data.get(field) is not None
        for field in ("is_honeypot", "buy_tax", "sell_tax", "can_buy", "can_sell")
    }
    if simulation_failed:
        data["status"] = "unknown"
        data["reason"] = "Honeypot simulation failed (unresolved)"
    else:
        data["status"] = "ok"
    return data


def _risk(entrypoint, is_contract, simulation_failed):
    contract, honeypot = _contract(is_contract), _honeypot(simulation_failed)
    engine = RiskEngine()
    if entrypoint == "direct":
        return engine.compute_composite_risk(contract, honeypot, MARKET, ETHOS)
    return engine.compute_from_results(
        [
            AnalyzerResult("structural", 0.4, 50 if is_contract is False else 0, data=contract),
            AnalyzerResult("market", 0.25, 0, data=MARKET),
            AnalyzerResult("behavioral", 0.2, 0, data=ETHOS),
            AnalyzerResult("honeypot", 0.15, 40 if simulation_failed else 0, data=honeypot),
        ]
    )


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
def test_confirmed_missing_bytecode_with_failed_simulation_still_escalates(entrypoint):
    risk = _risk(entrypoint, False, True)
    assert risk["rug_probability"] == 80
    assert risk["risk_level"] == "HIGH"
    assert risk["status"] == "unknown"


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
@pytest.mark.parametrize("simulation_failed", [True, False])
def test_failed_contract_lookup_never_escalates_on_its_own(entrypoint, simulation_failed):
    # is_contract None means eth_getCode failed; two failures are not evidence of a scam.
    risk = _risk(entrypoint, None, simulation_failed)
    assert risk["rug_probability"] < 71
    assert risk["risk_level"] != "HIGH"
    if simulation_failed:
        assert risk["status"] == "unknown"
        assert risk["risk_level"] == "MEDIUM"


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
@pytest.mark.parametrize("simulation_failed", [True, False])
def test_confirmed_contract_never_takes_the_destroyed_token_floor(entrypoint, simulation_failed):
    risk = _risk(entrypoint, True, simulation_failed)
    assert risk["rug_probability"] < 71
    assert risk["risk_level"] != "HIGH"


@pytest.mark.parametrize("entrypoint", ["direct", "registry"])
def test_confirmed_missing_bytecode_without_failed_simulation_is_not_escalated(entrypoint):
    risk = _risk(entrypoint, False, False)
    assert risk["rug_probability"] < 71
    assert risk["risk_level"] != "HIGH"
