"""A scan with no transaction measures no call and no signature, and an address with no Ethos
profile has no reputation to measure.

Intent, signature and behavioral used to answer such a scan with a covered 0, which diluted the
weighted mean below BLOCK_MIN: a contract the structural and market analyzers both scored 100 read
Medium and legitimate. They now skip (behavioral only when Ethos has no profile for the address),
and the same evidence reaches High.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from analyzers import BehavioralAnalyzer, IntentMismatchAnalyzer, SignaturePermitAnalyzer
from core.analyzer import Analyzer, AnalysisContext, AnalyzerResult, has_transaction
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine
from services.ethos_service import neutral_reputation

TARGET = "0x" + "c" * 40
CONTRACT = {
    "is_contract": True,
    "is_verified": True,
    "contract_age_days": 400,
    "has_proxy": False,
    "ownership_renounced": None,
}
MARKET = {"liquidity_usd": 50000, "pair_age_hours": 100}
HONEYPOT = {"is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0}


class _Fixed(Analyzer):
    """An analyzer that answers with recorded evidence, at its production weight."""

    def __init__(self, name, weight, score, data):
        self._name, self._weight, self._score, self._data = name, weight, score, data

    @property
    def name(self):
        return self._name

    @property
    def weight(self):
        return self._weight

    async def analyze(self, ctx):
        return AnalyzerResult(self._name, self._weight, self._score, data=dict(self._data))


def _registry(ethos):
    registry = AnalyzerRegistry()
    registry.register(_Fixed("structural", 0.40, 100, CONTRACT))
    registry.register(_Fixed("market", 0.25, 100, MARKET))
    registry.register(BehavioralAnalyzer(ethos))
    registry.register(_Fixed("honeypot", 0.15, 0, HONEYPOT))
    registry.register(IntentMismatchAnalyzer(SimpleNamespace()))
    registry.register(SignaturePermitAnalyzer())
    return registry


def test_has_transaction_reads_the_presence_of_an_input_not_its_content():
    assert not has_transaction(AnalysisContext(TARGET))
    assert not has_transaction(AnalysisContext(TARGET, extra={"deadline": 1.0}))
    assert has_transaction(AnalysisContext(TARGET, extra={"calldata": "0x"}))
    assert has_transaction(AnalysisContext(TARGET, extra={"calldata": ""}))
    assert has_transaction(AnalysisContext(TARGET, extra={"typed_data": None}))
    assert has_transaction(AnalysisContext(TARGET, extra={"authorization_list": []}))


@pytest.mark.asyncio
async def test_an_address_scan_with_no_profile_skips_the_three():
    ethos = SimpleNamespace(fetch_wallet_reputation=AsyncMock(return_value=neutral_reputation()))
    results = await _registry(ethos).run_all(AnalysisContext(TARGET))
    ethos.fetch_wallet_reputation.assert_awaited_once_with(TARGET)
    by_name = {result.name: result for result in results}
    for name, reason in (("intent", "no transaction"), ("signature", "no transaction"), ("behavioral", "no reputation profile")):
        assert by_name[name].data == {"skipped": True, "reason": reason}
        assert by_name[name].score == 0
    risk = RiskEngine().compute_from_results(results)
    assert set(risk["not_applicable"]) == {"intent", "signature", "behavioral"}
    assert all(risk["coverage"][name] == 1 for name in ("intent", "signature", "behavioral"))
    assert risk["status"] == "ok"


@pytest.mark.asyncio
async def test_strong_evidence_on_an_address_scan_reaches_high_without_a_floor():
    ethos = SimpleNamespace(fetch_wallet_reputation=AsyncMock(return_value=neutral_reputation()))
    results = await _registry(ethos).run_all(AnalysisContext(TARGET))
    after = RiskEngine().compute_from_results(results)
    # Before: the three answered with a covered 0 and stayed in the mean.
    covered_zero = {
        "intent": {"intent": "native_transfer"},
        "signature": {"sign_method": "", "has_typed_data": False},
        "behavioral": {"reputation_score": 50, "counterparty": TARGET, "status": "ok"},
    }
    before = RiskEngine().compute_from_results([
        AnalyzerResult(r.name, r.weight, 0, data=covered_zero[r.name]) if r.name in covered_zero else r
        for r in results
    ])
    assert (before["rug_probability"], before["risk_level"], before["risk_archetype"]) == (
        52.0, "MEDIUM", "legitimate",
    )
    assert (after["rug_probability"], after["risk_level"], after["risk_archetype"]) == (
        81.2, "HIGH", "high_risk_contract",
    )
    assert after["transaction_floor"] is None
