"""Risk engine weighting for skipped analyzers, with the container's production weights."""

import pytest

from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine

# The weights the registry normalises the container's six analyzers to.
WEIGHTS = {
    "structural": 0.32,
    "market": 0.20,
    "behavioral": 0.16,
    "honeypot": 0.12,
    "intent": 0.12,
    "signature": 0.08,
}
SKIPPED = {"skipped": True, "reason": "non-token contract"}
CONTRACT = {
    "is_contract": True,
    "is_verified": True,
    "contract_age_days": 400,
    "ownership_renounced": None,
}
MARKET = {"liquidity_usd": 50000, "pair_age_hours": 100}
HONEYPOT = {"is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0}
ETHOS = {"reputation_score": 80}


def _results(
    structural=0,
    contract=CONTRACT,
    market=MARKET,
    honeypot=HONEYPOT,
    intent=0,
    intent_data=None,
    signature=0,
    signature_data=None,
):
    return [
        AnalyzerResult("structural", WEIGHTS["structural"], structural, data=contract),
        AnalyzerResult("market", WEIGHTS["market"], 0, data=market),
        AnalyzerResult("behavioral", WEIGHTS["behavioral"], 0, data=ETHOS),
        AnalyzerResult("honeypot", WEIGHTS["honeypot"], 0, data=honeypot),
        AnalyzerResult("intent", WEIGHTS["intent"], intent, data=intent_data or {"status": "ok"}),
        AnalyzerResult(
            "signature",
            WEIGHTS["signature"],
            signature,
            data=signature_data or {"has_typed_data": False},
        ),
    ]


@pytest.mark.parametrize("structural, expected, level", [(100, 47.1, "MEDIUM"), (25, 11.8, "LOW")])
def test_skipped_analyzers_leave_the_weighted_mean(structural, expected, level):
    risk = RiskEngine().compute_from_results(
        _results(structural, market=SKIPPED, honeypot=SKIPPED), is_token=False
    )
    # structural * .32 / .68: market and honeypot do not apply to a non-token.
    assert risk["rug_probability"] == expected
    assert risk["risk_level"] == level
    assert risk["category_scores"]["market"] == 0.0
    assert risk["category_scores"]["honeypot"] == 0.0
    assert risk["coverage"]["market"] == risk["coverage"]["honeypot"] == 1
    assert risk["status"] == "ok"


def test_unknown_market_on_a_token_is_not_made_safer():
    unknown = {"status": "unknown", "reason": "DexScreener HTTP 500"}
    risk = RiskEngine().compute_from_results(_results(50, market=unknown))
    # Unknown market data is excluded exactly as before: 50 * .32 / .80.
    assert risk["rug_probability"] == 20
    assert risk["category_scores"]["market"] is None
    assert risk["coverage"]["market"] == 0
    assert risk["status"] == "unknown"
    assert risk["risk_level"] == "MEDIUM"


CLEAN_TOKEN = {**CONTRACT, "ownership_renounced": True}
DEEP_MARKET = {"liquidity_usd": 5_000_000, "pair_age_hours": 1000}


@pytest.mark.parametrize("intent, expected", [(35, 4.2), (70, 8.4)])
def test_clean_token_discount_keeps_the_transaction_share(intent, expected):
    risk = RiskEngine().compute_from_results(
        _results(0, contract=CLEAN_TOKEN, market=DEEP_MARKET, intent=intent)
    )
    # The renounced, liquid token earns its discount on its own components only: intent * .12.
    assert risk["rug_probability"] == expected
    assert risk["category_scores"]["intent"] == intent


def test_clean_token_discount_without_transaction_risk_is_unchanged():
    risk = RiskEngine().compute_from_results(
        _results(100, contract=CLEAN_TOKEN, market=DEEP_MARKET)
    )
    # 100 * .32 - 20, as before.
    assert risk["rug_probability"] == 12
