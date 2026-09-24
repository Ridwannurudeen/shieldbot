"""The 20 safe benchmark entries keep the scores they had before the scoring redesign.

eval/live_scorer.py scans each entry with AnalysisContext(address, chain_id): no calldata, no typed
data, is_token True. This replays recorded provider inputs through the real analyzers, registry and
engine and compares the result with the output of the engine before the redesign (`expected` in
the fixture): pinned at e820c2e, then at fix/audit-integration b400015, whose bytecode scan reads
1inch V5's 83197ef0 as destroy() rather than delegatecall (same score, different flag).
"""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from analyzers import (
    BehavioralAnalyzer,
    HoneypotAnalyzer,
    IntentMismatchAnalyzer,
    MarketAnalyzer,
    SignaturePermitAnalyzer,
    StructuralAnalyzer,
)
from core.analyzer import AnalysisContext
from core.registry import AnalyzerRegistry
from core.risk_engine import RiskEngine
from services.contract_service import ContractService
from utils.scam_db import ScamDatabase

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "benchmark_safe_inputs.json").read_text(encoding="utf-8")
)
# Not recorded (the explorer needs the production key). Every entry is a verified contract that
# has been live for years; the engine reads only whether both are known and whether the age is
# under 7 days.
EXPLORER_VERIFICATION = (True, None)
EXPLORER_CREATION = {"age_days": 1000}
FIELDS = (
    "rug_probability",
    "risk_level",
    "risk_archetype",
    "status",
    "confidence_level",
    "critical_flags",
    "category_scores",
    "coverage",
    "coverage_reasons",
)


async def _score(entry):
    patterns = entry["bytecode_patterns"]
    web3 = SimpleNamespace(
        is_contract=AsyncMock(return_value=entry["is_contract"]),
        is_verified_contract=AsyncMock(return_value=EXPLORER_VERIFICATION),
        get_contract_creation_info=AsyncMock(return_value=EXPLORER_CREATION),
        get_ownership_info=AsyncMock(return_value=entry["ownership"]),
        # Each recorded selector as a dispatcher's PUSH4 operand, which is how the scan finds it.
        get_bytecode=AsyncMock(
            return_value=None if patterns is None else "0x" + "".join("63" + sig for sig in patterns)
        ),
    )
    ethos = SimpleNamespace(fetch_wallet_reputation=AsyncMock(return_value=dict(entry["ethos"])))
    registry = AnalyzerRegistry()
    registry.register(StructuralAnalyzer(ContractService(web3, ScamDatabase())))
    registry.register(
        MarketAnalyzer(
            SimpleNamespace(fetch_token_market_data=AsyncMock(return_value=dict(entry["market"])))
        )
    )
    registry.register(BehavioralAnalyzer(ethos))
    registry.register(
        HoneypotAnalyzer(
            SimpleNamespace(fetch_honeypot_data=AsyncMock(return_value=dict(entry["honeypot"])))
        )
    )
    registry.register(IntentMismatchAnalyzer(web3))
    registry.register(SignaturePermitAnalyzer())
    goplus = AsyncMock(return_value=entry["goplus"])
    with (
        patch.object(ScamDatabase, "fetch_token_security", new=goplus),
        patch("services.contract_service.BSCSCAN_DELAY", 0),
    ):
        results = await registry.run_all(
            AnalysisContext(address=entry["address"], chain_id=entry["chain_id"])
        )
    ethos.fetch_wallet_reputation.assert_awaited_once_with(entry["address"])
    risk = RiskEngine().compute_from_results(results)
    return {field: risk[field] for field in FIELDS}


def test_fixture_covers_every_safe_benchmark_entry():
    with open(
        Path(__file__).parents[1] / "eval" / "data" / "benchmark_v1.json", encoding="utf-8"
    ) as f:
        safes = [
            (e["address"], e["chain_id"]) for e in json.load(f)["entries"] if e["label"] == "safe"
        ]
    assert [(e["address"], e["chain_id"]) for e in FIXTURE["entries"]] == safes
    assert len(safes) == 20


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "entry", FIXTURE["entries"], ids=[e["description"] for e in FIXTURE["entries"]]
)
async def test_safe_entry_scores_as_before(entry):
    assert await _score(entry) == entry["expected"]
