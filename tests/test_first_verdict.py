"""The streamed firewall's interim verdict (core/first_verdict.py): Unknown is never Safe, it is scored
by hard floors only, and those floors never put it in a higher band than the final verdict's."""

import itertools
import random

import pytest

from core import verdicts
from core.analyzer import AnalyzerResult
from core.extension_formatter import format_extension_alert, is_scan_incomplete
from core.first_verdict import IN_PROGRESS, FirstVerdictProgress, build_first_verdict
from core.risk_engine import RiskEngine

WEIGHTS = {
    "structural": 0.40,
    "market": 0.25,
    "behavioral": 0.20,
    "honeypot": 0.15,
    "intent": 0.15,
    "signature": 0.10,
}
TRANSACTION = {
    "decoded_action": "Native BNB Transfer",
    "calldata_details": {"category": "unknown", "fields": [{"label": "Function", "value": "Unknown"}]},
    "transaction_impact": {
        "sending": "Tokens",
        "granting_access": "None",
        "recipient": "0x" + "ab" * 20,
        "post_tx_state": IN_PROGRESS,
    },
    "chain_id": 56,
    "network": "BSC",
}
ADMIN = {"type": "Local Blacklist", "reason": "Confirmed scam address", "source": "ShieldBot", "severity": "block"}
COMMUNITY = {
    "type": "community_reports",
    "reason": "Reported by 3 users",
    "source": "ShieldBot",
    "severity": "medium",
    "reports": 3,
}
GOPLUS_HIGH = {"type": "GoPlus Security", "reason": "Owner can change balance", "source": "gopluslabs.io", "severity": "high"}
GOPLUS_BLOCK = {"type": "GoPlus Security", "reason": "Airdrop scam token", "source": "gopluslabs.io", "severity": "block"}
RANK = {classification: index for index, classification in enumerate(verdicts.CLASSIFICATIONS)}


def clean(name, scam_matches=()):
    """A fully covered result with nothing found."""
    data = {
        "structural": {
            "is_contract": True,
            "is_verified": True,
            "contract_age_days": 400,
            "coverage": {"is_verified": True, "contract_age_days": True, "scam_database": True},
            "scam_matches": list(scam_matches),
        },
        "market": {"liquidity_usd": 50_000},
        "behavioral": {},
        "honeypot": {"is_honeypot": False, "can_sell": True, "buy_tax": 0, "sell_tax": 0},
        "intent": {"coverage": {"selector_verification": True}},
        "signature": {},
    }[name]
    return AnalyzerResult(name, WEIGHTS[name], 0, data={**data, "status": "ok"})


def with_floor(name, floor, flag):
    result = clean(name)
    return AnalyzerResult(name, result.weight, floor, flags=[flag], data={**result.data, "floor": floor})


def progress_of(results, local_match=None, pending=None):
    progress = FirstVerdictProgress(WEIGHTS if pending is None else pending, "BALANCED")
    progress.add_local_match(local_match)
    for result in results:
        progress.add_result(result)
    return progress


def first(progress):
    return build_first_verdict(progress, TRANSACTION, 1234)


def final_classification(results):
    """The classification the engine gives a complete scan of these results, as the firewall's plain
    route does before its campaign and simulation escalations, which only raise it."""
    total = sum(result.weight for result in results)
    normalized = [
        AnalyzerResult(r.name, r.weight / total, r.score, list(r.flags), dict(r.data), r.error) for r in results
    ]
    return format_extension_alert(RiskEngine().compute_from_results(normalized))["risk_classification"]


@pytest.mark.parametrize(
    "finished",
    [combo for size in range(len(WEIGHTS) + 1) for combo in itertools.combinations(WEIGHTS, size)],
)
def test_unknown_is_never_safe_whichever_analyzers_have_returned(finished):
    verdict = first(progress_of([clean(name) for name in finished]))

    assert verdict["status"] == "unknown"
    assert verdict["classification"] != verdicts.SAFE
    assert is_scan_incomplete(verdict)
    # No floor: the interim is the CAUTION of an Unknown, even with every analyzer back and clean.
    assert verdict["classification"] == verdicts.CAUTION
    assert verdict["risk_score"] == 0
    assert "Unknown" in verdict["risk_display"]
    assert "Unknown" in verdict["verdict"]
    assert (verdict["final"], verdict["partial"], verdict["failed_sources"]) == (False, True, [])
    assert verdict["pending_sources"] == sorted(set(WEIGHTS) - set(finished))
    assert set(verdict["coverage"]) == set(finished)
    assert verdict["policy_mode"] == "BALANCED"
    assert verdict["elapsed_ms"] == 1234
    assert not {"evidence_hash", "evidence_url", "cached"} & set(verdict)
    assert {key: verdict[key] for key in TRANSACTION} == TRANSACTION


def test_the_pending_reason_names_the_analyzers_still_running():
    assert first(progress_of([clean("structural")], pending=["structural", "honeypot", "market"]))[
        "coverage_reasons"
    ] == {"pending": "Full analysis in progress: honeypot, market"}
    assert first(progress_of([clean("structural")], pending=["structural"]))["coverage_reasons"] == {
        "pending": "Full analysis in progress"
    }


def test_a_partial_mean_would_mislead_so_the_interim_reads_floors_only():
    # Structural 60 alone would read HIGH_RISK as a mean; the clean results still to come dilute it.
    structural = AnalyzerResult("structural", WEIGHTS["structural"], 60, flags=["Mint function detected"], data=clean("structural").data)
    verdict = first(progress_of([structural]))

    assert (verdict["risk_score"], verdict["classification"]) == (0, verdicts.CAUTION)
    assert verdict["danger_signals"] == []
    assert final_classification([structural, *(clean(name) for name in WEIGHTS if name != "structural")]) == verdicts.SAFE


@pytest.mark.parametrize(
    "results, local_match, score, classification, signals",
    [
        ([], ADMIN, 90, verdicts.BLOCK_RECOMMENDED, ["Confirmed scam address"]),
        ([], COMMUNITY, 40, verdicts.CAUTION, ["Reported by 3 users"]),
        ([with_floor("intent", 90, "Approval to a wallet")], None, 90, verdicts.BLOCK_RECOMMENDED, ["Approval to a wallet"]),
        ([with_floor("intent", 55, "Payment to an unverified contract")], None, 55, verdicts.HIGH_RISK, ["Payment to an unverified contract"]),
        ([clean("structural", [GOPLUS_HIGH])], None, 70, verdicts.HIGH_RISK, []),
        ([clean("structural", [GOPLUS_BLOCK])], None, 90, verdicts.BLOCK_RECOMMENDED, []),
    ],
)
def test_a_known_floor_sets_the_interim_band(results, local_match, score, classification, signals):
    verdict = first(progress_of(results, local_match))

    assert (verdict["risk_score"], verdict["classification"], verdict["status"]) == (score, classification, "unknown")
    assert verdict["danger_signals"][: len(signals)] == signals
    assert verdict["risk_display"] == IN_PROGRESS


def test_a_router_swap_keys_its_tokens_pending_and_coverage_by_token():
    token_a, token_b = "0x" + "11" * 20, "0x" + "22" * 20
    progress = progress_of([], pending=["structural", "honeypot"])
    progress.expect(token_a, ["structural", "honeypot"])
    progress.add_result(clean("structural"), token=token_a)
    progress.add_result(clean("honeypot"), token=token_a)
    progress.expect(token_b, ["structural", "honeypot"])
    progress.add_result(clean("structural", [GOPLUS_HIGH]), token=token_b)

    verdict = first(progress)

    assert verdict["pending_sources"] == [f"{token_b}:honeypot"]
    assert verdict["coverage"] == {f"{token_a}:structural": 1.0, f"{token_a}:honeypot": 1.0, f"{token_b}:structural": 1.0}
    assert (verdict["risk_score"], verdict["classification"]) == (70, verdicts.HIGH_RISK)


def test_block_known_is_set_only_by_a_floor_at_the_block_band():
    for result in (
        with_floor("intent", verdicts.BLOCK_MIN, "Approval to a wallet"),
        clean("structural", [GOPLUS_BLOCK]),
    ):
        assert progress_of([result]).block_known.is_set()
    assert progress_of([], ADMIN).block_known.is_set()

    errored = with_floor("intent", 90, "Approval to a wallet")
    errored.error = "intent analysis unavailable"
    for results, local_match in (
        ([with_floor("intent", verdicts.BLOCK_MIN - 1, "Payment to an unverified contract")], None),
        ([clean("structural", [GOPLUS_HIGH])], None),
        ([errored], None),
        ([], COMMUNITY),
        ([], None),
    ):
        progress = progress_of(results, local_match)
        assert not progress.block_known.is_set()
        assert first(progress)["classification"] != verdicts.BLOCK_RECOMMENDED
    assert progress_of([], None).local_matches == []


def _random_result(name, rng, local_match):
    """A returned analyzer's result: clean, adverse without a floor, or carrying a floor."""
    matches = [local_match] if local_match else []
    roll = rng.random()
    if roll < 0.4:
        return clean(name, matches)
    if roll < 0.6:
        result = clean(name, matches)
        result.score = rng.choice([20, 45, 60, 90])
        result.flags = ["Adverse finding"]
        return result
    if roll < 0.9:
        if name == "structural":
            return clean(name, matches + [rng.choice([GOPLUS_HIGH, GOPLUS_BLOCK, COMMUNITY])])
        return with_floor(name, rng.choice([30, 40, 55, 70, 71, 75, 90]), f"{name} floor")
    result = clean(name, matches)
    result.error = f"{name} analysis unavailable"
    result.score = 50
    return result


def test_the_interim_band_never_exceeds_the_final_band_for_the_same_evidence():
    rng = random.Random(20260924)
    for _ in range(2000):
        local_match = rng.choice([None, None, ADMIN, COMMUNITY])
        results = {name: _random_result(name, rng, local_match) for name in WEIGHTS}
        finished = [results[name] for name in WEIGHTS if rng.random() < 0.5]
        # The pending analyzers return clean results; the target's blacklist entry is in its
        # structural result either way, as check_address reports it.
        final = [
            result if result in finished else clean(name, [local_match] if local_match else [])
            for name, result in results.items()
        ]

        verdict = first(progress_of(finished, local_match))
        band = verdicts.classify(verdict["risk_score"])

        assert verdict["status"] == "unknown"
        assert verdict["classification"] == (verdicts.CAUTION if band == verdicts.SAFE else band)
        assert RANK[band] <= RANK[final_classification(final)], (finished, local_match)


HOLDERS_UNKNOWN = "Top-10 holder share unknown: no readable GoPlus holder list"


def test_the_interim_carries_the_returned_analyzers_notes_apart_from_its_danger_signals():
    structural = clean("structural", [GOPLUS_BLOCK])
    structural.data["notes"] = [HOLDERS_UNKNOWN]
    structural.flags = ["Scam DB match (1 sources)"]
    verdict = first(progress_of([structural, clean("market")]))

    assert verdict["notes"] == [HOLDERS_UNKNOWN]
    assert HOLDERS_UNKNOWN not in verdict["danger_signals"]
    # The final carries the same notes for the same results.
    assert verdict["notes"] == RiskEngine().compute_from_results([structural, clean("market")])["notes"]


def test_a_router_swaps_interim_names_each_notes_path_token():
    token = "0x" + "11" * 20
    progress = progress_of([], pending=["structural"])
    progress.expect(token, ["structural"])
    structural = clean("structural")
    structural.data["notes"] = [HOLDERS_UNKNOWN]
    progress.add_result(structural, token=token)

    assert first(progress)["notes"] == [f"{token}: {HOLDERS_UNKNOWN}"]


def test_an_interim_before_any_note_has_none():
    assert first(progress_of([]))["notes"] == []


def test_the_interim_never_claims_a_simulation():
    # The transaction simulation runs with the analyzers and reaches only the final.
    assert first(progress_of([clean("structural")], ADMIN))["simulated"] is False
