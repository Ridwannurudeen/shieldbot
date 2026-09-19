"""Evidence documents and verdict mapping for verdicts published on Robinhood Chain."""

import math

import pytest
from eth_utils import keccak

from core.verdict_evidence import (
    SCHEMA_VERSION,
    Verdict,
    build_evidence,
    canonical_bytes,
    evidence_hash,
    is_simulation_proven_honeypot,
    verdict_for,
)

SUBJECT = "0xABCDEF0000000000000000000000000000000001"
COMPLETE = {
    "status": "ok",
    "coverage": {"structural": 1, "market": 1, "behavioral": 1, "honeypot": 1},
    "coverage_reasons": {},
    "rug_probability": 12.5,
}
PROVEN = {
    "is_honeypot": True,
    "can_sell": False,
    "field_providers": {"is_honeypot": "eth_simulateV1", "can_sell": "eth_simulateV1"},
}


def complete(level):
    return {**COMPLETE, "risk_level": level}


# Every way core.extension_formatter.is_scan_incomplete can classify a scan as incomplete.
INCOMPLETE_VARIANTS = {
    "status_unknown": {"status": "unknown"},
    "status_missing": {"status": None},
    "partial": {"partial": True},
    "risk_level_unknown": {"risk_level": "UNKNOWN"},
    "simulation_failed": {"simulation_failed": True},
    "no_coverage": {"coverage": {}},
    "fractional_coverage": {"coverage": {"structural": 1, "honeypot": 0.8}},
    "none_coverage": {"coverage": {"structural": 1, "honeypot": None}},
}


# ---------------------------------------------------------------------------
# Verdict mapping
# ---------------------------------------------------------------------------


def test_verdict_codes_match_the_solidity_enum_order():
    assert [(v.name, v.value) for v in Verdict] == [
        ("UNKNOWN", 0),
        ("LOW", 1),
        ("MEDIUM", 2),
        ("HIGH", 3),
        ("HONEYPOT", 4),
    ]


@pytest.mark.parametrize(
    "level,expected",
    [
        ("LOW", Verdict.LOW),
        ("MEDIUM", Verdict.MEDIUM),
        ("HIGH", Verdict.HIGH),
        ("low", Verdict.LOW),
        ("High", Verdict.HIGH),
    ],
)
def test_complete_scan_maps_by_risk_level(level, expected):
    assert verdict_for(complete(level)) is expected


@pytest.mark.parametrize("level", ["SAFE", "WARNING", "DANGER", "", None])
def test_complete_scan_with_unrecognised_level_is_unknown(level):
    assert verdict_for(complete(level)) is Verdict.UNKNOWN


def test_complete_scan_without_risk_level_is_unknown():
    assert verdict_for(dict(COMPLETE)) is Verdict.UNKNOWN


@pytest.mark.parametrize("variant", sorted(INCOMPLETE_VARIANTS))
@pytest.mark.parametrize("level", ["LOW", "MEDIUM", "HIGH", "low"])
def test_incomplete_scan_is_unknown_never_low(variant, level):
    scan = {**complete(level), **INCOMPLETE_VARIANTS[variant]}
    if variant != "risk_level_unknown":
        scan["risk_level"] = level
    assert verdict_for(scan) is Verdict.UNKNOWN


@pytest.mark.parametrize("variant", sorted(INCOMPLETE_VARIANTS))
def test_simulation_proven_honeypot_wins_over_missing_fields(variant):
    scan = {**complete("HIGH"), **INCOMPLETE_VARIANTS[variant]}
    assert verdict_for(scan, PROVEN) is Verdict.HONEYPOT


def test_simulation_proven_honeypot_wins_over_complete_risk_level():
    assert verdict_for(complete("LOW"), PROVEN) is Verdict.HONEYPOT
    assert verdict_for(complete("HIGH"), PROVEN) is Verdict.HONEYPOT


@pytest.mark.parametrize(
    "honeypot",
    [
        None,
        {},
        {"is_honeypot": False, "field_providers": {"is_honeypot": "eth_simulateV1"}},
        {"is_honeypot": None, "field_providers": {"is_honeypot": "eth_simulateV1"}},
        {"is_honeypot": 1, "field_providers": {"is_honeypot": "eth_simulateV1"}},
        {"is_honeypot": "true", "field_providers": {"is_honeypot": "eth_simulateV1"}},
        {"is_honeypot": True},
        {"is_honeypot": True, "field_providers": None},
        {"is_honeypot": True, "field_providers": {"is_honeypot": "goplus"}},
        {"is_honeypot": True, "field_providers": {"is_honeypot": "honeypot.is"}},
        {"is_honeypot": True, "field_providers": {"can_sell": "eth_simulateV1"}},
    ],
)
def test_only_the_simulation_proves_a_honeypot(honeypot):
    assert not is_simulation_proven_honeypot(honeypot)
    # An unproven honeypot claim on an incomplete scan stays UNKNOWN; on a complete scan it keeps its level.
    assert verdict_for({**complete("HIGH"), "status": "unknown"}, honeypot) is Verdict.UNKNOWN
    assert verdict_for(complete("HIGH"), honeypot) is Verdict.HIGH


def test_proven_honeypot_detection():
    assert is_simulation_proven_honeypot(PROVEN)


# ---------------------------------------------------------------------------
# Evidence payload
# ---------------------------------------------------------------------------


def test_build_evidence_carries_the_public_fields():
    honeypot = {
        "is_honeypot": False,
        "can_buy": True,
        "can_sell": True,
        "buy_tax": 0.0,
        "sell_tax": 2.5,
        "simulation_failed": False,
        "simulation_block": 65551506,
        "field_providers": {"is_honeypot": "eth_simulateV1", "sell_tax": "eth_simulateV1"},
        "reason": "v4-native pool 0x01 at block 65551506: buy and sell succeeded",
        # Internal fields that are not part of the public document:
        "coverage": {"sell_tax": True},
        "status": "ok",
        "honeypot_reason": "x",
        "low_tax_honeypot": False,
    }
    payload = build_evidence(4663, SUBJECT, complete("LOW"), honeypot, scanned_at=1789000000)
    assert payload == {
        "schema_version": SCHEMA_VERSION,
        "chain_id": 4663,
        "subject": SUBJECT.lower(),
        "verdict": "LOW",
        "status": "ok",
        "coverage": COMPLETE["coverage"],
        "coverage_reasons": {},
        "rug_probability": 12.5,
        "honeypot": {
            "is_honeypot": False,
            "can_buy": True,
            "can_sell": True,
            "buy_tax": 0.0,
            "sell_tax": 2.5,
            "simulation_failed": False,
            "simulation_block": 65551506,
            "field_providers": {"is_honeypot": "eth_simulateV1", "sell_tax": "eth_simulateV1"},
            "reason": "v4-native pool 0x01 at block 65551506: buy and sell succeeded",
        },
        "observed_block": 65551506,
        "scanned_at": 1789000000,
    }


def test_build_evidence_without_honeypot_data():
    payload = build_evidence(4663, SUBJECT, complete("MEDIUM"), None, scanned_at=1)
    assert "honeypot" not in payload
    assert payload["observed_block"] == 0
    assert payload["verdict"] == "MEDIUM"


@pytest.mark.parametrize("block", [None, True, -1, "65551506", 1.5])
def test_observed_block_is_zero_unless_a_real_simulation_block(block):
    payload = build_evidence(
        4663, SUBJECT, complete("LOW"), {"simulation_block": block}, scanned_at=1
    )
    assert payload["observed_block"] == 0


def test_build_evidence_reports_incomplete_status_even_if_the_engine_said_ok():
    scan = {
        **complete("LOW"),
        "coverage": {"structural": 1, "honeypot": 0.5},
        "coverage_reasons": {"honeypot": "sell tax unmeasured"},
    }
    payload = build_evidence(4663, SUBJECT, scan, None, scanned_at=1)
    assert payload["status"] == "unknown"
    assert payload["verdict"] == "UNKNOWN"
    assert payload["coverage_reasons"] == {"honeypot": "sell tax unmeasured"}


def test_build_evidence_keeps_missing_rug_probability_unknown():
    scan = {k: v for k, v in complete("LOW").items() if k != "rug_probability"}
    assert build_evidence(4663, SUBJECT, scan, None, scanned_at=1)["rug_probability"] is None


# ---------------------------------------------------------------------------
# Canonical form and hash
# ---------------------------------------------------------------------------

# Written by hand, then hashed with Foundry's `cast keccak` over its UTF-8 bytes (an independent keccak
# implementation). The digest is kept as bare hex because the repository's secret scanner rejects 0x+64-hex literals.
HAND_CANONICAL = (
    '{"chain_id":4663,"coverage":{"honeypot":0.8,"structural":1},'
    '"coverage_reasons":{"honeypot":"sell_tax unmeasured — pool hook"},'
    '"honeypot":{"buy_tax":0.0,"can_buy":true,"can_sell":false,'
    '"field_providers":{"can_sell":"eth_simulateV1","is_honeypot":"eth_simulateV1"},'
    '"is_honeypot":true,"reason":"sell reverted","sell_tax":null,"simulation_block":65704949},'
    '"observed_block":65704949,"rug_probability":80.0,"scanned_at":1789000000,"schema_version":1,'
    '"status":"unknown","subject":"0xabcdef0000000000000000000000000000000001","verdict":"HONEYPOT"}'
)
HAND_HASH_HEX = "00b721cf35759c58454c6d20ce074285c889ec088d24dc6ab7807da3ed237379"


def hand_payload():
    scan = {
        "risk_level": "HIGH",
        "rug_probability": 80.0,
        "status": "unknown",
        "coverage": {"structural": 1, "honeypot": 0.8},
        "coverage_reasons": {"honeypot": "sell_tax unmeasured — pool hook"},
    }
    honeypot = {
        "is_honeypot": True,
        "can_buy": True,
        "can_sell": False,
        "buy_tax": 0.0,
        "sell_tax": None,
        "simulation_block": 65704949,
        "reason": "sell reverted",
        "field_providers": {"is_honeypot": "eth_simulateV1", "can_sell": "eth_simulateV1"},
        "coverage": {"sell_tax": False},
        "status": "unknown",
    }
    return build_evidence(4663, SUBJECT, scan, honeypot, scanned_at=1789000000)


def test_canonical_form_matches_the_hand_written_document():
    assert canonical_bytes(hand_payload()) == HAND_CANONICAL.encode("utf-8")


def test_evidence_hash_matches_the_independently_computed_keccak():
    assert evidence_hash(hand_payload()) == "0x" + HAND_HASH_HEX
    assert keccak(HAND_CANONICAL.encode("utf-8")).hex() == HAND_HASH_HEX


def test_canonical_form_is_utf8_not_ascii_escaped():
    encoded = canonical_bytes({"reason": "—"})
    assert encoded == b'{"reason":"\xe2\x80\x94"}'


def test_canonical_form_ignores_insertion_order():
    assert canonical_bytes({"b": 1, "a": {"d": 2, "c": 3}}) == canonical_bytes(
        {"a": {"c": 3, "d": 2}, "b": 1}
    )
    assert canonical_bytes({"b": 1, "a": {"d": 2, "c": 3}}) == b'{"a":{"c":3,"d":2},"b":1}'


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_canonical_form_rejects_nan_and_infinity(value):
    with pytest.raises(ValueError):
        canonical_bytes({"rug_probability": value})
    with pytest.raises(ValueError):
        evidence_hash({"coverage": {"honeypot": value}})


def test_evidence_hash_format():
    digest = evidence_hash({"a": 1})
    assert digest == "0x" + keccak(b'{"a":1}').hex()
    assert len(digest) == 66
