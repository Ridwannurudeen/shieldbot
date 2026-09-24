"""Evidence documents for /api/firewall and /api/scan verdicts (core/scan_evidence.py)."""

import json

import pytest
from eth_utils import keccak

from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine
from core.scan_evidence import (
    SCHEMA,
    SCHEMA_VERSION,
    analyzer_outcomes,
    build_scan_evidence,
    oldest_simulation_block,
    read_commit,
    render_evidence_page,
    transaction_evidence,
)
from core.verdict_evidence import build_evidence, canonical_bytes, evidence_hash

TARGET = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"
CALLER = "0x9f8E7d6C5b4A39281706f5E4d3C2b1A09f8E7d6C"
SPENDER = "0x1234567890123456789012345678901234567890"
# approve(SPENDER, 2**256 - 1)
CALLDATA = "0x095ea7b3" + SPENDER[2:].lower().rjust(64, "0") + "f" * 64
RESPONSE = {
    "classification": "CAUTION",
    "risk_score": 35.5,
    "status": "unknown",
    "coverage": {"structural": 1.0, "honeypot": 0.5},
    "coverage_reasons": {"honeypot": "honeypot.is HTTP 502"},
    "failed_sources": ["honeypot"],
    "policy_mode": "BALANCED",
    "shield_score": {"risk_level": "MEDIUM"},
    "danger_signals": [f"Approval from {CALLER}"],
    "transaction_impact": {"recipient": TARGET},
}


def document(**overrides):
    arguments = {
        "endpoint": "/api/firewall",
        "chain_id": 56,
        "response": RESPONSE,
        "target": TARGET,
        "caller": CALLER,
        "scanned_at": 1790000000,
    }
    arguments.update(overrides)
    return build_scan_evidence(**arguments)


def test_the_document_carries_the_verdict_and_its_coverage():
    doc = document(observed_block=123, analyzers={"structural": {"status": "ok"}})
    assert doc["schema"] == SCHEMA
    assert doc["schema_version"] == SCHEMA_VERSION
    assert (doc["endpoint"], doc["source"], doc["cached_scan_at"]) == (
        "/api/firewall",
        "scan",
        None,
    )
    assert (doc["chain_id"], doc["target"]) == (56, TARGET.lower())
    assert (doc["classification"], doc["risk_score"], doc["risk_level"], doc["status"]) == (
        "CAUTION",
        35.5,
        "MEDIUM",
        "unknown",
    )
    assert doc["coverage"] == RESPONSE["coverage"]
    assert doc["coverage_reasons"] == RESPONSE["coverage_reasons"]
    assert doc["failed_sources"] == ["honeypot"]
    assert doc["policy_mode"] == "BALANCED"
    assert doc["observed_block"] == 123
    assert doc["analyzers"] == {"structural": {"status": "ok"}}
    assert doc["transaction"] is None
    assert doc["scanned_at"] == 1790000000
    assert "shieldbot_commit" in doc


def test_a_path_that_reports_no_level_or_policy_records_none():
    doc = document(
        response={"classification": "SAFE", "risk_score": 5, "status": "ok", "coverage": {}}
    )
    assert (doc["risk_level"], doc["policy_mode"], doc["failed_sources"], doc["analyzers"]) == (
        None,
    ) * 4
    assert doc["observed_block"] is None
    scan = document(
        endpoint="/api/scan", response={**RESPONSE, "shield_score": None, "risk_level": "UNKNOWN"}
    )
    assert scan["risk_level"] == "UNKNOWN"


def test_a_cached_verdict_says_it_came_from_the_cache():
    doc = document(cached_scan_at=1789999900.25)
    assert (doc["source"], doc["cached_scan_at"]) == ("cache", 1789999900)
    # Its scan time is the stored scan's, so every hit on one row gives the same bytes.
    assert doc["scanned_at"] == 1789999900
    assert canonical_bytes(doc) == canonical_bytes(
        document(cached_scan_at=1789999900.25, scanned_at=1790000999)
    )


@pytest.mark.parametrize(
    "caller",
    [
        CALLER.upper(),
        CALLER[2:],
        CALLER[2:].lower(),
        "0X" + CALLER[2:].lower(),
        f"  {CALLER}\n",
    ],
    ids=["0X-upper", "unprefixed", "unprefixed-lower", "0X-lower", "padded"],
)
def test_the_caller_is_masked_in_any_form_the_request_gave_it(caller):
    doc = document(
        target=CALLER,
        caller=caller,
        response={
            **RESPONSE,
            "coverage_reasons": {"signature": f"spender 0X{CALLER[2:].upper()} or {CALLER[2:]}"},
        },
    )
    assert doc["target"] == "[caller]"
    assert CALLER[2:].lower() not in canonical_bytes(doc).decode("utf-8").lower()


def test_the_hash_is_stable_and_is_keccak_of_the_canonical_bytes():
    first = document()
    reordered = document(
        response={**RESPONSE, "coverage": dict(reversed(list(RESPONSE["coverage"].items())))}
    )
    assert canonical_bytes(first) == canonical_bytes(reordered) == canonical_bytes(document())
    assert evidence_hash(first) == "0x" + keccak(canonical_bytes(first)).hex()
    assert evidence_hash(document(scanned_at=1790000001)) != evidence_hash(first)


def test_a_scan_document_cannot_be_read_as_a_registry_record():
    registry = build_evidence(
        56, TARGET, {"risk_level": "LOW", "coverage": {"structural": 1}, "status": "ok"}, None
    )
    assert "schema" not in registry
    assert document()["schema"] == "shieldbot-scan-evidence"


def test_no_caller_address_ip_key_or_calldata_reaches_the_document():
    transaction = transaction_evidence(CALLDATA, function="approve")
    doc = document(
        target=CALLER,
        analyzers={
            "signature": {
                "status": "unknown",
                "reason": f"Permit: approval to unknown spender {CALLER}",
            }
        },
        transaction=transaction,
        response={
            **RESPONSE,
            "coverage_reasons": {"signature": f"spender {CALLER.lower()} unknown"},
        },
    )
    text = canonical_bytes(doc).decode("utf-8").lower()
    assert CALLER[2:].lower() not in text
    assert CALLDATA[10:].lower() not in text
    assert doc["target"] == "[caller]"
    assert doc["analyzers"]["signature"]["reason"] == "Permit: approval to unknown spender [caller]"
    for field in ("from", "sender", "ip", "client_ip", "api_key", "x-api-key", "calldata", "data"):
        assert field not in doc
        assert field not in (doc["transaction"] or {})
    # Fields of the response that the document does not take never reach it.
    assert "danger_signals" not in doc and "transaction_impact" not in doc


def test_a_transaction_carries_its_function_and_calldata_hash_only():
    transaction = transaction_evidence(CALLDATA, function="approve")
    assert transaction == {
        "function": "approve",
        "calldata_keccak": "0x" + keccak(bytes.fromhex(CALLDATA[2:])).hex(),
        "sign_method": None,
        "typed_data_primary_type": None,
        "typed_data_keccak": None,
    }


def test_typed_data_is_hashed_canonically():
    typed = {"primaryType": "Permit", "message": {"value": "1"}, "domain": {"chainId": 56}}
    transaction = transaction_evidence("0x", sign_method="eth_signTypedData_v4", typed_data=typed)
    assert transaction["typed_data_primary_type"] == "Permit"
    assert transaction["typed_data_keccak"] == evidence_hash(typed)
    assert transaction["calldata_keccak"] == "0x" + keccak(b"").hex()
    assert transaction["function"] is None


@pytest.mark.parametrize("calldata", ["0x123", "0xzz", "095ea7b3"])
def test_calldata_that_is_not_hex_bytes_has_no_hash(calldata):
    assert transaction_evidence(calldata, function="unknown")["calldata_keccak"] is None


def test_analyzer_outcomes_follow_the_engine():
    results = [
        AnalyzerResult(
            "structural",
            0.4,
            25,
            data={
                "is_contract": True,
                "is_verified": True,
                "contract_age_days": 400,
                "coverage": {
                    "is_verified": True,
                    "contract_age_days": True,
                    "top10_holder_percent": False,
                },
                "field_providers": {"is_verified": "goplus"},
                "status": "unknown",
                "reason": "Top-10 holder share unknown",
            },
        ),
        AnalyzerResult("market", 0.25, 0, data={"skipped": True, "reason": "non-token contract"}),
        AnalyzerResult(
            "behavioral", 0.2, 50, error="behavioral analysis unavailable (TimeoutError)"
        ),
        AnalyzerResult(
            "honeypot", 0.15, 0, data={"status": "ok", "coverage": {"is_honeypot": True}}
        ),
    ]
    risk = RiskEngine().compute_from_results(results)
    outcomes = analyzer_outcomes(results, risk)
    assert outcomes["structural"] == {
        "status": "unknown",
        "score": 25,
        "coverage": risk["coverage"]["structural"],
        "reason": "Top-10 holder share unknown",
        "fields": {
            "is_verified": "answered",
            "contract_age_days": "answered",
            "top10_holder_percent": "unknown",
        },
        "field_providers": {"is_verified": "goplus"},
    }
    assert outcomes["market"] == {"status": "skipped", "score": 0.0, "coverage": 1, "fields": {}}
    assert outcomes["behavioral"] == {
        "status": "failed",
        "score": None,
        "coverage": 0,
        "reason": "behavioral analysis unavailable (TimeoutError)",
        "fields": {},
    }
    assert outcomes["honeypot"] == {
        "status": "ok",
        "score": 0,
        "coverage": 1.0,
        "fields": {"is_honeypot": "answered"},
    }
    json.dumps(outcomes, allow_nan=False)


def test_the_observed_block_is_the_oldest_simulation_block():
    results = [
        AnalyzerResult("honeypot", 1, 0, data={"simulation_block": 900}),
        AnalyzerResult("honeypot", 1, 0, data={"simulation_block": 850}),
        AnalyzerResult("honeypot", 1, 0, data={"simulation_block": True}),
        AnalyzerResult("structural", 1, 0, data={}),
    ]
    assert oldest_simulation_block(results) == 850
    assert oldest_simulation_block(results[3:]) is None


def _repo(tmp_path, head, refs=None, packed=None):
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text(head, encoding="utf-8")
    for ref, value in (refs or {}).items():
        (git / ref).parent.mkdir(parents=True, exist_ok=True)
        (git / ref).write_text(value, encoding="utf-8")
    if packed:
        (git / "packed-refs").write_text(packed, encoding="utf-8")
    return tmp_path


COMMIT = "5551bf3" + "0" * 33


def test_the_commit_is_read_from_a_detached_head(tmp_path):
    assert read_commit(_repo(tmp_path, COMMIT + "\n")) == COMMIT


def test_the_commit_is_read_through_a_branch_ref(tmp_path):
    repo = _repo(tmp_path, "ref: refs/heads/main\n", refs={"refs/heads/main": COMMIT + "\n"})
    assert read_commit(repo) == COMMIT


def test_the_commit_is_read_from_packed_refs(tmp_path):
    packed = "# pack-refs with: peeled fully-peeled sorted\n" + COMMIT + " refs/heads/main\n"
    assert read_commit(_repo(tmp_path, "ref: refs/heads/main\n", packed=packed)) == COMMIT


def test_no_readable_checkout_has_no_commit(tmp_path):
    assert read_commit(tmp_path) is None
    (tmp_path / ".git").write_text("gitdir: /elsewhere\n", encoding="utf-8")
    assert read_commit(tmp_path) is None


def test_the_page_escapes_every_value_and_shows_the_canonical_bytes():
    marked = '<script>alert("x")</script><img src=x onerror=alert(1)>'
    doc = document(
        target_token={"name": marked, "symbol": "<b>SYM</b>"},
        analyzers={"structural": {"status": "ok", "reason": marked}},
        transaction=transaction_evidence(CALLDATA, function=marked),
    )
    canonical = canonical_bytes(doc).decode("utf-8")
    digest = evidence_hash(doc)
    page = render_evidence_page(digest, canonical, 1790000000.0)
    assert "<script" not in page.lower()
    assert "<img" not in page.lower()
    assert "<b>SYM" not in page
    assert "&lt;script&gt;" in page
    assert digest in page
    assert "keccak256" in page
    # The canonical JSON is shown escaped, and unescaping it gives the exact bytes back.
    import html

    shown = page.split('<pre id="canonical">', 1)[1].split("</pre>", 1)[0]
    assert html.unescape(shown) == canonical
    assert "0x" + keccak(html.unescape(shown).encode("utf-8")).hex() == digest
