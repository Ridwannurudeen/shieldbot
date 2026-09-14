import copy
import json

import pytest

from scripts.census_4663.smoke_cases import record_verdict, select_cases


def population():
    tokens = []
    for index in range(35):
        tokens.append(
            {
                "token": "0x" + format(index + 1, "040x"),
                "buys_window": 1 if index % 5 in (0, 1) else 0,
                "sells_window": 1 if index % 5 == 0 else 0,
                "eligibility": {
                    0: "pass",
                    1: "pass",
                    2: "fail",
                    3: "unknown",
                    4: "young",
                }[index % 5],
                "swaps_30m": 0,
            }
        )
    return {
        "chain_id": 4663,
        "tokens": tokens,
        "window": {"since": "start", "until": "end"},
    }


def test_selection_is_deterministic_stratified_and_order_independent():
    report = population()
    selected = select_cases(report)
    reordered = copy.deepcopy(report)
    reordered["tokens"].reverse()
    assert selected == select_cases(reordered)
    assert len(selected["cases"]) == 20
    assert len({case["token"] for case in selected["cases"]}) == 20
    assert {case["stratum"] for case in selected["cases"]} == {
        "two_way",
        "buys_only",
        "ineligible",
        "unknown",
        "young",
    }
    assert all(case["evidence"]["token"] == case["token"] for case in selected["cases"])


def test_goplus_flagged_stratum_only_uses_available_results():
    report = population()
    token = report["tokens"][0]["token"]
    probe = {
        "chain_id": 4663,
        "provider": "goplus",
        "records": [
            {
                "token": token,
                "data_status": "available",
                "response": {"result": {token: {"is_honeypot": "1", "buy_tax": "0"}}},
            }
        ],
    }
    selected = select_cases(report, probe)
    flagged = [
        case for case in selected["cases"] if case["stratum"] == "goplus_flagged"
    ]
    assert len(flagged) == 1
    assert flagged[0]["evidence"]["goplus_flags"] == {"is_honeypot": "1"}
    probe["records"][0]["data_status"] = "unknown"
    assert not any(
        case["stratum"] == "goplus_flagged"
        for case in select_cases(report, probe)["cases"]
    )


def test_insufficient_population_and_wrong_chain_rejected():
    report = population()
    report["tokens"] = report["tokens"][:19]
    with pytest.raises(ValueError, match="at least 20"):
        select_cases(report)
    report["chain_id"] = 1
    with pytest.raises(ValueError, match="4663"):
        select_cases(report)
    with pytest.raises(ValueError, match="GoPlus"):
        select_cases(population(), {"chain_id": 56, "provider": "goplus"})


def test_record_appends_distinct_comparator_evidence_and_rejects_duplicates(tmp_path):
    selected = select_cases(population())
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(selected), encoding="utf-8")
    case_id = selected["cases"][0]["case_id"]
    first = record_verdict(
        path,
        case_id,
        "manual comparator",
        "unknown",
        "Accès refusé",
        True,
        "Login unavailable",
        "Reviewed manually",
    )
    second = record_verdict(
        path, case_id, "another comparator", "flagged", {"risk": "high"}
    )
    records = [
        json.loads(line)
        for line in path.with_suffix(".verdicts.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert records == [first, second]
    assert first["access_failure"] is True
    assert first["failure_reason"] == "Login unavailable"
    assert first["timestamp"].endswith("+00:00")
    with pytest.raises(ValueError, match="already recorded"):
        record_verdict(path, case_id, "manual comparator", "safe", {})
    assert (
        len(
            path.with_suffix(".verdicts.jsonl").read_text(encoding="utf-8").splitlines()
        )
        == 2
    )


def test_record_unknown_case_or_unexplained_failure_rejected(tmp_path):
    selected = select_cases(population())
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(selected), encoding="utf-8")
    with pytest.raises(ValueError, match="Case id"):
        record_verdict(path, "not-selected", "manual", "unknown", {})
    with pytest.raises(ValueError, match="requires a reason"):
        record_verdict(
            path, selected["cases"][0]["case_id"], "manual", "unknown", {}, True
        )
    assert not path.with_suffix(".verdicts.jsonl").exists()
