"""eval.verify_onchain re-reads the on-chain facts behind benchmark v2 labels; here against recorded replies.

The fixture holds four entries copied from eval/data/benchmark_v2.json (a drainer contract, an impostor
token, an address-poisoning EOA and a safe token) and the replies their RPCs gave on 2026-09-24.
"""

import json
import os
import urllib.error
from pathlib import Path

import pytest

import eval.verify_onchain as verify
from eval.dataset import load_dataset

FIXTURES = Path("tests/fixtures/benchmark_onchain")
DATASET = FIXTURES / "dataset.json"
REPLIES = json.loads((FIXTURES / "replies.json").read_text(encoding="utf-8"))
# The owner of the tokens in the fixture's zero-value poisoning transfer.
VICTIM = "0x64e6824a09ecc262c93833e1532488af52e8fc1e"


def replay(replies, changes=None):
    """A post() that answers each JSON-RPC call from the recorded replies, with ``changes`` applied by method."""
    table = {
        (r["url"], r["method"], json.dumps(r["params"], sort_keys=True)): r["result"]
        for r in replies
    }
    changes = changes or {}

    def post(url, payload):
        answers = []
        for call in payload:
            if call["method"] in changes:
                answer = changes[call["method"]]
            else:
                answer = {
                    "result": table[
                        (url, call["method"], json.dumps(call["params"], sort_keys=True))
                    ]
                }
            answers.append({"jsonrpc": "2.0", "id": call["id"], **answer})
        return answers

    return post


def test_the_recorded_replies_confirm_every_fact_of_the_fixture(capsys):
    assert verify.main(["--dataset", str(DATASET)], post=replay(REPLIES)) == 0
    out = capsys.readouterr().out
    assert "4 entries, 4 with on-chain facts: 11 facts, 0 differ, 0 could not be read" in out
    checks = [c for e in load_dataset(str(DATASET)) for c in verify.checks_for(e)[0]]
    assert {c.fact for c in checks} >= {"code", "symbol", "name"}
    assert sum(c.method == "eth_getLogs" for c in checks) == 2
    assert [c.fact for c in checks if c.method == "eth_getTransactionByHash"] == [
        "sender of Transfer log 51735216/147"
    ]


def test_a_poisoning_transfer_sent_by_someone_else_is_reported(capsys):
    stranger = replay(REPLIES, {"eth_getTransactionByHash": {"result": {"from": "0x" + "ab" * 20}}})
    assert verify.main(["--dataset", str(DATASET)], post=stranger) == 1
    out = capsys.readouterr().out
    assert out.count("DIFFERS") == 1 and "sender of Transfer log 51735216/147" in out
    assert "0x" + "ab" * 20 in out


def test_a_poisoning_transfer_the_owner_sent_themselves_is_reported(capsys):
    owner = replay(REPLIES, {"eth_getTransactionByHash": {"result": {"from": VICTIM.upper().replace("0X", "0x")}}})
    assert verify.main(["--dataset", str(DATASET)], post=owner) == 1
    out = capsys.readouterr().out
    assert out.count("DIFFERS") == 1 and f"{VICTIM}, the tokens' owner" in out


def test_a_fact_that_no_longer_holds_is_reported(capsys):
    changed = replay(REPLIES, {"eth_getCode": {"result": "0x"}})
    assert verify.main(["--dataset", str(DATASET)], post=changed) == 1
    out = capsys.readouterr().out
    assert out.count("DIFFERS") == 3  # three entries claim code; the EOA still has none
    assert "evidence says 0" not in out


def test_a_failed_read_is_never_counted_as_confirmed(capsys):
    failed = replay(
        REPLIES, {"eth_call": {"error": {"code": -32000, "message": "execution reverted"}}}
    )
    assert verify.main(["--dataset", str(DATASET)], post=failed) == 1
    out = capsys.readouterr().out
    # symbol() and name() of two tokens; an unanswered call is unread, never a match or a mismatch.
    assert out.count("UNREAD") == 4 and "execution reverted" in out and "DIFFERS" not in out
    assert "11 facts, 0 differ, 4 could not be read" in out


def test_an_rpc_that_refuses_the_request_leaves_its_facts_unread(capsys):
    def refused(url, payload):
        raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

    assert verify.main(["--dataset", str(DATASET)], post=refused) == 1
    out = capsys.readouterr().out
    # The transaction behind a log that was never read is unread too, not assumed.
    assert out.count("UNREAD") == 11 and "HTTP Error 403" in out
    assert "its Transfer log was not found" in out


def test_an_rpc_over_its_quota_leaves_the_batch_unread_with_its_reason(capsys):
    def over_quota(url, payload):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": "usage limit"}}

    assert verify.main(["--dataset", str(DATASET)], post=over_quota) == 1
    out = capsys.readouterr().out
    # The sender check never runs when its log was not read, so 10 of the 11 facts carry the reason.
    assert "0 differ, 11 could not be read" in out and out.count(": usage limit") == 10


def test_an_rpc_given_for_a_chain_reads_all_of_its_facts():
    urls = set()

    def recording(url, payload):
        urls.add(url)
        return []

    args = ["--dataset", str(DATASET), "--rpc", "8453=https://archive.example"]
    assert verify.main(args, post=recording) == 1
    assert "https://archive.example" in urls and "https://ethereum-rpc.publicnode.com" in urls
    assert not urls & {"https://mainnet.base.org", "https://base-rpc.publicnode.com"}
    with pytest.raises(SystemExit):
        verify.main(["--dataset", str(DATASET), "--rpc", "base=http://archive.example"])


def test_a_log_that_is_gone_is_reported(capsys):
    assert (
        verify.main(
            ["--dataset", str(DATASET)], post=replay(REPLIES, {"eth_getLogs": {"result": []}})
        )
        == 1
    )
    assert capsys.readouterr().out.count("'no such log'") == 2


def test_a_log_a_reorganisation_removed_does_not_count(capsys):
    removed = [
        {**reply, "result": [{**log, "removed": True} for log in reply["result"]]}
        if reply["method"] == "eth_getLogs"
        else reply
        for reply in REPLIES
    ]
    assert verify.main(["--dataset", str(DATASET)], post=replay(removed)) == 1
    out = capsys.readouterr().out
    assert out.count("'no such log'") == 2 and out.count("UNREAD") == 1


def test_an_onchain_source_without_a_readable_fact_is_reported(tmp_path, capsys):
    data = json.loads(DATASET.read_text(encoding="utf-8"))
    entry = data["entries"][0]
    entry["sources"] = [
        {**entry["sources"][0]},
        {**entry["sources"][-1], "evidence": "looked at the contract"},
    ]
    path = tmp_path / "dataset.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert verify.main(["--dataset", str(path)], post=replay(REPLIES)) == 1
    assert "UNCHECKED" in capsys.readouterr().out


def test_every_committed_entry_states_a_fact_the_script_can_read():
    for entry in load_dataset("eval/data/benchmark_v2.json"):
        checks, unchecked = verify.checks_for(entry)
        assert checks and not unchecked, (entry.chain_id, entry.address)
        if entry.category == "address_poisoning":
            assert {c.fact for c in checks if c.method == "eth_getCode"} == {"code"}
            assert all(c.expected == 0 for c in checks if c.method == "eth_getCode")
            [sender] = [c for c in checks if c.method == "eth_getTransactionByHash"]
            assert sender.expected != sender.not_sender


def test_no_runtime_module_imports_the_verifier():
    python_files = []
    for directory, subdirectories, files in os.walk("."):
        subdirectories[:] = [
            d for d in subdirectories if d not in {".git", "node_modules", "tests"}
        ]
        python_files += [Path(directory, name) for name in files if name.endswith(".py")]
    assert Path("eval/verify_onchain.py") in python_files and len(python_files) > 50
    for path in python_files:
        if path != Path("eval/verify_onchain.py"):
            assert "verify_onchain" not in path.read_text(encoding="utf-8", errors="replace"), path
