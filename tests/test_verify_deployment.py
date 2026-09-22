"""Offline verification through the HTTP boundary; no chain access."""

import json as jsonlib

import pytest
import requests
from eth_abi import decode, encode
from eth_utils import keccak

from scripts import verify_deployment as verifier


REGISTRY, GUARD, TRANSFER, SUBJECT, RECIPIENT, OWNER, RECORDER, OTHER = (
    "0x" + f"{index:02x}" * 20 for index in range(1, 9)
)
GETTERS = (
    (GUARD, "registry()", REGISTRY, "guard.registry()"),
    (TRANSFER, "guard()", GUARD, "transfer.guard()"),
    (TRANSFER, "subject()", SUBJECT, "transfer.subject()"),
    (TRANSFER, "usdg()", verifier.simulation_usdg(), "transfer.usdg()"),
    (TRANSFER, "recipient()", RECIPIENT, "transfer.recipient()"),
    (REGISTRY, "owner()", OWNER, "registry.owner()"),
    (REGISTRY, "recorder()", RECORDER, "registry.recorder()"),
)


@pytest.fixture
def arguments():
    values = {
        "rpc-url": "https://rpc.invalid/private-token",
        "registry": REGISTRY,
        "guard": GUARD,
        "transfer": TRANSFER,
        "subject": SUBJECT,
        "usdg": verifier.simulation_usdg(),
        "recipient": RECIPIENT,
        "owner": OWNER,
        "recorder": RECORDER,
        "max-age": "900",
    }
    return [part for name, value in values.items() for part in (f"--{name}", value)]


@pytest.fixture
def rpc(monkeypatch):
    results = {("eth_chainId",): hex(4663)}
    for contract in (REGISTRY, GUARD, TRANSFER):
        results[("eth_getCode", contract)] = "0x600000"
    for contract, signature, expected, _ in GETTERS:
        selector = "0x" + keccak(text=signature)[:4].hex()
        results[("eth_call", contract, selector)] = (
            "0x" + encode(["address"], [expected]).hex()
        )
    results[("eth_call", GUARD, "0x5eb24b67")] = (
        "0x" + encode(["bool", "uint8"], [False, 1]).hex()
    )
    state = {"results": results, "calls": [], "status": 200}

    def post(session, url, *, json, timeout, allow_redirects):
        assert session.trust_env is False
        assert timeout == 30
        assert allow_redirects is False
        assert json["method"] in ("eth_chainId", "eth_getCode", "eth_call")
        state["calls"].append(json)
        if "exception" in state:
            raise state["exception"]
        method, params = json["method"], json["params"]
        if method == "eth_call":
            assert set(params[0]) == {"to", "data"}
            assert params[1] == "latest"
            key = (method, params[0]["to"], params[0]["data"][:10])
        elif method == "eth_getCode":
            assert params[1] == "latest"
            key = (method, params[0])
        else:
            assert params == []
            key = (method,)
        payload = {"jsonrpc": "2.0", "id": json["id"], "result": results[key]}
        payload = state.get("payloads", {}).get(key, payload)
        if "payload" in state:
            payload = state["payload"]
        response = requests.Response()
        response.status_code = state["status"]
        response._content = state.get("body", jsonlib.dumps(payload).encode())
        return response

    monkeypatch.setattr(requests.Session, "post", post)
    return state


def test_all_checks_and_runtime_sizes_with_policy_denial(arguments, rpc, capsys):
    assert verifier.main(arguments) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len([line for line in lines if line.startswith("PASS ")]) == 13
    assert sum("runtime bytecode size: 3 bytes" in line for line in lines) == 3
    assert "allowed=False, reason=1" in lines[-2]
    assert lines[-1] == "SUMMARY: PASS (13 passed, 0 failed)"
    assert len(rpc["calls"]) == 12
    check_call = rpc["calls"][-1]["params"][0]
    assert check_call["to"] == GUARD
    assert check_call["data"][:10] == "0x5eb24b67"
    assert decode(["address", "uint64"], bytes.fromhex(check_call["data"][10:])) == (
        SUBJECT,
        900,
    )


@pytest.mark.parametrize(
    "allowed,reason,max_age", [(True, 0, "0"), (False, 255, str(2**64 - 1))]
)
def test_decodable_uint8_and_uint64_boundaries(
    arguments, rpc, capsys, allowed, reason, max_age
):
    arguments[-1] = max_age
    rpc["results"][("eth_call", GUARD, "0x5eb24b67")] = (
        "0x" + encode(["bool", "uint8"], [allowed, reason]).hex()
    )
    assert verifier.main(arguments) == 0
    assert f"allowed={allowed}, reason={reason}" in capsys.readouterr().out


@pytest.mark.parametrize("contract,signature,expected,label", GETTERS)
def test_each_wrong_immutable_or_authority_fails(
    arguments, rpc, capsys, contract, signature, expected, label
):
    selector = "0x" + keccak(text=signature)[:4].hex()
    rpc["results"][("eth_call", contract, selector)] = (
        "0x" + encode(["address"], [OTHER]).hex()
    )
    assert verifier.main(arguments) == 1
    output = capsys.readouterr().out
    assert f"FAIL {label}: expected {expected}, got {OTHER}" in output
    assert output.endswith("SUMMARY: FAIL (12 passed, 1 failed)\n")


@pytest.mark.parametrize(
    "contract,name", [(REGISTRY, "registry"), (GUARD, "guard"), (TRANSFER, "transfer")]
)
def test_each_missing_contract_fails(arguments, rpc, capsys, contract, name):
    rpc["results"][("eth_getCode", contract)] = "0x"
    assert verifier.main(arguments) == 1
    assert (
        f"FAIL {name} code on 4663: runtime bytecode size: 0 bytes"
        in capsys.readouterr().out
    )


@pytest.mark.parametrize(
    "chain", ["0x1", "0x1238", "4663", None, 4663, "0x01237", "0x"]
)
def test_wrong_or_invalid_chain_does_not_read_contracts(arguments, rpc, capsys, chain):
    rpc["results"][("eth_chainId",)] = chain
    assert verifier.main(arguments) == 1
    output = capsys.readouterr().out
    assert "FAIL RPC chain id:" in output
    assert output.count("not run: RPC chain 4663 was not verified") == 11
    assert len(rpc["calls"]) == 1
    assert output.endswith("SUMMARY: FAIL (1 passed, 12 failed)\n")


def test_matching_usdg_getter_cannot_hide_wrong_proxy(arguments, rpc, capsys):
    arguments[arguments.index("--usdg") + 1] = OTHER
    selector = "0x" + keccak(text="usdg()")[:4].hex()
    rpc["results"][("eth_call", TRANSFER, selector)] = (
        "0x" + encode(["address"], [OTHER]).hex()
    )
    assert verifier.main(arguments) == 1
    output = capsys.readouterr().out
    assert "PASS transfer.usdg()" in output
    assert "FAIL USDG matches simulation Paxos proxy" in output


@pytest.mark.parametrize(
    "data",
    [
        "0x",
        "0x0",
        "0xzz",
        None,
        123,
        "0x" + "00" * 31,
        "0x" + "00" * 33,
        "0x01" + "00" * 31,
    ],
)
def test_malformed_getter_return_fails(arguments, rpc, capsys, data):
    selector = "0x" + keccak(text="registry()")[:4].hex()
    rpc["results"][("eth_call", GUARD, selector)] = data
    assert verifier.main(arguments) == 1
    assert "FAIL guard.registry():" in capsys.readouterr().out


@pytest.mark.parametrize(
    "data",
    [
        "0x",
        "0x" + "00" * 32,
        "0x" + "00" * 65,
        "0x" + (2).to_bytes(32, "big").hex() + "00" * 32,
        "0x" + "00" * 32 + (256).to_bytes(32, "big").hex(),
    ],
)
def test_guard_check_requires_exact_bool_uint8_encoding(arguments, rpc, capsys, data):
    rpc["results"][("eth_call", GUARD, "0x5eb24b67")] = data
    assert verifier.main(arguments) == 1
    assert "FAIL guard.check(subject, maxAge):" in capsys.readouterr().out


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"jsonrpc": "1.0", "id": 1, "result": "0x1237"},
        {"jsonrpc": "2.0", "id": 2, "result": "0x1237"},
        {"jsonrpc": "2.0", "id": True, "result": "0x1237"},
        {"jsonrpc": "2.0", "id": 1},
        {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32000, "message": "https://rpc.invalid/private-token"},
        },
        {"jsonrpc": "2.0", "id": 1, "result": "0x1237", "error": None},
    ],
)
def test_rpc_protocol_errors_fail_without_leaking_payload(
    arguments, rpc, capsys, payload
):
    rpc["payload"] = payload
    assert verifier.main(arguments) == 1
    output = capsys.readouterr().out
    assert "FAIL RPC chain id:" in output
    assert "private-token" not in output
    assert output.splitlines()[-1].startswith("SUMMARY: FAIL")


@pytest.mark.parametrize("status", [302, 429, 500])
def test_http_failures_are_explicit(arguments, rpc, capsys, status):
    rpc["status"] = status
    assert verifier.main(arguments) == 1
    assert f"FAIL RPC chain id: RPC HTTP {status}" in capsys.readouterr().out


def test_invalid_json_fails(arguments, rpc, capsys):
    rpc["body"] = b"private-token not json"
    assert verifier.main(arguments) == 1
    output = capsys.readouterr().out
    assert "RPC returned invalid JSON" in output
    assert "private-token" not in output


def test_reverting_guard_read_fails_and_preserves_other_checks(arguments, rpc, capsys):
    rpc["payloads"] = {
        ("eth_call", GUARD, "0x5eb24b67"): {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32000, "message": "execution reverted private-token"},
        }
    }
    assert verifier.main(arguments) == 1
    output = capsys.readouterr().out
    assert "FAIL guard.check(subject, maxAge): RPC error (code -32000)" in output
    assert output.endswith("SUMMARY: FAIL (12 passed, 1 failed)\n")
    assert "private-token" not in output


def test_address_comparisons_ignore_case(arguments, rpc):
    index = arguments.index("--usdg") + 1
    arguments[index] = "0x" + arguments[index][2:].upper()
    assert verifier.main(arguments) == 0


@pytest.mark.parametrize(
    "error",
    [
        requests.Timeout("https://rpc.invalid/private-token"),
        requests.ConnectionError("https://rpc.invalid/private-token"),
    ],
)
def test_network_failure_is_sanitized(arguments, rpc, capsys, error):
    rpc["exception"] = error
    assert verifier.main(arguments) == 1
    output = capsys.readouterr().out
    assert type(error).__name__ in output
    assert "private-token" not in output


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--registry", "0x123"),
        ("--guard", "0x" + "00" * 20),
        ("--owner", "0x" + "gg" * 20),
        ("--max-age", "-1"),
        ("--max-age", str(2**64)),
        ("--max-age", "1.5"),
        ("--rpc-url", "file:///private-token"),
        ("--rpc-url", "https://host:bad/private-token"),
    ],
)
def test_invalid_cli_never_calls_rpc(arguments, rpc, capsys, flag, value):
    arguments[arguments.index(flag) + 1] = value
    with pytest.raises(SystemExit) as exc:
        verifier.main(arguments)
    assert exc.value.code == 2
    assert not rpc["calls"]
    captured = capsys.readouterr()
    assert captured.out.endswith(
        "SUMMARY: FAIL (invalid command-line arguments; no RPC calls made)\n"
    )
    assert "private-token" not in captured.out + captured.err


def test_missing_arguments_end_with_summary(rpc, capsys):
    with pytest.raises(SystemExit) as exc:
        verifier.main([])
    assert exc.value.code == 2
    assert not rpc["calls"]
    assert capsys.readouterr().out.startswith("SUMMARY: FAIL")


def test_usdg_literal_read_does_not_execute_module(tmp_path, monkeypatch):
    source = tmp_path / "simulation.py"
    source.write_text(
        f'raise RuntimeError("must not execute")\nUSDG = "{OTHER}"\n', encoding="utf-8"
    )
    monkeypatch.setattr(verifier, "SIMULATION_SOURCE", source)
    assert verifier.simulation_usdg() == OTHER


@pytest.mark.parametrize(
    "source",
    [
        "",
        'USDG = "not an address"',
        'USDG = "0x" + "01" * 20',
        "USDG = (",
        'USDG = "0x' + "00" * 20 + '"',
    ],
)
def test_invalid_canonical_source_is_reported(
    arguments, rpc, capsys, tmp_path, monkeypatch, source
):
    path = tmp_path / "simulation.py"
    path.write_text(source, encoding="utf-8")
    monkeypatch.setattr(verifier, "SIMULATION_SOURCE", path)
    assert verifier.main(arguments) == 1
    assert "FAIL USDG matches simulation Paxos proxy" in capsys.readouterr().out
