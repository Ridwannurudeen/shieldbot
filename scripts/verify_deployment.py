#!/usr/bin/env python3
"""Read-only verification of the three ShieldBot contracts on Robinhood Chain."""

import argparse
import ast
import re
from pathlib import Path
from urllib.parse import urlsplit

import requests
from eth_abi import decode, encode
from eth_abi.exceptions import DecodingError
from eth_utils import keccak


SIMULATION_SOURCE = (
    Path(__file__).resolve().parents[1] / "services" / "robinhood_simulation.py"
)
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
HEX_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})*")


class VerificationError(Exception):
    """A failed check with a message safe to print without RPC credentials."""


def address(value):
    if not ADDRESS_RE.fullmatch(value) or int(value, 16) == 0:
        raise argparse.ArgumentTypeError("expected a nonzero 20-byte 0x address")
    return value.lower()


def max_age(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("max-age must be an integer") from None
    if not 0 <= number < 2**64:
        raise argparse.ArgumentTypeError(
            "max-age must fit uint64 (0 through 2**64 - 1)"
        )
    return number


def rpc_url(value):
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme in ("http", "https")
            and parsed.hostname
            and not parsed.fragment
        )
        parsed.port
    except ValueError:
        valid = False
    if not valid:
        raise argparse.ArgumentTypeError(
            "rpc-url must be a valid HTTP(S) URL without a fragment"
        )
    return value


def simulation_usdg():
    # Read the literal without importing the application or loading its configuration.
    try:
        tree = ast.parse(SIMULATION_SOURCE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        raise VerificationError("cannot read the simulation's USDG literal") from None
    values = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "USDG"
            for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if (
        len(values) != 1
        or not ADDRESS_RE.fullmatch(values[0])
        or int(values[0], 16) == 0
    ):
        raise VerificationError(
            "simulation must define one nonzero USDG address literal"
        )
    return values[0].lower()


def rpc(session, url, method, params):
    response = session.post(
        url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=30,
        allow_redirects=False,
    )
    if response.status_code != 200:
        raise VerificationError(f"RPC HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError:
        raise VerificationError("RPC returned invalid JSON") from None
    if (
        not isinstance(payload, dict)
        or payload.get("jsonrpc") != "2.0"
        or type(payload.get("id")) is not int
        or payload["id"] != 1
    ):
        raise VerificationError("malformed JSON-RPC response or mismatched id")
    if "error" in payload:
        error = payload["error"]
        code = error.get("code") if isinstance(error, dict) else None
        detail = f" (code {code})" if type(code) is int else ""
        raise VerificationError(f"RPC error{detail}")
    if "result" not in payload:
        raise VerificationError("RPC response has no result")
    return payload["result"]


def hex_bytes(value):
    if not isinstance(value, str) or not HEX_RE.fullmatch(value):
        raise VerificationError("RPC returned malformed hex data")
    return bytes.fromhex(value[2:])


def verify(args, session):
    passed = failed = 0
    chain_ok = False

    def check(label, operation):
        nonlocal passed, failed
        try:
            detail = operation()
        except VerificationError as exc:
            failed += 1
            print(f"FAIL {label}: {exc}")
        except requests.RequestException as exc:
            failed += 1
            print(f"FAIL {label}: RPC request failed ({type(exc).__name__})")
        else:
            passed += 1
            print(f"PASS {label}: {detail}")

    def chain():
        nonlocal chain_ok
        value = rpc(session, args.rpc_url, "eth_chainId", [])
        if not isinstance(value, str) or not re.fullmatch(
            r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value
        ):
            raise VerificationError("RPC returned malformed chain id")
        chain_id = int(value, 16)
        if chain_id != 4663:
            raise VerificationError(f"expected 4663, got {chain_id}")
        chain_ok = True
        return str(chain_id)

    def read(method, params):
        if not chain_ok:
            raise VerificationError("not run: RPC chain 4663 was not verified")
        return hex_bytes(rpc(session, args.rpc_url, method, params))

    def code(contract):
        runtime = read("eth_getCode", [contract, "latest"])
        if not runtime:
            raise VerificationError("runtime bytecode size: 0 bytes (no code)")
        return f"{contract}; runtime bytecode size: {len(runtime)} bytes"

    def call(contract, signature, output_types, arguments=b""):
        data = "0x" + (keccak(text=signature)[:4] + arguments).hex()
        result = read("eth_call", [{"to": contract, "data": data}, "latest"])
        if len(result) != 32 * len(output_types):
            raise VerificationError("unexpected ABI return length")
        try:
            return decode(output_types, result)
        except DecodingError:
            raise VerificationError("undecodable ABI return data") from None

    def getter(contract, signature, expected):
        actual = call(contract, signature, ["address"])[0].lower()
        if actual != expected:
            raise VerificationError(f"expected {expected}, got {actual}")
        return actual

    def canonical_usdg():
        expected = simulation_usdg()
        if args.usdg != expected:
            raise VerificationError(
                f"expected simulation proxy {expected}, got {args.usdg}"
            )
        return expected

    def guard_check():
        allowed, reason = call(
            args.guard,
            "check(address,uint64)",
            ["bool", "uint8"],
            encode(["address", "uint64"], [args.subject, args.max_age]),
        )
        return f"allowed={allowed}, reason={reason} (a denial is a valid read)"

    check("RPC chain id", chain)
    for name in ("registry", "guard", "transfer"):
        check(f"{name} code on 4663", lambda name=name: code(getattr(args, name)))
    for contract, signature, expected, name in (
        (args.guard, "registry()", args.registry, "guard"),
        (args.transfer, "guard()", args.guard, "transfer"),
        (args.transfer, "subject()", args.subject, "transfer"),
        (args.transfer, "usdg()", args.usdg, "transfer"),
        (args.transfer, "recipient()", args.recipient, "transfer"),
        (args.registry, "owner()", args.owner, "registry"),
        (args.registry, "recorder()", args.recorder, "registry"),
    ):
        check(f"{name}.{signature}", lambda: getter(contract, signature, expected))
    check("USDG matches simulation Paxos proxy", canonical_usdg)
    check("guard.check(subject, maxAge)", guard_check)
    print(f"SUMMARY: {'FAIL' if failed else 'PASS'} ({passed} passed, {failed} failed)")
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", required=True, type=rpc_url)
    for name in (
        "registry",
        "guard",
        "transfer",
        "subject",
        "usdg",
        "recipient",
        "owner",
        "recorder",
    ):
        parser.add_argument(f"--{name}", required=True, type=address)
    parser.add_argument(
        "--max-age",
        required=True,
        type=max_age,
        help="publication-age limit in seconds (uint64)",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code:
            print("SUMMARY: FAIL (invalid command-line arguments; no RPC calls made)")
        raise
    with requests.Session() as session:
        session.trust_env = False
        return verify(args, session)


if __name__ == "__main__":
    raise SystemExit(main())
