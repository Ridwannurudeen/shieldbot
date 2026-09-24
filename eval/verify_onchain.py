"""Re-check the on-chain facts behind benchmark v2 labels, against the public RPCs that first read them.

Usage:
    python -m eval.verify_onchain --dataset eval/data/benchmark_v2.json

Every source with provider "onchain" names the RPC it read (its url) and states what it read in its
evidence, in these forms; each is read again at the latest block:
  - "eth_getCode at block N returns K bytes of contract code": the address still holds K bytes of code.
  - "eth_getCode at block N returns no contract code": the address still holds none.
  - 'symbol() = "X"' and 'name() = "Y"': the token at the address still returns them.
  - "Transfer log at block B, log index I: token T, from F, to X, value V": block B still holds that log
    (a log a reorganisation removed does not count). When the text goes on "in a transaction sent by S",
    the transaction that emitted the log was sent by S, and S is not F.
An onchain source that states none of these is reported as unchecked, and a fact the RPC does not answer
is reported as unread, so a fact is never counted as confirmed without being read. Free public RPCs serve
old logs unevenly: --rpc CHAIN=URL reads a chain's facts from another RPC, such as an archive node. This
only reads (eth_getCode, eth_call, eth_getLogs, eth_getTransactionByHash); it computes no score, and
nothing that computes one imports it. eval/README.md says when to run it.
"""

import argparse
import json
import re
import sys
import urllib.request
from dataclasses import dataclass, replace

from eth_utils import keccak

from eval.dataset import load_dataset

TRANSFER_TOPIC = "0x" + keccak(text="Transfer(address,address,uint256)").hex()
SYMBOL_SELECTOR = "0x95d89b41"
NAME_SELECTOR = "0x06fdde03"
# mainnet.base.org answers at most 10 calls per batch.
BATCH_SIZE = 10
TIMEOUT_SECONDS = 60

_CODE = re.compile(r"eth_getCode at block \d+ returns (\d+) bytes of contract code")
_NO_CODE = re.compile(r"eth_getCode at block \d+ returns no contract code")
_SYMBOL = re.compile(r'symbol\(\) = "([^"]*)"')
_NAME = re.compile(r'name\(\) = "([^"]*)"')
_LOG = re.compile(
    r"Transfer log at block (\d+), log index (\d+): token (0x[0-9a-fA-F]{40}), "
    r"from (0x[0-9a-fA-F]{40}), to (0x[0-9a-fA-F]{40}), value (\d+)"
    r"(?:, in a transaction sent by (0x[0-9a-fA-F]{40}))?"
)
SENDER_OF = "sender of "


@dataclass
class Check:
    """One on-chain fact of one entry: the JSON-RPC call that reads it and what the evidence says it returns.

    A "sender of" check reads the transaction that emitted a Transfer log, so its params (the transaction
    hash) are only known once that log is read; ``not_sender`` is the tokens' owner, who must not have sent it.
    """

    chain_id: int
    address: str
    url: str
    fact: str
    method: str
    params: list
    expected: object
    not_sender: str = None


def checks_for(entry):
    """The checks an entry's onchain sources state, and the evidence of any onchain source that states none."""
    checks, unchecked = [], []
    for source in entry.sources:
        if source["provider"].lower() != "onchain":
            continue
        evidence, url = source["evidence"], source["url"]
        found = []
        code = _CODE.search(evidence)
        if code:
            found.append(("code", "eth_getCode", [entry.address, "latest"], int(code.group(1))))
        if _NO_CODE.search(evidence):
            found.append(("code", "eth_getCode", [entry.address, "latest"], 0))
        for fact, pattern, selector in (
            ("symbol", _SYMBOL, SYMBOL_SELECTOR),
            ("name", _NAME, NAME_SELECTOR),
        ):
            match = pattern.search(evidence)
            if match:
                found.append(
                    (
                        fact,
                        "eth_call",
                        [{"to": entry.address, "data": selector}, "latest"],
                        match.group(1),
                    )
                )
        senders = []
        for block, index, token, owner, receiver, value, tx_sender in _LOG.findall(evidence):
            query = {
                "address": token,
                "topics": [TRANSFER_TOPIC, _topic(owner), _topic(receiver)],
                "fromBlock": hex(int(block)),
                "toBlock": hex(int(block)),
            }
            fact = f"Transfer log {block}/{index}"
            found.append((fact, "eth_getLogs", [query], (int(index), int(value))))
            if tx_sender:
                senders.append(
                    Check(
                        entry.chain_id,
                        entry.address,
                        url,
                        SENDER_OF + fact,
                        "eth_getTransactionByHash",
                        [],
                        tx_sender.lower(),
                        owner.lower(),
                    )
                )
        if not found:
            unchecked.append(evidence)
        checks.extend(
            Check(entry.chain_id, entry.address, url, fact, method, params, expected)
            for fact, method, params, expected in found
        )
        checks.extend(senders)
    return checks, unchecked


def http_post(url, payload):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        # Public RPCs answer urllib's default User-Agent with 403.
        headers={"Content-Type": "application/json", "User-Agent": "shieldbot-benchmark-verify"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.load(response)


def run_checks(checks, post=http_post):
    """(differs, unread): each check whose result is not what its evidence says, with what was read; and each
    check its RPC did not answer, with the reason.

    Sender checks run second, one eth_getTransactionByHash per Transfer log that was found; the sender of a
    log that was not found is unread.
    """
    differs, unread, hashes = [], [], {}
    senders = [c for c in checks if c.fact.startswith(SENDER_OF)]
    for check, result in _read([c for c in checks if c not in senders], post, unread):
        if check.method == "eth_getLogs":
            log = _matching_log(check, result)
            if log:
                hashes[(check.chain_id, check.address, check.fact)] = log["transactionHash"]
        found = _observed(check, result)
        if found != check.expected:
            differs.append((check, found))
    readable = []
    for check in senders:
        tx_hash = hashes.get((check.chain_id, check.address, check.fact[len(SENDER_OF) :]))
        if tx_hash:
            readable.append(replace(check, params=[tx_hash]))
        else:
            unread.append((check, "its Transfer log was not found"))
    for check, result in _read(readable, post, unread):
        found = _observed(check, result)
        if found != check.expected:
            differs.append((check, found))
    return differs, unread


def _read(checks, post, unread):
    """(check, result) for each check its RPC answered, in batches per RPC; the rest are added to ``unread``."""
    by_url = {}
    for check in checks:
        by_url.setdefault(check.url, []).append(check)
    for url, group in by_url.items():
        for start in range(0, len(group), BATCH_SIZE):
            chunk = group[start : start + BATCH_SIZE]
            payload = [
                {"jsonrpc": "2.0", "id": i, "method": c.method, "params": c.params}
                for i, c in enumerate(chunk)
            ]
            try:
                reply = post(url, payload)
            except (OSError, ValueError) as e:
                unread.extend((check, f"{type(e).__name__}: {e}") for check in chunk)
                continue
            answers = {item.get("id"): item for item in reply} if isinstance(reply, list) else {}
            for i, check in enumerate(chunk):
                answer = answers.get(i, {})
                if answer.get("result") is None:
                    unread.append((check, (answer.get("error") or {}).get("message", "no answer")))
                    continue
                yield check, answer["result"]


def _observed(check, result):
    if check.method == "eth_getCode":
        return (len(result) - 2) // 2
    if check.method == "eth_call":
        return _decode_string(result)
    if check.method == "eth_getTransactionByHash":
        sender = str(result.get("from", "")).lower()
        return f"{sender}, the tokens' owner" if sender == check.not_sender else sender
    log = _matching_log(check, result)
    if not log:
        return "no such log"
    data = log["data"]
    return check.expected[0], int(data, 16) if data not in ("0x", "") else 0


def _matching_log(check, logs):
    """The log at the evidence's log index, unless a reorganisation removed it."""
    index, _ = check.expected
    for log in logs:
        if int(log["logIndex"], 16) == index and not log.get("removed"):
            return log
    return None


def _decode_string(result):
    """An ABI string, or a bytes32 some older tokens return, from an eth_call result; None for neither."""
    raw = bytes.fromhex(result[2:]) if isinstance(result, str) and result.startswith("0x") else b""
    try:
        if len(raw) >= 64 and int.from_bytes(raw[:32], "big") == 32:
            length = int.from_bytes(raw[32:64], "big")
            if 64 + length <= len(raw):
                return raw[64 : 64 + length].decode("utf-8")
        if len(raw) == 32:
            return raw.rstrip(b"\0").decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None


def _topic(address):
    return "0x" + "0" * 24 + address[2:].lower()


def main(argv=None, post=http_post):
    parser = argparse.ArgumentParser(
        description="Re-check the on-chain facts behind benchmark v2 labels"
    )
    parser.add_argument(
        "--dataset", default="eval/data/benchmark_v2.json", help="Path to benchmark v2 JSON file"
    )
    parser.add_argument(
        "--rpc",
        action="append",
        default=[],
        metavar="CHAIN=URL",
        help="Read this chain's facts from URL instead of the RPC each source names (repeatable)",
    )
    args = parser.parse_args(argv)
    overrides = {}
    for item in args.rpc:
        chain, _, url = item.partition("=")
        if not (chain.isdigit() and url.startswith("https://")):
            parser.error(f"--rpc takes CHAIN=https://..., not {item!r}")
        overrides[int(chain)] = url

    entries = load_dataset(args.dataset)
    checks, unchecked = [], []
    for entry in entries:
        found, missing = checks_for(entry)
        checks.extend(replace(c, url=overrides.get(c.chain_id, c.url)) for c in found)
        unchecked.extend((entry, evidence) for evidence in missing)
    differs, unread = run_checks(checks, post)

    checked_entries = {(c.chain_id, c.address.lower()) for c in checks}
    print(
        f"{len(entries)} entries, {len(checked_entries)} with on-chain facts: {len(checks)} facts, "
        f"{len(differs)} differ, {len(unread)} could not be read, {len(unchecked)} sources state no fact"
    )
    for check, found in differs:
        print(
            f"DIFFERS chain {check.chain_id} {check.address} {check.fact}: evidence says {check.expected!r}, "
            f"read {found!r} from {check.url}"
        )
    for check, reason in unread:
        print(
            f"UNREAD chain {check.chain_id} {check.address} {check.fact} from {check.url}: {reason}"
        )
    for entry, evidence in unchecked:
        print(f"UNCHECKED chain {entry.chain_id} {entry.address}: no readable fact in {evidence!r}")
    return 1 if differs or unread or unchecked else 0


if __name__ == "__main__":
    sys.exit(main())
