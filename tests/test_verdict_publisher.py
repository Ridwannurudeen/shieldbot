"""VerdictPublisher: stores every evidence document and records Robinhood Chain verdicts on-chain.

The RPC is a fake JSON-RPC node; no test touches the network. The recorder key is a dummy value that
controls no funds on any chain.
"""

import asyncio
import json
import logging
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
import pytest_asyncio
import rlp
from eth_abi import decode
from eth_account import Account
from eth_utils import keccak, to_checksum_address

import services.verdict_publisher as vp
from core.database import Database
from services.verdict_publisher import VerdictPublisher

KEY = "0x" + "5a" * 32
RECORDER = Account.from_key(KEY).address
REGISTRY = "0x" + "c0" * 20
TOKEN = "0x" + "7a" * 20
RPC_SECRET = "SYNTHETIC_RPC_SECRET"
RPC = f"https://rpc.invalid/v2/{RPC_SECRET}"
BASE_FEE = 56_209_984

COMPLETE = {
    "status": "ok",
    "risk_level": "LOW",
    "rug_probability": 5.0,
    "coverage": {"structural": 1, "honeypot": 1},
    "coverage_reasons": {},
}
INCOMPLETE = {
    "status": "unknown",
    "risk_level": "MEDIUM",
    "rug_probability": 40.0,
    "coverage": {"structural": 1, "honeypot": 0.8},
    "coverage_reasons": {"honeypot": "sell tax unmeasured"},
}
HONEYPOT = {
    "is_honeypot": True,
    "can_sell": False,
    "sell_tax": None,
    "simulation_block": 65704949,
    "field_providers": {"is_honeypot": "eth_simulateV1", "can_sell": "eth_simulateV1"},
    "reason": "sell reverted",
}


class FakeResponse:
    def __init__(self, status, payload, gate=None):
        self.status = status
        self._payload = payload
        self._gate = gate

    async def __aenter__(self):
        if self._gate is not None:
            await self._gate.wait()
        await asyncio.sleep(0)
        return self

    async def __aexit__(self, *exc):
        return False

    async def json(self, content_type=None):
        return self._payload


class FakeChain:
    """Answers the publisher's JSON-RPC requests the way a Robinhood Chain node would."""

    def __init__(self, nonce=7, base_fee=BASE_FEE, estimate=100_000):
        self.nonce = nonce
        self.base_fee = base_fee
        self.estimate = estimate
        self.posts = []
        self.sent = []
        self.http_statuses = []
        self.rate_limited_posts = 0
        self.errors = {}
        self.block = None
        self.raise_on_post = None
        self.gate = None

    def post(self, url, json):
        self.posts.append((url, json))
        if self.raise_on_post is not None:
            raise self.raise_on_post
        if self.http_statuses:
            return FakeResponse(self.http_statuses.pop(0), None)
        rows = json if isinstance(json, list) else [json]
        if self.rate_limited_posts:
            self.rate_limited_posts -= 1
            answers = [
                {
                    "jsonrpc": "2.0",
                    "id": row["id"],
                    "error": {"code": -32005, "message": "limit exceeded"},
                }
                for row in rows
            ]
        else:
            answers = [self.answer(row) for row in rows]
        return FakeResponse(200, answers if isinstance(json, list) else answers[0], self.gate)

    def answer(self, row):
        method = row["method"]
        if method in self.errors:
            return {"jsonrpc": "2.0", "id": row["id"], "error": self.errors[method]}
        if method == "eth_getTransactionCount":
            result = hex(self.nonce)
        elif method == "eth_getBlockByNumber":
            result = (
                self.block
                if self.block is not None
                else {
                    "number": hex(65_526_359),
                    "baseFeePerGas": hex(self.base_fee),
                }
            )
        elif method == "eth_estimateGas":
            result = hex(self.estimate)
        elif method == "eth_sendRawTransaction":
            raw = bytes.fromhex(row["params"][0][2:])
            self.sent.append(raw)
            self.nonce += 1
            result = "0x" + keccak(raw).hex()
        else:
            raise AssertionError(f"unexpected method {method}")
        return {"jsonrpc": "2.0", "id": row["id"], "result": result}

    def methods(self):
        return [
            [row["method"] for row in (body if isinstance(body, list) else [body])]
            for _, body in self.posts
        ]


@contextmanager
def rpc_node(chain):
    session = MagicMock()
    session.post.side_effect = chain.post
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=False)
    with patch("services.verdict_publisher.aiohttp.ClientSession", return_value=context) as factory:
        yield factory


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


def make_publisher(db, key=KEY, registry=REGISTRY):
    return VerdictPublisher(db, rpc_url=RPC, registry_address=registry, recorder_key=key)


async def drain(publisher):
    while publisher._tasks:
        await asyncio.gather(*list(publisher._tasks))


def decode_record(raw):
    """Decode a signed type-2 record() transaction into its fields and record() arguments."""
    assert raw[0] == 2
    chain_id, nonce, tip, max_fee, gas, to, value, data, access_list, *_ = rlp.decode(raw[1:])
    assert data[:4] == keccak(text="record(address,uint8,bytes32,uint64)")[:4]
    subject, verdict, evidence_hash, observed_block = decode(
        ["address", "uint8", "bytes32", "uint64"], data[4:]
    )

    def number(field):
        return int.from_bytes(field, "big")

    return {
        "chain_id": number(chain_id),
        "nonce": number(nonce),
        "tip": number(tip),
        "max_fee": number(max_fee),
        "gas": number(gas),
        "to": "0x" + to.hex(),
        "value": number(value),
        "data": data,
        "access_list": access_list,
        "subject": subject.lower(),
        "verdict": verdict,
        "evidence_hash": "0x" + evidence_hash.hex(),
        "observed_block": observed_block,
        "sender": Account.recover_transaction(raw),
    }


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_record_selector_matches_the_contract():
    # `cast sig "record(address,uint8,bytes32,uint64)"` prints 0xf160da27.
    assert vp.RECORD_SELECTOR.hex() == "f160da27"


def test_configuration_comes_from_the_environment(monkeypatch, db):
    monkeypatch.setenv("ROBINHOOD_VERDICT_REGISTRY", REGISTRY)
    monkeypatch.setenv("ROBINHOOD_RECORDER_PRIVATE_KEY", KEY)
    publisher = VerdictPublisher(db, rpc_url=RPC)
    assert publisher.is_onchain_enabled()
    assert publisher.registry == to_checksum_address(REGISTRY)
    assert publisher.recorder == RECORDER


@pytest.mark.parametrize("registry,key", [("", KEY), (REGISTRY, ""), ("", "")])
def test_on_chain_recording_needs_both_settings(monkeypatch, db, registry, key):
    monkeypatch.setenv("ROBINHOOD_VERDICT_REGISTRY", registry)
    monkeypatch.setenv("ROBINHOOD_RECORDER_PRIVATE_KEY", key)
    assert not VerdictPublisher(db, rpc_url=RPC).is_onchain_enabled()


@pytest.mark.parametrize(
    "registry,key",
    [
        ("not-an-address", KEY),
        (REGISTRY, "0x" + "zz" * 32),
        (REGISTRY, "0x" + "ff" * 32),
        (REGISTRY, KEY[:20]),
    ],
)
def test_invalid_configuration_disables_recording_without_logging_values(db, caplog, registry, key):
    caplog.set_level(logging.DEBUG)
    publisher = make_publisher(db, key=key, registry=registry)
    assert not publisher.is_onchain_enabled()
    assert key not in caplog.text and key[2:] not in caplog.text
    assert "disabled" in caplog.text


def test_key_is_not_kept_as_a_string_attribute(db):
    publisher = make_publisher(db)
    assert KEY[2:] not in repr(vars(publisher))


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_is_stored_when_recording_is_not_configured(db):
    publisher = make_publisher(db, key="", registry="")
    with rpc_node(FakeChain()) as factory:
        summary = await publisher.publish(4663, TOKEN, INCOMPLETE)
        await drain(publisher)
    factory.assert_not_called()
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert summary == {
        "evidence_id": stored["id"],
        "evidence_hash": stored["evidence_hash"],
        "verdict": "UNKNOWN",
        "onchain_status": "off",
    }
    payload = json.loads(stored["canonical"])
    assert payload["verdict"] == "UNKNOWN"
    assert payload["status"] == "unknown"
    assert stored["evidence_hash"] == "0x" + keccak(stored["canonical"].encode("utf-8")).hex()
    assert (stored["onchain_status"], stored["registry"], stored["tx_hash"]) == ("off", None, None)


@pytest.mark.asyncio
async def test_other_chains_are_stored_but_never_sent(db):
    publisher = make_publisher(db)
    with rpc_node(FakeChain()) as factory:
        summary = await publisher.publish(56, TOKEN, COMPLETE)
        await drain(publisher)
    factory.assert_not_called()
    assert summary["onchain_status"] == "off"
    assert (await db.get_latest_verdict_evidence(56, TOKEN))["verdict"] == "LOW"


@pytest.mark.asyncio
async def test_subject_is_stored_lowercase(db):
    publisher = make_publisher(db, key="", registry="")
    await publisher.publish(4663, to_checksum_address(TOKEN), COMPLETE)
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["subject"] == TOKEN


@pytest.mark.asyncio
async def test_invalid_subject_is_not_published(db, caplog):
    publisher = make_publisher(db)
    with rpc_node(FakeChain()) as factory:
        assert await publisher.publish(4663, "not-an-address", COMPLETE) is None
    factory.assert_not_called()
    cursor = await db._db.execute("SELECT COUNT(*) FROM verdict_evidence")
    assert (await cursor.fetchone())[0] == 0


@pytest.mark.asyncio
async def test_unserialisable_evidence_is_not_published(db, caplog):
    caplog.set_level(logging.DEBUG)
    publisher = make_publisher(db)
    with rpc_node(FakeChain()) as factory:
        assert (
            await publisher.publish(4663, TOKEN, {**COMPLETE, "rug_probability": float("nan")})
            is None
        )
    factory.assert_not_called()
    assert await db.get_latest_verdict_evidence(4663, TOKEN) is None
    assert "ValueError" in caplog.text


@pytest.mark.asyncio
async def test_publish_never_raises_when_storage_fails(db, caplog):
    caplog.set_level(logging.DEBUG)
    publisher = make_publisher(db)
    db.insert_verdict_evidence = AsyncMock(side_effect=RuntimeError(f"disk full {KEY}"))
    with rpc_node(FakeChain()) as factory:
        assert await publisher.publish(4663, TOKEN, COMPLETE) is None
    factory.assert_not_called()
    assert "RuntimeError" in caplog.text
    assert KEY[2:] not in caplog.text


# ---------------------------------------------------------------------------
# On-chain record()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_publish_records_the_verdict_on_robinhood_chain(db):
    chain = FakeChain()
    publisher = make_publisher(db)
    with rpc_node(chain) as factory:
        summary = await publisher.publish(4663, TOKEN, INCOMPLETE, honeypot_data=HONEYPOT)
        assert summary["onchain_status"] == "pending"
        await drain(publisher)

    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert summary == {
        "evidence_id": stored["id"],
        "evidence_hash": stored["evidence_hash"],
        "verdict": "HONEYPOT",
        "onchain_status": "pending",
    }
    [raw] = chain.sent
    assert (stored["onchain_status"], stored["onchain_error"]) == ("submitted", None)
    assert stored["tx_hash"] == "0x" + keccak(raw).hex()
    assert stored["registry"] == to_checksum_address(REGISTRY)

    tx = decode_record(raw)
    assert tx["chain_id"] == 4663
    assert tx["nonce"] == 7
    assert tx["to"] == REGISTRY
    assert tx["value"] == 0
    assert tx["tip"] == 0
    assert tx["max_fee"] == 2 * BASE_FEE
    assert tx["gas"] == 120_000
    assert tx["access_list"] == []
    assert tx["sender"] == RECORDER
    assert tx["subject"] == TOKEN
    assert tx["verdict"] == 4
    assert tx["evidence_hash"] == stored["evidence_hash"]
    assert tx["observed_block"] == 65704949 == json.loads(stored["canonical"])["observed_block"]

    assert chain.methods() == [
        ["eth_getTransactionCount", "eth_getBlockByNumber", "eth_estimateGas"],
        ["eth_sendRawTransaction"],
    ]
    batch = chain.posts[0][1]
    assert batch[0]["params"] == [RECORDER, "pending"]
    assert batch[1]["params"] == ["latest", False]
    assert batch[2]["params"] == [
        {
            "from": RECORDER,
            "to": to_checksum_address(REGISTRY),
            "data": "0x" + tx["data"].hex(),
        }
    ]
    assert {url for url, _ in chain.posts} == {RPC}
    assert factory.call_args.kwargs["timeout"].total == vp.RPC_TIMEOUT_SECONDS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scan,honeypot,code",
    [
        (COMPLETE, None, 1),
        ({**COMPLETE, "risk_level": "MEDIUM"}, None, 2),
        ({**COMPLETE, "risk_level": "HIGH"}, None, 3),
        (INCOMPLETE, None, 0),
        ({**COMPLETE, "partial": True}, None, 0),
    ],
)
async def test_recorded_code_is_the_evidence_verdict(db, scan, honeypot, code):
    chain = FakeChain()
    publisher = make_publisher(db)
    with rpc_node(chain):
        await publisher.publish(4663, TOKEN, scan, honeypot_data=honeypot)
        await drain(publisher)
    tx = decode_record(chain.sent[0])
    assert tx["verdict"] == code
    assert tx["observed_block"] == 0


@pytest.mark.asyncio
async def test_fire_and_forget_returns_at_once_and_publishes(db):
    chain = FakeChain()
    publisher = make_publisher(db)
    with rpc_node(chain):
        assert publisher.publish_fire_and_forget(4663, TOKEN, COMPLETE) is None
        assert await db.get_latest_verdict_evidence(4663, TOKEN) is None
        await drain(publisher)
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "submitted"


@pytest.mark.asyncio
async def test_concurrent_records_use_consecutive_nonces(db):
    chain = FakeChain()
    # Hold every RPC answer until all three record tasks are in flight, so they would overlap without the lock.
    chain.gate = asyncio.Event()
    publisher = make_publisher(db)
    with rpc_node(chain):
        for token in (TOKEN, "0x" + "7b" * 20, "0x" + "7c" * 20):
            await publisher.publish(4663, token, COMPLETE)
        for _ in range(50):
            await asyncio.sleep(0)
        assert len(publisher._tasks) == 3
        # Only the task holding the nonce lock has reached the node.
        assert len(chain.posts) == 1
        chain.gate.set()
        await drain(publisher)
    assert [decode_record(raw)["nonce"] for raw in chain.sent] == [7, 8, 9]
    assert (
        chain.methods()
        == [
            ["eth_getTransactionCount", "eth_getBlockByNumber", "eth_estimateGas"],
            ["eth_sendRawTransaction"],
        ]
        * 3
    )


@pytest.mark.asyncio
async def test_rate_cap_stores_evidence_but_skips_the_send(db, monkeypatch):
    monkeypatch.setattr(vp, "MAX_RECORDS_PER_HOUR", 2)
    chain = FakeChain()
    publisher = make_publisher(db)
    tokens = ["0x" + digit * 40 for digit in "abc"]
    with rpc_node(chain):
        summaries = [await publisher.publish(4663, token, COMPLETE) for token in tokens]
        await drain(publisher)
    assert [s["onchain_status"] for s in summaries] == ["pending", "pending", "failed"]
    assert len(chain.sent) == 2
    capped = await db.get_latest_verdict_evidence(4663, tokens[2])
    assert (capped["onchain_status"], capped["onchain_error"], capped["tx_hash"]) == (
        "failed",
        "RateCapExceeded",
        None,
    )

    # Once the window has passed, sends are allowed again.
    publisher._sent_at = type(publisher._sent_at)(
        t - vp.RATE_WINDOW_SECONDS for t in publisher._sent_at
    )
    with rpc_node(chain):
        assert (await publisher.publish(4663, tokens[2], COMPLETE))["onchain_status"] == "pending"
        await drain(publisher)
    assert len(chain.sent) == 3


# ---------------------------------------------------------------------------
# RPC failures: bounded retries, class-only reasons, never a crash
# ---------------------------------------------------------------------------


def backoffs(sleep):
    # Patching asyncio.sleep also catches FakeResponse's zero-second yields; keep only the backoffs.
    return [call.args[0] for call in sleep.await_args_list if call.args[0]]


async def publish_and_read(db, chain, scan=COMPLETE):
    publisher = make_publisher(db)
    with rpc_node(chain):
        await publisher.publish(4663, TOKEN, scan)
        await drain(publisher)
    return await db.get_latest_verdict_evidence(4663, TOKEN)


@pytest.mark.asyncio
async def test_http_429_is_retried_with_backoff(db):
    chain = FakeChain()
    chain.http_statuses = [429, 429]
    with patch("services.verdict_publisher.asyncio.sleep", new_callable=AsyncMock) as sleep:
        stored = await publish_and_read(db, chain)
    assert stored["onchain_status"] == "submitted"
    assert backoffs(sleep) == [1.0, 2.0]
    assert len(chain.sent) == 1


@pytest.mark.asyncio
async def test_persistent_429_fails_the_record_without_sending(db):
    chain = FakeChain()
    chain.http_statuses = [429] * vp.RPC_ATTEMPTS
    with patch("services.verdict_publisher.asyncio.sleep", new_callable=AsyncMock) as sleep:
        stored = await publish_and_read(db, chain)
    assert (stored["onchain_status"], stored["onchain_error"], stored["tx_hash"]) == (
        "failed",
        "RateLimited",
        None,
    )
    assert len(chain.posts) == vp.RPC_ATTEMPTS
    assert backoffs(sleep) == [1.0, 2.0]
    assert chain.sent == []


@pytest.mark.asyncio
async def test_json_rpc_rate_limit_errors_are_retried(db):
    chain = FakeChain()
    chain.rate_limited_posts = 2
    with patch("services.verdict_publisher.asyncio.sleep", new_callable=AsyncMock):
        stored = await publish_and_read(db, chain)
    assert stored["onchain_status"] == "submitted"
    assert len(chain.posts) == 4


@pytest.mark.asyncio
async def test_http_error_fails_without_retry(db):
    chain = FakeChain()
    chain.http_statuses = [503]
    stored = await publish_and_read(db, chain)
    assert (stored["onchain_status"], stored["onchain_error"]) == ("failed", "HTTP 503")
    assert len(chain.posts) == 1


@pytest.mark.asyncio
async def test_a_reverting_record_is_never_sent(db):
    chain = FakeChain()
    chain.errors["eth_estimateGas"] = {
        "code": 3,
        "message": "execution reverted",
        "data": "0x0e1c2ed5",
    }
    stored = await publish_and_read(db, chain)
    assert (stored["onchain_status"], stored["onchain_error"]) == (
        "failed",
        "eth_estimateGas JSON-RPC error 3",
    )
    assert chain.sent == []


@pytest.mark.asyncio
async def test_a_rejected_send_is_recorded_as_failed(db):
    chain = FakeChain()
    chain.errors["eth_sendRawTransaction"] = {
        "code": -32000,
        "message": f"nonce too low {RPC_SECRET}",
    }
    stored = await publish_and_read(db, chain)
    assert (stored["onchain_status"], stored["tx_hash"]) == ("failed", None)
    assert stored["onchain_error"] == "eth_sendRawTransaction JSON-RPC error -32000"


@pytest.mark.asyncio
async def test_non_integer_error_codes_are_not_echoed(db):
    chain = FakeChain()
    chain.errors["eth_estimateGas"] = {"code": f"text {RPC_SECRET}", "message": "x"}
    stored = await publish_and_read(db, chain)
    assert stored["onchain_error"] == "eth_estimateGas JSON-RPC error None"


@pytest.mark.asyncio
@pytest.mark.parametrize("block", [{"number": "0x1"}, {"baseFeePerGas": "wei"}, "0x1"])
async def test_malformed_block_fails_the_record(db, block):
    chain = FakeChain()
    chain.block = block
    stored = await publish_and_read(db, chain)
    assert (stored["onchain_status"], stored["onchain_error"]) == ("failed", "MalformedRPCResponse")
    assert chain.sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", [None, "text", [], {"jsonrpc": "2.0", "id": 9, "result": "0x1"}]
)
async def test_malformed_envelope_fails_the_record(db, payload):
    chain = FakeChain()
    chain.post = lambda url, json: (chain.posts.append((url, json)), FakeResponse(200, payload))[1]
    stored = await publish_and_read(db, chain)
    assert (stored["onchain_status"], stored["onchain_error"]) == ("failed", "MalformedRPCResponse")


@pytest.mark.asyncio
async def test_base_fee_above_the_cap_is_refused(db):
    chain = FakeChain(base_fee=vp.MAX_FEE_PER_GAS_WEI + 1)
    stored = await publish_and_read(db, chain)
    assert (stored["onchain_status"], stored["onchain_error"]) == ("failed", "FeeCapExceeded")
    assert chain.sent == []


@pytest.mark.asyncio
async def test_max_fee_is_capped(db):
    chain = FakeChain(base_fee=vp.MAX_FEE_PER_GAS_WEI * 3 // 4)
    await publish_and_read(db, chain)
    assert decode_record(chain.sent[0])["max_fee"] == vp.MAX_FEE_PER_GAS_WEI


# The gas limit is the estimate plus 20%: 416,667 gives exactly 500,000 and 416,668 gives 500,001.
LARGEST_ACCEPTED_ESTIMATE = 416_667


def test_gas_boundary_constant_matches_the_cap():
    assert LARGEST_ACCEPTED_ESTIMATE * 6 // 5 == vp.MAX_GAS_LIMIT
    assert (LARGEST_ACCEPTED_ESTIMATE + 1) * 6 // 5 == vp.MAX_GAS_LIMIT + 1


@pytest.mark.asyncio
async def test_gas_above_the_cap_is_refused(db):
    chain = FakeChain(estimate=LARGEST_ACCEPTED_ESTIMATE + 1)
    stored = await publish_and_read(db, chain)
    assert (stored["onchain_status"], stored["onchain_error"]) == ("failed", "GasCapExceeded")
    assert chain.sent == []


@pytest.mark.asyncio
async def test_gas_limit_at_the_cap_is_sent(db):
    chain = FakeChain(estimate=LARGEST_ACCEPTED_ESTIMATE)
    await publish_and_read(db, chain)
    assert decode_record(chain.sent[0])["gas"] == vp.MAX_GAS_LIMIT


@pytest.mark.asyncio
async def test_a_hung_rpc_times_out(db, monkeypatch):
    monkeypatch.setattr(vp, "RECORD_TIMEOUT_SECONDS", 0.05)
    chain = FakeChain()
    chain.gate = asyncio.Event()
    stored = await publish_and_read(db, chain)
    assert (stored["onchain_status"], stored["onchain_error"], stored["tx_hash"]) == (
        "failed",
        "TimeoutError",
        None,
    )
    assert chain.sent == []


@pytest.mark.asyncio
async def test_key_and_rpc_url_never_reach_logs_or_storage(db, caplog):
    caplog.set_level(logging.DEBUG)
    chain = FakeChain()
    chain.raise_on_post = aiohttp.ClientConnectionError(f"cannot connect to {RPC} with {KEY}")
    stored = await publish_and_read(db, chain)
    assert (stored["onchain_status"], stored["onchain_error"]) == (
        "failed",
        "ClientConnectionError",
    )
    for secret in (KEY, KEY[2:], RPC_SECRET):
        assert secret not in caplog.text
        assert secret not in json.dumps(stored)
    assert "ClientConnectionError" in caplog.text
