"""VerdictPublisher: every process stores evidence; only the API process's drain records verdicts on-chain.

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
PRE_SIGN = ["eth_getTransactionCount", "eth_getBlockByNumber", "eth_estimateGas", "eth_getBalance"]
ONE_RECORD = [PRE_SIGN, ["eth_sendRawTransaction"], ["eth_getTransactionReceipt"]]


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
    """Answers the drain's JSON-RPC requests the way a Robinhood Chain node would."""

    def __init__(self, nonce=7, base_fee=BASE_FEE, estimate=100_000, balance=10**18):
        self.nonce = nonce
        self.base_fee = base_fee
        self.estimate = estimate
        self.balance = balance
        self.posts = []
        self.sent = []
        self.receipts = {}
        self.receipt_status = "0x1"
        self.http_statuses = []
        self.rate_limited_posts = 0
        self.errors = {}
        self.block = None
        self.raise_on = {}
        self.gate = None

    def post(self, url, json):
        self.posts.append((url, json))
        rows = json if isinstance(json, list) else [json]
        for row in rows:
            if row["method"] in self.raise_on:
                raise self.raise_on[row["method"]]
        if self.http_statuses:
            return FakeResponse(self.http_statuses.pop(0), None)
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
        method, params = row["method"], row["params"]
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
        elif method == "eth_getBalance":
            result = hex(self.balance)
        elif method == "eth_sendRawTransaction":
            raw = bytes.fromhex(params[0][2:])
            self.sent.append(raw)
            self.nonce += 1
            tx_hash = "0x" + keccak(raw).hex()
            if self.receipt_status is not None:
                self.receipts[tx_hash] = {"transactionHash": tx_hash, "status": self.receipt_status}
            result = tx_hash
        elif method == "eth_getTransactionReceipt":
            result = self.receipts.get(params[0])
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


@pytest.fixture(autouse=True)
def no_receipt_delay(monkeypatch):
    monkeypatch.setattr(vp, "RECEIPT_DELAY_SECONDS", 0)


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


def make_publisher(db, registry=REGISTRY):
    return VerdictPublisher(db, rpc_url=RPC, registry_address=registry)


def sender(db, key=KEY):
    """The API process's publisher: it holds the key and drains, but the loop is driven by the test."""
    publisher = make_publisher(db)
    publisher._account = Account.from_key(key)
    publisher.recorder = publisher._account.address
    return publisher


async def drain_all(publisher):
    outcomes = []
    while (outcome := await publisher.drain_once()) not in ("idle", "capped"):
        outcomes.append(outcome)
    return outcomes + [outcome]


def backoffs(sleep):
    # Patching asyncio.sleep also catches FakeResponse's zero-second yields; keep only the real waits.
    return [call.args[0] for call in sleep.await_args_list if call.args[0]]


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
# Configuration: the registry is public, the key is read only by start()
# ---------------------------------------------------------------------------


def test_record_selector_matches_the_contract():
    # `cast sig "record(address,uint8,bytes32,uint64)"` prints 0xf160da27.
    assert vp.RECORD_SELECTOR.hex() == "f160da27"


def test_registry_comes_from_the_environment(monkeypatch, db):
    monkeypatch.setenv("ROBINHOOD_VERDICT_REGISTRY", REGISTRY)
    publisher = VerdictPublisher(db, rpc_url=RPC)
    assert publisher.is_onchain_enabled()
    assert publisher.registry == to_checksum_address(REGISTRY)
    assert publisher.recorder is None


def test_without_a_registry_verdicts_are_only_stored(monkeypatch, db):
    monkeypatch.setenv("ROBINHOOD_VERDICT_REGISTRY", "")
    assert not VerdictPublisher(db, rpc_url=RPC).is_onchain_enabled()


def test_an_invalid_registry_disables_queueing(db, caplog):
    caplog.set_level(logging.DEBUG)
    assert not make_publisher(db, registry="not-an-address").is_onchain_enabled()
    assert "disabled" in caplog.text


@pytest.mark.asyncio
async def test_publishing_never_reads_the_recorder_key(monkeypatch, db):
    """The bot process constructs and publishes but never starts, so it never touches the key."""
    monkeypatch.setenv("ROBINHOOD_VERDICT_REGISTRY", REGISTRY)
    monkeypatch.setenv("ROBINHOOD_RECORDER_PRIVATE_KEY", KEY)
    read = []
    real_getenv = vp.os.getenv
    monkeypatch.setattr(
        vp.os, "getenv", lambda name, *default: read.append(name) or real_getenv(name, *default)
    )
    with patch("services.verdict_publisher.Account") as account, rpc_node(FakeChain()) as factory:
        publisher = VerdictPublisher(db, rpc_url=RPC)
        summary = await publisher.publish(4663, TOKEN, COMPLETE)
        publisher.publish_fire_and_forget(4663, "0x" + "7b" * 20, COMPLETE)
        while publisher._tasks:
            await asyncio.gather(*list(publisher._tasks))
        assert await publisher.drain_once() == "idle"
    assert summary["onchain_status"] == "pending"
    assert "ROBINHOOD_RECORDER_PRIVATE_KEY" not in read
    account.from_key.assert_not_called()
    factory.assert_not_called()
    assert publisher._account is None and publisher._drain_task is None
    assert KEY[2:] not in repr(vars(publisher))


@pytest.mark.asyncio
async def test_start_reads_the_key_from_the_environment(monkeypatch, db):
    monkeypatch.setenv("ROBINHOOD_RECORDER_PRIVATE_KEY", KEY)
    publisher = make_publisher(db)
    with patch.object(VerdictPublisher, "_drain_loop", new=AsyncMock()):
        publisher.start()
        assert publisher.recorder == RECORDER
        assert publisher._drain_task is not None
        publisher.stop()
    assert publisher._drain_task is None
    assert KEY[2:] not in repr(vars(publisher))


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["", "0x" + "zz" * 32, "0x" + "ff" * 32, KEY[:20]])
async def test_start_without_a_valid_key_does_not_send(monkeypatch, db, caplog, key):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("ROBINHOOD_RECORDER_PRIVATE_KEY", key)
    publisher = make_publisher(db)
    publisher.start()
    assert publisher._drain_task is None and publisher._account is None
    assert "not sending" in caplog.text
    if key:
        assert key not in caplog.text and key[2:] not in caplog.text


@pytest.mark.asyncio
async def test_start_without_a_registry_does_nothing(db):
    publisher = make_publisher(db, registry="")
    publisher.start(recorder_key=KEY)
    assert publisher._drain_task is None and publisher._account is None


# ---------------------------------------------------------------------------
# Storing (every process)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_is_stored_when_recording_is_not_configured(db):
    publisher = make_publisher(db, registry="")
    summary = await publisher.publish(4663, TOKEN, INCOMPLETE)
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
async def test_robinhood_verdicts_are_queued_and_publish_never_contacts_the_rpc(db):
    publisher = sender(db)
    with rpc_node(FakeChain()) as factory:
        summary = await publisher.publish(4663, TOKEN, INCOMPLETE, honeypot_data=HONEYPOT)
    factory.assert_not_called()
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert summary["onchain_status"] == stored["onchain_status"] == "pending"
    assert summary["verdict"] == "HONEYPOT"
    assert stored["registry"] == to_checksum_address(REGISTRY)


@pytest.mark.asyncio
async def test_other_chains_are_stored_but_never_queued(db):
    publisher = sender(db)
    with rpc_node(FakeChain()) as factory:
        summary = await publisher.publish(56, TOKEN, COMPLETE)
        assert await publisher.drain_once() == "idle"
    factory.assert_not_called()
    assert summary["onchain_status"] == "off"
    assert (await db.get_latest_verdict_evidence(56, TOKEN))["verdict"] == "LOW"


@pytest.mark.asyncio
async def test_subject_is_stored_lowercase(db):
    await make_publisher(db, registry="").publish(4663, to_checksum_address(TOKEN), COMPLETE)
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["subject"] == TOKEN


@pytest.mark.asyncio
async def test_invalid_subject_is_not_published(db):
    assert await make_publisher(db).publish(4663, "not-an-address", COMPLETE) is None
    cursor = await db._db.execute("SELECT COUNT(*) FROM verdict_evidence")
    assert (await cursor.fetchone())[0] == 0


@pytest.mark.asyncio
async def test_unserialisable_evidence_is_not_published(db, caplog):
    caplog.set_level(logging.DEBUG)
    assert (
        await make_publisher(db).publish(4663, TOKEN, {**COMPLETE, "rug_probability": float("nan")})
        is None
    )
    assert await db.get_latest_verdict_evidence(4663, TOKEN) is None
    assert "ValueError" in caplog.text


@pytest.mark.asyncio
async def test_publish_never_raises_when_storage_fails(db, caplog):
    caplog.set_level(logging.DEBUG)
    publisher = make_publisher(db)
    db.insert_verdict_evidence = AsyncMock(side_effect=RuntimeError(f"disk full {KEY}"))
    assert await publisher.publish(4663, TOKEN, COMPLETE) is None
    assert "RuntimeError" in caplog.text
    assert KEY[2:] not in caplog.text


# ---------------------------------------------------------------------------
# The drain: record(), receipts and ordering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drain_records_a_queued_verdict_and_confirms_it(db):
    chain = FakeChain()
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, INCOMPLETE, honeypot_data=HONEYPOT)
    with rpc_node(chain) as factory:
        assert await drain_all(publisher) == ["done", "idle"]

    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    [raw] = chain.sent
    assert (stored["onchain_status"], stored["onchain_error"]) == ("confirmed", None)
    assert stored["tx_hash"] == "0x" + keccak(raw).hex()

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

    assert chain.methods() == ONE_RECORD
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
    assert batch[3]["params"] == [RECORDER, "latest"]
    assert chain.posts[2][1]["params"] == [stored["tx_hash"]]
    assert {url for url, _ in chain.posts} == {RPC}
    assert factory.call_args.kwargs["timeout"].total == vp.RPC_TIMEOUT_SECONDS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scan,code",
    [
        (COMPLETE, 1),
        ({**COMPLETE, "risk_level": "MEDIUM"}, 2),
        ({**COMPLETE, "risk_level": "HIGH"}, 3),
        (INCOMPLETE, 0),
        ({**COMPLETE, "partial": True}, 0),
    ],
)
async def test_recorded_code_is_the_evidence_verdict(db, scan, code):
    chain = FakeChain()
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, scan)
    with rpc_node(chain):
        await drain_all(publisher)
    tx = decode_record(chain.sent[0])
    assert tx["verdict"] == code
    assert tx["observed_block"] == 0


@pytest.mark.asyncio
async def test_a_reverted_receipt_is_stored_as_reverted(db):
    chain = FakeChain()
    chain.receipt_status = "0x0"
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        await drain_all(publisher)
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"]) == (
        "reverted",
        "0x" + keccak(chain.sent[0]).hex(),
    )


@pytest.mark.asyncio
async def test_no_receipt_within_the_timeout_keeps_submitted(db):
    chain = FakeChain()
    chain.receipt_status = None
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        await drain_all(publisher)
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"]) == (
        "submitted",
        "0x" + keccak(chain.sent[0]).hex(),
    )
    assert chain.methods() == ONE_RECORD


@pytest.mark.asyncio
async def test_a_hung_receipt_lookup_times_out_and_keeps_submitted(db, monkeypatch):
    monkeypatch.setattr(vp, "RECEIPT_TIMEOUT_SECONDS", 0.05)
    chain = FakeChain()
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    original = chain.post

    def hang_receipts(url, json):
        response = original(url, json)
        if not isinstance(json, list) and json["method"] == "eth_getTransactionReceipt":
            response._gate = asyncio.Event()
        return response

    chain.post = hang_receipts
    with rpc_node(chain):
        await drain_all(publisher)
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert stored["onchain_status"] == "submitted"


@pytest.mark.asyncio
async def test_drain_is_oldest_first_with_consecutive_nonces(db):
    chain = FakeChain()
    publisher = sender(db)
    tokens = ["0x" + digit * 40 for digit in "abc"]
    for token in tokens:
        await publisher.publish(4663, token, COMPLETE)
    with rpc_node(chain):
        assert await drain_all(publisher) == ["done", "done", "done", "idle"]
    assert [decode_record(raw)["nonce"] for raw in chain.sent] == [7, 8, 9]
    assert [decode_record(raw)["subject"] for raw in chain.sent] == tokens
    assert chain.methods() == ONE_RECORD * 3



@pytest.mark.asyncio
async def test_concurrent_drains_in_one_process_serialise_nonces(db):
    chain = FakeChain()
    # Hold every RPC answer until all three drains are in flight, so they would overlap without the lock.
    chain.gate = asyncio.Event()
    publisher = sender(db)
    for token in ("0x" + digit * 40 for digit in "abc"):
        await publisher.publish(4663, token, COMPLETE)
    with rpc_node(chain):
        drains = asyncio.gather(*(publisher.drain_once() for _ in range(3)))
        # Wait until all three drains have claimed a row; only the one holding the nonce lock reaches the node.
        for _ in range(500):
            if len(await db.get_claimed_verdicts(4663)) == 3 and chain.posts:
                break
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        assert len(await db.get_claimed_verdicts(4663)) == 3
        assert len(chain.posts) == 1
        chain.gate.set()
        assert await drains == ["done", "done", "done"]
    assert [decode_record(raw)["nonce"] for raw in chain.sent] == [7, 8, 9]

@pytest.mark.asyncio
async def test_two_processes_share_one_sender_with_consecutive_nonces(tmp_path):
    """The API and bot processes publish into one SQLite file; only the API process sends."""
    path = str(tmp_path / "shieldbot.db")
    api_db, bot_db = Database(path), Database(path)
    await api_db.initialize()
    await bot_db.initialize()
    try:
        chain = FakeChain()
        api, bot = sender(api_db), make_publisher(bot_db)
        bot._rpc = AsyncMock(
            side_effect=AssertionError("the bot process must never contact the RPC")
        )
        tokens = ["0x" + f"{n:040x}" for n in range(1, 9)]
        await asyncio.gather(
            *(
                (api if index % 2 else bot).publish(4663, token, COMPLETE)
                for index, token in enumerate(tokens)
            )
        )
        assert await bot.drain_once() == "idle"
        with rpc_node(chain):
            assert (await drain_all(api)).count("done") == len(tokens)
        bot._rpc.assert_not_called()
        assert [decode_record(raw)["nonce"] for raw in chain.sent] == list(
            range(7, 7 + len(tokens))
        )
        assert sorted(decode_record(raw)["subject"] for raw in chain.sent) == tokens
        cursor = await bot_db._db.execute("SELECT DISTINCT onchain_status FROM verdict_evidence")
        assert await cursor.fetchall() == [("confirmed",)]
    finally:
        await api_db.close()
        await bot_db.close()


# ---------------------------------------------------------------------------
# Rate cap and backoff
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_cap_makes_rows_wait_instead_of_failing(db, monkeypatch):
    monkeypatch.setattr(vp, "MAX_RECORDS_PER_HOUR", 2)
    chain = FakeChain()
    publisher = sender(db)
    tokens = ["0x" + digit * 40 for digit in "abc"]
    for token in tokens:
        await publisher.publish(4663, token, COMPLETE)
    with rpc_node(chain):
        assert await drain_all(publisher) == ["done", "done", "capped"]
    assert len(chain.sent) == 2
    assert (await db.get_latest_verdict_evidence(4663, tokens[2]))["onchain_status"] == "pending"
    assert 0 < publisher._rate_wait() <= vp.RATE_WINDOW_SECONDS

    # Once the window has passed, the waiting row is sent.
    publisher._sent_at = type(publisher._sent_at)(
        t - vp.RATE_WINDOW_SECONDS for t in publisher._sent_at
    )
    with rpc_node(chain):
        assert await drain_all(publisher) == ["done", "idle"]
    assert (await db.get_latest_verdict_evidence(4663, tokens[2]))["onchain_status"] == "confirmed"


@pytest.mark.asyncio
async def test_http_429_is_retried_with_backoff(db):
    chain = FakeChain()
    chain.http_statuses = [429, 429]
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with (
        rpc_node(chain),
        patch("services.verdict_publisher.asyncio.sleep", new_callable=AsyncMock) as sleep,
    ):
        await drain_all(publisher)
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "confirmed"
    assert backoffs(sleep) == [1.0, 2.0]
    assert len(chain.sent) == 1


@pytest.mark.asyncio
async def test_json_rpc_rate_limit_errors_are_retried(db):
    chain = FakeChain()
    chain.rate_limited_posts = 2
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain), patch("services.verdict_publisher.asyncio.sleep", new_callable=AsyncMock):
        await drain_all(publisher)
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "confirmed"
    assert chain.methods()[:3] == [PRE_SIGN] * 3


@pytest.mark.asyncio
async def test_persistent_429_returns_the_row_to_the_queue(db):
    chain = FakeChain()
    chain.http_statuses = [429] * vp.RPC_ATTEMPTS
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with (
        rpc_node(chain),
        patch("services.verdict_publisher.asyncio.sleep", new_callable=AsyncMock) as sleep,
    ):
        assert await publisher.drain_once() == "retry"
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"]) == ("pending", None)
    assert len(chain.posts) == vp.RPC_ATTEMPTS
    assert backoffs(sleep) == [1.0, 2.0]
    assert chain.sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup,reason",
    [
        (lambda chain: chain.http_statuses.append(503), "HTTP 503"),
        (
            lambda chain: chain.errors.update(
                eth_estimateGas={"code": 3, "message": "execution reverted"}
            ),
            "eth_estimateGas JSON-RPC error 3",
        ),
        (lambda chain: setattr(chain, "block", {"number": "0x1"}), "MalformedRPCResponse"),
        (lambda chain: setattr(chain, "base_fee", vp.MAX_FEE_PER_GAS_WEI + 1), "FeeCapExceeded"),
        (lambda chain: setattr(chain, "estimate", 416_668), "GasCapExceeded"),
        (lambda chain: setattr(chain, "balance", 120_000 * 2 * BASE_FEE - 1), "InsufficientFunds"),
        (
            lambda chain: chain.raise_on.update(
                eth_getTransactionCount=aiohttp.ClientConnectionError()
            ),
            "ClientConnectionError",
        ),
    ],
)
async def test_failures_before_signing_return_the_row_to_the_queue(db, caplog, setup, reason):
    caplog.set_level(logging.DEBUG)
    chain = FakeChain()
    setup(chain)
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        assert await publisher.drain_once() == "retry"
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"], stored["onchain_error"]) == (
        "pending",
        None,
        None,
    )
    assert chain.sent == []
    assert reason in caplog.text


def test_gas_boundary_constants():
    # The gas limit is the estimate plus 20%: 416,667 gives exactly 500,000 and 416,668 gives 500,001.
    assert 416_667 * 6 // 5 == vp.MAX_GAS_LIMIT
    assert 416_668 * 6 // 5 == vp.MAX_GAS_LIMIT + 1


@pytest.mark.asyncio
async def test_gas_limit_at_the_cap_and_max_fee_cap(db):
    chain = FakeChain(estimate=416_667, base_fee=vp.MAX_FEE_PER_GAS_WEI * 3 // 4)
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        await drain_all(publisher)
    tx = decode_record(chain.sent[0])
    assert (tx["gas"], tx["max_fee"]) == (vp.MAX_GAS_LIMIT, vp.MAX_FEE_PER_GAS_WEI)


@pytest.mark.asyncio
async def test_a_hung_rpc_before_signing_times_out_and_waits(db, monkeypatch):
    monkeypatch.setattr(vp, "PHASE_TIMEOUT_SECONDS", 0.05)
    chain = FakeChain()
    chain.gate = asyncio.Event()
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        assert await publisher.drain_once() == "retry"
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "pending"
    assert chain.sent == []


@pytest.mark.asyncio
async def test_the_drain_loop_backs_off_exponentially_and_resets_after_a_record(db, monkeypatch):
    publisher = sender(db)
    publisher._wake = asyncio.Event()
    outcomes = iter(["retry", "retry", "retry", "done", "retry"] + ["retry"] * 10)
    monkeypatch.setattr(publisher, "drain_once", AsyncMock(side_effect=lambda: next(outcomes)))
    monkeypatch.setattr(publisher, "_recover_claims", AsyncMock())
    waits = []

    async def sleep(seconds):
        waits.append(seconds)
        if len(waits) == 12:
            raise asyncio.CancelledError

    with patch("services.verdict_publisher.asyncio.sleep", new=sleep):
        with pytest.raises(asyncio.CancelledError):
            await publisher._drain_loop()
    assert waits == [5.0, 10.0, 20.0, 5.0, 10.0, 20.0, 40.0, 80.0, 160.0, 300.0, 300.0, 300.0]


@pytest.mark.asyncio
async def test_the_running_drain_wakes_on_publish_and_stops(db, monkeypatch):
    monkeypatch.setattr(vp, "DRAIN_POLL_SECONDS", 3600)
    chain = FakeChain()
    publisher = make_publisher(db)
    with rpc_node(chain):
        publisher.start(recorder_key=KEY)
        await publisher.publish(4663, TOKEN, COMPLETE)
        for _ in range(200):
            if (
                len(chain.sent)
                and (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"]
                == "confirmed"
            ):
                break
            await asyncio.sleep(0.01)
        task = publisher._drain_task
        publisher.stop()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "confirmed"
    assert len(chain.sent) == 1


# ---------------------------------------------------------------------------
# After signing: never resent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_explicitly_rejected_send_fails_without_a_tx_hash(db):
    chain = FakeChain()
    chain.errors["eth_sendRawTransaction"] = {
        "code": -32000,
        "message": f"nonce too low {RPC_SECRET}",
    }
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        assert await drain_all(publisher) == ["done", "idle"]
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"]) == ("failed", None)
    assert stored["onchain_error"] == "eth_sendRawTransaction JSON-RPC error -32000"


@pytest.mark.asyncio
async def test_a_rejected_send_that_is_already_mined_is_confirmed(db):
    chain = FakeChain()
    chain.errors["eth_sendRawTransaction"] = {"code": -32000, "message": "already known"}
    publisher = sender(db)
    summary = await publisher.publish(4663, TOKEN, COMPLETE)
    original = chain.answer

    def mined_earlier(row):
        if row["method"] == "eth_getTransactionReceipt":
            return {"jsonrpc": "2.0", "id": row["id"], "result": {"status": "0x1"}}
        return original(row)

    chain.answer = mined_earlier
    with rpc_node(chain):
        await drain_all(publisher)
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["onchain_error"]) == ("confirmed", None)
    assert stored["tx_hash"] is not None and stored["id"] == summary["evidence_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [aiohttp.ClientConnectionError(), asyncio.TimeoutError()])
async def test_an_ambiguous_send_is_unconfirmed_and_never_resent(db, failure):
    chain = FakeChain()
    chain.raise_on["eth_sendRawTransaction"] = failure
    chain.receipt_status = None
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        assert await drain_all(publisher) == ["done", "idle"]
        assert await publisher.drain_once() == "idle"
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert stored["onchain_status"] == "unconfirmed"
    assert stored["onchain_error"] == type(failure).__name__
    assert stored["tx_hash"] is not None
    assert [methods[0] for methods in chain.methods()].count("eth_sendRawTransaction") == 1


@pytest.mark.asyncio
async def test_a_crash_between_claim_and_signing_is_queued_again_and_sent_once(db):
    publisher = sender(db)
    evidence_id = (await publisher.publish(4663, TOKEN, COMPLETE))["evidence_id"]
    # The previous process claimed the row, then died before signing.
    assert (await db.claim_next_pending_verdict(4663))["id"] == evidence_id

    chain = FakeChain()
    restarted = sender(db)
    with rpc_node(chain):
        await restarted._recover_claims()
        assert await drain_all(restarted) == ["done", "idle"]
    assert len(chain.sent) == 1
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "confirmed"


@pytest.mark.asyncio
@pytest.mark.parametrize("mined", [True, False])
async def test_a_crash_after_signing_is_reconciled_and_never_resent(db, mined):
    chain = FakeChain()
    # The process dies while broadcasting: the claim holds a tx hash, but the outcome was never stored.
    chain.raise_on["eth_sendRawTransaction"] = asyncio.CancelledError()
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        with pytest.raises(asyncio.CancelledError):
            await publisher.drain_once()
    [claimed] = await db.get_claimed_verdicts(4663)
    assert claimed["tx_hash"] is not None
    if mined:
        chain.receipts[claimed["tx_hash"]] = {"status": "0x1"}

    restarted = sender(db)
    chain.raise_on.clear()
    with rpc_node(chain):
        await restarted._recover_claims()
        assert await restarted.drain_once() == "idle"
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert stored["tx_hash"] == claimed["tx_hash"]
    assert (stored["onchain_status"], stored["onchain_error"]) == (
        ("confirmed", None) if mined else ("unconfirmed", "ClaimInterrupted")
    )
    assert chain.sent == []
    assert await db.get_claimed_verdicts(4663) == []


@pytest.mark.asyncio
async def test_start_recovers_claims_before_draining(db, monkeypatch):
    monkeypatch.setattr(vp, "DRAIN_POLL_SECONDS", 3600)
    publisher = sender(db)
    evidence_id = (await publisher.publish(4663, TOKEN, COMPLETE))["evidence_id"]
    await db.claim_next_pending_verdict(4663)
    chain = FakeChain()
    restarted = make_publisher(db)
    with rpc_node(chain):
        restarted.start(recorder_key=KEY)
        for _ in range(200):
            if chain.sent:
                break
            await asyncio.sleep(0.01)
        for _ in range(200):
            if (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "confirmed":
                break
            await asyncio.sleep(0.01)
        restarted.stop()
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["id"], stored["onchain_status"]) == (evidence_id, "confirmed")
    assert len(chain.sent) == 1


@pytest.mark.asyncio
async def test_key_and_rpc_url_never_reach_logs_or_storage(db, caplog):
    caplog.set_level(logging.DEBUG)
    chain = FakeChain()
    chain.raise_on["eth_sendRawTransaction"] = aiohttp.ClientConnectionError(
        f"cannot connect to {RPC} with {KEY}"
    )
    chain.receipt_status = None
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        await drain_all(publisher)
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["onchain_error"]) == (
        "unconfirmed",
        "ClientConnectionError",
    )
    for secret in (KEY, KEY[2:], RPC_SECRET):
        assert secret not in caplog.text
        assert secret not in json.dumps(stored)
    assert "ClientConnectionError" in caplog.text
