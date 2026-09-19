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
        self.latest = nonce
        self.mine = True
        # The true chain: (nonce, tx_hash, evidence_hash) of every mined transaction.
        self.mined = []
        # A lagging view (a read replica behind the sequencer) does not see what was mined.
        self.lagging = False
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
            result = hex(self.latest if params[1] == "latest" else self.nonce)
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
            tx_hash = "0x" + keccak(raw).hex()
            if self.mine:
                tx = decode_record(raw)
                assert all(n != tx["nonce"] for n, _, _ in self.mined), "a used nonce is never mined twice"
                self.mined.append((tx["nonce"], tx_hash, tx["evidence_hash"]))
            if not self.lagging:
                self.nonce += 1
            if self.mine and not self.lagging:
                self.latest = self.nonce
            if self.mine and not self.lagging and self.receipt_status is not None:
                self.receipts[tx_hash] = {"transactionHash": tx_hash, "status": self.receipt_status}
            result = tx_hash
        elif method == "eth_getTransactionReceipt":
            result = self.receipts.get(params[0])
        else:
            raise AssertionError(f"unexpected method {method}")
        return {"jsonrpc": "2.0", "id": row["id"], "result": result}

    def catch_up(self):
        """The view catches up with the true chain."""
        self.lagging = False
        if self.mined:
            self.latest = max(self.latest, max(n for n, _, _ in self.mined) + 1)
            self.nonce = max(self.nonce, self.latest)
        for _, tx_hash, _ in self.mined:
            self.receipts.setdefault(tx_hash, {"transactionHash": tx_hash, "status": "0x1"})

    def doubles(self):
        """Evidence hashes recorded by more than one mined transaction."""
        evidence = [evidence_hash for _, _, evidence_hash in self.mined]
        return sorted({e for e in evidence if evidence.count(e) > 1})

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
        (lambda chain: setattr(chain, "estimate", 833_335), "GasCapExceeded"),
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
    # The gas limit is the estimate plus 20%: 833,334 gives exactly 1,000,000 and 833,335 gives 1,000,002.
    assert vp.MAX_GAS_LIMIT == 1_000_000
    assert 833_334 * 6 // 5 == vp.MAX_GAS_LIMIT
    assert 833_335 * 6 // 5 == vp.MAX_GAS_LIMIT + 2


@pytest.mark.asyncio
async def test_gas_limit_at_the_cap_and_max_fee_cap(db):
    chain = FakeChain(estimate=833_334, base_fee=vp.MAX_FEE_PER_GAS_WEI * 3 // 4)
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
    monkeypatch.setattr(publisher, "_recover_claims", AsyncMock(return_value=0))
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
async def test_an_explicitly_rejected_send_fails_and_keeps_its_tx_hash(db):
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
    assert (stored["onchain_status"], stored["tx_hash"]) == ("failed", posted_hash(chain))
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
async def test_a_crash_between_claim_and_signing_is_queued_again_and_sent_once(db, reconcile_now):
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


async def sends_settled(publisher):
    """Wait for shielded sends that outlived a cancelled drain."""
    while publisher._tasks:
        await asyncio.gather(*list(publisher._tasks))


async def until(predicate, tries=500):
    for _ in range(tries):
        if await predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition never became true")


def gate_method(chain, method):
    """Hold the node's answer to `method` until the returned event is set."""
    gate = asyncio.Event()
    original = chain.post

    def post(url, json):
        response = original(url, json)
        rows = json if isinstance(json, list) else [json]
        if any(row["method"] == method for row in rows):
            response._gate = gate
        return response

    chain.post = post
    return gate


@pytest.mark.asyncio
@pytest.mark.parametrize("window", ["pre-sign reads", "broadcast", "receipt"])
async def test_cancelling_the_drain_never_interrupts_a_send(db, window):
    chain = FakeChain()
    method = {
        "pre-sign reads": "eth_getTransactionCount",
        "broadcast": "eth_sendRawTransaction",
        "receipt": "eth_getTransactionReceipt",
    }[window]
    gate = gate_method(chain, method)
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        drain = asyncio.create_task(publisher.drain_once())
        await until(lambda: asyncio.sleep(0, any(
            row["method"] == method
            for _, body in chain.posts for row in (body if isinstance(body, list) else [body])
        )))
        drain.cancel()
        with pytest.raises(asyncio.CancelledError):
            await drain
        gate.set()
        await sends_settled(publisher)
    assert len(chain.sent) == 1
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert outbox_row(stored) == ("confirmed", "0x" + keccak(chain.sent[0]).hex(), None)


@pytest.mark.asyncio
async def test_cancelling_between_storing_the_hash_and_the_broadcast_still_broadcasts(db, monkeypatch):
    chain = FakeChain()
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    stored_hash, release = asyncio.Event(), asyncio.Event()
    store = db.set_verdict_tx_hash

    async def store_then_pause(*args):
        claimed = await store(*args)
        stored_hash.set()
        await release.wait()
        return claimed

    monkeypatch.setattr(db, "set_verdict_tx_hash", store_then_pause)
    with rpc_node(chain):
        drain = asyncio.create_task(publisher.drain_once())
        await stored_hash.wait()
        assert chain.sent == []
        drain.cancel()
        with pytest.raises(asyncio.CancelledError):
            await drain
        release.set()
        await sends_settled(publisher)
    assert len(chain.sent) == 1
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "confirmed"


@pytest.mark.asyncio
async def test_stop_lets_a_send_under_way_finish(db, monkeypatch):
    monkeypatch.setattr(vp, "DRAIN_POLL_SECONDS", 3600)
    chain = FakeChain()
    gate = gate_method(chain, "eth_sendRawTransaction")
    publisher = make_publisher(db)
    with rpc_node(chain):
        publisher.start(recorder_key=KEY)
        await publisher.publish(4663, TOKEN, COMPLETE)
        await until(lambda: asyncio.sleep(0, bool(chain.sent)))
        publisher.stop()
        gate.set()
        await sends_settled(publisher)
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "confirmed"
    assert len(chain.sent) == 1


async def crash_during(db, chain, method):
    """Simulate the process dying during `method`: the shielded send itself is torn down."""
    chain.raise_on[method] = asyncio.CancelledError()
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        with pytest.raises(asyncio.CancelledError):
            await publisher.drain_once()
    chain.raise_on.clear()
    [claimed] = await db.get_claimed_verdicts(4663)
    assert claimed["tx_hash"] is not None and claimed["nonce"] == 7
    return claimed


@pytest.mark.asyncio
async def test_a_crash_after_storing_the_hash_but_before_the_broadcast_is_resent_as_the_same_bytes(
    db, reconcile_now
):
    chain = FakeChain()
    claimed = await crash_during(db, chain, "eth_sendRawTransaction")
    assert chain.sent == []
    restarted = sender(db)
    with rpc_node(chain):
        await restarted._recover_claims()
        assert await restarted.drain_once() == "done"
    [replacement] = chain.sent
    assert "0x" + keccak(replacement).hex() == claimed["tx_hash"]
    assert decode_record(replacement)["nonce"] == claimed["nonce"]
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert outbox_row(stored) == ("confirmed", claimed["tx_hash"], None)
    assert await attempts(db) == (7, 2)


@pytest.mark.asyncio
async def test_a_crash_after_a_mined_broadcast_is_finished_without_resending(db, reconcile_now):
    chain = FakeChain()
    claimed = await crash_during(db, chain, "eth_getTransactionReceipt")
    assert len(chain.sent) == 1
    restarted = sender(db)
    with rpc_node(chain):
        await restarted._recover_claims()
        assert await restarted.drain_once() == "idle"
    assert len(chain.sent) == 1
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert outbox_row(stored) == ("confirmed", claimed["tx_hash"], None)


@pytest.mark.asyncio
async def test_a_crash_after_a_pending_broadcast_waits_instead_of_resending(db, reconcile_now):
    chain = FakeChain()
    chain.mine = False
    claimed = await crash_during(db, chain, "eth_getTransactionReceipt")
    restarted = sender(db)
    with rpc_node(chain):
        await restarted._recover_claims()
        assert await restarted.drain_once() == "retry"
    assert len(chain.sent) == 1
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"]) == ("pending", claimed["tx_hash"])


@pytest.mark.asyncio
async def test_a_crashed_claim_at_the_attempt_cap_is_left_unconfirmed(db, monkeypatch, reconcile_now):
    monkeypatch.setattr(vp, "MAX_SEND_ATTEMPTS", 1)
    chain = FakeChain()
    claimed = await crash_during(db, chain, "eth_sendRawTransaction")
    restarted = sender(db)
    with rpc_node(chain):
        await restarted._recover_claims()
        assert await restarted.drain_once() == "idle"
    assert chain.sent == []
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert outbox_row(stored) == ("unconfirmed", claimed["tx_hash"], "ClaimInterrupted")


@pytest.mark.asyncio
@pytest.mark.parametrize("method,broadcasts,after_recovery", [
    ("set_verdict_tx_hash", 0, ["done", "idle"]),
    ("update_verdict_onchain", 1, ["idle"]),
    ("release_verdict_claim", 0, ["done", "idle"]),
])
async def test_a_database_failure_mid_send_is_recovered_and_sent_once(
    db, monkeypatch, caplog, method, broadcasts, after_recovery, reconcile_now
):
    chain = FakeChain()
    if method == "release_verdict_claim":
        chain.http_statuses.append(503)  # a failure before signing, so the claim must be released
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    real = getattr(db, method)
    failures = [RuntimeError(f"database is locked {KEY}")]

    async def fail_once(*args, **kwargs):
        if failures:
            raise failures.pop()
        return await real(*args, **kwargs)

    monkeypatch.setattr(db, method, fail_once)
    with rpc_node(chain):
        assert await publisher.drain_once() == "error"
        assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "sending"
        assert len(chain.sent) == broadcasts
        await publisher._recover_claims()
        assert await drain_all(publisher) == after_recovery
    assert len(chain.sent) == 1
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "confirmed"
    assert "RuntimeError" in caplog.text and KEY[2:] not in caplog.text


@pytest.mark.asyncio
async def test_the_drain_recovers_claims_after_an_error(db, monkeypatch):
    publisher = sender(db)
    publisher._wake = asyncio.Event()
    outcomes = iter(["error", "done", "retry"])

    async def drain_once():
        try:
            return next(outcomes)
        except StopIteration:
            raise asyncio.CancelledError

    recoveries = []
    monkeypatch.setattr(publisher, "drain_once", drain_once)
    monkeypatch.setattr(publisher, "_reconcile", AsyncMock(return_value=0))
    monkeypatch.setattr(publisher, "_recover_claims", AsyncMock(side_effect=lambda: recoveries.append("recover")))
    with patch("services.verdict_publisher.asyncio.sleep", new=AsyncMock()):
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(publisher._drain_loop(), 5)
    # Once at start and once after the error; a plain retry does not trigger recovery.
    assert recoveries == ["recover", "recover"]


@pytest.mark.asyncio
async def test_a_failing_claim_query_is_an_error_not_a_crash(db, monkeypatch):
    publisher = sender(db)
    publisher._wake = asyncio.Event()
    monkeypatch.setattr(db, "claim_next_pending_verdict", AsyncMock(side_effect=[RuntimeError("locked"), None]))
    monkeypatch.setattr(publisher, "_reconcile", AsyncMock(side_effect=[0, asyncio.CancelledError()]))
    recover = AsyncMock(return_value=0)
    monkeypatch.setattr(publisher, "_recover_claims", recover)
    with patch("services.verdict_publisher.asyncio.sleep", new=AsyncMock()):
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(publisher._drain_loop(), 5)
    # At start, after the error, and when the drain found nothing to do.
    assert recover.await_count == 3


@pytest.mark.asyncio
async def test_start_recovers_claims_before_draining(db, monkeypatch, reconcile_now):
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


# ---------------------------------------------------------------------------
# Reconciling unresolved records and re-sending them safely
# ---------------------------------------------------------------------------

RESEND = [PRE_SIGN + ["eth_getTransactionCount", "eth_getTransactionReceipt"]]


def posted_hash(chain):
    # Hash of the last raw transaction posted to the node, whether or not the node accepted it.
    [raw] = [body["params"][0] for _, body in chain.posts
             if not isinstance(body, list) and body["method"] == "eth_sendRawTransaction"][-1:]
    return "0x" + keccak(bytes.fromhex(raw[2:])).hex()


def outbox_row(db_row):
    return (db_row["onchain_status"], db_row["tx_hash"], db_row["onchain_error"])


async def attempts(db, subject=TOKEN):
    cursor = await db._db.execute(
        "SELECT nonce, attempts FROM verdict_evidence WHERE subject = ? ORDER BY id DESC LIMIT 1", (subject,)
    )
    return tuple(await cursor.fetchone())


async def record_once(db, chain, publisher, subject=TOKEN):
    await publisher.publish(4663, subject, COMPLETE)
    with rpc_node(chain):
        assert await publisher.drain_once() == "done"
    return await db.get_latest_verdict_evidence(4663, subject)


@pytest.fixture
def reconcile_now(monkeypatch):
    """Reconciliation and claim recovery look at rows at once (the adversarial harness does the same)."""
    monkeypatch.setattr(vp, "RECONCILE_AFTER_SECONDS", -1)


@pytest.mark.asyncio
@pytest.mark.parametrize("setup,status", [
    (lambda chain: setattr(chain, "receipt_status", None), "submitted"),
    (lambda chain: chain.raise_on.update(eth_sendRawTransaction=aiohttp.ClientConnectionError()), "unconfirmed"),
    (lambda chain: chain.errors.update(eth_sendRawTransaction={"code": -32000, "message": "x"}), "failed"),
])
async def test_reconcile_finishes_a_record_whose_receipt_arrived_late(db, reconcile_now, setup, status):
    chain = FakeChain()
    setup(chain)
    publisher = sender(db)
    first = await record_once(db, chain, publisher)
    assert first["onchain_status"] == status
    chain.receipts[first["tx_hash"]] = {"status": "0x1"}
    chain.posts.clear()
    with rpc_node(chain):
        assert await publisher._reconcile() == 0
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert outbox_row(stored) == ("confirmed", first["tx_hash"], None)
    assert chain.methods() == [["eth_getTransactionReceipt"]]


@pytest.mark.asyncio
async def test_reconcile_requeues_a_record_without_a_receipt_and_keeps_its_transaction(db, reconcile_now):
    chain = FakeChain()
    chain.receipt_status = None
    publisher = sender(db)
    first = await record_once(db, chain, publisher)
    with rpc_node(chain):
        assert await publisher._reconcile() == 1
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"]) == ("pending", first["tx_hash"])
    assert await attempts(db) == (7, 1)


@pytest.mark.asyncio
async def test_reconcile_waits_until_a_record_is_old_enough(db):
    chain = FakeChain()
    chain.receipt_status = None
    publisher = sender(db)
    await record_once(db, chain, publisher)
    chain.posts.clear()
    with rpc_node(chain) as factory:
        assert await publisher._reconcile() == 0
    factory.assert_not_called()
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "submitted"


@pytest.mark.asyncio
async def test_reconcile_looks_up_at_most_one_batch_in_one_request(db, reconcile_now):
    chain = FakeChain()
    chain.receipt_status = None
    publisher = sender(db)
    for digit in "abcdef1":
        await record_once(db, chain, publisher, subject="0x" + digit * 40)
    chain.posts.clear()
    with rpc_node(chain):
        assert await publisher._reconcile() == vp.RECONCILE_BATCH
    assert chain.methods() == [["eth_getTransactionReceipt"] * vp.RECONCILE_BATCH]


@pytest.mark.asyncio
async def test_a_record_at_the_attempt_cap_is_still_looked_up_but_not_resent(db, reconcile_now, monkeypatch):
    monkeypatch.setattr(vp, "MAX_SEND_ATTEMPTS", 1)
    chain = FakeChain()
    chain.receipt_status = None
    publisher = sender(db)
    first = await record_once(db, chain, publisher)
    chain.posts.clear()
    with rpc_node(chain):
        assert await publisher._reconcile() == 0
        assert await publisher.drain_once() == "idle"
    assert chain.methods() == [["eth_getTransactionReceipt"]]
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "submitted"
    # Its transaction lands late: the next lookup reports it.
    chain.receipts[first["tx_hash"]] = {"status": "0x1"}
    with rpc_node(chain):
        assert await publisher._reconcile() == 0
    assert outbox_row(await db.get_latest_verdict_evidence(4663, TOKEN)) == ("confirmed", first["tx_hash"], None)
    assert len(chain.sent) == 1


@pytest.mark.asyncio
async def test_a_failed_reconcile_changes_nothing(db, reconcile_now, caplog):
    chain = FakeChain()
    chain.receipt_status = None
    publisher = sender(db)
    await record_once(db, chain, publisher)
    chain.http_statuses.append(503)
    with rpc_node(chain):
        assert await publisher._reconcile() == 0
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "submitted"
    assert "RecordFailed" in caplog.text


@pytest.mark.asyncio
async def test_a_rejected_record_is_resent_at_a_fresh_nonce_once_its_nonce_is_used(db, reconcile_now):
    chain = FakeChain()
    chain.errors["eth_sendRawTransaction"] = {"code": -32000, "message": "fee too low"}
    publisher = sender(db)
    first = await record_once(db, chain, publisher)
    assert outbox_row(first)[:2] == ("failed", posted_hash(chain))
    # The rejected transaction never took nonce 7; another transaction has used it since.
    chain.errors.clear()
    chain.nonce = chain.latest = 8
    chain.posts.clear()
    with rpc_node(chain):
        assert await publisher._reconcile() == 1
        assert await publisher.drain_once() == "done"
    # After the broadcast, one lookup covers both of the row's transactions.
    assert chain.methods() == [["eth_getTransactionReceipt"]] + RESEND + [
        ["eth_sendRawTransaction"], ["eth_getTransactionReceipt"] * 2,
    ]
    retry = decode_record(chain.sent[-1])
    assert retry["nonce"] == 8
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert outbox_row(stored) == ("confirmed", "0x" + keccak(chain.sent[-1]).hex(), None)
    assert await attempts(db) == (8, 2)


@pytest.mark.asyncio
async def test_a_requeued_record_takes_the_same_nonce_while_it_is_unused(db, reconcile_now):
    chain = FakeChain()
    # The send's outcome is unknown: the transaction never reached the node.
    chain.raise_on["eth_sendRawTransaction"] = aiohttp.ClientConnectionError()
    chain.receipt_status = None
    publisher = sender(db)
    first = await record_once(db, chain, publisher)
    assert first["onchain_status"] == "unconfirmed"
    assert chain.sent == []
    chain.raise_on.clear()
    chain.receipt_status = "0x1"
    with rpc_node(chain):
        assert await publisher._reconcile() == 1
        assert await publisher.drain_once() == "done"
    [replacement] = chain.sent
    # The same bytes again, never a second transaction at the same nonce.
    assert "0x" + keccak(replacement).hex() == first["tx_hash"]
    assert decode_record(replacement)["nonce"] == 7
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "confirmed"
    assert await attempts(db) == (7, 2)


@pytest.mark.asyncio
async def test_a_requeued_record_waits_while_something_is_pending_at_its_nonce(db, reconcile_now):
    chain = FakeChain()
    chain.mine = False
    publisher = sender(db)
    first = await record_once(db, chain, publisher)
    assert first["onchain_status"] == "submitted"
    assert (chain.latest, chain.nonce) == (7, 8)
    with rpc_node(chain):
        assert await publisher._reconcile() == 1
        assert await publisher.drain_once() == "retry"
    assert len(chain.sent) == 1
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert (stored["onchain_status"], stored["tx_hash"]) == ("pending", first["tx_hash"])
    assert await attempts(db) == (7, 1)


@pytest.mark.asyncio
async def test_a_requeued_record_whose_first_transaction_was_mined_is_not_resent(db):
    chain = FakeChain()
    chain.receipt_status = None
    publisher = sender(db)
    first = await record_once(db, chain, publisher)
    await db.requeue_verdict(first["id"])
    chain.receipts[first["tx_hash"]] = {"status": "0x1"}
    with rpc_node(chain):
        assert await publisher.drain_once() == "done"
    assert len(chain.sent) == 1
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert outbox_row(stored) == ("confirmed", first["tx_hash"], None)
    assert await attempts(db) == (7, 1)


@pytest.mark.asyncio
async def test_the_drain_reconciles_at_start_and_when_idle(db, monkeypatch):
    monkeypatch.setattr(vp, "DRAIN_POLL_SECONDS", 0.01)
    publisher = sender(db)
    publisher._wake = asyncio.Event()
    monkeypatch.setattr(publisher, "_recover_claims", AsyncMock(return_value=0))
    monkeypatch.setattr(publisher, "drain_once", AsyncMock(return_value="idle"))
    calls = []

    async def reconcile():
        calls.append(len(publisher.drain_once.await_args_list))
        if len(calls) == 3:
            raise asyncio.CancelledError
        return 0

    monkeypatch.setattr(publisher, "_reconcile", reconcile)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(publisher._drain_loop(), 5)
    # Once before the first drain, then after each idle drain.
    assert calls == [0, 1, 2]


@pytest.mark.asyncio
async def test_rows_requeued_by_reconcile_are_drained_without_waiting(db, monkeypatch):
    monkeypatch.setattr(vp, "DRAIN_POLL_SECONDS", 3600)
    publisher = sender(db)
    publisher._wake = asyncio.Event()
    monkeypatch.setattr(publisher, "_recover_claims", AsyncMock(return_value=0))
    outcomes = iter(["idle", "done", "idle"])
    monkeypatch.setattr(publisher, "drain_once", AsyncMock(side_effect=lambda: next(outcomes)))
    results = iter([0, 1])

    async def reconcile():
        try:
            return next(results)
        except StopIteration:
            raise asyncio.CancelledError

    monkeypatch.setattr(publisher, "_reconcile", reconcile)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(publisher._drain_loop(), 5)
    assert publisher.drain_once.await_count == 3


def test_the_publisher_imports_no_private_names_from_the_simulator():
    import ast

    with open(vp.__file__, encoding="utf-8") as source:
        tree = ast.parse(source.read())
    private = [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "services.robinhood_simulation"
        for alias in node.names
        if alias.name.startswith("_")
    ]
    assert private == []


@pytest.mark.parametrize("value,expected", [("0x0", 0), ("0x1f", 31), ("0X1F", None), ("1f", None), ("0x", None), (31, None)])
def test_quantities_are_strict_hex(value, expected):
    assert vp._quantity(value) == expected


@pytest.mark.parametrize("error,limited", [
    ({"code": 429}, True),
    ({"code": -32005, "message": "limit exceeded"}, True),
    ({"code": -32000, "message": "Rate limit reached"}, True),
    ({"code": -32000, "message": "Too Many Requests"}, True),
    ({"code": -32000, "message": "nonce too low"}, False),
    ("rate limit", False),
    (None, False),
])
def test_rate_limit_errors_are_recognised(error, limited):
    assert vp._rate_limited(error) is limited


# ---------------------------------------------------------------------------
# A late transaction is never recorded twice: the review's scenarios S1, S2 and S4, with the fee changed between
# attempts so that signing again would produce different bytes
# ---------------------------------------------------------------------------

FEE_CHANGE = 1_000_000


def status_and_hash(stored):
    return stored["onchain_status"], stored["tx_hash"]


@pytest.mark.asyncio
async def test_s1_a_restart_while_the_replica_lags_resends_the_same_bytes_and_records_once(db, reconcile_now):
    chain = FakeChain()
    chain.lagging = True  # the node answering us has not seen the block with our transaction yet
    chain.raise_on["eth_getTransactionReceipt"] = asyncio.CancelledError()  # the process dies after broadcasting
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    with rpc_node(chain):
        with pytest.raises(asyncio.CancelledError):
            await publisher.drain_once()
    chain.raise_on.clear()
    [(_, first, _)] = chain.mined
    chain.errors["eth_sendRawTransaction"] = {"code": -32000, "message": "nonce too low"}
    chain.base_fee += FEE_CHANGE
    restarted = sender(db)
    with rpc_node(chain):
        assert await restarted._recover_claims() == 1
        assert await restarted.drain_once() == "done"
    assert posted_hash(chain) == first
    assert status_and_hash(await db.get_latest_verdict_evidence(4663, TOKEN)) == ("failed", first)
    chain.errors.clear()
    chain.catch_up()
    with rpc_node(chain):
        assert await restarted._reconcile() == 0
        assert await restarted.drain_once() == "idle"
    assert status_and_hash(await db.get_latest_verdict_evidence(4663, TOKEN)) == ("confirmed", first)
    assert len(chain.mined) == 1 and chain.doubles() == []


@pytest.mark.asyncio
async def test_s2_a_stale_replica_during_reconcile_resends_the_same_bytes_and_records_once(db, reconcile_now):
    chain = FakeChain()
    chain.lagging = True
    publisher = sender(db)
    first = await record_once(db, chain, publisher)
    assert status_and_hash(first) == ("submitted", chain.mined[0][1])
    chain.errors["eth_sendRawTransaction"] = {"code": -32000, "message": "nonce too low"}
    chain.base_fee += FEE_CHANGE
    with rpc_node(chain):
        assert await publisher._reconcile() == 1
        assert await publisher.drain_once() == "done"
    assert posted_hash(chain) == first["tx_hash"]
    assert status_and_hash(await db.get_latest_verdict_evidence(4663, TOKEN)) == ("failed", first["tx_hash"])
    chain.errors.clear()
    chain.catch_up()
    with rpc_node(chain):
        assert await publisher._reconcile() == 0
        assert await publisher.drain_once() == "idle"
    assert status_and_hash(await db.get_latest_verdict_evidence(4663, TOKEN)) == ("confirmed", first["tx_hash"])
    assert len(chain.mined) == 1 and chain.doubles() == []


@pytest.mark.asyncio
async def test_s4_an_underpriced_rejection_while_the_first_transaction_is_held_records_once(db, reconcile_now):
    chain = FakeChain()
    chain.lagging, chain.mine = True, False  # another backend holds our transaction; it is not mined yet
    publisher = sender(db)
    first = await record_once(db, chain, publisher)
    assert first["onchain_status"] == "submitted"
    chain.errors["eth_sendRawTransaction"] = {"code": -32000, "message": "replacement transaction underpriced"}
    chain.base_fee += FEE_CHANGE
    with rpc_node(chain):
        assert await publisher._reconcile() == 1
        assert await publisher.drain_once() == "done"
    assert posted_hash(chain) == first["tx_hash"]
    assert status_and_hash(await db.get_latest_verdict_evidence(4663, TOKEN)) == ("failed", first["tx_hash"])
    # The held transaction lands after all.
    held = decode_record(chain.sent[0])
    chain.mined.append((held["nonce"], first["tx_hash"], held["evidence_hash"]))
    chain.errors.clear()
    chain.catch_up()
    with rpc_node(chain):
        assert await publisher._reconcile() == 0
        assert await publisher.drain_once() == "idle"
    assert status_and_hash(await db.get_latest_verdict_evidence(4663, TOKEN)) == ("confirmed", first["tx_hash"])
    assert len(chain.mined) == 1 and chain.doubles() == []


async def two_transaction_row(db, chain, publisher):
    """A row whose first transaction was rejected at nonce 7 and whose second, at nonce 8, is unconfirmed."""
    chain.errors["eth_sendRawTransaction"] = {"code": -32000, "message": "fee too low"}
    first = await record_once(db, chain, publisher)
    chain.errors.clear()
    chain.nonce = chain.latest = 8  # another transaction used nonce 7
    await db.requeue_verdict(first["id"])
    chain.raise_on["eth_sendRawTransaction"] = aiohttp.ClientConnectionError()
    chain.receipt_status = None
    with rpc_node(chain):
        assert await publisher.drain_once() == "done"
    chain.raise_on.clear()
    second = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert second["onchain_status"] == "unconfirmed"
    assert second["tx_hash"] != first["tx_hash"]
    assert await attempts(db) == (8, 2)
    return first["id"], first["tx_hash"], second["tx_hash"]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["drain", "reconcile", "recovery"])
async def test_a_receipt_for_an_older_transaction_finishes_the_row(db, reconcile_now, path):
    chain = FakeChain()
    publisher = sender(db)
    evidence_id, first, second = await two_transaction_row(db, chain, publisher)
    chain.receipts[first] = {"status": "0x1"}  # only the older transaction is mined
    chain.posts.clear()
    with rpc_node(chain):
        if path == "drain":
            await db.requeue_verdict(evidence_id)
            assert await publisher.drain_once() == "done"
        elif path == "reconcile":
            assert await publisher._reconcile() == 0
        else:
            await db.requeue_verdict(evidence_id)
            await db.claim_next_pending_verdict(4663)
            assert await publisher._recover_claims() == 0
    assert outbox_row(await db.get_latest_verdict_evidence(4663, TOKEN)) == ("confirmed", first, None)
    assert ["eth_sendRawTransaction"] not in chain.methods()
    assert any(len(methods) > 1 and methods.count("eth_getTransactionReceipt") >= 2 for methods in chain.methods())


@pytest.mark.asyncio
async def test_a_row_with_several_transactions_resends_the_bytes_at_its_last_nonce(db, reconcile_now):
    chain = FakeChain()
    publisher = sender(db)
    evidence_id, first, second = await two_transaction_row(db, chain, publisher)
    await db.requeue_verdict(evidence_id)
    with rpc_node(chain):
        assert await publisher.drain_once() == "done"
    assert posted_hash(chain) == second
    assert decode_record(chain.sent[-1])["nonce"] == 8
    assert await attempts(db) == (8, 3)
    transactions = (await db.get_verdict_transactions([evidence_id]))[evidence_id]
    assert [t["tx_hash"] for t in transactions] == [first, second]


SECOND_TOKEN = "0x" + "7b" * 20


async def row_without_stored_bytes(db, publisher, nonce=7):
    """A row whose earlier transaction's bytes were never stored: only its hash and nonce are known."""
    evidence_id = (await publisher.publish(4663, TOKEN, COMPLETE))["evidence_id"]
    await db.claim_next_pending_verdict(4663)
    await db.set_verdict_tx_hash(evidence_id, "0x" + "44" * 32, nonce)
    await db.update_verdict_onchain(evidence_id, "unconfirmed", tx_hash="0x" + "44" * 32)
    await db.requeue_verdict(evidence_id)
    return evidence_id


@pytest.mark.asyncio
async def test_without_the_stored_bytes_a_replacement_is_signed_at_the_same_unused_nonce(db):
    chain = FakeChain()
    publisher = sender(db)
    evidence_id = await row_without_stored_bytes(db, publisher)
    with rpc_node(chain):
        assert await publisher.drain_once() == "done"
    [replacement] = chain.sent
    # Only one transaction per nonce can be mined, and both hashes are checked from now on.
    assert decode_record(replacement)["nonce"] == 7
    replacement_hash = "0x" + keccak(replacement).hex()
    assert outbox_row(await db.get_latest_verdict_evidence(4663, TOKEN)) == ("confirmed", replacement_hash, None)
    transactions = (await db.get_verdict_transactions([evidence_id]))[evidence_id]
    assert [t["tx_hash"] for t in transactions] == ["0x" + "44" * 32, replacement_hash]


@pytest.mark.asyncio
async def test_without_the_stored_bytes_the_drain_waits_while_something_is_pending_at_the_nonce(db):
    chain = FakeChain()
    chain.nonce = 8  # something is pending at nonce 7, possibly the earlier transaction
    publisher = sender(db)
    await row_without_stored_bytes(db, publisher)
    with rpc_node(chain):
        assert await publisher.drain_once() == "retry"
    assert ["eth_sendRawTransaction"] not in chain.methods()
    stored = await db.get_latest_verdict_evidence(4663, TOKEN)
    assert status_and_hash(stored) == ("pending", "0x" + "44" * 32)


@pytest.mark.asyncio
async def test_a_failed_transaction_insert_never_stalls_the_outbox(tmp_path, reconcile_now, caplog):
    """The review's S13: the insert fails mid-send, nothing is broadcast, and every row is still recorded."""
    import sqlite3

    database = Database(str(tmp_path / "shieldbot.db"))
    await database.initialize()
    try:
        chain = FakeChain()
        publisher = sender(database)
        await publisher.publish(4663, TOKEN, COMPLETE)
        execute = database._db.execute
        failures = [sqlite3.OperationalError("disk I/O error")]

        async def failing_insert_once(sql, parameters=()):
            if "INSERT OR IGNORE INTO verdict_transactions" in sql and failures:
                raise failures.pop()
            return await execute(sql, parameters)

        database._db.execute = failing_insert_once
        with rpc_node(chain):
            assert await publisher.drain_once() == "error"
        assert chain.sent == []
        await publisher.publish(4663, SECOND_TOKEN, COMPLETE)
        with rpc_node(chain):
            assert await publisher._recover_claims() == 1
            assert await drain_all(publisher) == ["done", "done", "idle"]
        assert [decode_record(raw)["nonce"] for raw in chain.sent] == [7, 8]
        for subject in (TOKEN, SECOND_TOKEN):
            assert (await database.get_latest_verdict_evidence(4663, subject))["onchain_status"] == "confirmed"
        assert "OperationalError" in caplog.text
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_a_transaction_is_never_broadcast_once_the_claim_is_lost(db, monkeypatch, caplog):
    chain = FakeChain()
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    monkeypatch.setattr(db, "set_verdict_tx_hash", AsyncMock(return_value=False))
    with rpc_node(chain):
        assert await publisher.drain_once() == "done"
    assert ["eth_sendRawTransaction"] not in chain.methods()
    assert chain.sent == []
    assert "no longer claimed" in caplog.text


@pytest.mark.asyncio
async def test_claim_recovery_gives_a_lagging_replica_time(db, monkeypatch):
    chain = FakeChain()
    publisher = sender(db)
    await publisher.publish(4663, TOKEN, COMPLETE)
    await db.claim_next_pending_verdict(4663)
    with rpc_node(chain) as factory:
        assert await publisher._recover_claims() == 0
    factory.assert_not_called()
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "sending"
    monkeypatch.setattr(vp, "RECONCILE_AFTER_SECONDS", -1)
    with rpc_node(chain):
        assert await publisher._recover_claims() == 1
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "pending"


@pytest.mark.asyncio
async def test_the_idle_drain_recovers_old_claims(db, monkeypatch):
    monkeypatch.setattr(vp, "DRAIN_POLL_SECONDS", 0.01)
    publisher = sender(db)
    publisher._wake = asyncio.Event()
    recover = AsyncMock(side_effect=[0, 0, asyncio.CancelledError()])
    monkeypatch.setattr(publisher, "_recover_claims", recover)
    monkeypatch.setattr(publisher, "_reconcile", AsyncMock(return_value=0))
    monkeypatch.setattr(publisher, "drain_once", AsyncMock(return_value="idle"))
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(publisher._drain_loop(), 5)
    # Once at start, then after each idle drain.
    assert (recover.await_count, publisher.drain_once.await_count) == (3, 2)


# ---------------------------------------------------------------------------
# D3: stopping waits (bounded) for a send under way; D5: long waits raise an alarm
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_awaiting_stop_waits_for_a_send_under_way_to_record_its_outcome(db, monkeypatch):
    monkeypatch.setattr(vp, "DRAIN_POLL_SECONDS", 3600)
    chain = FakeChain()
    gate = gate_method(chain, "eth_getTransactionReceipt")
    publisher = make_publisher(db)
    with rpc_node(chain):
        publisher.start(recorder_key=KEY)
        await publisher.publish(4663, TOKEN, COMPLETE)
        await until(lambda: asyncio.sleep(0, bool(chain.sent)))
        stopped = publisher.stop()
        await asyncio.sleep(0.05)
        assert not stopped.done()
        gate.set()
        await asyncio.wait_for(stopped, 5)
    # The outcome is stored before the lifespan goes on to close the database.
    assert (await db.get_latest_verdict_evidence(4663, TOKEN))["onchain_status"] == "confirmed"


@pytest.mark.asyncio
async def test_stop_waits_at_most_its_bound(db, monkeypatch, caplog):
    monkeypatch.setattr(vp, "DRAIN_POLL_SECONDS", 3600)
    monkeypatch.setattr(vp, "STOP_TIMEOUT_SECONDS", 0.05)
    chain = FakeChain()
    gate = gate_method(chain, "eth_getTransactionReceipt")
    publisher = make_publisher(db)
    with rpc_node(chain):
        publisher.start(recorder_key=KEY)
        await publisher.publish(4663, TOKEN, COMPLETE)
        await until(lambda: asyncio.sleep(0, bool(chain.sent)))
        await asyncio.wait_for(publisher.stop(), 5)
        assert "1 send(s) still under way" in caplog.text
        gate.set()
        await sends_settled(publisher)


@pytest.mark.asyncio
async def test_stop_without_a_drain_or_sends_finishes_at_once(db):
    publisher = make_publisher(db)
    await asyncio.wait_for(publisher.stop(), 1)


@pytest.mark.asyncio
async def test_long_waits_on_an_earlier_transaction_raise_an_alarm(db, reconcile_now, monkeypatch, caplog):
    monkeypatch.setattr(vp, "WAIT_ALARM_AFTER", 2)
    chain = FakeChain()
    chain.mine = False  # accepted but never mined: something stays pending at nonce 7
    publisher = sender(db)
    await record_once(db, chain, publisher)
    with rpc_node(chain):
        assert await publisher._reconcile() == 1
        assert await publisher.drain_once() == "retry"
        assert "in a row" not in caplog.text
        assert await publisher.drain_once() == "retry"
    assert "waited 2 times in a row" in caplog.text
    assert len(chain.sent) == 1
