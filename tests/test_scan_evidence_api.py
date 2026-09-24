"""/api/firewall and /api/scan responses link a stored evidence document; GET /api/evidence and
GET /evidence serve it."""

import itertools
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from eth_utils import keccak
from fastapi.testclient import TestClient
from web3 import Web3

from core.analyzer import AnalyzerResult
from core.database import SCAN_EVIDENCE_RETENTION_DAYS, Database
from core.risk_engine import RiskEngine

TARGET = "0x" + "ab" * 20
CALLER = "0x9f8E7d6C5b4A39281706f5E4d3C2b1A09f8E7d6C"
SPENDER = "0x" + "cd" * 20
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
APPROVE = "0x095ea7b3" + SPENDER[2:].rjust(64, "0") + "f" * 64
API_KEY = "sk-evidence-test-key-1234567890"
FORWARDED_IP = "203.0.113.9"
URL_BASE = "https://api.example"


def _results():
    return [
        AnalyzerResult(
            "structural",
            0.4,
            0,
            data={
                "is_contract": True,
                "is_verified": True,
                "contract_age_days": 400,
                "top10_holder_percent": 12.5,
                "coverage": {
                    "is_verified": True,
                    "contract_age_days": True,
                    "top10_holder_percent": True,
                },
                "status": "ok",
            },
        ),
        AnalyzerResult("market", 0.25, 0, data={"status": "ok", "liquidity_usd": 50_000}),
        AnalyzerResult("behavioral", 0.2, 0, data={"status": "ok", "reputation_score": 50}),
        AnalyzerResult(
            "honeypot",
            0.15,
            0,
            data={
                "is_honeypot": False,
                "can_buy": True,
                "can_sell": True,
                "buy_tax": 0,
                "sell_tax": 0,
                "simulation_block": 777,
                "field_providers": {"is_honeypot": "eth_simulateV1"},
                "status": "ok",
            },
        ),
    ]


def _decode(data):
    if data.startswith("0x095ea7b3"):
        return {
            "selector": "095ea7b3",
            "function_name": "approve",
            "category": "approval",
            "params": {"param_0": SPENDER, "param_1": 2**256 - 1},
            "is_approval": True,
            "is_unlimited_approval": True,
        }
    return {"selector": None}


@pytest_asyncio.fixture
async def evidence_api(monkeypatch, mock_web3_client):
    import api

    database = Database(":memory:")
    await database.initialize()
    mock_web3_client.is_token_contract = AsyncMock(return_value=True)
    services = SimpleNamespace(
        web3_client=mock_web3_client,
        db=database,
        registry=SimpleNamespace(run_all=AsyncMock(side_effect=lambda ctx: _results())),
        policy_engine=None,
        indexer=None,
        counterparty_service=None,
        auth_manager=SimpleNamespace(
            validate_key=AsyncMock(return_value={"key_id": "key-1"}),
            check_rate_limit=AsyncMock(return_value=True),
            record_usage=AsyncMock(),
        ),
        settings=SimpleNamespace(
            policy_mode="BALANCED",
            reporter_hash_secret="",
            trusted_proxies=["testclient"],
            public_api_url=URL_BASE + "/",
        ),
    )
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", mock_web3_client)
    monkeypatch.setattr(
        api,
        "calldata_decoder",
        SimpleNamespace(decode=_decode, is_whitelisted_target=lambda *args, **kwargs: None),
    )
    monkeypatch.setattr(api, "risk_engine", RiskEngine())
    monkeypatch.setattr(api, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False))
    monkeypatch.setattr(api, "greenfield_service", None)
    monkeypatch.setattr(api, "ai_analyzer", SimpleNamespace(is_available=lambda: False))
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(1000, 1000))
    monkeypatch.setattr(api, "_token_cache", {})
    client = TestClient(api.app, raise_server_exceptions=False)
    yield api, client, database
    client.close()
    await database.close()


def _firewall(client, data="0x", **headers):
    return client.post(
        "/api/firewall",
        json={"to": TARGET, "from": CALLER, "value": "0", "data": data, "chainId": 56},
        headers=headers,
    )


def _stored(client, response):
    body = response.json()
    evidence = client.get(f"/api/evidence/{body['evidence_hash']}")
    assert evidence.status_code == 200
    return body, evidence.json()


def test_a_firewall_verdict_links_its_stored_evidence(evidence_api):
    _, client, _ = evidence_api
    response = _firewall(client, APPROVE, **{"x-api-key": API_KEY, "X-Forwarded-For": FORWARDED_IP})
    assert response.status_code == 200
    body, stored = _stored(client, response)
    digest = body["evidence_hash"]
    assert body["evidence_url"] == f"{URL_BASE}/evidence/{digest}"
    assert stored["evidence_hash"] == digest
    assert "0x" + keccak(stored["canonical"].encode("utf-8")).hex() == digest
    assert stored["evidence"] == json.loads(stored["canonical"])
    assert stored["expires_at"] == pytest.approx(
        stored["stored_at"] + SCAN_EVIDENCE_RETENTION_DAYS * 86400
    )
    assert "keccak256" in stored["verify"]

    doc = stored["evidence"]
    assert (doc["schema"], doc["endpoint"], doc["source"]) == (
        "shieldbot-scan-evidence",
        "/api/firewall",
        "scan",
    )
    assert (doc["chain_id"], doc["target"]) == (56, TARGET)
    assert doc["target_token"] == {"name": "TestToken", "symbol": "TT"}
    assert (doc["classification"], doc["risk_score"]) == (
        body["classification"],
        body["risk_score"],
    )
    assert (doc["risk_level"], doc["status"]) == (
        body["shield_score"]["risk_level"],
        body["status"],
    )
    assert (doc["coverage"], doc["coverage_reasons"]) == (
        body["coverage"],
        body["coverage_reasons"],
    )
    assert (doc["failed_sources"], doc["policy_mode"]) == (
        body["failed_sources"],
        body["policy_mode"],
    )
    assert set(doc["analyzers"]) == {"structural", "market", "behavioral", "honeypot"}
    assert doc["analyzers"]["structural"]["fields"]["top10_holder_percent"] == "answered"
    assert doc["analyzers"]["honeypot"]["field_providers"] == {"is_honeypot": "eth_simulateV1"}
    assert doc["observed_block"] == 777
    assert doc["transaction"]["function"] == "approve"
    assert doc["transaction"]["calldata_keccak"] == "0x" + keccak(bytes.fromhex(APPROVE[2:])).hex()

    text = stored["canonical"].lower()
    for secret in (CALLER[2:], FORWARDED_IP, "testclient", API_KEY, SPENDER[2:], "f" * 64):
        assert secret.lower() not in text


def test_a_plain_call_records_no_transaction(evidence_api):
    _, client, _ = evidence_api
    _, stored = _stored(client, _firewall(client))
    assert stored["evidence"]["transaction"] is None
    assert stored["evidence"]["target_token"] is None


@pytest.mark.asyncio
async def test_hits_on_one_cached_row_share_one_cache_document(evidence_api, monkeypatch):
    api, client, database = evidence_api
    # Each response is built five seconds after the last, so the hits never share a second.
    clock = itertools.count(int(time.time()), 5)
    monkeypatch.setattr(
        api, "time", SimpleNamespace(time=lambda: next(clock), monotonic=time.monotonic)
    )
    first, first_doc = _stored(client, _firewall(client))
    cached, cached_doc = _stored(client, _firewall(client))
    again = _firewall(client).json()
    assert cached["cached"] is True and again["cached"] is True
    assert again["evidence_hash"] == cached["evidence_hash"] != first["evidence_hash"]
    cursor = await database._db.execute("SELECT COUNT(*) FROM scan_evidence")
    assert (await cursor.fetchone())[0] == 2
    assert first_doc["evidence"]["source"] == "scan"
    doc = cached_doc["evidence"]
    assert doc["source"] == "cache"
    # The stored scan's time, not the time this hit was served (that is stored_at).
    assert doc["scanned_at"] == doc["cached_scan_at"] <= first_doc["evidence"]["scanned_at"]
    assert doc["analyzers"] is None
    assert (doc["classification"], doc["risk_score"]) == (
        cached["classification"],
        cached["risk_score"],
    )


def test_a_signature_request_records_hashes_not_the_signed_data(evidence_api):
    _, client, _ = evidence_api
    typed = {
        "types": {
            "EIP712Domain": [{"name": "chainId", "type": "uint256"}],
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ],
        },
        "primaryType": "Permit",
        "domain": {"chainId": 56, "verifyingContract": TARGET},
        "message": {"owner": CALLER, "spender": PERMIT2, "value": "1", "nonce": 0, "deadline": 1},
    }
    response = client.post(
        "/api/firewall",
        json={
            "to": "",
            "from": CALLER,
            "data": "0x",
            "chainId": 56,
            "typedData": typed,
            "signMethod": "eth_signTypedData_v4",
        },
    )
    assert response.status_code == 200
    _, stored = _stored(client, response)
    doc = stored["evidence"]
    assert doc["target"] == TARGET
    assert set(doc["analyzers"]) == {"signature"}
    assert doc["transaction"]["typed_data_primary_type"] == "Permit"
    assert doc["transaction"]["typed_data_keccak"].startswith("0x")
    assert CALLER[2:].lower() not in stored["canonical"].lower()


@pytest.mark.parametrize(
    "sender", ["0X" + CALLER[2:], CALLER[2:], CALLER[2:].lower()], ids=["0X", "unprefixed", "lower"]
)
def test_a_personal_sign_caller_is_masked_in_any_address_form(
    evidence_api, mock_web3_client, sender
):
    _, client, _ = evidence_api
    # The API's address checks accept these forms, so the signature target falls back to the sender.
    mock_web3_client.is_valid_address.side_effect = Web3.is_address
    mock_web3_client.to_checksum_address.side_effect = Web3.to_checksum_address
    response = client.post(
        "/api/firewall",
        json={
            "to": "",
            "from": sender,
            "data": "0x68656c6c6f",
            "chainId": 56,
            "signMethod": "personal_sign",
        },
    )
    assert response.status_code == 200
    _, stored = _stored(client, response)
    assert stored["evidence"]["target"] == "[caller]"
    assert CALLER[2:].lower() not in stored["canonical"].lower()


def test_a_document_that_cannot_be_serialised_leaves_the_verdict(evidence_api, monkeypatch):
    api, client, database = evidence_api
    monkeypatch.setattr(
        api, "build_scan_evidence", lambda *args, **kwargs: {"risk_score": float("nan")}
    )
    insert = AsyncMock()
    monkeypatch.setattr(database, "insert_scan_evidence", insert)
    response = _firewall(client)
    assert response.status_code == 200
    body = response.json()
    assert (body["evidence_hash"], body["evidence_url"]) == (None, None)
    assert body["classification"]
    insert.assert_not_awaited()


ROUTER = "0x" + "12" * 20
PATH = ["0x" + "34" * 20, "0x" + "56" * 20]


def test_a_router_swap_records_the_analyzers_of_every_path_token(evidence_api, monkeypatch):
    api, client, _ = evidence_api

    def decode(data):
        if data.startswith("0x38ed1739"):
            return {
                "selector": "38ed1739",
                "function_name": "swapExactTokensForTokens",
                "category": "swap",
                "params": {"param_2": PATH},
            }
        return _decode(data)

    monkeypatch.setattr(
        api,
        "calldata_decoder",
        SimpleNamespace(
            decode=decode,
            is_whitelisted_target=lambda address, **kwargs: (
                "Router" if address.lower() == ROUTER else None
            ),
        ),
    )
    response = client.post(
        "/api/firewall",
        json={
            "to": ROUTER,
            "from": CALLER,
            "value": "0",
            "data": "0x38ed1739" + "00" * 32,
            "chainId": 56,
        },
    )
    assert response.status_code == 200
    body, stored = _stored(client, response)
    doc = stored["evidence"]
    assert doc["target"] == ROUTER
    assert set(doc["analyzers"]) == {
        f"{token}:{name}"
        for token in PATH
        for name in ("structural", "market", "behavioral", "honeypot")
    }
    assert set(doc["coverage"]) == set(doc["analyzers"])
    assert doc["observed_block"] == 777
    assert (doc["classification"], doc["risk_level"]) == (
        body["classification"],
        body["shield_score"]["risk_level"],
    )
    assert doc["transaction"] is None


def test_the_legacy_fallback_records_what_it_reports_and_no_analyzers(evidence_api, monkeypatch):
    api, client, _ = evidence_api
    api.container.registry.run_all.side_effect = RuntimeError("registry down")
    monkeypatch.setattr(
        api,
        "token_scanner",
        SimpleNamespace(
            check_token=AsyncMock(
                return_value={
                    "risk_score": 20,
                    "is_verified": True,
                    "scam_matches": [],
                    "status": "ok",
                    "coverage": {"is_verified": True, "scam_database": True},
                    "coverage_reasons": {},
                }
            )
        ),
    )
    response = _firewall(client)
    assert response.status_code == 200
    body, stored = _stored(client, response)
    doc = stored["evidence"]
    assert "shield_score" not in body
    assert (doc["target"], doc["classification"], doc["risk_score"]) == (
        TARGET,
        body["classification"],
        body["risk_score"],
    )
    # The composite pipeline failed, so nothing it measured describes this verdict.
    assert (doc["analyzers"], doc["observed_block"]) == (None, None)
    assert (doc["risk_level"], doc["policy_mode"], doc["failed_sources"]) == (None, None, None)


def test_a_scan_links_its_stored_evidence(evidence_api, monkeypatch):
    api, client, _ = evidence_api
    monkeypatch.setattr(
        api,
        "tx_scanner",
        SimpleNamespace(
            scan_address=AsyncMock(
                return_value={
                    "address": TARGET,
                    "risk_score": 20,
                    "risk_level": "low",
                    "status": "ok",
                    "coverage": {"is_verified": True, "scam_database": True},
                    "coverage_reasons": {},
                }
            )
        ),
    )
    response = client.post("/api/scan", json={"address": TARGET, "chainId": 56})
    assert response.status_code == 200
    body, stored = _stored(client, response)
    doc = stored["evidence"]
    assert (doc["endpoint"], doc["target"], doc["classification"]) == (
        "/api/scan",
        TARGET,
        body["classification"],
    )
    assert (doc["risk_level"], doc["analyzers"], doc["transaction"]) == ("low", None, None)


def test_a_failed_store_leaves_the_verdict_and_no_url(evidence_api, monkeypatch):
    _, client, database = evidence_api
    monkeypatch.setattr(
        database, "insert_scan_evidence", AsyncMock(side_effect=RuntimeError("disk full"))
    )
    response = _firewall(client)
    assert response.status_code == 200
    body = response.json()
    assert body["evidence_hash"].startswith("0x") and len(body["evidence_hash"]) == 66
    assert body["evidence_url"] is None
    assert client.get(f"/api/evidence/{body['evidence_hash']}").status_code == 404


def test_the_page_is_self_contained_and_escapes_the_token_name(evidence_api, mock_web3_client):
    _, client, _ = evidence_api
    mock_web3_client.get_token_info.return_value = {
        "name": "<script>alert(1)</script>",
        "symbol": "<b>X</b>",
    }
    body = _firewall(client, APPROVE).json()
    page = client.get(f"/evidence/{body['evidence_hash'].upper().replace('0X', '0x')}")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    csp = page.headers["content-security-policy"]
    assert (
        "default-src 'none'" in csp and "script-src" not in csp and "frame-ancestors 'none'" in csp
    )
    assert "<script" not in page.text.lower()
    assert "<b>X" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert body["evidence_hash"] in page.text


@pytest.mark.parametrize("path", ["/api/evidence/{}", "/evidence/{}"])
@pytest.mark.parametrize("value", ["0x" + "0" * 64, "0x1234", "not-a-hash"])
def test_an_unknown_hash_is_404(evidence_api, path, value):
    _, client, _ = evidence_api
    assert client.get(path.format(value)).status_code == 404


@pytest.mark.parametrize("path", ["/api/evidence/{}", "/evidence/{}"])
def test_the_routes_need_the_database(evidence_api, monkeypatch, path):
    api, client, _ = evidence_api
    monkeypatch.setattr(api.container, "db", None)
    assert client.get(path.format("0x" + "0" * 64)).status_code == 503


@pytest.mark.parametrize("path", ["/api/evidence/{}", "/evidence/{}"])
def test_the_routes_use_the_global_ip_rate_limit(evidence_api, monkeypatch, path):
    api, client, _ = evidence_api
    monkeypatch.setattr(api, "rate_limiter", api.RateLimiter(requests_per_minute=2, burst=10))
    codes = [client.get(path.format("0x" + "0" * 64)).status_code for _ in range(3)]
    assert codes == [404, 404, 429]
