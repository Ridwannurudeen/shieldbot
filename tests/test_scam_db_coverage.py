"""A scam database provider failure must never read as a clean address."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

import utils.scam_db as scam_module
from analyzers.structural import StructuralAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.risk_engine import RiskEngine
from scanner.transaction_scanner import TransactionScanner
from services.contract_service import ContractService
from utils.scam_db import ScamDatabase, ScamMatches


ADDRESS = "0x1111111111111111111111111111111111111111"
SECRET = "SCAM-DB-SECRET-51c2"
SCAM_MATCH = {"type": "Local Blacklist", "reason": "Known scam address", "source": "ShieldBot"}
GOPLUS_OK = {"status": "ok", "reason": None, "data": {"is_honeypot": "0", "is_open_source": "1"}}


@pytest.fixture(autouse=True)
def goplus_cache():
    scam_module._GOPLUS_CACHE.clear()
    yield
    scam_module._GOPLUS_CACHE.clear()


def _chainabuse(db, status=200, payload=None, error=None):
    response = MagicMock(status=status)
    response.json = AsyncMock(return_value=payload)
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    session.get.return_value.__aexit__ = AsyncMock(return_value=False)
    if error is not None:
        session.get.side_effect = error
    db._get_session = AsyncMock(return_value=session)


async def _lookup(db, goplus=GOPLUS_OK):
    with patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock(return_value=goplus)):
        return await db.check_address(ADDRESS, chain_id=4663)


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [[], None])
async def test_every_provider_answered_without_matches_is_complete(payload):
    db = ScamDatabase()
    _chainabuse(db, payload=payload)
    matches = await _lookup(db)
    assert matches == []
    assert matches.failed_providers == ()


@pytest.mark.asyncio
async def test_goplus_without_a_record_for_the_address_answered():
    # GoPlus answers code 1 with no entry for wallets and unindexed contracts.
    db = ScamDatabase()
    _chainabuse(db, payload=[])
    response = MagicMock(status=200)
    response.json = AsyncMock(return_value={"code": 1, "result": {}})
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    session.get.return_value.__aexit__ = AsyncMock(return_value=False)
    with patch("utils.scam_db.aiohttp.ClientSession") as http:
        http.return_value.__aenter__ = AsyncMock(return_value=session)
        http.return_value.__aexit__ = AsyncMock(return_value=False)
        matches = await db.check_address(ADDRESS, chain_id=4663)
    assert session.get.call_count == 1
    assert (matches, matches.failed_providers) == ([], ())


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [404, 429, 500, 503])
async def test_chainabuse_non_200_is_a_failed_lookup(status):
    # The client documents no "not found" status: only HTTP 200 carries an answer.
    db = ScamDatabase()
    _chainabuse(db, status=status, payload=[])
    matches = await _lookup(db)
    assert matches == []
    assert matches.failed_providers == (f"ChainAbuse HTTP {status}",)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error, name",
    [
        (
            aiohttp.ClientConnectionError(f"Cannot connect to host {SECRET}"),
            "ClientConnectionError",
        ),
        (asyncio.TimeoutError(), "TimeoutError"),
    ],
)
async def test_chainabuse_exception_is_a_failed_lookup_with_class_only_reason(error, name):
    db = ScamDatabase()
    _chainabuse(db, error=error)
    matches = await _lookup(db)
    assert matches == []
    assert matches.failed_providers == (f"ChainAbuse request failed ({name})",)
    assert SECRET not in repr(matches.failed_providers)


@pytest.mark.asyncio
async def test_chainabuse_malformed_success_body_is_a_failed_lookup():
    db = ScamDatabase()
    _chainabuse(db, payload={"unexpected": "shape"})
    matches = await _lookup(db)
    assert matches.failed_providers == ("ChainAbuse request failed (KeyError)",)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason",
    [
        "GoPlus HTTP 500",
        "GoPlus returned an unsuccessful response",
        "GoPlus request failed (ClientConnectionError)",
    ],
)
async def test_goplus_failure_is_a_failed_lookup(reason):
    db = ScamDatabase()
    _chainabuse(db, payload=[])
    matches = await _lookup(db, goplus={"status": "unknown", "reason": reason, "data": {}})
    assert matches == []
    assert matches.failed_providers == (reason,)


@pytest.mark.asyncio
async def test_matches_found_by_answering_providers_survive_a_failure():
    db = ScamDatabase()
    db.known_scams.add(ADDRESS)
    _chainabuse(db, status=503)
    matches = await _lookup(
        db, goplus={"status": "ok", "reason": None, "data": {"is_honeypot": "1"}}
    )
    assert [match["type"] for match in matches] == ["Local Blacklist", "GoPlus Security"]
    assert matches.failed_providers == ("ChainAbuse HTTP 503",)


@pytest.mark.asyncio
async def test_invalid_address_is_not_a_clean_lookup():
    matches = await ScamDatabase().check_address("0xnot-an-address")
    assert matches == []
    assert matches.failed_providers


def _incomplete(matches=()):
    return ScamMatches(matches, failed_providers=("ChainAbuse HTTP 503",))


async def _scan(mock_web3_client, is_contract, lookup, ai_analyzer=None):
    mock_web3_client.is_contract.return_value = is_contract
    scanner = TransactionScanner(mock_web3_client, ai_analyzer)
    scanner.scam_db.check_address = AsyncMock(return_value=lookup)
    return await scanner.scan_address(ADDRESS)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_contract", [False, True])
async def test_transaction_scanner_incomplete_lookup_without_matches_is_unknown(
    mock_web3_client, is_contract
):
    result = await _scan(mock_web3_client, is_contract, _incomplete())
    assert result["status"] == "unknown"
    assert result["risk_level"] == "unknown"
    assert result["coverage"]["scam_database"] is False
    assert (
        result["coverage_reasons"]["scam_database"] == "scam_database unknown: ChainAbuse HTTP 503"
    )
    assert result["checks"]["scam_database_clean"] is None
    assert result["scam_matches"] == []
    assert type(result["scam_matches"]) is list


@pytest.mark.asyncio
@pytest.mark.parametrize("is_contract", [False, True])
async def test_transaction_scanner_incomplete_lookup_keeps_matches_and_floor(
    mock_web3_client,
    mock_ai_analyzer,
    is_contract,
):
    mock_ai_analyzer.compute_ai_risk_score.return_value = {"risk_score": 0}
    result = await _scan(mock_web3_client, is_contract, _incomplete([SCAM_MATCH]), mock_ai_analyzer)
    assert result["scam_matches"] == [SCAM_MATCH]
    assert type(result["scam_matches"]) is list
    assert result["checks"]["scam_database_clean"] is False
    assert result["status"] == "unknown"
    assert result["coverage"]["scam_database"] is False
    assert (
        result["coverage_reasons"]["scam_database"] == "scam_database unknown: ChainAbuse HTTP 503"
    )
    assert result["risk_score"] >= 40
    assert result["risk_level"] in ("medium", "high")


async def _structural(mock_web3_client, lookup, is_token=True):
    service = ContractService(
        mock_web3_client, MagicMock(check_address=AsyncMock(return_value=lookup))
    )
    with patch("services.contract_service.BSCSCAN_DELAY", 0):
        data = await service.fetch_contract_data(ADDRESS, chain_id=4663)
        structural = await StructuralAnalyzer(service).analyze(
            AnalysisContext(ADDRESS, is_token=is_token)
        )
    return data, structural


def _complete_honeypot():
    return {"is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0}


def _registry_results(structural):
    return [
        structural,
        AnalyzerResult("market", 0.25, 0, data={"liquidity_usd": 200000, "pair_age_hours": 100}),
        AnalyzerResult("behavioral", 0.2, 0, data={"reputation_score": 80}),
        AnalyzerResult("honeypot", 0.15, 0, data=_complete_honeypot()),
    ]


@pytest.mark.asyncio
async def test_contract_service_incomplete_lookup_without_matches_is_unknown(mock_web3_client):
    data, structural = await _structural(mock_web3_client, _incomplete())
    assert data["scam_matches"] == []
    assert type(data["scam_matches"]) is list
    assert data["coverage"] == {"scam_database": False}
    assert data["reason"] == "Scam database unavailable: ChainAbuse HTTP 503"
    assert structural.data["status"] == "unknown"
    direct = RiskEngine().compute_composite_risk(
        data,
        _complete_honeypot(),
        {"liquidity_usd": 200000, "pair_age_hours": 100},
        {"reputation_score": 80},
    )
    registry = RiskEngine().compute_from_results(_registry_results(structural))
    for risk in (direct, registry):
        assert risk["status"] == "unknown"
        assert risk["risk_level"] != "LOW"
        assert risk["coverage"]["structural"] < 1
        assert (
            risk["coverage_reasons"]["structural"]
            == "Scam database unavailable: ChainAbuse HTTP 503"
        )


@pytest.mark.asyncio
async def test_contract_service_incomplete_lookup_keeps_matches_and_floor(mock_web3_client):
    data, structural = await _structural(mock_web3_client, _incomplete([SCAM_MATCH]))
    assert data["scam_matches"] == [SCAM_MATCH]
    assert "Scam DB match (1 sources)" in structural.flags
    risk = RiskEngine().compute_from_results(_registry_results(structural))
    assert risk["status"] == "unknown"
    assert risk["rug_probability"] >= 70
    assert risk["risk_level"] != "LOW"


@pytest.mark.asyncio
async def test_contract_service_scam_and_bytecode_failures_are_both_reported(mock_web3_client):
    mock_web3_client.get_bytecode.return_value = None
    data, structural = await _structural(mock_web3_client, _incomplete())
    assert data["coverage"] == {"scam_database": False, "bytecode": False}
    assert (
        data["reason"]
        == "Scam database unavailable: ChainAbuse HTTP 503; Bytecode scan unavailable"
    )
    assert structural.data["status"] == "unknown"
