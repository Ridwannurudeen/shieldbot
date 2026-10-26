"""A scam database provider failure must never read as a clean address."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import utils.scam_db as scam_module
from analyzers.structural import StructuralAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.risk_engine import RiskEngine
from scanner.transaction_scanner import TransactionScanner
from services.contract_service import ContractService
from utils.scam_db import ScamDatabase, ScamMatches


ADDRESS = "0x1111111111111111111111111111111111111111"
SCAM_MATCH = {"type": "Local Blacklist", "reason": "Known scam address", "source": "ShieldBot"}
GOPLUS_OK = {"status": "ok", "reason": None, "data": {"is_honeypot": "0", "is_open_source": "1"}}
# Recorded GoPlus reply for an address it has no token record for (chain 56 router, 2026-09-17).
GOPLUS_NO_RECORD = {"code": 1, "message": "OK", "result": {}}
CREATOR = "0x2222222222222222222222222222222222222222"
GOPLUS_FLAGGED_EOA = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
GOPLUS_FLAGGED_EOA_REPLY = {
    "status": "ok",
    "reason": None,
    "data": {
        "address": GOPLUS_FLAGGED_EOA,
        "data_source": "SlowMist,BlockSec",
        "blacklist_doubt": "1",
        "stealing_attack": "1",
        "sanctioned": "1",
    },
}
BOTCHAIN_ADDRESS_RECORD = {
    "address": ADDRESS,
    "data_source": "",
    "stealing_attack": "0",
    "phishing_activities": "0",
    "sanctioned": "0",
}


@pytest.fixture(autouse=True)
def goplus_cache():
    scam_module._GOPLUS_CACHE.clear()
    scam_module._GOPLUS_ADDRESS_CACHE.clear()
    yield
    scam_module._GOPLUS_CACHE.clear()
    scam_module._GOPLUS_ADDRESS_CACHE.clear()


async def _lookup(db, goplus=GOPLUS_OK):
    with patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock(return_value=goplus)):
        return await db.check_address(ADDRESS, chain_id=4663)


def _goplus_http(payload):
    response = MagicMock(status=200)
    response.json = AsyncMock(return_value=payload)
    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=response)
    session.get.return_value.__aexit__ = AsyncMock(return_value=False)
    http = patch("utils.scam_db.aiohttp.ClientSession")
    return http, session


@pytest.mark.asyncio
async def test_every_provider_answered_without_matches_is_complete():
    matches = await _lookup(ScamDatabase())
    assert matches == []
    assert matches.failed_providers == ()


@pytest.mark.asyncio
async def test_goplus_without_a_record_for_the_address_answered():
    http, session = _goplus_http(GOPLUS_NO_RECORD)
    with http as factory:
        factory.return_value.__aenter__ = AsyncMock(return_value=session)
        factory.return_value.__aexit__ = AsyncMock(return_value=False)
        matches = await ScamDatabase().check_address(ADDRESS, chain_id=4663)
    assert factory.call_count == 1
    assert session.get.call_args.args[0].startswith("https://api.gopluslabs.io/")
    assert (matches, matches.failed_providers) == ([], ())


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
    matches = await _lookup(
        ScamDatabase(), goplus={"status": "unknown", "reason": reason, "data": {}}
    )
    assert matches == []
    assert matches.failed_providers == (reason,)


@pytest.mark.asyncio
async def test_local_blacklist_match_survives_a_goplus_failure():
    db = ScamDatabase()
    db.known_scams[(None, ADDRESS.lower())] = {
        "source": "community", "reports": 3, "expires_at": time.time() + 60,
    }
    matches = await _lookup(
        db, goplus={"status": "unknown", "reason": "GoPlus HTTP 503", "data": {}}
    )
    # Three community reports are griefable, so they are a medium-severity match, never a block.
    assert matches == [{
        "type": "community_reports", "reason": "Reported by 3 users", "source": "ShieldBot",
        "severity": "medium", "reports": 3,
    }]
    assert matches.failed_providers == ("GoPlus HTTP 503",)


@pytest.mark.asyncio
async def test_invalid_address_is_not_a_clean_lookup():
    matches = await ScamDatabase().check_address("0xnot-an-address")
    assert matches == []
    assert matches.failed_providers


@pytest.mark.asyncio
@pytest.mark.parametrize("is_contract", [False, True])
async def test_clean_address_with_goplus_no_record_is_covered(mock_web3_client, is_contract):
    mock_web3_client.is_contract.return_value = is_contract
    http, session = _goplus_http(GOPLUS_NO_RECORD)
    with http as factory:
        factory.return_value.__aenter__ = AsyncMock(return_value=session)
        factory.return_value.__aexit__ = AsyncMock(return_value=False)
        result = await TransactionScanner(mock_web3_client).scan_address(ADDRESS, chain_id=56)
    assert factory.call_count == 1
    assert result["status"] == "ok"
    assert result["coverage"]["scam_database"] is True
    assert "scam_database" not in result["coverage_reasons"]
    assert result["checks"]["scam_database_clean"] is True
    assert result["risk_level"] == "low"


@pytest.mark.asyncio
async def test_contract_service_clean_address_with_goplus_no_record_is_covered(mock_web3_client):
    http, session = _goplus_http(GOPLUS_NO_RECORD)
    service = ContractService(mock_web3_client, ScamDatabase())
    with http as factory, patch("services.contract_service.BSCSCAN_DELAY", 0):
        factory.return_value.__aenter__ = AsyncMock(return_value=session)
        factory.return_value.__aexit__ = AsyncMock(return_value=False)
        structural = await StructuralAnalyzer(service).analyze(
            AnalysisContext(ADDRESS, chain_id=56)
        )
    assert factory.call_count == 1
    assert structural.data["scam_matches"] == []
    assert "scam_database" not in structural.data["coverage"]
    assert structural.data["status"] == "ok"


def _incomplete(matches=()):
    return ScamMatches(matches, failed_providers=("GoPlus HTTP 503",))


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
    assert result["coverage_reasons"]["scam_database"] == "scam_database unknown: GoPlus HTTP 503"
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
    result = await _scan(mock_web3_client, is_contract, _incomplete([SCAM_MATCH]), mock_ai_analyzer)
    assert result["scam_matches"] == [SCAM_MATCH]
    assert type(result["scam_matches"]) is list
    assert result["checks"]["scam_database_clean"] is False
    assert result["status"] == "unknown"
    assert result["coverage"]["scam_database"] is False
    assert result["coverage_reasons"]["scam_database"] == "scam_database unknown: GoPlus HTTP 503"
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


@pytest.mark.asyncio
async def test_botchain_address_labels_answer_coverage_without_token_security(mock_web3_client):
    service = ContractService(mock_web3_client, ScamDatabase())
    with patch.object(
        ScamDatabase, "fetch_address_security",
        new=AsyncMock(return_value={"status": "ok", "reason": None, "data": BOTCHAIN_ADDRESS_RECORD}),
    ), patch("services.contract_service.BSCSCAN_DELAY", 0):
        data = await service.fetch_contract_data(ADDRESS, chain_id=677)
        structural = await StructuralAnalyzer(service).analyze(
            AnalysisContext(ADDRESS, chain_id=677, is_token=True)
        )

    assert data["coverage"] == {"scam_database": True}
    assert data["token_security_unsupported"] is True
    assert structural.data["coverage"]["scam_database"] is True
    assert structural.data["scam_matches"] == []
    assert structural.data["notes"][0] == (
        "Scam check: GoPlus address labels checked for the token. "
        "Creator not available from Blockscout. "
        "GoPlus token security does not cover BOT Chain."
    )
    risk = RiskEngine().compute_from_results([
        structural,
        AnalyzerResult("market", 0.25, 0, data={"liquidity_usd": 200000, "pair_age_hours": 100}),
        AnalyzerResult("behavioral", 0.2, 0, data={"reputation_score": 80}),
        AnalyzerResult("honeypot", 0.15, 0, data=_complete_honeypot()),
    ])
    assert risk["status"] == "ok"
    assert risk["coverage"]["structural"] == 1
    assert risk["risk_level"] in {"LOW", "MEDIUM", "HIGH"}


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
    assert data["reason"] == "Scam database unavailable: GoPlus HTTP 503"
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
            risk["coverage_reasons"]["structural"] == "Scam database unavailable: GoPlus HTTP 503"
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
    assert data["reason"] == "Scam database unavailable: GoPlus HTTP 503; Bytecode scan unavailable"
    assert structural.data["status"] == "unknown"


def _record(**fields):
    return {"status": "ok", "reason": None, "data": {"is_open_source": "1", **fields}}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields, severity, reason",
    [
        ({"is_airdrop_scam": "1"}, "block", "Airdrop scam token"),
        (
            {"fake_token": {"true_token_address": "0x" + "2" * 40, "value": 1}},
            "block",
            "Counterfeit of a mainstream token",
        ),
        ({"fake_token": {"value": "1"}}, "block", "Counterfeit of a mainstream token"),
        ({"is_honeypot": "1"}, "high", "Honeypot (GoPlus)"),
        ({"cannot_sell_all": "1"}, "high", "Cannot sell all tokens"),
        ({"owner_change_balance": "1"}, "high", "Owner can change balance"),
        (
            {"is_airdrop_scam": "1", "is_honeypot": "1"},
            "block",
            "Airdrop scam token; Honeypot (GoPlus)",
        ),
    ],
)
async def test_goplus_match_severity(fields, severity, reason):
    matches = await _lookup(ScamDatabase(), goplus=_record(**fields))
    assert matches == [
        {"type": "GoPlus Security", "reason": reason, "source": "gopluslabs.io", "severity": severity}
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [
        {"is_open_source": "0"},
        # A blacklist function is an owner power the structural analyzer scores, not a scam finding:
        # USDT on Ethereum has one (GoPlus is_blacklisted "1", probed 2026-09-24).
        {"is_blacklisted": "1"},
        # GoPlus sets it on Binance-Peg Dogecoin (probed 2026-09-24): a fact about the deployer.
        {"honeypot_with_same_creator": "1"},
        {"fake_token": {"true_token_address": "", "value": 0}},
        {"is_airdrop_scam": "0", "is_blacklisted": "0", "is_honeypot": "0"},
        {},
    ],
)
async def test_goplus_fields_that_are_not_scam_matches(fields):
    matches = await _lookup(ScamDatabase(), goplus=_record(**fields))
    assert (matches, matches.failed_providers) == ([], ())


async def _fill(mock_web3_client, explorer, goplus):
    mock_web3_client.is_verified_contract.return_value = (explorer, None)
    service = ContractService(mock_web3_client, ScamDatabase())
    with patch.object(ScamDatabase, "fetch_token_security", new=AsyncMock(return_value=goplus)), patch(
        "services.contract_service.BSCSCAN_DELAY", 0
    ):
        return await service.fetch_contract_data(ADDRESS, chain_id=4663)


@pytest.mark.asyncio
@pytest.mark.parametrize("open_source, verified", [("1", True), ("0", False)])
async def test_goplus_fills_verification_only_when_the_explorer_did_not_answer(
    mock_web3_client, open_source, verified
):
    data = await _fill(mock_web3_client, None, _record(is_open_source=open_source))
    assert data["is_verified"] is verified
    assert data["field_providers"] == {"is_verified": "goplus"}
    assert data["scam_matches"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("explorer", [True, False])
async def test_explorer_verification_answer_is_kept(mock_web3_client, explorer):
    data = await _fill(mock_web3_client, explorer, _record(is_open_source="1" if not explorer else "0"))
    assert data["is_verified"] is explorer
    assert "field_providers" not in data


@pytest.mark.asyncio
async def test_goplus_record_rides_with_the_matches():
    matches = await _lookup(ScamDatabase(), goplus=_record(is_blacklisted="1"))
    assert matches.goplus_record == {"is_open_source": "1", "is_blacklisted": "1"}
    failed = await _lookup(ScamDatabase(), goplus={"status": "unknown", "reason": "GoPlus HTTP 503", "data": {}})
    assert failed.goplus_record == {}


@pytest.mark.asyncio
async def test_goplus_blacklist_function_becomes_the_structural_owner_power(mock_web3_client):
    data = await _fill(mock_web3_client, True, _record(is_blacklisted="1"))
    assert data["scam_matches"] == []
    assert data["has_blacklist"] is True
    assert data["field_providers"] == {"has_blacklist": "goplus"}


@pytest.mark.asyncio
async def test_bytecode_blacklist_finding_needs_no_goplus_provider(mock_web3_client):
    mock_web3_client.get_bytecode.return_value = "0x6344337ea1"
    data = await _fill(mock_web3_client, True, _record(is_blacklisted="1"))
    assert data["has_blacklist"] is True
    assert "field_providers" not in data


@pytest.mark.asyncio
async def test_contract_service_reads_goplus_through_the_injected_scam_database(mock_web3_client):
    mock_web3_client.is_verified_contract.return_value = (None, None)
    scam_db = MagicMock(check_address=AsyncMock(
        return_value=ScamMatches(goplus_record={"is_open_source": "1", "is_blacklisted": "1"})
    ))
    direct = AsyncMock()
    with patch.object(ScamDatabase, "fetch_token_security", new=direct), patch(
        "services.contract_service.BSCSCAN_DELAY", 0
    ):
        data = await ContractService(mock_web3_client, scam_db).fetch_contract_data(ADDRESS, chain_id=56)
    direct.assert_not_awaited()
    assert (data["is_verified"], data["has_blacklist"]) == (True, True)
    assert data["field_providers"] == {"is_verified": "goplus", "has_blacklist": "goplus"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "goplus",
    [
        {"status": "unknown", "reason": "GoPlus HTTP 429", "data": {}},
        {"status": "ok", "reason": None, "data": {"is_honeypot": "0"}},
    ],
)
async def test_verification_stays_unknown_without_a_goplus_answer(mock_web3_client, goplus):
    data = await _fill(mock_web3_client, None, goplus)
    assert data["is_verified"] is None
    assert "field_providers" not in data


@pytest.mark.asyncio
async def test_botchain_address_label_severity_and_token_record_separation():
    db = ScamDatabase()
    response = {
        "status": "ok", "reason": None,
        "data": {
            "address": ADDRESS, "data_source": "SlowMist",
            "stealing_attack": "1", "phishing_activities": "1",
            "sanctioned": "1", "gas_abuse": "1", "number_of_malicious_contracts_created": "2",
        },
    }
    with patch.object(ScamDatabase, "fetch_address_security", new=AsyncMock(return_value=response)):
        matches = await db.check_address(ADDRESS, chain_id=677)

    assert [match["severity"] for match in matches] == ["block", "high"]
    assert "stealing_attack, phishing_activities" in matches[0]["reason"]
    assert "sanctioned" in matches[1]["reason"]
    assert "number_of_malicious_contracts_created: 2" in matches[1]["reason"]
    assert matches.goplus_record == {}
    assert matches.address_record == response["data"]
    assert matches.address_notes == ("GoPlus address label on token: gas_abuse",)
    assert matches.failed_providers == ()


@pytest.mark.asyncio
async def test_botchain_fake_token_label_is_block_severity():
    response = {
        "status": "ok", "reason": None,
        "data": {"address": ADDRESS, "data_source": "SlowMist", "fake_token": "1"},
    }
    with patch.object(ScamDatabase, "fetch_address_security", new=AsyncMock(return_value=response)):
        matches = await ScamDatabase().check_address(ADDRESS, chain_id=677)
    assert matches[0]["severity"] == "block"
    assert "fake_token" in matches[0]["reason"]


@pytest.mark.asyncio
@pytest.mark.parametrize("data_source", ["", "   "])
async def test_botchain_block_label_without_data_source_is_high(data_source):
    response = {
        "status": "ok", "reason": None,
        "data": {"address": ADDRESS, "data_source": data_source, "stealing_attack": "1"},
    }
    with patch.object(ScamDatabase, "fetch_address_security", new=AsyncMock(return_value=response)):
        matches = await ScamDatabase().check_address(ADDRESS, chain_id=677)
    assert len(matches) == 1
    assert matches[0]["severity"] == "high"
    assert "stealing_attack" in matches[0]["reason"]


@pytest.mark.asyncio
async def test_recorded_goplus_flagged_address_fixture_uses_direct_label_severity():
    with patch.object(
        ScamDatabase, "fetch_address_security",
        new=AsyncMock(return_value=GOPLUS_FLAGGED_EOA_REPLY),
    ):
        matches = await ScamDatabase().check_address(GOPLUS_FLAGGED_EOA, chain_id=677)
    assert [match["severity"] for match in matches] == ["block", "high"]
    assert "stealing_attack" in matches[0]["reason"]
    assert "sanctioned" in matches[1]["reason"]
    assert matches.address_notes == ("GoPlus address label on token: blacklist_doubt",)
    assert matches.goplus_record == {}


@pytest.mark.asyncio
async def test_botchain_address_failure_keeps_local_matches_and_names_source():
    db = ScamDatabase()
    db.known_scams[(677, ADDRESS.lower())] = {
        "source": "admin", "reports": 0, "expires_at": time.time() + 60,
    }
    with patch.object(
        ScamDatabase, "fetch_address_security",
        new=AsyncMock(return_value={"status": "unknown", "reason": "GoPlus HTTP 503", "data": {}}),
    ):
        matches = await db.check_address(ADDRESS, chain_id=677)
    assert matches[0]["type"] == "Local Blacklist"
    assert matches.failed_providers == ("GoPlus address security: GoPlus HTTP 503",)
    assert matches.goplus_record == {}


@pytest.mark.asyncio
async def test_botchain_address_failure_sets_existing_coverage_reason(mock_web3_client):
    service = ContractService(mock_web3_client, ScamDatabase())
    with patch.object(
        ScamDatabase, "fetch_address_security",
        new=AsyncMock(return_value={"status": "unknown", "reason": "GoPlus HTTP 503", "data": {}}),
    ), patch("services.contract_service.BSCSCAN_DELAY", 0):
        data = await service.fetch_contract_data(ADDRESS, chain_id=677)
        structural = await StructuralAnalyzer(service).analyze(
            AnalysisContext(ADDRESS, chain_id=677, is_token=True)
        )
    assert data["coverage"]["scam_database"] is False
    assert data["reason"] == "Scam database unavailable: GoPlus address security: GoPlus HTTP 503"
    assert structural.data["coverage"]["scam_database"] is False
    assert structural.data["token_security_unsupported"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [1, 10, 56, 137, 204, 8453, 42161, 4663])
async def test_other_chains_keep_token_security_lookup(chain_id):
    token = AsyncMock(return_value={
        "status": "ok", "reason": None, "data": {"is_open_source": "1"},
    })
    address = AsyncMock()
    with (
        patch.object(ScamDatabase, "fetch_token_security", new=token),
        patch.object(ScamDatabase, "fetch_address_security", new=address),
    ):
        matches = await ScamDatabase().check_address(ADDRESS, chain_id=chain_id)
    token.assert_awaited_once_with(ADDRESS, chain_id)
    address.assert_not_awaited()
    assert matches.goplus_record == {"is_open_source": "1"}


@pytest.mark.asyncio
async def test_creator_address_is_checked_only_when_creation_lookup_supplies_it(mock_web3_client):
    mock_web3_client.get_contract_creation_info.return_value = {
        "creator": CREATOR, "age_days": 138,
    }
    scam_db = MagicMock(
        check_address=AsyncMock(return_value=ScamMatches()),
        fetch_address_security=AsyncMock(return_value={
            "status": "ok", "reason": None,
            "data": {"address": CREATOR, "data_source": "SlowMist", "phishing_activities": "1"},
        }),
    )
    with patch("services.contract_service.BSCSCAN_DELAY", 0):
        data = await ContractService(mock_web3_client, scam_db).fetch_contract_data(ADDRESS, chain_id=677)
    scam_db.fetch_address_security.assert_awaited_once_with(CREATOR, ledger_chain=677)
    assert data["contract_age_days"] == 138
    assert data["creator_address"] == CREATOR
    assert data["creator_address_labels"]["phishing_activities"] == "1"
    assert data["scam_matches"] == []


@pytest.mark.asyncio
async def test_creator_task_joins_the_creation_lookup_deadline(mock_web3_client):
    import asyncio
    import time

    started = asyncio.Event()
    release = asyncio.Event()
    finished = asyncio.Event()
    mock_web3_client.get_contract_creation_info.return_value = {
        "creator": CREATOR, "age_days": 138,
    }

    async def slow_creator(address, *, ledger_chain):
        started.set()
        await release.wait()
        finished.set()
        return {"status": "ok", "reason": None, "data": {"address": address}}

    scam_db = MagicMock(
        check_address=AsyncMock(return_value=ScamMatches()),
        fetch_address_security=slow_creator,
    )
    with patch("services.contract_service.BSCSCAN_DELAY", 0):
        data = await ContractService(mock_web3_client, scam_db).fetch_contract_data(
            ADDRESS, chain_id=677, deadline=time.monotonic() + 0.55,
        )
    assert started.is_set()
    assert data["contract_age_days"] == 138
    assert data["creator_address_status"] == "unknown"
    assert data["creator_address_pending"] is True
    release.set()
    await finished.wait()


@pytest.mark.asyncio
async def test_creator_address_timeout_keeps_token_check_and_adds_unavailable_note(mock_web3_client):
    import asyncio

    mock_web3_client.get_contract_creation_info.return_value = {
        "creator": CREATOR, "age_days": 138,
    }

    async def hung_creator(address, *, ledger_chain):
        await asyncio.Event().wait()

    scam_db = MagicMock(
        check_address=AsyncMock(return_value=ScamMatches()),
        fetch_address_security=AsyncMock(side_effect=hung_creator),
    )
    service = ContractService(mock_web3_client, scam_db)
    with (
        patch("services.contract_service.GOPLUS_ADDRESS_TIMEOUT_SECONDS", 0.01),
        patch("services.contract_service.BSCSCAN_DELAY", 0),
    ):
        structural = await StructuralAnalyzer(service).analyze(
            AnalysisContext(ADDRESS, chain_id=677, is_token=True)
        )

    assert structural.data["coverage"]["scam_database"] is True
    assert structural.data["token_security_unsupported"] is True
    assert structural.data["creator_address_status"] == "unknown"
    assert any("Creator labels were unavailable." in note for note in structural.data["notes"])
    assert scam_db.fetch_address_security.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "label",
    ["stealing_attack", "phishing_activities", "honeypot_related_address", "number_of_malicious_contracts_created"],
)
async def test_creator_scoring_labels_add_one_bounded_structural_signal(mock_web3_client, label):
    data = {
        "is_contract": True, "is_verified": True, "contract_age_days": 100,
        "coverage": {"scam_database": True}, "creator_address_status": "ok",
        "creator_address": CREATOR,
        "creator_address_labels": {label: "2" if label.startswith("number_") else "1"},
        "scam_matches": [],
    }
    structural = await StructuralAnalyzer(MagicMock(fetch_contract_data=AsyncMock(return_value=data))).analyze(
        AnalysisContext(ADDRESS, chain_id=677, is_token=True)
    )
    assert structural.score == 15
    assert len([flag for flag in structural.flags if flag.startswith("Creator ")]) == 1
    assert structural.data["scam_matches"] == []


@pytest.mark.asyncio
async def test_other_creator_labels_are_notes_without_score(mock_web3_client):
    data = {
        "is_contract": True, "is_verified": True, "contract_age_days": 100,
        "coverage": {"scam_database": True}, "creator_address_status": "ok",
        "creator_address": CREATOR, "creator_address_labels": {"gas_abuse": "1"},
        "scam_matches": [],
    }
    structural = await StructuralAnalyzer(MagicMock(fetch_contract_data=AsyncMock(return_value=data))).analyze(
        AnalysisContext(ADDRESS, chain_id=677, is_token=True)
    )
    assert structural.score == 0
    assert "Creator address label: gas_abuse" in structural.data["notes"]
    assert structural.data["scam_matches"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status, expected",
    [
        (
            "unknown",
            "Scam check: GoPlus address labels checked for the token. "
            "Creator labels were unavailable. GoPlus token security does not cover BOT Chain.",
        ),
        (
            "not_available",
            "Scam check: GoPlus address labels checked for the token. "
            "Creator not available from Blockscout. GoPlus token security does not cover BOT Chain.",
        ),
    ],
)
async def test_botchain_scope_note_names_creator_availability(mock_web3_client, status, expected):
    data = {
        "is_contract": True, "is_verified": True, "contract_age_days": 100,
        "coverage": {"scam_database": True}, "creator_address_status": status,
        "scam_matches": [],
    }
    structural = await StructuralAnalyzer(MagicMock(fetch_contract_data=AsyncMock(return_value=data))).analyze(
        AnalysisContext(ADDRESS, chain_id=677, is_token=True)
    )
    assert structural.data["notes"][0] == expected


@pytest.mark.asyncio
async def test_creator_result_is_used_when_token_address_lookup_failed(mock_web3_client):
    data = {
        "is_contract": True, "is_verified": True, "contract_age_days": 100,
        "coverage": {"scam_database": False},
        "reason": "Scam database unavailable: GoPlus address security: GoPlus HTTP 503",
        "creator_address_status": "ok", "creator_address": CREATOR,
        "creator_address_labels": {"phishing_activities": "1"}, "scam_matches": [],
    }
    structural = await StructuralAnalyzer(
        MagicMock(fetch_contract_data=AsyncMock(return_value=data))
    ).analyze(AnalysisContext(ADDRESS, chain_id=677, is_token=True))
    assert not any(note.startswith("Scam check:") for note in structural.data["notes"])
    assert structural.score == 15
    assert structural.flags == [
        f"Creator {CREATOR} carries GoPlus address labels: phishing_activities"
    ]


@pytest.mark.asyncio
async def test_creator_pending_note_names_the_deadline(mock_web3_client):
    data = {
        "is_contract": True, "is_verified": True, "contract_age_days": 100,
        "coverage": {"scam_database": True}, "creator_address_pending": True,
        "scam_matches": [],
    }
    structural = await StructuralAnalyzer(
        MagicMock(fetch_contract_data=AsyncMock(return_value=data))
    ).analyze(AnalysisContext(ADDRESS, chain_id=677, is_token=True))
    assert "Creator labels not checked before the request deadline" in structural.data["notes"]
