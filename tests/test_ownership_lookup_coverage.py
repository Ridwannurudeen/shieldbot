"""A failed ownership lookup is missing data; a reverting owner() is an answer."""

import io
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests
from web3 import Web3
from web3.exceptions import ContractLogicError, OffchainLookup

from adapters.evm_base import EvmAdapter
from analyzers.structural import StructuralAnalyzer
from core.analyzer import AnalysisContext, AnalyzerResult
from core.extension_formatter import format_extension_alert
from core.risk_engine import RiskEngine
from services.contract_service import ContractService


TEST_KEY = "ownership-lookup-key"
RPC_URL = f"https://rpc.invalid/v2/{TEST_KEY}"
TOKEN = "0x1111111111111111111111111111111111111111"
OWNER = Web3.to_checksum_address("0x" + "0" * 38 + "aa")
UNKNOWN = {"owner": None, "is_renounced": None}
# A contract with code whose non-reverting fallback answers owner() with no data, as WETH9 does.
WETH9_CODE = "0x6060604052361561"


def _word(hex_value):
    return "0x" + hex_value.rjust(64, "0")


def _node(call_reply, status=200, code="0x", calls=None):
    """Patch requests so the installed web3 builds its own result or exception."""

    def post(session, url, data=None, **kwargs):
        request = json.loads(data)
        if calls is not None:
            calls.append((request["method"], request["params"]))
        body = {"jsonrpc": "2.0", "id": request["id"]}
        if request["method"] == "eth_call":
            body.update(call_reply)
        elif request["method"] == "eth_chainId":
            body["result"] = hex(4663)
        elif request["method"] == "eth_getCode":
            body["result"] = code
        else:
            body["result"] = "0x"
        response = requests.Response()
        response.status_code = status
        response.reason = "Node reply"
        response.url = url
        response.encoding = "utf-8"
        response.raw = io.BytesIO(json.dumps(body).encode())
        return response

    return patch.object(requests.Session, "post", post)


async def _lookup(caplog, call_reply, status=200, calls=None):
    adapter = EvmAdapter(4663, "Robinhood Chain", RPC_URL)
    caplog.set_level(logging.DEBUG, logger="adapters.evm_base")
    with (
        _node(call_reply, status, code=WETH9_CODE, calls=calls),
        patch("time.sleep"),
        patch("adapters.evm_base.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await adapter.get_ownership_info(TOKEN)
    assert TEST_KEY not in caplog.text
    return result


@pytest.mark.asyncio
@pytest.mark.parametrize("owner, renounced", [(OWNER, False), ("0x" + "0" * 40, True)])
async def test_successful_lookup_shape_is_unchanged(caplog, owner, renounced):
    result = await _lookup(caplog, {"result": _word(owner[2:].lower())})
    assert result == {"owner": owner, "is_renounced": renounced}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        {"code": -32000, "message": "execution reverted"},
        {"code": 3, "message": "execution reverted", "data": None},
        # Robinhood Chain's exact reply for owner() on a token without one (measured 2026-09-19).
        {"code": 3, "message": "execution reverted", "data": "0x"},
    ],
)
async def test_reverting_owner_is_a_complete_answer(caplog, error):
    result = await _lookup(caplog, {"error": error})
    assert result == UNKNOWN


@pytest.mark.asyncio
async def test_empty_reply_means_there_is_no_owner_function(caplog):
    calls = []
    result = await _lookup(caplog, {"result": "0x"}, calls=calls)
    assert result == UNKNOWN
    owner_calls = [params for method, params in calls if method == "eth_call"]
    # The raw re-read sends exactly the calldata web3 sent for owner().
    assert len(owner_calls) == 2
    assert owner_calls[0][0]["data"] == owner_calls[1][0]["data"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "call_reply",
    [
        {"result": "0x" + "ff" * 32},
        {"result": "0x12345678"},
    ],
)
async def test_non_empty_non_address_output_is_missing_data(caplog, call_reply):
    result = await _lookup(caplog, call_reply)
    assert result == {
        **UNKNOWN,
        "status": "unknown",
        "reason": "Ownership lookup failed (BadFunctionCallOutput)",
    }


@pytest.mark.asyncio
async def test_rate_limit_after_retries_is_missing_data(caplog):
    result = await _lookup(caplog, {"result": "0x"}, status=429)
    assert result == {
        **UNKNOWN,
        "status": "unknown",
        "reason": "Ownership lookup failed (HTTPError)",
    }


@pytest.mark.asyncio
async def test_json_rpc_error_is_missing_data(caplog):
    result = await _lookup(caplog, {"error": {"code": -32602, "message": "invalid argument"}})
    assert result["status"] == "unknown"
    assert result["reason"].startswith("Ownership lookup failed (")
    assert (result["owner"], result["is_renounced"]) == (None, None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error, missing",
    [
        (ContractLogicError("execution reverted", data=None), False),
        (OffchainLookup({"sender": TOKEN, "urls": [], "callData": "0x"}, data="0x556f1830"), True),
        (TimeoutError(), True),
    ],
)
async def test_only_a_revert_counts_as_an_answer(error, missing):
    adapter = EvmAdapter(4663, "Robinhood Chain", RPC_URL)
    adapter.w3 = MagicMock()
    adapter.w3.eth.contract.return_value.functions.owner.return_value.call.side_effect = error
    result = await adapter.get_ownership_info(TOKEN)
    assert (result.get("status") == "unknown") is missing


MINT_AND_PROXY = "0x6080" + "40c10f19" + "3659cfe6"
FAILED = {**UNKNOWN, "status": "unknown", "reason": "Ownership lookup failed (HTTPError)"}
HONEYPOT = {"is_honeypot": False, "can_buy": True, "can_sell": True, "buy_tax": 0, "sell_tax": 0}
MARKET = {"liquidity_usd": 50000, "pair_age_hours": 100, "fdv": 200000, "volume_24h": 2000}
ETHOS = {"reputation_score": 80}


async def _contract_risk(mock_web3_client, ownership):
    mock_web3_client.get_bytecode.return_value = MINT_AND_PROXY
    mock_web3_client.get_ownership_info.return_value = ownership
    scam_db = MagicMock(check_address=AsyncMock(return_value=[]))
    service = ContractService(mock_web3_client, scam_db)
    with patch("services.contract_service.BSCSCAN_DELAY", 0):
        data = await service.fetch_contract_data(TOKEN, chain_id=4663)
        structural = await StructuralAnalyzer(service).analyze(
            AnalysisContext(TOKEN, chain_id=4663)
        )
    direct = RiskEngine().compute_composite_risk(data, HONEYPOT, MARKET, ETHOS)
    registry = RiskEngine().compute_from_results(
        [
            structural,
            AnalyzerResult("market", 0.25, 0, data=MARKET),
            AnalyzerResult("behavioral", 0.2, 0, data=ETHOS),
            AnalyzerResult("honeypot", 0.15, 0, data=HONEYPOT),
        ]
    )
    return data, structural, direct, registry


@pytest.mark.asyncio
async def test_failed_ownership_lookup_is_unknown_and_never_safe(mock_web3_client):
    data, structural, direct, registry = await _contract_risk(mock_web3_client, FAILED)
    assert (data["has_mint"], data["has_proxy"], data["ownership_renounced"]) == (True, True, None)
    assert data["coverage"] == {"ownership_renounced": False}
    assert data["reason"] == "Ownership lookup failed (HTTPError)"
    assert structural.data["status"] == "unknown"
    for risk in (direct, registry):
        assert risk["status"] == "unknown"
        assert risk["coverage"]["structural"] < 1
        assert risk["coverage_reasons"]["structural"] == "Ownership lookup failed (HTTPError)"
        assert risk["risk_level"] != "LOW"
        assert risk["risk_archetype"] not in ("legitimate", "rug_pull")
        alert = format_extension_alert(risk)
        assert alert["risk_classification"] != "SAFE"
        assert alert["status"] == "unknown"
        assert alert["risk_display"].startswith("Unknown")


@pytest.mark.asyncio
async def test_reverting_owner_keeps_ownership_covered(mock_web3_client):
    data, structural, direct, registry = await _contract_risk(mock_web3_client, dict(UNKNOWN))
    assert "coverage" not in data
    assert structural.data["status"] == "ok"
    for risk in (direct, registry):
        assert risk["status"] == "ok"
        assert risk["coverage"]["structural"] == 1


@pytest.mark.asyncio
async def test_ownership_and_bytecode_failures_are_both_reported(mock_web3_client):
    mock_web3_client.get_ownership_info.return_value = FAILED
    mock_web3_client.get_bytecode.return_value = None
    service = ContractService(mock_web3_client, MagicMock(check_address=AsyncMock(return_value=[])))
    with patch("services.contract_service.BSCSCAN_DELAY", 0):
        data = await service.fetch_contract_data(TOKEN, chain_id=4663)
    assert data["coverage"] == {"ownership_renounced": False, "bytecode": False}
    assert data["reason"] == "Ownership lookup failed (HTTPError); Bytecode scan unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "chain_id, token",
    [
        (56, "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"),  # WBNB
        (1, "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),  # WETH
    ],
)
async def test_weth9_shaped_token_scan_stays_ok(mock_web3_client, chain_id, token):
    adapter = EvmAdapter(chain_id, "Wrapped native", RPC_URL)
    mock_web3_client.get_bytecode.return_value = WETH9_CODE

    async def ownership(address, chain_id=56):
        return await adapter.get_ownership_info(address)

    mock_web3_client.get_ownership_info = ownership
    service = ContractService(mock_web3_client, MagicMock(check_address=AsyncMock(return_value=[])))
    with (
        _node({"result": "0x"}, code=WETH9_CODE),
        patch("time.sleep"),
        patch("adapters.evm_base.asyncio.sleep", new_callable=AsyncMock),
        patch("services.contract_service.BSCSCAN_DELAY", 0),
    ):
        data = await service.fetch_contract_data(token, chain_id=chain_id)
        structural = await StructuralAnalyzer(service).analyze(AnalysisContext(token, chain_id=chain_id))
    assert "coverage" not in data
    assert data["ownership_renounced"] is None
    direct = RiskEngine().compute_composite_risk(data, HONEYPOT, MARKET, ETHOS)
    registry = RiskEngine().compute_from_results(
        [
            structural,
            AnalyzerResult("market", 0.25, 0, data=MARKET),
            AnalyzerResult("behavioral", 0.2, 0, data=ETHOS),
            AnalyzerResult("honeypot", 0.15, 0, data=HONEYPOT),
        ]
    )
    for risk in (direct, registry):
        assert risk["status"] == "ok"
        assert risk["coverage"]["structural"] == 1
        assert format_extension_alert(risk)["status"] == "ok"
