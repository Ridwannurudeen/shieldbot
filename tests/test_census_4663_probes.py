"""Offline tests for census provider availability and request accounting."""

import json
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from scripts.census_4663 import probe_blockscout, probe_goplus, probes


TOKEN = "0x" + "12" * 20
OTHER = "0x" + "34" * 20


def mock_session(payloads, status=200):
    responses = []
    for payload in payloads:
        response = MagicMock()
        response.status = status
        response.headers = {"x-credits-remaining": "99980", "set-cookie": "private"}
        response.json = AsyncMock(return_value=payload)
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=False)
        responses.append(response)
    session = MagicMock()
    session.get.side_effect = responses
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


@pytest.mark.asyncio
async def test_goplus_field_accounting_preserves_zero_and_false(tmp_path):
    fields = {
        "is_honeypot": "0",
        "buy_tax": "",
        "sell_tax": None,
        "cannot_sell_all": False,
        "transfer_pausable": 0,
        "holders": [],
    }
    session = mock_session([{"code": 1, "result": {TOKEN: fields}}])
    with (
        patch.object(probe_goplus, "sample_tokens", AsyncMock(return_value=[TOKEN])),
        patch.object(probe_goplus.aiohttp, "ClientSession", return_value=session),
    ):
        result = await probe_goplus.probe(tmp_path, 1)
    record = result["records"][0]
    assert record["http_status"] == 200
    assert record["data_status"] == "available"
    assert record["fields_nonempty"] == [
        "cannot_sell_all",
        "is_honeypot",
        "transfer_pausable",
    ]
    assert result["field_summary"]["is_open_source"] == {"present": 0, "nonempty": 0}
    assert result["field_summary"]["buy_tax"] == {"present": 1, "nonempty": 0}
    assert record["response"]["result"][TOKEN] == fields
    assert result["calls"] == session.get.call_count == 1
    assert record["latency_ms"] >= 0
    assert record["response_headers"] == {"x-credits-remaining": "99980"}
    kwargs = session.get.call_args.kwargs
    assert kwargs["timeout"].total == 30
    assert kwargs["params"] == {"contract_addresses": TOKEN}
    assert kwargs["allow_redirects"] is False
    assert (
        json.loads((tmp_path / "probe_goplus.json").read_text(encoding="utf-8"))
        == result
    )


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"code": 0, "result": {TOKEN: {"is_honeypot": "0"}}},
        {"code": 1, "result": {}},
        {"code": 1, "result": []},
        {"code": 1, "result": {OTHER: {"is_honeypot": "0"}}},
        {"code": 1, "result": {TOKEN: []}},
        {"code": 1, "chain_id": 56, "result": {TOKEN: {"is_honeypot": "0"}}},
    ],
)
@pytest.mark.asyncio
async def test_goplus_missing_malformed_and_wrong_chain_are_unknown(tmp_path, payload):
    session = mock_session([payload])
    with (
        patch.object(probe_goplus, "sample_tokens", AsyncMock(return_value=[TOKEN])),
        patch.object(probe_goplus.aiohttp, "ClientSession", return_value=session),
    ):
        result = await probe_goplus.probe(tmp_path, 1)
    record = result["records"][0]
    assert record["data_status"] == "unknown"
    assert record["fields_present"] == []
    assert record["error"]
    assert all(
        counts == {"present": 0, "nonempty": 0}
        for counts in result["field_summary"].values()
    )


@pytest.mark.asyncio
async def test_goplus_waits_between_calls(tmp_path):
    session = mock_session([{"code": 1, "result": {}}, {"code": 1, "result": {}}])
    with (
        patch.object(
            probe_goplus, "sample_tokens", AsyncMock(return_value=[TOKEN, OTHER])
        ),
        patch.object(probe_goplus.aiohttp, "ClientSession", return_value=session),
        patch.object(probe_goplus.asyncio, "sleep", AsyncMock()) as sleep,
    ):
        result = await probe_goplus.probe(tmp_path, 2)
    sleep.assert_awaited_once_with(1)
    assert result["calls"] == 2


@pytest.mark.asyncio
async def test_http_failure_retains_status_and_unknown(tmp_path):
    session = mock_session(
        [{"code": 1, "result": {TOKEN: {"is_honeypot": "0"}}}], status=429
    )
    with (
        patch.object(probe_goplus, "sample_tokens", AsyncMock(return_value=[TOKEN])),
        patch.object(probe_goplus.aiohttp, "ClientSession", return_value=session),
    ):
        result = await probe_goplus.probe(tmp_path, 1)
    record = result["records"][0]
    assert record["http_status"] == 429
    assert record["error"] == "HTTP 429"
    assert record["data_status"] == "unknown"


@pytest.mark.asyncio
async def test_invalid_json_and_transport_errors_are_accounted():
    session = mock_session([{}])
    session.get.side_effect = None
    invalid = MagicMock()
    invalid.status = 200
    invalid.headers = {}
    invalid.json = AsyncMock(side_effect=ValueError("bad JSON"))
    invalid.__aenter__ = AsyncMock(return_value=invalid)
    invalid.__aexit__ = AsyncMock(return_value=False)
    session.get.return_value = invalid
    record = await probes.request_record(session, TOKEN, probe_goplus.URL)
    assert record["error"] == "Response was not valid JSON"
    assert record["data_status"] == "unknown"
    session.get.side_effect = aiohttp.ClientConnectionError(
        "do not expose this request"
    )
    record = await probes.request_record(session, TOKEN, probe_goplus.URL)
    assert record["error"] == "ClientConnectionError"
    assert record["http_status"] is None
    assert record["data_status"] == "unknown"


def test_blockscout_missing_key_exits_two_without_io(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("BLOCKSCOUT_API_KEY", raising=False)
    with patch.object(probe_blockscout.aiohttp, "ClientSession") as session:
        assert probe_blockscout.main(["--data-dir", str(tmp_path), "--limit", "1"]) == 2
    session.assert_not_called()
    assert capsys.readouterr().err == "BLOCKSCOUT_API_KEY is required\n"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_blockscout_exact_pro_paths_and_fields(tmp_path):
    session = mock_session(
        [
            {"hash": TOKEN, "is_verified": False},
            {"address_hash": TOKEN, "symbol": "CENSUS"},
            {"source_code": "contract Census {}", "abi": []},
        ]
    )
    with (
        patch.object(
            probe_blockscout, "sample_tokens", AsyncMock(return_value=[TOKEN])
        ),
        patch.object(probe_blockscout.aiohttp, "ClientSession", return_value=session),
        patch.object(probe_blockscout.asyncio, "sleep", AsyncMock()),
    ):
        result = await probe_blockscout.probe(tmp_path, 1, "test-key")
    assert result["calls"] == 3
    assert [call.args[0] for call in session.get.call_args_list] == [
        f"https://api.blockscout.com/4663/api/v2/{resource}/{TOKEN}"
        for resource in ("addresses", "tokens", "smart-contracts")
    ]
    assert all(record["data_status"] == "available" for record in result["records"])
    assert "is_verified" in result["records"][0]["fields_nonempty"]
    assert all(
        call.kwargs["headers"] == {"Authorization": "Bearer test-key"}
        for call in session.get.call_args_list
    )
    assert "test-key" not in (tmp_path / "probe_blockscout.json").read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {},
        {"message": "unavailable"},
        {"chain_id": 56, "hash": TOKEN},
        {"hash": OTHER},
    ],
)
@pytest.mark.asyncio
async def test_blockscout_missing_wrong_chain_and_wrong_address_unknown(
    tmp_path, payload
):
    session = mock_session([payload] * 3)
    with (
        patch.object(
            probe_blockscout, "sample_tokens", AsyncMock(return_value=[TOKEN])
        ),
        patch.object(probe_blockscout.aiohttp, "ClientSession", return_value=session),
        patch.object(probe_blockscout.asyncio, "sleep", AsyncMock()),
    ):
        result = await probe_blockscout.probe(tmp_path, 1, "test-key")
    assert all(record["data_status"] == "unknown" for record in result["records"])


@pytest.mark.asyncio
async def test_sample_tokens_deduplicates_excludes_quote_and_sorts(tmp_path):
    census = SimpleNamespace(
        meta={"chain_id": "4663"},
        pools=lambda: [
            {"token0": OTHER, "token1": probes.WETH},
            {"token0": TOKEN, "token1": "0x" + "0" * 40},
            {"token0": TOKEN, "token1": OTHER},
        ],
    )
    with patch.object(probes, "read_snapshot", return_value=nullcontext(census)):
        assert await probes.sample_tokens(tmp_path, 20) == [TOKEN, OTHER]
        assert await probes.sample_tokens(tmp_path, 1) == [TOKEN]


@pytest.mark.parametrize("chain_id", [None, "56", 1])
@pytest.mark.asyncio
async def test_sample_wrong_chain_rejected_before_provider_call(tmp_path, chain_id):
    with (
        patch.object(
            probes,
            "read_snapshot",
            return_value=nullcontext(
                SimpleNamespace(meta={"chain_id": chain_id}, pools=lambda: [])
            ),
        ),
        patch.object(probe_goplus.aiohttp, "ClientSession") as session,
    ):
        with pytest.raises(ValueError, match="chain 4663"):
            await probe_goplus.probe(tmp_path, 1)
    session.assert_not_called()
