"""Tests for BaseAttestationService — reads ShieldBot attestations from EAS on Base."""

from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from eth_abi import encode

from services.base_attestation_service import BaseAttestationService, RISK_LABELS, _decode_attestation_data


def _encoded(scanned: str, risk: int, scan_type: str, chain: int, evidence_hash: bytes, uri: str) -> str:
    raw = encode(
        ["address", "uint8", "string", "uint64", "bytes32", "string"],
        [scanned, risk, scan_type, chain, evidence_hash, uri],
    )
    return "0x" + raw.hex()


def test_disabled_when_no_address():
    s = BaseAttestationService(attestor_address="")
    assert not s.is_available()


def test_available_when_address_set():
    s = BaseAttestationService(attestor_address="0x" + "11" * 20, schema_uid="0x" + "11" * 32)
    assert s.is_available()


def test_decode_attestation_data_roundtrip():
    addr = "0x" + "ab" * 20
    data_hex = _encoded(addr, 5, "contract", 56, b"\xaa" * 32, "ipfs://Qm...")
    decoded = _decode_attestation_data(data_hex)
    assert decoded is not None
    assert decoded["scanned_address"].lower() == addr
    assert decoded["risk_level"] == 5
    assert decoded["risk_label"] == "DANGER"
    assert decoded["scan_type"] == "contract"
    assert decoded["source_chain_id"] == 56
    assert decoded["evidence_uri"] == "ipfs://Qm..."


def test_decode_returns_none_on_garbage():
    assert _decode_attestation_data("") is None
    assert _decode_attestation_data("0xdeadbeef") is None
    assert _decode_attestation_data("not-hex") is None


def test_risk_labels_complete():
    assert RISK_LABELS == {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "SAFE", 4: "WARNING", 5: "DANGER"}


@pytest.mark.asyncio
async def test_get_recent_empty_when_disabled():
    s = BaseAttestationService(attestor_address="")
    assert await s.get_recent() == []


def _mock_session(payload: dict):
    mock_resp = MagicMock()
    mock_resp.json = AsyncMock(return_value=payload)
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)
    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    return mock_session


@pytest.mark.asyncio
async def test_get_recent_decodes_results():
    addr = "0x" + "ab" * 20
    data1 = _encoded(addr, 5, "contract", 56, b"\xaa" * 32, "ipfs://1")
    data2 = _encoded(addr, 2, "token", 8453, b"\xbb" * 32, "ipfs://2")
    schema = "0x" + "11" * 32
    payload = {
        "data": {
            "attestations": [
                {"id": "0xuid1", "attester": "0xatt", "recipient": addr, "time": 1000, "txid": "0xtx1", "data": data1, "schemaId": schema},
                {"id": "0xuid2", "attester": "0xatt", "recipient": addr, "time": 999, "txid": "0xtx2", "data": data2, "schemaId": schema},
            ]
        }
    }

    s = BaseAttestationService(attestor_address="0x" + "11" * 20, schema_uid=schema)
    with patch("services.base_attestation_service.aiohttp.ClientSession", return_value=_mock_session(payload)):
        results = await s.get_recent()

    assert len(results) == 2
    assert results[0]["uid"] == "0xuid1"
    assert results[0]["risk_level"] == 5
    assert results[0]["risk_label"] == "DANGER"
    assert results[0]["source_chain_id"] == 56
    assert results[1]["risk_level"] == 2
    assert results[1]["source_chain_id"] == 8453


@pytest.mark.asyncio
async def test_get_recent_drops_attestations_with_wrong_schema():
    addr = "0x" + "ab" * 20
    data = _encoded(addr, 5, "contract", 56, b"\xaa" * 32, "ipfs://1")
    expected = "0x" + "aa" * 32
    other = "0x" + "bb" * 32
    payload = {
        "data": {
            "attestations": [
                {"id": "0xgood", "attester": "0xatt", "recipient": addr, "time": 1, "txid": "0xt", "data": data, "schemaId": expected},
                {"id": "0xbad",  "attester": "0xatt", "recipient": addr, "time": 1, "txid": "0xt", "data": data, "schemaId": other},
            ]
        }
    }
    s = BaseAttestationService(attestor_address="0x" + "11" * 20, schema_uid=expected)
    with patch("services.base_attestation_service.aiohttp.ClientSession", return_value=_mock_session(payload)):
        results = await s.get_recent()
    assert [r["uid"] for r in results] == ["0xgood"]


def test_attestor_address_is_checksum():
    s = BaseAttestationService(attestor_address="0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
    # Web3.to_checksum_address mixes case. Confirm we don't lower-case it.
    assert s.attestor_address.startswith("0x")
    assert s.attestor_address != s.attestor_address.lower()


@pytest.mark.asyncio
async def test_get_recent_skips_undecodable():
    payload = {
        "data": {
            "attestations": [
                {"id": "0xbad", "attester": "0xatt", "recipient": "0xr", "time": 1, "txid": "0xt", "data": "0xdeadbeef", "schemaId": "0x" + "11" * 32},
            ]
        }
    }
    s = BaseAttestationService(attestor_address="0x" + "11" * 20, schema_uid="0x" + "11" * 32)
    with patch("services.base_attestation_service.aiohttp.ClientSession", return_value=_mock_session(payload)):
        results = await s.get_recent()
    assert results == []


@pytest.mark.asyncio
async def test_get_recent_empty_on_graphql_error():
    payload = {"errors": [{"message": "schema not found"}]}
    s = BaseAttestationService(attestor_address="0x" + "11" * 20, schema_uid="0x" + "11" * 32)
    with patch("services.base_attestation_service.aiohttp.ClientSession", return_value=_mock_session(payload)):
        assert await s.get_recent() == []


@pytest.mark.asyncio
async def test_get_recent_empty_on_network_error():
    s = BaseAttestationService(attestor_address="0x" + "11" * 20, schema_uid="0x" + "11" * 32)
    with patch("services.base_attestation_service.aiohttp.ClientSession", side_effect=RuntimeError("network down")):
        assert await s.get_recent() == []


@pytest.mark.asyncio
async def test_get_summary_aggregates():
    addr = "0x" + "ab" * 20
    payload = {
        "data": {
            "attestations": [
                {"id": "1", "attester": "0xatt", "recipient": addr, "time": 3, "txid": "0xt1", "data": _encoded(addr, 5, "contract", 56, b"\x00" * 32, ""), "schemaId": "0x" + "11" * 32},
                {"id": "2", "attester": "0xatt", "recipient": addr, "time": 2, "txid": "0xt2", "data": _encoded(addr, 5, "contract", 56, b"\x00" * 32, ""), "schemaId": "0x" + "11" * 32},
                {"id": "3", "attester": "0xatt", "recipient": addr, "time": 1, "txid": "0xt3", "data": _encoded(addr, 3, "token", 8453, b"\x00" * 32, ""), "schemaId": "0x" + "11" * 32},
            ]
        }
    }
    s = BaseAttestationService(attestor_address="0x" + "11" * 20, schema_uid="0x" + "11" * 32)
    with patch("services.base_attestation_service.aiohttp.ClientSession", return_value=_mock_session(payload)):
        summary = await s.get_summary()

    assert summary["total_recent"] == 3
    assert summary["by_risk"] == {"DANGER": 2, "SAFE": 1}
    assert summary["by_source_chain"] == {56: 2, 8453: 1}
