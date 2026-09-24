"""The API's side of signature requests from the extension: every signing method is answered on
the signature path, never as a transaction without a target, and a raw eth_sign is always Block
Recommended."""

import re
from types import SimpleNamespace

import pytest

from core import verdicts
from tests.test_consumer_unknowns import assert_unknown_response, consumer_api  # noqa: F401
from tests.test_scan_evidence_api import _stored, evidence_api  # noqa: F401

SIGNING_METHODS = [
    "eth_signTypedData",
    "eth_signTypedData_v1",
    "eth_signTypedData_v3",
    "eth_signTypedData_v4",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("sign_method", SIGNING_METHODS)
async def test_typed_data_that_did_not_arrive_as_an_object_is_an_unknown_signature(
    consumer_api, sign_method
):  # noqa: F811
    # The extension sends MetaMask's legacy list of fields, and typed data it could not parse, without
    # typedData; the request is still a signature, not a transaction to an invalid address.
    api, _ = consumer_api
    req = api.FirewallRequest(to="", sender="0x" + "b" * 40, signMethod=sign_method)
    assert api._is_signature_only_request(req)
    response = await api._build_signature_only_response(req)
    assert_unknown_response(response)


@pytest.mark.asyncio
async def test_eth_sign_is_block_recommended_and_says_it_can_sign_a_transaction(consumer_api):  # noqa: F811
    api, _ = consumer_api
    req = api.FirewallRequest(to="", sender="0x" + "b" * 40, signMethod="eth_sign")
    response = await api._build_signature_only_response(req)
    assert response["classification"] == "BLOCK_RECOMMENDED"
    assert response["risk_score"] >= 71
    assert any("can be a transaction" in signal for signal in response["danger_signals"])
    # Nothing about the hash can be checked, so the verdict stays incomplete.
    assert_unknown_response(response)


@pytest.mark.asyncio
@pytest.mark.parametrize("to", ["", "0x" + "a" * 40], ids=["no-target", "valid-target"])
async def test_eth_sign_is_block_recommended_whatever_its_target(consumer_api, to):  # noqa: F811
    # eth_sign signs a raw hash, not a call to `to`, so a valid `to` does not send it down the
    # transaction path, where the target's cached row or its own scan would answer it without the
    # floor and the signature's verdict would be stored as the target's.
    api, services = consumer_api
    req = api.FirewallRequest(to=to, sender="", signMethod="eth_sign")
    assert api._is_signature_only_request(req)
    trail = {}
    response = await api._firewall_verdict(req, SimpleNamespace(headers={}), trail)
    assert response["classification"] == verdicts.BLOCK_RECOMMENDED
    assert response["risk_score"] >= verdicts.BLIND_SIGN_MIN
    assert response["danger_signals"][0].startswith("eth_sign signs a raw hash")
    assert_unknown_response(response)
    assert trail["target"] == (to or "0x" + "0" * 40)
    services.db.get_contract_score.assert_not_awaited()
    services.db.upsert_contract_score.assert_not_awaited()
    services.registry.run_all.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("sign_method", ["personal_sign", "eth_sign"])
async def test_a_signature_with_typed_data_it_does_not_recognise_is_labelled_by_its_method(consumer_api, sign_method):  # noqa: F811
    # The signature type names the method that was asked for: an eth_sign is not reported as a
    # personal_sign, and its verdict is still the eth_sign floor.
    api, _ = consumer_api
    req = api.FirewallRequest(
        to="", sender="0x" + "b" * 40, signMethod=sign_method,
        typedData={"primaryType": "UnknownType", "message": {}},
    )
    response = await api._build_signature_only_response(req)
    fields = {field["label"]: field["value"] for field in response["calldata_details"]["fields"]}
    assert fields["Signature Type"] == sign_method
    assert response["raw_checks"]["signature"]["sig_type"] == sign_method
    assert response["shield_score"]["threat_type"] == sign_method
    assert response["decoded_action"] == f"{sign_method} signature request"
    assert_unknown_response(response)
    if sign_method == "eth_sign":
        assert response["classification"] == verdicts.BLOCK_RECOMMENDED
        assert response["risk_score"] == verdicts.BLIND_SIGN_MIN


@pytest.mark.asyncio
@pytest.mark.parametrize("sign_method", ["personal_sign", "eth_sign"])
async def test_a_signature_without_a_signer_address_is_accepted_and_judged_as_before(consumer_api, sign_method):  # noqa: F811
    # The extension sends no signer for personal_sign and eth_sign; the request model takes an
    # empty "from" and the verdict does not depend on it.
    api, _ = consumer_api
    req = api.FirewallRequest.model_validate({"to": "", "from": "", "signMethod": sign_method, "chainId": 56})
    assert req.sender == ""
    response = await api._build_signature_only_response(req)
    with_signer = await api._build_signature_only_response(
        api.FirewallRequest(to="", sender="0x" + "b" * 40, signMethod=sign_method)
    )
    assert response["classification"] == with_signer["classification"]
    assert response["risk_score"] == with_signer["risk_score"]
    assert response["status"] == with_signer["status"]


@pytest.mark.parametrize(
    "sign_method, classification",
    [("personal_sign", verdicts.SAFE), ("eth_sign", verdicts.BLOCK_RECOMMENDED)],
)
def test_a_signature_sent_without_its_signer_keeps_its_verdict_and_stores_no_address(
    evidence_api, mock_web3_client, sign_method, classification  # noqa: F811
):
    # The extension sends personal_sign and eth_sign with an empty "from": the verdict, its
    # evidence document and its notes hold no address, and the target is the zero-address fallback.
    _, client, _ = evidence_api
    mock_web3_client.is_valid_address.side_effect = lambda value: bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", value))
    mock_web3_client.to_checksum_address.side_effect = lambda value: value
    response = client.post(
        "/api/firewall",
        json={"to": "", "from": "", "data": "0x", "chainId": 56, "signMethod": sign_method},
    )
    assert response.status_code == 200
    body, stored = _stored(client, response)
    assert body["classification"] == classification
    assert body["notes"] == []
    assert stored["evidence"]["target"] == "0x" + "0" * 40
    if sign_method == "eth_sign":
        assert body["risk_score"] >= verdicts.BLIND_SIGN_MIN
        assert body["danger_signals"][0].startswith("eth_sign signs a raw hash")
