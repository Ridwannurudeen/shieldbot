"""The API's side of signature requests from the extension: every signing method is answered on
the signature path, never as a transaction without a target, and a raw eth_sign is always Block
Recommended."""

import pytest

from tests.test_consumer_unknowns import assert_unknown_response, consumer_api  # noqa: F401

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
