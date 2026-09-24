"""The firewall overlay's plain-language rows must describe the chain and the call they show.

These rows ("Sending", "Granting Access", "Recipient", the action label and the asset delta) are
what a user reads before signing, so a wrong gas-token name, a "None" on an approval or a shortened
address is a safety defect, not a cosmetic one.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from eth_abi import encode
from web3 import Web3

from core.analyzer import AnalyzerResult
from core.risk_engine import RiskEngine
from utils.calldata_decoder import CalldataDecoder
from utils.chain_info import CHAIN_INFO, get_native_symbol

DECODER = CalldataDecoder()
SENDER = "0x" + "b" * 40
SPENDER = "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f"
RECIPIENT = "0x8ba1f109551bd432803012645ac136ddd64dba72"
HALF = hex(5 * 10**17)
MAX = 2**256 - 1


def calldata(selector, types, values):
    return "0x" + selector + encode(types, values).hex()


def approve(amount):
    return DECODER.decode(calldata("095ea7b3", ["address", "uint256"], [SPENDER, amount]))


def covered_risk_output():
    return RiskEngine().compute_from_results(
        [
            AnalyzerResult(
                "structural",
                0.5,
                0,
                data={
                    "is_contract": True,
                    "is_verified": True,
                    "contract_age_days": 100,
                },
            ),
            AnalyzerResult(
                "honeypot",
                0.5,
                0,
                data={
                    "is_honeypot": False,
                    "can_sell": True,
                    "buy_tax": 0,
                    "sell_tax": 0,
                },
            ),
        ]
    )


@pytest.fixture
def labels_api(monkeypatch, mock_web3_client):
    import api

    mock_web3_client.to_checksum_address.side_effect = Web3.to_checksum_address
    mock_web3_client.is_token_contract = AsyncMock(return_value=True)
    services = SimpleNamespace(
        web3_client=mock_web3_client,
        db=SimpleNamespace(
            get_contract_score=AsyncMock(return_value=None),
            get_deployer_risk_summary=AsyncMock(return_value=None),
            upsert_contract_score=AsyncMock(),
        ),
        registry=SimpleNamespace(run_all=AsyncMock(return_value=[])),
        policy_engine=None,
        indexer=None,
        settings=SimpleNamespace(policy_mode="BALANCED"),
    )
    monkeypatch.setattr(api, "container", services)
    monkeypatch.setattr(api, "web3_client", mock_web3_client)
    monkeypatch.setattr(
        api,
        "calldata_decoder",
        SimpleNamespace(
            decode=DECODER.decode,
            is_whitelisted_target=lambda *args, **kwargs: None,
        ),
    )
    monkeypatch.setattr(
        api,
        "risk_engine",
        SimpleNamespace(
            compute_from_results=lambda *args, **kwargs: covered_risk_output(),
        ),
    )
    monkeypatch.setattr(api, "tenderly_simulator", SimpleNamespace(is_enabled=lambda: False))
    monkeypatch.setattr(api, "greenfield_service", None)
    monkeypatch.setattr(api, "ai_analyzer", SimpleNamespace(is_available=lambda: False))
    return api


def test_polygon_gas_token_is_pol():
    assert get_native_symbol(137) == "POL"


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", sorted(CHAIN_INFO))
async def test_native_send_names_the_chain_gas_token(labels_api, chain_id):
    api = labels_api
    symbol = get_native_symbol(chain_id)
    to = "0x" + format(chain_id, "040x")
    response = await api.firewall(
        api.FirewallRequest(to=to, sender=SENDER, value=HALF, data="0x", chainId=chain_id),
        SimpleNamespace(headers={}),
    )
    assert response["transaction_impact"]["sending"] == f"0.5 {symbol}"
    assert response["decoded_action"] == f"Native {symbol} Transfer"
    assert response["asset_delta"] == [f"-0.5 {symbol}"]
    if symbol != "BNB":
        assert "BNB" not in str(
            {key: response[key] for key in ("transaction_impact", "decoded_action", "asset_delta")}
        )


@pytest.mark.parametrize("chain_id", sorted(CHAIN_INFO))
def test_every_response_builder_names_the_chain_gas_token(labels_api, chain_id):
    api = labels_api
    symbol = get_native_symbol(chain_id)
    native = DECODER.decode("0x")
    to = Web3.to_checksum_address(RECIPIENT)
    req = api.FirewallRequest(to=to, sender=SENDER, value=HALF, chainId=chain_id)
    cached = api._build_cached_response(
        {
            "risk_score": 0,
            "risk_level": "LOW",
            "category_scores": {
                "_scan_metadata": {
                    "status": "ok",
                    "coverage": {"honeypot": 1},
                    "coverage_reasons": {},
                }
            },
        },
        native,
        0.5,
        chain_id,
        to_addr=to,
    )
    unverified = api._build_unverified_swap_response(
        req,
        to,
        native,
        "Router",
        0.5,
        "token_path",
        "Token path could not be decoded",
    )
    fallback = api._build_fallback_response(native, {"risk_score": 0}, None, chain_id)
    for response in (cached, unverified):
        assert response["transaction_impact"]["sending"] == f"0.5 {symbol}"
        assert response["asset_delta"] == [f"-0.5 {symbol}"]
    for response in (cached, unverified, fallback):
        assert response["decoded_action"] == f"Native {symbol} Transfer"


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", sorted(CHAIN_INFO))
async def test_router_swap_names_the_chain_gas_token_and_full_router(labels_api, chain_id):
    api = labels_api
    to = Web3.to_checksum_address(RECIPIENT)
    req = api.FirewallRequest(to=to, sender=SENDER, value=HALF, chainId=chain_id)
    path = ["0x" + char * 40 for char in "cd"]
    response = await api._analyze_router_swap(
        req, to, SENDER, {"params": {"path": path}}, "Router", 0.5
    )
    assert response["transaction_impact"]["sending"] == f"0.5 {get_native_symbol(chain_id)}"
    assert response["transaction_impact"]["recipient"] == f"Router ({to})"


@pytest.mark.parametrize(
    "decoded,expected",
    [
        (approve(MAX), "UNLIMITED"),
        (approve(0), "None (amount is 0)"),
        (approve(1234), "Limited approval: 1234 (raw token units)"),
        ({**approve(1234), "formatted_amount": "0.0012 USDT"}, "Limited approval: 0.0012 USDT"),
        (
            DECODER.decode(calldata("39509351", ["address", "uint256"], [SPENDER, 7])),
            "Limited approval: 7 (raw token units)",
        ),
        (
            DECODER.decode(calldata("a22cb465", ["address", "bool"], [SPENDER, True])),
            "ALL tokens in the collection",
        ),
        (
            DECODER.decode(calldata("a22cb465", ["address", "bool"], [SPENDER, False])),
            "None (revokes access)",
        ),
        (
            DECODER.decode(
                calldata(
                    "8fcbaf0c",
                    [
                        "address",
                        "address",
                        "uint256",
                        "uint256",
                        "bool",
                        "uint8",
                        "bytes32",
                        "bytes32",
                    ],
                    [SENDER, SPENDER, 0, 1, True, 27, b"\x00" * 32, b"\x00" * 32],
                )
            ),
            "UNLIMITED",
        ),
        (
            DECODER.decode(
                calldata(
                    "d505accf",
                    ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
                    [SENDER, SPENDER, 5, 1, 27, b"\x00" * 32, b"\x00" * 32],
                )
            ),
            "Limited approval: 5 (raw token units)",
        ),
        (DECODER.decode("0x2b67b570" + "00" * 12 + "11" * 20), "Approval, amount unknown"),
        (DECODER.decode("0x095ea7b3" + "00" * 12 + "11" * 20), "Approval, amount unknown"),
        (DECODER.decode(calldata("a9059cbb", ["address", "uint256"], [RECIPIENT, 5])), "None"),
        (DECODER.decode("0x"), "None"),
        (DECODER.decode("0xdeadbeef" + "00" * 32), "Unknown"),
        ({}, "Unknown"),
    ],
)
def test_granting_access_says_what_the_call_grants(decoded, expected):
    import api

    assert api._granting_access(decoded) == expected
    if decoded.get("is_approval"):
        assert api._build_asset_delta_fallback(decoded, 0, 56) == [f"Access granted: {expected}"]


@pytest.mark.asyncio
async def test_limited_approval_is_labelled_with_its_amount_on_every_path(labels_api):
    api = labels_api
    token = "0x" + "e" * 40
    data = calldata("095ea7b3", ["address", "uint256"], [SPENDER, 1000 * 10**18])
    response = await api.firewall(
        api.FirewallRequest(to=token, sender=SENDER, data=data, chainId=1),
        SimpleNamespace(headers={}),
    )
    assert response["transaction_impact"]["granting_access"] == "Limited approval: 1,000.0000 TT"
    fallback = api._build_fallback_response(approve(1000), {"risk_score": 0}, None, 1)
    assert (
        fallback["transaction_impact"]["granting_access"]
        == "Limited approval: 1000 (raw token units)"
    )
    unlimited = await api.firewall(
        api.FirewallRequest(
            to=token,
            sender=SENDER,
            data=calldata("095ea7b3", ["address", "uint256"], [SPENDER, MAX]),
            chainId=1,
        ),
        SimpleNamespace(headers={}),
    )
    assert unlimited["transaction_impact"]["granting_access"] == "UNLIMITED"


@pytest.mark.asyncio
async def test_recipient_is_the_full_checksummed_address(labels_api):
    api = labels_api
    checksummed = Web3.to_checksum_address(RECIPIENT)
    response = await api.firewall(
        api.FirewallRequest(to=RECIPIENT, sender=SENDER, value=HALF, chainId=56),
        SimpleNamespace(headers={}),
    )
    assert response["transaction_impact"]["recipient"] == checksummed
    cached = api._build_cached_response(
        {
            "risk_score": 0,
            "risk_level": "LOW",
            "category_scores": {
                "_scan_metadata": {
                    "status": "ok",
                    "coverage": {"honeypot": 1},
                    "coverage_reasons": {},
                }
            },
        },
        {},
        0,
        56,
        to_addr=checksummed,
    )
    assert cached["transaction_impact"]["recipient"] == checksummed
    req = api.FirewallRequest(to=checksummed, sender=SENDER, chainId=56)
    unverified = api._build_unverified_swap_response(
        req, checksummed, {}, "Router", 0, "token_path", "Unreadable"
    )
    assert unverified["transaction_impact"]["recipient"] == f"Router ({checksummed})"


def test_transfer_recipient_and_approval_spender_are_never_shortened(labels_api):
    api = labels_api
    checksummed = Web3.to_checksum_address(RECIPIENT)
    transfer = DECODER.decode(calldata("a9059cbb", ["address", "uint256"], [RECIPIENT, 5]))
    fields = {
        field["label"]: field["value"] for field in api._build_calldata_details(transfer)["fields"]
    }
    assert fields["To"] == checksummed
    assert api._format_decoded_action(transfer, 56) == f"Token Transfer to {checksummed}"
    moved = DECODER.decode(
        calldata("23b872dd", ["address", "address", "uint256"], [SENDER, RECIPIENT, 5])
    )
    fields = {
        field["label"]: field["value"] for field in api._build_calldata_details(moved)["fields"]
    }
    assert fields["To"] == checksummed
    spender = Web3.to_checksum_address(SPENDER)
    fields = {
        field["label"]: field["value"] for field in api._build_calldata_details(approve(5))["fields"]
    }
    assert fields["Spender"] == spender
    assert api._format_decoded_action(approve(5), 56) == f"Token Approval to {spender}"


@pytest.mark.asyncio
async def test_signature_recipient_is_the_full_checksummed_address(labels_api):
    api = labels_api
    response = await api._build_signature_only_response(
        api.FirewallRequest(
            to="",
            sender=SENDER,
            signMethod="eth_signTypedData_v4",
            typedData={
                "primaryType": "Permit",
                "message": {"spender": SPENDER, "value": "1", "deadline": "1"},
            },
        )
    )
    assert response["transaction_impact"]["recipient"] == Web3.to_checksum_address(SPENDER)
