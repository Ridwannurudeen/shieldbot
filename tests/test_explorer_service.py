"""Offline explorer schema and routing regressions."""

from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
import json

import aiohttp
import pytest
from cachetools import TTLCache

from adapters.evm_base import EvmAdapter
from services.explorer_service import ExplorerResult, ExplorerService


ADDRESS = "0x89e5db8b5aa49aa85ac63f691524311aeb649eba"
FUNDER = "0x" + "1" * 40
TX_HASH = "0x" + "a" * 64

# Recorded from keyless Sourcify v2 on 2026-09-13.
# https://docs.sourcify.dev/docs/api/
SOURCIFY_ROUTER = json.loads(
    """{"matchId":"42264481","creationMatch":"match","runtimeMatch":"match","verifiedAt":"2026-07-14T17:52:53Z","match":"match","chainId":"4663","address":"0x89e5DB8B5aA49aA85AC63f691524311AEB649eba"}"""
)
SOURCIFY_FACTORY = json.loads(
    """{"match":null,"creationMatch":null,"runtimeMatch":null,"chainId":"4663","address":"0x8bcEaA40B9AcdfAedF85AdF4FF01F5Ad6517937f"}"""
)
SOURCIFY_DEAD = json.loads(
    """{"match":null,"creationMatch":null,"runtimeMatch":null,"chainId":"4663","address":"0x000000000000000000000000000000000000dEaD"}"""
)

# Schema fixtures, not authenticated live responses:
# https://docs.blockscout.com/api-reference/addresses/retrieve-detailed-information-about-a-specific-address-or-contract
BLOCKSCOUT_ADDRESS = {
    "hash": ADDRESS,
    "is_contract": True,
    "is_verified": True,
    "creator_address_hash": FUNDER,
    "creation_transaction_hash": TX_HASH,
    "creation_status": "success",
}


@pytest.fixture
def http():
    session = MagicMock()
    responses = []

    def enqueue(payload, status=200):
        response = MagicMock(status=status)
        response.json = AsyncMock(return_value=payload)
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=response)
        responses.append(context)
        return response

    session.get.side_effect = responses
    with patch("aiohttp.ClientSession") as client:
        client.return_value.__aenter__.return_value = session
        with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": ""}):
            yield enqueue, session, client


@pytest.mark.asyncio
@pytest.mark.parametrize("match", ["match", "exact_match"])
async def test_sourcify_match_skips_blockscout_and_caches(http, match):
    enqueue, session, _ = http
    enqueue({**SOURCIFY_ROUTER, "match": match, "runtimeMatch": match})
    service = ExplorerService()
    with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}):
        result = await service.get_verification_status(ADDRESS, 4663)
        again = await service.get_verification_status(
            ADDRESS.upper().replace("0X", "0x"), 4663
        )
    assert result.status == "verified"
    assert result.data == {"match": match}
    assert again == result
    session.get.assert_called_once_with(
        f"https://sourcify.dev/server/v2/contract/4663/{ADDRESS}",
        params={},
        allow_redirects=False,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [SOURCIFY_FACTORY, SOURCIFY_DEAD])
async def test_live_sourcify_absence_is_unknown(http, payload):
    enqueue, session, _ = http
    enqueue(payload, 404)
    result = await ExplorerService().get_verification_status(payload["address"], 4663)
    # Sourcify's 404 says the contract is not verified there; without Blockscout's answer the
    # contract's verification is still unknown.
    assert result.status == "unknown"
    assert "Sourcify: not verified" in result.reason and "BLOCKSCOUT_API_KEY" in result.reason
    assert session.get.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {**SOURCIFY_ROUTER, "chainId": "56"},
        {**SOURCIFY_ROUTER, "address": FUNDER},
        {**SOURCIFY_ROUTER, "runtimeMatch": []},
        {**SOURCIFY_ROUTER, "match": None},
    ],
)
async def test_sourcify_malformed_or_wrong_identity_unknown(http, payload):
    http[0](payload)
    assert (
        await ExplorerService().get_verification_status(ADDRESS, 4663)
    ).status == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("verified", [True, False])
async def test_blockscout_fallback_and_shared_address_cache(http, verified):
    enqueue, session, client = http
    enqueue({**SOURCIFY_DEAD, "address": ADDRESS}, 404)
    enqueue({**BLOCKSCOUT_ADDRESS, "is_verified": verified})
    service = ExplorerService()
    with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}):
        result = await service.get_verification_status(ADDRESS, 4663)
        creation = await service.get_contract_creation_info(ADDRESS, 4663)
    assert result.status == ("verified" if verified else "unverified")
    assert creation.data == {"creator": FUNDER, "tx_hash": TX_HASH}
    assert session.get.call_count == 2
    assert session.get.call_args.kwargs["params"] == {"apikey": "test-key"}
    assert (
        session.get.call_args.args[0]
        == f"https://api.blockscout.com/4663/api/v2/addresses/{ADDRESS}"
    )
    assert all(call.kwargs["timeout"].total == 15 for call in client.call_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"is_verified": None},
        {"is_verified": "false"},
        {"is_contract": None},
        {"hash": FUNDER},
    ],
)
async def test_blockscout_missing_verification_evidence_unknown(http, changes):
    http[0]({}, 404)
    http[0]({**BLOCKSCOUT_ADDRESS, **changes})
    with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}):
        result = await ExplorerService().get_verification_status(ADDRESS, 4663)
    assert result.status == "unknown" and result.reason


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["get_contract_creation_info", "get_first_funder"])
async def test_missing_key_creator_and_funder_unknown_without_http(http, method):
    result = await getattr(ExplorerService(), method)(ADDRESS, 4663)
    assert result.status == "unknown" and "BLOCKSCOUT_API_KEY" in result.reason
    http[1].get.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        [],
        {**BLOCKSCOUT_ADDRESS, "creator_address_hash": None},
        {**BLOCKSCOUT_ADDRESS, "creation_transaction_hash": None},
        {**BLOCKSCOUT_ADDRESS, "hash": FUNDER},
        {**BLOCKSCOUT_ADDRESS, "creation_status": "failed"},
    ],
)
async def test_missing_creation_evidence_unknown(http, payload):
    http[0](payload)
    with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}):
        result = await ExplorerService().get_contract_creation_info(ADDRESS, 4663)
    assert result.status == "unknown" and result.data is None and result.reason


@pytest.mark.asyncio
async def test_blockscout_429_backoff_then_success(http):
    http[0]({}, 429)
    http[0](BLOCKSCOUT_ADDRESS)
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch(
            "services.explorer_service.asyncio.sleep", new_callable=AsyncMock
        ) as sleep,
    ):
        result = await ExplorerService().get_contract_creation_info(ADDRESS, 4663)
    assert result.status == "known"
    assert sleep.await_args_list[0].args == (1,)
    assert http[1].get.call_count == 2


@pytest.mark.asyncio
async def test_blockscout_429_retry_budget(http):
    for _ in range(3):
        http[0]({}, 429)
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await ExplorerService().get_contract_creation_info(ADDRESS, 4663)
    assert result.status == "unknown" and result.reason == "HTTP 429"
    assert http[1].get.call_count == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [asyncio.TimeoutError(), ValueError("invalid JSON")])
async def test_request_error_returns_unknown(http, error):
    response = http[0](None)
    response.json.side_effect = error
    with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}):
        result = await ExplorerService().get_contract_creation_info(ADDRESS, 4663)
    assert result.status == "unknown" and result.reason == type(error).__name__


@pytest.mark.asyncio
async def test_blockscout_rate_limit_shared_across_requests(http):
    clock = [10.0]
    starts = []
    for _ in range(7):
        response = http[0](BLOCKSCOUT_ADDRESS)
        response.json.side_effect = lambda: (
            starts.append(clock[0]) or BLOCKSCOUT_ADDRESS
        )

    async def sleep(delay):
        clock[0] += delay

    service = ExplorerService()
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.time.monotonic", side_effect=lambda: clock[0]),
        patch("services.explorer_service.asyncio.sleep", side_effect=sleep),
    ):
        await asyncio.gather(
            *(
                service.get_contract_creation_info("0x" + f"{i:040x}", 4663)
                for i in range(7)
            )
        )
    assert len(starts) == 7
    assert all(b - a >= 0.209 for a, b in zip(starts, starts[1:]))


@pytest.mark.asyncio
async def test_ttl_expiry_and_chain_cache_separation(http):
    clock = [0]
    for chain_id in (4663, 56, 4663):
        http[0]({**SOURCIFY_ROUTER, "chainId": str(chain_id)})
    service = ExplorerService()
    service._cache = TTLCache(maxsize=10, ttl=300, timer=lambda: clock[0])
    await service.get_verification_status(ADDRESS, 4663)
    await service.get_verification_status(ADDRESS, 56)
    clock[0] = 301
    await service.get_verification_status(ADDRESS, 4663)
    assert http[1].get.call_count == 3


def transfer(block=10, internal=False, **changes):
    # https://docs.blockscout.com/api-reference/addresses/list-all-internal-transactions-involving-a-specific-address
    # https://docs.blockscout.com/api-reference/addresses/list-transactions-involving-a-specific-address-with-to-from-filtering
    item = {
        "block_number": block,
        "from": {"hash": FUNDER},
        "to": {"hash": ADDRESS},
        "value": "123",
        "hash": TX_HASH,
    }
    item.update(
        {
            "success": True,
            "type": "call",
            "transaction_index": 0,
            "index": 0,
            "transaction_hash": TX_HASH,
        }
        if internal
        else {"status": "ok", "position": 0}
    )
    return {**item, **changes}


@pytest.mark.asyncio
async def test_funder_earliest_across_both_paginated_histories(http):
    cursor = {"block_number": 20, "transaction_index": 1, "index": 0}
    http[0]({"items": [transfer(15)], "next_page_params": None})
    http[0]({"items": [transfer(20, True)], "next_page_params": cursor})
    http[0]({"items": [transfer(5, True, value="456")], "next_page_params": None})
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.data == {"funder": FUNDER, "value": 456}
    assert http[1].get.call_args.kwargs["params"] == {
        **cursor,
        "filter": "to",
        "apikey": "test-key",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("internal", [False, True])
async def test_funder_incomplete_history_unknown(http, internal):
    if internal:
        http[0]({"items": [transfer()], "next_page_params": None})
    for block in (30, 20, 10):
        http[0](
            {
                "items": [transfer(block, internal)],
                "next_page_params": {"block_number": block, "index": 0},
            }
        )
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.status == "unknown" and "page limit" in result.reason
    assert http[1].get.call_count == (4 if internal else 3)


@pytest.mark.asyncio
async def test_funder_ignores_failed_zero_outgoing_and_self_transfers(http):
    http[0](
        {
            "items": [
                transfer(status="error"),
                transfer(value="0"),
                transfer(to={"hash": FUNDER}),
                transfer(**{"from": {"hash": ADDRESS}}),
            ],
            "next_page_params": None,
        }
    )
    http[0](
        {"items": [transfer(internal=True, success=False)], "next_page_params": None}
    )
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.status == "unknown" and result.data is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"items": [], "next_page_params": {}},
        {"items": [], "next_page_params": {"index": []}},
        {"items": [transfer(value=None)], "next_page_params": None},
        {"items": [transfer(position=None)], "next_page_params": None},
        {"items": [transfer(status=None)], "next_page_params": None},
    ],
)
async def test_funder_missing_evidence_unknown(http, payload):
    http[0](payload)
    with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.status == "unknown" and result.reason


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value", ["1" * 5000, str(2**256)], ids=["oversized", "uint256-overflow"]
)
async def test_funder_out_of_range_value_unknown(http, value):
    http[0]({"items": [transfer(value=value)], "next_page_params": None})
    with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.status == "unknown" and result.reason


def _sourcify_answers(adapter, status="unverified"):
    """Answer the adapter's Sourcify lookup and its clone check without HTTP or RPC."""
    adapter._explorer_service = MagicMock()
    adapter._explorer_service.get_sourcify_verification = AsyncMock(
        return_value=ExplorerResult(status, reason="test")
    )
    adapter.get_bytecode = AsyncMock(return_value="0x6080")
    return adapter


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [56, 8453])
@pytest.mark.parametrize("source", ["", "contract Token {}"])
async def test_existing_etherscan_verification_request_and_result_unchanged(
    http, chain_id, source
):
    http[0]({"status": "1", "result": [{"SourceCode": source}]})
    adapter = _sourcify_answers(EvmAdapter(
        chain_id, "Existing", "https://rpc.invalid", etherscan_api_key="test-key"
    ))
    assert await adapter.is_verified_contract(ADDRESS) == (bool(source), source or None)
    http[1].get.assert_called_once_with(
        "https://api.etherscan.io/v2/api",
        params={
            "chainid": chain_id,
            "module": "contract",
            "action": "getsourcecode",
            "address": ADDRESS,
            "apikey": "test-key",
        },
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,expected", [("verified", True), ("unverified", False), ("unknown", None)]
)
async def test_robinhood_adapter_verification_tuple(http, status, expected):
    adapter = EvmAdapter(4663, "Robinhood Chain", "https://rpc.invalid")
    adapter._explorer_service = MagicMock()
    adapter._explorer_service.get_verification_status = AsyncMock(
        return_value=ExplorerResult(status, reason="test")
    )
    adapter.get_bytecode = AsyncMock(return_value="0x6080")
    assert await adapter.is_verified_contract(ADDRESS) == (expected, None)
    adapter._explorer_service.get_verification_status.assert_awaited_once_with(
        ADDRESS, 4663
    )
    http[1].get.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("rpc_available", [True, False])
async def test_robinhood_adapter_creation_preserves_known_creator(http, rpc_available):
    adapter = EvmAdapter(4663, "Robinhood Chain", "https://rpc.invalid")
    adapter._explorer_service = MagicMock()
    adapter._explorer_service.get_contract_creation_info = AsyncMock(
        return_value=ExplorerResult(
            "known", data={"creator": FUNDER, "tx_hash": TX_HASH}
        )
    )
    adapter._call_with_retry = AsyncMock(
        side_effect=[{"blockNumber": 1}, {"timestamp": 1704067200}]
        if rpc_available
        else RuntimeError("RPC unavailable")
    )
    result = await adapter.get_contract_creation_info(ADDRESS)
    assert result["creator"] == FUNDER and result["tx_hash"] == TX_HASH
    assert (result["creation_time"] is not None) == rpc_available
    assert (result["age_days"] is not None) == rpc_available
    http[1].get.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", [{"status": "0", "result": "NOTOK"}, {}, {"status": "1", "result": []}]
)
async def test_etherscan_missing_verification_is_unknown(payload):
    response = MagicMock(status=200)
    response.json = AsyncMock(return_value=payload)
    session = MagicMock()
    session.get.return_value.__aenter__.return_value = response
    with patch("aiohttp.ClientSession") as client:
        client.return_value.__aenter__.return_value = session
        adapter = _sourcify_answers(EvmAdapter(56, "BSC", "https://rpc.invalid"))
        assert await adapter.is_verified_contract("0x" + "1" * 40) == (None, None)


def test_unknown_explorer_backend_is_rejected():
    with pytest.raises(ValueError, match="Unsupported explorer chain"):
        EvmAdapter(999999, "Unknown", "https://rpc.invalid")


def test_constructor_preserves_unsupported_honeypot_provider():
    adapter = EvmAdapter(
        4663, "Robinhood Chain", "https://rpc.invalid", honeypot_chain_id=None
    )
    assert adapter._honeypot_chain_id is None


@pytest.mark.parametrize("chain_id", [1, 56, 8453, 42161, 137, 10, 204])
def test_constructor_preserves_existing_honeypot_provider(chain_id):
    adapter = EvmAdapter(
        chain_id, "Existing", "https://rpc.invalid", honeypot_chain_id=chain_id
    )
    assert adapter._honeypot_chain_id == chain_id


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [56, 42161])
async def test_existing_etherscan_creation_request_and_result_unchanged(http, chain_id):
    http[0]({"status": "1", "result": [{"contractCreator": FUNDER, "txHash": TX_HASH}]})
    adapter = EvmAdapter(
        chain_id, "Existing", "https://rpc.invalid", etherscan_api_key="test-key"
    )
    adapter._call_with_retry = AsyncMock(
        side_effect=[{"blockNumber": 1}, {"timestamp": 1704067200}]
    )
    result = await adapter.get_contract_creation_info(ADDRESS)
    assert result["creator"] == FUNDER and result["tx_hash"] == TX_HASH
    assert result["creation_time"] == "2024-01-01T00:00:00+00:00"
    assert result["age_days"] >= 0
    http[1].get.assert_called_once_with(
        "https://api.etherscan.io/v2/api",
        params={
            "chainid": chain_id,
            "module": "contract",
            "action": "getcontractcreation",
            "contractaddresses": ADDRESS,
            "apikey": "test-key",
        },
    )


@pytest.mark.asyncio
async def test_robinhood_adapter_missing_creator_skips_rpc(http):
    adapter = EvmAdapter(4663, "Robinhood Chain", "https://rpc.invalid")
    adapter._explorer_service = ExplorerService()
    adapter._call_with_retry = AsyncMock()
    assert await adapter.get_contract_creation_info(ADDRESS) is None
    adapter._call_with_retry.assert_not_awaited()
    http[1].get.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,payload",
    [
        (
            "is_verified_contract",
            {"status": "1", "result": [{"SourceCode": "contract Token {}"}]},
        ),
        (
            "get_contract_creation_info",
            {"status": "1", "result": [{"contractCreator": FUNDER, "txHash": TX_HASH}]},
        ),
    ],
)
async def test_etherscan_http_error_does_not_produce_evidence(http, method, payload):
    http[0](payload, 500)
    adapter = _sourcify_answers(EvmAdapter(56, "BSC", "https://rpc.invalid"))
    adapter._call_with_retry = AsyncMock()
    result = await getattr(adapter, method)(ADDRESS)
    assert result == ((None, None) if method == "is_verified_contract" else None)
    adapter._call_with_retry.assert_not_awaited()


@pytest.mark.asyncio
async def test_funder_orders_transactions_and_internal_calls_within_same_block(http):
    http[0]({"items": [transfer(10, position=2)], "next_page_params": None})
    http[0](
        {
            "items": [
                transfer(10, True, transaction_index=1, index=2, value="222"),
                transfer(10, True, transaction_index=1, index=1, value="111"),
            ],
            "next_page_params": None,
        }
    )
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.data == {"funder": FUNDER, "value": 111}


@pytest.mark.asyncio
@pytest.mark.parametrize("call_type", ["delegatecall", "callcode", "staticcall"])
async def test_funder_excludes_non_transfer_internal_call_types(http, call_type):
    http[0]({"items": [], "next_page_params": None})
    http[0](
        {
            "items": [
                transfer(1, True, type=call_type),
                transfer(2, True, value="456"),
            ],
            "next_page_params": None,
        }
    )
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.status == "known"
    assert result.data == {"funder": FUNDER, "value": 456}


@pytest.mark.asyncio
@pytest.mark.parametrize("call_type", [None, "unrecognised", 1])
async def test_funder_unknown_internal_type_cannot_prove_earliest_funding(
    http, call_type
):
    record = transfer(1, True, type=call_type)
    if call_type is None:
        del record["type"]
    http[0]({"items": [transfer(2, value="456")], "next_page_params": None})
    http[0]({"items": [record], "next_page_params": None})
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.status == "unknown"
    assert result.data is None
    assert "type" in result.reason


@pytest.mark.asyncio
async def test_blockscout_cache_does_not_retain_api_key(http):
    http[0](BLOCKSCOUT_ADDRESS)
    service = ExplorerService()
    test_key = "cache-regression-key-material"
    with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": test_key}):
        result = await service.get_contract_creation_info(ADDRESS, 4663)
    assert result.status == "known"
    assert test_key not in repr(list(service._cache.items()))
    assert "apikey" not in repr(list(service._cache.keys()))
    assert test_key not in repr(result)
    assert http[1].get.call_args.kwargs["params"]["apikey"] == test_key
    with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "replacement-test-key"}):
        assert await service.get_contract_creation_info(ADDRESS, 4663) == result
    assert http[1].get.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("call_type", ["create", "create2"])
async def test_funder_creation_uses_created_contract_recipient(http, call_type):
    http[0]({"items": [], "next_page_params": None})
    http[0](
        {
            "items": [
                transfer(
                    1, True, type=call_type, to=None, created_contract={"hash": ADDRESS}
                )
            ],
            "next_page_params": None,
        }
    )
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.status == "known"
    assert result.data == {"funder": FUNDER, "value": 123}


@pytest.mark.asyncio
@pytest.mark.parametrize("call_type", ["create", "create2"])
async def test_funder_creation_does_not_use_to_field(http, call_type):
    http[0]({"items": [transfer(2, value="456")], "next_page_params": None})
    http[0](
        {
            "items": [
                transfer(1, True, type=call_type, created_contract={"hash": FUNDER})
            ],
            "next_page_params": None,
        }
    )
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.data == {"funder": FUNDER, "value": 456}


@pytest.mark.asyncio
async def test_funder_creation_missing_recipient_is_unknown(http):
    http[0]({"items": [], "next_page_params": None})
    http[0]({"items": [transfer(1, True, type="create")], "next_page_params": None})
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.status == "unknown"


@pytest.mark.asyncio
async def test_funder_selfdestruct_uses_to_recipient(http):
    http[0]({"items": [], "next_page_params": None})
    http[0](
        {"items": [transfer(1, True, type="selfdestruct")], "next_page_params": None}
    )
    with (
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
        patch("services.explorer_service.asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await ExplorerService().get_first_funder(ADDRESS, 4663)
    assert result.data == {"funder": FUNDER, "value": 123}


@pytest.mark.asyncio
async def test_blockscout_echoed_api_key_is_removed_before_caching(http):
    test_key = "echoed-provider-test-key"
    payload = {
        **BLOCKSCOUT_ADDRESS,
        "apikey": test_key,
        "metadata": [
            {"echo": test_key, "request_url": f"https://api.invalid/?apikey={test_key}"}
        ],
        test_key: {"nested": [None, 7, False, test_key]},
    }
    http[0](payload)
    service = ExplorerService()
    with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": test_key}):
        result = await service.get_contract_creation_info(ADDRESS, 4663)
        assert await service.get_contract_creation_info(ADDRESS, 4663) == result
    assert result.data == {"creator": FUNDER, "tx_hash": TX_HASH}
    assert test_key not in repr(list(service._cache.items()))
    assert test_key not in repr(result)
    assert payload["apikey"] == test_key
    assert http[1].get.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,chain_id",
    [
        ("is_verified_contract", 56),
        ("get_contract_creation_info", 56),
        ("get_contract_creation_info", 4663),
    ],
)
async def test_adapter_explorer_exception_logs_do_not_expose_api_key(
    http, caplog, method, chain_id
):
    test_key = "exception-log-test-key"
    error = aiohttp.ClientResponseError(
        MagicMock(real_url=f"https://api.etherscan.io/v2/api?apikey={test_key}"),
        (),
        status=403,
        message=f"provider echoed {test_key}",
    )
    adapter = EvmAdapter(
        chain_id, "Test Chain", "https://rpc.invalid", etherscan_api_key=test_key
    )
    if chain_id == 4663:
        adapter._explorer_service = MagicMock()
        adapter._explorer_service.get_contract_creation_info = AsyncMock(
            side_effect=error
        )
    else:
        http[0]({}).json.side_effect = error
        _sourcify_answers(adapter)
    result = await getattr(adapter, method)(ADDRESS)
    assert result == ((None, None) if method == "is_verified_contract" else None)
    assert "ClientResponseError" in caplog.text
    assert test_key not in caplog.text
    assert "https://api.etherscan.io" not in caplog.text


@pytest.mark.asyncio
async def test_adapter_creation_time_exception_log_does_not_expose_key(http, caplog):
    test_key = "creation-time-test-key"
    adapter = EvmAdapter(4663, "Robinhood Chain", "https://rpc.invalid")
    adapter._explorer_service = MagicMock()
    adapter._explorer_service.get_contract_creation_info = AsyncMock(
        return_value=ExplorerResult(
            "known", data={"creator": FUNDER, "tx_hash": TX_HASH}
        )
    )
    adapter._call_with_retry = AsyncMock(
        side_effect=RuntimeError(f"https://rpc.invalid/?apikey={test_key}")
    )
    result = await adapter.get_contract_creation_info(ADDRESS)
    assert result["creation_time"] is None
    assert "RuntimeError" in caplog.text
    assert test_key not in caplog.text
