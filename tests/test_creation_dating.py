"""A contract is dated from its explorer's own timestamp or from its creation block's header, and
from the creation transaction only when the explorer named neither.

Every node keeps every header, but old transactions are not indexed everywhere (Geth indexes
about a year of them by default), so reading WETH's and USDC's 2017/2018 creation transactions
on Ethereum flapped between dated and Unknown. Where Etherscan refuses the lookup (its free tier
refuses getcontractcreation on BNB Chain, which no public Blockscout serves), Sourcify's deployment
record dates a contract verified there from one header read; a contract Sourcify does not know
stays Unknown.
"""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
import requests
from web3.exceptions import TransactionNotFound

from adapters.evm_base import EvmAdapter
from core.circuit_breaker import FAILURE_THRESHOLD, OPEN, provider_breakers
from services.explorer_service import ExplorerService

ADDRESS = "0x" + "ab" * 20
CREATOR = "0x" + "1" * 40
TX_HASH = "0x" + "a" * 64
ETHERSCAN_URL = "https://api.etherscan.io/v2/api"

# The getcontractcreation sample reply in Etherscan's docs (USDT on Ethereum, block 4634748):
# https://docs.etherscan.io/api-reference/endpoint/getcontractcreation
TIMESTAMPED = {
    "status": "1",
    "message": "OK",
    "result": [
        {
            "contractAddress": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "contractCreator": CREATOR,
            "txHash": TX_HASH,
            "blockNumber": "4634748",
            "timestamp": "1511829681",
            "contractFactory": "",
            "creationBytecode": "0x6060",
        }
    ],
}
USDT_CREATED = "2017-11-28T00:41:21+00:00"
REFUSED = {
    "status": "0",
    "message": "NOTOK",
    "result": "Free API access is not supported for this chain",
}
# GET https://sourcify.dev/server/v2/contract/56/{CAKE}?fields=deployment, recorded keyless on
# 2026-09-26 (chain, address, block and transaction); the deployer, index and dates are synthetic.
CAKE = "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82"
CAKE_TX = "0x" + "7dd36f3b6d38f8a6b2f2fb0c850a75d57114a1b2fdcd350eaeee609cf3d827ae"
SOURCIFY_CAKE = {
    "matchId": "1",
    "creationMatch": "exact_match",
    "runtimeMatch": "exact_match",
    "verifiedAt": "2021-01-01T00:00:00Z",
    "match": "exact_match",
    "chainId": "56",
    "address": CAKE,
    "deployment": {
        "transactionHash": CAKE_TX,
        "blockNumber": "693963",
        "transactionIndex": "0",
        "deployer": CREATOR,
    },
}
CAKE_CREATED = "2020-09-22T05:47:49+00:00"


def _not_verified(address):
    # Sourcify v2's 404 body for an address with no verified contract.
    return {
        "match": None,
        "creationMatch": None,
        "runtimeMatch": None,
        "chainId": "56",
        "address": address,
    }


def _reply(result_fields):
    return {
        "status": "1",
        "message": "OK",
        "result": [{"contractCreator": CREATOR, "txHash": TX_HASH, **result_fields}],
    }


@pytest.fixture
def http():
    """Successive GETs from any aiohttp session, Etherscan's and Sourcify's alike, get the queued
    replies: (status, body), or an exception raised before any reply."""
    session = MagicMock()
    replies = []

    def enqueue(body, status=200):
        context = MagicMock()
        if isinstance(body, Exception):
            context.__aenter__ = AsyncMock(side_effect=body)
        else:
            response = MagicMock(status=status)
            response.json = AsyncMock(return_value=body)
            context.__aenter__ = AsyncMock(return_value=response)
        replies.append(context)

    session.get.side_effect = replies
    with patch("aiohttp.ClientSession") as client:
        client.return_value.__aenter__.return_value = session
        yield enqueue, session


def _adapter(chain_id=1, name="Ethereum"):
    adapter = EvmAdapter(chain_id, name, "https://rpc.invalid", etherscan_api_key="test-key")
    adapter._explorer_service = ExplorerService()
    adapter.w3 = MagicMock()
    return adapter


@pytest.mark.asyncio
async def test_a_timestamped_reply_dates_the_contract_without_an_rpc_read(http):
    enqueue, session = http
    enqueue(TIMESTAMPED)
    adapter = _adapter()
    result = await adapter.get_contract_creation_info(ADDRESS)
    assert result == {
        "tx_hash": TX_HASH,
        "creator": CREATOR,
        "creation_time": USDT_CREATED,
        "age_days": result["age_days"],
    }
    assert result["age_days"] > 3000
    adapter.w3.eth.get_transaction.assert_not_called()
    adapter.w3.eth.get_block.assert_not_called()
    assert session.get.call_count == 1
    assert session.get.call_args.args == (ETHERSCAN_URL,)


@pytest.mark.asyncio
async def test_a_reply_naming_only_the_block_reads_its_header_and_never_the_transaction(http):
    enqueue, _ = http
    enqueue(_reply({"blockNumber": "4634748"}))
    adapter = _adapter()
    adapter.w3.eth.get_block.return_value = {"timestamp": 1511829681}
    result = await adapter.get_contract_creation_info(ADDRESS)
    assert result["creation_time"] == USDT_CREATED and result["age_days"] > 3000
    adapter.w3.eth.get_block.assert_called_once_with(4634748)
    adapter.w3.eth.get_transaction.assert_not_called()


@pytest.mark.asyncio
async def test_a_reply_naming_neither_reads_the_transaction_then_its_header(http):
    enqueue, _ = http
    enqueue(_reply({}))
    adapter = _adapter()
    adapter.w3.eth.get_transaction.return_value = {"blockNumber": 4634748}
    adapter.w3.eth.get_block.return_value = {"timestamp": 1511829681}
    result = await adapter.get_contract_creation_info(ADDRESS)
    assert result["creation_time"] == USDT_CREATED
    adapter.w3.eth.get_transaction.assert_called_once_with(TX_HASH)
    adapter.w3.eth.get_block.assert_called_once_with(4634748)


@pytest.mark.asyncio
@pytest.mark.parametrize("timestamp", ["", "0", "soon"], ids=["empty", "zero", "text"])
async def test_an_unusable_timestamp_falls_back_to_the_block(http, timestamp):
    enqueue, _ = http
    enqueue(_reply({"blockNumber": "4634748", "timestamp": timestamp}))
    adapter = _adapter()
    adapter.w3.eth.get_block.return_value = {"timestamp": 1511829681}
    result = await adapter.get_contract_creation_info(ADDRESS)
    assert result["creation_time"] == USDT_CREATED
    adapter.w3.eth.get_block.assert_called_once_with(4634748)


@pytest.mark.asyncio
async def test_a_missing_transaction_no_longer_loses_the_age_when_the_block_is_known(http):
    enqueue, _ = http
    enqueue(_reply({"blockNumber": "4634748"}))
    adapter = _adapter()
    adapter.w3.eth.get_transaction.side_effect = TransactionNotFound(
        f"Transaction with hash: {TX_HASH!r} not found."
    )
    adapter.w3.eth.get_block.return_value = {"timestamp": 1511829681}
    result = await adapter.get_contract_creation_info(ADDRESS)
    assert result["age_days"] > 3000
    adapter.w3.eth.get_transaction.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields, failing",
    [
        ({"blockNumber": "4634748"}, "get_block"),
        ({}, "get_transaction"),
    ],
    ids=["header-read-fails", "transaction-missing"],
)
async def test_a_creation_that_cannot_be_dated_keeps_its_creator_and_is_asked_again(
    http, caplog, fields, failing
):
    enqueue, session = http
    enqueue(_reply(fields))
    enqueue(_reply(fields))
    adapter = _adapter()
    error = (
        TransactionNotFound("not found")
        if failing == "get_transaction"
        else requests.exceptions.ConnectionError()
    )
    getattr(adapter.w3.eth, failing).side_effect = error
    caplog.set_level(logging.WARNING, logger="adapters.evm_base")
    result = await adapter.get_contract_creation_info(ADDRESS)
    assert result == {
        "tx_hash": TX_HASH,
        "creator": CREATOR,
        "creation_time": None,
        "age_days": None,
    }
    assert f"[Ethereum] Creation time unknown: {type(error).__name__}" in caplog.text
    # Undated, so not kept: the next caller asks Etherscan again.
    await adapter.get_contract_creation_info(ADDRESS)
    assert session.get.call_count == 2


@pytest.mark.asyncio
async def test_a_refused_chain_is_dated_from_sourcify_s_deployment_with_one_header_read(
    http, caplog
):
    enqueue, session = http
    enqueue(REFUSED)
    enqueue(SOURCIFY_CAKE)
    adapter = _adapter(56, "BSC")
    adapter.w3.eth.get_block.return_value = {"timestamp": 0x5F699005}
    caplog.set_level(logging.WARNING, logger="adapters.evm_base")
    result = await adapter.get_contract_creation_info(CAKE)
    assert result == {
        "tx_hash": CAKE_TX,
        "creator": CREATOR,
        "creation_time": CAKE_CREATED,
        "age_days": result["age_days"],
    }
    assert result["age_days"] > 2000
    adapter.w3.eth.get_block.assert_called_once_with(693963)
    adapter.w3.eth.get_transaction.assert_not_called()
    assert [call.args[0] for call in session.get.call_args_list] == [
        ETHERSCAN_URL,
        f"https://sourcify.dev/server/v2/contract/56/{CAKE.lower()}",
    ]
    assert session.get.call_args.kwargs["params"] == {"fields": "deployment"}
    # The refusal is logged, so the journal says why an age came from Sourcify; the key is not.
    assert "[BSC] Creation not answered by Etherscan (NOTOK); asking Sourcify" in caplog.text
    assert "test-key" not in caplog.text


@pytest.mark.asyncio
async def test_a_refusal_sent_as_an_http_error_is_asked_of_sourcify_too(http):
    # Whether Etherscan's free tier refuses with a status 0 or with an HTTP error, a contract
    # Sourcify knows is dated.
    enqueue, session = http
    enqueue(REFUSED, status=403)
    enqueue(SOURCIFY_CAKE)
    adapter = _adapter(56, "BSC")
    adapter.w3.eth.get_block.return_value = {"timestamp": 0x5F699005}
    result = await adapter.get_contract_creation_info(CAKE)
    assert result["creation_time"] == CAKE_CREATED
    adapter.w3.eth.get_block.assert_called_once_with(693963)
    assert [call.args[0] for call in session.get.call_args_list] == [
        ETHERSCAN_URL,
        f"https://sourcify.dev/server/v2/contract/56/{CAKE.lower()}",
    ]


@pytest.mark.asyncio
async def test_etherscan_s_refusal_is_logged_once_per_chain(http, caplog):
    # The free tier's refusal is permanent, so repeating it for every BNB Chain lookup would only
    # fill the journal.
    enqueue, session = http
    enqueue(REFUSED)
    enqueue(SOURCIFY_CAKE)
    enqueue(REFUSED)
    enqueue(_not_verified(ADDRESS), status=404)
    adapter = _adapter(56, "BSC")
    adapter.w3.eth.get_block.return_value = {"timestamp": 0x5F699005}
    caplog.set_level(logging.WARNING, logger="adapters.evm_base")
    await adapter.get_contract_creation_info(CAKE)
    await adapter.get_contract_creation_info(ADDRESS)
    assert session.get.call_count == 4
    assert caplog.text.count("Creation not answered by Etherscan") == 1


@pytest.mark.asyncio
async def test_a_contract_sourcify_does_not_know_stays_unknown(http, caplog):
    enqueue, session = http
    enqueue(REFUSED)
    enqueue(_not_verified(ADDRESS), 404)
    adapter = _adapter(56, "BSC")
    caplog.set_level(logging.WARNING, logger="adapters.evm_base")
    assert await adapter.get_contract_creation_info(ADDRESS) is None
    adapter.w3.eth.get_block.assert_not_called()
    adapter.w3.eth.get_transaction.assert_not_called()
    assert session.get.call_count == 2
    assert "[BSC] Creation unknown: Sourcify not verified" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {**SOURCIFY_CAKE, "address": CREATOR},
        {**SOURCIFY_CAKE, "chainId": "1"},
        {key: value for key, value in SOURCIFY_CAKE.items() if key != "deployment"},
        {
            **SOURCIFY_CAKE,
            "deployment": {**SOURCIFY_CAKE["deployment"], "blockNumber": "0x" + "a95cb"},
        },
    ],
    ids=["other-address", "other-chain", "no-deployment", "hex-block"],
)
async def test_a_sourcify_reply_without_the_contract_s_deployment_stays_unknown(http, body):
    enqueue, _ = http
    enqueue(REFUSED)
    enqueue(body)
    adapter = _adapter(56, "BSC")
    assert await adapter.get_contract_creation_info(CAKE) is None
    adapter.w3.eth.get_block.assert_not_called()


@pytest.mark.asyncio
async def test_a_refusal_never_opens_etherscan_s_breaker_and_sourcify_s_guards_the_fallback(http):
    enqueue, session = http
    for _ in range(FAILURE_THRESHOLD):
        enqueue(REFUSED)
        enqueue(aiohttp.ClientConnectionError())
    enqueue(REFUSED)
    adapter = _adapter(56, "BSC")
    for i in range(FAILURE_THRESHOLD + 1):
        assert await adapter.get_contract_creation_info("0x" + f"{i + 1:040x}") is None
    states = provider_breakers.states()
    assert states["sourcify:56"] == OPEN and states["etherscan:56"] != OPEN
    # The last lookup sent Etherscan's request and, with Sourcify's breaker open, nothing more.
    assert session.get.call_count == 2 * FAILURE_THRESHOLD + 1
    adapter.w3.eth.get_block.assert_not_called()


@pytest.mark.asyncio
async def test_concurrent_callers_share_one_lookup_and_a_dated_answer_is_kept(http):
    enqueue, session = http
    enqueue(TIMESTAMPED)
    adapter = _adapter()
    first, second = await asyncio.gather(
        adapter.get_contract_creation_info(ADDRESS), adapter.get_contract_creation_info(ADDRESS)
    )
    third = await adapter.get_contract_creation_info(ADDRESS.upper().replace("0X", "0x"))
    assert first == second == third and first["creation_time"] == USDT_CREATED
    assert session.get.call_count == 1
    assert adapter._creation_inflight == {}


@pytest.mark.asyncio
async def test_a_refused_chain_s_dated_answer_is_kept_by_both_caches(http):
    enqueue, session = http
    enqueue(REFUSED)
    enqueue(SOURCIFY_CAKE)
    adapter = _adapter(56, "BSC")
    adapter.w3.eth.get_block.return_value = {"timestamp": 0x5F699005}
    first = await adapter.get_contract_creation_info(CAKE)
    adapter._creation_infos.clear()
    # Etherscan is asked again (its reply is not cached), Sourcify's deployment is not.
    enqueue(REFUSED)
    second = await adapter.get_contract_creation_info(CAKE)
    assert first == second
    assert [call.args[0] for call in session.get.call_args_list].count(ETHERSCAN_URL) == 2
    assert session.get.call_count == 3
    assert adapter.w3.eth.get_block.call_count == 2
