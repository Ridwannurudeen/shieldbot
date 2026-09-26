"""Contract creation on Base and Optimism comes from their public Blockscout instances.

Etherscan's free tier refuses getcontractcreation on chains 8453 and 10 and the Blockscout PRO
gateway answers 402 without a key, so contract age there was Unknown on every scan.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from adapters.base_chain import BaseChainAdapter
from adapters.bsc import BscAdapter
from adapters.optimism import OptimismAdapter
from services.explorer_service import ExplorerResult, ExplorerService

# Fields of GET {instance}/api/v2/addresses/{address}, recorded without a key on 2026-09-24
# (native USDC on each chain).
RECORDED = {
    8453: {
        "hash": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "is_contract": True,
        "is_verified": True,
        "creation_status": "success",
        "creator_address_hash": "0x6aAFF8af0ae8017725312C388bA3745dfE91185B",
        "creation_transaction_hash": "0x"
        + "8aa214f98bcf2984add809d10232135cccc4d6ab97d8477e66475d8bf68def34",
        "proxy_type": "eip1967_oz",
    },
    10: {
        "hash": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
        "is_contract": True,
        "is_verified": True,
        "creation_status": "success",
        "creator_address_hash": "0x9bcCD51ee5cf97791E39544827Ef675Cd81171B8",
        "creation_transaction_hash": "0x"
        + "4a9f336b868a6fbff412d545b37a568d62a9ab04f6fa54604959fb374336b216",
        "proxy_type": "eip1967_oz",
    },
}
INSTANCES = {8453: "https://base.blockscout.com", 10: "https://explorer.optimism.io"}
ADDRESS = "0x" + "ab" * 20
CREATOR = "0x" + "1" * 40
TX_HASH = "0x" + "a" * 64


@pytest.fixture
def http():
    session = MagicMock()

    def respond(payload, status=200):
        response = MagicMock(status=status)
        response.json = AsyncMock(return_value=payload)
        session.get.return_value.__aenter__ = AsyncMock(return_value=response)

    with patch("aiohttp.ClientSession") as client:
        client.return_value.__aenter__.return_value = session
        with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": ""}):
            yield respond, session


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [8453, 10])
async def test_creation_comes_from_the_public_instance_without_a_key(http, chain_id):
    respond, session = http
    respond(RECORDED[chain_id])
    address = RECORDED[chain_id]["hash"]
    result = await ExplorerService().get_contract_creation_info(address, chain_id)
    assert result.status == "known"
    assert result.data == {
        "creator": RECORDED[chain_id]["creator_address_hash"],
        "tx_hash": RECORDED[chain_id]["creation_transaction_hash"],
    }
    session.get.assert_called_once_with(
        f"{INSTANCES[chain_id]}/api/v2/addresses/{address.lower()}",
        params={},
        allow_redirects=False,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [8453, 10])
@pytest.mark.parametrize("status", [503, 301])
async def test_instance_failure_or_move_is_unknown(http, chain_id, status):
    # A moved instance redirects; redirects are not followed, so a move reads as Unknown.
    respond, _ = http
    respond({}, status)
    result = await ExplorerService().get_contract_creation_info(
        RECORDED[chain_id]["hash"], chain_id
    )
    assert result.status == "unknown" and result.reason == f"HTTP {status}"


@pytest.mark.asyncio
async def test_robinhood_still_needs_the_pro_gateway_key(http):
    result = await ExplorerService().get_contract_creation_info(ADDRESS, 4663)
    assert result.status == "unknown" and "BLOCKSCOUT_API_KEY" in result.reason
    http[1].get.assert_not_called()


@pytest.mark.asyncio
async def test_each_blockscout_host_is_spaced_on_its_own(http):
    respond, session = http
    respond(RECORDED[8453])
    clock = [10.0]
    starts = {}

    def get(url, **kwargs):
        starts.setdefault(url.split("/")[2], []).append(clock[0])
        return session.get.return_value

    session.get.side_effect = get

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
                service.get_contract_creation_info("0x" + f"{i:040x}", chain_id)
                for i in range(3)
                for chain_id in (4663, 8453, 10)
            )
        )
    assert set(starts) == {"api.blockscout.com", "base.blockscout.com", "explorer.optimism.io"}
    for host_starts in starts.values():
        assert len(host_starts) == 3
        assert all(b - a >= 0.209 for a, b in zip(host_starts, host_starts[1:]))
    # No host's spacing counts another host's requests.
    assert all(host_starts[0] == 10.0 for host_starts in starts.values())


@pytest.mark.asyncio
async def test_a_busy_host_does_not_hold_up_the_others(http):
    gateway_open = asyncio.Event()
    calls = []
    response = MagicMock(status=200)
    response.json = AsyncMock(return_value=RECORDED[8453])

    def get(url, **kwargs):
        host = url.split("/")[2]
        calls.append(host)

        async def enter():
            if host == "api.blockscout.com":
                await gateway_open.wait()
            return response

        context = MagicMock()
        context.__aenter__ = AsyncMock(side_effect=enter)
        return context

    http[1].get.side_effect = get
    service = ExplorerService()
    with patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}):
        gateway = [
            asyncio.create_task(service.get_contract_creation_info("0x" + f"{i:040x}", 4663))
            for i in range(2)
        ]
        await asyncio.sleep(0)
        # The first gateway request is stuck inside its host's lock and the second waits for it;
        # Base and Optimism must still be answered meanwhile.
        await asyncio.wait_for(
            asyncio.gather(
                service.get_contract_creation_info(RECORDED[8453]["hash"], 8453),
                service.get_contract_creation_info(RECORDED[10]["hash"], 10),
            ),
            timeout=5,
        )
        assert calls.count("api.blockscout.com") == 1
        assert not any(task.done() for task in gateway)
        gateway_open.set()
        await asyncio.gather(*gateway)
    assert calls.count("api.blockscout.com") == 2


def _adapter(adapter_class, creation):
    adapter = adapter_class(rpc_url="https://rpc.invalid")
    adapter._explorer_service = MagicMock()
    adapter._explorer_service.get_contract_creation_info = AsyncMock(return_value=creation)
    adapter._call_with_retry = AsyncMock(
        side_effect=[{"blockNumber": 1}, {"timestamp": 1704067200}]
    )
    return adapter


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_class", [BaseChainAdapter, OptimismAdapter])
async def test_base_and_optimism_adapters_date_contracts_from_blockscout(http, adapter_class):
    adapter = _adapter(
        adapter_class, ExplorerResult("known", data={"creator": CREATOR, "tx_hash": TX_HASH})
    )
    result = await adapter.get_contract_creation_info(ADDRESS)
    assert result["creator"] == CREATOR and result["tx_hash"] == TX_HASH
    assert result["creation_time"] == "2024-01-01T00:00:00+00:00"
    assert result["age_days"] >= 0
    adapter._explorer_service.get_contract_creation_info.assert_awaited_once_with(
        ADDRESS, adapter.chain_id
    )
    http[1].get.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter_class", [BaseChainAdapter, OptimismAdapter])
async def test_unknown_creation_leaves_age_unknown(http, adapter_class):
    adapter = _adapter(adapter_class, ExplorerResult("unknown", reason="HTTP 503"))
    assert await adapter.get_contract_creation_info(ADDRESS) is None
    adapter._call_with_retry.assert_not_awaited()


REFUSED = {
    "status": "0",
    "message": "NOTOK",
    "result": "Free API access is not supported for this chain",
}


def _bsc_adapter(http, deployment):
    """BSC asks Etherscan first, which refuses on the free tier, then Sourcify's deployment record:
    no public Blockscout serves chain 56."""
    http[0](REFUSED)
    adapter = _adapter(
        BscAdapter, ExplorerResult("known", data={"creator": CREATOR, "tx_hash": TX_HASH})
    )
    adapter._explorer_service.get_sourcify_deployment = AsyncMock(return_value=deployment)
    adapter._call_with_retry = AsyncMock(side_effect=[{"timestamp": 1704067200}])
    return adapter


@pytest.mark.asyncio
async def test_a_chain_etherscan_refuses_is_dated_from_sourcify_s_deployment(http):
    adapter = _bsc_adapter(
        http,
        ExplorerResult(
            "known",
            data={"creator": CREATOR, "tx_hash": TX_HASH, "block_number": 693963},
            provider="sourcify",
        ),
    )
    result = await adapter.get_contract_creation_info(ADDRESS)
    assert result["creator"] == CREATOR and result["tx_hash"] == TX_HASH
    assert result["creation_time"] == "2024-01-01T00:00:00+00:00"
    assert result["age_days"] >= 0
    assert http[1].get.call_args.args == ("https://api.etherscan.io/v2/api",)
    adapter._explorer_service.get_sourcify_deployment.assert_awaited_once_with(ADDRESS, 56)
    adapter._explorer_service.get_contract_creation_info.assert_not_awaited()
    # One header read dates the deployment; the transaction is never read.
    adapter._call_with_retry.assert_awaited_once_with(adapter.w3.eth.get_block, 693963)


@pytest.mark.asyncio
async def test_a_contract_sourcify_has_not_verified_stays_unknown_where_etherscan_refuses(http):
    adapter = _bsc_adapter(
        http, ExplorerResult("unknown", reason="not verified", provider="sourcify")
    )
    assert await adapter.get_contract_creation_info(ADDRESS) is None
    adapter._call_with_retry.assert_not_awaited()
