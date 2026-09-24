"""Verification from the chain's explorer or Sourcify, and EIP-1167 clones judged by their implementation."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cachetools import TLRUCache

from adapters.evm_base import EvmAdapter
from services.explorer_service import ExplorerResult, ExplorerService

ADDRESS = "0x89e5db8b5aa49aa85ac63f691524311aeb649eba"
IMPLEMENTATION = "0x" + "4" * 40
ETHERSCAN = "https://api.etherscan.io/v2/api"
SOURCIFY = "https://sourcify.dev/server/v2/contract/"


def _sourcify(chain_id, address, verified):
    # Shapes recorded from keyless Sourcify v2 on 2026-09-24: 200 with the match, or 404 with nulls.
    match = "match" if verified else None
    return {
        "match": match,
        "creationMatch": match,
        "runtimeMatch": match,
        "chainId": str(chain_id),
        "address": address,
    }


def _etherscan(source):
    return {"status": "1", "result": [{"SourceCode": source}]}


class FakeHttp:
    """aiohttp.ClientSession answering by URL: (status, payload) per address, or an exception."""

    def __init__(self, etherscan, sourcify):
        self.etherscan, self.sourcify = etherscan, sourcify
        self.session = MagicMock()
        self.session.get.side_effect = self.get

    def get(self, url, params=None, **kwargs):
        if url == ETHERSCAN:
            answer = self.etherscan[params["address"].lower()]
        else:
            answer = self.sourcify[url.removeprefix(SOURCIFY).split("/")[1]]
        context = MagicMock()
        if isinstance(answer, Exception):
            context.__aenter__ = AsyncMock(side_effect=answer)
        else:
            response = MagicMock(status=answer[0])
            response.json = AsyncMock(return_value=answer[1])
            context.__aenter__ = AsyncMock(return_value=response)
        context.__aexit__ = AsyncMock(return_value=False)
        return context


async def _verify(etherscan, sourcify, code="0x6080", chain_id=56, address=ADDRESS):
    http = FakeHttp(etherscan, sourcify)
    adapter = EvmAdapter(chain_id, "Test", "https://rpc.invalid", etherscan_api_key="test-key")
    adapter._explorer_service = ExplorerService()
    adapter.get_bytecode = AsyncMock(return_value=code)
    with patch("aiohttp.ClientSession") as client:
        client.return_value.__aenter__.return_value = http.session
        return await adapter.is_verified_contract(address), http


VERIFIED_SOURCE = (200, _etherscan("contract Token {}"))
UNVERIFIED_SOURCE = (200, _etherscan(""))
EXPLORER_DOWN = (500, None)
SOURCIFY_VERIFIED = (200, _sourcify(56, ADDRESS, True))
SOURCIFY_UNVERIFIED = (404, _sourcify(56, ADDRESS, False))
SOURCIFY_DOWN = (502, None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "explorer, sourcify, expected",
    [
        (VERIFIED_SOURCE, SOURCIFY_UNVERIFIED, (True, "contract Token {}")),
        (VERIFIED_SOURCE, SOURCIFY_DOWN, (True, "contract Token {}")),
        (UNVERIFIED_SOURCE, SOURCIFY_VERIFIED, (True, None)),
        (EXPLORER_DOWN, SOURCIFY_VERIFIED, (True, None)),
        (UNVERIFIED_SOURCE, SOURCIFY_UNVERIFIED, (False, None)),
        # Either source unread and the other not saying verified: unknown, never unverified.
        (UNVERIFIED_SOURCE, SOURCIFY_DOWN, (None, None)),
        (EXPLORER_DOWN, SOURCIFY_UNVERIFIED, (None, None)),
        (EXPLORER_DOWN, SOURCIFY_DOWN, (None, None)),
        # A Sourcify reply about another contract is not an answer about this one.
        (UNVERIFIED_SOURCE, (404, _sourcify(56, IMPLEMENTATION, False)), (None, None)),
        (UNVERIFIED_SOURCE, (404, _sourcify(1, ADDRESS, False)), (None, None)),
    ],
    ids=[
        "explorer-verified",
        "explorer-verified-sourcify-down",
        "sourcify-verified",
        "sourcify-verified-explorer-down",
        "both-unverified",
        "sourcify-down",
        "explorer-down",
        "both-down",
        "sourcify-other-address",
        "sourcify-other-chain",
    ],
)
async def test_explorer_or_sourcify_verifies_and_both_must_deny(explorer, sourcify, expected):
    result, _ = await _verify({ADDRESS: explorer}, {ADDRESS: sourcify})
    assert result == expected


# EIP-1167 runtime for a clone of IMPLEMENTATION.
CLONE_CODE = "363d3d373d3d3d363d73" + IMPLEMENTATION[2:] + "5af43d82803e903d91602b57fd5bf3"


@pytest.mark.asyncio
@pytest.mark.parametrize("prefix", ["", "0x"], ids=["web3-7", "web3-6"])
@pytest.mark.parametrize(
    "implementation, expected, requests",
    [
        # Sourcify is asked only when the explorer did not verify the contract.
        ((VERIFIED_SOURCE, SOURCIFY_UNVERIFIED), (True, "contract Token {}"), 3),
        ((UNVERIFIED_SOURCE, SOURCIFY_UNVERIFIED), (False, None), 4),
        ((EXPLORER_DOWN, SOURCIFY_UNVERIFIED), (None, None), 4),
    ],
    ids=["verified-implementation", "unverified-implementation", "implementation-unknown"],
)
async def test_a_minimal_proxy_is_judged_by_its_implementation(prefix, implementation, expected, requests):
    impl_explorer, impl_sourcify = implementation
    result, http = await _verify(
        {ADDRESS: UNVERIFIED_SOURCE, IMPLEMENTATION: impl_explorer},
        {
            ADDRESS: SOURCIFY_UNVERIFIED,
            IMPLEMENTATION: (impl_sourcify[0], _sourcify(56, IMPLEMENTATION, False)),
        },
        code=prefix + CLONE_CODE,
    )
    assert result == expected
    assert http.session.get.call_count == requests


async def _hang(*args, **kwargs):
    await asyncio.sleep(60)


def _adapter_with(explorer, sourcify, code="0x6080"):
    adapter = EvmAdapter(56, "Test", "https://rpc.invalid", etherscan_api_key="test-key")
    adapter._etherscan_verification = AsyncMock(return_value=explorer)
    adapter._explorer_service = MagicMock(get_sourcify_verification=sourcify)
    adapter.get_bytecode = AsyncMock(return_value=code)
    return adapter


@pytest.mark.asyncio
async def test_an_explorer_verified_contract_does_not_wait_for_sourcify():
    sourcify = AsyncMock(side_effect=_hang)
    adapter = _adapter_with((True, "contract Token {}"), sourcify)
    assert await asyncio.wait_for(adapter.is_verified_contract(ADDRESS), 1) == (True, "contract Token {}")
    sourcify.assert_not_called()


@pytest.mark.asyncio
async def test_a_stalled_sourcify_leaves_the_answer_unknown_in_bounded_time(monkeypatch):
    import services.counterparty_service as counterparty_module

    monkeypatch.setattr(counterparty_module, "PROVIDER_TIMEOUT", 0.05)
    adapter = _adapter_with((False, None), AsyncMock(side_effect=_hang))
    assert await asyncio.wait_for(adapter.is_verified_contract(ADDRESS), 5) == (None, None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sourcify, expected",
    [(ExplorerResult("verified"), (True, None)), (ExplorerResult("unverified"), (None, None))],
    ids=["sourcify-verifies", "sourcify-denies"],
)
async def test_a_stalled_explorer_is_unknown_in_bounded_time_and_sourcify_is_still_asked(
    monkeypatch, sourcify, expected
):
    import services.counterparty_service as counterparty_module

    monkeypatch.setattr(counterparty_module, "PROVIDER_TIMEOUT", 0.05)
    lookup = AsyncMock(return_value=sourcify)
    adapter = _adapter_with((False, None), lookup)
    adapter._etherscan_verification = AsyncMock(side_effect=_hang)
    assert await asyncio.wait_for(adapter.is_verified_contract(ADDRESS), 1) == expected
    lookup.assert_awaited_once_with(ADDRESS, 56)


@pytest.mark.asyncio
async def test_a_stalled_robinhood_chain_verification_is_unknown_in_bounded_time(monkeypatch):
    import services.counterparty_service as counterparty_module

    monkeypatch.setattr(counterparty_module, "PROVIDER_TIMEOUT", 0.05)
    adapter = EvmAdapter(4663, "Robinhood Chain", "https://rpc.invalid")
    assert adapter._explorer_backend == "sourcify_blockscout"
    adapter._explorer_service = MagicMock(get_verification_status=AsyncMock(side_effect=_hang))
    adapter.get_bytecode = AsyncMock(return_value="0x6080")
    assert await asyncio.wait_for(adapter.is_verified_contract(ADDRESS), 1) == (None, None)


@pytest.mark.asyncio
async def test_an_unreadable_code_leaves_the_clone_check_out():
    adapter = _adapter_with((False, None), AsyncMock(return_value=ExplorerResult("unverified")), code=None)
    assert await adapter.is_verified_contract(ADDRESS) == (False, None)
    adapter.get_bytecode.assert_awaited_once_with(ADDRESS)


@pytest.mark.asyncio
async def test_code_the_caller_already_read_is_not_read_again():
    adapter = _adapter_with((False, None), AsyncMock(return_value=ExplorerResult("unverified")))
    adapter._verification = AsyncMock(side_effect=[(False, None), (True, "contract Impl {}")])
    assert await adapter.is_verified_contract(ADDRESS, code=CLONE_CODE) == (True, "contract Impl {}")
    adapter.get_bytecode.assert_not_awaited()
    assert adapter._verification.await_args_list[1].args == (IMPLEMENTATION,)


@pytest.mark.asyncio
async def test_a_verified_contract_needs_no_code_read():
    http = FakeHttp({ADDRESS: VERIFIED_SOURCE}, {ADDRESS: SOURCIFY_UNVERIFIED})
    adapter = EvmAdapter(56, "Test", "https://rpc.invalid", etherscan_api_key="test-key")
    adapter._explorer_service = ExplorerService()
    adapter.get_bytecode = AsyncMock(return_value=CLONE_CODE)
    with patch("aiohttp.ClientSession") as client:
        client.return_value.__aenter__.return_value = http.session
        assert (await adapter.is_verified_contract(ADDRESS))[0] is True
    adapter.get_bytecode.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sourcify, blockscout_verified, expected",
    [
        (SOURCIFY_UNVERIFIED, False, "unverified"),
        (SOURCIFY_DOWN, False, "unknown"),
        (SOURCIFY_DOWN, True, "verified"),
        ((200, _sourcify(4663, ADDRESS, True)), False, "verified"),
    ],
    ids=["both-unverified", "sourcify-down", "blockscout-verified", "sourcify-verified"],
)
async def test_robinhood_chain_needs_both_sourcify_and_blockscout_to_deny(
    sourcify, blockscout_verified, expected
):
    status, payload = sourcify
    if payload is not None and payload["chainId"] == "56":
        payload = {**payload, "chainId": "4663"}
    blockscout = {"hash": ADDRESS, "is_contract": True, "is_verified": blockscout_verified}
    session = MagicMock()

    def get(url, params=None, **kwargs):
        answer = (status, payload) if url.startswith(SOURCIFY) else (200, blockscout)
        response = MagicMock(status=answer[0])
        response.json = AsyncMock(return_value=answer[1])
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=response)
        context.__aexit__ = AsyncMock(return_value=False)
        return context

    session.get.side_effect = get
    with (
        patch("aiohttp.ClientSession") as client,
        patch.dict("os.environ", {"BLOCKSCOUT_API_KEY": "test-key"}),
    ):
        client.return_value.__aenter__.return_value = session
        result = await ExplorerService().get_verification_status(ADDRESS, 4663)
    assert result.status == expected


@pytest.mark.asyncio
async def test_a_timed_out_sourcify_lookup_is_still_counted_once_when_it_ends(monkeypatch):
    import services.counterparty_service as counterparty_module
    import services.explorer_service as explorer_module
    from core.unknown_ledger import UnknownLedger

    ledger = UnknownLedger()
    monkeypatch.setattr(explorer_module, "unknown_ledger", ledger)
    monkeypatch.setattr(counterparty_module, "PROVIDER_TIMEOUT", 0.05)
    response = MagicMock(status=404)
    response.json = AsyncMock(return_value=_sourcify(56, ADDRESS, False))

    async def slow_reply():
        await asyncio.sleep(0.2)
        return response

    context = MagicMock()
    context.__aenter__ = AsyncMock(side_effect=slow_reply)
    context.__aexit__ = AsyncMock(return_value=False)
    session = MagicMock()
    session.get.return_value = context
    adapter = EvmAdapter(56, "Test", "https://rpc.invalid", etherscan_api_key="test-key")
    adapter._explorer_service = ExplorerService()
    adapter._etherscan_verification = AsyncMock(return_value=(False, None))
    adapter.get_bytecode = AsyncMock(return_value="0x6080")
    with patch("aiohttp.ClientSession") as client:
        client.return_value.__aenter__.return_value = session
        assert await adapter.is_verified_contract(ADDRESS) == (None, None)
        assert ledger.for_chain(56) == {}
        await asyncio.sleep(0.4)
    assert {k: ledger.for_chain(56)["sourcify"][k] for k in ("answered", "unknown", "failed")} == {
        "answered": 0, "unknown": 1, "failed": 0,
    }
    # The late answer was cached for the next scan.
    assert (await adapter._explorer_service.get_sourcify_verification(ADDRESS, 56)).status == "unverified"
    assert session.get.call_count == 1


def _held_sourcify(release):
    """A session whose Sourcify reply (404, not verified) comes once `release` is set."""
    response = MagicMock(status=404)
    response.json = AsyncMock(return_value=_sourcify(56, ADDRESS, False))

    async def held_reply():
        await release.wait()
        return response

    context = MagicMock()
    context.__aenter__ = AsyncMock(side_effect=held_reply)
    context.__aexit__ = AsyncMock(return_value=False)
    session = MagicMock()
    session.get.return_value = context
    return session


@pytest.mark.asyncio
async def test_a_hot_address_has_one_live_sourcify_lookup(monkeypatch):
    import services.counterparty_service as counterparty_module
    import services.explorer_service as explorer_module
    from core.unknown_ledger import UnknownLedger

    ledger = UnknownLedger()
    monkeypatch.setattr(explorer_module, "unknown_ledger", ledger)
    monkeypatch.setattr(counterparty_module, "PROVIDER_TIMEOUT", 0.05)
    release = asyncio.Event()
    session = _held_sourcify(release)
    adapter = EvmAdapter(56, "Test", "https://rpc.invalid", etherscan_api_key="test-key")
    service = adapter._explorer_service = ExplorerService()
    adapter._etherscan_verification = AsyncMock(return_value=(False, None))
    adapter.get_bytecode = AsyncMock(return_value="0x6080")
    with patch("aiohttp.ClientSession") as client:
        client.return_value.__aenter__.return_value = session
        # Two scans stop waiting while the first Sourcify lookup is still out; two more callers,
        # one with the address in upper case, then wait on it together.
        assert await adapter.is_verified_contract(ADDRESS) == (None, None)
        assert await adapter.is_verified_contract(ADDRESS) == (None, None)
        waiting = asyncio.gather(
            service.get_sourcify_verification(ADDRESS, 56),
            service.get_sourcify_verification("0x" + ADDRESS[2:].upper(), 56),
        )
        await asyncio.sleep(0)
        release.set()
        results = await waiting
        await asyncio.sleep(0.01)
    assert [result.status for result in results] == ["unverified", "unverified"]
    assert session.get.call_count == 1
    counts = ledger.for_chain(56)["sourcify"]
    assert {k: counts[k] for k in ("answered", "unknown", "failed")} == {"answered": 0, "unknown": 1, "failed": 0}
    assert service._inflight == {}


@pytest.mark.asyncio
async def test_cancelling_the_first_caller_leaves_the_shared_sourcify_lookup_running():
    release = asyncio.Event()
    session = _held_sourcify(release)
    service = ExplorerService()
    with patch("aiohttp.ClientSession") as client:
        client.return_value.__aenter__.return_value = session
        leader = asyncio.create_task(service.get_sourcify_verification(ADDRESS, 56))
        await asyncio.sleep(0)
        follower = asyncio.create_task(service.get_sourcify_verification(ADDRESS, 56))
        await asyncio.sleep(0)
        leader.cancel()
        release.set()
        result = await follower
    with pytest.raises(asyncio.CancelledError):
        await leader
    assert result.status == "unverified"
    assert session.get.call_count == 1
    assert service._inflight == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("status, held", [(200, 300), (404, 300), (502, 30)], ids=["verified", "unverified", "unknown"])
async def test_an_unknown_explorer_result_is_kept_only_thirty_seconds(status, held):
    import services.explorer_service as explorer_module

    service = ExplorerService()
    assert service._cache.ttu is explorer_module._result_ttu
    clock = [0.0]
    service._cache = TLRUCache(maxsize=16, ttu=explorer_module._result_ttu, timer=lambda: clock[0])
    payload = None if status == 502 else _sourcify(56, ADDRESS, status == 200)
    http = FakeHttp({}, {ADDRESS: (status, payload)})
    with patch("aiohttp.ClientSession") as client:
        client.return_value.__aenter__.return_value = http.session
        first = await service.get_sourcify_verification(ADDRESS, 56)
        clock[0] = held - 1
        await service.get_sourcify_verification(ADDRESS, 56)
        assert http.session.get.call_count == 1
        clock[0] = held + 1
        await service.get_sourcify_verification(ADDRESS, 56)
    assert http.session.get.call_count == 2
    assert first.status == {200: "verified", 404: "unverified", 502: "unknown"}[status]
