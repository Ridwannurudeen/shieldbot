"""The intent analyzer must check an approval's spender against the router list of the scanned chain."""

import pytest

from adapters.eth import EthAdapter
from adapters.optimism import OptimismAdapter
from analyzers.intent import IntentMismatchAnalyzer
from core.analyzer import AnalysisContext
from utils.web3_client import Web3Client

MAX_UINT256 = "f" * 64


def _client():
    client = Web3Client()
    client.register_adapter(EthAdapter(rpc_url="https://rpc.invalid"))
    client.register_adapter(OptimismAdapter(rpc_url="https://rpc.invalid"))
    return client


def _unlimited_approve(spender):
    return "0x095ea7b3" + spender[2:].lower().rjust(64, "0") + MAX_UINT256


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "chain_id,spender,router",
    [
        (1, "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "Uniswap V2 Router"),
        (1, "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", "Uniswap Universal Router V2"),
        (10, "0xa062aE8A9c5e11aaA026fc2670B0D65cCc8B2858", "Velodrome V2 Router"),
        (56, "0x10ED43C718714eb63d5aA57B78B54704E256024E", "PancakeSwap V2 Router"),
    ],
)
async def test_unlimited_approval_to_the_chains_router_is_whitelisted(chain_id, spender, router):
    result = await IntentMismatchAnalyzer(_client()).analyze(
        AnalysisContext(
            "0x" + "a" * 40, chain_id=chain_id, extra={"calldata": _unlimited_approve(spender)}
        )
    )
    assert result.flags == [f"Unlimited approval to {router}"]
    assert result.score == 5


@pytest.mark.asyncio
async def test_another_chains_router_is_not_whitelisted():
    pancake_v2 = "0x10ED43C718714eb63d5aA57B78B54704E256024E"
    result = await IntentMismatchAnalyzer(_client()).analyze(
        AnalysisContext(
            "0x" + "a" * 40, chain_id=1, extra={"calldata": _unlimited_approve(pancake_v2)}
        )
    )
    assert result.flags[0] == "Unlimited approval to non-whitelisted contract"
    assert result.score == 35
    # With no counterparty service the spender's facts are unknown, so the verdict is too.
    assert result.data["status"] == "unknown"
