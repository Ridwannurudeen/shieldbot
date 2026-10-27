"""The API looks up the explorer facts of the token most BOT Chain swaps pass through when it starts,
as background work, until both are answered."""

from unittest.mock import AsyncMock

import pytest

from adapters import botchain
from adapters.botchain import USDT, BotChainAdapter
from services.explorer_service import BACKGROUND

DATED = {"creator": "0x" + "1" * 40, "creation_time": "2026-01-01T00:00:00+00:00", "age_days": 299}


@pytest.fixture
def adapter(monkeypatch):
    monkeypatch.setattr(botchain.asyncio, "sleep", AsyncMock())
    return BotChainAdapter("https://rpc.invalid")


@pytest.mark.asyncio
async def test_the_warm_up_runs_as_background_work_until_both_facts_are_answered(adapter):
    seen = []

    async def verified(token):
        seen.append(BACKGROUND.get())
        return (None, None) if len(seen) == 1 else (True, None)

    adapter.is_verified_contract = verified
    adapter.get_contract_creation_info = AsyncMock(side_effect=[None, DATED])
    await adapter.warm_explorer_caches()
    assert seen == [True, True]
    assert adapter.get_contract_creation_info.await_args_list[-1].args == (USDT,)
    botchain.asyncio.sleep.assert_awaited_once_with(botchain.WARM_RETRY_SECONDS)
    # The warm-up's context does not leak into its caller's.
    assert BACKGROUND.get() is False


@pytest.mark.asyncio
async def test_the_warm_up_gives_up_after_its_attempts(adapter, caplog):
    adapter.is_verified_contract = AsyncMock(return_value=(True, None))
    adapter.get_contract_creation_info = AsyncMock(return_value={**DATED, "age_days": None})
    await adapter.warm_explorer_caches()
    assert adapter.get_contract_creation_info.await_count == botchain.WARM_ATTEMPTS
    assert botchain.asyncio.sleep.await_count == botchain.WARM_ATTEMPTS - 1
    assert "not warmed" in caplog.text
