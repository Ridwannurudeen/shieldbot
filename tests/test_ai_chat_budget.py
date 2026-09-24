"""The daily AI token budget shared by advisor chat and scan explanations."""

import asyncio
import logging
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from agent.advisor import AI_CHAT_PAUSED, Advisor
from core.database import Database


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


@pytest.mark.asyncio
async def test_token_usage_accumulates_per_utc_day(db):
    assert await db.get_ai_tokens_used(20000) == 0
    await db.add_ai_tokens_used(20000, 1200)
    await db.add_ai_tokens_used(20000, 300)
    await db.add_ai_tokens_used(20001, 7)
    assert await db.get_ai_tokens_used(20000) == 1500
    assert await db.get_ai_tokens_used(20001) == 7


@pytest.mark.asyncio
async def test_anthropic_usage_counts_input_and_output_tokens():
    from utils.ai_analyzer import AIAnalyzer

    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    analyzer.client = MagicMock()
    analyzer._openai_client = None
    analyzer.client.messages.create = AsyncMock(
        return_value=SimpleNamespace(
            content=[SimpleNamespace(text="reply")],
            usage=SimpleNamespace(input_tokens=1200, output_tokens=300),
        )
    )
    assert await analyzer.chat_with_usage(
        model="m", messages=[{"role": "user", "content": "hi"}]
    ) == ("reply", 1500)
    assert await analyzer.chat(model="m", messages=[{"role": "user", "content": "hi"}]) == "reply"


@pytest.mark.asyncio
async def test_openai_fallback_usage_counts_total_tokens():
    from utils.ai_analyzer import AIAnalyzer

    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    analyzer.client = None
    analyzer._openai_client = MagicMock()
    analyzer._openai_client.chat.completions.create = AsyncMock(
        return_value=SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="reply"))],
            usage=SimpleNamespace(prompt_tokens=900, completion_tokens=100, total_tokens=1000),
        )
    )
    assert await analyzer.chat_with_usage(model="m", messages=[], system="s") == ("reply", 1000)


def _advisor(db, budget=10_000, reply=("AI answer", 1500)):
    from utils.web3_client import Web3Client

    registry = Web3Client.__new__(Web3Client)
    registry._adapters = {56: MagicMock()}
    tools = SimpleNamespace(
        _container=SimpleNamespace(web3_client=registry),
        scan_contract=AsyncMock(
            return_value={"status": "ok", "coverage": {"honeypot": 1}, "risk_score": 10}
        ),
        check_deployer=AsyncMock(return_value={}),
        check_honeypot=AsyncMock(return_value={}),
        get_market_data=AsyncMock(return_value={}),
        get_agent_findings=AsyncMock(return_value=[]),
    )
    ai = SimpleNamespace(is_available=lambda: True, chat_with_usage=AsyncMock(return_value=reply))
    return Advisor(tools=tools, db=db, ai_analyzer=ai, daily_token_budget=budget), ai


def _today():
    return int(time.time() // 86400)


@pytest.mark.asyncio
async def test_chat_records_the_tokens_the_provider_reports(db):
    advisor, ai = _advisor(db)
    result = await advisor.chat("u1", "How does ShieldBot work?")
    assert result["text"] == "AI answer"
    assert await db.get_ai_tokens_used(_today()) == 1500


@pytest.mark.asyncio
@pytest.mark.parametrize("used", [10_000, 12_000])
async def test_chat_is_paused_once_the_budget_is_used(db, used):
    advisor, ai = _advisor(db)
    await db.add_ai_tokens_used(_today(), used)
    result = await advisor.chat("u1", "How does ShieldBot work?")
    assert result["text"] == AI_CHAT_PAUSED
    assert "AI chat is paused for today" in AI_CHAT_PAUSED
    ai.chat_with_usage.assert_not_called()
    assert await db.get_ai_tokens_used(_today()) == used
    assert await db.get_chat_history("u1") == []


@pytest.mark.asyncio
async def test_paused_chat_still_returns_the_scan(db):
    advisor, ai = _advisor(db, budget=0)
    result = await advisor.chat("u1", "Check 0x" + "a" * 40)
    assert result["text"] == AI_CHAT_PAUSED
    assert result["scan_data"]["status"] == "ok"
    ai.chat_with_usage.assert_not_called()


@pytest.mark.asyncio
async def test_budget_is_shared_across_calls_until_spent(db):
    advisor, ai = _advisor(db, budget=2000)
    assert (await advisor.chat("u1", "first"))["text"] == "AI answer"
    assert (await advisor.chat("u2", "second"))["text"] == "AI answer"
    assert (await advisor.chat("u3", "third"))["text"] == AI_CHAT_PAUSED
    assert ai.chat_with_usage.await_count == 2


@pytest.mark.asyncio
async def test_failed_or_timed_out_chat_records_nothing(db):
    advisor, ai = _advisor(db)
    ai.chat_with_usage.side_effect = RuntimeError("provider down")
    assert "encountered an error" in (await advisor.chat("u1", "hi"))["text"]
    ai.chat_with_usage.side_effect = asyncio.TimeoutError
    assert "timed out" in (await advisor.chat("u1", "hi"))["text"]
    assert await db.get_ai_tokens_used(_today()) == 0


@pytest.mark.asyncio
async def test_explain_records_tokens_and_falls_back_to_rules_when_spent(db):
    advisor, ai = _advisor(db, budget=2000, reply=("Plain English", 1500))
    scan = {"risk_score": 85, "risk_level": "HIGH"}
    assert await advisor.explain_scan(scan) == "Plain English"
    assert await db.get_ai_tokens_used(_today()) == 1500
    assert await advisor.explain_scan(scan) == "Plain English"
    assert "85/100" in await advisor.explain_scan(scan)
    assert ai.chat_with_usage.await_count == 2


@pytest.mark.asyncio
async def test_failed_usage_record_still_returns_the_chat_reply(db, caplog):
    advisor, ai = _advisor(db)
    db.add_ai_tokens_used = AsyncMock(side_effect=RuntimeError("disk I/O error at /srv/private"))
    result = await advisor.chat("u1", "How does ShieldBot work?")
    assert result["text"] == "AI answer"
    assert "RuntimeError" in caplog.text
    assert "/srv/private" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("failing", ["get_ai_tokens_used", "add_ai_tokens_used"])
async def test_explain_falls_back_to_rules_when_the_budget_store_fails(db, caplog, failing):
    advisor, ai = _advisor(db, reply=("Plain English", 1500))
    setattr(db, failing, AsyncMock(side_effect=RuntimeError("disk I/O error at /srv/private")))
    assert "85/100" in await advisor.explain_scan({"risk_score": 85, "risk_level": "HIGH"})
    assert "/srv/private" not in caplog.text


@pytest.mark.asyncio
async def test_zero_budget_pauses_ai(db):
    advisor, ai = _advisor(db, budget=0)
    assert (await advisor.chat("u1", "hi"))["text"] == AI_CHAT_PAUSED
    assert "85/100" in await advisor.explain_scan({"risk_score": 85, "risk_level": "HIGH"})
    ai.chat_with_usage.assert_not_called()


def test_default_budget():
    from core.config import Settings

    assert Settings.model_fields["ai_daily_token_budget"].default == 1_000_000


def test_negative_budget_is_refused_at_startup():
    from pydantic import ValidationError

    from core.config import Settings

    with pytest.raises(ValidationError, match="ai_daily_token_budget"):
        Settings(_env_file=None, ai_daily_token_budget=-1)
    assert Settings(_env_file=None, ai_daily_token_budget=0).ai_daily_token_budget == 0

