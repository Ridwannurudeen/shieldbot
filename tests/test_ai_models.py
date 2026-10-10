"""Claude model selection and response handling for the optional AI layer."""

import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent.prompts import HAIKU_MODEL, SONNET_MODEL
from utils import ai_analyzer
from utils.ai_analyzer import AIAnalyzer


def _analyzer(response):
    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    analyzer.client = MagicMock()
    analyzer.client.messages.create = AsyncMock(return_value=response)
    analyzer.model = "test-model"
    analyzer.api_key = "test-key"
    analyzer.status = "ok"
    analyzer._probe_complete = True
    return analyzer


def _response(content, stop_reason="end_turn"):
    return SimpleNamespace(
        content=content,
        stop_reason=stop_reason,
        usage=SimpleNamespace(input_tokens=2, output_tokens=3),
    )


@pytest.mark.parametrize(
    "model,effort",
    [
        ("claude-sonnet-5-5", True),
        ("claude-opus-5-5", True),
        ("claude-haiku-4-5", False),
    ],
)
@pytest.mark.asyncio
async def test_chat_extracts_text_blocks_and_sets_effort_for_thinking_models(model, effort):
    response = _response([
        SimpleNamespace(type="thinking", thinking="private reasoning"),
        SimpleNamespace(type="text", text="Key finding "),
        SimpleNamespace(type="text", text="and recommendation."),
    ])
    analyzer = _analyzer(response)

    text, tokens = await analyzer.chat_with_usage(model, [{"role": "user", "content": "hi"}])

    assert text == "Key finding and recommendation."
    assert tokens == 5
    kwargs = analyzer.client.messages.create.await_args.kwargs
    assert ("output_config" in kwargs) is effort
    if effort:
        assert kwargs["output_config"] == {"effort": "low"}
    assert "thinking" not in kwargs


@pytest.mark.asyncio
async def test_chat_raises_ai_refused_for_a_refusal_response():
    refused = getattr(ai_analyzer, "AIRefused", RuntimeError)
    analyzer = _analyzer(_response([SimpleNamespace(type="text", text="I cannot help.")], "refusal"))

    with pytest.raises(refused) as raised:
        await analyzer.chat_with_usage("claude-sonnet-5-5", [])

    assert type(raised.value).__name__ == "AIRefused"


@pytest.mark.asyncio
async def test_chat_raises_ai_empty_response_for_empty_max_tokens_response():
    analyzer = _analyzer(_response([SimpleNamespace(type="thinking", thinking="still thinking")], "max_tokens"))

    with pytest.raises(Exception) as raised:
        await analyzer.chat_with_usage("claude-sonnet-5-5", [])

    assert type(raised.value).__name__ == "AIEmptyResponse"


def test_defaults_use_current_claude_models(monkeypatch):
    from core.config import Settings

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    assert HAIKU_MODEL == "claude-haiku-4-5"
    assert SONNET_MODEL == "claude-sonnet-5-5"
    assert Settings(_env_file=None).anthropic_model == "claude-haiku-4-5"
    assert AIAnalyzer().model == "claude-haiku-4-5"


def test_openai_key_does_not_enable_ai_without_anthropic(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "not-used")

    analyzer = AIAnalyzer()

    assert analyzer.client is None
    assert analyzer.is_available() is False


def _probe_analyzer(model=HAIKU_MODEL):
    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    analyzer.api_key = "test-key"
    analyzer.model = model
    analyzer.status = "unverified"
    analyzer._probe_complete = False
    analyzer.client = MagicMock()
    analyzer.client.models.retrieve = AsyncMock()
    return analyzer


def _provider_error(error_type, status):
    import anthropic
    import httpx

    request = httpx.Request("GET", "https://api.anthropic.com/v1/models")
    if error_type == "APIConnectionError":
        return anthropic.APIConnectionError(request=request)
    response = httpx.Response(status, request=request)
    return getattr(anthropic, error_type)("provider error", response=response, body=None)


@pytest.mark.asyncio
async def test_probe_checks_distinct_models_once(caplog):
    analyzer = _probe_analyzer()
    caplog.set_level(logging.INFO, logger="utils.ai_analyzer")

    assert await analyzer.probe() == "ok"
    assert [call.args[0] for call in analyzer.client.models.retrieve.await_args_list] == [
        HAIKU_MODEL,
        SONNET_MODEL,
    ]
    assert analyzer.is_available() is True
    assert await analyzer.probe() == "ok"
    assert analyzer.client.models.retrieve.await_count == 2
    assert caplog.text.count("AI model probe") == 1
    assert "test-key" not in caplog.text


@pytest.mark.asyncio
async def test_probe_without_a_key_is_unconfigured():
    analyzer = _probe_analyzer()
    analyzer.api_key = ""
    analyzer.client = None

    assert await analyzer.probe() == "unconfigured"
    assert analyzer.is_available() is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_type,status",
    [("AuthenticationError", 401), ("NotFoundError", 404)],
)
async def test_probe_rejects_invalid_credentials_or_models(error_type, status):
    analyzer = _probe_analyzer()
    analyzer.client.models.retrieve = AsyncMock(side_effect=_provider_error(error_type, status))

    result = await analyzer.probe()

    assert result == f"rejected: {error_type}"
    assert analyzer.is_available() is False
    analyzer.client.models.retrieve.assert_awaited_once_with(HAIKU_MODEL)


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type,status", [("APIConnectionError", None), ("timeout", None)])
async def test_probe_connection_errors_leave_ai_usable(error_type, status):
    import asyncio

    analyzer = _probe_analyzer()
    error = asyncio.TimeoutError() if error_type == "timeout" else _provider_error(error_type, status)
    analyzer.client.models.retrieve = AsyncMock(side_effect=error)

    assert await analyzer.probe() == "unverified"
    assert analyzer.is_available() is True


@pytest.mark.asyncio
async def test_rejected_real_call_disables_ai():
    error = _provider_error("AuthenticationError", 401)
    analyzer = _analyzer(_response([]))
    analyzer.client.messages.create = AsyncMock(side_effect=error)

    with pytest.raises(type(error)):
        await analyzer.chat_with_usage("claude-sonnet-5-5", [])

    assert analyzer.status == "rejected: AuthenticationError"
    assert analyzer.is_available() is False


def test_runtime_has_no_retired_claude_model_ids():
    root = Path(__file__).resolve().parents[1]
    retired = ("claude-3-", "claude-sonnet-4-2025")
    excluded = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", "tests"}

    for path in root.rglob("*.py"):
        if excluded.intersection(path.relative_to(root).parts):
            continue
        source = path.read_text(encoding="utf-8")
        assert not any(model in source for model in retired), path

    example = (root / ".env.example").read_text(encoding="utf-8")
    assert not any(model in example for model in retired)
