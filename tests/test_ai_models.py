"""Claude model selection and response handling for the optional AI layer."""

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
