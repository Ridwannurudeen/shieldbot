"""Tests for agent.advisor — intent routing, context gathering, and chat engine."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.advisor import Advisor


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_tools():
    tools = MagicMock()
    tools.scan_contract = AsyncMock(return_value={
        "rug_probability": 72,
        "risk_level": "HIGH",
        "risk_archetype": "honeypot",
        "critical_flags": ["Honeypot detected", "Sell tax > 50%"],
    })
    tools.check_deployer = AsyncMock(return_value={
        "deployer_address": "0xdead",
        "total_contracts": 8,
        "high_risk_contracts": 6,
    })
    tools.get_agent_findings = AsyncMock(return_value=[
        {"id": 1, "finding_type": "honeypot", "address": "0xaaa", "risk_score": 90},
        {"id": 2, "finding_type": "rugpull", "address": "0xbbb", "risk_score": 85},
    ])
    return tools


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.get_chat_history = AsyncMock(return_value=[])
    db.insert_chat_message = AsyncMock(return_value=None)
    return db


@pytest.fixture
def mock_ai():
    ai = MagicMock()
    ai.client = MagicMock()  # not None — AI is available
    return ai


@pytest.fixture
def mock_ai_disabled():
    ai = MagicMock()
    ai.client = None  # AI disabled
    return ai


@pytest.fixture
def advisor(mock_tools, mock_db, mock_ai):
    return Advisor(tools=mock_tools, db=mock_db, ai_analyzer=mock_ai)


@pytest.fixture
def advisor_no_ai(mock_tools, mock_db, mock_ai_disabled):
    return Advisor(tools=mock_tools, db=mock_db, ai_analyzer=mock_ai_disabled)


# ---------------------------------------------------------------------------
# route() tests
# ---------------------------------------------------------------------------

def test_route_address(advisor):
    """Message containing a 0x address routes to CONTRACT_CHECK."""
    intent, data = advisor.route(
        "Is 0x4904c02efa081cb7685346968bac854cdf4e7777 safe?"
    )
    assert intent == "CONTRACT_CHECK"
    assert data["address"] == "0x4904c02efa081cb7685346968bac854cdf4e7777"


def test_route_multiple_addresses(advisor):
    """When multiple addresses appear, picks the first one."""
    intent, data = advisor.route(
        "Compare 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA and 0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    )
    assert intent == "CONTRACT_CHECK"
    assert data["address"] == "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def test_route_threat_keywords(advisor):
    """Threat-related keywords route to THREAT_FEED."""
    for msg in [
        "What threats are active?",
        "Any recent alerts?",
        "Is anything dangerous happening?",
        "What did the agent found recently?",
    ]:
        intent, data = advisor.route(msg)
        assert intent == "THREAT_FEED", f"Failed for: {msg}"
        assert data == {}


def test_route_general(advisor):
    """Generic questions route to GENERAL."""
    intent, data = advisor.route("How does ShieldBot work?")
    assert intent == "GENERAL"
    assert data == {}


def test_route_address_takes_priority(advisor):
    """Address detection should take priority over keyword matching."""
    intent, data = advisor.route(
        "Is this threat contract 0x1234567890abcdef1234567890abcdef12345678 dangerous?"
    )
    assert intent == "CONTRACT_CHECK"
    assert data["address"] == "0x1234567890abcdef1234567890abcdef12345678"


# ---------------------------------------------------------------------------
# _gather_context() tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gather_context_contract(advisor, mock_tools):
    """CONTRACT_CHECK gathers scan + deployer data."""
    addr = "0x4904c02efa081cb7685346968bac854cdf4e7777"
    context = await advisor._gather_context("CONTRACT_CHECK", {"address": addr})

    mock_tools.scan_contract.assert_awaited_once_with(addr)
    mock_tools.check_deployer.assert_awaited_once_with(addr)
    assert "scan" in context
    assert "deployer" in context
    assert context["scan"]["risk_level"] == "HIGH"


@pytest.mark.asyncio
async def test_gather_context_threats(advisor, mock_tools):
    """THREAT_FEED gathers agent findings."""
    context = await advisor._gather_context("THREAT_FEED", {})

    mock_tools.get_agent_findings.assert_awaited_once_with(limit=10)
    assert isinstance(context, list)
    assert len(context) == 2


@pytest.mark.asyncio
async def test_gather_context_general(advisor, mock_tools):
    """GENERAL intent returns empty dict, no tool calls."""
    context = await advisor._gather_context("GENERAL", {})

    assert context == {}
    mock_tools.scan_contract.assert_not_awaited()
    mock_tools.check_deployer.assert_not_awaited()
    mock_tools.get_agent_findings.assert_not_awaited()


# ---------------------------------------------------------------------------
# chat() tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chat_saves_history(advisor, mock_db, mock_ai):
    """chat() saves user message and assistant response to DB."""
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="This contract looks risky.")]
    mock_ai.client.messages.create = AsyncMock(return_value=mock_response)

    response = await advisor.chat("user123", "How does ShieldBot work?")

    assert response == "This contract looks risky."
    # Should save both user message and assistant response
    assert mock_db.insert_chat_message.await_count == 2
    calls = mock_db.insert_chat_message.call_args_list
    assert calls[0].args[0] == "user123"
    assert calls[0].args[1] == "user"
    assert calls[0].args[2] == "How does ShieldBot work?"
    assert calls[1].args[0] == "user123"
    assert calls[1].args[1] == "assistant"
    assert calls[1].args[2] == "This contract looks risky."


@pytest.mark.asyncio
async def test_chat_with_contract_context(advisor, mock_db, mock_ai):
    """chat() injects contract context into the user message."""
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="High risk contract detected.")]
    mock_ai.client.messages.create = AsyncMock(return_value=mock_response)

    response = await advisor.chat(
        "user456", "Check 0x4904c02efa081cb7685346968bac854cdf4e7777"
    )

    assert response == "High risk contract detected."
    # Verify the API was called with context in the message
    create_call = mock_ai.client.messages.create.call_args
    messages = create_call.kwargs["messages"]
    last_msg = messages[-1]["content"]
    assert "[ShieldBot Data]" in last_msg
    assert "rug_probability" in last_msg


@pytest.mark.asyncio
async def test_chat_includes_history(advisor, mock_db, mock_ai):
    """chat() includes previous messages from history."""
    mock_db.get_chat_history = AsyncMock(return_value=[
        {"role": "user", "message": "Hello"},
        {"role": "assistant", "message": "Hi there!"},
    ])
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="Sure, what would you like to know?")]
    mock_ai.client.messages.create = AsyncMock(return_value=mock_response)

    await advisor.chat("user789", "Tell me more")

    create_call = mock_ai.client.messages.create.call_args
    messages = create_call.kwargs["messages"]
    # History + new message = 3 messages
    assert len(messages) == 3
    assert messages[0]["role"] == "user"
    assert messages[0]["content"] == "Hello"
    assert messages[1]["role"] == "assistant"
    assert messages[1]["content"] == "Hi there!"


@pytest.mark.asyncio
async def test_chat_without_ai(advisor_no_ai, mock_db):
    """When AI is disabled, returns a fallback message without calling the API."""
    response = await advisor_no_ai.chat("user999", "How does ShieldBot work?")

    assert "AI analysis is currently unavailable" in response
    # Should still save messages to history
    assert mock_db.insert_chat_message.await_count == 2


# ---------------------------------------------------------------------------
# explain_scan() tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_explain_scan(advisor, mock_ai):
    """explain_scan() calls Haiku with the formatted template."""
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="This contract has high risk.")]
    mock_ai.client.messages.create = AsyncMock(return_value=mock_response)

    scan = {"risk_score": 85, "risk_level": "HIGH", "flags": ["Honeypot"]}
    result = await advisor.explain_scan(scan)

    assert result == "This contract has high risk."
    create_call = mock_ai.client.messages.create.call_args
    assert create_call.kwargs["max_tokens"] == 300
    msg_content = create_call.kwargs["messages"][0]["content"]
    assert "risk_score" in msg_content


@pytest.mark.asyncio
async def test_explain_scan_without_ai(advisor_no_ai):
    """When AI disabled, returns rule-based explanation from risk_score."""
    # High risk
    result = await advisor_no_ai.explain_scan({"risk_score": 85, "risk_level": "HIGH"})
    assert "high" in result.lower() or "dangerous" in result.lower() or "risk" in result.lower()

    # Low risk
    result = await advisor_no_ai.explain_scan({"risk_score": 15, "risk_level": "LOW"})
    assert "low" in result.lower() or "safe" in result.lower()

    # Medium risk
    result = await advisor_no_ai.explain_scan({"risk_score": 50, "risk_level": "MEDIUM"})
    assert "moderate" in result.lower() or "caution" in result.lower() or "medium" in result.lower()
