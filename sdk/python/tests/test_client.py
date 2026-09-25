"""Tests for the ShieldBot Python SDK client."""

import pytest
import json
import httpx
from enum import IntEnum
from unittest.mock import AsyncMock, patch, MagicMock
from shieldbot.client import ShieldBot, ShieldBotError
from shieldbot.models import Verdict


@pytest.fixture
def sb():
    return ShieldBot(api_key="sb_test", agent_id="agent:1", base_url="http://localhost:8000")


@pytest.mark.asyncio
async def test_check_returns_verdict(sb):
    """check() returns a Verdict object."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "ok", "coverage": {"honeypot": 1},
        "verdict": "ALLOW", "score": 12, "flags": [],
        "policy_check": {"passed": True, "checks": {}, "failed": [], "needs_owner_approval": False},
        "cached": False, "latency_ms": 100,
    }
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        verdict = await sb.check({
            "from": "0xAgent", "to": "0xTarget", "chain_id": 56,
        })
    assert isinstance(verdict, Verdict)
    assert verdict.allowed is True
    assert verdict.score == 12
    assert verdict.verdict == "ALLOW"


@pytest.mark.asyncio
async def test_check_block_verdict(sb):
    """BLOCK verdict sets allowed=False."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "verdict": "BLOCK", "score": 91, "flags": ["honeypot"],
        "policy_check": {"passed": False, "checks": {}, "failed": ["risk_threshold"], "needs_owner_approval": False},
        "cached": False, "latency_ms": 380,
    }
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        verdict = await sb.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert verdict.allowed is False
    assert verdict.blocked is True
    assert "honeypot" in verdict.flags


@pytest.mark.asyncio
async def test_local_cache_hit(sb):
    """Second check for the same transaction uses local cache."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "ok", "coverage": {"honeypot": 1},
        "verdict": "ALLOW", "score": 5, "flags": [],
        "policy_check": {"passed": True, "checks": {}, "failed": [], "needs_owner_approval": False},
        "cached": False, "latency_ms": 100,
    }
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp) as mock_post:
        transaction = {"from": "0xA", "to": "0xSame", "chain_id": 56, "data": "0x1234", "value": "1"}
        await sb.check(transaction)
        v2 = await sb.check(dict(transaction))
    # Only 1 HTTP call — second was cached
    assert mock_post.call_count == 1
    assert v2.score == 5


@pytest.mark.asyncio
async def test_a_cache_hit_is_a_copy_marked_cached_that_callers_cannot_poison(sb):
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "status": "ok", "coverage": {"honeypot": 1}, "verdict": "ALLOW", "score": 5, "cached": False,
    }
    transaction = {"from": "0xA", "to": "0xB", "chain_id": 56}
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response) as post:
        fresh = await sb.check(transaction)
        fresh.verdict, fresh.score = "BLOCK", 99
        first_hit = await sb.check(transaction)
        first_hit.verdict, first_hit.score = "BLOCK", 99
        second_hit = await sb.check(transaction)
    assert post.await_count == 1
    assert fresh.cached is False
    assert first_hit.cached is True
    assert second_hit is not first_hit
    assert (second_hit.verdict, second_hit.score, second_hit.cached) == ("ALLOW", 5, True)
    assert (second_hit.status, second_hit.risk_display, second_hit.allowed) == ("ok", "5%", True)


@pytest.mark.asyncio
async def test_equivalent_transaction_encodings_reuse_cache(sb):
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "status": "ok", "coverage": {"honeypot": 1},
        "verdict": "ALLOW", "score": 5, "flags": [],
    }
    transaction = {
        "from": "0x52908400098527886E0F7030069857D2E4169EE7",
        "to": "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        "chain_id": 56,
        "data": "0xABCD", "value": "0",
    }
    with patch(
        "shieldbot.client.httpx.AsyncClient.post",
        new_callable=AsyncMock,
        return_value=response,
    ) as post:
        await sb.check(transaction)
        await sb.check({
            **transaction,
            "from": transaction["from"].lower(),
            "to": transaction["to"].lower(),
            "data": transaction["data"].lower(),
            "value": "0x0",
        })
        await sb.check({
            **transaction,
            "from": transaction["from"].lower(),
            "to": transaction["to"].lower(),
            "data": transaction["data"].lower(),
            "value": 0,
        })
    assert post.await_count == 1


@pytest.mark.asyncio
async def test_hex_and_decimal_encodings_of_one_value_share_the_cache(sb):
    response = MagicMock(status_code=200)
    response.json.return_value = {"status": "ok", "coverage": {"honeypot": 1}, "verdict": "ALLOW", "score": 5}
    transaction = {"from": "0xA", "to": "0xB", "chain_id": 56, "value": "0x10"}
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response) as post:
        await sb.check(transaction)
        second = await sb.check({**transaction, "value": "16"})
    assert post.await_count == 1
    assert second.allowed


@pytest.mark.asyncio
@pytest.mark.parametrize("first_value,second_value", [
    ("0x10", "10"),
])
async def test_different_value_encodings_do_not_share_cache(sb, first_value, second_value):
    allow = MagicMock(status_code=200)
    allow.json.return_value = {
        "status": "ok", "coverage": {"honeypot": 1},
        "verdict": "ALLOW", "score": 5, "flags": [],
    }
    block = MagicMock(status_code=200)
    block.json.return_value = {"verdict": "BLOCK", "score": 90}
    transaction = {
        "from": "0xAgent", "to": "0xTarget", "chain_id": 56,
        "data": "0x1234", "value": first_value,
    }
    with patch(
        "shieldbot.client.httpx.AsyncClient.post",
        new_callable=AsyncMock,
        side_effect=[allow, block],
    ) as post:
        await sb.check(transaction)
        second = await sb.check({**transaction, "value": second_value})
    assert post.await_count == 2
    assert second.blocked


class Wei(int):
    pass


@pytest.mark.asyncio
@pytest.mark.parametrize("value,sent", [
    ("0x10", "16"),
    ("0X10", "16"),
    ("0x0010", "16"),
    ("16", "16"),
    ("0016", "16"),
    (" 16 ", "16"),
    (16, "16"),
    (Wei(16), "16"),
    ("0", "0"),
    (None, "0"),
    ("0x" + "f" * 64, str(2**256 - 1)),
    (str(2**256 - 1), str(2**256 - 1)),
])
async def test_value_is_sent_as_decimal_wei(sb, value, sent):
    response = MagicMock(status_code=200)
    response.json.return_value = {"status": "ok", "coverage": {"honeypot": 1}, "verdict": "ALLOW", "score": 5}
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response) as post:
        await sb.check({"from": "0xA", "to": "0xB", "chain_id": 56, "value": value})
    assert post.await_args.kwargs["json"]["transaction"]["value"] == sent


@pytest.mark.asyncio
async def test_missing_value_is_sent_as_zero(sb):
    response = MagicMock(status_code=200)
    response.json.return_value = {"status": "ok", "coverage": {"honeypot": 1}, "verdict": "ALLOW", "score": 5}
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response) as post:
        await sb.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert post.await_args.kwargs["json"]["transaction"]["value"] == "0"


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [
    "not-a-number", "", "-1", "0b1", "1.5", "1e18", "1_000", 1.5, -1, True,
    str(2**256), "0x1" + "0" * 64, 2**256,
])
async def test_unparseable_value_is_rejected_before_any_request(value):
    client = ShieldBot(api_key="sb_test", agent_id="agent:1", fail_mode="open")
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock) as post:
        with pytest.raises(ValueError, match="value must be"):
            await client.check({"from": "0xA", "to": "0xB", "chain_id": 56, "value": value})
    post.assert_not_awaited()
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", ["56", "0x38", " 56 ", 56.0, 0, -1, True, False, Wei(0)])
async def test_chain_id_that_is_not_a_positive_int_is_rejected_before_any_request(chain_id):
    client = ShieldBot(api_key="sb_test", agent_id="agent:1", fail_mode="open")
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock) as post:
        with pytest.raises(ValueError, match="chain_id must be a positive int"):
            await client.check({"from": "0xA", "to": "0xB", "chain_id": chain_id})
    post.assert_not_awaited()
    await client.close()


@pytest.mark.parametrize("timeout", [0, -1, 0.0, float("nan"), float("inf"), "10", None, True])
def test_a_timeout_that_is_not_a_positive_number_is_rejected(timeout):
    with pytest.raises(ValueError, match="timeout must be a positive number of seconds"):
        ShieldBot(api_key="sb_test", agent_id="agent:1", timeout=timeout)


@pytest.mark.parametrize("cache_size", [-1, 1.5, "10", None, True])
def test_a_cache_size_that_is_not_an_int_of_0_or_more_is_rejected(cache_size):
    with pytest.raises(ValueError, match="cache_size must be an int of 0 or more"):
        ShieldBot(api_key="sb_test", agent_id="agent:1", cache_size=cache_size)


@pytest.mark.parametrize("options", [
    {"timeout": 0.5}, {"timeout": 10}, {"cache_size": 0}, {"cache_size": 1}, {"cache_size": Wei(5)},
])
def test_a_positive_timeout_and_a_cache_size_of_0_or_more_are_accepted(options):
    ShieldBot(api_key="sb_test", agent_id="agent:1", **options)


@pytest.mark.asyncio
async def test_cache_size_0_turns_the_cache_off():
    client = ShieldBot(api_key="sb_test", agent_id="agent:1", cache_size=0)
    response = MagicMock(status_code=200)
    response.json.return_value = {"status": "ok", "coverage": {"honeypot": 1}, "verdict": "ALLOW", "score": 5}
    transaction = {"from": "0xA", "to": "0xB", "chain_id": 56}
    with patch(
        "shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock,
        side_effect=[response, response, httpx.ConnectError("offline")],
    ) as post:
        await client.check(transaction)
        second = await client.check(transaction)
        offline = await client.check(transaction)
    assert post.await_count == 3
    assert second.cached is False
    assert (offline.verdict, offline.cached, offline.analysis_unavailable) == ("WARN", False, True)
    await client.close()


class Chain(IntEnum):
    BSC = 56


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_id", [56, Wei(56), Chain.BSC])
async def test_an_int_chain_id_including_a_subclass_is_sent_as_a_plain_int(sb, chain_id):
    response = MagicMock(status_code=200)
    response.json.return_value = {"status": "ok", "coverage": {"honeypot": 1}, "verdict": "ALLOW", "score": 5}
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response) as post:
        verdict = await sb.check({"from": "0xA", "to": "0xB", "chain_id": chain_id})
    sent = post.await_args.kwargs["json"]["transaction"]["chain_id"]
    assert (sent, type(sent)) == (56, int)
    assert verdict.allowed


@pytest.mark.asyncio
async def test_an_intenum_chain_shares_the_cache_entry_of_its_int(sb):
    response = MagicMock(status_code=200)
    response.json.return_value = {"status": "ok", "coverage": {"honeypot": 1}, "verdict": "ALLOW", "score": 5}
    transaction = {"from": "0xA", "to": "0xB", "chain_id": 56}
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response) as post:
        await sb.check(transaction)
        hit = await sb.check({**transaction, "chain_id": Chain.BSC})
    assert post.await_count == 1
    assert hit.cached is True


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    ("from", "0xOther"),
    ("to", "0xOther"),
    ("chain_id", 1),
    ("data", "0x095ea7b3" + "0" * 24 + "1" * 40 + "f" * 64),
    ("value", "2"),
])
async def test_cached_allow_does_not_authorize_different_transaction(sb, field, value):
    transaction = {
        "from": "0xAgent", "to": "0xTarget", "chain_id": 56,
        "data": "0x095ea7b3" + "0" * 24 + "1" * 40 + "0" * 63 + "1",
        "value": "1",
    }
    allow = MagicMock(status_code=200)
    allow.json.return_value = {
        "status": "ok", "coverage": {"honeypot": 1},
        "verdict": "ALLOW", "score": 5, "flags": [],
    }
    block = MagicMock(status_code=200)
    block.json.return_value = {"verdict": "BLOCK", "score": 90}
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=[allow, block]) as post:
        first = await sb.check(transaction)
        second = await sb.check({**transaction, field: value})
    assert first.allowed
    assert post.await_count == 2
    assert second.blocked
    await sb.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("cache_ttl,expiry", [(None, 60), (2, 2), (0, 0)])
async def test_expired_allow_is_not_used_when_api_unreachable(cache_ttl, expiry):
    options = {} if cache_ttl is None else {"cache_ttl": cache_ttl}
    client = ShieldBot(api_key="sb_test", agent_id="agent:1", **options)
    transaction = {"from": "0xAgent", "to": "0xTarget", "data": "0x1234", "value": "1", "chain_id": 56}
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "status": "ok", "coverage": {"honeypot": 1},
        "verdict": "ALLOW", "score": 5, "flags": [],
    }
    with patch("shieldbot.client.time.time", return_value=1000) as now, patch(
        "shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock,
        side_effect=[response, httpx.ConnectError("offline")],
    ) as post:
        first = await client.check(transaction)
        now.return_value += expiry
        second = await client.check(transaction)
    assert first.allowed
    assert post.await_count == 2
    assert not second.allowed
    assert second.analysis_unavailable
    await client.close()


def test_verdict_properties():
    """Verdict model properties work correctly."""
    v = Verdict(verdict="ALLOW", score=12, status="ok", coverage={"honeypot": 1}, flags=[], evidence=None,
                policy_check={}, cached=False, latency_ms=100)
    assert v.allowed is True
    assert v.blocked is False

    v2 = Verdict(verdict="BLOCK", score=91, flags=["honeypot"], evidence="scam",
                 policy_check={}, cached=False, latency_ms=380)
    assert v2.allowed is False
    assert v2.blocked is True


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,label", [
    (401, "unauthorized"),
    (403, "forbidden"),
    (404, "not found"),
    (429, "rate limited"),
])
async def test_4xx_raises_shieldbot_error(sb, status_code, label):
    """4xx errors raise ShieldBotError instead of returning a fail-mode verdict."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = label
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        with pytest.raises(ShieldBotError) as exc_info:
            await sb.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert exc_info.value.status_code == status_code
    assert label in exc_info.value.message


@pytest.mark.asyncio
async def test_500_uses_fail_mode(sb):
    """5xx server errors use fail-mode (WARN for default cached with no cached verdict) instead of raising."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        verdict = await sb.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert isinstance(verdict, Verdict)
    assert verdict.verdict == "WARN"
    assert "api_unavailable" in verdict.flags


@pytest.mark.asyncio
async def test_500_fail_closed():
    """5xx with fail_mode='closed' returns BLOCK verdict."""
    client = ShieldBot(api_key="sb_test", agent_id="agent:1",
                       base_url="http://localhost:8000", fail_mode="closed")
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_resp.text = "Bad Gateway"
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        verdict = await client.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert verdict.verdict == "BLOCK"
    assert "api_unavailable" in verdict.flags


@pytest.mark.asyncio
async def test_network_error_uses_fail_mode(sb):
    """Network errors (connection refused, DNS failure) use fail-mode."""
    with patch("shieldbot.client.httpx.AsyncClient.post", new_callable=AsyncMock,
               side_effect=httpx.ConnectError("Connection refused")):
        verdict = await sb.check({"from": "0xA", "to": "0xB", "chain_id": 56})
    assert isinstance(verdict, Verdict)
    assert verdict.verdict == "WARN"
    assert "api_unavailable" in verdict.flags


@pytest.mark.asyncio
async def test_shieldbot_error_exported():
    """ShieldBotError is importable from the top-level package."""
    from shieldbot import ShieldBotError as SBE
    err = SBE(401, "bad key")
    assert err.status_code == 401
    assert "bad key" in str(err)
