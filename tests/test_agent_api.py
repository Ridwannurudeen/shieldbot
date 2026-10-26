from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    import api as api_module
    from utils.web3_client import Web3Client

    web3_client = Web3Client.__new__(Web3Client)
    web3_client._adapters = {56: MagicMock(), 1: MagicMock()}
    monkeypatch.setattr(api_module, "web3_client", web3_client)

    advisor = MagicMock()
    advisor.chat = AsyncMock(return_value={"text": "This contract looks risky."})
    advisor.explain_scan = AsyncMock(return_value="High sell tax detected.")

    api_module.container = SimpleNamespace(
        db=MagicMock(),
        settings=SimpleNamespace(trusted_proxies=[]),
        advisor=advisor,
    )

    # Reset rate limiters so tests don't bleed into each other
    api_module.rate_limiter = api_module.RateLimiter(
        requests_per_minute=50, burst=10,
    )
    api_module.chat_limiter = api_module.RateLimiter(
        requests_per_minute=50, burst=10,
    )

    return TestClient(api_module.app, raise_server_exceptions=False)


def test_chat_success(client):
    response = client.post(
        "/api/agent/chat",
        json={"message": "Is this contract safe?", "user_id": "user123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["response"] == "This contract looks risky."
    assert data["user_id"] == "user123"


def test_chat_empty_message(client):
    response = client.post(
        "/api/agent/chat",
        json={"message": "", "user_id": "user123"},
    )
    assert response.status_code == 422


def test_chat_calls_advisor(client):
    import api as api_module
    import hashlib

    advisor = api_module.container.advisor

    client.post(
        "/api/agent/chat",
        json={"message": "Check 0xdead", "user_id": "user42"},
    )

    # user_id is bound to client IP: sha256("testclient:user42")[:24]
    # TestClient uses "testclient" as the client host
    bound_id = hashlib.sha256("testclient:user42".encode()).hexdigest()[:24]
    advisor.chat.assert_awaited_once_with(bound_id, "Check 0xdead", chain_id=56)


def test_explain_success(client):
    response = client.post(
        "/api/agent/explain",
        json={"scan_result": {"risk_score": 85, "risk_level": "HIGH", "status": "ok", "coverage": {"honeypot": 1}}},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["explanation"] == "High sell tax detected."


def test_explain_calls_advisor(client):
    import api as api_module

    advisor = api_module.container.advisor

    scan = {"risk_score": 85, "risk_level": "HIGH", "status": "ok", "coverage": {"honeypot": 1}}
    client.post("/api/agent/explain", json={"scan_result": scan})

    advisor.explain_scan.assert_awaited_once_with(scan)


# ---------------------------------------------------------------------------
# Additional coverage: chain_id, scan_data, error paths
# ---------------------------------------------------------------------------

def test_chat_forwards_chain_id(client):
    """Non-default chain_id is forwarded to advisor.chat()."""
    import api as api_module
    import hashlib

    advisor = api_module.container.advisor
    client.post(
        "/api/agent/chat",
        json={"message": "Check 0xdead", "user_id": "u1", "chain_id": 1},
    )
    bound_id = hashlib.sha256("testclient:u1".encode()).hexdigest()[:24]
    advisor.chat.assert_awaited_once_with(bound_id, "Check 0xdead", chain_id=1)


def test_chat_invalid_chain_id_zero(client):
    """chain_id=0 rejected before the advisor is called."""
    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1", "chain_id": 0})
    assert resp.status_code == 400


def test_chat_invalid_chain_id_negative(client):
    """Negative chain_id rejected."""
    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1", "chain_id": -5})
    assert resp.status_code == 400


def test_chat_response_includes_scan_data(client):
    """When advisor returns scan_data, it passes through in the HTTP response."""
    import api as api_module
    api_module.container.advisor.chat = AsyncMock(return_value={
        "text": "This is dangerous.",
        "scan_data": {"address": "0xdead", "risk_level": "HIGH", "risk_score": 90,
                      "status": "ok", "coverage": {"honeypot": 1}},
    })
    resp = client.post("/api/agent/chat", json={"message": "Check 0xdead", "user_id": "u1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"] == "This is dangerous."
    assert data["scan_data"]["risk_level"] == "HIGH"
    assert data["scan_data"]["address"] == "0xdead"


def test_chat_no_scan_data_when_absent(client):
    """When advisor returns no scan_data, the key is absent from the response."""
    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"})
    data = resp.json()
    assert "scan_data" not in data


def test_chat_backward_compat_string_return(client):
    """If advisor.chat returns a plain string (old behavior), API still works."""
    import api as api_module
    api_module.rate_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    api_module.chat_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    api_module.container.advisor.chat = AsyncMock(return_value="Plain string response")
    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"] == "Plain string response"
    assert "scan_data" not in data


def test_chat_advisor_exception_returns_500(client):
    """If advisor.chat() raises, API returns 500."""
    import api as api_module
    api_module.rate_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    api_module.chat_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    api_module.container.advisor.chat = AsyncMock(side_effect=RuntimeError("DB crash"))
    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"})
    assert resp.status_code == 500


def test_chat_no_advisor_returns_503(client):
    """If container is None, returns 503."""
    import api as api_module
    api_module.rate_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    api_module.chat_limiter = api_module.RateLimiter(requests_per_minute=50, burst=10)
    saved = api_module.container
    api_module.container = None
    try:
        resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"})
        assert resp.status_code == 503
    finally:
        api_module.container = saved


INSTALL_ID = "3f2c9a1e-8b7d-4c6e-9f10-2a4b6c8d0e12"


def test_chat_binds_history_to_the_install_id_not_the_ip(client):
    """With X-Install-Id the history key no longer depends on the client IP or the proxy setup."""
    import api as api_module
    import asyncio
    import hashlib
    from types import SimpleNamespace

    advisor = api_module.container.advisor
    client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"}, headers={"X-Install-Id": INSTALL_ID})
    bound_id = hashlib.sha256(f"install:{INSTALL_ID}:u1".encode()).hexdigest()[:24]
    advisor.chat.assert_awaited_once_with(bound_id, "hi", chain_id=56)

    request = SimpleNamespace(client=SimpleNamespace(host="203.0.113.9"), headers={"x-install-id": INSTALL_ID})
    asyncio.run(api_module.agent_chat(api_module.ChatRequest(message="hi", user_id="u1"), request))
    assert advisor.chat.await_args.args[0] == bound_id


def test_side_panel_sends_its_install_id_with_chat():
    """The side panel's chat request carries its per-install random id, the header the server keys history by."""
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "extension" / "sidepanel.js").read_text(encoding="utf-8")
    assert "chatUserId = crypto.randomUUID();" in source
    chat_fetch = source[source.index("/api/agent/chat"):]
    chat_fetch = chat_fetch[:chat_fetch.index("});")]
    assert '"X-Install-Id": chatUserId' in chat_fetch


@pytest.mark.parametrize("install_id", ["", "short", "x" * 129, "has space in it here", "10.0.0.1:user-ip-look"])
def test_chat_rejects_a_malformed_install_id(client, install_id):
    import api as api_module

    resp = client.post("/api/agent/chat", json={"message": "hi", "user_id": "u1"}, headers={"X-Install-Id": install_id})
    assert resp.status_code == 400
    api_module.container.advisor.chat.assert_not_called()

UNKNOWN_SCAN = {
    "address": "0xdead",
    "risk_level": "UNKNOWN",
    "risk_score": 0,
    "status": "unknown",
    "coverage": {"honeypot": 0},
    "coverage_reasons": {
        "honeypot": "Initialize logs scanned over blocks 87195168-87225167; No supported pool found; Unknown fields: buy_tax, sell_tax, can_sell"
    },
}
UNKNOWN_REPLY = (
    "ShieldBot could not finish checking this token, so it has no verdict.\n"
    "- no pool ShieldBot can simulate a sale on, so it could not test selling\n"
    "- buy tax, sell tax and whether the token can be sold are unknown"
)


def test_chat_unknown_drops_the_model_text_and_uses_readable_gaps(client):
    import api as api_module

    api_module.container.advisor.chat = AsyncMock(return_value={
        "text": "Selling could not be tested because no supported pool was found.",
        "model_response_available": True,
        "scan_data": UNKNOWN_SCAN,
    })
    response = client.post("/api/agent/chat", json={"message": "Check token", "user_id": "u1"})

    assert response.status_code == 200
    assert response.json()["response"] == UNKNOWN_REPLY
    assert "Initialize logs scanned over blocks" not in response.json()["response"]


def test_chat_unknown_without_model_returns_only_deterministic_gaps(client):
    import api as api_module

    api_module.container.advisor.chat = AsyncMock(return_value={
        "text": "AI analysis is currently unavailable.",
        "model_response_available": False,
        "scan_data": UNKNOWN_SCAN,
    })
    response = client.post("/api/agent/chat", json={"message": "Check token", "user_id": "u1"})

    assert response.status_code == 200
    assert response.json()["response"] == UNKNOWN_REPLY


def test_chat_coverage_reason_translation_and_clean_fallback():
    from core.chat_coverage import readable_coverage_gaps

    assert readable_coverage_gaps({"honeypot": UNKNOWN_SCAN["coverage_reasons"]["honeypot"]}) == [
        "no pool ShieldBot can simulate a sale on, so it could not test selling",
        "buy tax, sell tax and whether the token can be sold are unknown",
    ]
    assert readable_coverage_gaps({"scan": "Initialize logs scanned over blocks 12-34; New provider check unavailable"}) == [
        "New provider check unavailable"
    ]


def test_unknown_reply_carries_no_block_ranges_and_no_model_text():
    from core.chat_coverage import UNKNOWN_LINE, unknown_reply

    reply = unknown_reply(
        {"honeypot": "Initialize logs scanned over blocks 87222191-87252190; No supported pool found"},
    )
    assert "87222191" not in reply
    assert "blocks" not in reply
    assert reply == UNKNOWN_LINE + "\n- no pool ShieldBot can simulate a sale on, so it could not test selling"


@pytest.mark.parametrize("supported", [
    "Uniswap V3, Uniswap V2 or SushiSwap, paired with WETH",
    "BDEX V3 or BDEX V2, paired with WBOT",
    "V4 hookless or Doppler pools with ETH, WETH or USDG, or V3 or V2 pools with WETH",
])
def test_chat_coverage_names_the_pools_a_simulator_supports(supported):
    from core.chat_coverage import readable_coverage_gaps

    reason = f"Initialize logs scanned over blocks 12-34; No supported pool found ({supported}); Unknown fields: can_sell"
    assert readable_coverage_gaps({"honeypot": reason}) == [
        f"no pool ShieldBot can simulate a sale on ({supported}), so it could not test selling",
        "whether the token can be sold is unknown",
    ]


def test_chat_scan_data_carries_the_readable_coverage_gaps(client):
    import api as api_module

    api_module.container.advisor.chat = AsyncMock(return_value={
        "text": "AI analysis is currently unavailable.",
        "model_response_available": False,
        "scan_data": UNKNOWN_SCAN,
    })
    response = client.post("/api/agent/chat", json={"message": "Check token", "user_id": "u1"})

    assert response.json()["scan_data"]["coverage_gaps"] == [
        "no pool ShieldBot can simulate a sale on, so it could not test selling",
        "buy tax, sell tax and whether the token can be sold are unknown",
    ]


def test_chat_coverage_keeps_the_no_sell_reason_readable():
    from core.chat_coverage import readable_coverage_gaps

    reason = (
        "No supported pool found (BDEX V3 or BDEX V2, paired with WBOT); "
        "Own simulation made no sell (unresolved); "
        "Unknown fields: sell_tax, can_sell"
    )
    assert readable_coverage_gaps({"honeypot": reason}) == [
        "no pool ShieldBot can simulate a sale on (BDEX V3 or BDEX V2, paired with WBOT), so it could not test selling",
        "Own simulation made no sell (unresolved)",
        "sell tax and whether the token can be sold are unknown",
    ]


@pytest.mark.parametrize("text", [
    "The token appears fine and has no issues.",
    "can_sell is null; can_buy is true",
    "It looks safe.",
    "This one seems legit.",
    "There is nothing suspicious here.",
    "You should be fine buying a small amount.",
    "Risk 12.",
    "The risk is 0%.",
    "El token es seguro.",
    "Riesgo 0 de 100, sin problemas.",
    "该代币是安全的。",
    "Score 12 / 100, low.",
    "Selling could not be tested because no supported pool was found.",
])
def test_chat_unknown_reply_never_carries_model_text(client, text):
    """An incomplete scan's reply is the server's own: no model sentence, in any words or language, reaches it."""
    import api as api_module

    api_module.container.advisor.chat = AsyncMock(return_value={
        "text": text, "model_response_available": True, "scan_data": UNKNOWN_SCAN,
    })
    response = client.post("/api/agent/chat", json={"message": "Check token", "user_id": "u1"})

    assert response.json()["response"] == UNKNOWN_REPLY
    assert text not in response.json()["response"]


OBSERVED = (
    "\n\nWhat ShieldBot did observe:\n- Contract age 0 days\n- Source code verified\n- Scam database: no match"
    "\n- Liquidity $24,472.84\n- 24h volume $48,096.40\n- Pair age 4.1 hours\n- New pair (under 24 hours old)"
)
CREATOR = "0x" + "ab" * 20
CONTRACT = {"contract_age_days": 0, "is_verified": True, "scam_matches": [], "creator_address": CREATOR,
            "coverage": {"is_verified": True, "contract_age_days": True, "scam_database": True}}
MARKET = {"price_usd": 0.0001, "liquidity_usd": 24472.84, "volume_24h": 48096.4, "pair_age_hours": 4.1}
COVERAGE = {"structural": 1, "market": 1, "behavioral": 1, "honeypot": 0}
FLAGS = ["Market data unknown: DexScreener unavailable",
         f"Creator {CREATOR} carries GoPlus address labels: honeypot_related_address",
         "Sellability unknown: No supported pool found; Unknown fields: can_sell"]


def test_unknown_reply_lists_only_covered_structured_values_in_fixed_words():
    from core.chat_coverage import observed_facts, unknown_reply

    reasons = UNKNOWN_SCAN["coverage_reasons"]
    assert unknown_reply(reasons, observed_facts(COVERAGE, MARKET, CONTRACT)) == UNKNOWN_REPLY + OBSERVED
    # An uncovered field is never an observation: market the scan did not cover, an age it could not read.
    assert observed_facts({**COVERAGE, "market": 0}, MARKET, CONTRACT) == [
        "Contract age 0 days", "Source code verified", "Scam database: no match",
    ]
    unread_age = {**CONTRACT, "contract_age_days": None, "coverage": {**CONTRACT["coverage"], "contract_age_days": False}}
    assert observed_facts(COVERAGE, {}, unread_age) == ["Source code verified", "Scam database: no match"]
    assert observed_facts({}, None, None) == []
    # A scam database match and an unverified source read in the same fixed words; a community report is no match.
    flagged = {**CONTRACT, "is_verified": False,
               "scam_matches": [{"source": "GoPlus", "severity": "block"}, {"source": "community", "severity": "medium"}]}
    assert observed_facts({}, None, flagged) == ["Contract age 0 days", "Source code not verified", "Scam database: 1 match"]
    assert unknown_reply(reasons, observed_facts({}, {}, {})) == UNKNOWN_REPLY


def test_chat_unknown_reply_lists_what_the_scan_observed_and_never_a_flag(client):
    """The observed list is built from covered values in the server's words: no flag, no reason, no address."""
    import api as api_module

    api_module.container.advisor.chat = AsyncMock(return_value={
        "text": "It looks safe.", "model_response_available": True,
        "scan_data": {**UNKNOWN_SCAN, "flags": FLAGS, "market": MARKET, "contract": CONTRACT, "coverage": COVERAGE},
    })
    response = client.post("/api/agent/chat", json={"message": "Check token", "user_id": "u1"})

    assert response.json()["response"] == UNKNOWN_REPLY + OBSERVED
    for flag in FLAGS:
        assert flag not in response.json()["response"]
    assert CREATOR not in response.json()["response"]

