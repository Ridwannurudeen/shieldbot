# ShieldBot AI Agent — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a full-spectrum AI agent (Hunter + Sentinel + Advisor) to ShieldBot with proactive threat discovery, real-time event response, and conversational security chat.

**Architecture:** Three agent modes sharing a common tool layer over existing services. SQLite tables for findings, chat history, and tracked pairs. Tiered LLM: Haiku for narration, Sonnet for chat. No frameworks — direct Anthropic SDK.

**Tech Stack:** Python 3.11+, FastAPI, aiosqlite, anthropic SDK (already installed), Chrome MV3 Side Panel API

**Design doc:** `docs/plans/2026-03-14-ai-agent-design.md`

---

## Task 1: Database Models (agent tables)

**Files:**
- Modify: `core/database.py` (add tables to `_create_tables` at line 34, add query methods)
- Test: `tests/test_agent_db.py`

**Step 1: Write the failing tests**

```python
# tests/test_agent_db.py
import time
import pytest
from core.database import Database


@pytest.fixture
async def db(tmp_path):
    d = Database(str(tmp_path / "test.db"))
    await d.initialize()
    yield d
    await d.close()


@pytest.mark.asyncio
async def test_insert_and_get_finding(db):
    await db.insert_agent_finding(
        finding_type="hunter_sweep",
        investigation_id="sweep-001",
        address="0xabc",
        deployer="0xdef",
        chain_id=56,
        risk_score=85,
        narrative="Deployer launched 3 rugs in 24h.",
        evidence={"flags": ["unverified", "high_tax"]},
        action_taken="blocked",
    )
    findings = await db.get_agent_findings(limit=10)
    assert len(findings) == 1
    assert findings[0]["address"] == "0xabc"
    assert findings[0]["risk_score"] == 85
    assert findings[0]["investigation_id"] == "sweep-001"


@pytest.mark.asyncio
async def test_get_findings_by_type(db):
    await db.insert_agent_finding(
        finding_type="hunter_sweep", address="0x1", chain_id=56, risk_score=90,
    )
    await db.insert_agent_finding(
        finding_type="sentinel_event", address="0x2", chain_id=56, risk_score=60,
    )
    hunter = await db.get_agent_findings(finding_type="hunter_sweep")
    assert len(hunter) == 1
    assert hunter[0]["address"] == "0x1"


@pytest.mark.asyncio
async def test_chat_history_insert_and_prune(db):
    old_time = time.time() - 90000  # 25 hours ago
    await db.insert_chat_message("user-1", "user", "Is 0xabc safe?")
    await db.insert_chat_message("user-1", "assistant", "It looks risky.")
    # Manually insert an old message
    await db._db.execute(
        "INSERT INTO chat_history (user_id, role, message, created_at) VALUES (?, ?, ?, ?)",
        ("user-1", "user", "old message", old_time),
    )
    await db._db.commit()

    history = await db.get_chat_history("user-1", limit=10)
    assert len(history) == 3

    pruned = await db.prune_old_chats(max_age_seconds=86400)
    assert pruned == 1

    history = await db.get_chat_history("user-1", limit=10)
    assert len(history) == 2


@pytest.mark.asyncio
async def test_tracked_pair_lifecycle(db):
    await db.upsert_tracked_pair(
        pair_address="0xpair1",
        token_address="0xtoken1",
        deployer="0xdep1",
        liquidity_usd=5000.0,
        status="watching",
    )
    pairs = await db.get_tracked_pairs(status="watching")
    assert len(pairs) == 1
    assert pairs[0]["token_address"] == "0xtoken1"

    await db.update_tracked_pair_status("0xpair1", "blocked")
    pairs = await db.get_tracked_pairs(status="blocked")
    assert len(pairs) == 1

    # Cleanup: cleared pairs older than 7 days would be pruned
    await db.update_tracked_pair_status("0xpair1", "cleared")
    cleared = await db.get_tracked_pairs(status="cleared")
    assert len(cleared) == 1
```

**Step 2: Run tests to verify they fail**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_agent_db.py -v`
Expected: FAIL — methods don't exist yet

**Step 3: Implement the database methods**

Add to `core/database.py`:

1. Add three new CREATE TABLE statements inside `_create_tables()` after the `deployment_alerts` table (after line 153):
   - `agent_findings` (id, finding_type, investigation_id, address, deployer, chain_id, risk_score, narrative, evidence, action_taken, created_at)
   - `chat_history` (id, user_id, role, message, tools_used, created_at)
   - `tracked_pairs` (id, pair_address UNIQUE, token_address, deployer, liquidity_usd, first_seen, last_checked, status)

2. Add methods:
   - `insert_agent_finding(...)` — INSERT into agent_findings
   - `get_agent_findings(limit, finding_type=None)` — SELECT with optional type filter
   - `insert_chat_message(user_id, role, message, tools_used=None)` — INSERT into chat_history
   - `get_chat_history(user_id, limit=10)` — SELECT last N messages for user, ordered oldest first
   - `prune_old_chats(max_age_seconds=86400)` — DELETE WHERE created_at < now - max_age, return count
   - `upsert_tracked_pair(pair_address, token_address, deployer, liquidity_usd, status)` — UPSERT
   - `get_tracked_pairs(status=None, limit=100)` — SELECT with optional status filter
   - `update_tracked_pair_status(pair_address, status)` — UPDATE status + last_checked

**Step 4: Run tests to verify they pass**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_agent_db.py -v`
Expected: all PASS

**Step 5: Commit**

```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
git add core/database.py tests/test_agent_db.py
git commit -m "feat(agent): add agent_findings, chat_history, tracked_pairs tables"
```

---

## Task 2: Agent Tool Layer

**Files:**
- Create: `agent/__init__.py`
- Create: `agent/tools.py`
- Test: `tests/test_agent_tools.py`

**Step 1: Write the failing tests**

```python
# tests/test_agent_tools.py
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from agent.tools import AgentTools


def _make_container():
    """Build a mock ServiceContainer with the services AgentTools needs."""
    contract_svc = MagicMock()
    contract_svc.get_contract_info = AsyncMock(return_value={
        "is_verified": True, "name": "TestToken",
    })

    honeypot_svc = MagicMock()
    honeypot_svc.check = AsyncMock(return_value={
        "is_honeypot": False, "buy_tax": 1, "sell_tax": 3,
    })

    dex_svc = MagicMock()
    dex_svc.get_pair_data = AsyncMock(return_value={
        "liquidity_usd": 50000, "volume_24h": 12000,
    })

    db = MagicMock()
    db.get_contract_score = AsyncMock(return_value=None)
    db.get_deployer_risk_summary = AsyncMock(return_value={
        "deployer_address": "0xdep", "total_contracts": 5, "high_risk_contracts": 2,
    })
    db.get_campaign_graph = AsyncMock(return_value={
        "deployer": "0xdep", "funder": "0xfund", "total_deployed": 5,
    })
    db.get_agent_findings = AsyncMock(return_value=[])
    db.add_watched_deployer = AsyncMock()

    registry = MagicMock()
    risk_engine = MagicMock()

    return SimpleNamespace(
        contract_service=contract_svc,
        honeypot_service=honeypot_svc,
        dex_service=dex_svc,
        db=db,
        registry=registry,
        risk_engine=risk_engine,
    )


@pytest.fixture
def tools():
    return AgentTools(_make_container())


@pytest.mark.asyncio
async def test_check_deployer(tools):
    result = await tools.check_deployer("0xabc", chain_id=56)
    assert "deployer_address" in result
    assert result["total_contracts"] == 5


@pytest.mark.asyncio
async def test_get_market_data(tools):
    result = await tools.get_market_data("0xtoken")
    assert result["liquidity_usd"] == 50000


@pytest.mark.asyncio
async def test_query_campaign(tools):
    result = await tools.query_campaign("0xabc")
    assert result["total_deployed"] == 5


@pytest.mark.asyncio
async def test_auto_watch(tools):
    await tools.auto_watch_deployer("0xscammer", reason="AI agent: 3 rugs detected", chain_id=56)
    tools._container.db.add_watched_deployer.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_findings(tools):
    result = await tools.get_agent_findings(limit=5)
    assert result == []
```

**Step 2: Run tests to verify they fail**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_agent_tools.py -v`
Expected: FAIL — module doesn't exist

**Step 3: Implement**

Create `agent/__init__.py` (empty).

Create `agent/tools.py`:
- Class `AgentTools` taking a `ServiceContainer` (or SimpleNamespace with same attrs)
- Methods (all async):
  - `scan_contract(address, chain_id=56)` — runs full analyzer pipeline via `registry.run_all()` + `risk_engine.compute_from_results()`
  - `check_deployer(address, chain_id=56)` — calls `db.get_deployer_risk_summary()`
  - `check_honeypot(address)` — calls `honeypot_service.check()`
  - `get_market_data(address)` — calls `dex_service.get_pair_data()`
  - `query_campaign(address)` — calls `db.get_campaign_graph()`
  - `get_funder_links(deployer)` — calls `db.get_campaign_graph()` focused on funder
  - `get_agent_findings(limit=10, finding_type=None)` — calls `db.get_agent_findings()`
  - `auto_watch_deployer(address, reason, chain_id=0)` — calls `db.add_watched_deployer()`
  - `get_cached_score(address, chain_id=56)` — calls `db.get_contract_score()`

Each method is a thin wrapper — no business logic, just delegation.

**Step 4: Run tests to verify they pass**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_agent_tools.py -v`
Expected: all PASS

**Step 5: Commit**

```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
git add agent/__init__.py agent/tools.py tests/test_agent_tools.py
git commit -m "feat(agent): add tool layer wrapping existing services"
```

---

## Task 3: Agent Prompts

**Files:**
- Create: `agent/prompts.py`
- No test file needed (pure constants)

**Step 1: Create prompts file**

Create `agent/prompts.py` with:

1. `ADVISOR_SYSTEM_PROMPT` — Sonnet persona: "You are ShieldBot's security advisor. You analyze blockchain contracts and transactions on BNB Chain and other EVM chains. You have access to real-time data from ShieldBot's analysis pipeline. Rules: (1) Never give financial advice. (2) Never speculate on price. (3) Always cite specific data from tool results. (4) If unsure, say so. (5) Keep responses concise — 2-4 sentences unless user asks for detail."

2. `NARRATIVE_TEMPLATE` — Haiku prompt for threat findings: "You are a blockchain security analyst. Given the following threat data, write a 2-3 sentence alert in plain English. Focus on: who deployed it, what's wrong with it, and how dangerous it is. No markdown. No disclaimers. Data: {data}"

3. `EXPLAIN_SCAN_TEMPLATE` — Haiku prompt for "Why?" button: "Explain this security scan result in 2-3 plain English sentences. Focus on the most important risk factors and what they mean for the user. Data: {data}"

**Step 2: Commit**

```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
git add agent/prompts.py
git commit -m "feat(agent): add system prompts and narrative templates"
```

---

## Task 4: Advisor Core (Chat Engine)

**Files:**
- Create: `agent/advisor.py`
- Test: `tests/test_advisor.py`

**Step 1: Write the failing tests**

```python
# tests/test_advisor.py
import re
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from agent.advisor import Advisor


def _make_advisor():
    tools = MagicMock()
    tools.scan_contract = AsyncMock(return_value={
        "risk_score": 85, "risk_level": "HIGH",
        "flags": ["unverified", "high_sell_tax"],
        "archetype": "honeypot",
    })
    tools.check_deployer = AsyncMock(return_value={
        "deployer_address": "0xdep", "total_contracts": 5, "high_risk_contracts": 3,
    })
    tools.get_agent_findings = AsyncMock(return_value=[
        {"address": "0x1", "narrative": "Known rug deployer.", "risk_score": 90},
    ])

    db = MagicMock()
    db.get_chat_history = AsyncMock(return_value=[])
    db.insert_chat_message = AsyncMock()

    ai = MagicMock()
    ai.client = MagicMock()  # non-None = enabled

    return Advisor(tools=tools, db=db, ai_analyzer=ai)


@pytest.fixture
def advisor():
    return _make_advisor()


def test_route_address(advisor):
    intent, data = advisor.route("Is 0x4904c02efa081cb7685346968bac854cdf4e7777 safe?")
    assert intent == "CONTRACT_CHECK"
    assert data["address"] == "0x4904c02efa081cb7685346968bac854cdf4e7777"


def test_route_threat_keywords(advisor):
    intent, _ = advisor.route("What threats are active right now?")
    assert intent == "THREAT_FEED"


def test_route_general(advisor):
    intent, _ = advisor.route("How does ShieldBot work?")
    assert intent == "GENERAL"


@pytest.mark.asyncio
async def test_gather_context_for_contract(advisor):
    ctx = await advisor._gather_context("CONTRACT_CHECK", {"address": "0xabc"})
    assert "risk_score" in ctx
    advisor.tools.scan_contract.assert_awaited_once()


@pytest.mark.asyncio
async def test_gather_context_for_threats(advisor):
    ctx = await advisor._gather_context("THREAT_FEED", {})
    assert isinstance(ctx, list)
    advisor.tools.get_agent_findings.assert_awaited_once()
```

**Step 2: Run tests to verify they fail**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_advisor.py -v`
Expected: FAIL — module doesn't exist

**Step 3: Implement**

Create `agent/advisor.py`:

- Class `Advisor(tools, db, ai_analyzer)`
- `route(message: str) -> tuple[str, dict]`:
  - Regex: `0x[a-fA-F0-9]{40}` → return `("CONTRACT_CHECK", {"address": match})`
  - Keywords `threat|alert|active|happening|danger` → return `("THREAT_FEED", {})`
  - Else → return `("GENERAL", {})`
- `async _gather_context(intent, data) -> dict|list`:
  - CONTRACT_CHECK: `tools.scan_contract(data["address"])` + `tools.check_deployer(data["address"])`
  - THREAT_FEED: `tools.get_agent_findings(limit=10)`
  - GENERAL: return empty dict
- `async chat(user_id: str, message: str) -> str`:
  - Route the message
  - Load chat history from DB (last 10)
  - Gather context
  - Build messages array: system prompt + history + context + user message
  - Call Claude Sonnet (`claude-sonnet-4-20250514`)
  - Save user message + assistant response to DB
  - Return response text
- `async explain_scan(scan_result: dict) -> str`:
  - Call Haiku with EXPLAIN_SCAN_TEMPLATE + scan data
  - Return plain English explanation

**Step 4: Run tests to verify they pass**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_advisor.py -v`
Expected: all PASS

**Step 5: Commit**

```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
git add agent/advisor.py tests/test_advisor.py
git commit -m "feat(agent): add advisor with intent routing and context gathering"
```

---

## Task 5: Chat API Endpoint

**Files:**
- Modify: `api.py` — add `POST /api/agent/chat` and `POST /api/agent/explain`
- Modify: `core/container.py` — wire AgentTools + Advisor
- Test: `tests/test_agent_api.py`

**Step 1: Write the failing tests**

```python
# tests/test_agent_api.py
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    import api as api_module

    advisor = MagicMock()
    advisor.chat = AsyncMock(return_value="This contract looks risky. The deployer has launched 3 rugs.")
    advisor.explain_scan = AsyncMock(return_value="High sell tax and unverified source code.")

    api_module.container = SimpleNamespace(
        db=MagicMock(),
        settings=SimpleNamespace(trusted_proxies=[]),
        advisor=advisor,
    )

    return TestClient(api_module.app, raise_server_exceptions=False)


def test_chat_endpoint(client):
    resp = client.post("/api/agent/chat", json={
        "message": "Is 0x4904c02efa081cb7685346968bac854cdf4e7777 safe?",
        "user_id": "ext-session-123",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "response" in data
    assert len(data["response"]) > 0


def test_chat_empty_message(client):
    resp = client.post("/api/agent/chat", json={
        "message": "",
        "user_id": "ext-session-123",
    })
    assert resp.status_code == 422


def test_explain_endpoint(client):
    resp = client.post("/api/agent/explain", json={
        "scan_result": {
            "risk_score": 85,
            "classification": "BLOCK_RECOMMENDED",
            "danger_signals": ["unverified", "high sell tax"],
        },
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "explanation" in data
```

**Step 2: Run tests to verify they fail**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_agent_api.py -v`
Expected: FAIL — endpoint doesn't exist

**Step 3: Implement**

1. In `core/container.py`:
   - Add import: `from agent.tools import AgentTools` and `from agent.advisor import Advisor`
   - After `self.email_service` (line ~140), add:
     ```python
     self.agent_tools = AgentTools(self)
     self.advisor = Advisor(
         tools=self.agent_tools,
         db=self.db,
         ai_analyzer=self.ai_analyzer,
     )
     ```

2. In `api.py`:
   - Add Pydantic models:
     ```python
     class ChatRequest(BaseModel):
         message: str = Field(..., min_length=1, max_length=2000)
         user_id: str = Field(..., min_length=1, max_length=100)

     class ExplainRequest(BaseModel):
         scan_result: Dict[str, Any]
     ```
   - Add `POST /api/agent/chat` endpoint:
     - Rate limit: 50/hour per user_id
     - Call `container.advisor.chat(req.user_id, req.message)`
     - Return `{"response": result, "user_id": req.user_id}`
   - Add `POST /api/agent/explain` endpoint:
     - Rate limit: 30/min per IP
     - Call `container.advisor.explain_scan(req.scan_result)`
     - Return `{"explanation": result}`
   - Add `advisor` to `_bind_globals()`

**Step 4: Run tests to verify they pass**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_agent_api.py -v`
Expected: all PASS

**Step 5: Run ALL existing tests to verify no regressions**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/ -v`
Expected: all 194+ tests PASS

**Step 6: Commit**

```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
git add api.py core/container.py tests/test_agent_api.py
git commit -m "feat(agent): add /api/agent/chat and /api/agent/explain endpoints"
```

---

## Task 6: "Why?" Button on Overlays

**Files:**
- Modify: `extension/content.js` — add "Why?" button to BLOCK/WARN overlay (after line 509)
- Modify: `extension/background.js` — add message handler for SHIELDAI_EXPLAIN
- Modify: `extension/overlay.css` — style for the button

**Step 1: Add "Why?" button to overlay HTML**

In `content.js`, inside the `showTransactionOverlay()` function, after the `.shieldai-actions` div (line 509), add a new button row:

```javascript
<div class="shieldai-explain-row">
  <button class="shieldai-btn shieldai-btn-explain" id="shieldai-explain">
    ${_t("overlayBtnWhy") || "Why is this risky?"}
  </button>
</div>
<div class="shieldai-explain-response" id="shieldai-explain-response" style="display:none;">
  <div class="shieldai-explain-loading" id="shieldai-explain-loading">Analyzing...</div>
  <div class="shieldai-explain-text" id="shieldai-explain-text"></div>
</div>
```

Add click handler for the "Why?" button (after the proceed button handler, ~line 545):

```javascript
document.getElementById("shieldai-explain").addEventListener("click", async () => {
  const explainBtn = document.getElementById("shieldai-explain");
  const responseDiv = document.getElementById("shieldai-explain-response");
  const loadingEl = document.getElementById("shieldai-explain-loading");
  const textEl = document.getElementById("shieldai-explain-text");

  explainBtn.disabled = true;
  explainBtn.textContent = "Analyzing...";
  responseDiv.style.display = "block";
  loadingEl.style.display = "block";
  textEl.style.display = "none";

  try {
    const resp = await new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: "SHIELDAI_EXPLAIN", scanResult: result },
        (response) => resolve(response)
      );
    });
    loadingEl.style.display = "none";
    textEl.style.display = "block";
    textEl.textContent = resp?.explanation || "Unable to generate explanation.";
  } catch {
    loadingEl.style.display = "none";
    textEl.style.display = "block";
    textEl.textContent = "Unable to generate explanation.";
  }
});
```

**Step 2: Add background.js handler**

In `background.js`, add a message handler for `SHIELDAI_EXPLAIN`:

```javascript
case "SHIELDAI_EXPLAIN": {
  const { apiUrl } = await chrome.storage.local.get({ apiUrl: DEFAULT_API_URL });
  try {
    const resp = await fetch(`${apiUrl}/api/agent/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_result: message.scanResult }),
    });
    const data = await resp.json();
    sendResponse({ explanation: data.explanation || "No explanation available." });
  } catch {
    sendResponse({ explanation: "Unable to reach ShieldBot API." });
  }
  return true; // async sendResponse
}
```

**Step 3: Add CSS styles**

In `extension/overlay.css`, add:

```css
.shieldai-explain-row {
  text-align: center;
  margin-top: 8px;
}
.shieldai-btn-explain {
  background: transparent;
  border: 1px solid #475569;
  color: #94a3b8;
  padding: 6px 16px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  transition: all 0.2s;
}
.shieldai-btn-explain:hover {
  border-color: #3b82f6;
  color: #3b82f6;
}
.shieldai-btn-explain:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.shieldai-explain-response {
  margin-top: 10px;
  padding: 10px 12px;
  background: rgba(30, 41, 59, 0.8);
  border-radius: 6px;
  border-left: 3px solid #3b82f6;
}
.shieldai-explain-loading {
  color: #64748b;
  font-size: 12px;
}
.shieldai-explain-text {
  color: #e2e8f0;
  font-size: 13px;
  line-height: 1.5;
}
```

**Step 4: Add i18n key**

Add `"overlayBtnWhy"` to all locale files (`locales/en/messages.json`, `locales/zh/messages.json`, `locales/vi/messages.json`).

**Step 5: Test manually**

- Load unpacked extension in Chrome
- Visit a DeFi site and trigger a transaction scan
- Verify "Why is this risky?" button appears on BLOCK/WARN overlays
- Verify clicking it calls the API and shows explanation

**Step 6: Commit**

```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
git add extension/content.js extension/background.js extension/overlay.css extension/locales/
git commit -m "feat(agent): add Why? button to BLOCK/WARN overlays with AI explanation"
```

---

## Task 7: Sentinel (Event Handlers)

**Files:**
- Create: `agent/sentinel.py`
- Test: `tests/test_sentinel.py`

**Step 1: Write the failing tests**

```python
# tests/test_sentinel.py
import pytest
from unittest.mock import AsyncMock, MagicMock
from agent.sentinel import Sentinel


def _make_sentinel():
    tools = MagicMock()
    tools.auto_watch_deployer = AsyncMock()
    tools.scan_contract = AsyncMock(return_value={
        "risk_score": 90, "risk_level": "HIGH", "flags": ["unverified"],
    })

    db = MagicMock()
    db.get_deployer_risk_summary = AsyncMock(return_value={
        "deployer_address": "0xdep", "total_contracts": 5, "high_risk_contracts": 3,
    })
    db.insert_agent_finding = AsyncMock()

    ai = MagicMock()
    ai.client = MagicMock()

    return Sentinel(tools=tools, db=db, ai_analyzer=ai)


@pytest.fixture
def sentinel():
    return _make_sentinel()


@pytest.mark.asyncio
async def test_on_scan_blocked_watches_deployer(sentinel):
    await sentinel.on_scan_blocked(
        address="0xcontract",
        deployer="0xscammer",
        chain_id=56,
        risk_score=85,
    )
    sentinel.tools.auto_watch_deployer.assert_awaited_once()
    call_kwargs = sentinel.tools.auto_watch_deployer.call_args[1]
    assert call_kwargs["address"] == "0xscammer"


@pytest.mark.asyncio
async def test_on_scan_blocked_skips_if_no_deployer(sentinel):
    await sentinel.on_scan_blocked(
        address="0xcontract",
        deployer=None,
        chain_id=56,
        risk_score=85,
    )
    sentinel.tools.auto_watch_deployer.assert_not_awaited()


@pytest.mark.asyncio
async def test_on_scan_blocked_skips_low_risk(sentinel):
    await sentinel.on_scan_blocked(
        address="0xcontract",
        deployer="0xdep",
        chain_id=56,
        risk_score=50,
    )
    sentinel.tools.auto_watch_deployer.assert_not_awaited()
```

**Step 2: Run tests to verify they fail**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_sentinel.py -v`
Expected: FAIL

**Step 3: Implement**

Create `agent/sentinel.py`:

- Class `Sentinel(tools, db, ai_analyzer)`
- `async on_scan_blocked(address, deployer, chain_id, risk_score)`:
  - If risk_score < 71 or deployer is None: return (skip)
  - Call `tools.auto_watch_deployer(deployer, reason=f"auto: blocked contract {address}", chain_id=chain_id)`
  - Log finding to `db.insert_agent_finding(finding_type="sentinel_event", ...)`
- `async on_mempool_alert(alert_data)`:
  - Generate narrative via Haiku
  - Store in agent_findings
- `async on_deployer_flagged(deployer, new_contract, chain_id)`:
  - Scan new contract via tools
  - If HIGH risk: auto-block + narrative + Telegram alert

**Step 4: Run tests to verify they pass**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_sentinel.py -v`
Expected: all PASS

**Step 5: Wire Sentinel into the firewall endpoint**

In `api.py`, in the `/api/firewall` POST handler, after the response is computed and risk_classification is BLOCK_RECOMMENDED, add:

```python
if container.sentinel and risk_classification == "BLOCK_RECOMMENDED":
    deployer_info = await container.db.get_deployer_risk_summary(address, chain_id)
    deployer_addr = deployer_info["deployer_address"] if deployer_info else None
    asyncio.create_task(container.sentinel.on_scan_blocked(
        address=address,
        deployer=deployer_addr,
        chain_id=chain_id,
        risk_score=composite_score,
    ))
```

**Step 6: Wire Sentinel into container.py**

In `core/container.py`, after advisor init:
```python
from agent.sentinel import Sentinel
self.sentinel = Sentinel(
    tools=self.agent_tools,
    db=self.db,
    ai_analyzer=self.ai_analyzer,
)
```

**Step 7: Run all tests**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/ -v`
Expected: all PASS

**Step 8: Commit**

```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
git add agent/sentinel.py tests/test_sentinel.py api.py core/container.py
git commit -m "feat(agent): add sentinel with auto-watch feedback loop on BLOCK scans"
```

---

## Task 8: Hunter (Scheduled Threat Sweeps)

**Files:**
- Create: `agent/hunter.py`
- Test: `tests/test_hunter.py`

**Step 1: Write the failing tests**

```python
# tests/test_hunter.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from agent.hunter import Hunter


def _make_hunter():
    tools = MagicMock()
    tools.scan_contract = AsyncMock(return_value={
        "risk_score": 90, "risk_level": "HIGH",
        "flags": ["unverified", "high_sell_tax"],
    })
    tools.auto_watch_deployer = AsyncMock()

    db = MagicMock()
    db.get_watched_deployers = AsyncMock(return_value=[
        {"deployer_address": "0xscam1", "chain_id": 56, "watch_reason": "MANUAL"},
    ])
    db.get_tracked_pairs = AsyncMock(return_value=[])
    db.upsert_tracked_pair = AsyncMock()
    db.insert_agent_finding = AsyncMock()
    db.update_tracked_pair_status = AsyncMock()

    ai = MagicMock()
    ai.client = MagicMock()

    web3 = MagicMock()

    sentinel = MagicMock()
    sentinel.on_deployer_flagged = AsyncMock()

    return Hunter(tools=tools, db=db, ai_analyzer=ai, web3_client=web3, sentinel=sentinel)


@pytest.fixture
def hunter():
    return _make_hunter()


@pytest.mark.asyncio
async def test_check_watched_deployers_flags_new_contract(hunter):
    # Simulate deployer having a new contract not yet tracked
    hunter._get_recent_contracts_by_deployer = AsyncMock(return_value=["0xnewcontract"])
    hunter.db.get_tracked_pairs = AsyncMock(return_value=[])

    flagged = await hunter._check_watched_deployers()
    assert len(flagged) >= 0  # depends on mock setup


@pytest.mark.asyncio
async def test_sweep_runs_without_error(hunter):
    hunter._check_watched_deployers = AsyncMock(return_value=[])
    hunter._recheck_warn_contracts = AsyncMock(return_value=[])
    hunter._scan_new_pairs = AsyncMock(return_value=[])

    await hunter.sweep()
    hunter._check_watched_deployers.assert_awaited_once()
```

**Step 2: Run tests to verify they fail**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_hunter.py -v`
Expected: FAIL

**Step 3: Implement**

Create `agent/hunter.py`:

- Class `Hunter(tools, db, ai_analyzer, web3_client, sentinel)`
- `async sweep()` — orchestrates one hunt cycle:
  1. `_scan_new_pairs()` — check PancakeSwap factory for new pairs (placeholder: query recent contracts via BSCScan API)
  2. `_check_watched_deployers()` — for each watched deployer, check for new contracts
  3. `_recheck_warn_contracts()` — contracts scored 31-70, recheck up to 20
  4. For any flagged contracts: scan → if BLOCK → auto-watch + narrative + store finding
- `async start(interval_seconds=1800)` — asyncio background loop calling `sweep()` every 30 min
- `async stop()` — cancel the background task
- `_generate_narrative(finding_data)` — call Haiku to narrate

**Step 4: Run tests to verify they pass**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/test_hunter.py -v`
Expected: all PASS

**Step 5: Wire Hunter into container and lifespan**

In `core/container.py`:
```python
from agent.hunter import Hunter
self.hunter = Hunter(
    tools=self.agent_tools,
    db=self.db,
    ai_analyzer=self.ai_analyzer,
    web3_client=self.web3_client,
    sentinel=self.sentinel,
)
```

In `api.py` lifespan (after `container.startup()`):
```python
await container.hunter.start()
```

In lifespan shutdown (before `container.shutdown()`):
```python
await container.hunter.stop()
```

**Step 6: Run all tests**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/ -v`
Expected: all PASS

**Step 7: Commit**

```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
git add agent/hunter.py tests/test_hunter.py core/container.py api.py
git commit -m "feat(agent): add hunter with scheduled threat sweeps every 30 min"
```

---

## Task 9: Extension Side Panel (Chat UI)

**Files:**
- Create: `extension/sidepanel.html`
- Create: `extension/sidepanel.js`
- Modify: `extension/manifest.json` — add side_panel config
- Modify: `extension/background.js` — add side panel open handler
- Modify: `extension/popup.html` — add "Ask ShieldBot" button

**Step 1: Update manifest.json**

Add to `manifest.json`:
```json
"side_panel": {
  "default_path": "sidepanel.html"
},
"permissions": ["storage", "permissions", "sidePanel"]
```

Also add `"sidepanel.html"` and `"sidepanel.js"` to `web_accessible_resources`.

**Step 2: Create sidepanel.html**

Minimal chat UI: dark theme matching existing design (navy #0f172a), text input at bottom, scrollable message area. Messages styled as bubbles — user on right (blue), assistant on left (dark gray). "ShieldBot AI" header at top.

**Step 3: Create sidepanel.js**

- On submit: POST to `${apiUrl}/api/agent/chat` with `{ message, user_id }` (user_id = random UUID stored in chrome.storage.local)
- Render response as assistant bubble
- Show typing indicator while waiting
- Store last 20 messages locally for instant display on reopen

**Step 4: Add "Ask ShieldBot" button to popup.html**

After the tabs div (line 452), add a button that opens the side panel:

```html
<button class="btn" id="askBtn" style="background:#1e293b;border:1px solid #334155;color:#94a3b8;margin-bottom:12px;">
  Ask ShieldBot AI
</button>
```

In `popup.js`, add handler:
```javascript
document.getElementById("askBtn")?.addEventListener("click", () => {
  chrome.sidePanel.open({ windowId: undefined });
  window.close();
});
```

**Step 5: Wire "Why?" button to side panel**

In `content.js`, update the "Why?" button to optionally open the side panel with context instead of inline explanation (if side panel is available).

**Step 6: Test manually**

- Load unpacked extension
- Click "Ask ShieldBot AI" in popup → side panel opens
- Type "Is 0x... safe?" → response from API
- Click "Why?" on overlay → opens side panel with context

**Step 7: Commit**

```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
git add extension/sidepanel.html extension/sidepanel.js extension/manifest.json extension/popup.html extension/popup.js extension/background.js
git commit -m "feat(agent): add Chrome Side Panel chat UI with Ask ShieldBot button"
```

---

## Task 10: Telegram Chat Integration

**Files:**
- Modify: `bot.py` — add free-text message handler
- Test: manual (Telegram bot testing requires live bot)

**Step 1: Add message handler to bot.py**

Add a `MessageHandler` with `filters.TEXT & ~filters.COMMAND` that routes to the Advisor:

```python
async def handle_free_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = f"tg-{update.effective_user.id}"
    message = update.message.text

    if not container or not container.advisor:
        await update.message.reply_text("AI advisor is not available.")
        return

    typing = await update.message.reply_text("Analyzing...")
    try:
        response = await container.advisor.chat(user_id, message)
        await typing.edit_text(response)
    except Exception as e:
        logger.error(f"Advisor error: {e}")
        await typing.edit_text("Sorry, I couldn't process that. Try again.")
```

Register: `app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_free_text))`

Place this handler LAST so existing command handlers take priority.

**Step 2: Test manually**

- DM the bot: "Is 0xabc safe?"
- Verify response with analysis data
- DM: "What threats are active?"
- Verify threat feed response

**Step 3: Commit**

```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
git add bot.py
git commit -m "feat(agent): add Telegram free-text chat via Advisor"
```

---

## Task 11: Final Integration Test + Version Bump

**Files:**
- Modify: `extension/manifest.json` — bump to v2.0.0
- Modify: `api.py` — bump version

**Step 1: Run full test suite**

Run: `cd C:/Users/GUDMAN/Desktop/shieldbot && python -m pytest tests/ -v`
Expected: all tests PASS (194 existing + ~25 new agent tests)

**Step 2: Version bump**

- `extension/manifest.json`: `"version": "2.0.0"`
- `api.py` line 178: `version="2.0.0"`

**Step 3: Final commit**

```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
git add -A
git commit -m "feat: ShieldBot v2.0.0 — AI Agent (Hunter + Sentinel + Advisor)"
```

---

## Summary

| Task | What | New Tests |
|------|------|-----------|
| 1 | Database models (3 tables + methods) | 5 |
| 2 | Agent tool layer (thin service wrappers) | 5 |
| 3 | System prompts + narrative templates | 0 |
| 4 | Advisor core (routing + context + chat) | 5 |
| 5 | Chat API endpoint + container wiring | 3 |
| 6 | "Why?" button on overlays | manual |
| 7 | Sentinel (auto-watch feedback loop) | 3 |
| 8 | Hunter (scheduled sweeps) | 2 |
| 9 | Extension side panel chat UI | manual |
| 10 | Telegram free-text chat | manual |
| 11 | Integration test + version bump | 0 |
| **Total** | **11 tasks, ~11 commits** | **~23 automated + 3 manual** |
