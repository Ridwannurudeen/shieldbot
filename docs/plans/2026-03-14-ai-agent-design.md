# ShieldBot AI Agent — Design Document

**Date:** 2026-03-14
**Version:** v2.0.0 (AI Agent)
**Status:** Approved

---

## Summary

Add a full-spectrum AI agent to ShieldBot with three operating modes:
- **Hunter** — proactive threat discovery (scheduled sweeps)
- **Sentinel** — real-time event response (direct function calls)
- **Advisor** — conversational security assistant (chat interface)

All three modes share a common tool layer wrapping existing ShieldBot services. AI (Claude) is used surgically — rule-based logic handles the heavy lifting, LLM narrates findings and powers chat. Estimated cost: under $1/day.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                 AGENT CORE                       │
│                                                  │
│  ┌───────────┐  ┌───────────┐  ┌──────────────┐ │
│  │  HUNTER   │  │ SENTINEL  │  │   ADVISOR    │ │
│  │ (30 min)  │  │ (events)  │  │  (user chat) │ │
│  └─────┬─────┘  └─────┬─────┘  └──────┬───────┘ │
│        │              │               │          │
│  ┌─────▼──────────────▼───────────────▼───────┐  │
│  │            TOOL LAYER                       │  │
│  │  scan_contract()  check_deployer()          │  │
│  │  query_campaign() get_mempool_alerts()      │  │
│  │  check_honeypot() get_funder_links()        │  │
│  │  get_market_data() auto_block()             │  │
│  │  send_telegram_alert() get_agent_findings() │  │
│  └─────────────────────────────────────────────┘  │
│                                                  │
│  ┌─────────────────────────────────────────────┐  │
│  │            MEMORY (SQLite)                  │  │
│  │  agent_findings, chat_history, tracked_pairs │  │
│  └─────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

---

## LLM Strategy

**Tiered model usage:**
- **Haiku** — threat narratives, intent classification fallback (~$0.001/call)
- **Sonnet** — chat synthesis, complex reasoning, deep investigations (~$0.01/call)

**AI is NOT in the decision loop.** The Hunter's sweep logic, Sentinel's event handlers, and auto-blocking are pure Python. AI is a narrator and conversationalist only.

---

## Mode 1: Hunter (Proactive Threat Discovery)

**Schedule:** Every 30 minutes via asyncio background task.

**Hunt cycle:**
1. **PancakeSwap pair monitor** — watch Factory `PairCreated` events for new liquidity pairs. Scan token contracts through the full analyzer pipeline. (~50-100 new pairs/day)
2. **Watched deployer check** — any watched deployer launched something new? Auto-scan.
3. **Funder trail walk** — only triggered when step 1 or 2 flags something. Trace funding source 2-3 hops back, check for overlap with known scam funders.
4. **Honeypot recheck** — contracts previously scored WARN (31-70) rechecked for liquidity pulls or tax changes. Cap at 20 per cycle.
5. **Bytecode similarity** — only compare contracts flagged in step 1, not every new contract.

**When something is found:**
- Run through existing `RiskEngine` for scoring
- Score >= 71 → auto-add to deployer watch + auto-block
- Haiku generates 2-3 sentence threat narrative
- Push to Telegram admin channel
- Store in `agent_findings` table

---

## Mode 2: Sentinel (Real-Time Event Response)

**Trigger mechanism:** Direct function calls from existing services (no event bus).

**Event handlers:**
| Event | Handler | Action |
|-------|---------|--------|
| User scan returns BLOCK | `on_scan_blocked()` | Auto-watch deployer (feedback loop) |
| Watched deployer deploys | `on_deployer_flagged()` | Full scan → auto-block → Telegram |
| Mempool sandwich detected | `on_mempool_alert()` | Narrate for threat feed |
| High-value approval | `on_suspicious_approval()` | Flag + push warning |

**Key feature:** User scans passively train the Hunter. Every BLOCK result auto-watches the deployer, growing the threat intelligence over time.

---

## Mode 3: Advisor (Conversational Security Agent)

**Interfaces (build order):**
1. Telegram — free-text message handler in bot.py
2. API — `POST /api/agent/chat`
3. Chrome extension — Side Panel chat UI
4. BLOCK/WARN overlay — "Why?" button opens side panel with context

**Intent routing (3 branches, no LLM):**
- Message contains valid address → scan it
- Message contains threat/alert keywords → threat feed
- Everything else → Sonnet with all tools available

**Conversation memory:**
- Last 10 messages per user in `chat_history` table
- Auto-pruned after 24 hours
- Injected as context on each turn

**Cost controls:**
- Haiku for intent classification fallback
- Sonnet only for final synthesis
- Cache repeated questions on same contract (5-min TTL)
- Rate limit: 50 messages/hour per user

---

## Data Model

### agent_findings
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| finding_type | TEXT | 'hunter_sweep', 'sentinel_event', 'auto_block' |
| investigation_id | TEXT | Groups related findings from same sweep |
| address | TEXT | Contract address |
| deployer | TEXT | Deployer address |
| chain_id | INTEGER | Chain ID |
| risk_score | INTEGER | 0-100 |
| narrative | TEXT | Haiku-generated plain English |
| evidence | JSON | Raw data backing the finding |
| action_taken | TEXT | 'blocked', 'watched', 'ignored' |
| created_at | TIMESTAMP | When found |

### chat_history
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| user_id | TEXT | Telegram user ID or extension session |
| role | TEXT | 'user' or 'assistant' |
| message | TEXT | Message content |
| tools_used | JSON | Which tools the agent called |
| created_at | TIMESTAMP | Auto-pruned after 24h |

### tracked_pairs
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| pair_address | TEXT UNIQUE | PancakeSwap pair address |
| token_address | TEXT | Token contract address |
| deployer | TEXT | Token deployer |
| liquidity_usd | REAL | USD liquidity at first seen |
| first_seen | TIMESTAMP | When pair was created |
| last_checked | TIMESTAMP | Last Hunter sweep check |
| status | TEXT | 'watching', 'cleared', 'rugged', 'blocked' |

**Cleanup policy:** `cleared` pairs older than 7 days are deleted. `rugged` and `blocked` stay forever.

---

## New Files

```
agent/
├── __init__.py
├── hunter.py        -- Scheduled sweep logic
├── sentinel.py      -- Direct-call event handlers
├── advisor.py       -- Intent routing, tool orchestration, Sonnet synthesis
├── tools.py         -- Thin wrappers around existing services
├── prompts.py       -- System prompts + narrative templates
└── models.py        -- SQLAlchemy models for new tables
```

## Modified Files

| File | Change |
|------|--------|
| `core/container.py` | Wire agent services into DI container |
| `core/database.py` | New table definitions + 24h chat prune job |
| `api.py` | Add `POST /api/agent/chat` endpoint |
| `bot.py` | Add free-text message handler → Advisor |
| `extension/manifest.json` | Add `sidePanel` permission |
| `extension/popup.html` | Add "Ask ShieldBot" button |
| `extension/sidepanel.html` | New — chat UI |
| `extension/sidepanel.js` | New — chat logic |
| `extension/content.js` | Add "Why?" button on BLOCK/WARN overlays |
| `extension/overlay.css` | Styles for "Why?" button |

---

## Build Order

| Phase | What | User Value |
|-------|------|-----------|
| 1 | `agent/tools.py` + `agent/models.py` | Foundation |
| 2 | `agent/advisor.py` + `POST /api/agent/chat` | Chat works |
| 3 | "Why?" button on BLOCK/WARN overlays | One-click explainability |
| 4 | `agent/hunter.py` | Proactive defense |
| 5 | `agent/sentinel.py` | Feedback loop |
| 6 | Extension side panel | Full chat UX |
| 7 | Telegram chat integration | Extends bot.py |

---

## What We're NOT Building (YAGNI)

- No vector database / embeddings
- No agent framework (LangChain, CrewAI)
- No persistent memory beyond 24h chat
- No multi-agent orchestration
- No fine-tuned model
- No custom event bus
- No local model (Ollama)

---

## Cost Estimate

| Component | Daily Cost |
|-----------|-----------|
| Hunter narratives (~20 findings × Haiku) | ~$0.02 |
| Sentinel narratives (~10 events × Haiku) | ~$0.01 |
| Advisor chat (~50 messages × Sonnet) | ~$0.50 |
| Intent classification fallback (Haiku) | ~$0.01 |
| **Total** | **~$0.54/day** |
