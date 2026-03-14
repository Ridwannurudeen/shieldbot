"""Tests for agent_findings, chat_history, and tracked_pairs tables."""

import pytest
import pytest_asyncio
import time
from core.database import Database


@pytest_asyncio.fixture
async def db(tmp_path):
    d = Database(str(tmp_path / "test.db"))
    await d.initialize()
    yield d
    await d.close()


class TestAgentFindings:
    @pytest.mark.asyncio
    async def test_insert_and_retrieve(self, db):
        """Insert an agent finding and retrieve it."""
        await db.insert_agent_finding(
            finding_type="rug_pull",
            address="0xDEAD",
            deployer="0xBEEF",
            chain_id=56,
            risk_score=95,
            narrative="Token has hidden mint function",
            evidence={"functions": ["mint"], "severity": "critical"},
            action_taken="alert_sent",
            investigation_id="inv-001",
        )

        findings = await db.get_agent_findings(limit=10)
        assert len(findings) == 1
        f = findings[0]
        assert f["finding_type"] == "rug_pull"
        assert f["address"] == "0xDEAD"
        assert f["deployer"] == "0xBEEF"
        assert f["chain_id"] == 56
        assert f["risk_score"] == 95
        assert f["narrative"] == "Token has hidden mint function"
        assert f["action_taken"] == "alert_sent"
        assert f["investigation_id"] == "inv-001"
        # evidence should be stored as JSON and parsed back
        assert f["evidence"]["functions"] == ["mint"]
        assert f["evidence"]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_filter_by_type(self, db):
        """Filter findings by finding_type."""
        await db.insert_agent_finding(finding_type="rug_pull", address="0x1")
        await db.insert_agent_finding(finding_type="honeypot", address="0x2")
        await db.insert_agent_finding(finding_type="rug_pull", address="0x3")

        rug_pulls = await db.get_agent_findings(finding_type="rug_pull")
        assert len(rug_pulls) == 2
        assert all(f["finding_type"] == "rug_pull" for f in rug_pulls)

        honeypots = await db.get_agent_findings(finding_type="honeypot")
        assert len(honeypots) == 1
        assert honeypots[0]["address"] == "0x2"

    @pytest.mark.asyncio
    async def test_default_chain_id(self, db):
        """chain_id defaults to 56 when not provided."""
        await db.insert_agent_finding(finding_type="scam", address="0xABC")
        findings = await db.get_agent_findings()
        assert findings[0]["chain_id"] == 56

    @pytest.mark.asyncio
    async def test_findings_ordered_newest_first(self, db):
        """Findings should come back ordered by created_at DESC."""
        await db.insert_agent_finding(finding_type="type_a", address="0x1")
        await db.insert_agent_finding(finding_type="type_b", address="0x2")
        await db.insert_agent_finding(finding_type="type_c", address="0x3")

        findings = await db.get_agent_findings()
        # Most recent (type_c) should be first
        assert findings[0]["finding_type"] == "type_c"
        assert findings[-1]["finding_type"] == "type_a"


class TestChatHistory:
    @pytest.mark.asyncio
    async def test_insert_and_retrieve(self, db):
        """Insert chat messages and retrieve them oldest-first."""
        await db.insert_chat_message("user-1", "user", "What is 0xDEAD?")
        await db.insert_chat_message("user-1", "assistant", "It looks risky.", tools_used=["scan_contract"])

        history = await db.get_chat_history("user-1", limit=10)
        assert len(history) == 2
        # Should be oldest first (for LLM context)
        assert history[0]["role"] == "user"
        assert history[0]["message"] == "What is 0xDEAD?"
        assert history[0]["tools_used"] is None
        assert history[1]["role"] == "assistant"
        assert history[1]["message"] == "It looks risky."
        assert history[1]["tools_used"] == ["scan_contract"]

    @pytest.mark.asyncio
    async def test_separate_users(self, db):
        """Different user_ids should have separate histories."""
        await db.insert_chat_message("user-a", "user", "Hello from A")
        await db.insert_chat_message("user-b", "user", "Hello from B")

        history_a = await db.get_chat_history("user-a")
        history_b = await db.get_chat_history("user-b")
        assert len(history_a) == 1
        assert len(history_b) == 1
        assert history_a[0]["message"] == "Hello from A"
        assert history_b[0]["message"] == "Hello from B"

    @pytest.mark.asyncio
    async def test_limit_returns_most_recent(self, db):
        """Limit should return the N most recent messages, ordered oldest-first."""
        for i in range(5):
            await db.insert_chat_message("user-1", "user", f"msg-{i}")

        history = await db.get_chat_history("user-1", limit=3)
        assert len(history) == 3
        # Should be the last 3 messages, ordered oldest-first
        assert history[0]["message"] == "msg-2"
        assert history[1]["message"] == "msg-3"
        assert history[2]["message"] == "msg-4"

    @pytest.mark.asyncio
    async def test_prune_old_chats(self, db):
        """Prune should delete messages older than max_age_seconds."""
        now = time.time()

        # Insert an old message by manipulating the DB directly
        await db._db.execute(
            "INSERT INTO chat_history (user_id, role, message, created_at) VALUES (?, ?, ?, ?)",
            ("user-1", "user", "old message", now - 100000),
        )
        await db._db.commit()

        # Insert a fresh message
        await db.insert_chat_message("user-1", "user", "new message")

        deleted = await db.prune_old_chats(max_age_seconds=86400)
        assert deleted == 1

        history = await db.get_chat_history("user-1")
        assert len(history) == 1
        assert history[0]["message"] == "new message"


class TestTrackedPairs:
    @pytest.mark.asyncio
    async def test_upsert_and_retrieve(self, db):
        """Insert a tracked pair and retrieve it."""
        await db.upsert_tracked_pair(
            pair_address="0xPAIR1",
            token_address="0xTOKEN1",
            deployer="0xDEPLOYER1",
            liquidity_usd=50000.0,
            status="watching",
        )

        pairs = await db.get_tracked_pairs()
        assert len(pairs) == 1
        p = pairs[0]
        assert p["pair_address"] == "0xPAIR1"
        assert p["token_address"] == "0xTOKEN1"
        assert p["deployer"] == "0xDEPLOYER1"
        assert p["liquidity_usd"] == 50000.0
        assert p["status"] == "watching"

    @pytest.mark.asyncio
    async def test_upsert_updates_existing(self, db):
        """Upserting with the same pair_address should update, not duplicate."""
        await db.upsert_tracked_pair(pair_address="0xPAIR1", liquidity_usd=10000.0)
        await db.upsert_tracked_pair(pair_address="0xPAIR1", liquidity_usd=50000.0)

        pairs = await db.get_tracked_pairs()
        assert len(pairs) == 1
        assert pairs[0]["liquidity_usd"] == 50000.0

    @pytest.mark.asyncio
    async def test_filter_by_status(self, db):
        """Filter tracked pairs by status."""
        await db.upsert_tracked_pair(pair_address="0xP1", status="watching")
        await db.upsert_tracked_pair(pair_address="0xP2", status="alerted")
        await db.upsert_tracked_pair(pair_address="0xP3", status="watching")

        watching = await db.get_tracked_pairs(status="watching")
        assert len(watching) == 2

        alerted = await db.get_tracked_pairs(status="alerted")
        assert len(alerted) == 1
        assert alerted[0]["pair_address"] == "0xP2"

    @pytest.mark.asyncio
    async def test_update_status(self, db):
        """Update a tracked pair's status."""
        await db.upsert_tracked_pair(pair_address="0xPAIR1", status="watching")

        await db.update_tracked_pair_status("0xPAIR1", "alerted")

        pairs = await db.get_tracked_pairs(status="alerted")
        assert len(pairs) == 1
        assert pairs[0]["pair_address"] == "0xPAIR1"
        assert pairs[0]["last_checked"] is not None

    @pytest.mark.asyncio
    async def test_full_lifecycle(self, db):
        """Test the full lifecycle: insert -> retrieve -> update status -> verify."""
        # Insert
        await db.upsert_tracked_pair(
            pair_address="0xLIFE",
            token_address="0xTOK",
            deployer="0xDEP",
            liquidity_usd=1000.0,
        )

        # Retrieve watching
        pairs = await db.get_tracked_pairs(status="watching")
        assert len(pairs) == 1

        # Update to alerted
        await db.update_tracked_pair_status("0xLIFE", "alerted")

        # Watching should now be empty
        watching = await db.get_tracked_pairs(status="watching")
        assert len(watching) == 0

        # Alerted should have our pair
        alerted = await db.get_tracked_pairs(status="alerted")
        assert len(alerted) == 1
        assert alerted[0]["pair_address"] == "0xLIFE"
        assert alerted[0]["last_checked"] is not None

        # Update to dismissed
        await db.update_tracked_pair_status("0xLIFE", "dismissed")

        dismissed = await db.get_tracked_pairs(status="dismissed")
        assert len(dismissed) == 1
