"""Tests for core.auth.AuthManager."""

import pytest
import pytest_asyncio
from core.database import Database
from core.auth import AuthManager, generate_api_key, hash_key, KEY_PREFIX


@pytest_asyncio.fixture
async def db():
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


@pytest_asyncio.fixture
async def auth(db):
    return AuthManager(db)


class TestKeyGeneration:
    def test_generate_key_has_prefix(self):
        key = generate_api_key()
        assert key.startswith(KEY_PREFIX)
        assert len(key) == len(KEY_PREFIX) + 32  # 16 bytes hex = 32 chars

    def test_hash_key_deterministic(self):
        key = "sb_abc123"
        assert hash_key(key) == hash_key(key)

    def test_hash_key_different_for_different_keys(self):
        assert hash_key("sb_aaa") != hash_key("sb_bbb")


class TestAuthManager:
    @pytest.mark.asyncio
    async def test_create_and_validate_key(self, auth):
        result = await auth.create_key(owner="test_partner", tier="free")
        assert result["key"].startswith(KEY_PREFIX)
        assert result["owner"] == "test_partner"
        assert result["tier"] == "free"

        # Validate the key
        info = await auth.validate_key(result["key"])
        assert info is not None
        assert info["owner"] == "test_partner"
        assert info["tier"] == "free"
        assert info["rpm_limit"] == 60
        assert info["daily_limit"] == 1000

    @pytest.mark.asyncio
    async def test_validate_invalid_key(self, auth):
        info = await auth.validate_key("sb_nonexistent1234567890abcdef12")
        assert info is None

    @pytest.mark.asyncio
    async def test_validate_no_prefix(self, auth):
        info = await auth.validate_key("no_prefix_key")
        assert info is None

    @pytest.mark.asyncio
    async def test_validate_empty(self, auth):
        info = await auth.validate_key("")
        assert info is None

    @pytest.mark.asyncio
    async def test_pro_tier_limits(self, auth):
        result = await auth.create_key(owner="pro_user", tier="pro")
        info = await auth.validate_key(result["key"])
        assert info["rpm_limit"] == 300
        assert info["daily_limit"] == 50000

    @pytest.mark.asyncio
    async def test_invalid_tier(self, auth):
        with pytest.raises(ValueError):
            await auth.create_key(owner="test", tier="enterprise")


class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_rate_limit_allows_under_limit(self, auth):
        result = await auth.create_key(owner="test", tier="free")
        info = await auth.validate_key(result["key"])
        assert await auth.check_rate_limit(info) is True

    @pytest.mark.asyncio
    async def test_rate_limit_blocks_over_rpm(self, auth):
        result = await auth.create_key(owner="test", tier="free")
        info = await auth.validate_key(result["key"])

        # Exhaust the RPM limit (60)
        for _ in range(60):
            assert await auth.check_rate_limit(info) is True

        # 61st should fail
        assert await auth.check_rate_limit(info) is False


class TestUsageTracking:
    @pytest.mark.asyncio
    async def test_record_and_get_usage(self, auth):
        result = await auth.create_key(owner="test", tier="free")
        key_id = result["key_id"]

        await auth.record_usage(key_id, "/api/firewall")
        await auth.record_usage(key_id, "/api/firewall")
        await auth.record_usage(key_id, "/api/scan")

        usage = await auth.get_usage(key_id)
        assert usage["total"] == 3
        assert usage["by_endpoint"]["/api/firewall"] == 2
        assert usage["by_endpoint"]["/api/scan"] == 1


class TestDeactivation:
    @pytest.mark.asyncio
    async def test_deactivate_key(self, auth):
        result = await auth.create_key(owner="test", tier="free")
        key_id = result["key_id"]

        # Active
        info = await auth.validate_key(result["key"])
        assert info is not None

        # Deactivate
        await auth.deactivate_key(key_id)

        # Should now return None
        info = await auth.validate_key(result["key"])
        assert info is None
