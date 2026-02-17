"""Tests for core.config.Settings."""

import os
import pytest
from core.config import Settings


class TestSettings:
    def test_defaults(self, monkeypatch):
        """Settings loads with sensible defaults when no env vars set."""
        # Clear any existing env vars that would interfere
        for key in ("TELEGRAM_BOT_TOKEN", "BSCSCAN_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(key, raising=False)
        s = Settings(_env_file=None)
        assert s.bsc_rpc_url == "https://bsc-dataseed.binance.org/"
        assert s.opbnb_rpc_url == "https://opbnb-mainnet-rpc.bnbchain.org"
        assert s.risk_threshold == 70
        assert s.cache_duration == 300
        assert s.policy_mode == "BALANCED"
        assert s.database_path == "shieldbot.db"

    def test_cors_origins_default(self, monkeypatch):
        monkeypatch.delenv("CORS_ALLOW_ORIGINS", raising=False)
        s = Settings(_env_file=None)
        origins = s.cors_origins
        assert "http://localhost:8000" in origins
        assert len(origins) == 3

    def test_cors_origins_custom(self, monkeypatch):
        monkeypatch.setenv("CORS_ALLOW_ORIGINS", "https://example.com, https://foo.bar")
        s = Settings(_env_file=None)
        origins = s.cors_origins
        assert origins == ["https://example.com", "https://foo.bar"]

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("RISK_THRESHOLD", "80")
        monkeypatch.setenv("POLICY_MODE", "STRICT")
        s = Settings(_env_file=None)
        assert s.risk_threshold == 80
        assert s.policy_mode == "STRICT"
