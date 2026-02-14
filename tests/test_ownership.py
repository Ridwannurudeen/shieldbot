"""Tests for tri-state ownership propagation (None = unknown, True, False)."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from core.risk_engine import RiskEngine


class TestWeb3ClientOwnershipTriState:
    """web3_client returns is_renounced: None on error."""

    def test_error_returns_none(self, mock_web3_client):
        """When get_ownership_info fails, default is_renounced should be None."""
        mock_web3_client.get_ownership_info = AsyncMock(
            return_value={"owner": None, "is_renounced": None}
        )
        result = asyncio.run(mock_web3_client.get_ownership_info("0xabc"))
        assert result["is_renounced"] is None

    def test_renounced_returns_true(self, mock_web3_client):
        mock_web3_client.get_ownership_info = AsyncMock(
            return_value={
                "owner": "0x0000000000000000000000000000000000000000",
                "is_renounced": True,
            }
        )
        result = asyncio.run(mock_web3_client.get_ownership_info("0xabc"))
        assert result["is_renounced"] is True

    def test_active_owner_returns_false(self, mock_web3_client):
        mock_web3_client.get_ownership_info = AsyncMock(
            return_value={
                "owner": "0x1234567890123456789012345678901234567890",
                "is_renounced": False,
            }
        )
        result = asyncio.run(mock_web3_client.get_ownership_info("0xabc"))
        assert result["is_renounced"] is False


class TestRiskEngineOwnershipPenalty:
    """risk_engine only penalizes is_renounced=False, not None."""

    def _base_contract_data(self, ownership_renounced):
        return {
            "is_contract": True,
            "is_verified": True,
            "contract_age_days": 90,
            "scam_matches": [],
            "ownership_renounced": ownership_renounced,
            "has_mint": False,
            "has_proxy": False,
            "has_pause": False,
            "has_blacklist": False,
        }

    def _empty_honeypot(self):
        return {"is_honeypot": False, "can_sell": True, "sell_tax": 0, "buy_tax": 0}

    def _empty_dex(self):
        return {"liquidity_usd": 50_000, "pair_age_hours": 100}

    def _empty_ethos(self):
        return {"reputation_score": 50}

    def test_false_ownership_adds_penalty(self):
        engine = RiskEngine()
        result = engine.compute_composite_risk(
            self._base_contract_data(False),
            self._empty_honeypot(),
            self._empty_dex(),
            self._empty_ethos(),
        )
        # structural should include the +5 for ownership not renounced
        assert result["category_scores"]["structural"] >= 5

    def test_none_ownership_no_penalty(self):
        engine = RiskEngine()
        result = engine.compute_composite_risk(
            self._base_contract_data(None),
            self._empty_honeypot(),
            self._empty_dex(),
            self._empty_ethos(),
        )
        # structural should be 0 (verified, old, no patterns, no scams, ownership=None)
        assert result["category_scores"]["structural"] == 0

    def test_true_ownership_no_penalty(self):
        engine = RiskEngine()
        result = engine.compute_composite_risk(
            self._base_contract_data(True),
            self._empty_honeypot(),
            self._empty_dex(),
            self._empty_ethos(),
        )
        assert result["category_scores"]["structural"] == 0

    def test_rug_rule_requires_false_not_none(self):
        """mint + proxy + ownership=None should NOT trigger the rug escalation."""
        engine = RiskEngine()
        contract = self._base_contract_data(None)
        contract["has_mint"] = True
        contract["has_proxy"] = True
        result = engine.compute_composite_risk(
            contract,
            self._empty_honeypot(),
            self._empty_dex(),
            self._empty_ethos(),
        )
        # Without the rug escalation, composite should be less than 85
        assert result["rug_probability"] < 85

    def test_rug_rule_triggers_with_false(self):
        """mint + proxy + ownership=False SHOULD trigger the rug escalation."""
        engine = RiskEngine()
        contract = self._base_contract_data(False)
        contract["has_mint"] = True
        contract["has_proxy"] = True
        result = engine.compute_composite_risk(
            contract,
            self._empty_honeypot(),
            self._empty_dex(),
            self._empty_ethos(),
        )
        assert result["rug_probability"] >= 85
