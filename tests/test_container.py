"""Tests for core.container.ServiceContainer."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from core.config import Settings


class TestServiceContainer:
    def test_container_creates_all_services(self):
        """Container initializes all expected service attributes."""
        with patch("core.container.Web3Client") as MockWeb3, \
             patch("core.container.AIAnalyzer") as MockAI, \
             patch("core.container.ScamDatabase"), \
             patch("core.container.CalldataDecoder"), \
             patch("core.container.OnchainRecorder"), \
             patch("core.container.TransactionScanner"), \
             patch("core.container.TokenScanner"), \
             patch("core.container.DexService"), \
             patch("core.container.EthosService"), \
             patch("core.container.HoneypotService"), \
             patch("core.container.ContractService"), \
             patch("core.container.GreenfieldService"), \
             patch("core.container.TenderlySimulator"), \
             patch("core.container.RiskEngine"):

            from core.container import ServiceContainer
            s = Settings(_env_file=None)
            c = ServiceContainer(s)

            assert c.settings is s
            assert c.web3_client is not None
            assert c.ai_analyzer is not None
            assert c.tx_scanner is not None
            assert c.token_scanner is not None
            assert c.calldata_decoder is not None
            assert c.scam_db is not None
            assert c.dex_service is not None
            assert c.ethos_service is not None
            assert c.honeypot_service is not None
            assert c.contract_service is not None
            assert c.risk_engine is not None
            assert c.greenfield_service is not None
            assert c.tenderly_simulator is not None

    @pytest.mark.asyncio
    async def test_startup_shutdown(self):
        """startup() and shutdown() call the right async methods."""
        with patch("core.container.Web3Client"), \
             patch("core.container.AIAnalyzer") as MockAI, \
             patch("core.container.ScamDatabase"), \
             patch("core.container.CalldataDecoder"), \
             patch("core.container.OnchainRecorder"), \
             patch("core.container.TransactionScanner"), \
             patch("core.container.TokenScanner"), \
             patch("core.container.DexService"), \
             patch("core.container.EthosService"), \
             patch("core.container.HoneypotService"), \
             patch("core.container.ContractService"), \
             patch("core.container.GreenfieldService") as MockGF, \
             patch("core.container.TenderlySimulator") as MockTenderly, \
             patch("core.container.RiskEngine"):

            MockAI.return_value.is_available.return_value = False
            MockGF.return_value.is_enabled.return_value = False
            MockGF.return_value.async_init = AsyncMock()
            MockGF.return_value.close = AsyncMock()
            MockTenderly.return_value.is_enabled.return_value = False
            MockTenderly.return_value.close = AsyncMock()

            from core.container import ServiceContainer
            s = Settings(_env_file=None)
            c = ServiceContainer(s)

            await c.startup()
            c.greenfield_service.async_init.assert_awaited_once()

            await c.shutdown()
            c.greenfield_service.close.assert_awaited_once()
            c.tenderly_simulator.close.assert_awaited_once()
