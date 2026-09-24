"""The unused TierService is gone and the container still builds without it."""

import importlib.util
from unittest.mock import patch

from core.config import Settings


def test_tier_service_module_is_removed():
    assert importlib.util.find_spec("services.tier_service") is None


def test_container_builds_without_tier_service():
    with (
        patch("core.container.Web3Client"),
        patch("core.container.AIAnalyzer"),
        patch("core.container.ScamDatabase"),
        patch("core.container.CalldataDecoder"),
        patch("core.container.OnchainRecorder"),
        patch("core.container.TransactionScanner"),
        patch("core.container.TokenScanner"),
        patch("core.container.DexService"),
        patch("core.container.EthosService"),
        patch("core.container.HoneypotService"),
        patch("core.container.ContractService"),
        patch("core.container.GreenfieldService"),
        patch("core.container.TenderlySimulator"),
        patch("core.container.RiskEngine"),
    ):
        from core.container import ServiceContainer

        container = ServiceContainer(Settings(_env_file=None))

    assert not hasattr(container, "tier_service")
