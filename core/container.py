"""Service container — single object holding all shared service instances."""

import logging

from core.config import Settings
from utils.web3_client import Web3Client
from utils.ai_analyzer import AIAnalyzer
from utils.scam_db import ScamDatabase
from utils.calldata_decoder import CalldataDecoder
from utils.onchain_recorder import OnchainRecorder
from scanner.transaction_scanner import TransactionScanner
from scanner.token_scanner import TokenScanner
from services import (
    DexService, EthosService, HoneypotService,
    ContractService, GreenfieldService, TenderlySimulator,
)
from core.risk_engine import RiskEngine
from core.database import Database
from core.registry import AnalyzerRegistry
from core.policy import PolicyEngine
from core.auth import AuthManager
from core.indexer import DeployerIndexer
from analyzers import StructuralAnalyzer, MarketAnalyzer, BehavioralAnalyzer, HoneypotAnalyzer

logger = logging.getLogger(__name__)


class ServiceContainer:
    """Holds all service instances. Call startup() on app init, shutdown() on teardown."""

    def __init__(self, settings: Settings):
        self.settings = settings

        # Core clients
        self.web3_client = Web3Client()
        self.ai_analyzer = AIAnalyzer()
        self.scam_db = ScamDatabase()
        self.calldata_decoder = CalldataDecoder()
        self.onchain_recorder = OnchainRecorder()

        # Scanners (legacy fallback)
        self.tx_scanner = TransactionScanner(self.web3_client, self.ai_analyzer)
        self.token_scanner = TokenScanner(self.web3_client, self.ai_analyzer)

        # Intelligence services
        self.dex_service = DexService()
        self.ethos_service = EthosService()
        self.honeypot_service = HoneypotService(self.web3_client)
        self.contract_service = ContractService(self.web3_client, self.scam_db)

        # Risk engine + analyzer registry
        self.risk_engine = RiskEngine()
        self.registry = AnalyzerRegistry()
        self.registry.register(StructuralAnalyzer(self.contract_service))
        self.registry.register(MarketAnalyzer(self.dex_service))
        self.registry.register(BehavioralAnalyzer(self.ethos_service))
        self.registry.register(HoneypotAnalyzer(self.honeypot_service))

        # Policy engine
        self.policy_engine = PolicyEngine(settings.policy_mode)

        # Database + Auth + Indexer
        self.db = Database(settings.database_path)
        self.auth_manager = AuthManager(self.db)
        self.indexer = DeployerIndexer(self.web3_client, self.db)

        # Optional services (need async init)
        self.greenfield_service = GreenfieldService()
        self.tenderly_simulator = TenderlySimulator()

    async def startup(self):
        """Initialize async-dependent services."""
        await self.db.initialize()
        await self.indexer.start()
        await self.greenfield_service.async_init()
        logger.info("ServiceContainer started")
        logger.info(f"AI Analysis: {'enabled' if self.ai_analyzer.is_available() else 'disabled'}")
        logger.info(f"Greenfield storage: {'enabled' if self.greenfield_service.is_enabled() else 'disabled'}")
        logger.info(f"Tenderly simulation: {'enabled' if self.tenderly_simulator.is_enabled() else 'disabled'}")

    async def shutdown(self):
        """Clean up resources."""
        await self.indexer.stop()
        await self.db.close()
        await self.greenfield_service.close()
        await self.tenderly_simulator.close()
        logger.info("ServiceContainer shut down")
