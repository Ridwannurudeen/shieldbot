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
    MempoolMonitor, RescueService, CampaignService,
)
from core.risk_engine import RiskEngine
from core.calibration import load_calibration
from core.database import Database
from core.registry import AnalyzerRegistry
from core.policy import PolicyEngine
from core.auth import AuthManager
from core.indexer import DeployerIndexer
from analyzers import (
    StructuralAnalyzer, MarketAnalyzer, BehavioralAnalyzer,
    HoneypotAnalyzer, IntentMismatchAnalyzer, SignaturePermitAnalyzer,
)
from adapters.eth import EthAdapter
from adapters.base_chain import BaseChainAdapter
from adapters.arbitrum import ArbitrumAdapter
from adapters.polygon import PolygonAdapter
from adapters.opbnb import OpBNBAdapter
from adapters.optimism import OptimismAdapter

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

        # Register multichain adapters
        # Etherscan v2 API accepts any chain's key across all chains,
        # so fall back to bscscan_api_key when chain-specific key is empty.
        eth_api_key = settings.etherscan_api_key or settings.bscscan_api_key
        base_api_key = settings.basescan_api_key or settings.bscscan_api_key
        self.eth_adapter = EthAdapter(
            rpc_url=settings.eth_rpc_url,
            etherscan_api_key=eth_api_key,
        )
        self.base_adapter = BaseChainAdapter(
            rpc_url=settings.base_rpc_url,
            basescan_api_key=base_api_key,
        )
        self.web3_client.register_adapter(self.eth_adapter)
        self.web3_client.register_adapter(self.base_adapter)

        arb_api_key = settings.arbiscan_api_key or settings.bscscan_api_key
        poly_api_key = settings.polygonscan_api_key or settings.bscscan_api_key
        self.arb_adapter = ArbitrumAdapter(
            rpc_url=settings.arbitrum_rpc_url,
            arbiscan_api_key=arb_api_key,
        )
        self.polygon_adapter = PolygonAdapter(
            rpc_url=settings.polygon_rpc_url,
            polygonscan_api_key=poly_api_key,
        )
        self.web3_client.register_adapter(self.arb_adapter)
        self.web3_client.register_adapter(self.polygon_adapter)

        opbnb_api_key = settings.opbnbscan_api_key or settings.bscscan_api_key
        optimism_api_key = settings.optimism_api_key or settings.bscscan_api_key
        self.opbnb_adapter = OpBNBAdapter(
            rpc_url=settings.opbnb_rpc_url,
            opbnbscan_api_key=opbnb_api_key,
        )
        self.optimism_adapter = OptimismAdapter(
            rpc_url=settings.optimism_rpc_url,
            optimism_api_key=optimism_api_key,
        )
        self.web3_client.register_adapter(self.opbnb_adapter)
        self.web3_client.register_adapter(self.optimism_adapter)

        # Scanners (legacy fallback)
        self.tx_scanner = TransactionScanner(self.web3_client, self.ai_analyzer)
        self.token_scanner = TokenScanner(self.web3_client, self.ai_analyzer)

        # Intelligence services
        self.dex_service = DexService()
        self.ethos_service = EthosService()
        self.honeypot_service = HoneypotService(self.web3_client)
        self.contract_service = ContractService(self.web3_client, self.scam_db)

        # Risk engine + analyzer registry
        self.calibration = load_calibration(settings.calibration_config_path)
        self.risk_engine = RiskEngine(calibration=self.calibration)
        self.registry = AnalyzerRegistry()
        self.registry.register(StructuralAnalyzer(self.contract_service))
        self.registry.register(MarketAnalyzer(self.dex_service))
        self.registry.register(BehavioralAnalyzer(self.ethos_service))
        self.registry.register(HoneypotAnalyzer(self.honeypot_service))
        self.registry.register(IntentMismatchAnalyzer())
        self.registry.register(SignaturePermitAnalyzer())

        # Policy engine
        self.policy_engine = PolicyEngine(settings.policy_mode)

        # Database + Auth + Indexer
        self.db = Database(settings.database_path)
        self.auth_manager = AuthManager(self.db)
        self.indexer = DeployerIndexer(self.web3_client, self.db)

        # Mempool monitor + Rescue mode + Campaign detection
        self.mempool_monitor = MempoolMonitor(self.web3_client, self.db)
        self.rescue_service = RescueService(self.web3_client, self.db)
        self.campaign_service = CampaignService(self.web3_client, self.db)

        # Optional services (need async init)
        self.greenfield_service = GreenfieldService()
        self.tenderly_simulator = TenderlySimulator()

    async def startup(self):
        """Initialize async-dependent services."""
        await self.db.initialize()
        await self.indexer.start()
        await self.greenfield_service.async_init()
        # Start mempool monitor on BSC and ETH (chains with txpool support)
        await self.mempool_monitor.start(chain_ids=[56, 1])
        logger.info("ServiceContainer started")
        logger.info(f"AI Analysis: {'enabled' if self.ai_analyzer.is_available() else 'disabled'}")
        logger.info(f"Greenfield storage: {'enabled' if self.greenfield_service.is_enabled() else 'disabled'}")
        logger.info(f"Tenderly simulation: {'enabled' if self.tenderly_simulator.is_enabled() else 'disabled'}")

    async def shutdown(self):
        """Clean up resources."""
        await self.mempool_monitor.stop()
        await self.indexer.stop()
        await self.db.close()
        await self.greenfield_service.close()
        await self.tenderly_simulator.close()
        logger.info("ServiceContainer shut down")
