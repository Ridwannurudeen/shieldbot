"""Centralized configuration via Pydantic Settings."""

from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Telegram
    telegram_bot_token: str = ""

    # BSC / Etherscan
    bscscan_api_key: str = ""

    # AI
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-3-haiku-20240307"

    # On-chain recording
    bot_wallet_private_key: str = ""

    # RPC endpoints
    bsc_rpc_url: str = "https://bsc-dataseed.binance.org/"
    opbnb_rpc_url: str = "https://opbnb-mainnet-rpc.bnbchain.org"
    eth_rpc_url: str = "https://eth.llamarpc.com"
    base_rpc_url: str = "https://mainnet.base.org"

    # Etherscan API keys (per chain — all use Etherscan v2 API)
    etherscan_api_key: str = ""
    basescan_api_key: str = ""

    # Tenderly
    tenderly_api_key: str = ""
    tenderly_project_id: str = ""

    # Greenfield
    greenfield_bucket_name: str = "shieldbot-reports"
    greenfield_address: str = ""
    greenfield_private_key: str = ""

    # Ethos
    ethos_privy_token: str = ""

    # CORS
    cors_allow_origins: str = ""

    # Bot settings
    risk_threshold: int = 70
    cache_duration: int = 300

    # Policy mode (STRICT or BALANCED)
    policy_mode: str = "BALANCED"

    # Database
    database_path: str = "shieldbot.db"

    # Calibration
    calibration_config_path: str = "core/calibration_config.json"

    # RPC Proxy
    rpc_proxy_enabled: bool = True

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    @property
    def cors_origins(self) -> List[str]:
        """Parse CORS origins from comma-separated string."""
        default_origins = [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:3000",
            "https://shieldbotsecurity.online",
            "https://api.shieldbotsecurity.online",
        ]
        raw = self.cors_allow_origins.strip()
        if not raw:
            return default_origins
        return [o.strip() for o in raw.split(",") if o.strip()]
