"""Centralized configuration via Pydantic Settings."""

from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Telegram
    telegram_bot_token: str = ""
    telegram_alert_chat_id: str = ""
    webhook_secret: str = ""  # shared secret for /webhook/uptime verification

    # BSC / Etherscan
    bscscan_api_key: str = ""

    # AI
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-3-haiku-20240307"

    # On-chain recording
    bot_wallet_private_key: str = ""

    # RPC endpoints
    bsc_rpc_url: str = "https://bsc-dataseed.binance.org/"
    # Archive RPC for eth_getLogs queries (approval scanning).
    # Must support 50k-block range getLogs. Defaults to NodeReal free tier.
    logs_rpc_url: str = ""
    opbnb_rpc_url: str = "https://opbnb-mainnet-rpc.bnbchain.org"
    eth_rpc_url: str = "https://ethereum-rpc.publicnode.com"
    base_rpc_url: str = "https://mainnet.base.org"
    arbitrum_rpc_url: str = "https://arb1.arbitrum.io/rpc"
    polygon_rpc_url: str = "https://polygon-bor-rpc.publicnode.com"
    optimism_rpc_url: str = "https://mainnet.optimism.io"

    # Etherscan API keys (per chain — all use Etherscan v2 API)
    etherscan_api_key: str = ""
    basescan_api_key: str = ""
    arbiscan_api_key: str = ""
    polygonscan_api_key: str = ""
    opbnbscan_api_key: str = ""
    optimism_api_key: str = ""

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
    cors_allow_all: bool = False

    # Proxy trust (comma-separated IPs of trusted reverse proxies)
    trusted_proxy_ips: str = ""

    # Bot settings
    risk_threshold: int = 70
    cache_duration: int = 300

    # Policy mode (STRICT or BALANCED)
    policy_mode: str = "BALANCED"

    # Database
    database_path: str = "shieldbot.db"

    # Calibration
    calibration_config_path: str = "core/calibration_config.json"

    # Token Sniffer (bytecode fingerprinting for unverified contracts)
    token_sniffer_api_key: str = ""

    # Resend (beta welcome emails)
    resend_api_key: str = ""
    resend_from_email: str = "ShieldBot <noreply@shieldbotsecurity.online>"

    # Admin
    admin_secret: str = ""

    # Webhook security
    webhook_allow_query_secret: bool = False

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
        parts = [o.strip() for o in raw.split(",") if o.strip()]
        if any(p == "*" for p in parts):
            # Only allow wildcard if explicitly enabled.
            if self.cors_allow_all:
                return ["*"]
            return default_origins
        return parts

    @property
    def trusted_proxies(self) -> List[str]:
        """Parse trusted proxy IPs from comma-separated string."""
        raw = self.trusted_proxy_ips.strip()
        if not raw:
            return []
        return [ip.strip() for ip in raw.split(",") if ip.strip()]
