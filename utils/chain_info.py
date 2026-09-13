"""Chain info — centralized chain metadata for multichain support."""

from typing import Dict, Optional, Tuple

CHAIN_INFO: Dict[int, Dict[str, str]] = {
    56: {
        'name': 'BSC',
        'explorer_url': 'https://bscscan.com',
        'dexscreener_slug': 'bsc',
        'native_symbol': 'BNB',
    },
    204: {
        'name': 'opBNB',
        'explorer_url': 'https://opbnbscan.com',
        'dexscreener_slug': 'opbnb',
        'native_symbol': 'BNB',
    },
    1: {
        'name': 'Ethereum',
        'explorer_url': 'https://etherscan.io',
        'dexscreener_slug': 'ethereum',
        'native_symbol': 'ETH',
    },
    8453: {
        'name': 'Base',
        'explorer_url': 'https://basescan.org',
        'dexscreener_slug': 'base',
        'native_symbol': 'ETH',
    },
    42161: {
        'name': 'Arbitrum',
        'explorer_url': 'https://arbiscan.io',
        'dexscreener_slug': 'arbitrum',
        'native_symbol': 'ETH',
    },
    137: {
        'name': 'Polygon',
        'explorer_url': 'https://polygonscan.com',
        'dexscreener_slug': 'polygon',
        'native_symbol': 'MATIC',
    },
    4663: {
        'name': 'Robinhood Chain',
        'explorer_url': 'https://robinhoodchain.blockscout.com',
        'dexscreener_slug': 'robinhood',
        'native_symbol': 'ETH',
    },
    10: {
        'name': 'Optimism',
        'explorer_url': 'https://optimistic.etherscan.io',
        'dexscreener_slug': 'optimism',
        'native_symbol': 'ETH',
    },
}

# Chain prefix aliases for parsing "eth:0x..." or "base:0x..."
CHAIN_PREFIXES: Dict[str, int] = {
    'bsc': 56,
    'bnb': 56,
    'eth': 1,
    'ethereum': 1,
    'base': 8453,
    'opbnb': 204,
    'arb': 42161,
    'arbitrum': 42161,
    'poly': 137,
    'polygon': 137,
    'op': 10,
    'optimism': 10,
    'robinhood': 4663,
    'rh': 4663,
}


def get_chain_name(chain_id: int) -> str:
    """Get human-readable chain name."""
    info = CHAIN_INFO.get(chain_id)
    return info['name'] if info else f'Chain {chain_id}'


def get_explorer_url(chain_id: int) -> Optional[str]:
    """Get block explorer base URL for a chain."""
    info = CHAIN_INFO.get(chain_id)
    return info['explorer_url'] if info else None


def get_dexscreener_slug(chain_id: int) -> Optional[str]:
    """Get DexScreener chain slug."""
    info = CHAIN_INFO.get(chain_id)
    return info['dexscreener_slug'] if info else None


def get_native_symbol(chain_id: int) -> Optional[str]:
    """Get native currency symbol."""
    info = CHAIN_INFO.get(chain_id)
    return info['native_symbol'] if info else None


def parse_chain_prefix(text: str) -> Tuple[Optional[int], str]:
    """Parse an optional chain prefix from an address string.

    Supports formats like:
        "eth:0xabc..." -> (1, "0xabc...")
        "base:0xabc..." -> (8453, "0xabc...")
        "0xabc..." -> (None, "0xabc...")

    Returns (chain_id or None, address).
    """
    text = text.strip()
    if ':' in text:
        prefix, address = text.split(':', 1)
        prefix = prefix.strip().lower()
        chain_id = CHAIN_PREFIXES.get(prefix)
        if chain_id is not None:
            return chain_id, address.strip()
    return None, text
