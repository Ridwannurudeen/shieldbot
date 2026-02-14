import aiohttp
import logging

logger = logging.getLogger(__name__)

DEX_API_URL = "https://api.dexscreener.com/latest/dex/tokens/{address}"


class DexService:
    """Fetches token market data from DexScreener API."""

    async def fetch_token_market_data(self, address: str) -> dict:
        defaults = {
            'liquidity_usd': 0,
            'volume_24h': 0,
            'price_change_24h': 0,
            'fdv': 0,
            'pair_age_hours': None,
            'volatility_flag': False,
            'low_liquidity_flag': False,
            'wash_trade_flag': False,
            'new_pair_flag': False,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    DEX_API_URL.format(address=address),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status != 200:
                        logger.warning("DexScreener returned %s for %s", resp.status, address)
                        return defaults

                    data = await resp.json()

            pairs = data.get('pairs') or []
            if not pairs:
                return defaults

            # Use the highest-liquidity pair for price/liquidity/FDV metrics
            pair = max(pairs, key=lambda p: float(p.get('liquidity', {}).get('usd', 0) or 0))

            liquidity_usd = float(pair.get('liquidity', {}).get('usd', 0) or 0)
            price_change_24h = float(pair.get('priceChange', {}).get('h24', 0) or 0)
            fdv = float(pair.get('fdv', 0) or 0)

            # Aggregate volume across ALL pairs for accurate total trading activity
            volume_24h = sum(
                float(p.get('volume', {}).get('h24', 0) or 0)
                for p in pairs
            )

            pair_created = pair.get('pairCreatedAt')
            if pair_created:
                import time
                pair_age_hours = (time.time() * 1000 - pair_created) / (1000 * 3600)
            else:
                pair_age_hours = None

            # Risk flags
            low_liquidity_flag = liquidity_usd < 10_000
            new_pair_flag = pair_age_hours is not None and pair_age_hours < 24
            volatility_flag = abs(price_change_24h) > 200
            wash_trade_flag = (
                liquidity_usd < 50_000
                and liquidity_usd > 0
                and volume_24h > liquidity_usd * 10
            )

            return {
                'liquidity_usd': liquidity_usd,
                'volume_24h': volume_24h,
                'price_change_24h': price_change_24h,
                'fdv': fdv,
                'pair_age_hours': round(pair_age_hours, 1) if pair_age_hours else None,
                'volatility_flag': volatility_flag,
                'low_liquidity_flag': low_liquidity_flag,
                'wash_trade_flag': wash_trade_flag,
                'new_pair_flag': new_pair_flag,
            }

        except Exception as e:
            logger.error("DexScreener fetch failed for %s: %s", address, e)
            return defaults
