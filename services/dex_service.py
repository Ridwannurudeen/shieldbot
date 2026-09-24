import aiohttp
import logging
import math
import time

from core.circuit_breaker import provider_breakers
from core.unknown_ledger import unknown_ledger
from utils.chain_info import get_dexscreener_slug

logger = logging.getLogger(__name__)

# The token's pools on one chain. The unscoped latest/dex/tokens route answers with at most 30
# pairs from every chain, so where the same address exists on another chain (PulseChain copied
# Ethereum's state), those pairs can crowd out the requested chain's.
DEX_API_URL = "https://api.dexscreener.com/token-pairs/v1/{chain}/{address}"


class DexService:
    """Fetches token market data from DexScreener API."""

    async def fetch_token_market_data(self, address: str, chain_id: int = 56) -> dict:
        defaults = {
            'observed_at': time.time(),
            'token_name': None,
            'token_symbol': None,
            'price_usd': None,
            'liquidity_usd': None,
            'volume_24h': None,
            'price_change_24h': None,
            'fdv': None,
            'pair_age_hours': None,
            'volatility_flag': None,
            'low_liquidity_flag': None,
            'wash_trade_flag': None,
            'new_pair_flag': None,
        }

        metrics = ('price_usd', 'liquidity_usd', 'volume_24h', 'price_change_24h', 'fdv', 'pair_age_hours')
        defaults.update(status='unknown', reason='DexScreener data unavailable',
                        coverage={field: False for field in metrics})

        try:
            slug = get_dexscreener_slug(chain_id)
            if not slug:
                defaults['reason'] = f'DexScreener unsupported for chain {chain_id}'
                return defaults
            # One breaker for every chain: DexScreener is one service, whichever chain is asked.
            provider_breakers.check('dexscreener')
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    DEX_API_URL.format(chain=slug, address=address),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status != 200:
                        provider_breakers.record_status('dexscreener', None, resp.status)
                        unknown_ledger.record('dexscreener', chain_id, 'failed')
                        logger.warning("DexScreener returned %s for %s", resp.status, address)
                        defaults['reason'] = f'DexScreener HTTP {resp.status}'
                        return defaults

                    data = await resp.json()
                    provider_breakers.record_status('dexscreener', None, resp.status)

            pairs = [p for p in data if p.get('chainId') == slug]
            if not pairs:
                unknown_ledger.record('dexscreener', chain_id, 'unknown')
                defaults['reason'] = f'No DexScreener pairs on requested chain ({slug})'
                return defaults

            # Deepest pool first. Liquidity and pair age are the deepest pool's, whichever side
            # of it the token is on.
            pairs.sort(key=lambda p: float((p.get('liquidity') or {}).get('usd', 0) or 0), reverse=True)
            deepest = pairs[0]
            # A pair's price, 24h change, FDV and names are its base token's, so they come from the
            # deepest pair with the token as base token, and are unknown without one.
            token = address.lower()
            pair = next(
                (p for p in pairs if ((p.get('baseToken') or {}).get('address') or '').lower() == token),
                {},
            )

            base_token = pair.get('baseToken') or {}
            token_name = base_token.get('name')
            token_symbol = base_token.get('symbol')
            values = {
                'price_usd': pair.get('priceUsd'),
                'liquidity_usd': (deepest.get('liquidity') or {}).get('usd'),
                'price_change_24h': (pair.get('priceChange') or {}).get('h24'),
                'fdv': pair.get('fdv'),
            }
            for field, value in values.items():
                if value is None or value == '':
                    values[field] = None
                else:
                    number = float(value)
                    values[field] = number if math.isfinite(number) else None
            price_usd = values['price_usd']
            liquidity_usd = values['liquidity_usd']
            price_change_24h = values['price_change_24h']
            fdv = values['fdv']

            # Total volume is unknown if any requested-chain pair lacks volume.
            volumes = [(p.get('volume') or {}).get('h24') for p in pairs]
            volume_24h = None
            if all(v is not None and v != '' for v in volumes):
                total = sum(float(v) for v in volumes)
                volume_24h = total if math.isfinite(total) else None

            pair_created = deepest.get('pairCreatedAt')
            if pair_created:
                pair_age_hours = (time.time() * 1000 - pair_created) / (1000 * 3600)
            else:
                pair_age_hours = None

            # Risk flags
            low_liquidity_flag = liquidity_usd < 10_000 if liquidity_usd is not None else None
            new_pair_flag = pair_age_hours < 24 if pair_age_hours is not None else None
            volatility_flag = abs(price_change_24h) > 200 if price_change_24h is not None else None
            wash_trade_flag = (
                liquidity_usd < 50_000
                and liquidity_usd > 0
                and volume_24h > liquidity_usd * 10
            ) if liquidity_usd is not None and volume_24h is not None else None

            result = {
                'observed_at': defaults['observed_at'],
                'token_name': token_name,
                'token_symbol': token_symbol,
                'price_usd': price_usd,
                'liquidity_usd': liquidity_usd,
                'volume_24h': volume_24h,
                'price_change_24h': price_change_24h,
                'fdv': fdv,
                'pair_age_hours': round(pair_age_hours, 1) if pair_age_hours is not None else None,
                'volatility_flag': volatility_flag,
                'low_liquidity_flag': low_liquidity_flag,
                'wash_trade_flag': wash_trade_flag,
                'new_pair_flag': new_pair_flag,
            }

            coverage = {field: result[field] is not None for field in metrics}
            missing = [field for field, covered in coverage.items() if not covered]
            result.update(coverage=coverage, status='unknown' if missing else 'ok',
                          reason='Missing DexScreener fields: ' + ', '.join(missing) if missing else None)
            unknown_ledger.record('dexscreener', chain_id, 'answered')
            return result

        except Exception as e:
            provider_breakers.record_error('dexscreener', None, e)
            unknown_ledger.record('dexscreener', chain_id, 'failed')
            logger.error("DexScreener fetch failed for %s: %s", address, type(e).__name__)
            defaults['reason'] = f'DexScreener fetch failed: {type(e).__name__}'
            return defaults
