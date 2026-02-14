import os
import aiohttp
import logging

logger = logging.getLogger(__name__)

ETHOS_API_BASE = "https://api.ethos.network/api/v2"
ETHOS_PROFILES_URL = f"{ETHOS_API_BASE}/profiles/{{userkey}}"

# Score thresholds on Ethos 0-2800 scale
LOW_REPUTATION_THRESHOLD = 500
SEVERE_REPUTATION_THRESHOLD = 300


class EthosService:
    """Fetches wallet reputation data from Ethos Network."""

    def __init__(self):
        self.privy_token = os.getenv('ETHOS_PRIVY_TOKEN')

    async def fetch_wallet_reputation(self, wallet_address: str) -> dict:
        defaults = {
            'reputation_score': 50,
            'ethos_raw_score': None,
            'trust_level': 'unknown',
            'scam_flags': [],
            'linked_wallets': [],
            'vouch_count': 0,
            'review_stats': {},
            'low_reputation_flag': False,
            'severe_reputation_flag': False,
        }

        try:
            userkey = f"address:{wallet_address}"
            headers = {'X-Ethos-Client': 'shieldbot@1.0'}

            if self.privy_token:
                headers['Authorization'] = f'Bearer {self.privy_token}'

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    ETHOS_PROFILES_URL.format(userkey=userkey),
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 404:
                        # No Ethos profile — not necessarily bad, return neutral
                        return defaults
                    if resp.status != 200:
                        logger.warning("Ethos API returned %s for %s", resp.status, wallet_address)
                        return defaults

                    data = await resp.json()

            # Ethos score is 0-2800; normalize to 0-100 for our engine
            raw_score = data.get('score', 0)
            normalized = round((raw_score / 2800) * 100, 1) if raw_score else 50

            # Extract stats
            stats = data.get('stats', {})
            vouch_received = stats.get('vouch', {}).get('received', {})
            review_received = stats.get('review', {}).get('received', {})
            vouch_count = vouch_received.get('count', 0)

            # Trust level based on raw score
            if raw_score >= 1800:
                trust_level = 'high'
            elif raw_score >= 1000:
                trust_level = 'medium'
            elif raw_score >= 500:
                trust_level = 'low'
            else:
                trust_level = 'very_low'

            status = data.get('status', 'ACTIVE')
            scam_flags = []
            if status == 'SLASHED':
                scam_flags.append('Profile slashed on Ethos')

            negative_reviews = review_received.get('negative', 0)
            if negative_reviews > 3:
                scam_flags.append(f'{negative_reviews} negative reviews')

            return {
                'reputation_score': normalized,
                'ethos_raw_score': raw_score,
                'trust_level': trust_level,
                'scam_flags': scam_flags,
                'linked_wallets': [],
                'vouch_count': vouch_count,
                'review_stats': review_received,
                'low_reputation_flag': raw_score < LOW_REPUTATION_THRESHOLD,
                'severe_reputation_flag': raw_score < SEVERE_REPUTATION_THRESHOLD,
            }

        except Exception as e:
            logger.error("Ethos fetch failed for %s: %s", wallet_address, e)
            return defaults
