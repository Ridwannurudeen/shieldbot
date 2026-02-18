import logging

logger = logging.getLogger(__name__)


class HoneypotService:
    """Wraps existing web3_client honeypot checks."""

    def __init__(self, web3_client):
        self.web3_client = web3_client

    async def fetch_honeypot_data(self, address: str, chain_id: int = 56) -> dict:
        defaults = {
            'is_honeypot': False,
            'honeypot_reason': None,
            'buy_tax': 0,
            'sell_tax': 0,
            'can_buy': True,
            'can_sell': True,
        }

        try:
            honeypot_result = await self.web3_client.check_honeypot(address, chain_id=chain_id)
            tax_result = await self.web3_client.get_tax_info(address, chain_id=chain_id)

            is_honeypot = honeypot_result.get('is_honeypot', False)
            honeypot_reason = honeypot_result.get('reason')
            buy_tax = tax_result.get('buy_tax', 0)
            sell_tax = tax_result.get('sell_tax', 0)

            return {
                'is_honeypot': is_honeypot,
                'honeypot_reason': honeypot_reason,
                'buy_tax': buy_tax,
                'sell_tax': sell_tax,
                'can_buy': buy_tax < 100,
                'can_sell': sell_tax < 100,
            }

        except Exception as e:
            logger.error("Honeypot fetch failed for %s: %s", address, e)
            return defaults
