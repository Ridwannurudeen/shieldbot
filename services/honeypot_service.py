import logging
import math
from decimal import Decimal, InvalidOperation

from utils.scam_db import ScamDatabase

logger = logging.getLogger(__name__)

_TRADE_FIELDS = ('is_honeypot', 'buy_tax', 'sell_tax', 'can_buy', 'can_sell')


def map_goplus_token_security(raw: dict) -> dict:
    data = {}
    for field in ('is_honeypot', 'cannot_buy', 'cannot_sell_all', 'transfer_pausable'):
        value = raw.get(field)
        data[field] = value == '1' if value in ('0', '1') else None
    for field in ('buy_tax', 'sell_tax'):
        data[field] = None
        value = raw.get(field)
        if isinstance(value, str) and value:
            try:
                fraction = Decimal(value)
            except InvalidOperation:
                logger.warning('Invalid GoPlus %s value', field)
                continue
            if fraction.is_finite() and 0 <= fraction <= 1:
                data[field] = float(fraction * 100)
    data['can_buy'] = None
    if data['cannot_buy'] is True or data['buy_tax'] == 100:
        data['can_buy'] = False
    elif data['cannot_buy'] is False:
        data['can_buy'] = True
    data['can_sell'] = None
    if data['is_honeypot'] is True or data['sell_tax'] == 100:
        data['can_sell'] = False
    elif (data['is_honeypot'] is False and data['cannot_sell_all'] is False
          and data['transfer_pausable'] is False and data['sell_tax'] is not None):
        data['can_sell'] = True
    return data


class HoneypotService:
    """Wraps existing web3_client honeypot checks."""

    def __init__(self, web3_client):
        self.web3_client = web3_client

    async def fetch_honeypot_data(self, address: str, chain_id: int = 56) -> dict:
        from utils.web3_client import UnsupportedChainError

        if chain_id not in self.web3_client.get_supported_chain_ids():
            raise UnsupportedChainError(f'No registered adapter for chain {chain_id}')
        data = {
            'is_honeypot': None,
            'honeypot_reason': None,
            'simulation_failed': False,
            'low_tax_honeypot': False,
            'buy_tax': None,
            'sell_tax': None,
            'can_buy': None,
            'can_sell': None,
            'field_providers': {},
        }
        reasons = []
        simulation_success = None
        for fetch in (self.web3_client.check_honeypot, self.web3_client.get_tax_info):
            try:
                response = await fetch(address, chain_id=chain_id)
                if response.get('reason'):
                    reasons.append(response['reason'])
                for field in ('simulation_failed', 'low_tax_honeypot'):
                    if response.get(field) is True:
                        data[field] = True
                        data['field_providers'][field] = 'honeypot.is'
                if response.get('simulation_success') is False:
                    simulation_success = False
                elif response.get('simulation_success') is True and simulation_success is None:
                    simulation_success = True
                providers = response.get('field_providers') or {}
                for field in ('is_honeypot', 'can_buy', 'can_sell'):
                    if isinstance(response.get(field), bool):
                        data[field] = response[field]
                        data['field_providers'][field] = providers.get(field, 'honeypot.is')
                for field in ('buy_tax', 'sell_tax'):
                    value = response.get(field)
                    if type(value) in (int, float) and math.isfinite(value) and value >= 0:
                        data[field] = value
                        data['field_providers'][field] = providers.get(field, 'honeypot.is')
                # Only the Robinhood Chain simulation reports a block; other providers' output is unchanged.
                if type(response.get('simulation_block')) is int and 'simulation_block' not in data:
                    data['simulation_block'] = response['simulation_block']
            except UnsupportedChainError:
                raise
            except Exception as e:
                logger.error('Honeypot fetch failed for %s: %s', address, type(e).__name__)
                reasons.append(f'honeypot.is request failed ({type(e).__name__})')

        if (not data['simulation_failed'] and simulation_success is not False
                and data['is_honeypot'] is not None):
            for action, tax in (('can_buy', 'buy_tax'), ('can_sell', 'sell_tax')):
                if data[action] is None and data[tax] is not None:
                    data[action] = data[tax] < 100
                    data['field_providers'][action] = data['field_providers'][tax]
        if any(data[field] is None for field in _TRADE_FIELDS):
            try:
                response = await ScamDatabase.fetch_token_security(address, chain_id)
                mapped = map_goplus_token_security(response['data'])
                if response['reason']:
                    reasons.append(response['reason'])
                for field, value in mapped.items():
                    if data.get(field) is None:
                        data[field] = value
                        if value is not None:
                            data['field_providers'][field] = 'goplus'
            except UnsupportedChainError:
                raise
            except Exception as e:
                logger.error('GoPlus fallback failed for %s: %s', address, type(e).__name__)
                reasons.append(f'GoPlus fallback failed ({type(e).__name__})')

        if data['simulation_failed']:
            if data['can_sell'] is True:
                data['can_sell'] = None
                data['field_providers'].pop('can_sell', None)
            reasons.append('Honeypot simulation failed (unresolved)')

        data['coverage'] = {field: data[field] is not None for field in _TRADE_FIELDS}
        if data['simulation_failed']:
            data['coverage']['can_sell'] = False
        missing = [field for field, covered in data['coverage'].items() if not covered]
        data['status'] = 'unknown' if missing else 'ok'
        if missing:
            reasons.append(f'Unknown fields: {", ".join(missing)}')
        data['reason'] = '; '.join(dict.fromkeys(reasons)) if reasons else None
        data['honeypot_reason'] = data['reason']
        return data
