import logging
import math
import time
from decimal import Decimal, InvalidOperation

from utils.scam_db import ScamDatabase

logger = logging.getLogger(__name__)

_TRADE_FIELDS = ('is_honeypot', 'buy_tax', 'sell_tax', 'can_buy', 'can_sell')
# A sell tax (percent) above this is scored by the honeypot analyzer (analyzers/honeypot.py), and
# only a GoPlus sell tax above it stands in for one ShieldBot's own simulation could not measure,
# so the gate never takes a tax the analyzer would not score.
SELL_TAX_HIGH = 20


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
            'observed_at': time.time(),
            'is_honeypot': None,
            'honeypot_reason': None,
            'simulation_failed': False,
            'rpc_failed': False,
            'low_tax_honeypot': False,
            'likely_false_positive': False,
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
                data['observed_at'] = min(data['observed_at'], response.get('observed_at', data['observed_at']))
                if response.get('reason'):
                    reasons.append(response['reason'])
                # A provider that does not name itself for a field is honeypot.is.
                providers = response.get('field_providers') or {}
                for field in ('simulation_failed', 'low_tax_honeypot', 'likely_false_positive'):
                    if response.get(field) is True:
                        data[field] = True
                        data['field_providers'][field] = providers.get(field, 'honeypot.is')
                # Only ShieldBot's own simulations (Robinhood Chain, Arbitrum One) report one that could not run.
                if response.get('rpc_failed') is True:
                    data['rpc_failed'] = True
                    data['field_providers']['rpc_failed'] = 'eth_simulateV1'
                if response.get('simulation_success') is False:
                    simulation_success = False
                elif response.get('simulation_success') is True and simulation_success is None:
                    simulation_success = True
                for field in ('is_honeypot', 'can_buy', 'can_sell'):
                    if isinstance(response.get(field), bool):
                        data[field] = response[field]
                        data['field_providers'][field] = providers.get(field, 'honeypot.is')
                for field in ('buy_tax', 'sell_tax'):
                    value = response.get(field)
                    if type(value) in (int, float) and math.isfinite(value) and value >= 0:
                        data[field] = value
                        data['field_providers'][field] = providers.get(field, 'honeypot.is')
                # Only ShieldBot's own simulations (Robinhood Chain, Arbitrum One) report a block; other
                # providers' output is unchanged.
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
        # A GoPlus sell tax taken for a sell ShieldBot's own simulation made at a tax it could not measure.
        goplus_tax_for_unmeasured_sell = False
        if any(data[field] is None for field in _TRADE_FIELDS):
            try:
                response = await ScamDatabase.fetch_token_security(address, chain_id)
                data['observed_at'] = min(data['observed_at'], response.get('observed_at', 0))
                mapped = map_goplus_token_security(response['data'])
                if response['reason']:
                    reasons.append(response['reason'])
                # A sell ShieldBot's own simulation made at a tax it could not measure: GoPlus's tax is not
                # that sell's, so the sell tax stays unknown. Above SELL_TAX_HIGH, where the honeypot
                # analyzer scores a sell tax, GoPlus's tax is evidence against the token: it is taken and
                # scored, but it still does not complete the answer (coverage below).
                unmeasured = (data['can_sell'] is True and data['sell_tax'] is None
                              and data['field_providers'].get('can_sell') == 'eth_simulateV1')
                for field, value in mapped.items():
                    if data.get(field) is None and not (unmeasured and field == 'sell_tax'
                                                        and (value is None or value <= SELL_TAX_HIGH)):
                        data[field] = value
                        if value is not None:
                            data['field_providers'][field] = 'goplus'
                goplus_tax_for_unmeasured_sell = unmeasured and data['sell_tax'] is not None
            except UnsupportedChainError:
                raise
            except Exception as e:
                logger.error('GoPlus fallback failed for %s: %s', address, type(e).__name__)
                reasons.append(f'GoPlus fallback failed ({type(e).__name__})')

        # A honeypot verdict is a failed sell, whatever tax or sellability a provider reported with it
        # (the Robinhood simulator reports a sell that paid out nothing as sellable at 100% tax).
        if data['is_honeypot'] is True and data['can_sell'] is not False:
            data['can_sell'] = False
            data['field_providers']['can_sell'] = data['field_providers']['is_honeypot']

        if data['simulation_failed']:
            if data['can_sell'] is True:
                data['can_sell'] = None
                data['field_providers'].pop('can_sell', None)
            reasons.append('Honeypot simulation failed (unresolved)')

        # ShieldBot's own simulation could not run. GoPlus misses the honeypots it exists to catch, so a
        # GoPlus answer cannot establish sellability instead; unknown, but nothing about the token was
        # observed, so it is not scored as suspicious.
        if data['rpc_failed']:
            if data['can_sell'] is True:
                data['can_sell'] = None
                data['field_providers'].pop('can_sell', None)
            reasons.append('Honeypot simulation could not run (unresolved)')

        data['coverage'] = {field: data[field] is not None for field in _TRADE_FIELDS}
        if data['simulation_failed'] or data['rpc_failed']:
            data['coverage']['can_sell'] = False
        if goplus_tax_for_unmeasured_sell:
            data['coverage']['sell_tax'] = False
        missing = [field for field, covered in data['coverage'].items() if not covered]
        data['status'] = 'unknown' if missing else 'ok'
        if missing:
            reasons.append(f'Unknown fields: {", ".join(missing)}')
        data['reason'] = '; '.join(dict.fromkeys(reasons)) if reasons else None
        data['honeypot_reason'] = data['reason']
        return data
