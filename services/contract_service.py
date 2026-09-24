import asyncio
import logging
import time
from decimal import Decimal, InvalidOperation
from typing import Optional

from adapters.evm_base import BURN_ADDRESSES

logger = logging.getLogger(__name__)

# Bytecode signatures for dangerous patterns
BYTECODE_PATTERNS = {
    '40c10f19': 'mint',
    'a0712d68': 'mint',
    '8456cb59': 'pause',
    '44337ea1': 'blacklist',
    '3659cfe6': 'proxy_upgrade',
    '4f1ef286': 'proxy_upgrade',
    '83197ef0': 'destroy',
}

# Small delay between BscScan API calls to avoid free-tier rate limit (5/sec)
BSCSCAN_DELAY = 0.25


def push4_operands(bytecode_hex: str) -> set:
    """Every PUSH4 operand in the code, as hex, found by walking the opcodes once.

    A Solidity dispatcher compares the call's selector against PUSH4 operands, so a selector found
    here is a function; the same bytes inside another push's data (PUSH1 to PUSH32 immediates are
    skipped) are not. The walk runs straight from byte 0, so data stored after the code, such as
    tables read with CODECOPY or the metadata tail, is read as opcodes and can desync it there.
    """
    code = bytes.fromhex(bytecode_hex[2:] if bytecode_hex.startswith('0x') else bytecode_hex)
    operands = set()
    position = 0
    while position < len(code):
        opcode = code[position]
        if 0x60 <= opcode <= 0x7f:
            if opcode == 0x63:
                operands.add(code[position + 1:position + 5].hex())
            position += opcode - 0x5f
        position += 1
    return operands


def top_holder_share(goplus: dict, excluded: set) -> Optional[float]:
    """Percent of total supply held by the largest holders GoPlus lists, rounded to 0.01.

    GoPlus lists a token's ten largest holders, each with `percent` as a fraction of total supply.
    Left out: `excluded` (burn addresses and the chain's known lockers), holders GoPlus marks
    locked, and the token's DEX pairs and pool managers, which hold liquidity rather than a stake;
    so the share covers fewer than ten holders when any are left out. None when GoPlus gave no
    holder list or an entry cannot be read: a missing list is Unknown, never a spread-out token.
    """
    holders = goplus.get('holders')
    if not isinstance(holders, list) or not holders:
        return None
    pools = {
        str(pool[key]).lower()
        for pool in goplus.get('dex') or [] if isinstance(pool, dict)
        for key in ('pair', 'pool_manager') if pool.get(key)
    }
    share = Decimal(0)
    for holder in holders:
        if not isinstance(holder, dict) or not isinstance(holder.get('address'), str):
            return None
        try:
            fraction = Decimal(str(holder.get('percent')))
        except InvalidOperation:
            return None
        if not fraction.is_finite() or not 0 <= fraction <= 1:
            return None
        address = holder['address'].lower()
        if address not in excluded and address not in pools and holder.get('is_locked') not in (1, '1'):
            share += fraction
    return float(round(share * 100, 2))


class ContractService:
    """Wraps existing scanner + web3_client contract checks."""

    def __init__(self, web3_client, scam_db):
        self.web3_client = web3_client
        self.scam_db = scam_db

    async def fetch_contract_data(self, address: str, chain_id: int = 56) -> dict:
        from utils.web3_client import UnsupportedChainError

        defaults = {
            'observed_at': time.time(),
            'is_contract': False,
            'is_verified': None,
            'contract_age_days': None,
            'scam_matches': [],
            'ownership_renounced': None,
            'has_proxy': None,
            'has_mint': None,
            'has_pause': None,
            'has_blacklist': None,
            'has_destroy': None,
            'source_code_patterns': [],
            'bytecode_warnings': [],
            'top10_holder_percent': None,
        }

        try:
            is_contract = await self.web3_client.is_contract(address, chain_id=chain_id)
            if is_contract is None:
                return {**defaults, 'is_contract': None, 'status': 'unknown', 'reason': 'Contract data unavailable'}
            if not is_contract:
                return {
                    **defaults,
                    'has_proxy': False,
                    'has_mint': False,
                    'has_pause': False,
                    'has_blacklist': False,
                    'has_destroy': False,
                }

            results = {'is_contract': True}

            # Verification + source code
            verified, source_code = await self.web3_client.is_verified_contract(address, chain_id=chain_id)
            results['is_verified'] = verified

            await asyncio.sleep(BSCSCAN_DELAY)

            # Contract age
            creation_info = await self.web3_client.get_contract_creation_info(address, chain_id=chain_id)
            if creation_info:
                results['contract_age_days'] = creation_info.get('age_days')

            # Scam DB (external APIs, not BscScan — no delay needed)
            scam_matches = await self.scam_db.check_address(address, chain_id=chain_id)
            results['scam_matches'] = list(scam_matches or [])
            results['observed_at'] = min(defaults['observed_at'], getattr(scam_matches, 'observed_at', 0))
            failed_providers = getattr(scam_matches, 'failed_providers', ())
            if failed_providers:
                results['coverage'] = {'scam_database': False}
                results['reason'] = 'Scam database unavailable: ' + '; '.join(failed_providers)

            # GoPlus's token record, fetched by the scam check. When the explorer did not answer, it
            # says whether the source is open, which is the same fact.
            goplus = getattr(scam_matches, 'goplus_record', {})
            if results['is_verified'] is None and goplus.get('is_open_source') in ('0', '1'):
                results['is_verified'] = goplus['is_open_source'] == '1'
                results['field_providers'] = {'is_verified': 'goplus'}

            # The largest holders' share of supply, from the same record; None when it lists none.
            if goplus.get('holders'):
                lockers = self.web3_client._get_adapter(chain_id).get_known_lockers()
                results['top10_holder_percent'] = top_holder_share(goplus, BURN_ADDRESSES | set(lockers))

            # Ownership (RPC call, not BscScan)
            ownership = await self.web3_client.get_ownership_info(address, chain_id=chain_id)
            if ownership:
                results['ownership_renounced'] = ownership.get('is_renounced')
                if ownership.get('status') == 'unknown':
                    results['coverage'] = {**results.get('coverage', {}), 'ownership_renounced': False}
                    results['reason'] = '; '.join(filter(None, (results.get('reason'), ownership.get('reason'))))

            # Bytecode pattern scan (RPC call)
            bytecode_warnings = []
            has_proxy = None
            has_mint = None
            has_pause = None
            has_blacklist = None
            has_destroy = None

            try:
                bytecode = await self.web3_client.get_bytecode(address, chain_id=chain_id)
                if bytecode is None:
                    results['coverage'] = {**results.get('coverage', {}), 'bytecode': False}
                    results['reason'] = '; '.join(filter(None, (results.get('reason'), 'Bytecode scan unavailable')))
                else:
                    has_proxy = False
                    has_mint = False
                    has_pause = False
                    has_blacklist = False
                    has_destroy = False
                    if bytecode:
                        bytecode_hex = bytecode.hex() if isinstance(bytecode, bytes) else str(bytecode)
                        operands = push4_operands(bytecode_hex)
                        for sig, pattern_name in BYTECODE_PATTERNS.items():
                            if sig in operands:
                                bytecode_warnings.append(pattern_name)
                                if pattern_name == 'mint':
                                    has_mint = True
                                elif pattern_name == 'pause':
                                    has_pause = True
                                elif pattern_name == 'blacklist':
                                    has_blacklist = True
                                elif pattern_name == 'proxy_upgrade':
                                    has_proxy = True
                                elif pattern_name == 'destroy':
                                    has_destroy = True
            except UnsupportedChainError:
                raise
            except Exception as e:
                logger.warning("Bytecode scan failed for %s: %s", address, type(e).__name__)
                results['coverage'] = {**results.get('coverage', {}), 'bytecode': False}
                results['reason'] = '; '.join(filter(None, (results.get('reason'), 'Bytecode scan unavailable')))

            # GoPlus also finds blacklist functions under names the selector table does not list
            # (USDT's addBlackList); the owner power is the same whoever reports it.
            if has_blacklist is not True and goplus.get('is_blacklisted') == '1':
                has_blacklist = True
                results['field_providers'] = {**results.get('field_providers', {}), 'has_blacklist': 'goplus'}

            results['bytecode_warnings'] = bytecode_warnings
            results['has_proxy'] = has_proxy
            results['has_mint'] = has_mint
            results['has_pause'] = has_pause
            results['has_blacklist'] = has_blacklist
            results['has_destroy'] = has_destroy

            # Source code patterns
            source_patterns = []
            if source_code:
                patterns_to_check = [
                    'onlyOwner', 'blacklist', 'addBlacklist', 'setMaxTx',
                    'setMaxWallet', 'setFee', 'setTax', 'selfdestruct',
                    'delegatecall', 'mint', 'pause', 'proxy',
                ]
                for pat in patterns_to_check:
                    if pat.lower() in source_code.lower():
                        source_patterns.append(pat)

            results['source_code_patterns'] = source_patterns

            return {**defaults, **results}

        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Contract data fetch failed for %s: %s", address, type(e).__name__)
            return {**defaults, 'is_contract': None, 'status': 'unknown', 'reason': 'Contract data unavailable'}
