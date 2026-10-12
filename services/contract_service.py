import asyncio
import json
import logging
import re
import time
from decimal import Decimal, InvalidOperation
from typing import Optional

from eth_utils import keccak

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
# An interactive scan's explorer lookups (verification and contract creation: on Robinhood Chain one
# Blockscout addresses/{address} reply serves both) are used when they answer this long before the
# analyzers' deadline, so the analyzer returns before the registry cancels it, with only the fields
# still unanswered named as gaps. Its work after that wait is local.
EXPLORER_RESULT_RESERVE_SECONDS = 0.5
# A cached official Robinhood token list answers within a few event-loop turns. A cold one (a fetch
# of up to 10 s) does not hold up the explorer lookups, which start beside it.
OFFICIAL_LIST_WAIT_SECONDS = 0.05

# Words the source line reports, each attributed to a function the deployed code dispatches to
SOURCE_PATTERNS = [
    'onlyOwner', 'blacklist', 'addBlacklist', 'setMaxTx',
    'setMaxWallet', 'setFee', 'setTax', 'mint', 'pause',
]

COMMENTS_AND_STRINGS = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|/\*.*?\*/|//[^\n]*', re.S)
FUNCTION_HEADER = re.compile(r'\bfunction\s+(\w+)\s*\(([^)]*)\)([^{;]*)')
TYPE_AND_ARRAYS = re.compile(r'([A-Za-z_]\w*)((?:\[\d*\])*)')


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


def source_files(source_code: str) -> list:
    """The files in an explorer's source reply: a standard JSON input wrapped in one more pair of
    braces, a map of files, or one flat file. A reply that does not parse is read as one file.
    """
    text = source_code.strip()
    if text.startswith('{'):
        try:
            data = json.loads(text[1:-1] if text.startswith('{{') else text)
        except ValueError:
            return [source_code]
        if isinstance(data, dict):
            sources = data.get('sources', data)
            if isinstance(sources, dict):
                return [
                    file['content'] for file in sources.values()
                    if isinstance(file, dict) and isinstance(file.get('content'), str)
                ]
    return [source_code]


def canonical_type(param: str) -> Optional[str]:
    """A parameter's ABI type when it is elementary (uint, address, bytes32, address[] ...), else
    None: a struct, enum or contract type is not resolved, so its function is not attributed.
    """
    match = TYPE_AND_ARRAYS.match(param.strip())
    if not match:
        return None
    base, arrays = match.groups()
    if base in ('uint', 'int'):
        base += '256'
    elif base.startswith(('uint', 'int')):
        bits = base.lstrip('uint')
        if not bits.isdigit() or int(bits) % 8 or not 8 <= int(bits) <= 256:
            return None
    elif base.startswith('bytes') and base != 'bytes':
        if not base[5:].isdigit() or not 1 <= int(base[5:]) <= 32:
            return None
    elif base not in ('address', 'bool', 'string', 'bytes'):
        return None
    return base + arrays


def live_source_patterns(source_code: str, operands: set) -> list:
    """The SOURCE_PATTERNS words borne by functions the deployed code dispatches to.

    The published source is a bundle of every file the compiler read, so a word found anywhere in
    it says nothing about the contract at the address: a function counts only when its selector,
    hashed from its declaration, is one the bytecode compares against (`operands`), and comments
    and string literals are never read. A name pattern is found in a counted function's name, as
    written or capitalised inside it (mintAllocations, isBlacklisted, not minTicketBalance);
    onlyOwner is found among a counted function's modifiers.
    """
    functions = []
    for text in source_files(source_code):
        code = COMMENTS_AND_STRINGS.sub(' ', text)
        for name, params, header in FUNCTION_HEADER.findall(code):
            types = [canonical_type(param) for param in params.split(',')] if params.strip() else []
            if None in types:
                continue
            if keccak(text=f'{name}({",".join(types)})')[:4].hex() in operands:
                functions.append((name, re.findall(r'\w+', header)))
    found = []
    for pattern in SOURCE_PATTERNS:
        if pattern == 'onlyOwner':
            hit = any('onlyOwner' in modifiers for _, modifiers in functions)
        else:
            capitalised = pattern[0].upper() + pattern[1:]
            hit = any(pattern in name or capitalised in name for name, _ in functions)
        if hit:
            found.append(pattern)
    return found


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

    async def fetch_contract_data(
        self, address: str, chain_id: int = 56, robinhood_assets=None, deadline: Optional[float] = None,
    ) -> dict:
        """The contract's structural facts.

        The explorer lookups (verification and creation) start first and run beside the scam
        database, ownership and bytecode checks. With ``deadline`` (a time.monotonic() value: the
        analyzers' deadline of an interactive scan) a lookup still running
        EXPLORER_RESULT_RESERVE_SECONDS before it leaves only its own field unknown, with a named
        reason, and runs on to fill the explorer caches for the next scan. Without one (background
        scans) both are awaited, as before. An exact Robinhood Chain address ``robinhood_assets``
        knows has no explorer lookup: its verification and age are reported as exemptions.
        """
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

            results = {'is_contract': True, 'is_verified': None, 'contract_age_days': None}
            field_reasons = {}
            source_code = None

            exemption = None
            official = None
            if robinhood_assets is not None:
                exemption = robinhood_assets.static_explorer_exemption(address, chain_id)
                if exemption is None and chain_id == 4663:
                    official = asyncio.create_task(robinhood_assets.explorer_exemption(address, chain_id))
                    await asyncio.wait((official,), timeout=OFFICIAL_LIST_WAIT_SECONDS)
                    if official.done():
                        exemption = official.result()
                        official = None

            async def creation_lookup():
                await asyncio.sleep(BSCSCAN_DELAY)
                return await self.web3_client.get_contract_creation_info(address, chain_id=chain_id)

            # Verification + source code, and contract age. Below this call both lookups are shielded
            # and cached, so one still running at the deadline fills the caches when it ends.
            lookups = ()
            if exemption is None:
                lookups = (
                    asyncio.create_task(self.web3_client.is_verified_contract(address, chain_id=chain_id)),
                    asyncio.create_task(creation_lookup()),
                )
                for lookup in lookups:
                    lookup.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)

            # Scam DB (external APIs, not BscScan — no delay needed)
            scam_matches = await self.scam_db.check_address(address, chain_id=chain_id)
            results['scam_matches'] = list(scam_matches or [])
            results['observed_at'] = min(defaults['observed_at'], getattr(scam_matches, 'observed_at', 0))
            failed_providers = getattr(scam_matches, 'failed_providers', ())
            if failed_providers:
                results['coverage'] = {'scam_database': False}
                results['reason'] = 'Scam database unavailable: ' + '; '.join(failed_providers)

            goplus = getattr(scam_matches, 'goplus_record', {})

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
            operands = set()

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

            if lookups:
                timeout = None
                if deadline is not None:
                    timeout = max(0.0, deadline - EXPLORER_RESULT_RESERVE_SECONDS - time.monotonic())
                await asyncio.wait(lookups, timeout=timeout)
            if official is not None and official.done():
                exemption = official.result()
            if exemption is not None:
                results['coverage_exemptions'] = exemption
            for field, lookup in zip(('is_verified', 'contract_age_days'), lookups if exemption is None else ()):
                if not lookup.done():
                    field_reasons[field] = 'Explorer lookup still running at the request deadline; it continues for the next scan'
                elif isinstance(lookup.exception(), UnsupportedChainError):
                    raise lookup.exception()
                elif lookup.exception() is not None:
                    logger.warning("Explorer lookup for %s failed: %s", address, type(lookup.exception()).__name__)
                    field_reasons[field] = f'Explorer lookup failed ({type(lookup.exception()).__name__})'
                elif field == 'is_verified':
                    results['is_verified'], source_code = lookup.result()
                elif lookup.result():
                    results['contract_age_days'] = lookup.result().get('age_days')

            # GoPlus's token record, fetched by the scam check. When the explorer did not answer, it
            # says whether the source is open, which is the same fact.
            if results['is_verified'] is None and exemption is None and goplus.get('is_open_source') in ('0', '1'):
                results['is_verified'] = goplus['is_open_source'] == '1'
                results['field_providers'] = {'is_verified': 'goplus'}
                field_reasons.pop('is_verified', None)
            if field_reasons:
                results['coverage_reasons'] = field_reasons
                results['reason'] = '; '.join(filter(None, (
                    results.get('reason'), *(f'{field}: {reason}' for field, reason in field_reasons.items()),
                )))

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

            results['source_code_patterns'] = live_source_patterns(source_code, operands) if source_code else []

            return {**defaults, **results}

        except UnsupportedChainError:
            raise
        except Exception as e:
            logger.error("Contract data fetch failed for %s: %s", address, type(e).__name__)
            return {**defaults, 'is_contract': None, 'status': 'unknown', 'reason': 'Contract data unavailable'}
