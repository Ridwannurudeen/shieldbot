import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Optional

from eth_utils import keccak

from adapters.evm_base import BURN_ADDRESSES
from services.launch_discovery import SOURCES, LaunchDiscoveryError, _decode_log, _quantity
from services.robinhood_assets import OFFICIAL_LIST_WAIT_SECONDS

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
# Robinhood Chain launches ShieldBot's own discovery recorded (core.database discovered_launches). Only
# Doppler's Create event dates a token, and only once the receipt of the row's transaction proves it: a
# row is dated from its earliest event across sources, so it can carry another event's block.
#
# Audit of the launchpads' verified source on chain, 2026-10-12:
# - Doppler is sound. DopplerHookInitializer (0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544) emits
#   Create(address(poolManager), asset, numeraire) only inside initialize(), which requires
#   msg.sender == airlock (an immutable, ImmutableAirlock) and an Uninitialized pool. Airlock.create()
#   checks the token factory against its owner's whitelist (_validateModuleState(tokenFactory,
#   ModuleState.TokenFactory)), deploys the asset with asset = tokenFactory.create(...), and only then
#   calls poolInitializer.initialize(asset, ...). So a Doppler Create in transaction T means the asset
#   was deployed in T by a whitelisted factory. This rests on that whitelist: a change to Doppler's
#   airlock or initializer needs a new audit before this proof is trusted.
# - Uniswap LiquidityLauncher is not sound: createToken(factory, ...) takes any caller's factory and
#   emits TokenCreated for whatever address it returns, so it can announce a predicted address days
#   before a token is deployed there. It proves nothing.
# - LONG's LaunchCreated comes from an upgradeable proxy (implementation
#   0x7B7b87fd1Fb05864cD572C7306038552286c73d9) whose create path was not audited, so it proves nothing
#   by itself. LONG launches through Doppler, so a long row is proven by Doppler's Create in its receipt.
# - A pool (Uniswap V2 PairCreated, V4 Initialize) never calls the token and can be made for a predicted
#   address before the token exists: it dates nothing.
LAUNCH_PROVEN_SOURCES = ('doppler', 'long')
DOPPLER_CREATE = next(source for source in SOURCES if source.name == 'doppler')
# The launch row is one primary-key read; past this the explorer path runs as before.
LAUNCH_AGE_READ_TIMEOUT_SECONDS = 0.25
# The receipt is one read-RPC request; past this the explorer path runs as before.
LAUNCH_RECEIPT_TIMEOUT_SECONDS = 0.5

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
        # The database with ShieldBot's launch table; the container sets it.
        self.db = None
        # Each token's proven creation block timestamp, by (chain, token): a creation never changes.
        self._proven_creations = {}

    async def _launch_age(self, address: str, chain_id: int) -> Optional[int]:
        """The token's age in days from Doppler's creation event in the launch table, proven by the
        receipt of the row's transaction; None otherwise (no row, a row of another source, an unproven
        row, a timestamp that cannot be read or lies ahead, or a read that failed or was slow), and the
        explorer path runs as before."""
        key = (chain_id, address.lower())
        created = self._proven_creations.get(key)
        if created is None:
            created = await self._proven_creation(address, chain_id)
            if created is None:
                return None
            self._proven_creations[key] = created
        # The same day count as an explorer creation date (adapters.evm_base _date_creation).
        age = (datetime.now(timezone.utc) - created).days
        return age if age >= 0 else None

    async def _proven_creation(self, address: str, chain_id: int) -> Optional[datetime]:
        """When the row's block was made, if the receipt of its transaction, in that block, holds
        Doppler's Create for this token, read where discovery reads it (see the audit above)."""
        try:
            launch = await asyncio.wait_for(
                self.db.get_launch(chain_id, address), LAUNCH_AGE_READ_TIMEOUT_SECONDS,
            )
            if launch is None or launch['source'] not in LAUNCH_PROVEN_SOURCES:
                return None
            created = datetime.fromtimestamp(launch['block_timestamp'], tz=timezone.utc)
            receipt = await asyncio.wait_for(
                self.web3_client.get_transaction_receipt(launch['tx_hash'], chain_id=chain_id),
                LAUNCH_RECEIPT_TIMEOUT_SECONDS,
            )
        except Exception as e:
            logger.warning("Launch creation could not be read for %s: %s", address, type(e).__name__)
            return None
        block = launch['block_number']
        try:
            if not isinstance(receipt, dict) or _quantity(receipt.get('blockNumber')) != block:
                return None
            logs = receipt.get('logs')
            # Only Doppler's own Create counts: its emitter, its topic, four topics and the token at
            # topics[2]. Other logs in the transaction (pools, positions, LONG's) also name the token.
            for log in logs if isinstance(logs, list) else ():
                try:
                    tokens, _ = _decode_log(DOPPLER_CREATE, log, block, block)
                except LaunchDiscoveryError:
                    continue
                if address.lower() in tokens:
                    return created
        except LaunchDiscoveryError:
            return None
        logger.warning("Launch creation of %s not in its transaction's receipt", address)
        return None

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
                    official.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
                    await asyncio.wait((official,), timeout=OFFICIAL_LIST_WAIT_SECONDS)
                    if official.done():
                        exemption = official.result() if official.exception() is None else None
                        official = None

            async def creation_lookup():
                await asyncio.sleep(BSCSCAN_DELAY)
                return await self.web3_client.get_contract_creation_info(address, chain_id=chain_id)

            def start(lookup):
                task = asyncio.create_task(lookup)
                task.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
                return task

            def wait_timeout():
                if deadline is None:
                    return None
                return max(0.0, deadline - EXPLORER_RESULT_RESERVE_SECONDS - time.monotonic())

            # Verification + source code, and contract age. Below this call both lookups are shielded
            # and cached, so one still running at the deadline fills the caches when it ends.
            # Verification starts first; it does not depend on the launch table.
            lookups = {}
            creator_security_task = None
            if exemption is None:
                lookups['is_verified'] = start(self.web3_client.is_verified_contract(address, chain_id=chain_id))

            # On Robinhood Chain the launch table can date the token without the explorer's creation
            # lookup.
            launch = None
            if exemption is None and chain_id == 4663 and self.db is not None:
                launch = await self._launch_age(address, chain_id)
            if launch is not None:
                results['contract_age_days'] = launch
                results['field_providers'] = {'contract_age_days': 'launch_table'}
            elif exemption is None:
                creation_task = start(creation_lookup())
                lookups['contract_age_days'] = creation_task
                if chain_id == 677:
                    async def creator_lookup():
                        creation = await creation_task
                        creator = creation.get('creator') if isinstance(creation, dict) else None
                        if not isinstance(creator, str) or not re.fullmatch(r'0x[0-9a-fA-F]{40}', creator):
                            return None
                        response = await self.scam_db.fetch_address_security(creator, ledger_chain=677)
                        return creator, response

                    creator_security_task = start(creator_lookup())

            if chain_id == 677:
                results['token_security_unsupported'] = True

            # Scam DB (external APIs, not BscScan — no delay needed)
            scam_matches = await self.scam_db.check_address(address, chain_id=chain_id)
            results['scam_matches'] = list(scam_matches or [])
            results['observed_at'] = min(defaults['observed_at'], getattr(scam_matches, 'observed_at', 0))
            failed_providers = getattr(scam_matches, 'failed_providers', ())
            if failed_providers:
                results['coverage'] = {'scam_database': False}
                results['reason'] = 'Scam database unavailable: ' + '; '.join(failed_providers)
            elif chain_id == 677:
                results['coverage'] = {'scam_database': True}
            if chain_id == 677:
                results['address_labels'] = getattr(scam_matches, 'address_record', {})
                results['address_label_notes'] = getattr(scam_matches, 'address_notes', ())

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

            pending_lookups = list(lookups.values())
            if creator_security_task is not None:
                pending_lookups.append(creator_security_task)
            if pending_lookups:
                await asyncio.wait(pending_lookups, timeout=wait_timeout())
            if exemption is not None:
                results['coverage_exemptions'] = exemption
            creation_lookup_answered = False
            # The official list answered after the lookups started: it exempts only the fields they
            # left unanswered.
            late = (
                official.result() if official is not None and official.done() and official.exception() is None
                else None
            )
            for field, lookup in lookups.items():
                if lookup.done() and isinstance(lookup.exception(), UnsupportedChainError):
                    raise lookup.exception()
                if late is not None and not (
                    lookup.done() and lookup.exception() is None
                    and (lookup.result()[0] if field == 'is_verified' else (lookup.result() or {}).get('age_days'))
                    is not None
                ):
                    results.setdefault('coverage_exemptions', {})[field] = late[field]
                elif not lookup.done():
                    field_reasons[field] = 'Explorer lookup still running at the request deadline; it continues for the next scan'
                elif lookup.exception() is not None:
                    logger.warning("Explorer lookup for %s failed: %s", address, type(lookup.exception()).__name__)
                    field_reasons[field] = f'Explorer lookup failed ({type(lookup.exception()).__name__})'
                elif field == 'is_verified':
                    results['is_verified'], source_code = lookup.result()
                elif lookup.result():
                    if chain_id == 677:
                        creation_lookup_answered = True
                    results['contract_age_days'] = lookup.result().get('age_days')

            if chain_id == 677:
                if creator_security_task is not None:
                    if (
                        creator_security_task.done()
                        and not creator_security_task.cancelled()
                        and creator_security_task.exception() is None
                    ):
                        creator_result = creator_security_task.result()
                        if creator_result is not None:
                            creator, creator_response = creator_result
                            results['creator_address'] = creator
                            results['creator_address_status'] = creator_response.get('status')
                            results['creator_address_labels'] = creator_response.get('data', {})
                            results['creator_address_reason'] = creator_response.get('reason')
                        else:
                            results['creator_address_status'] = (
                                'not_available' if creation_lookup_answered else 'unknown'
                            )
                    else:
                        results['creator_address_status'] = 'unknown'
                        results['creator_address_pending'] = not creator_security_task.done()
                else:
                    results['creator_address_status'] = (
                        'not_available' if creation_lookup_answered else 'unknown'
                    )

            # GoPlus's token record, fetched by the scam check. When the explorer did not answer, it
            # says whether the source is open, which is the same fact.
            if results['is_verified'] is None and 'is_verified' not in results.get('coverage_exemptions', {}) and goplus.get('is_open_source') in ('0', '1'):
                results['is_verified'] = goplus['is_open_source'] == '1'
                results['field_providers'] = {**results.get('field_providers', {}), 'is_verified': 'goplus'}
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
