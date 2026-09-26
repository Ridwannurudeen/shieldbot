"""Shared EVM adapter base class — config-driven extraction for EVM-compatible chains."""

import logging
import asyncio
import re
import aiohttp
from typing import Dict, List, Optional, Tuple
from cachetools import TTLCache
from web3 import Web3
try:
    from web3.middleware import ExtraDataToPOAMiddleware as geth_poa_middleware
except ImportError:
    from web3.middleware import geth_poa_middleware
from datetime import datetime, timezone

from core.chain_adapter import ChainAdapter
from core.circuit_breaker import provider_breakers
from core.unknown_ledger import unknown_ledger

logger = logging.getLogger(__name__)

# Per-request timeout for every web3 HTTP call. It equals web3 6.15.1's own default
# (web3._utils.request.DEFAULT_TIMEOUT), so production on 6.15.1 behaves as before, and it stops
# web3 7 from waiting its 30 s default. Both versions accept HTTPProvider(request_kwargs=...).
RPC_REQUEST_TIMEOUT_SECONDS = 10

# Without honeypot.is no sell is simulated; HoneypotService falls back to GoPlus's own flags.
HONEYPOT_IS_UNSUPPORTED = (
    'honeypot.is unsupported for this chain; any honeypot and tax data here is GoPlus-reported, '
    'not simulated by ShieldBot'
)
# The sources verification asks on a chain with Etherscan, in this order; GET /api/coverage names
# them from the same tuple.
VERIFICATION_SOURCES = ('etherscan', 'sourcify')
# EIP-1167 minimal proxy runtime code: a clone that delegates every call to the embedded address.
EIP1167_RUNTIME = re.compile(r'363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3')

# check_honeypot and get_tax_info read the same honeypot.is reply, and a scan calls them back to back.
HONEYPOT_IS_REPLY_TTL_SECONDS = 60
# The structural analyzer, the payment rule and the spender lookup can all ask for one contract's
# creation within a scan, and a creation does not change.
CREATION_INFO_TTL_SECONDS = 300
# Burned LP counts as locked, but these addresses cannot hold a lock, so a chain whose only known
# "lockers" they are cannot tell unlocked liquidity from liquidity held by an unlisted locker.
BURN_ADDRESSES = {
    '0x0000000000000000000000000000000000000000',
    '0x000000000000000000000000000000000000dead',
}

# 'etherscan': verification and creation from Etherscan, with Sourcify's deployment record dating a
# contract when Etherscan does not answer (its free tier refuses getcontractcreation on BNB Chain,
# which no public Blockscout serves). 'etherscan_blockscout': verification from Etherscan, creation
# from Blockscout, because Etherscan's free tier refuses getcontractcreation on Base and Optimism.
EXPLORER_BACKENDS = {
    1: 'etherscan', 56: 'etherscan', 8453: 'etherscan_blockscout',
    42161: 'etherscan', 137: 'etherscan', 10: 'etherscan_blockscout', 204: 'etherscan',
    4663: 'sourcify_blockscout',
}


def _get_explorer_backend(chain_id: int) -> str:
    if chain_id not in EXPLORER_BACKENDS:
        raise ValueError(f"Unsupported explorer chain: {chain_id}")
    return EXPLORER_BACKENDS[chain_id]


def _decimal(value) -> Optional[int]:
    """An explorer's decimal-string number (Etherscan's blockNumber and timestamp) as an int; None
    for a missing, empty or non-decimal value."""
    return int(value) if isinstance(value, str) and re.fullmatch(r'[0-9]{1,20}', value) else None

FACTORY_ABI = [
    {
        "constant": True,
        "inputs": [
            {"name": "tokenA", "type": "address"},
            {"name": "tokenB", "type": "address"}
        ],
        "name": "getPair",
        "outputs": [{"name": "pair", "type": "address"}],
        "type": "function"
    }
]

# Solidly-style factories (Aerodrome on Base, Velodrome on Optimism) revert on getPair.
SOLIDLY_FACTORY_ABI = [
    {
        "constant": True,
        "inputs": [
            {"name": "tokenA", "type": "address"},
            {"name": "tokenB", "type": "address"},
            {"name": "stable", "type": "bool"}
        ],
        "name": "getPool",
        "outputs": [{"name": "pool", "type": "address"}],
        "type": "function"
    }
]

PAIR_ABI = [
    {
        "constant": True, "inputs": [], "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}], "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}], "type": "function"
    }
]

ERC20_ABI = [
    {"constant": True, "inputs": [], "name": "name",
     "outputs": [{"name": "", "type": "string"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "symbol",
     "outputs": [{"name": "", "type": "string"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals",
     "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "totalSupply",
     "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "owner",
     "outputs": [{"name": "", "type": "address"}], "type": "function"},
]


class EvmAdapter(ChainAdapter):
    """Config-driven EVM adapter base class.

    Subclasses only need to provide chain-specific config via constructor args.
    All API logic (Etherscan v2, honeypot.is, liquidity checks) is shared.
    """

    def __init__(
        self,
        chain_id_value: int,
        chain_name_value: str,
        rpc_url: str,
        etherscan_api_key: str = "",
        honeypot_chain_id: int = None,
        known_lockers: Dict[str, str] = None,
        quote_tokens: List[Tuple[str, str]] = None,
        factory_address: str = None,
        whitelisted_routers: Dict[str, str] = None,
        solidly_factory: bool = False,
    ):
        from services.explorer_service import explorer_service

        self._explorer_backend = _get_explorer_backend(chain_id_value)
        self._explorer_service = explorer_service
        self._chain_id = chain_id_value
        self._chain_name = chain_name_value
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': RPC_REQUEST_TIMEOUT_SECONDS}))
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        self.etherscan_api_key = etherscan_api_key
        self.etherscan_api_url = 'https://api.etherscan.io/v2/api'
        self._honeypot_chain_id = honeypot_chain_id
        self._known_lockers = known_lockers or {}
        self._quote_tokens = quote_tokens or []
        self._factory_address = factory_address
        self._solidly_factory = solidly_factory
        self._whitelisted_routers = whitelisted_routers or {}
        self._honeypot_is_replies = TTLCache(maxsize=1024, ttl=HONEYPOT_IS_REPLY_TTL_SECONDS)
        self._creation_infos = TTLCache(maxsize=1024, ttl=CREATION_INFO_TTL_SECONDS)
        self._creation_inflight = {}

    @property
    def chain_id(self) -> int:
        return self._chain_id

    @property
    def chain_name(self) -> str:
        return self._chain_name

    async def _call_with_retry(self, fn, *args, retries=3, base_delay=1.0):
        """Wrap a synchronous web3 call with retry + executor to avoid blocking the event loop.

        Only transient provider failures are retried, decided from structured error data, never
        exception text: the HTTP status on the requests HTTPError that web3's HTTPProvider raises,
        or the JSON-RPC "limit exceeded" code -32005 (web3 6 raises ValueError(error object),
        web3 7 raises Web3RPCError with rpc_response). Reverts and other errors raise at once.
        """
        import requests
        from web3.exceptions import BadFunctionCallOutput, ContractLogicError

        if retries < 1:
            retries = 1
        loop = asyncio.get_event_loop()
        last_exc = None
        for attempt in range(retries):
            try:
                result = await loop.run_in_executor(None, fn, *args)
            except Exception as e:
                last_exc = e
                if isinstance(e, requests.exceptions.HTTPError):
                    is_retriable = e.response is not None and e.response.status_code in (429, 502, 503)
                else:
                    rpc_response = getattr(e, 'rpc_response', None)
                    if isinstance(rpc_response, dict):
                        rpc_error = rpc_response.get('error')
                    else:
                        rpc_error = e.args[0] if isinstance(e, ValueError) and e.args else None
                    is_retriable = isinstance(rpc_error, dict) and rpc_error.get('code') == -32005
                if is_retriable and attempt < retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.warning(
                        "[%s] RPC rate-limited (attempt %d/%d), retrying in %ss: %s",
                        self._chain_name, attempt + 1, retries, delay, type(e).__name__,
                    )
                    await asyncio.sleep(delay)
                elif not is_retriable:
                    answered = isinstance(e, (BadFunctionCallOutput, ContractLogicError))
                    unknown_ledger.record('rpc', self._chain_id, 'answered' if answered else 'failed')
                    raise
            else:
                unknown_ledger.record('rpc', self._chain_id, 'answered')
                return result
        unknown_ledger.record('rpc', self._chain_id, 'failed')
        raise last_exc

    async def is_contract(self, address: str) -> Optional[bool]:
        """Return True/False from on-chain code; None means the lookup failed."""
        try:
            code = await self._call_with_retry(self.w3.eth.get_code, Web3.to_checksum_address(address))
            return len(code) > 0
        except Exception as e:
            logger.error("[%s] Error checking if contract: %s", self._chain_name, type(e).__name__)
            return None

    async def get_bytecode(self, address: str) -> Optional[str]:
        try:
            code = await self._call_with_retry(self.w3.eth.get_code, Web3.to_checksum_address(address))
            return code.hex()
        except Exception as e:
            logger.error("[%s] Error getting bytecode: %s", self._chain_name, type(e).__name__)
            return None

    async def is_verified_contract(
        self, address: str, code: Optional[str] = None,
    ) -> Tuple[Optional[bool], Optional[str]]:
        """Return (verification, source); None means unknown, False means unverified.

        An EIP-1167 minimal proxy (a clone) has no source of its own, so a clone that is not
        verified itself is judged by its implementation. A caller that already read the contract's
        code passes it, so the clone check does not read it again.
        """
        verified, source = await self._verification(address)
        if verified is not True:
            implementation = await self._minimal_proxy_implementation(address, code)
            if implementation:
                return await self._verification(implementation)
        return verified, source

    async def _minimal_proxy_implementation(self, address: str, code: Optional[str]) -> Optional[str]:
        if code is None:
            code = await self.get_bytecode(address)
        # web3 6 returns the hex with 0x, web3 7 without.
        match = EIP1167_RUNTIME.fullmatch(code.lower().removeprefix('0x')) if code else None
        return '0x' + match.group(1) if match else None

    async def _verification(self, address: str) -> Tuple[Optional[bool], Optional[str]]:
        """The chain's explorer and Sourcify together: verified when either says so, unverified
        only when both say not, unknown when one could not be read and the other did not verify.

        Each source is awaited for PROVIDER_TIMEOUT (8 s) at most and counts as unknown after it.
        A direct caller such as the structural analyzer waits about 16 s at most on a chain with
        Etherscan (Etherscan, then Sourcify) and 8 s on Robinhood Chain, where Sourcify and
        Blockscout share one bound. Approvals and permits get one 8 s window for both sources on
        every chain: the spender-facts step wraps this call in its own PROVIDER_TIMEOUT, so there a
        stalled Etherscan leaves verification unknown, and Sourcify's later answer is only cached
        for a later lookup.
        """
        # Imported here: services imports utils.web3_client, which imports this module's adapters.
        from services.counterparty_service import within_timeout

        if self._explorer_backend == 'sourcify_blockscout':
            from services.explorer_service import ExplorerResult

            result = await within_timeout(
                self._explorer_service.get_verification_status(address, self._chain_id),
                ExplorerResult('unknown', reason='Sourcify and Blockscout timed out'),
            )
            if result.status == 'unknown':
                logger.warning("[%s] Verification unknown: %s", self._chain_name, result.reason)
                return (None, None)
            return (result.status == 'verified', None)
        lookups = {'etherscan': self._etherscan_verification, 'sourcify': self._sourcify_verification}
        timed_out = object()
        answers = []
        # A source is asked only when none before it verified the contract.
        for name in VERIFICATION_SOURCES:
            answer = await within_timeout(lookups[name](address), timed_out)
            verified = None if answer is timed_out else answer[0]
            if verified is True:
                return answer
            answers.append('timed out' if answer is timed_out else 'unknown' if verified is None else 'unverified')
        if all(answer == 'unverified' for answer in answers):
            return (False, None)
        logger.warning(
            "[%s] Verification unknown: %s", self._chain_name,
            ', '.join(f'{name} {answer}' for name, answer in zip(VERIFICATION_SOURCES, answers)),
        )
        return (None, None)

    async def _sourcify_verification(self, address: str) -> Tuple[Optional[bool], Optional[str]]:
        result = await self._explorer_service.get_sourcify_verification(address, self._chain_id)
        if result.status == 'unknown':
            logger.warning("[%s] Sourcify verification unknown: %s", self._chain_name, result.reason)
            return (None, None)
        return (result.status == 'verified', None)

    async def _etherscan_verification(self, address: str) -> Tuple[Optional[bool], Optional[str]]:
        try:
            provider_breakers.check('etherscan', self._chain_id)
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                params = {
                    'chainid': self._chain_id,
                    'module': 'contract',
                    'action': 'getsourcecode',
                    'address': address,
                    'apikey': self.etherscan_api_key,
                }
                async with session.get(self.etherscan_api_url, params=params) as resp:
                    if resp.status != 200:
                        provider_breakers.record_status('etherscan', self._chain_id, resp.status)
                        unknown_ledger.record('etherscan', self._chain_id, 'failed')
                        logger.warning("[%s] Verification unknown: HTTP %s", self._chain_name, resp.status)
                        return (None, None)
                    data = await resp.json()
                    provider_breakers.record_status('etherscan', self._chain_id, resp.status)
                    if (
                        isinstance(data, dict) and data.get('status') == '1'
                        and isinstance(data.get('result'), list) and len(data['result']) == 1
                        and isinstance(data['result'][0], dict)
                        and isinstance(data['result'][0].get('SourceCode'), str)
                    ):
                        unknown_ledger.record('etherscan', self._chain_id, 'answered')
                        source_code = data['result'][0]['SourceCode']
                        is_verified = len(source_code) > 0
                        return (is_verified, source_code if is_verified else None)
            unknown_ledger.record('etherscan', self._chain_id, 'failed')
            logger.warning("[%s] Verification unknown: missing source response", self._chain_name)
            return (None, None)
        except Exception as e:
            provider_breakers.record_error('etherscan', self._chain_id, e)
            unknown_ledger.record('etherscan', self._chain_id, 'failed')
            logger.error("[%s] Error checking verification: %s", self._chain_name, type(e).__name__)
            return (None, None)

    async def get_contract_creation_info(self, address: str) -> Optional[Dict]:
        """Creation info, one lookup per contract shared by concurrent callers and kept for five
        minutes. Only an answer with an age is kept, so a failed or undated lookup is asked again.
        A cached answer is not a lookup, so it records nothing in the Unknown ledger.
        """
        key = (self._chain_id, address.lower())
        cached = self._creation_infos.get(key)
        if cached is not None:
            return dict(cached)
        flight_key = (asyncio.get_running_loop(), key)
        if flight_key not in self._creation_inflight:
            self._creation_inflight[flight_key] = asyncio.create_task(
                self._lookup_creation_info(address, key, flight_key)
            )
        info = await asyncio.shield(self._creation_inflight[flight_key])
        return dict(info) if info else info

    async def _lookup_creation_info(self, address: str, key: tuple, flight_key: tuple) -> Optional[Dict]:
        try:
            info = await self._fetch_creation_info(address)
        finally:
            self._creation_inflight.pop(flight_key, None)
        if info and info.get('age_days') is not None:
            self._creation_infos[key] = info
        return info

    async def _fetch_creation_info(self, address: str) -> Optional[Dict]:
        """The contract's creator and creation transaction from its explorer, dated by _date_creation.
        None when no source knows the contract; undated when a source knows it but it could not be
        dated, so the next caller asks again.
        """
        try:
            if self._explorer_backend in ('sourcify_blockscout', 'etherscan_blockscout'):
                result = await self._explorer_service.get_contract_creation_info(address, self._chain_id)
                if result.status == 'unknown':
                    logger.warning("[%s] Creation unknown: %s", self._chain_name, result.reason)
                    return None
                creation = dict(result.data)
            else:
                creation = await self._etherscan_creation(address)
                if creation is None:
                    return None
        except Exception as e:
            logger.error("[%s] Error getting creation info: %s", self._chain_name, type(e).__name__)
            return None
        return await self._date_creation(creation)

    async def _etherscan_creation(self, address: str) -> Optional[Dict]:
        """Etherscan's creation record: the creator, the transaction and, when its reply names them,
        the creation block and timestamp. When Etherscan does not answer (a status 0 that is not
        "No data found": its free tier refuses getcontractcreation on BNB Chain), Sourcify's
        deployment record is asked instead, so a contract verified there is still dated; its
        breaker, cache and ledger entries are the explorer service's. The refusal still counts as
        Etherscan failing, and is logged so the journal says where an age came from. An error in
        Etherscan's request or reply is counted against Etherscan and raised to the caller.
        """
        try:
            provider_breakers.check('etherscan', self._chain_id)
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                params = {
                    'chainid': self._chain_id,
                    'module': 'contract',
                    'action': 'getcontractcreation',
                    'contractaddresses': address,
                    'apikey': self.etherscan_api_key,
                }
                async with session.get(self.etherscan_api_url, params=params) as resp:
                    if resp.status != 200:
                        provider_breakers.record_status('etherscan', self._chain_id, resp.status)
                        unknown_ledger.record('etherscan', self._chain_id, 'failed')
                        logger.warning("[%s] Creation unknown: HTTP %s", self._chain_name, resp.status)
                        return None
                    data = await resp.json()
                    provider_breakers.record_status('etherscan', self._chain_id, resp.status)
                    if data['status'] == '1' and data['result']:
                        result = data['result'][0]
                        creation = {
                            'tx_hash': result.get('txHash'),
                            'creator': result.get('contractCreator'),
                            'block_number': _decimal(result.get('blockNumber')),
                            'timestamp': _decimal(result.get('timestamp')),
                        }
                        unknown_ledger.record('etherscan', self._chain_id, 'answered')
                        return creation
            # Etherscan answers "No data found" for an address it holds no creation record for.
            no_record = data['status'] == '0' and data.get('message') == 'No data found'
            unknown_ledger.record('etherscan', self._chain_id, 'unknown' if no_record else 'failed')
        except Exception as e:
            provider_breakers.record_error('etherscan', self._chain_id, e)
            unknown_ledger.record('etherscan', self._chain_id, 'failed')
            raise
        if no_record:
            return None
        logger.warning("[%s] Creation not answered by Etherscan; asking Sourcify", self._chain_name)
        deployment = await self._explorer_service.get_sourcify_deployment(address, self._chain_id)
        if deployment.status == 'unknown':
            logger.warning("[%s] Creation unknown: Sourcify %s", self._chain_name, deployment.reason)
            return None
        return dict(deployment.data)

    async def _date_creation(self, creation: Dict) -> Dict:
        """creation with its creation_time and age_days: from the explorer's own timestamp when it
        gave one, else from the creation block's header, else from the creation transaction's block.
        Every node keeps every header, but a node indexes only its recent transactions (Geth about a
        year of them by default), so the transaction is read only when the explorer named neither,
        and an old creation is dated from its header alone. A creation that cannot be dated is
        returned undated, with a class-only warning, and is not cached.
        """
        timestamp = creation.pop('timestamp', None)
        block_number = creation.pop('block_number', None)
        creation.update({'creation_time': None, 'age_days': None})
        try:
            if timestamp:
                creation_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            else:
                if block_number is None:
                    tx = await self._call_with_retry(self.w3.eth.get_transaction, creation['tx_hash'])
                    block_number = tx['blockNumber']
                block = await self._call_with_retry(self.w3.eth.get_block, block_number)
                creation_time = datetime.fromtimestamp(block['timestamp'], tz=timezone.utc)
        except Exception as e:
            logger.warning("[%s] Creation time unknown: %s", self._chain_name, type(e).__name__)
            return creation
        creation['creation_time'] = creation_time.isoformat()
        creation['age_days'] = (datetime.now(timezone.utc) - creation_time).days
        return creation

    async def get_token_info(self, address: str) -> Dict:
        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=ERC20_ABI,
            )
            name = await self._call_with_retry(contract.functions.name().call)
            symbol = await self._call_with_retry(contract.functions.symbol().call)
            decimals = await self._call_with_retry(contract.functions.decimals().call)
            total_supply = await self._call_with_retry(contract.functions.totalSupply().call)
            return {
                'name': name, 'symbol': symbol,
                'decimals': decimals, 'total_supply': total_supply / (10 ** decimals),
            }
        except Exception as e:
            logger.error("[%s] Error getting token info: %s", self._chain_name, type(e).__name__)
            return {}

    async def get_ownership_info(self, address: str) -> Dict:
        """Return the owner and whether it is renounced.

        A reverting owner() (ContractLogicError, raised by web3 6 and 7 alike) is a definitive
        answer: there is no Ownable owner to read, so the lookup is complete with both fields None.
        So is an empty reply, which is how a contract whose fallback does not revert (WETH9 and
        its WBNB copy) answers a function it lacks. web3 raises BadFunctionCallOutput for that and
        for output that is not an address alike, so the raw reply is read again to tell them apart
        by length. Every other failure is missing data and carries status unknown with a
        class-only reason. OffchainLookup is a ContractLogicError subclass that asks for more
        data rather than reverting.
        """
        from web3.exceptions import BadFunctionCallOutput, ContractLogicError, OffchainLookup

        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=ERC20_ABI,
            )
            try:
                owner = await self._call_with_retry(contract.functions.owner().call)
            except BadFunctionCallOutput:
                # 0x8da5cb5b is the owner() selector.
                reply = await self._call_with_retry(
                    self.w3.eth.call, {'to': contract.address, 'data': '0x8da5cb5b'},
                )
                if len(reply) == 0:
                    return {'owner': None, 'is_renounced': None}
                raise
            zero_address = '0x0000000000000000000000000000000000000000'
            is_renounced = owner.lower() == zero_address.lower()
            return {'owner': owner, 'is_renounced': is_renounced}
        except Exception as e:
            logger.error("[%s] Error getting ownership info: %s", self._chain_name, type(e).__name__)
            result = {'owner': None, 'is_renounced': None}
            if isinstance(e, ContractLogicError) and not isinstance(e, OffchainLookup):
                return result
            return {**result, 'status': 'unknown', 'reason': f'Ownership lookup failed ({type(e).__name__})'}

    async def _honeypot_is_reply(self, address: str) -> Tuple[int, Optional[Dict]]:
        """(HTTP status, JSON body when 200) from honeypot.is, requested once per token.

        A request that raises is not kept, so the next caller asks again. While the breaker is open
        nothing is sent: CircuitOpenError is raised, and callers report it like any failed request.
        """
        key = address.lower()
        reply = self._honeypot_is_replies.get(key)
        if reply is None:
            try:
                provider_breakers.check('honeypot.is', self._chain_id)
                async with aiohttp.ClientSession() as session:
                    url = f"https://api.honeypot.is/v2/IsHoneypot?address={address}&chainID={self._honeypot_chain_id}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        reply = (resp.status, await resp.json() if resp.status == 200 else None)
            except Exception as e:
                provider_breakers.record_error('honeypot.is', self._chain_id, e)
                unknown_ledger.record('honeypot.is', self._chain_id, 'failed')
                raise
            self._honeypot_is_replies[key] = reply
            status, data = reply
            provider_breakers.record_status('honeypot.is', self._chain_id, status)
            unknown_ledger.record('honeypot.is', self._chain_id, (
                'answered' if isinstance(data, dict) and data.get('simulationSuccess') is True
                else 'unknown' if status == 404 or isinstance(data, dict) else 'failed'
            ))
        return reply

    async def check_honeypot(self, address: str) -> Dict:
        result = {
            'is_honeypot': None, 'status': 'unknown',
            'reason': 'No honeypot data returned', 'field_providers': {},
        }
        if self._honeypot_chain_id is None:
            result['reason'] = HONEYPOT_IS_UNSUPPORTED
            return result
        try:
            status, data = await self._honeypot_is_reply(address)
            if status != 200:
                result['reason'] = (
                    'Token not found on honeypot.is' if status == 404
                    else f'honeypot.is HTTP {status}'
                )
                return result
            sim_success = data.get('simulationSuccess')
            if isinstance(sim_success, bool):
                result['simulation_success'] = sim_success
            if sim_success is False:
                result['reason'] = 'Simulation failed (inconclusive)'
                result['simulation_failed'] = True
                return result

            honeypot_result = data.get('honeypotResult') or {}
            is_honeypot = honeypot_result.get('isHoneypot')
            if not isinstance(is_honeypot, bool):
                return result
            reason = honeypot_result.get('honeypotReason') or 'honeypot.is result'
            result.update({
                'is_honeypot': is_honeypot, 'status': 'ok', 'reason': reason,
                'field_providers': {'is_honeypot': 'honeypot.is'},
            })
            simulation = data.get('simulationResult') or {}
            sell_tax = simulation.get('sellTax')
            buy_tax = simulation.get('buyTax')
            if (
                is_honeypot and sim_success is True
                and isinstance(sell_tax, (int, float)) and not isinstance(sell_tax, bool)
                and isinstance(buy_tax, (int, float)) and not isinstance(buy_tax, bool)
                and 0 <= sell_tax < 5 and 0 <= buy_tax < 5
            ):
                # Verification is free for a scammer, so it cannot clear a failed sell: the
                # simulator's verdict stands and the doubt is flagged.
                verified, _ = await self.is_verified_contract(address)
                if verified is True:
                    result.update({
                        'reason': f'Flagged but verified with normal taxes (buy:{float(buy_tax)}% sell:{float(sell_tax)}%)',
                        'likely_false_positive': True,
                    })
                else:
                    result.update({
                        'reason': f'{reason} (taxes low: buy:{float(buy_tax)}% sell:{float(sell_tax)}%)',
                        'low_tax_honeypot': True,
                    })
            return result
        except Exception as e:
            logger.error("[%s] Error checking honeypot: %s", self._chain_name, type(e).__name__)
            result['reason'] = f'Error checking honeypot.is: {type(e).__name__}'
            return result

    async def get_tax_info(self, address: str) -> Dict:
        result = {
            'buy_tax': None, 'sell_tax': None, 'status': 'unknown',
            'reason': 'No tax data returned', 'field_providers': {},
        }
        if self._honeypot_chain_id is None:
            result['reason'] = HONEYPOT_IS_UNSUPPORTED
            return result
        try:
            status, data = await self._honeypot_is_reply(address)
            if status != 200:
                result['reason'] = f'honeypot.is HTTP {status}'
                return result
            if data.get('simulationSuccess') is False:
                result['reason'] = 'Simulation failed (inconclusive)'
                result['simulation_failed'] = True
                return result
            if data.get('simulationSuccess') is not True:
                result['reason'] = 'Simulation success unknown'
                return result
            simulation = data.get('simulationResult') or {}
            for field, provider_field in (('buy_tax', 'buyTax'), ('sell_tax', 'sellTax')):
                value = simulation.get(provider_field)
                if value is None or value == '' or isinstance(value, bool):
                    continue
                try:
                    value = float(value)
                except (TypeError, ValueError):
                    continue
                if 0 <= value < float('inf'):
                    result[field] = value
                    result['field_providers'][field] = 'honeypot.is'
            if result['buy_tax'] is not None and result['sell_tax'] is not None:
                result['status'] = 'ok'
                result['reason'] = 'honeypot.is simulation taxes'
            else:
                result['reason'] = 'Missing or invalid honeypot.is tax data'
            return result
        except Exception as e:
            logger.error("[%s] Error getting tax info: %s", self._chain_name, type(e).__name__)
            result['reason'] = f'Error getting honeypot.is taxes: {type(e).__name__}'
            return result

    async def get_liquidity_info(self, address: str) -> Dict:
        """Lock status of the token's first LP pair against a quote token.

        A lock that cannot be read (no factory, no pair found, any failed call) is status unknown
        with is_locked None, never "not locked". Solidly factories are asked for the volatile
        pool, then the stable one.
        """
        unknown = {'is_locked': None, 'lock_percentage': None, 'pair': None, 'status': 'unknown'}
        if not self._factory_address:
            return {**unknown, 'reason': 'No pair factory configured for this chain'}

        try:
            checksum_addr = Web3.to_checksum_address(address)
            factory = self.w3.eth.contract(
                address=Web3.to_checksum_address(self._factory_address),
                abi=SOLIDLY_FACTORY_ABI if self._solidly_factory else FACTORY_ABI,
            )
            zero_address = '0x0000000000000000000000000000000000000000'
            pair_address = None
            paired_with = None

            lookups = []
            for quote_name, quote_addr in self._quote_tokens:
                quote = Web3.to_checksum_address(quote_addr)
                if self._solidly_factory:
                    lookups += [
                        (quote_name, factory.functions.getPool(checksum_addr, quote, stable).call)
                        for stable in (False, True)
                    ]
                else:
                    lookups.append((quote_name, factory.functions.getPair(checksum_addr, quote).call))
            for quote_name, lookup in lookups:
                addr = await self._call_with_retry(lookup)
                if addr != zero_address:
                    pair_address = addr
                    paired_with = quote_name
                    break

            if not pair_address:
                return {**unknown, 'reason': 'No pair with a known quote token'}

            pair_contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(pair_address), abi=PAIR_ABI,
            )
            total_supply = await self._call_with_retry(pair_contract.functions.totalSupply().call)
            if total_supply == 0:
                return {**unknown, 'pair': pair_address, 'reason': 'Pair has no liquidity'}

            locked_amount = 0
            locker_details = []
            for locker_addr, locker_name in self._known_lockers.items():
                balance = await self._call_with_retry(
                    pair_contract.functions.balanceOf(
                        Web3.to_checksum_address(locker_addr),
                    ).call,
                )
                if balance > 0:
                    pct = (balance / total_supply) * 100
                    locked_amount += balance
                    locker_details.append({
                        'locker': locker_name,
                        'address': locker_addr,
                        'percentage': round(pct, 2),
                    })

            lock_percentage = round((locked_amount / total_supply) * 100, 2) if total_supply > 0 else 0
            is_locked = lock_percentage > 50
            if not is_locked and not set(self._known_lockers) - BURN_ADDRESSES:
                return {**unknown, 'pair': pair_address, 'reason': 'No liquidity lockers known for this chain'}

            return {
                'is_locked': is_locked,
                'lock_percentage': lock_percentage,
                'pair': pair_address,
                'paired_with': paired_with,
                'lockers': locker_details,
            }
        except Exception as e:
            logger.error("[%s] Error getting liquidity info: %s", self._chain_name, type(e).__name__)
            return {**unknown, 'reason': f'Liquidity lookup failed ({type(e).__name__})'}

    def get_whitelisted_routers(self) -> Dict[str, str]:
        return dict(self._whitelisted_routers)

    def get_known_lockers(self) -> Dict[str, str]:
        """Return {lowercase_address: locker_name} for this chain, burn addresses included."""
        return dict(self._known_lockers)

    def capabilities(self) -> Dict:
        """What this chain's configuration lets a scan check, for GET /api/coverage/{chain_id}.

        sell_simulation is goplus_reported where no sell is simulated and honeypot and tax fields come
        from GoPlus's own flags. A Blockscout source is named only where a Blockscout request can be
        sent; without one, contract_age is None (no other source is asked) and verification falls back
        to Sourcify alone, which can verify a contract but not call it unverified. Liquidity lock
        status is unknown on a chain whose only known lockers are burn addresses: an unlocked pool
        cannot be told from one held by an unlisted locker.
        """
        lockers = [name for address, name in self._known_lockers.items() if address not in BURN_ADDRESSES]
        blockscout = self._explorer_service.can_reach_blockscout(self._chain_id)
        return {
            'sell_simulation': 'honeypot.is' if self._honeypot_chain_id is not None else 'goplus_reported',
            # Etherscan, then Sourcify's deployment record when Etherscan does not answer (its free
            # tier refuses the lookup on BNB Chain): the sources in the order asked, as for verification.
            'contract_age': (
                'etherscan+sourcify' if self._explorer_backend == 'etherscan'
                else 'blockscout' if blockscout else None
            ),
            # VERIFICATION_SOURCES in the order they are asked; on Robinhood Chain, Sourcify then
            # Blockscout where a Blockscout request can be sent. Verified when any source says so,
            # unverified only when every source asked says not.
            'verification': (
                '+'.join(VERIFICATION_SOURCES) if self._explorer_backend != 'sourcify_blockscout'
                else 'sourcify+blockscout' if blockscout else 'sourcify'
            ),
            'liquidity_lock': {'lockers': 'known' if lockers else 'unknown', 'known_lockers': lockers},
            'router_allowlist': {
                'present': bool(self._whitelisted_routers), 'routers': len(self._whitelisted_routers),
            },
        }
