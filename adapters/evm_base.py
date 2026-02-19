"""Shared EVM adapter base class — config-driven extraction for EVM-compatible chains."""

import logging
import asyncio
import aiohttp
from typing import Dict, List, Optional, Tuple
from web3 import Web3
try:
    from web3.middleware import ExtraDataToPOAMiddleware as geth_poa_middleware
except ImportError:
    from web3.middleware import geth_poa_middleware
from datetime import datetime, timezone

from core.chain_adapter import ChainAdapter

logger = logging.getLogger(__name__)

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
    ):
        self._chain_id = chain_id_value
        self._chain_name = chain_name_value
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        self.etherscan_api_key = etherscan_api_key
        self.etherscan_api_url = 'https://api.etherscan.io/v2/api'
        self._honeypot_chain_id = honeypot_chain_id or chain_id_value
        self._known_lockers = known_lockers or {}
        self._quote_tokens = quote_tokens or []
        self._factory_address = factory_address
        self._whitelisted_routers = whitelisted_routers or {}

    @property
    def chain_id(self) -> int:
        return self._chain_id

    @property
    def chain_name(self) -> str:
        return self._chain_name

    async def _call_with_retry(self, fn, *args, retries=3, base_delay=1.0):
        """Wrap a synchronous web3 call with retry + executor to avoid blocking the event loop."""
        if retries < 1:
            retries = 1
        loop = asyncio.get_event_loop()
        last_exc = None
        for attempt in range(retries):
            try:
                return await loop.run_in_executor(None, fn, *args)
            except Exception as e:
                last_exc = e
                err_str = str(e)
                is_retriable = '429' in err_str or '502' in err_str or '503' in err_str
                if is_retriable and attempt < retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.warning(
                        f"[{self._chain_name}] RPC rate-limited (attempt {attempt + 1}/{retries}), "
                        f"retrying in {delay}s: {err_str[:80]}"
                    )
                    await asyncio.sleep(delay)
                elif not is_retriable:
                    raise
        raise last_exc

    async def is_contract(self, address: str) -> bool:
        try:
            code = await self._call_with_retry(self.w3.eth.get_code, Web3.to_checksum_address(address))
            return len(code) > 0
        except Exception as e:
            logger.error(f"[{self._chain_name}] Error checking if contract: {e}")
            return False

    async def get_bytecode(self, address: str) -> Optional[str]:
        try:
            code = await self._call_with_retry(self.w3.eth.get_code, Web3.to_checksum_address(address))
            return code.hex()
        except Exception as e:
            logger.error(f"[{self._chain_name}] Error getting bytecode: {e}")
            return None

    async def is_verified_contract(self, address: str) -> Tuple[bool, Optional[str]]:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                params = {
                    'chainid': self._chain_id,
                    'module': 'contract',
                    'action': 'getsourcecode',
                    'address': address,
                    'apikey': self.etherscan_api_key,
                }
                async with session.get(self.etherscan_api_url, params=params) as resp:
                    data = await resp.json()
                    if data['status'] == '1' and data['result']:
                        source_code = data['result'][0].get('SourceCode', '')
                        is_verified = len(source_code) > 0
                        return (is_verified, source_code if is_verified else None)
            return (False, None)
        except Exception as e:
            logger.error(f"[{self._chain_name}] Error checking verification: {e}")
            return (False, None)

    async def get_contract_creation_info(self, address: str) -> Optional[Dict]:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                params = {
                    'chainid': self._chain_id,
                    'module': 'contract',
                    'action': 'getcontractcreation',
                    'contractaddresses': address,
                    'apikey': self.etherscan_api_key,
                }
                async with session.get(self.etherscan_api_url, params=params) as resp:
                    data = await resp.json()
                    if data['status'] == '1' and data['result']:
                        result = data['result'][0]
                        tx_hash = result.get('txHash')
                        tx = await self._call_with_retry(self.w3.eth.get_transaction, tx_hash)
                        block = await self._call_with_retry(self.w3.eth.get_block, tx['blockNumber'])
                        creation_time = datetime.fromtimestamp(block['timestamp'], tz=timezone.utc)
                        age_days = (datetime.now(timezone.utc) - creation_time).days
                        return {
                            'tx_hash': tx_hash,
                            'creator': result.get('contractCreator'),
                            'creation_time': creation_time.isoformat(),
                            'age_days': age_days,
                        }
            return None
        except Exception as e:
            logger.error(f"[{self._chain_name}] Error getting creation info: {e}")
            return None

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
            logger.error(f"[{self._chain_name}] Error getting token info: {e}")
            return {}

    async def get_ownership_info(self, address: str) -> Dict:
        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=ERC20_ABI,
            )
            owner = await self._call_with_retry(contract.functions.owner().call)
            zero_address = '0x0000000000000000000000000000000000000000'
            is_renounced = owner.lower() == zero_address.lower()
            return {'owner': owner, 'is_renounced': is_renounced}
        except Exception as e:
            logger.error(f"[{self._chain_name}] Error getting ownership info: {e}")
            return {'owner': None, 'is_renounced': None}

    async def check_honeypot(self, address: str) -> Dict:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.honeypot.is/v2/IsHoneypot?address={address}&chainID={self._honeypot_chain_id}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        honeypot_result = data.get('honeypotResult', {})
                        simulation = data.get('simulationResult', {})
                        is_honeypot = honeypot_result.get('isHoneypot', False)
                        reason = honeypot_result.get('honeypotReason', 'Unknown')
                        sim_success = data.get('simulationSuccess', True)

                        if not sim_success:
                            return {
                                'is_honeypot': False,
                                'reason': 'Simulation failed (inconclusive)',
                                'simulation_failed': True,
                            }

                        sell_tax = float(simulation.get('sellTax', 0))
                        buy_tax = float(simulation.get('buyTax', 0))
                        if is_honeypot and sell_tax < 5 and buy_tax < 5:
                            # Low taxes but flagged — check if verified.
                            # Verified contracts with 0% taxes are almost
                            # always honeypot.is false positives (e.g.
                            # Binance-pegged tokens like LINK, DOGE, XVS).
                            verified, _ = await self.is_verified_contract(address)
                            if verified:
                                return {
                                    'is_honeypot': False,
                                    'reason': f'Flagged but verified with normal taxes (buy:{buy_tax}% sell:{sell_tax}%)',
                                    'likely_false_positive': True,
                                }
                            # Unverified + flagged = trust the flag
                            return {
                                'is_honeypot': True,
                                'reason': f'{reason} (taxes low: buy:{buy_tax}% sell:{sell_tax}%)',
                                'low_tax_honeypot': True,
                            }

                        return {'is_honeypot': is_honeypot, 'reason': reason}
                    if resp.status == 404:
                        return {
                            'is_honeypot': False,
                            'reason': 'Token not found on honeypot.is',
                            'simulation_failed': True,
                        }
            return {'is_honeypot': False, 'reason': 'Unable to check'}
        except Exception as e:
            logger.error(f"[{self._chain_name}] Error checking honeypot: {e}")
            return {'is_honeypot': False, 'reason': f'Error: {str(e)}'}

    async def get_tax_info(self, address: str) -> Dict:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.honeypot.is/v2/IsHoneypot?address={address}&chainID={self._honeypot_chain_id}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        simulation = data.get('simulationResult', {})
                        return {
                            'buy_tax': float(simulation.get('buyTax', 0)),
                            'sell_tax': float(simulation.get('sellTax', 0)),
                        }
            return {'buy_tax': 0, 'sell_tax': 0}
        except Exception as e:
            logger.error(f"[{self._chain_name}] Error getting tax info: {e}")
            return {'buy_tax': 0, 'sell_tax': 0}

    async def get_liquidity_info(self, address: str) -> Dict:
        if not self._factory_address:
            return {'is_locked': False, 'lock_percentage': 0, 'pair': None}

        try:
            checksum_addr = Web3.to_checksum_address(address)
            factory = self.w3.eth.contract(
                address=Web3.to_checksum_address(self._factory_address), abi=FACTORY_ABI,
            )
            zero_address = '0x0000000000000000000000000000000000000000'
            pair_address = None
            paired_with = None

            for quote_name, quote_addr in self._quote_tokens:
                try:
                    addr = await self._call_with_retry(
                        factory.functions.getPair(
                            checksum_addr, Web3.to_checksum_address(quote_addr),
                        ).call,
                    )
                    if addr != zero_address:
                        pair_address = addr
                        paired_with = quote_name
                        break
                except Exception:
                    continue

            if not pair_address:
                return {'is_locked': False, 'lock_percentage': 0, 'pair': None}

            pair_contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(pair_address), abi=PAIR_ABI,
            )
            total_supply = await self._call_with_retry(pair_contract.functions.totalSupply().call)
            if total_supply == 0:
                return {'is_locked': False, 'lock_percentage': 0, 'pair': pair_address}

            locked_amount = 0
            locker_details = []
            for locker_addr, locker_name in self._known_lockers.items():
                try:
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
                except Exception:
                    continue

            lock_percentage = round((locked_amount / total_supply) * 100, 2) if total_supply > 0 else 0
            is_locked = lock_percentage > 50

            return {
                'is_locked': is_locked,
                'lock_percentage': lock_percentage,
                'pair': pair_address,
                'paired_with': paired_with,
                'lockers': locker_details,
            }
        except Exception as e:
            logger.error(f"[{self._chain_name}] Error getting liquidity info: {e}")
            return {'is_locked': False, 'lock_percentage': 0}

    def get_whitelisted_routers(self) -> Dict[str, str]:
        return dict(self._whitelisted_routers)
