"""BSC (BNB Smart Chain) adapter — extracted from Web3Client."""

import os
import logging
import aiohttp
from typing import Dict, Optional, Tuple
from web3 import Web3
try:
    from web3.middleware import ExtraDataToPOAMiddleware as geth_poa_middleware
except ImportError:
    from web3.middleware import geth_poa_middleware
from datetime import datetime, timezone

from core.chain_adapter import ChainAdapter

logger = logging.getLogger(__name__)

# BSC Constants
KNOWN_LOCKERS = {
    '0x407993575c91ce7643a4d4cCACc9A98c36eE1BBE'.lower(): 'PinkLock',
    '0xC765bddB93b0D1c1A88282BA0fa6B2d00E3e0c83'.lower(): 'Unicrypt',
    '0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214'.lower(): 'DxLock',
    '0x0000000000000000000000000000000000000000': 'Burn Address',
    '0x000000000000000000000000000000000000dEaD'.lower(): 'Dead Address',
}

PANCAKESWAP_V2_FACTORY = '0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73'
WBNB_ADDRESS = '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c'
BUSD_ADDRESS = '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56'
USDT_ADDRESS = '0x55d398326f99059fF775485246999027B3197955'

QUOTE_TOKENS = [
    ('WBNB', WBNB_ADDRESS),
    ('BUSD', BUSD_ADDRESS),
    ('USDT', USDT_ADDRESS),
]

WHITELISTED_ROUTERS = {
    "0x10ED43C718714eb63d5aA57B78B54704E256024E".lower(): "PancakeSwap V2 Router",
    "0x13f4EA83D0bd40E75C8222255bc855a974568Dd4".lower(): "PancakeSwap V3 Smart Router",
    "0x1a0A18AC4BECDdbd6389559687d1A73d8927E416".lower(): "PancakeSwap Universal Router",
    "0xd9C500DfF816a1Da21A48A732d3498Bf09dc9AEB".lower(): "PancakeSwap Universal Router 2",
    "0x1111111254EEB25477B68fb85Ed929f73A960582".lower(): "1inch V5 Router",
    "0x111111125421cA6dc452d289314280a0f8842A65".lower(): "1inch V6 Router",
}

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


class BscAdapter(ChainAdapter):
    """BNB Smart Chain (BSC) adapter — chain_id=56."""

    def __init__(self, rpc_url: str = None, bscscan_api_key: str = None):
        rpc = rpc_url or os.getenv('BSC_RPC_URL', 'https://bsc-dataseed1.binance.org/')
        self.w3 = Web3(Web3.HTTPProvider(rpc))
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        self.bscscan_api_key = bscscan_api_key or os.getenv('BSCSCAN_API_KEY', '')
        self.bscscan_api_url = 'https://api.etherscan.io/v2/api'

    @property
    def chain_id(self) -> int:
        return 56

    @property
    def chain_name(self) -> str:
        return "BSC"

    async def is_contract(self, address: str) -> bool:
        try:
            code = self.w3.eth.get_code(Web3.to_checksum_address(address))
            return len(code) > 0
        except Exception as e:
            logger.error(f"Error checking if contract: {e}")
            return False

    async def get_bytecode(self, address: str) -> Optional[str]:
        try:
            code = self.w3.eth.get_code(Web3.to_checksum_address(address))
            return code.hex()
        except Exception as e:
            logger.error(f"Error getting bytecode: {e}")
            return None

    async def is_verified_contract(self, address: str) -> Tuple[bool, Optional[str]]:
        try:
            async with aiohttp.ClientSession() as session:
                params = {
                    'chainid': self.chain_id,
                    'module': 'contract',
                    'action': 'getsourcecode',
                    'address': address,
                    'apikey': self.bscscan_api_key,
                }
                async with session.get(self.bscscan_api_url, params=params) as resp:
                    data = await resp.json()
                    if data['status'] == '1' and data['result']:
                        source_code = data['result'][0].get('SourceCode', '')
                        is_verified = len(source_code) > 0
                        return (is_verified, source_code if is_verified else None)
            return (False, None)
        except Exception as e:
            logger.error(f"Error checking verification: {e}")
            return (False, None)

    async def get_contract_creation_info(self, address: str) -> Optional[Dict]:
        try:
            async with aiohttp.ClientSession() as session:
                params = {
                    'chainid': self.chain_id,
                    'module': 'contract',
                    'action': 'getcontractcreation',
                    'contractaddresses': address,
                    'apikey': self.bscscan_api_key,
                }
                async with session.get(self.bscscan_api_url, params=params) as resp:
                    data = await resp.json()
                    if data['status'] == '1' and data['result']:
                        result = data['result'][0]
                        tx_hash = result.get('txHash')
                        tx = self.w3.eth.get_transaction(tx_hash)
                        block = self.w3.eth.get_block(tx['blockNumber'])
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
            logger.error(f"Error getting creation info: {e}")
            return None

    async def get_token_info(self, address: str) -> Dict:
        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=ERC20_ABI,
            )
            name = contract.functions.name().call()
            symbol = contract.functions.symbol().call()
            decimals = contract.functions.decimals().call()
            total_supply = contract.functions.totalSupply().call()
            return {
                'name': name, 'symbol': symbol,
                'decimals': decimals, 'total_supply': total_supply / (10 ** decimals),
            }
        except Exception as e:
            logger.error(f"Error getting token info: {e}")
            return {}

    async def get_ownership_info(self, address: str) -> Dict:
        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address), abi=ERC20_ABI,
            )
            owner = contract.functions.owner().call()
            zero_address = '0x0000000000000000000000000000000000000000'
            is_renounced = owner.lower() == zero_address.lower()
            return {'owner': owner, 'is_renounced': is_renounced}
        except Exception as e:
            logger.error(f"Error getting ownership info: {e}")
            return {'owner': None, 'is_renounced': None}

    async def check_honeypot(self, address: str) -> Dict:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.honeypot.is/v2/IsHoneypot?address={address}&chainID=56"
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
                        if is_honeypot and sell_tax < 50 and buy_tax < 50:
                            return {
                                'is_honeypot': False,
                                'reason': f'Flagged but taxes normal (buy:{buy_tax}% sell:{sell_tax}%)',
                                'likely_false_positive': True,
                            }

                        return {'is_honeypot': is_honeypot, 'reason': reason}
            return {'is_honeypot': False, 'reason': 'Unable to check'}
        except Exception as e:
            logger.error(f"Error checking honeypot: {e}")
            return {'is_honeypot': False, 'reason': f'Error: {str(e)}'}

    async def get_tax_info(self, address: str) -> Dict:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.honeypot.is/v2/IsHoneypot?address={address}&chainID=56"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        simulation = data.get('simulationResult', {})
                        return {
                            'buy_tax': float(simulation.get('buyTax', 0)),
                            'sell_tax': float(simulation.get('sellTax', 0)),
                        }
            return {'buy_tax': 0, 'sell_tax': 0}
        except Exception as e:
            logger.error(f"Error getting tax info: {e}")
            return {'buy_tax': 0, 'sell_tax': 0}

    async def get_liquidity_info(self, address: str) -> Dict:
        try:
            checksum_addr = Web3.to_checksum_address(address)
            factory = self.w3.eth.contract(
                address=Web3.to_checksum_address(PANCAKESWAP_V2_FACTORY), abi=FACTORY_ABI,
            )
            zero_address = '0x0000000000000000000000000000000000000000'
            pair_address = None
            paired_with = None

            for quote_name, quote_addr in QUOTE_TOKENS:
                try:
                    addr = factory.functions.getPair(
                        checksum_addr, Web3.to_checksum_address(quote_addr),
                    ).call()
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
            total_supply = pair_contract.functions.totalSupply().call()
            if total_supply == 0:
                return {'is_locked': False, 'lock_percentage': 0, 'pair': pair_address}

            locked_amount = 0
            locker_details = []
            for locker_addr, locker_name in KNOWN_LOCKERS.items():
                try:
                    balance = pair_contract.functions.balanceOf(
                        Web3.to_checksum_address(locker_addr),
                    ).call()
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
            logger.error(f"Error getting liquidity info: {e}")
            return {'is_locked': False, 'lock_percentage': 0}

    def get_whitelisted_routers(self) -> Dict[str, str]:
        return dict(WHITELISTED_ROUTERS)
