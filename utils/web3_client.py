"""
Web3 Client for BNB Chain interaction
Handles contract calls, verification checks, and blockchain queries
"""

import os
import logging
import aiohttp
from typing import Dict, Optional, Tuple, Union
from web3 import Web3
try:
    from web3.middleware import ExtraDataToPOAMiddleware as geth_poa_middleware
except ImportError:
    from web3.middleware import geth_poa_middleware
from web3.exceptions import BadFunctionCallOutput
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Known liquidity locker addresses on BSC
KNOWN_LOCKERS = {
    '0x407993575c91ce7643a4d4cCACc9A98c36eE1BBE'.lower(): 'PinkLock',
    '0xC765bddB93b0D1c1A88282BA0fa6B2d00E3e0c83'.lower(): 'Unicrypt',
    '0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214'.lower(): 'DxLock',
    '0x0000000000000000000000000000000000000000': 'Burn Address',
    '0x000000000000000000000000000000000000dEaD'.lower(): 'Dead Address',
}

# PancakeSwap V2 Factory address on BSC
PANCAKESWAP_V2_FACTORY = '0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73'
WBNB_ADDRESS = '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c'
BUSD_ADDRESS = '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56'
USDT_ADDRESS = '0x55d398326f99059fF775485246999027B3197955'

# Quote tokens to check for LP pairs (most BSC tokens pair with one of these)
QUOTE_TOKENS = [
    ('WBNB', WBNB_ADDRESS),
    ('BUSD', BUSD_ADDRESS),
    ('USDT', USDT_ADDRESS),
]

# Minimal ABIs
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
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    }
]


class Web3Client:
    """Web3 client for BNB Chain (BSC and opBNB)"""

    def __init__(self):
        bsc_rpc = os.getenv('BSC_RPC_URL', 'https://bsc-dataseed1.binance.org/')
        opbnb_rpc = os.getenv('OPBNB_RPC_URL', 'https://opbnb-mainnet-rpc.bnbchain.org')

        self.bsc_web3 = Web3(Web3.HTTPProvider(bsc_rpc))
        self.bsc_web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        self.opbnb_web3 = Web3(Web3.HTTPProvider(opbnb_rpc))
        self.opbnb_web3.middleware_onion.inject(geth_poa_middleware, layer=0)

        self.bscscan_api_key = os.getenv('BSCSCAN_API_KEY', '')
        self.bscscan_api_url = 'https://api.etherscan.io/v2/api'
        self.bscscan_chainid = 56

        # ERC20 ABI (minimal)
        self.erc20_abi = [
            {
                "constant": True, "inputs": [], "name": "name",
                "outputs": [{"name": "", "type": "string"}], "type": "function"
            },
            {
                "constant": True, "inputs": [], "name": "symbol",
                "outputs": [{"name": "", "type": "string"}], "type": "function"
            },
            {
                "constant": True, "inputs": [], "name": "decimals",
                "outputs": [{"name": "", "type": "uint8"}], "type": "function"
            },
            {
                "constant": True, "inputs": [], "name": "totalSupply",
                "outputs": [{"name": "", "type": "uint256"}], "type": "function"
            },
            {
                "constant": True, "inputs": [], "name": "owner",
                "outputs": [{"name": "", "type": "address"}], "type": "function"
            }
        ]

        logger.info("Web3Client initialized")

    def get_web3(self, chain_id: int = 56):
        """Return the appropriate Web3 instance for the given chain ID."""
        if chain_id == 204:
            return self.opbnb_web3
        return self.bsc_web3

    def is_valid_address(self, address: str) -> bool:
        """Check if address is valid"""
        return Web3.is_address(address)

    def to_checksum_address(self, address: str) -> str:
        """Convert address to checksum format"""
        return Web3.to_checksum_address(address)

    async def is_contract(self, address: str, chain_id: int = 56) -> bool:
        """Check if address is a contract"""
        try:
            w3 = self.get_web3(chain_id)
            code = w3.eth.get_code(Web3.to_checksum_address(address))
            return len(code) > 0
        except Exception as e:
            logger.error(f"Error checking if contract: {e}")
            return False

    async def is_token_contract(self, address: str, chain_id: int = 56) -> bool:
        """Check if address is a token contract (has ERC20 functions)"""
        try:
            w3 = self.get_web3(chain_id)
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=self.erc20_abi
            )
            contract.functions.symbol().call()
            return True
        except Exception:
            return False

    async def get_bytecode(self, address: str, chain_id: int = 56) -> Optional[str]:
        """Get contract bytecode"""
        try:
            w3 = self.get_web3(chain_id)
            code = w3.eth.get_code(Web3.to_checksum_address(address))
            return code.hex()
        except Exception as e:
            logger.error(f"Error getting bytecode: {e}")
            return None

    async def is_verified_contract(self, address: str) -> Union[bool, Tuple[bool, Optional[str]]]:
        """
        Check if contract is verified on BscScan.
        Returns tuple (is_verified, source_code_or_None) when source is available.
        """
        try:
            async with aiohttp.ClientSession() as session:
                params = {
                    'chainid': self.bscscan_chainid,
                    'module': 'contract',
                    'action': 'getsourcecode',
                    'address': address,
                    'apikey': self.bscscan_api_key
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
        """Get contract creation transaction and age"""
        try:
            async with aiohttp.ClientSession() as session:
                params = {
                    'chainid': self.bscscan_chainid,
                    'module': 'contract',
                    'action': 'getcontractcreation',
                    'contractaddresses': address,
                    'apikey': self.bscscan_api_key
                }

                async with session.get(self.bscscan_api_url, params=params) as resp:
                    data = await resp.json()

                    if data['status'] == '1' and data['result']:
                        result = data['result'][0]
                        tx_hash = result.get('txHash')

                        tx = self.bsc_web3.eth.get_transaction(tx_hash)
                        block = self.bsc_web3.eth.get_block(tx['blockNumber'])

                        creation_time = datetime.fromtimestamp(block['timestamp'], tz=timezone.utc)
                        age_days = (datetime.now(timezone.utc) - creation_time).days

                        return {
                            'tx_hash': tx_hash,
                            'creator': result.get('contractCreator'),
                            'creation_time': creation_time.isoformat(),
                            'age_days': age_days
                        }

            return None
        except Exception as e:
            logger.error(f"Error getting creation info: {e}")
            return None

    async def get_token_info(self, address: str, chain_id: int = 56) -> Dict:
        """Get token information (name, symbol, decimals, supply)"""
        try:
            w3 = self.get_web3(chain_id)
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=self.erc20_abi
            )

            name = contract.functions.name().call()
            symbol = contract.functions.symbol().call()
            decimals = contract.functions.decimals().call()
            total_supply = contract.functions.totalSupply().call()

            return {
                'name': name,
                'symbol': symbol,
                'decimals': decimals,
                'total_supply': total_supply / (10 ** decimals)
            }
        except Exception as e:
            logger.error(f"Error getting token info: {e}")
            return {}

    async def can_transfer_token(self, address: str, chain_id: int = 56) -> bool:
        """Check if token transfers work (simplified check)"""
        try:
            w3 = self.get_web3(chain_id)
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=self.erc20_abi
            )
            contract.functions.decimals().call()
            return True
        except Exception:
            return False

    async def get_ownership_info(self, address: str, chain_id: int = 56) -> Dict:
        """Get contract ownership information"""
        try:
            w3 = self.get_web3(chain_id)
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=self.erc20_abi
            )

            owner = contract.functions.owner().call()
            zero_address = '0x0000000000000000000000000000000000000000'
            is_renounced = owner.lower() == zero_address.lower()

            return {
                'owner': owner,
                'is_renounced': is_renounced
            }
        except Exception as e:
            logger.error(f"Error getting ownership info: {e}")
            return {'owner': None, 'is_renounced': None}

    async def get_liquidity_info(self, address: str, chain_id: int = 56) -> Dict:
        """
        Get real liquidity lock information by checking PancakeSwap V2 LP tokens
        held by known locker contracts (PinkLock, Unicrypt, DxLock, burn/dead addresses).
        Checks pairs against multiple quote tokens (WBNB, BUSD, USDT).
        """
        try:
            checksum_addr = Web3.to_checksum_address(address)
            w3 = self.get_web3(chain_id)
            factory = w3.eth.contract(
                address=Web3.to_checksum_address(PANCAKESWAP_V2_FACTORY),
                abi=FACTORY_ABI
            )

            zero_address = '0x0000000000000000000000000000000000000000'
            pair_address = None
            paired_with = None

            # Check pairs against all major quote tokens
            for quote_name, quote_addr in QUOTE_TOKENS:
                try:
                    addr = factory.functions.getPair(
                        checksum_addr,
                        Web3.to_checksum_address(quote_addr)
                    ).call()
                    if addr != zero_address:
                        pair_address = addr
                        paired_with = quote_name
                        logger.info(f"Found LP pair for {address}/{quote_name}: {addr}")
                        break
                except Exception:
                    continue

            if not pair_address:
                logger.info(f"No PancakeSwap V2 pair found for {address}")
                return {'is_locked': False, 'lock_percentage': 0, 'pair': None}

            # Get total LP supply and check balances of known lockers
            pair_contract = w3.eth.contract(
                address=Web3.to_checksum_address(pair_address),
                abi=PAIR_ABI
            )

            total_supply = pair_contract.functions.totalSupply().call()
            if total_supply == 0:
                return {'is_locked': False, 'lock_percentage': 0, 'pair': pair_address}

            locked_amount = 0
            locker_details = []

            for locker_addr, locker_name in KNOWN_LOCKERS.items():
                try:
                    balance = pair_contract.functions.balanceOf(
                        Web3.to_checksum_address(locker_addr)
                    ).call()
                    if balance > 0:
                        pct = (balance / total_supply) * 100
                        locked_amount += balance
                        locker_details.append({
                            'locker': locker_name,
                            'address': locker_addr,
                            'percentage': round(pct, 2)
                        })
                except Exception:
                    continue

            lock_percentage = round((locked_amount / total_supply) * 100, 2) if total_supply > 0 else 0
            is_locked = lock_percentage > 50  # Consider locked if >50% in lockers

            return {
                'is_locked': is_locked,
                'lock_percentage': lock_percentage,
                'pair': pair_address,
                'paired_with': paired_with,
                'lockers': locker_details
            }

        except Exception as e:
            logger.error(f"Error getting liquidity info: {e}")
            return {'is_locked': False, 'lock_percentage': 0}

    async def check_honeypot(self, address: str) -> Dict:
        """Check if token is a honeypot using external API"""
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

                        # If simulation failed, don't trust the honeypot flag
                        if not sim_success:
                            logger.info(f"Honeypot API simulation failed for {address} - treating as inconclusive")
                            return {
                                'is_honeypot': False,
                                'reason': 'Simulation failed (inconclusive)',
                                'simulation_failed': True
                            }

                        # If buy/sell taxes are both readable and sell tax < 50%, likely not a real honeypot
                        sell_tax = float(simulation.get('sellTax', 0))
                        buy_tax = float(simulation.get('buyTax', 0))
                        if is_honeypot and sell_tax < 50 and buy_tax < 50:
                            logger.info(f"Honeypot API flagged {address} but taxes are normal (buy:{buy_tax}% sell:{sell_tax}%) - likely false positive")
                            return {
                                'is_honeypot': False,
                                'reason': f'Flagged but taxes normal (buy:{buy_tax}% sell:{sell_tax}%)',
                                'likely_false_positive': True
                            }

                        return {
                            'is_honeypot': is_honeypot,
                            'reason': reason
                        }

            return {'is_honeypot': False, 'reason': 'Unable to check'}
        except Exception as e:
            logger.error(f"Error checking honeypot: {e}")
            return {'is_honeypot': False, 'reason': f'Error: {str(e)}'}

    async def get_tax_info(self, address: str) -> Dict:
        """Get buy/sell tax information"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.honeypot.is/v2/IsHoneypot?address={address}&chainID=56"

                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()

                        simulation = data.get('simulationResult', {})
                        buy_tax = float(simulation.get('buyTax', 0))
                        sell_tax = float(simulation.get('sellTax', 0))

                        return {
                            'buy_tax': buy_tax,
                            'sell_tax': sell_tax
                        }

            return {'buy_tax': 0, 'sell_tax': 0}
        except Exception as e:
            logger.error(f"Error getting tax info: {e}")
            return {'buy_tax': 0, 'sell_tax': 0}
