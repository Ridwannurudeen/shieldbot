"""
Web3 Client for BNB Chain interaction
Handles contract calls, verification checks, and blockchain queries
"""

import os
import logging
import aiohttp
from typing import Dict, Optional
from web3 import Web3
from web3.exceptions import BadFunctionCallOutput
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class Web3Client:
    """Web3 client for BNB Chain (BSC and opBNB)"""
    
    def __init__(self):
        # Initialize Web3 connections
        bsc_rpc = os.getenv('BSC_RPC_URL', 'https://bsc-dataseed1.binance.org/')
        opbnb_rpc = os.getenv('OPBNB_RPC_URL', 'https://opbnb-mainnet-rpc.bnbchain.org')
        
        self.bsc_web3 = Web3(Web3.HTTPProvider(bsc_rpc))
        self.opbnb_web3 = Web3(Web3.HTTPProvider(opbnb_rpc))
        
        # Default to BSC
        self.web3 = self.bsc_web3
        
        # BscScan API
        self.bscscan_api_key = os.getenv('BSCSCAN_API_KEY', '')
        self.bscscan_api_url = 'https://api.bscscan.com/api'
        
        # ERC20 ABI (minimal)
        self.erc20_abi = [
            {
                "constant": True,
                "inputs": [],
                "name": "name",
                "outputs": [{"name": "", "type": "string"}],
                "type": "function"
            },
            {
                "constant": True,
                "inputs": [],
                "name": "symbol",
                "outputs": [{"name": "", "type": "string"}],
                "type": "function"
            },
            {
                "constant": True,
                "inputs": [],
                "name": "decimals",
                "outputs": [{"name": "", "type": "uint8"}],
                "type": "function"
            },
            {
                "constant": True,
                "inputs": [],
                "name": "totalSupply",
                "outputs": [{"name": "", "type": "uint256"}],
                "type": "function"
            },
            {
                "constant": True,
                "inputs": [],
                "name": "owner",
                "outputs": [{"name": "", "type": "address"}],
                "type": "function"
            }
        ]
        
        logger.info("Web3Client initialized")
    
    def is_valid_address(self, address: str) -> bool:
        """Check if address is valid"""
        return Web3.is_address(address)
    
    def to_checksum_address(self, address: str) -> str:
        """Convert address to checksum format"""
        return Web3.to_checksum_address(address)
    
    async def is_contract(self, address: str) -> bool:
        """Check if address is a contract"""
        try:
            code = self.web3.eth.get_code(Web3.to_checksum_address(address))
            return len(code) > 0
        except Exception as e:
            logger.error(f"Error checking if contract: {e}")
            return False
    
    async def is_token_contract(self, address: str) -> bool:
        """Check if address is a token contract (has ERC20 functions)"""
        try:
            contract = self.web3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=self.erc20_abi
            )
            
            # Try to call symbol() - most tokens have this
            contract.functions.symbol().call()
            return True
        except Exception:
            return False
    
    async def get_bytecode(self, address: str) -> Optional[str]:
        """Get contract bytecode"""
        try:
            code = self.web3.eth.get_code(Web3.to_checksum_address(address))
            return code.hex()
        except Exception as e:
            logger.error(f"Error getting bytecode: {e}")
            return None
    
    async def is_verified_contract(self, address: str) -> bool:
        """Check if contract is verified on BscScan"""
        try:
            async with aiohttp.ClientSession() as session:
                params = {
                    'module': 'contract',
                    'action': 'getsourcecode',
                    'address': address,
                    'apikey': self.bscscan_api_key
                }
                
                async with session.get(self.bscscan_api_url, params=params) as resp:
                    data = await resp.json()
                    
                    if data['status'] == '1' and data['result']:
                        source_code = data['result'][0].get('SourceCode', '')
                        return len(source_code) > 0
            
            return False
        except Exception as e:
            logger.error(f"Error checking verification: {e}")
            return False
    
    async def get_contract_creation_info(self, address: str) -> Optional[Dict]:
        """Get contract creation transaction and age"""
        try:
            async with aiohttp.ClientSession() as session:
                params = {
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
                        
                        # Get transaction details for timestamp
                        tx = self.web3.eth.get_transaction(tx_hash)
                        block = self.web3.eth.get_block(tx['blockNumber'])
                        
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
    
    async def get_token_info(self, address: str) -> Dict:
        """Get token information (name, symbol, decimals, supply)"""
        try:
            contract = self.web3.eth.contract(
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
                'total_supply': total_supply / (10 ** decimals)  # Human readable
            }
        except Exception as e:
            logger.error(f"Error getting token info: {e}")
            return {}
    
    async def can_transfer_token(self, address: str) -> bool:
        """Check if token transfers work (simplified check)"""
        try:
            # For now, just check if the contract has the transfer function
            # In production, you'd simulate a transfer
            contract = self.web3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=self.erc20_abi
            )
            
            # If we can get decimals, basic functions work
            contract.functions.decimals().call()
            return True
        except Exception:
            return False
    
    async def get_ownership_info(self, address: str) -> Dict:
        """Get contract ownership information"""
        try:
            contract = self.web3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=self.erc20_abi
            )
            
            # Try to get owner
            owner = contract.functions.owner().call()
            
            # Check if ownership is renounced (owner is zero address)
            zero_address = '0x0000000000000000000000000000000000000000'
            is_renounced = owner.lower() == zero_address.lower()
            
            return {
                'owner': owner,
                'is_renounced': is_renounced
            }
        except Exception as e:
            logger.error(f"Error getting ownership info: {e}")
            return {'owner': None, 'is_renounced': False}
    
    async def get_liquidity_info(self, address: str) -> Dict:
        """Get liquidity lock information"""
        # This is a simplified version - in production you'd check actual lock contracts
        # For now, return basic info
        return {
            'is_locked': False,  # Would check lock contracts
            'lock_percentage': 0
        }
    
    async def check_honeypot(self, address: str) -> Dict:
        """Check if token is a honeypot using external API"""
        try:
            # Use honeypot.is API (free tier available)
            async with aiohttp.ClientSession() as session:
                url = f"https://api.honeypot.is/v2/IsHoneypot?address={address}&chainID=56"
                
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        is_honeypot = data.get('honeypotResult', {}).get('isHoneypot', False)
                        reason = data.get('honeypotResult', {}).get('honeypotReason', 'Unknown')
                        
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
            # Use honeypot.is API which also provides tax info
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
