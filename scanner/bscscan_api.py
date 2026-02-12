"""
BSCScan API Client
Handles contract verification and blockchain data queries
"""

import os
import requests
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

class BSCScanAPI:
    """Client for BSCScan API interactions"""
    
    BASE_URLS = {
        "BSC": "https://api.bscscan.com/api",
        "opBNB": "https://api-opbnb.bscscan.com/api"
    }
    
    def __init__(self, chain: str = "BSC"):
        """
        Initialize BSCScan API client
        
        Args:
            chain: "BSC" or "opBNB"
        """
        self.chain = chain
        self.base_url = self.BASE_URLS.get(chain, self.BASE_URLS["BSC"])
        self.api_key = os.getenv('BSCSCAN_API_KEY', '')
    
    def _make_request(self, params: dict) -> dict:
        """Make API request to BSCScan"""
        params['apikey'] = self.api_key
        try:
            response = requests.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": "0", "message": f"API Error: {str(e)}"}
    
    def is_contract_verified(self, address: str) -> tuple:
        """
        Check if contract is verified on BSCScan
        
        Returns:
            tuple: (is_verified: bool, contract_name: str, source_code: str)
        """
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }
        
        result = self._make_request(params)
        
        if result.get('status') == '1' and result.get('result'):
            source_data = result['result'][0]
            source_code = source_data.get('SourceCode', '')
            contract_name = source_data.get('ContractName', '')
            
            is_verified = bool(source_code and source_code != '')
            return is_verified, contract_name, source_code
        
        return False, '', ''
    
    def get_contract_abi(self, address: str) -> Optional[str]:
        """Get contract ABI"""
        params = {
            'module': 'contract',
            'action': 'getabi',
            'address': address
        }
        
        result = self._make_request(params)
        
        if result.get('status') == '1':
            return result.get('result', '')
        
        return None
    
    def get_transaction_receipt(self, tx_hash: str) -> dict:
        """Get transaction receipt"""
        params = {
            'module': 'proxy',
            'action': 'eth_getTransactionReceipt',
            'txhash': tx_hash
        }
        
        return self._make_request(params)
    
    def get_normal_transactions(self, address: str, startblock: int = 0, endblock: int = 99999999) -> list:
        """Get normal transactions for an address"""
        params = {
            'module': 'account',
            'action': 'txlist',
            'address': address,
            'startblock': startblock,
            'endblock': endblock,
            'sort': 'desc'
        }
        
        result = self._make_request(params)
        
        if result.get('status') == '1':
            return result.get('result', [])
        
        return []

# Singleton instances
bsc_api = BSCScanAPI("BSC")
opbnb_api = BSCScanAPI("opBNB")
