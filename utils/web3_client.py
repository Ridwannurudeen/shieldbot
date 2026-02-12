"""
Web3 Client for BSC and opBNB
Handles blockchain connections and queries
"""

import os
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

class Web3Client:
    """Web3 client for interacting with BSC/opBNB"""
    
    def __init__(self, chain: str = "BSC"):
        """
        Initialize Web3 client
        
        Args:
            chain: "BSC" or "opBNB"
        """
        self.chain = chain
        rpc_url = os.getenv('BSC_RPC_URL') if chain == "BSC" else os.getenv('OPBNB_RPC_URL')
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        
    def is_connected(self) -> bool:
        """Check if connected to blockchain"""
        return self.w3.is_connected()
    
    def get_transaction(self, tx_hash: str) -> dict:
        """Get transaction details"""
        return self.w3.eth.get_transaction(tx_hash)
    
    def get_contract_code(self, address: str) -> str:
        """Get contract bytecode"""
        return self.w3.eth.get_code(address).hex()
    
    def is_contract(self, address: str) -> bool:
        """Check if address is a contract"""
        code = self.get_contract_code(address)
        return code != '0x' and code != '0x0'

# Singleton instances
bsc_client = Web3Client("BSC")
opbnb_client = Web3Client("opBNB")
