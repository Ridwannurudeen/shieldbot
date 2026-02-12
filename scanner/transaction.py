"""
Transaction Security Analysis Module
Checks transactions for security risks before signing
"""

from .bscscan_api import bsc_api, opbnb_api
from .scam_database import check_known_scam, check_contract_name_suspicious
from ..utils.web3_client import bsc_client, opbnb_client

async def analyze_transaction(tx_hash: str, chain: str = "BSC") -> dict:
    """
    Analyze a transaction for security risks
    
    Args:
        tx_hash: Transaction hash (0x...)
        chain: Blockchain (BSC or opBNB)
    
    Returns:
        dict: Analysis results with risk score and findings
    """
    findings = []
    
    # Select appropriate API client
    api = bsc_api if chain == "BSC" else opbnb_api
    w3_client = bsc_client if chain == "BSC" else opbnb_client
    
    # Get transaction details
    try:
        tx = w3_client.get_transaction(tx_hash)
    except Exception as e:
        return {
            "status": "error",
            "risk_score": 0,
            "findings": [{"severity": "info", "message": f"Could not fetch transaction: {str(e)}"}],
            "recommendation": "Unable to analyze transaction"
        }
    
    # Extract key info
    to_address = tx.get('to', '')
    from_address = tx.get('from', '')
    value = tx.get('value', 0)
    
    if not to_address:
        findings.append({
            "severity": "high",
            "message": "Contract creation transaction - requires manual review"
        })
        return {
            "status": "analyzed",
            "risk_score": 60,
            "findings": findings,
            "recommendation": "Contract creation detected. Verify source code carefully."
        }
    
    # Check if TO address is a contract
    is_contract = w3_client.is_contract(to_address)
    
    if not is_contract:
        findings.append({
            "severity": "info",
            "message": "Interacting with EOA (wallet), not a contract"
        })
    else:
        # Check contract verification
        is_verified, contract_name, source_code = api.is_contract_verified(to_address)
        
        if not is_verified:
            findings.append({
                "severity": "high",
                "message": "⚠️ Contract is NOT verified on BSCScan"
            })
        else:
            findings.append({
                "severity": "info",
                "message": f"✅ Contract verified: {contract_name}"
            })
            
            # Check for suspicious contract name
            if check_contract_name_suspicious(contract_name):
                findings.append({
                    "severity": "medium",
                    "message": f"⚠️ Suspicious contract name: {contract_name}"
                })
    
    # Check if TO address is a known scam
    is_scam, scam_data = check_known_scam(to_address)
    if is_scam:
        findings.append({
            "severity": "critical",
            "message": f"🚨 KNOWN SCAM ADDRESS: {scam_data.get('type', 'unknown')}"
        })
    
    # Check if FROM address is a known scam (compromised wallets)
    is_from_scam, from_scam_data = check_known_scam(from_address)
    if is_from_scam:
        findings.append({
            "severity": "critical",
            "message": f"🚨 Your wallet appears in scam database: {from_scam_data.get('type', 'unknown')}"
        })
    
    # Check transaction value
    if value > 0:
        value_bnb = value / 1e18
        findings.append({
            "severity": "info",
            "message": f"💰 Sending {value_bnb:.4f} BNB"
        })
        
        if value_bnb > 1:
            findings.append({
                "severity": "medium",
                "message": f"⚠️ Large transfer: {value_bnb:.4f} BNB - Double check recipient!"
            })
    
    return {
        "status": "analyzed",
        "tx_hash": tx_hash,
        "to_address": to_address,
        "from_address": from_address,
        "chain": chain,
        "findings": findings
    }
