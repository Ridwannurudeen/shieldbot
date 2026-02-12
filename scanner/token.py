"""
Token Safety Check Module
Detects honeypots, hidden taxes, and other token scams
"""

import json
from .bscscan_api import bsc_api, opbnb_api
from .scam_database import check_known_scam
from ..utils.web3_client import bsc_client, opbnb_client

# Standard ERC20 ABI for basic checks
ERC20_ABI = json.loads('[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"type":"function"},{"constant":true,"inputs":[{"name":"account","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"}]')

async def analyze_token(token_address: str, chain: str = "BSC") -> dict:
    """
    Analyze a token for honeypot and safety issues
    
    Args:
        token_address: Token contract address (0x...)
        chain: Blockchain (BSC or opBNB)
    
    Returns:
        dict: Token safety analysis with risk score and findings
    """
    findings = []
    
    # Select appropriate clients
    api = bsc_api if chain == "BSC" else opbnb_api
    w3_client = bsc_client if chain == "BSC" else opbnb_client
    
    # Check if address is a contract
    if not w3_client.is_contract(token_address):
        return {
            "status": "error",
            "findings": [{
                "severity": "critical",
                "message": "❌ Not a contract address - this is an EOA (wallet)"
            }]
        }
    
    # Check contract verification
    is_verified, contract_name, source_code = api.is_contract_verified(token_address)
    
    if not is_verified:
        findings.append({
            "severity": "critical",
            "message": "🚨 Contract is NOT verified - HIGH RISK!"
        })
    else:
        findings.append({
            "severity": "info",
            "message": f"✅ Contract verified: {contract_name}"
        })
    
    # Check if it's a known scam
    is_scam, scam_data = check_known_scam(token_address)
    if is_scam:
        findings.append({
            "severity": "critical",
            "message": f"🚨 KNOWN SCAM TOKEN: {scam_data.get('type', 'unknown')}"
        })
    
    # Get token info using Web3
    try:
        token_contract = w3_client.w3.eth.contract(
            address=w3_client.w3.to_checksum_address(token_address),
            abi=ERC20_ABI
        )
        
        # Get basic token info
        try:
            token_name = token_contract.functions.name().call()
            findings.append({
                "severity": "info",
                "message": f"📛 Token Name: {token_name}"
            })
        except:
            findings.append({
                "severity": "medium",
                "message": "⚠️ Cannot read token name - might not be standard ERC20"
            })
        
        try:
            token_symbol = token_contract.functions.symbol().call()
            findings.append({
                "severity": "info",
                "message": f"💱 Symbol: {token_symbol}"
            })
        except:
            pass
        
        try:
            total_supply = token_contract.functions.totalSupply().call()
            supply_formatted = total_supply / 1e18  # Assuming 18 decimals
            findings.append({
                "severity": "info",
                "message": f"📊 Total Supply: {supply_formatted:,.0f}"
            })
            
            # Check for suspicious supply
            if supply_formatted > 1_000_000_000_000:  # 1 trillion+
                findings.append({
                    "severity": "medium",
                    "message": "⚠️ Extremely high total supply - potential red flag"
                })
        except:
            findings.append({
                "severity": "medium",
                "message": "⚠️ Cannot read total supply"
            })
        
    except Exception as e:
        findings.append({
            "severity": "medium",
            "message": f"⚠️ Error reading token info: {str(e)}"
        })
    
    # Honeypot detection (basic checks from source code if verified)
    if is_verified and source_code:
        # Check for common honeypot patterns
        honeypot_patterns = [
            "onlyOwner",
            "blacklist",
            "addBlacklist",
            "removeBlacklist",
            "_isBlacklisted",
            "excludeFrom",
            "includeIn"
        ]
        
        detected_patterns = []
        for pattern in honeypot_patterns:
            if pattern.lower() in source_code.lower():
                detected_patterns.append(pattern)
        
        if detected_patterns:
            findings.append({
                "severity": "high",
                "message": f"⚠️ Suspicious functions detected: {', '.join(detected_patterns[:3])}"
            })
            findings.append({
                "severity": "medium",
                "message": "⚠️ Owner can potentially restrict selling - CAUTION!"
            })
        
        # Check for excessive owner control
        if "renounceOwnership" not in source_code:
            findings.append({
                "severity": "medium",
                "message": "⚠️ No ownership renounce function - owner has permanent control"
            })
    
    # Tax detection (if we can analyze the source)
    if is_verified and source_code:
        tax_keywords = ["tax", "fee", "burn", "liquidity"]
        has_taxes = any(keyword in source_code.lower() for keyword in tax_keywords)
        
        if has_taxes:
            findings.append({
                "severity": "info",
                "message": "💰 Token appears to have taxes/fees - Check tokenomics!"
            })
    
    # Get contract creation info
    try:
        txs = api.get_normal_transactions(token_address, startblock=0, endblock=99999999)
        if txs and len(txs) > 0:
            # Check contract age
            first_tx_timestamp = int(txs[-1].get('timeStamp', 0))
            import time
            age_days = (time.time() - first_tx_timestamp) / 86400
            
            if age_days < 1:
                findings.append({
                    "severity": "high",
                    "message": f"🚨 VERY NEW TOKEN (< 1 day old) - EXTREME RISK!"
                })
            elif age_days < 7:
                findings.append({
                    "severity": "medium",
                    "message": f"⚠️ New token ({age_days:.1f} days old) - Be cautious!"
                })
            else:
                findings.append({
                    "severity": "info",
                    "message": f"✅ Token age: {age_days:.0f} days"
                })
    except:
        pass
    
    return {
        "status": "analyzed",
        "token_address": token_address,
        "chain": chain,
        "is_verified": is_verified,
        "contract_name": contract_name,
        "findings": findings
    }
