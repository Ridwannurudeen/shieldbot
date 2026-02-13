"""
Known Scam Address Database
Maintains list of known malicious addresses, phishing sites, etc.
"""

# Known scam addresses (will expand this list)
KNOWN_SCAMS = {
    # Phishing addresses
    "0x00000000000000000000000000000000000000": {"type": "null_address", "severity": "info"},
    
    # Add more known scam addresses here
    # Format: address (lowercase): {type, severity, description}
}

# Common scam patterns in contract names
SCAM_KEYWORDS = [
    "airdrop",
    "claim",
    "voucher",
    "giveaway",
    "distribution", 
    "reward",
    "bonus"
]

# Risky function signatures (common in honeypots/scams)
RISKY_FUNCTIONS = [
    "0x3ccfd60b",  # withdraw() - common in scams
    "0xe2f4daff",  # blacklist related
    "0x8da5cb5b",  # owner() check
]

def check_known_scam(address: str) -> tuple:
    """
    Check if address is a known scam
    
    Args:
        address: Ethereum address (0x...)
    
    Returns:
        tuple: (is_scam: bool, scam_data: dict)
    """
    address_lower = address.lower()
    
    if address_lower in KNOWN_SCAMS:
        return True, KNOWN_SCAMS[address_lower]
    
    return False, {}

def check_contract_name_suspicious(contract_name: str) -> bool:
    """Check if contract name contains suspicious keywords"""
    if not contract_name:
        return False
    
    contract_lower = contract_name.lower()
    return any(keyword in contract_lower for keyword in SCAM_KEYWORDS)

def analyze_function_signatures(abi: str) -> list:
    """
    Analyze contract ABI for risky function signatures
    
    Returns:
        list: List of risky functions found
    """
    risky_found = []
    
    if not abi:
        return risky_found
    
    # Simple check for now - can be enhanced
    for risky_sig in RISKY_FUNCTIONS:
        if risky_sig in abi:
            risky_found.append(risky_sig)
    
    return risky_found

# Growing database - add more scam addresses as we discover them
def add_scam_address(address: str, scam_type: str, severity: str, description: str = ""):
    """Add a new scam address to the database"""
    KNOWN_SCAMS[address.lower()] = {
        "type": scam_type,
        "severity": severity,
        "description": description
    }
