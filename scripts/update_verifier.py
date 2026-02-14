#!/usr/bin/env python3
"""
Script to update the verifier address in ShieldBotVerifier contract.
This allows the bot wallet to record scans on-chain.

Usage:
    python scripts/update_verifier.py
"""
import os
import sys
from web3 import Web3
from eth_account import Account

# Contract details
CONTRACT_ADDRESS = "0x67e26f346bE9BA54F1F29D30c0C04f45Cb20EC16"
BOT_WALLET = "0xc62A8ae13a2Ea84F443dA5681501e7aaC43dC6F5"

# Contract ABI (only the functions we need)
ABI = [
    {
        "inputs": [{"internalType": "address", "name": "_newVerifier", "type": "address"}],
        "name": "updateVerifier",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "verifier",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    }
]

def main():
    print("🛡️ ShieldBot - Update Verifier Script\n")

    # Load owner private key from environment
    owner_pk = os.getenv('OWNER_PRIVATE_KEY')
    if not owner_pk:
        print("❌ Error: OWNER_PRIVATE_KEY environment variable not set")
        print("\nUsage:")
        print("  export OWNER_PRIVATE_KEY='your_owner_private_key'")
        print("  python scripts/update_verifier.py")
        sys.exit(1)

    # Connect to BSC
    print("📡 Connecting to BSC mainnet...")
    w3 = Web3(Web3.HTTPProvider('https://bsc-dataseed1.binance.org'))

    if not w3.is_connected():
        print("❌ Failed to connect to BSC")
        sys.exit(1)

    print("✅ Connected to BSC\n")

    # Load owner account
    owner_account = Account.from_key(owner_pk)
    owner_address = owner_account.address
    print(f"👤 Owner wallet: {owner_address}")

    # Load contract
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

    # Check current state
    print(f"\n📋 Current contract state:")
    contract_owner = contract.functions.owner().call()
    current_verifier = contract.functions.verifier().call()
    print(f"   Contract owner: {contract_owner}")
    print(f"   Current verifier: {current_verifier}")
    print(f"   Bot wallet: {BOT_WALLET}")

    # Verify caller is owner
    if owner_address.lower() != contract_owner.lower():
        print(f"\n❌ Error: Connected wallet ({owner_address}) is not the contract owner ({contract_owner})")
        sys.exit(1)

    # Check if already updated
    if current_verifier.lower() == BOT_WALLET.lower():
        print(f"\n✅ Verifier is already set to bot wallet!")
        print("No update needed.")
        sys.exit(0)

    # Prepare transaction
    print(f"\n🔄 Preparing updateVerifier transaction...")
    print(f"   New verifier: {BOT_WALLET}")

    # Build transaction
    nonce = w3.eth.get_transaction_count(owner_address)

    tx = contract.functions.updateVerifier(BOT_WALLET).build_transaction({
        'from': owner_address,
        'nonce': nonce,
        'gas': 200000,  # Conservative gas limit to avoid "out of gas"
        'gasPrice': w3.eth.gas_price,
        'chainId': 56,  # BSC mainnet
    })

    print(f"   Gas price: {w3.from_wei(tx['gasPrice'], 'gwei')} Gwei")
    print(f"   Estimated cost: {w3.from_wei(tx['gas'] * tx['gasPrice'], 'ether')} BNB")

    # Sign transaction
    print("\n🔐 Signing transaction...")
    signed_tx = owner_account.sign_transaction(tx)

    # Send transaction
    print("📤 Sending transaction...")
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"   TX hash: {tx_hash.hex()}")
    print(f"   BSCScan: https://bscscan.com/tx/{tx_hash.hex()}")

    # Wait for receipt
    print("\n⏳ Waiting for confirmation...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    if receipt['status'] == 1:
        print("\n✅ Transaction successful!")

        # Verify update
        new_verifier = contract.functions.verifier().call()
        print(f"\n📋 Updated state:")
        print(f"   New verifier: {new_verifier}")

        if new_verifier.lower() == BOT_WALLET.lower():
            print("\n🎉 Verifier successfully updated!")
            print("Bot can now record scans on-chain.")
        else:
            print("\n⚠️ Warning: Verifier address doesn't match expected value")
    else:
        print("\n❌ Transaction failed!")
        print(f"Receipt: {receipt}")
        sys.exit(1)

if __name__ == '__main__':
    main()
