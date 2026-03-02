#!/usr/bin/env python3
"""
Deploy ShieldBotVerifier.sol to BSC Mainnet.

Usage:
    cd shieldbot/
    python scripts/deploy_contract.py

Reads BOT_WALLET_PRIVATE_KEY from .env -- that wallet becomes owner + initial verifier.
After deploy, updates bsc.address with the new contract address.
"""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account
import solcx

ROOT = Path(__file__).parent.parent
load_dotenv(ROOT / ".env")

BSC_RPC      = os.getenv("BSC_RPC_URL", "https://bsc-dataseed1.binance.org/")
PRIVATE_KEY  = os.getenv("BOT_WALLET_PRIVATE_KEY", "")
CONTRACT_SOL = ROOT / "contracts" / "ShieldBotVerifier.sol"
BSC_ADDRESS  = ROOT / "bsc.address"


def compile_contract() -> tuple:
    print("[*] Installing solc 0.8.24...")
    solcx.install_solc("0.8.24", show_progress=False)
    solcx.set_solc_version("0.8.24")

    print("[*] Compiling ShieldBotVerifier.sol...")
    source = CONTRACT_SOL.read_text()
    compiled = solcx.compile_source(
        source,
        output_values=["abi", "bin"],
        optimize=True,
        optimize_runs=200,
    )

    key = "<stdin>:ShieldBotVerifier"
    contract_data = compiled[key]
    bytecode = contract_data["bin"]
    abi = contract_data["abi"]
    print(f"    OK -- bytecode {len(bytecode)//2} bytes")
    return bytecode, abi


def deploy(w3, account, bytecode, abi):
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    nonce     = w3.eth.get_transaction_count(account.address)
    gas_price = w3.eth.gas_price

    deploy_tx = contract.constructor().build_transaction({
        "from":     account.address,
        "nonce":    nonce,
        "gas":      1_500_000,
        "gasPrice": gas_price,
        "chainId":  56,
    })

    cost_bnb = w3.from_wei(deploy_tx["gas"] * gas_price, "ether")
    print(f"\n[*] Deployment details")
    print(f"    Deployer : {account.address}")
    print(f"    Gas limit: {deploy_tx['gas']:,}")
    print(f"    Gas price: {w3.from_wei(gas_price, 'gwei'):.2f} Gwei")
    print(f"    Est. cost: {cost_bnb:.6f} BNB")

    balance = w3.from_wei(w3.eth.get_balance(account.address), "ether")
    print(f"    Balance  : {balance:.6f} BNB")

    if balance < cost_bnb:
        print(f"\n[!] Insufficient BNB -- need {cost_bnb:.6f}, have {balance:.6f}")
        sys.exit(1)

    print("\n[*] Deploying...")
    signed  = account.sign_transaction(deploy_tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"    TX hash  : {tx_hash.hex()}")
    print(f"    BscScan  : https://bscscan.com/tx/{tx_hash.hex()}")
    print("    Waiting for confirmation...")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt["status"] != 1:
        print("[!] Transaction reverted")
        sys.exit(1)

    address = receipt["contractAddress"]
    print(f"\n[+] Contract deployed at: {address}")
    print(f"    BscScan  : https://bscscan.com/address/{address}#code")
    return address, tx_hash.hex(), abi


def update_bsc_address(new_address, tx_hash):
    """Update bsc.address JSON with new contract address."""
    data = json.loads(BSC_ADDRESS.read_text())
    old_address = None

    for contract in data.get("contracts", []):
        if contract.get("name") == "ShieldBotVerifier":
            old_address = contract["address"]
            contract["address"]          = new_address
            contract["explorerLink"]     = f"https://bscscan.com/address/{new_address}#code"
            contract["deploymentTxHash"] = tx_hash
            contract["deploymentTxLink"] = f"https://bscscan.com/tx/{tx_hash}"
            contract["description"]      = (
                "On-chain scan recording contract. Status: Deployed on BSC Mainnet. "
                "Source verification pending on BscScan."
            )
            break

    BSC_ADDRESS.write_text(json.dumps(data, indent=2))
    print(f"\n[*] bsc.address updated")
    print(f"    Old: {old_address}")
    print(f"    New: {new_address}")
    return old_address


def save_abi(abi, address):
    """Save ABI to contracts/ for future interaction scripts."""
    abi_path = ROOT / "contracts" / "ShieldBotVerifier.abi.json"
    abi_path.write_text(json.dumps(abi, indent=2))
    print(f"    ABI saved: contracts/ShieldBotVerifier.abi.json")


def main():
    print("ShieldBot -- Contract Redeployment\n")

    if not PRIVATE_KEY:
        print("[!] BOT_WALLET_PRIVATE_KEY not set in .env")
        sys.exit(1)

    print(f"[*] Connecting to BSC via {BSC_RPC}...")
    w3 = Web3(Web3.HTTPProvider(BSC_RPC))
    if not w3.is_connected():
        print("[!] Could not connect to BSC")
        sys.exit(1)
    print(f"    OK -- block #{w3.eth.block_number:,}\n")

    account = Account.from_key(PRIVATE_KEY)

    bytecode, abi = compile_contract()

    new_address, tx_hash, abi = deploy(w3, account, bytecode, abi)

    old_address = update_bsc_address(new_address, tx_hash)
    save_abi(abi, new_address)

    print(f"""
------------------------------------------------------------
DEPLOYMENT COMPLETE

  New contract : {new_address}
  Old contract : {old_address}
  TX hash      : {tx_hash}
  BscScan      : https://bscscan.com/address/{new_address}

Next steps:
  1. Verify source on BscScan
       Compiler : 0.8.24
       Optimized: Yes, 200 runs
       Code     : contracts/ShieldBotVerifier.sol
  2. Deployer wallet is already owner + verifier:
       {account.address}
  3. If bot wallet differs from deployer, run:
       python scripts/update_verifier.py
------------------------------------------------------------
""")


if __name__ == "__main__":
    main()
