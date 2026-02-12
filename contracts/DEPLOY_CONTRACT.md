# Deploy ShieldBot Verification Contract

## Purpose
This contract provides **onchain proof** that ShieldBot is actively scanning and recording security checks on BNB Chain.

**Optional for hackathon:** Core functionality works off-chain. This is for bonus points.

---

## Quick Deploy (Remix - 5 minutes)

### Step 1: Open Remix
1. Go to https://remix.ethereum.org
2. Create new file: `ShieldBotVerifier.sol`
3. Copy contents from `contracts/ShieldBotVerifier.sol`

### Step 2: Compile
1. Click "Solidity Compiler" (left sidebar)
2. Select compiler version: `0.8.20+`
3. Click "Compile ShieldBotVerifier.sol"
4. Should show green checkmark ✅

### Step 3: Connect Wallet
1. Click "Deploy & Run Transactions" (left sidebar)
2. Environment: Select "Injected Provider - MetaMask"
3. MetaMask will popup → Select BSC network
4. Ensure you have ~0.01 BNB for gas (~$3)

### Step 4: Deploy
1. Contract: Select "ShieldBotVerifier"
2. Click "Deploy" (orange button)
3. MetaMask confirms → Gas ~0.005 BNB
4. Wait for confirmation (~3 seconds)
5. Copy deployed contract address (e.g., `0x1234...`)

### Step 5: Verify on BscScan
1. Go to https://bscscan.com/address/YOUR_CONTRACT_ADDRESS
2. Click "Contract" tab
3. Click "Verify and Publish"
4. Fill in:
   - Compiler: `v0.8.20+commit.xxx`
   - Optimization: No
   - Paste contract code
5. Submit → Contract verified ✅

---

## Usage

### Record a Scan (From Bot)

```javascript
// In bot.py, add optional onchain recording:

const Web3 = require('web3');
const web3 = new Web3('https://bsc-dataseed1.binance.org/');

const CONTRACT_ADDRESS = '0xYourContractAddress';
const ABI = [...]; // Contract ABI

const contract = new web3.eth.Contract(ABI, CONTRACT_ADDRESS);

// After scan completes
async function recordScanOnchain(address, riskLevel, scanType) {
    const tx = await contract.methods.recordScan(
        address,
        riskLevel,  // 0=LOW, 1=MEDIUM, 2=HIGH, 3=SAFE, 4=WARNING, 5=DANGER
        scanType    // "contract" or "token"
    ).send({ from: botAddress });
    
    console.log('Recorded onchain:', tx.transactionHash);
}
```

### Query Scan Results (Public)

```javascript
// Anyone can check if address has been scanned
const hasBeenScanned = await contract.methods.hasBeenScanned(address).call();

// Get latest scan details
const scan = await contract.methods.getLatestScan(address).call();
console.log('Risk Level:', scan.riskLevel);
console.log('Scan Type:', scan.scanType);
console.log('Timestamp:', scan.timestamp);

// Get total scans
const totalScans = await contract.methods.totalScans().call();
console.log('Total scans recorded:', totalScans);
```

---

## Contract Functions

### Public Functions (Anyone)

**`hasBeenScanned(address)`** → Returns bool
- Check if address has been scanned by ShieldBot

**`getLatestScan(address)`** → Returns ScanRecord
- Get most recent scan details for address

**`getStats()`** → Returns (totalScans, uniqueAddresses)
- Get global scan statistics

**`getRiskLevelName(uint8)`** → Returns string
- Convert risk level number to human-readable name

### Authorized Functions (Owner/Verifier Only)

**`recordScan(address, riskLevel, scanType)`**
- Record a single scan onchain
- Only callable by authorized verifier (bot address)

**`recordBatchScans(addresses[], riskLevels[], scanTypes[])`**
- Record multiple scans in one transaction (gas optimization)

**`updateVerifier(address)`** (Owner only)
- Update authorized bot address

---

## Risk Levels

```
Contract Scans (Module 1):
  0 = LOW       → Safe, verified contract
  1 = MEDIUM    → Some warnings, proceed with caution
  2 = HIGH      → Multiple red flags, avoid

Token Scans (Module 2):
  3 = SAFE      → Token is safe to trade
  4 = WARNING   → Some concerns (high taxes, etc.)
  5 = DANGER    → Honeypot or scam, do not buy
```

---

## Gas Costs (BSC)

- **Deploy:** ~0.005 BNB (~$2)
- **Record single scan:** ~0.0003 BNB (~$0.15)
- **Record batch (10 scans):** ~0.001 BNB (~$0.50)
- **Query (read):** FREE (no gas)

---

## For Hackathon Submission

### What to Include

1. **Contract Address:**
   ```
   BSC Mainnet: 0xYourDeployedAddress
   ```

2. **Deployment Transaction:**
   ```
   https://bscscan.com/tx/0xYourDeploymentTxHash
   ```

3. **Verified Contract:**
   ```
   https://bscscan.com/address/0xYourContractAddress#code
   ```

4. **Example Scan Transaction:**
   ```
   (Record a test scan after deployment)
   https://bscscan.com/tx/0xYourScanTxHash
   ```

### Submission Text

```markdown
## Onchain Proof

ShieldBot integrates with BNB Chain through:

**Verification Contract:** 0xYourAddress
- **Deployed:** [BscScan Link]
- **Verified Source:** [Code Link]
- **Example Scan:** [Tx Link]

The contract records security scan results onchain for:
✅ Transparency - Anyone can verify scans
✅ Immutability - Scan history cannot be altered
✅ Community Trust - Provable security checking

**Note:** Core functionality runs off-chain (zero gas for users).
Onchain recording is optional for transparency.
```

---

## Alternative: Deploy on Testnet

If you prefer testing first:

### BSC Testnet
1. Get testnet BNB: https://testnet.bnbchain.org/faucet-smart
2. MetaMask → Add BSC Testnet:
   - RPC: https://data-seed-prebsc-1-s1.binance.org:8545/
   - Chain ID: 97
   - Currency: tBNB
3. Deploy same contract on testnet
4. Test recording scans
5. Once working, deploy to mainnet

---

## Integration with Bot (Optional)

If you want to actually use this contract:

### Add to bot.py

```python
# After successful scan
if RECORD_ONCHAIN:
    try:
        record_scan_onchain(
            address=scan_result['address'],
            risk_level=scan_result['risk_level_code'],
            scan_type=scan_result['type']
        )
    except Exception as e:
        logger.error(f"Onchain recording failed: {e}")
        # Continue anyway - off-chain analysis is primary
```

### Environment Variables

```bash
# Add to .env
VERIFIER_CONTRACT_ADDRESS=0xYourContractAddress
VERIFIER_PRIVATE_KEY=your_private_key
RECORD_ONCHAIN=false  # Set to true to enable
```

---

## Security Notes

1. **Verifier Authorization:** Only authorized bot address can record scans
2. **Owner Control:** Owner can update verifier address
3. **No Funds:** Contract doesn't hold any tokens/BNB
4. **Read-Only Public:** Anyone can query, only verifier can write
5. **Gas Optimization:** Batch recording for multiple scans

---

## Summary

**Minimum for Hackathon:**
- Deploy contract ✅
- Verify on BscScan ✅
- Record 1-2 test scans ✅
- Include links in submission ✅

**Time:** ~10 minutes  
**Cost:** ~$3 in BNB  
**Benefit:** Onchain proof + bonus points  

**Not required for core functionality to work!**

---

Questions? Check:
- Remix Docs: https://remix-ide.readthedocs.io/
- BSC Docs: https://docs.bnbchain.org/
- BscScan: https://bscscan.com/
