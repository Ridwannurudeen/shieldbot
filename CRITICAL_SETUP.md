# 🚨 CRITICAL SETUP - Fix Dealbreakers

## 1. Get Anthropic API Key (REQUIRED - AI Integration)

### Why This is Critical
The hackathon is **AI-first**. Your bot now uses **Claude 3.5 Sonnet** for AI-powered contract analysis, but it needs an API key to work.

### How to Get It (5 minutes)

1. **Go to** https://console.anthropic.com/
2. **Sign up** (free credits available)
3. **Get API key:**
   - Click "API Keys" in left sidebar
   - Click "Create Key"
   - Copy the key (starts with `sk-ant-api...`)

4. **Add to your VPS:**
```bash
# SSH into your VPS
ssh root@your_vps_ip

# Edit .env file
cd /opt/shieldbot
nano .env

# Add this line:
ANTHROPIC_API_KEY=sk-ant-api-your-key-here

# Save and exit (Ctrl+X, Y, Enter)

# Restart bot
systemctl restart shieldbot

# Verify AI is working
journalctl -u shieldbot -f
# You should see: "AI analysis added to scan result"
```

### Test AI Integration

Send a test scan in Telegram - you should now see:
```
🤖 AI Analysis:
MEDIUM risk. This contract is unverified and only 3 days old...
```

---

## 2. Deploy Contract to BSC (REQUIRED - Onchain Proof)

### Why This is Critical
**Hackathon rule:** "Onchain proof required: Contract address or transaction hash on BSC or opBNB."

Your project is currently off-chain only. **Without a deployed contract, you're disqualified.**

### Deploy Now (10 minutes)

#### Option 1: Quick Deploy via Remix (Easiest)

1. **Go to** https://remix.ethereum.org

2. **Create file:** `ShieldBotVerifier.sol`

3. **Copy contract code:** From `contracts/ShieldBotVerifier.sol`

4. **Compile:**
   - Click "Solidity Compiler" (left sidebar)
   - Select version `0.8.20+`
   - Click "Compile"

5. **Connect wallet:**
   - Click "Deploy & Run" (left sidebar)
   - Environment: "Injected Provider - MetaMask"
   - MetaMask prompts → Select BSC Mainnet
   - **Need 0.01 BNB (~$6) for gas**

6. **Deploy:**
   - Contract: "ShieldBotVerifier"
   - Click orange "Deploy" button
   - Confirm in MetaMask
   - **COPY THE CONTRACT ADDRESS** (e.g., `0x1234...`)

7. **Verify on BscScan:**
   - Go to https://bscscan.com/address/YOUR_CONTRACT_ADDRESS
   - Click "Contract" tab → "Verify and Publish"
   - Compiler: v0.8.20
   - Optimization: No
   - Paste contract code
   - Submit

8. **Record a test scan:**
   - In Remix, call `recordScan()` with:
     - `_scannedAddress`: `0x10ED43C718714eb63d5aA57B78B54704E256024E` (PancakeSwap)
     - `_riskLevel`: `0` (LOW)
     - `_scanType`: "contract"
   - Confirm transaction
   - **COPY THE TRANSACTION HASH**

#### Option 2: Deploy via Hardhat (If you prefer CLI)

```bash
# On your local machine (not VPS)
git clone https://github.com/Ridwannurudeen/shieldbot.git
cd shieldbot/contracts

# Install Hardhat
npm init -y
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox

# Create deploy script
cat > scripts/deploy.js << 'EOF'
const hre = require("hardhat");

async function main() {
  const ShieldBotVerifier = await hre.ethers.getContractFactory("ShieldBotVerifier");
  const verifier = await ShieldBotVerifier.deploy();
  await verifier.deployed();
  
  console.log("ShieldBotVerifier deployed to:", verifier.address);
  
  // Record a test scan
  const tx = await verifier.recordScan(
    "0x10ED43C718714eb63d5aA57B78B54704E256024E",
    0,
    "contract"
  );
  await tx.wait();
  console.log("Test scan recorded:", tx.hash);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
EOF

# Configure Hardhat
cat > hardhat.config.js << 'EOF'
require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: "0.8.20",
  networks: {
    bsc: {
      url: "https://bsc-dataseed1.binance.org/",
      accounts: [process.env.PRIVATE_KEY]
    }
  }
};
EOF

# Deploy
PRIVATE_KEY=your_wallet_private_key npx hardhat run scripts/deploy.js --network bsc
```

### After Deployment

**Update these files immediately:**

**README.md:**
```markdown
## 🔗 Onchain Proof

**Contract Address:** 0xYourContractAddress  
**Deployment Tx:** https://bscscan.com/tx/0xYourDeploymentTx  
**Verified Contract:** https://bscscan.com/address/0xYourContractAddress#code  
**Example Scan Tx:** https://bscscan.com/tx/0xYourScanTx  
```

**SUBMISSION.md:**
```markdown
## Onchain Integration

ShieldBot records security scan results on BNB Chain for transparency:

- **Verification Contract:** 0xYourContractAddress
- **Network:** BSC Mainnet (Chain ID: 56)
- **Deployed:** https://bscscan.com/tx/0xYourDeploymentTx
- **Verified Source:** https://bscscan.com/address/0xYourContractAddress#code
- **Example Scan:** https://bscscan.com/tx/0xYourScanTx

The contract provides:
✅ Immutable scan history
✅ Public verification of security checks
✅ Community trust through transparency

Total scans recorded: [Check contract]
```

---

## 3. Update Bot Username (REQUIRED - Live Demo)

Your README says "[Your bot username]" everywhere. Judges need the real link!

### Get Bot Username

1. Open Telegram
2. Search for @BotFather
3. Send `/mybots`
4. Select your bot
5. Click "API Token" → Copy username (e.g., `@shieldbot_bnb_bot`)

### Update Files

**Find and replace in these files:**
- `README.md`
- `SUBMISSION.md`
- `QUICK_START.md`

Replace:
```
[Your bot username]
@YourBotUsername
```

With:
```
@shieldbot_bnb_bot  (or whatever your real username is)
```

---

## 4. Record Demo Video (REQUIRED - 10 minutes)

### Script

**Opening (10 seconds):**
"Hi, I'm demonstrating ShieldBot - an AI-powered security bot for BNB Chain"

**Demo (2 minutes):**
1. Open Telegram → Show bot
2. `/start` → Show welcome with features
3. `/scan 0x10ED43C718714eb63d5aA57B78B54704E256024E`
   - Show: Verified, LOW risk, **🤖 AI Analysis**
4. `/token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`
   - Show: SAFE, not honeypot, **🤖 AI Analysis**
5. Send address without command (auto-detection)
6. Click BscScan button → Opens in browser

**Closing (20 seconds):**
"ShieldBot combines rule-based scanning with AI-powered analysis from Claude to protect users from scams. All code is open source at github.com/Ridwannurudeen/shieldbot"

### Recording

**Tools:**
- **Phone:** Built-in screen recorder
- **Mac:** QuickTime → File → New Screen Recording
- **Windows:** Xbox Game Bar (Win+G)
- **Linux:** SimpleScreenRecorder

**Upload:**
- YouTube (unlisted)
- Loom (free, easy)
- Google Drive (public link)

**Add link to:**
- README.md (top of page)
- SUBMISSION.md

---

## 5. Quick Verification Checklist

Before submitting, verify:

### AI Integration ✅
```bash
# On VPS
grep "ANTHROPIC_API_KEY" /opt/shieldbot/.env
# Should show your key

# In bot logs
journalctl -u shieldbot -n 50 | grep "AI analysis"
# Should show AI analysis being generated
```

### Onchain Proof ✅
- [ ] Contract deployed on BSC Mainnet
- [ ] Contract verified on BscScan
- [ ] At least 2 transactions on contract
- [ ] Contract address in README.md
- [ ] Deployment tx hash in SUBMISSION.md

### Live Demo ✅
- [ ] Bot running 24/7 on VPS
- [ ] Bot username updated in all docs
- [ ] Demo video recorded
- [ ] Demo video uploaded and linked

### Documentation ✅
- [ ] AI_BUILD_LOG.md complete
- [ ] README.md has onchain proof section
- [ ] SUBMISSION.md has all links
- [ ] All placeholder text removed

---

## 6. Cost Summary

**Total cost to fix dealbreakers:**

| Item | Cost |
|------|------|
| Anthropic API (Claude) | Free ($5 credit) or $20/month |
| BSC Gas (deploy + 2 txs) | ~0.01 BNB (~$6) |
| Demo video | Free |
| **TOTAL** | **~$6** |

**Without this:** Disqualified ❌  
**With this:** Competitive entry ✅

---

## 7. Priority Order

**Do in this order:**

1. ✅ **AI Integration** (30 min)
   - Get Anthropic API key
   - Add to .env
   - Restart bot
   - Test AI responses

2. ✅ **Deploy Contract** (15 min)
   - Deploy via Remix
   - Verify on BscScan
   - Record 2 test scans
   - Update docs with addresses

3. ✅ **Live Demo** (15 min)
   - Record video
   - Upload to YouTube/Loom
   - Add link to docs

4. ✅ **Final Check** (5 min)
   - Bot running? ✓
   - AI working? ✓
   - Contract deployed? ✓
   - Demo live? ✓

**Total time:** ~1 hour  
**Deadline:** Feb 19, 2026, 3:00 PM UTC

---

## 🆘 Help

If you get stuck:
- **AI issues:** Check `.env` has `ANTHROPIC_API_KEY`
- **Deploy issues:** Make sure you have 0.01 BNB in wallet
- **Bot issues:** Check `systemctl status shieldbot`

**Time is critical - do this NOW before submitting!**
