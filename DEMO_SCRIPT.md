# ShieldBot Demo Script

## For Hackathon Video/Presentation

### Opening
"Hi judges! I'm demonstrating ShieldBot - Your BNB Chain Shield. An AI-powered security agent that protects users from scams, honeypots, and malicious transactions."

### Demo Flow

#### 1. Start the Bot
```
User: /start
```
**Shows:** Welcome message with features and commands

#### 2. Check Help
```
User: /help
```
**Shows:** Detailed instructions and risk levels

#### 3. Analyze a Safe Token (USDT)
```
User: 0x55d398326f99059fF775485246999027B3197955
```
**Expected Result:**
- ✅ Contract verified
- ✅ Token name: Tether USD
- 🟢 Low risk score
- Token info (supply, age, etc.)

**Narration:** "This is USDT on BSC - ShieldBot correctly identifies it as verified and safe."

#### 4. Analyze an Unverified Contract
```
User: [Paste any unverified token address]
```
**Expected Result:**
- 🚨 Contract NOT verified
- 🔴 High risk score
- Warning messages

**Narration:** "For unverified contracts, ShieldBot immediately flags the risk and warns users."

#### 5. Analyze a Transaction
```
User: [Paste recent BSC transaction hash]
```
**Expected Result:**
- Transaction details
- Contract interaction analysis
- Risk assessment

**Narration:** "ShieldBot can analyze transactions before you sign them, checking the contract and destination address."

### Closing
"ShieldBot provides TWO critical security modules:
1. **Pre-Transaction Scanner** - Checks transactions before you commit
2. **Token Safety Check** - Detects honeypots and scam tokens

Both modules are fully functional, deployed on BSC, and ready to protect users today."

---

## Key Demo Points to Emphasize

✅ **Real-time Analysis** - Works on actual BSC blockchain  
✅ **Comprehensive Checks** - Contract verification, scam detection, honeypot patterns  
✅ **Clear Risk Scoring** - Easy to understand (Low/Medium/High)  
✅ **User-Friendly** - Simple Telegram interface  
✅ **Practical Utility** - Solves real problems users face daily  
✅ **Reproducible** - Open source, clear documentation, anyone can run it  

---

## Technical Highlights (For Judges)

- **BSCScan API integration** for on-chain verification
- **Web3.py** for direct blockchain interaction
- **Pattern recognition** for honeypot detection
- **Risk scoring algorithm** based on multiple factors
- **Modular architecture** - easy to extend
- **Clean codebase** with documentation

---

## Sample Token Addresses for Demo

**Safe (Low Risk):**
- USDT: `0x55d398326f99059fF775485246999027B3197955`
- BUSD: `0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56`
- WBNB: `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`

**For Testing Warnings:**
- Use any unverified token contract
- Use very new tokens (< 1 day old)
- Use tokens with "airdrop" or "giveaway" in name

---

## If Demo Bot Fails

**Backup Plan:**
1. Show screenshots of working bot
2. Walk through code on GitHub
3. Explain architecture and logic
4. Show testing results

**Common Issues:**
- API rate limits → Show cached results
- Network delays → Explain it's normal for blockchain calls
- Bot offline → Use screenshots/video recording
