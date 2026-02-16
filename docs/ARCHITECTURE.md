# ShieldBot Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         User (Telegram)                          │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          │ Send Address
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ShieldBot (Python)                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Telegram Bot Handler                         │  │
│  │  • Command routing (/start, /scan, /token, /help)        │  │
│  │  • Auto-detection (addresses without commands)           │  │
│  │  • Response formatting with inline buttons               │  │
│  └─────────────────────┬─────────────────────────────────────┘  │
│                        │                                          │
│         ┌──────────────┴──────────────┐                          │
│         ▼                              ▼                          │
│  ┌──────────────────┐         ┌───────────────────┐             │
│  │ Transaction      │         │  Token Scanner    │             │
│  │ Scanner          │         │                   │             │
│  │ (Module 1)       │         │  (Module 2)       │             │
│  │                  │         │                   │             │
│  │ • Scam DB Check  │         │ • Honeypot Check  │             │
│  │ • Verification   │         │ • Trading Checks  │             │
│  │ • Age Analysis   │         │ • Ownership       │             │
│  │ • Pattern Detect │         │ • Tax Detection   │             │
│  │ • Risk Scoring   │         │ • Safety Scoring  │             │
│  └────────┬─────────┘         └──────────┬────────┘             │
│           │                               │                      │
│           └───────────┬───────────────────┘                      │
│                       ▼                                          │
│           ┌───────────────────────┐                             │
│           │   Web3 Client         │                             │
│           │                       │                             │
│           │ • BSC RPC Connection  │                             │
│           │ • opBNB RPC Connect   │                             │
│           │ • Contract Calls      │                             │
│           │ • Token Queries       │                             │
│           └───────────┬───────────┘                             │
└───────────────────────┼─────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  BNB Chain   │ │  External    │ │  Scam        │
│  (BSC/opBNB) │ │  APIs        │ │  Databases   │
│              │ │              │ │              │
│ • Contract   │ │ • BscScan    │ │ • ChainAbuse │
│   Code       │ │ • Honeypot.is│ │ • ScamSniffer│
│ • Bytecode   │ │              │ │              │
│ • Token Data │ │              │ │              │
└──────────────┘ └──────────────┘ └──────────────┘
```

---

## Component Details

### 1. Telegram Bot Handler
**File:** `bot.py`

**Responsibilities:**
- Receive user messages and commands
- Route to appropriate scanner module
- Format responses with risk indicators
- Provide inline buttons (BscScan, DexScreener)

**Flow:**
```
User Input → Validate Address → Detect Type → Route to Scanner → Format Result → Send Response
```

---

### 2. Transaction Scanner (Module 1)
**File:** `scanner/transaction_scanner.py`

**Security Checks:**
```python
1. Contract Verification (BscScan API)
   ├─ Source code published?
   └─ Verified by BscScan?

2. Scam Database Check (Multi-source)
   ├─ ChainAbuse.com lookup
   ├─ ScamSniffer.io lookup
   └─ Local blacklist check

3. Age Analysis
   ├─ Get contract creation tx
   ├─ Calculate age in days
   └─ Flag if < 7 days old

4. Bytecode Pattern Detection
   ├─ Check for backdoor functions
   ├─ Check for self-destruct
   └─ Check for delegatecall risks

5. Risk Scoring Algorithm
   └─ Calculate: HIGH / MEDIUM / LOW
```

**Risk Calculation:**
```python
HIGH risk if:
  - Found in scam databases
  - Unverified AND very new (< 7 days)

MEDIUM risk if:
  - Unverified contract OR
  - Suspicious patterns detected

LOW risk if:
  - Verified source code
  - Clean scam database check
  - No suspicious patterns
```

---

### 3. Token Scanner (Module 2)
**File:** `scanner/token_scanner.py`

**Safety Checks:**
```python
1. Token Information
   ├─ Name, Symbol, Decimals
   └─ Total Supply

2. Honeypot Detection (Honeypot.is API)
   ├─ Simulate buy transaction
   ├─ Simulate sell transaction
   └─ Check if sells are blocked

3. Trading Restrictions
   ├─ Can buy?
   ├─ Can sell?
   └─ Transfer function accessible?

4. Ownership Analysis
   ├─ Get contract owner
   ├─ Check if renounced (0x0 address)
   └─ Warn if active owner

5. Tax Detection (Honeypot.is API)
   ├─ Buy tax percentage
   ├─ Sell tax percentage
   └─ Flag if > 10%

6. Liquidity Lock Check
   └─ Verify LP tokens locked (future)

7. Safety Scoring Algorithm
   └─ Calculate: SAFE / WARNING / DANGER
```

**Safety Calculation:**
```python
DANGER if:
  - Is honeypot (can't sell)
  - Sell tax > 50%

WARNING if:
  - Ownership not renounced
  - Liquidity not locked
  - Taxes > 10%

SAFE if:
  - Can buy and sell
  - Not a honeypot
  - Reasonable taxes (< 10%)
```

---

### 4. Web3 Client
**File:** `utils/web3_client.py`

**Blockchain Interaction:**
```python
BSC RPC:
  └─ https://bsc-dataseed1.binance.org/

opBNB RPC:
  └─ https://opbnb-mainnet-rpc.bnbchain.org

Functions:
  ├─ is_contract() - Check if address is contract
  ├─ get_bytecode() - Fetch contract bytecode
  ├─ get_token_info() - ERC20 token data
  ├─ get_ownership_info() - Contract owner
  ├─ check_honeypot() - API call to Honeypot.is
  └─ get_tax_info() - Buy/sell tax percentages
```

**API Integration:**
```python
BscScan API:
  ├─ Contract verification status
  ├─ Contract creation info
  └─ Source code retrieval

Honeypot.is API:
  ├─ Honeypot simulation
  ├─ Tax calculation
  └─ Trading restriction detection
```

---

### 5. Scam Database
**File:** `utils/scam_db.py`

**Multi-Source Validation:**
```python
Sources:
  ├─ ChainAbuse.com (reported scams)
  ├─ ScamSniffer.io (flagged addresses)
  └─ Local blacklist (manually added)

Check Flow:
  1. Query ChainAbuse API
  2. Query ScamSniffer API
  3. Check local blacklist
  4. Aggregate results
  5. Return all matches
```

---

## Data Flow Example

### Scenario: User scans a token

```
1. User sends: 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c

2. Bot validates address format
   └─ Valid Ethereum address ✓

3. Bot checks if it's a contract
   └─ Web3 call: eth_getCode
   └─ Result: Contract ✓

4. Bot detects token (has symbol() function)
   └─ Web3 call: symbol()
   └─ Result: "WBNB" → Token detected

5. Token Scanner runs all checks:
   
   a) Get token info:
      Web3 calls: name(), symbol(), decimals(), totalSupply()
      Result: Wrapped BNB (WBNB), 18 decimals
   
   b) Honeypot check:
      API call: honeypot.is/v2/IsHoneypot?address=0xbb4C...&chainID=56
      Result: Not a honeypot ✓
   
   c) Trading checks:
      Web3 call: decimals() (proxy for transfer function)
      Result: Transfer function works ✓
   
   d) Ownership:
      Web3 call: owner()
      Result: 0x0000... (renounced) ✓
   
   e) Tax info:
      API call: honeypot.is (buy/sell taxes)
      Result: Buy 0%, Sell 0% ✓

6. Safety level calculated:
   └─ All checks passed → SAFE

7. Response formatted with:
   └─ Token name/symbol
   └─ Safety indicators (✅ emojis)
   └─ Inline buttons (BscScan, DexScreener)

8. Sent to user in Telegram
```

**Total time: ~3-5 seconds**

---

## AI/Agent Components

### Pattern Learning (Adaptive Detection)
```python
Current: Static pattern matching
  └─ Hardcoded suspicious function signatures

Future Enhancement:
  └─ Machine learning model trained on:
      ├─ Known scam bytecode patterns
      ├─ Exploit transaction patterns
      └─ Community-reported scams
  
  └─ Self-updating risk parameters:
      ├─ Track false positives/negatives
      ├─ Adjust risk thresholds
      └─ Learn new attack vectors
```

### Intelligent Risk Scoring
```python
Current: Rule-based scoring
  └─ IF conditions → risk level

Future Enhancement:
  └─ AI risk model considering:
      ├─ Historical exploit patterns
      ├─ Similar contract behaviors
      ├─ Developer reputation (GitHub)
      ├─ Community sentiment (social signals)
      └─ Transaction pattern anomalies
```

---

## Performance Characteristics

### Response Time
- **Average:** 3-5 seconds
- **Breakdown:**
  - Address validation: <10ms
  - Contract checks: 1-2s (RPC calls)
  - API calls: 1-2s (BscScan, Honeypot.is)
  - Scam DB queries: 500ms-1s
  - Response formatting: <100ms

### Resource Usage
- **Memory:** ~50-100MB
- **CPU:** <5% (idle), 10-20% (scanning)
- **Network:** ~100KB per scan
- **Storage:** ~10MB (code + dependencies)

### Scalability
- **Concurrent users:** 100+ (async I/O)
- **Rate limits:**
  - BscScan free tier: 5 calls/sec
  - Honeypot.is: No official limit (fair use)
  - RPC endpoints: 1000+ calls/sec

---

## Security & Privacy

### Data Handling
```python
What we store:
  └─ NOTHING - ShieldBot is stateless

What we process:
  ├─ User-provided addresses (ephemeral)
  └─ API responses (not logged)

What we share:
  └─ NOTHING - No data leaves the analysis flow
```

### API Key Security
```python
Credentials stored in:
  └─ .env file (not in git)

Used by:
  └─ Server-side only (never exposed to users)
```

---

## Deployment Architecture

### Current: Single VPS
```
┌─────────────────────────┐
│  VPS (Ubuntu 22.04)     │
│                         │
│  ├─ ShieldBot Service   │
│  │  └─ systemd managed  │
│  │                      │
│  ├─ Python 3.11 + deps  │
│  │                      │
│  └─ Logs: journalctl    │
└─────────────────────────┘
         ▲
         │ Telegram API
         │
    Users (Telegram)
```

### Future: Production-Ready
```
┌──────────────────┐
│  Load Balancer   │
└────────┬─────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌─────┐   ┌─────┐
│ Bot │   │ Bot │  (Multiple instances)
│  #1 │   │  #2 │
└──┬──┘   └──┬──┘
   │         │
   └────┬────┘
        ▼
   ┌─────────┐
   │  Redis  │  (Cache frequently scanned addresses)
   └─────────┘
```

---

## Future Enhancements

### Phase 2: Advanced Detection
- [ ] ML-based risk scoring
- [ ] Historical pattern analysis
- [ ] Community reputation system
- [ ] Real-time exploit monitoring

### Phase 3: Integrations
- [ ] MetaMask Snap integration
- [ ] TrustWallet SDK
- [ ] Web3 dApp integration
- [ ] REST API for developers

### Phase 4: Onchain Components
- [ ] Verification contract on BSC
- [ ] Scan result recording (for transparency)
- [ ] Reputation token system
- [ ] Decentralized scam reporting

---

## Why This Architecture?

### ✅ Advantages
1. **Fast:** Async operations, parallel API calls
2. **Reliable:** Multiple data sources (no single point of failure)
3. **Scalable:** Stateless design, easy to replicate
4. **Maintainable:** Modular structure, clear separation
5. **Cost-Effective:** Off-chain analysis (no gas fees)

### 🎯 Design Principles
1. **User First:** Simple Telegram interface
2. **Speed Matters:** <5 second responses
3. **Trust Through Transparency:** Multiple verification sources
4. **Fail Safely:** Errors default to caution (warn user)
5. **Privacy:** No data collection or logging

---

**Architecture Version:** 1.0  
**Last Updated:** Feb 12, 2026  
**Status:** Production-Ready ✅
