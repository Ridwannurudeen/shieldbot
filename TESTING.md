# ShieldBot Testing Guide

## Test Addresses (BSC Mainnet)

Use these addresses to test ShieldBot functionality:

### ✅ Safe/Legitimate Contracts

**PancakeSwap Router V2**
```
0x10ED43C718714eb63d5aA57B78B54704E256024E
```
- Verified contract ✅
- Well-known DEX
- Expected: LOW risk

**WBNB (Wrapped BNB)**
```
0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
```
- Verified token contract ✅
- Native wrapper
- Expected: SAFE token

### ⚠️ High-Risk Test Cases

**Unverified Contract**
```
# Find a recent unverified contract on BscScan
https://bscscan.com/contractsVerified?filter=unverified
```
- Expected: MEDIUM/HIGH risk (unverified)

**New Contract (< 7 days old)**
```
# Check recent contracts
https://bscscan.com/txs?sort=age
```
- Expected: WARNING (too new)

### 🔴 Known Scam Addresses (Use with Caution)

Check these aggregators for known scams:
- [ChainAbuse](https://www.chainabuse.com/)
- [ScamSniffer](https://scamsniffer.io/)

Expected: HIGH risk with scam database matches

---

## Testing Workflow

### 1. Basic Bot Commands

```bash
# Start bot
./run.sh
```

In Telegram:
1. `/start` - Should show welcome message
2. `/help` - Should show command list
3. `/scan 0x10ED43C718714eb63d5aA57B78B54704E256024E` - Scan PancakeSwap
4. `/token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` - Check WBNB

### 2. Auto-Detection

Send addresses directly (no command):
1. `0x10ED43C718714eb63d5aA57B78B54704E256024E` - Should auto-scan
2. `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` - Should detect token

### 3. Edge Cases

**Invalid Address**
```
0x123
```
Expected: "Invalid address format" error

**EOA (Not a Contract)**
```
0x0000000000000000000000000000000000000000
```
Expected: "This is an EOA, not a contract"

**Non-Token Contract**
```
0x10ED43C718714eb63d5aA57B78B54704E256024E
```
Expected: Contract scan (not token check)

---

## Test Scenarios

### Scenario 1: Legitimate Token
**Goal:** Verify safe token detection

1. Send `/token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`
2. Expected results:
   - ✅ Token name: Wrapped BNB (WBNB)
   - ✅ Can Buy/Sell: YES
   - ✅ Not a honeypot
   - Safety: SAFE

### Scenario 2: Unverified Contract
**Goal:** Catch unverified contract risk

1. Find unverified contract on BscScan
2. Send `/scan <address>`
3. Expected results:
   - ❌ Contract not verified
   - ⚠️ Warning in report
   - Risk: MEDIUM or HIGH

### Scenario 3: New Contract
**Goal:** Flag very new contracts

1. Find contract created < 7 days ago
2. Send `/scan <address>`
3. Expected results:
   - ⚠️ Contract is only X days old
   - Risk: includes age warning

### Scenario 4: Honeypot Token
**Goal:** Detect honeypot scams

1. Find a known honeypot on honeypot.is
2. Send `/token <address>`
3. Expected results:
   - 🔴 HONEYPOT DETECTED
   - ❌ Cannot sell
   - Safety: DANGER

---

## Manual Testing Checklist

### Core Functionality
- [ ] Bot starts without errors
- [ ] `/start` shows welcome message
- [ ] `/help` shows commands
- [ ] `/scan` accepts addresses
- [ ] `/token` accepts addresses
- [ ] Auto-detection works for bare addresses

### Scanner Module
- [ ] Detects verified vs unverified contracts
- [ ] Checks contract age
- [ ] Queries scam databases
- [ ] Calculates risk level correctly

### Token Module
- [ ] Gets token name/symbol/decimals
- [ ] Checks buy/sell capability
- [ ] Detects honeypots via API
- [ ] Shows tax information
- [ ] Calculates safety level

### Error Handling
- [ ] Invalid address format handled
- [ ] API errors caught gracefully
- [ ] Timeout handling works
- [ ] Rate limiting handled

### UI/UX
- [ ] Messages formatted correctly
- [ ] Buttons work (BscScan links, etc.)
- [ ] Emoji indicators clear
- [ ] Response time acceptable (<5s)

---

## Automated Testing

Tests live in `tests/` and use **pytest** with mocked network calls (no RPC or API keys needed).

### Test Modules

| File | Covers |
|------|--------|
| `tests/test_risk_scorer.py` | `calculate_risk_score`, `blend_scores`, `compute_confidence`, `score_level_from_int` |
| `tests/test_ownership.py` | Tri-state ownership propagation (None/True/False) through risk engine |
| `tests/test_calldata.py` | Calldata decoding, router whitelist, unknown selector fallback |

### Running Tests

```bash
pip install pytest pytest-asyncio
pytest tests/ -v
```

---

## Performance Testing

### Load Test
Use `locust` or `ab` to simulate multiple concurrent users:

```bash
pip install locust

# Create locustfile.py for Telegram bot testing
# Run load test
locust -f locustfile.py
```

### API Rate Limiting
Monitor BscScan API calls:
- Free tier: 5 calls/sec
- Track your usage
- Add caching if needed

---

## Integration Testing

### 1. Telegram Integration
- [ ] Bot receives messages
- [ ] Bot sends responses
- [ ] Buttons trigger callbacks
- [ ] Images/media work (if added)

### 2. Web3 Integration
- [ ] RPC connection stable
- [ ] Contract calls succeed
- [ ] Handles network errors

### 3. API Integration
- [ ] BscScan API works
- [ ] Honeypot.is API works
- [ ] Scam databases accessible

---

## Demo Preparation

For hackathon submission:

1. **Record demo video:**
   - Show bot startup
   - Test with safe contract
   - Test with risky contract
   - Test token safety check
   - Show onchain proof (if implemented)

2. **Prepare test script:**
   ```
   1. /start - "Welcome to ShieldBot!"
   2. Send PancakeSwap address - Show LOW risk
   3. /token WBNB - Show SAFE
   4. Send unverified contract - Show risks
   5. Show BscScan verification
   ```

3. **Screenshots needed:**
   - Welcome message
   - Scan results (safe)
   - Scan results (risky)
   - Token check (safe)
   - Token check (honeypot)

---

## Known Issues / Limitations

- [ ] Free honeypot.is API has rate limits
- [ ] BscScan free tier: 5 calls/sec
- [ ] Some scam databases may be slow
- [ ] Liquidity lock detection not fully implemented
- [ ] No historical scan data stored

---

## Pre-Deployment Checklist

Before submitting to hackathon:

- [ ] All tests passing
- [ ] Bot running on VPS/server
- [ ] Telegram bot accessible 24/7
- [ ] GitHub repo public
- [ ] README.md complete
- [ ] DEPLOYMENT.md accurate
- [ ] Demo video recorded
- [ ] Onchain component deployed (if applicable)
- [ ] Contract address documented
- [ ] Submission form filled

---

**Next Steps:**
1. Run through all test scenarios
2. Fix any bugs found
3. Record demo
4. Deploy to production
5. Submit to hackathon!

Good luck! 🛡️
