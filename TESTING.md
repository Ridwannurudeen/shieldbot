# ShieldBot Testing Guide

## Test Addresses for BSC

### Safe/Verified Tokens (Low Risk)
- **USDT (BSC):** `0x55d398326f99059fF775485246999027B3197955`
- **BUSD:** `0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56`
- **WBNB:** `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`

### Unverified Contracts (Should trigger warnings)
- Test with any random contract address to see unverified warnings

### Test Transaction Hashes
- Find recent transactions on BSCScan.com
- Copy transaction hash (0x... 66 characters)
- Send to bot for analysis

## Expected Behavior

### Token Analysis (42 char address)
Should check:
- ✅ Contract verification status
- ✅ Known scam database
- ✅ Token name, symbol, supply
- ✅ Honeypot patterns (blacklist functions)
- ✅ Contract age
- ✅ Tax/fee detection

### Transaction Analysis (66 char hash)
Should check:
- ✅ Contract verification (if interacting with contract)
- ✅ Known scam addresses
- ✅ Transaction value warnings
- ✅ Suspicious contract names
- ✅ Risk scoring

## Risk Levels

- **🟢 Low (0-30):** Generally safe
- **🟡 Medium (31-70):** Proceed with caution
- **🔴 High (71-100):** Dangerous, avoid!

## Testing Checklist

- [ ] Bot starts without errors
- [ ] /start command shows welcome message
- [ ] /help command shows instructions
- [ ] Token address (42 chars) triggers analysis
- [ ] Transaction hash (66 chars) triggers analysis
- [ ] Invalid input shows helpful error
- [ ] Risk scores calculate correctly
- [ ] Reports are readable and clear

## Known Issues

- Token sell simulation not yet implemented (coming in v2)
- Liquidity lock detection not yet implemented
- Tax percentage detection is basic (needs improvement)

## Next Tests (After Full Implementation)

1. Test with real scam tokens
2. Test with honeypot tokens
3. Test with high-tax tokens
4. Performance test (multiple concurrent requests)
5. Error handling (invalid addresses, API failures)
