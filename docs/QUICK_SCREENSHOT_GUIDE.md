# Quick Screenshot Guide - 3 Priority Screenshots

**Time Required:** 30 minutes
**Priority Order:** BLOCK → Telegram → Greenfield

---

## SETUP FIRST

### 1. Start ShieldBot API
```bash
cd C:/Users/GUDMAN/Desktop/shieldbot
uvicorn api:app --host 0.0.0.0 --port 8000
```

### 2. Verify Extension is Loaded
- Open Chrome
- Go to `chrome://extensions`
- Verify ShieldBot extension is enabled
- Note the Extension ID

---

## SCREENSHOT #1: Extension BLOCK Verdict (HIGHEST PRIORITY)

### Steps:
1. **Open Test Page:**
   - Navigate to: `http://localhost:8000/test`

2. **Trigger BLOCK:**
   - Click the button: **"Test BLOCK Verdict (Honeypot Token)"**
   - Wait 2 seconds for the red modal to appear

3. **Capture Screenshot:**
   - **Windows:** Press `Win + Shift + S` (Snipping Tool)
   - **Or:** Press `PrtScn` then paste in Paint
   - Capture the **ENTIRE RED MODAL** including:
     - Full-screen red background
     - "🔴 TRANSACTION BLOCKED" header
     - Risk Score: 85/100 HIGH RISK
     - All critical flags
     - Contract address
     - "This transaction has been blocked" message

4. **Save:**
   - File: `C:/Users/GUDMAN/Desktop/shieldbot/docs/images/extension_block.png`
   - Format: PNG
   - Resolution: Keep original (1920x1080 recommended)

### What It Should Show:
```
╔═══════════════════════════════════════════════════╗
║          🔴 TRANSACTION BLOCKED                    ║
║                                                    ║
║  Risk Score: 85/100 - HIGH RISK                   ║
║                                                    ║
║  ⚠️ Critical Flags:                               ║
║  ✗ Honeypot confirmed - cannot sell after buying  ║
║  ✗ Sell tax: 99%                                  ║
║  ✗ Ownership not renounced                        ║
║  ✗ Low liquidity: $2,000                          ║
║                                                    ║
║  Contract: 0x...                                   ║
║                                                    ║
║  This transaction has been blocked for your        ║
║  protection.                                       ║
╚═══════════════════════════════════════════════════╝
```

---

## SCREENSHOT #2: Telegram Bot with Token Names (HIGH PRIORITY)

### Steps:
1. **Open Telegram:**
   - Open Telegram app or web: https://web.telegram.org
   - Search for: `@shieldbot_bnb_bot`

2. **Run Token Scan:**
   - Send this command:
     ```
     /token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
     ```
   - This is WBNB (Wrapped BNB) - safe token

3. **Wait for Response:**
   - Bot will respond in 2-3 seconds
   - Response will show:
     - **Token: Wrapped BNB (WBNB)** ← This is key!
     - Address: 0xbb4...
     - Risk Score: LOW
     - Full intelligence report

4. **Capture Screenshot:**
   - **Windows:** `Win + Shift + S`
   - Capture the **ENTIRE BOT RESPONSE** including:
     - Your command: `/token 0xbb4...`
     - Bot response with green shield icon
     - "Token: Wrapped BNB (WBNB)" line
     - Risk score and all metrics
     - Timestamp

5. **Save:**
   - File: `C:/Users/GUDMAN/Desktop/shieldbot/docs/images/telegram_token_scan.png`
   - Format: PNG

### What It Should Show:
```
You:
/token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c

ShieldBot:
🟢 ShieldBot Intelligence Report

Token: Wrapped BNB (WBNB)
Address: 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
Risk Archetype: Low Risk
Rug Probability: 5% | Risk Level: LOW
Confidence: 95%

✓ Category Scores:
  • Structural: 10/100
  • Market: 5/100
  • Behavioral: 0/100
  • Honeypot: 0/100

✓ No Critical Flags
...
```

---

## SCREENSHOT #3: BNB Greenfield Report (MEDIUM PRIORITY)

### Steps:
1. **Get Greenfield URL:**
   - Option A: From Telegram bot response (if you scanned a risky token)
   - Option B: Use the example URL from `bsc.address`:
     ```
     https://greenfield-sp.bnbchain.org/view/shieldbot-reports/reports/3a4039ef0349eb5f.json
     ```

2. **Open in Browser:**
   - Paste the URL in Chrome/Edge
   - The JSON report will load

3. **Capture Screenshot:**
   - **Windows:** `Win + Shift + S`
   - Capture the **BROWSER WINDOW** showing:
     - URL bar with greenfield-sp.bnbchain.org
     - JSON content including:
       - `"risk_score": 85`
       - `"risk_level": "HIGH"`
       - `"timestamp": "..."`
       - `"contract_address": "0x..."`
       - All forensic data

4. **Save:**
   - File: `C:/Users/GUDMAN/Desktop/shieldbot/docs/images/greenfield_report.png`
   - Format: PNG

### What It Should Show:
```
Browser URL: https://greenfield-sp.bnbchain.org/view/...

{
  "report_id": "3a4039ef0349eb5f",
  "timestamp": "2026-02-16T03:45:12Z",
  "contract_address": "0x...",
  "risk_score": 85,
  "risk_level": "HIGH",
  "rug_probability": 87.5,
  "critical_flags": [
    "Honeypot confirmed",
    "99% sell tax",
    ...
  ],
  "category_scores": {
    "structural": 90,
    "market": 75,
    ...
  }
}
```

---

## AFTER CAPTURING SCREENSHOTS

### 1. Verify All 3 Files Exist:
```bash
ls docs/images/
# Should show:
# extension_block.png
# telegram_token_scan.png
# greenfield_report.png
```

### 2. Optimize Images (Optional):
- Use https://tinypng.com/ to compress
- Target: <500KB per image
- Maintains quality while reducing file size

### 3. I'll Update Documentation Automatically
Once you confirm the screenshots are ready, I'll:
- Add them to README.md
- Add them to docs/PROJECT.md
- Add them to docs/TECHNICAL.md
- Update .gitignore to allow images
- Commit and push

---

## TROUBLESHOOTING

### Extension BLOCK Not Appearing:
1. Check API is running: `http://localhost:8000/api/health`
2. Check extension is enabled: `chrome://extensions`
3. Refresh test page: `http://localhost:8000/test`
4. Check browser console for errors (F12)

### Telegram Bot Not Responding:
1. Use live bot: @shieldbot_bnb_bot
2. Make sure you sent the exact command
3. Wait 5 seconds (might be busy)
4. Try /start first to wake it up

### Greenfield URL Not Working:
1. Check internet connection
2. Try example URL from bsc.address
3. Or use any public Greenfield URL
4. The exact report doesn't matter - we just need to show the JSON format

---

## NEXT STEPS

1. **Capture all 3 screenshots** (follow steps above)
2. **Save them in** `docs/images/`
3. **Tell me when done** → I'll update all documentation
4. **I'll commit and push** → Ready for submission!

---

**Estimated Time:**
- Screenshot #1 (Extension BLOCK): 5 minutes
- Screenshot #2 (Telegram Bot): 10 minutes
- Screenshot #3 (Greenfield): 5 minutes
- Image optimization: 5 minutes
- **Total: ~25 minutes**

**Ready? Start with Screenshot #1!** 📸
