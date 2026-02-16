# ShieldBot - Screenshots Guide

## Required Screenshots for Documentation

To make the documentation more visual and impactful, add the following screenshots:

---

## 1. Chrome Extension Screenshots

### A. BLOCK Verdict (High Risk)
**File:** `docs/images/extension_block.png`
**How to Capture:**
1. Run ShieldBot API: `uvicorn api:app --port 8000`
2. Open Chrome extension test page: `http://localhost:8000/test`
3. Click "Test BLOCK Verdict (Honeypot Token)"
4. Screenshot the full-screen RED modal showing:
   - Risk score 85/100
   - "HIGH RISK" label
   - Critical flags (honeypot, 99% sell tax, etc.)
   - Blocked message

**Where to Add:**
- README.md (Features section)
- docs/PROJECT.md (Solution section)

---

### B. WARN Verdict (Medium Risk)
**File:** `docs/images/extension_warn.png`
**How to Capture:**
1. On test page, click "Test WARN Verdict (Unverified Contract)"
2. Screenshot the ORANGE warning overlay showing:
   - Risk score 45/100
   - "MEDIUM RISK" label
   - Warning flags (unverified, low liquidity, etc.)
   - "Proceed Anyway" and "Cancel Transaction" buttons

**Where to Add:**
- README.md (Features section)
- docs/TECHNICAL.md (Demo section)

---

### C. ALLOW Verdict (Safe)
**File:** `docs/images/extension_allow.png`
**How to Capture:**
1. On test page, click "Test ALLOW Verdict (PancakeSwap)"
2. Screenshot showing NO overlay (silent passthrough)
3. Optionally show MetaMask signature request appearing immediately

**Where to Add:**
- README.md (Features section)

---

## 2. Telegram Bot Screenshots

### A. Token Scan with Name/Symbol
**File:** `docs/images/telegram_token_scan.png`
**How to Capture:**
1. Open Telegram: @shieldbot_bnb_bot
2. Send: `/token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`
3. Screenshot the response showing:
   - Token name: "Wrapped BNB (WBNB)"
   - Risk score: LOW
   - ShieldBot Intelligence Report
   - All safety metrics

**Where to Add:**
- README.md (Quick Start section)
- docs/PROJECT.md (Current Traction)

---

### B. Contract Scan
**File:** `docs/images/telegram_contract_scan.png`
**How to Capture:**
1. Send: `/scan 0x10ED43C718714eb63d5aA57B78B54704E256024E`
2. Screenshot showing PancakeSwap Router analysis
3. Shows "SAFE" verdict with all metrics

**Where to Add:**
- docs/TECHNICAL.md (Demo Guide)

---

### C. Risky Token Detection
**File:** `docs/images/telegram_risky_token.png`
**How to Capture:**
1. Find a known honeypot token address
2. Send: `/token <honeypot_address>`
3. Screenshot showing:
   - HIGH RISK verdict
   - Red warning icon
   - Critical flags
   - BNB Greenfield report URL

**Where to Add:**
- README.md (Features section)
- docs/PROJECT.md (Impact section)

---

## 3. BNB Greenfield Report

### A. Forensic Report JSON
**File:** `docs/images/greenfield_report.png`
**How to Capture:**
1. Get a Greenfield report URL from Telegram bot response
2. Open URL in browser: `https://greenfield-sp.bnbchain.org/view/shieldbot-reports/reports/<id>.json`
3. Screenshot showing:
   - JSON structure
   - Risk score data
   - Timestamp
   - Public URL visibility

**Where to Add:**
- README.md (Features section)
- bsc.address (Verify Integration section)

---

## 4. API Response Example

### A. /api/firewall Response
**File:** `docs/images/api_response.png`
**How to Capture:**
1. Use curl or Postman:
   ```bash
   curl -X POST http://localhost:8000/api/firewall \
     -H "Content-Type: application/json" \
     -d '{"to":"0x10ED43C718714eb63d5aA57B78B54704E256024E", "from":"0x742d35Cc6634C0532925a3b844Bc9e7595f2bD61", "value":"0x2386F26FC10000", "data":"0x", "chainId":56}'
   ```
2. Screenshot the JSON response showing ShieldScore, verdict, danger signals

**Where to Add:**
- README.md (API section)
- docs/TECHNICAL.md (API Demo)

---

## Implementation Steps

Once you have the screenshots:

### 1. Create Images Directory
```bash
mkdir -p docs/images
```

### 2. Add Screenshots to Directory
Move all captured screenshots to `docs/images/`

### 3. Update README.md

Add after "Features" heading:

```markdown
## Features

### Visual Examples

**Chrome Extension Blocking Honeypot:**
![BLOCK Verdict](docs/images/extension_block.png)

**Warning for Medium-Risk Contract:**
![WARN Verdict](docs/images/extension_warn.png)

**Telegram Bot Showing Token Names:**
![Telegram Token Scan](docs/images/telegram_token_scan.png)

**BNB Greenfield Forensic Report:**
![Greenfield Report](docs/images/greenfield_report.png)
```

### 4. Update docs/PROJECT.md

Add after "How It Works" section:

```markdown
### Visual Demonstration

![Chrome Extension BLOCK](docs/images/extension_block.png)
*ShieldBot blocking a honeypot token in real-time*

![Telegram Bot Analysis](docs/images/telegram_token_scan.png)
*Telegram bot displaying token information and risk analysis*
```

### 5. Update docs/TECHNICAL.md

Add to "Demo Guide" section:

```markdown
### Screenshots

**Extension BLOCK Verdict:**
![BLOCK](docs/images/extension_block.png)

**Extension WARN Verdict:**
![WARN](docs/images/extension_warn.png)

**Telegram Token Scan:**
![Telegram](docs/images/telegram_token_scan.png)
```

### 6. Update .gitignore

Make sure images are NOT ignored:

```gitignore
# Don't ignore documentation images
!docs/images/
!docs/images/*.png
!docs/images/*.jpg
```

---

## Quick Screenshot Tips

1. **Use high resolution:** At least 1920x1080 for desktop screenshots
2. **Clean browser:** Close unnecessary tabs, use incognito mode
3. **Zoom appropriately:** 100% zoom for extension, can zoom in for details
4. **Crop wisely:** Remove unnecessary UI, focus on ShieldBot content
5. **Compress for web:** Use tools like TinyPNG to reduce file size (<500KB each)
6. **Use descriptive names:** `extension_block_verdict.png` not `screenshot1.png`

---

## Alternative: Placeholder Images

If you can't capture screenshots immediately, create placeholder text:

```markdown
> **[Screenshot: Chrome Extension BLOCK Verdict]**
> - Full-screen red modal
> - Risk Score: 85/100 HIGH RISK
> - Critical flags: Honeypot confirmed, 99% sell tax
> - "Transaction Blocked" message
```

This shows judges what the feature looks like even without the image.

---

## Priority Order

1. **Extension BLOCK verdict** (most impressive)
2. **Telegram bot with token names** (shows recent feature)
3. **BNB Greenfield report** (proves BNB Chain integration)
4. **Extension WARN verdict** (shows user choice)
5. **API response** (technical proof)

Focus on capturing #1-3 first as they have the highest impact for judges.
