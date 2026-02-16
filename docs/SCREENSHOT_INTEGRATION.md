# Screenshot Integration Plan

## Once Screenshots Are Ready

This document shows where each screenshot will be added to the documentation.

---

## README.md Updates

### Location 1: After "Features" Heading (Line ~64)

Add this section:

```markdown
## Features

### 🎬 Visual Demonstration

**Real-Time Transaction Blocking:**

![Extension BLOCK Verdict](docs/images/extension_block.png)
*ShieldBot intercepting and blocking a honeypot token with 99% sell tax*

**Telegram Bot Intelligence:**

![Telegram Token Scan](docs/images/telegram_token_scan.png)
*Telegram bot displaying token name (Wrapped BNB) and comprehensive risk analysis*

**Immutable Forensic Reports:**

![BNB Greenfield Report](docs/images/greenfield_report.png)
*High-risk transaction forensic report stored on BNB Greenfield*

---
```

---

## docs/PROJECT.md Updates

### Location 1: After "How It Works" Section

Add this:

```markdown
### Visual Proof

**Chrome Extension in Action:**

![BLOCK Verdict](images/extension_block.png)

When ShieldBot detects a honeypot token, it displays a full-screen red modal that completely blocks the transaction. Users cannot proceed even if they want to - this is a hard stop that prevents losses before they occur.

**Telegram Bot Analysis:**

![Token Scan](images/telegram_token_scan.png)

The Telegram bot shows token names and symbols (new feature!), making it easy to verify you're checking the right contract. Comprehensive risk analysis is available to anyone via @shieldbot_bnb_bot.

**BNB Greenfield Integration:**

![Forensic Report](images/greenfield_report.png)

High-risk transactions are recorded as immutable JSON objects on BNB Greenfield, providing public, verifiable evidence of dangerous contracts.
```

---

## docs/TECHNICAL.md Updates

### Location 1: Demo Guide Section (After Line 470)

Add this:

```markdown
### Visual Examples

**Extension BLOCK Verdict:**
![BLOCK](images/extension_block.png)

**Telegram Bot Token Scan:**
![Telegram](images/telegram_token_scan.png)

**BNB Greenfield Forensic Report:**
![Greenfield](images/greenfield_report.png)
```

---

## .gitignore Update

Ensure images are NOT ignored:

```gitignore
# Demo materials (videos, presentations)
demo/
*.mp4
*.avi
*.mov

# ALLOW documentation images
!docs/images/
!docs/images/*.png
!docs/images/*.jpg
!docs/images/*.gif
```

---

## Commit Message Template

```
Add visual proof screenshots to documentation

Screenshots added:
1. Extension BLOCK verdict - Shows real-time honeypot blocking
2. Telegram bot token scan - Shows token name/symbol feature
3. BNB Greenfield report - Shows immutable forensic storage

Locations:
- README.md: Features section (visual demonstration)
- docs/PROJECT.md: After "How It Works"
- docs/TECHNICAL.md: Demo guide section

Impact: Visual proof makes submission more compelling for judges.
Judges can see the system in action without running it themselves.
```

---

## File Checklist

Before committing, verify:

- [ ] `docs/images/extension_block.png` exists (<500KB)
- [ ] `docs/images/telegram_token_scan.png` exists (<500KB)
- [ ] `docs/images/greenfield_report.png` exists (<500KB)
- [ ] Images are clear and readable
- [ ] No sensitive data in screenshots (real addresses are OK)
- [ ] .gitignore allows `docs/images/` folder
- [ ] All markdown image links are correct

---

## Quick Test

After adding screenshots, verify they render:

1. **Local test:**
   - Open README.md in VS Code
   - Enable Markdown preview (Ctrl+Shift+V)
   - Verify images appear

2. **GitHub test:**
   - Push to GitHub
   - View README.md on GitHub
   - Verify images render correctly

---

## Image Specifications

| Screenshot | Recommended Size | Max File Size | Format |
|------------|------------------|---------------|---------|
| extension_block.png | 1920x1080 | 500KB | PNG |
| telegram_token_scan.png | 1080x1920 (mobile) | 300KB | PNG |
| greenfield_report.png | 1920x1080 | 400KB | PNG |

---

## Alternative: Use Placeholders First

If screenshots aren't ready yet, use text placeholders:

```markdown
### Visual Demonstration

> **[Screenshot: Extension BLOCK Verdict]**
> - Full-screen red modal blocking honeypot token
> - Risk Score: 85/100 HIGH RISK
> - Critical flags: Honeypot confirmed, 99% sell tax
> - Cannot proceed with transaction

> **[Screenshot: Telegram Bot Token Scan]**
> - Shows "Token: Wrapped BNB (WBNB)"
> - Risk Score: 5/100 LOW RISK
> - Comprehensive intelligence report

> **[Screenshot: BNB Greenfield Report]**
> - JSON forensic report stored on-chain
> - Public URL: greenfield-sp.bnbchain.org/view/...
> - Immutable and verifiable
```

This shows judges what exists even without the actual images.
