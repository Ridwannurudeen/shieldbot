# CWS Screenshot Capture Guide
# ShieldAI Transaction Firewall — v1.0.8

CWS requires: 1280×800 or 640×400 PNG/JPG. Max 5 screenshots + 1 promo tile.
Use 1280×800. Chrome DevTools device mode handles this easily.

---

## How to set up Chrome for screenshots

1. Load extension: chrome://extensions → Developer mode → Load unpacked → select /extension folder
2. Open Chrome DevTools (F12) → Toggle device toolbar (Ctrl+Shift+M)
3. Set custom dimensions: 1280 × 800
4. Use the DevTools screenshot: Ctrl+Shift+P → "Capture screenshot"

---

## Screenshot 1 — Transaction Block Overlay
**What to capture:** The red overlay that appears when ShieldAI blocks a HIGH RISK transaction.
**How to trigger it:**
- Visit any DApp that triggers a transaction, or temporarily lower the BLOCK threshold in settings to force a block on a test transaction
- The overlay covers the full page with the verdict, ShieldScore, and risk explanation

**CWS Caption (max 2 lines):**
> ShieldAI intercepts HIGH RISK transactions before your wallet signs them — showing the exact threat in plain English.

**Filename:** `01-transaction-block.png`

---

## Screenshot 2 — Command Center Dashboard (Full Page)
**What to capture:** The 3-column dashboard in full-page mode.
**How to trigger it:** Right-click the extension icon → "Open in new tab" OR navigate to the popup URL with ?tab=1

To get the popup URL:
1. chrome://extensions → Find ShieldAI → Details
2. Note the extension ID (e.g. abcdefghijk...)
3. Navigate to: chrome-extension://[ID]/popup.html?tab=1

**CWS Caption:**
> The Command Center dashboard gives you a live ShieldScore, scan history feed, and protection layer status at a glance.

**Filename:** `02-command-center.png`

---

## Screenshot 3 — Wallet Health Scanner
**What to capture:** The wallet health tab showing open approvals with risk scores.
**How to trigger it:** Open extension popup → Switch to the Wallet Health tab → Enter a wallet address that has existing approvals

Use a known active address with ERC-20 approvals for a realistic screenshot.

**CWS Caption:**
> The Wallet Health Scanner surfaces dangerous open token approvals ranked by risk — so you know exactly what to revoke.

**Filename:** `03-wallet-health.png`

---

## Screenshot 4 — Phishing Site Warning
**What to capture:** The warning banner/overlay ShieldAI shows when you land on a known phishing site.
**How to trigger it:**
- Use a known-flagged URL from the GoPlus phishing database (check their public list)
- Or temporarily stub the phishing check in content.js to force a warning on a test page

**CWS Caption:**
> ShieldAI flags malicious DApp sites in real time — before you connect your wallet or sign anything.

**Filename:** `04-phishing-warning.png`

---

## Screenshot 5 — Safe Transaction with Asset Delta
**What to capture:** The green overlay showing a SAFE transaction with the Tenderly simulation result — showing exactly what assets will move.
**How to trigger it:** Initiate a legitimate swap or transfer on a known-safe DApp (PancakeSwap, etc.)

The overlay should show: ShieldScore (e.g. 12), verdict SAFE, and the asset delta ("You will send X BNB, receive Y TOKEN")

**CWS Caption:**
> Even SAFE transactions show you a full asset delta preview — so you always know what will leave your wallet before you sign.

**Filename:** `05-safe-with-delta.png`

---

## Promo Tile
**File:** `promo-tile.svg` (in this folder)
**Required size:** 440×280 PNG
**Convert SVG → PNG:**
- Open promo-tile.svg in Chrome → right-click → Save as image
- Or use: https://svgconverter.app (upload, export 440×280 PNG)
- Or Figma: paste SVG, export as PNG at 1x

**Filename for upload:** `promo-tile-440x280.png`

---

## Upload order in CWS Dashboard
1. Screenshot 1 (block overlay) — strongest first impression
2. Screenshot 2 (command center dashboard)
3. Screenshot 3 (wallet health)
4. Screenshot 4 (phishing warning)
5. Screenshot 5 (safe + delta)
Promo tile: uploaded separately in the "Store listing" section

---

## CWS Description
Paste the full description from the OPTIMIZATION-OUTPUT doc into:
Developer Dashboard → Store listing → Detailed description
