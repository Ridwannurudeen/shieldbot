# ShieldAI Extension Setup Guide

## 📥 Installation & First-Time Setup

### Step 1: Install the Extension

1. Download from Chrome Web Store (or load unpacked for development)
2. Click "Add to Chrome"
3. Extension icon appears in your toolbar (shield icon 🛡️)

### Step 2: Configure Your API Server

1. **Click the extension icon** in your Chrome toolbar
2. You'll see the popup with a blue setup guide
3. **Enter your API server URL** in the "API Endpoint" field
   - Example: `https://api.shieldbot.io:8000`
   - Must be HTTPS (or localhost for development)
4. Make sure "Enable Firewall" toggle is ON (default)

### Step 3: Grant Permission

1. **Click "Save Settings"** button
2. **Chrome will immediately show a permission dialog** like this:

   ```
   ┌──────────────────────────────────────┐
   │ "ShieldAI Transaction Firewall"      │
   │  wants to:                           │
   │                                      │
   │  • Access your data on               │
   │    api.shieldbot.io                  │
   │                                      │
   │  [Deny]              [Allow]  ←──────┤ Click this!
   └──────────────────────────────────────┘
   ```

3. **Click "Allow"** - This grants permission for the extension to communicate with your API server
4. Wait 2-3 seconds for connection test

### Step 4: Verify Connection

You should see:
- ✅ Status indicator turns **green**
- ✅ Text shows: "Connected (AI active)"
- ✅ "Saved!" confirmation message appears

**You're all set!** 🎉

---

## 🚨 Troubleshooting

### "Permission denied" Error

**Cause:** You clicked "Deny" on the permission dialog

**Fix:**
1. Click "Save Settings" button again
2. When Chrome shows the permission dialog, click **"Allow"** this time

### "No API endpoint configured" Error

**Cause:** You tried to use the extension before configuring it

**Fix:**
1. Click the extension icon in your toolbar
2. Enter your API server URL
3. Click "Save Settings"
4. Click "Allow" when Chrome prompts

### "Cannot reach API" Error

**Possible causes:**
- API server is offline
- Wrong URL entered
- Network connectivity issue
- Firewall blocking connection

**Fix:**
1. Verify your API server is running
2. Check the URL is correct (no typos)
3. Test the URL in a browser: `https://your-api-url/api/health`
4. Should return JSON: `{"status": "ok", "ai_available": true}`

### Connection Timeout

**Cause:** API server is slow or unreachable

**Fix:**
1. Check your internet connection
2. Verify API server is responding: `curl https://your-api-url/api/health`
3. Check server logs for errors
4. Try a different network

---

## 🔄 Changing API Server

To switch to a different API server:

1. Open extension popup
2. Enter new API server URL
3. Click "Save Settings"
4. Click "Allow" when Chrome prompts for the new domain
5. Wait for green "Connected" status

**Note:** Each new domain requires permission approval.

---

## 🔒 Privacy & Security

### What Permissions Does This Extension Need?

**Storage:**
- Saves your API server URL and firewall on/off setting
- Stores last 50 transaction scans locally in your browser
- Never leaves your computer

**Access to Your API Server:**
- Required to send transaction data for security analysis
- You choose which server to use
- Extension only connects to the URL you configure

### What Data Is Sent to the API?

When analyzing a transaction, the extension sends:
- Transaction recipient address
- Transaction sender address (your wallet)
- Transaction value (amount)
- Transaction data (encoded function call)
- Chain ID (which blockchain)

**NOT sent:**
- Private keys or seed phrases
- Browsing history
- Personal information
- Passwords or credentials

See full privacy policy: [PRIVACY_POLICY.md](PRIVACY_POLICY.md)

---

## 💡 Tips for Best Experience

1. **Use HTTPS API servers** - More secure and required for production
2. **Keep firewall enabled** - Maximum protection against scams
3. **Check scan history** - Review past transactions in History tab
4. **Green status = protected** - If you see red status, transactions won't be analyzed

---

## 🆘 Still Need Help?

- **GitHub Issues:** https://github.com/Ridwannurudeen/shieldbot/issues
- **Email:** ridwannurudeen@gmail.com
- **Twitter:** [@Ggudman1](https://twitter.com/Ggudman1)

---

**Last Updated:** February 16, 2026
