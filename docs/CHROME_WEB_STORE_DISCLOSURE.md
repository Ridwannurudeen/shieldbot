# Chrome Web Store Privacy Disclosure

This document provides the exact wording to use when completing the Chrome Web Store Developer Dashboard privacy questionnaire for ShieldAI Transaction Firewall.

These are source-tree disclosures for review, not confirmation of the currently published store version. The shipped extension can analyze on BNB Chain when a dApp omits `chainId`; it does not establish Robinhood Chain or other multichain protection in that case. The chain-resolution repair is unreleased (see [TECHNICAL.md](TECHNICAL.md)).

## Privacy Practices

### Data Collection and Usage

**Question: Does this extension collect or use user data?**

**Answer:** Yes

---

### Data Types Collected

**Question: What types of data does your extension collect?**

**Answer:**
- Financial and payment information (transaction metadata only)
- Website content (limited to Web3 transaction data and site origin for phishing checks)

**Justification:**
The extension intercepts blockchain transaction data (recipient address, sender address, value, encoded function data, and chain ID) to perform security analysis and risk assessment before the user signs the transaction.
When phishing protection is enabled, the extension also checks the current site origin (scheme, host, and port only) against phishing intelligence. Full paths, query strings, and page contents are not sent.

---

### Data Usage Declaration

**Question: How is user data being used?**

**Checkboxes to select:**
- ✅ **Security and fraud prevention** - Transaction data is analyzed to detect malicious contracts, phishing attempts, and other security threats
- ✅ **Functionality** - Transaction metadata is required for the core security analysis feature

**Do NOT select:**
- ❌ Advertising or marketing
- ❌ Analytics
- ❌ Personalization

---

### Data Handling Certification

**Question: Certify your extension complies with the following:**

**Required certifications (check all):**
- ✅ The extension only uses data for purposes disclosed in the privacy policy
- ✅ The extension does not sell user data to third parties
- ✅ The extension does not use or transfer user data for purposes unrelated to the extension's core functionality
- ✅ The extension does not use or transfer user data to determine creditworthiness or for lending purposes

---

## Privacy Policy URL

**Question: Privacy policy URL**

**Answer:**
```
https://shieldbotsecurity.online/privacy.html
```

This is the URL the live store listing links. `PRIVACY_POLICY.md` in the repository only points to it.

---

## Detailed Privacy Disclosure

**Question: Describe in detail what user data your extension collects:**

**Answer (copy this verbatim):**

```
ShieldAI Transaction Firewall intercepts blockchain transaction requests from Web3 wallet extensions (such as MetaMask) to provide security analysis before users sign transactions.

DATA COLLECTED:
- Transaction recipient address (contract or wallet address)
- Transaction sender address (user's wallet address)
- Transaction value (amount of cryptocurrency being sent)
- Transaction data (encoded smart contract function call)
- Chain ID (blockchain network identifier, e.g., 56 for BNB Chain)
- Current website origin for phishing checks (for example, https://example.com/)
- Messages and text users submit to the assistant or injection scanner
- A generated chat identifier and wallet addresses supplied to optional guardian features

DATA NOT COLLECTED:
- Private keys, seed phrases, or wallet passwords
- Page contents, form data, or full browsing history
- User credentials or authentication data

STORAGE:
The browser stores settings, up to 50 transaction scan results, a generated chat identifier and up to 20 recent chat messages using chrome.storage.local. Removing the extension clears its local data, not backend records. The configured ShieldBot backend persists scan scores, findings, agent transaction history, chat messages and identifiers, subscriptions, verdict evidence and publication outbox state in SQLite. Backend retention depends on the deployed configuration and cleanup jobs; no fixed deletion period is promised here.

API COMMUNICATION:
Transaction metadata is sent to the configured API endpoint for security analysis. The extension ships with https://api.shieldbotsecurity.online as the default endpoint, and users can replace it with their own HTTPS server or localhost development server. Communication with the API uses HTTPS encryption (localhost HTTP allowed for development only).

THIRD-PARTY SERVICES:
The extension itself does not use any third-party analytics, tracking, or advertising services. The configured API endpoint may use external services for threat intelligence, phishing checks, and contract verification. The extension ships with https://api.shieldbotsecurity.online as the default endpoint, and users can replace it with their own HTTPS endpoint.
```

---

## Detailed Usage Disclosure

**Question: Describe in detail how your extension uses the collected data:**

**Answer (copy this verbatim):**

```
SECURITY ANALYSIS:
Transaction metadata is analyzed to detect security threats before users sign blockchain transactions. The analysis includes:
- Contract verification (checking if the recipient address is a known malicious contract)
- Risk scoring (calculating the likelihood of financial loss or theft)
- Threat detection (identifying phishing, honeypots, rug pulls, and other scams)
- Transaction impact analysis (decoding function calls to explain what will happen)

USER WORKFLOW:
1. User initiates a transaction in a Web3 application
2. Extension intercepts the transaction before signature
3. Transaction metadata is sent to the user-configured API endpoint via HTTPS
4. API performs security analysis and returns a risk assessment
5. Extension displays the analysis in an overlay (SAFE, CAUTION, HIGH RISK, or BLOCK RECOMMENDED)
6. User decides whether to proceed with or block the transaction based on the analysis
7. Scan result is stored locally in browser for user reference (History tab in extension popup)

DATA RETENTION:
- Local scan history: Maximum 50 transactions, automatically pruned
- Configuration settings: Persist until user changes them or removes extension
- Transaction metadata and site origins are transmitted only to the configured API endpoint for security analysis
- The backend can forward check inputs to configured RPC, intelligence and optional AI providers; removing the extension does not delete those providers' or the backend's records

SECURITY MEASURES:
- HTTPS enforcement for API communication (except localhost development)
- Least-privilege API permissions for the shipped workflows
- No remote code execution or dynamic script loading
- Open source codebase for transparency and auditability
```

---

## Permission Justifications

**Question: Justify each permission requested by your extension:**

**Answer:**

### `permissions`
**Justification:** Required to request and verify user-approved API origin access at runtime using `chrome.permissions.request()` and `chrome.permissions.contains()`.

### `storage`
**Justification:** Required to store user settings (API endpoint URL, firewall enabled/disabled state), local scan history, a generated chat identifier and recent chat messages using chrome.storage.local. API-side storage is separate, as described above.

### `sidePanel`
**Justification:** Required to open the ShieldAI assistant, wallet health, guardian alerts, and prompt-injection scanner in Chrome's side panel.

### `tabs`
**Justification:** Required to open extension pages and to read the active tab URL/title only when a popup or side panel page starts the "Scan this page" workflow. Content scripts are blocked from requesting active tab details.

---

## Optional Host Permissions

**Question: Why does your extension request optional host permissions?**

**Answer:**

```
ShieldAI uses optional_host_permissions only for local development endpoints.

When a developer configures a localhost API URL in the extension settings:
1. The extension requests permission for that local origin using chrome.permissions.request()
2. Chrome shows a permission prompt asking the user to approve access to localhost
3. If granted, the extension can make fetch() requests to the local development API
4. If denied, the extension displays an error and asks the user to reconfigure

This model provides maximum security:
- Production API calls use HTTPS
- Local HTTP access is limited to localhost and 127.0.0.1
- Permissions can be revoked at any time in chrome://extensions
- Least-privilege principle for development-only HTTP origins

Optional permissions requested:
- http://localhost/* - Allows localhost for development/testing
- http://127.0.0.1/* - Allows 127.0.0.1 for development/testing
```

---

## Content Script Host Access

**Question: Why does your extension need access to user data on websites?**

**Answer:**

```
ShieldAI must run on all HTTPS websites because Web3 applications (decentralized apps/dApps) can be hosted on any domain. The extension needs to intercept transaction requests regardless of which website the user is interacting with.

Examples of Web3 application domains:
- app.uniswap.org
- pancakeswap.finance
- opensea.io
- Any custom or newly launched dApp

The extension analyzes blockchain transaction data and the current site origin for phishing checks. It does not read, modify, or collect page contents, form data, or unrelated user interactions.

Content scripts are injected at document_start to ensure transaction interception occurs before wallet extensions process the transaction request.
```

---

## Single Purpose Description

**Question: What is the single purpose of your extension?**

**Answer:**

```
Provide real-time security analysis for BNB Chain blockchain transactions to protect users from malicious contracts, phishing attempts, and scams before they sign transactions.
```

---

## Compliance Checklist

Before submitting to Chrome Web Store, ensure:

- ✅ The privacy policy is published at https://shieldbotsecurity.online/privacy.html
- ✅ Privacy policy URL is added to manifest.json (optional but recommended)
- ✅ Extension does not use remote code execution (no `eval()`, `new Function()`, or external scripts)
- ✅ All API communication uses HTTPS (except localhost for development)
- ✅ No hardcoded HTTP endpoints or raw IP addresses in production code
- ✅ Permissions are minimized to only what's necessary
- ✅ Extension description clearly explains security analysis functionality
- ✅ Screenshots demonstrate the transaction analysis workflow
- ✅ No misleading claims about data collection or privacy practices

---

## Additional Notes for Reviewers

**If Chrome Web Store reviewers request clarification:**

1. **Why does the extension need access to all websites?**
   - Web3 applications can be hosted on any domain, and the extension must intercept transaction requests regardless of the dApp's URL.

2. **What happens to collected transaction data?**
   - Transaction metadata is sent only to the configured API endpoint for analysis. The default endpoint is https://api.shieldbotsecurity.online, and users can replace it with their own HTTPS endpoint.

3. **How can users verify privacy claims?**
   - The extension is fully open source at https://github.com/Ridwannurudeen/shieldbot. Users can audit extension requests and backend integrations; the configured backend can forward check inputs to external providers.

4. **Is blockchain transaction data considered sensitive?**
   - Yes. API communication uses HTTPS except for localhost development, and the extension does not collect wallet private keys or seed phrases. Transaction metadata is processed by the configured API; local and backend retention are separate.

---

**Last Updated:** February 22, 2026
