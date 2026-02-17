# Chrome Web Store Privacy Disclosure

This document provides the exact wording to use when completing the Chrome Web Store Developer Dashboard privacy questionnaire for ShieldAI Transaction Firewall.

## Privacy Practices

### Data Collection and Usage

**Question: Does this extension collect or use user data?**

**Answer:** Yes

---

### Data Types Collected

**Question: What types of data does your extension collect?**

**Answer:**
- Financial and payment information (transaction metadata only)
- Website content (limited to Web3 transaction data)

**Justification:**
The extension intercepts blockchain transaction data (recipient address, sender address, value, encoded function data, and chain ID) to perform security analysis and risk assessment before the user signs the transaction.

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
https://github.com/Ridwannurudeen/shieldbot/blob/main/PRIVACY_POLICY.md
```

Or if you prefer a hosted version:
```
https://raw.githubusercontent.com/Ridwannurudeen/shieldbot/main/PRIVACY_POLICY.md
```

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

DATA NOT COLLECTED:
- Private keys, seed phrases, or wallet passwords
- Personally identifiable information (PII)
- Browsing history outside of transaction analysis
- User credentials or authentication data

STORAGE:
All data is stored locally in the user's browser using chrome.storage.local API. A maximum of 50 transaction scans are retained, with older scans automatically removed. Users can clear this data at any time by removing the extension.

API COMMUNICATION:
Transaction metadata is sent to a user-configured API endpoint for security analysis. The extension does not include a default API server - users must configure their own server or use a trusted third-party service. Communication with the API uses HTTPS encryption (localhost HTTP allowed for development only).

THIRD-PARTY SERVICES:
The extension itself does not use any third-party analytics, tracking, or advertising services. However, the user-configured API endpoint may use external services for threat intelligence and contract verification. Users are responsible for reviewing the privacy policy of any API service they configure.
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
- No data is transmitted to any server operated by the extension developer

SECURITY MEASURES:
- HTTPS enforcement for API communication (except localhost development)
- Least-privilege permissions (only activeTab and storage)
- No remote code execution or dynamic script loading
- Open source codebase for transparency and auditability
```

---

## Permission Justifications

**Question: Justify each permission requested by your extension:**

**Answer:**

### `activeTab`
**Justification:** Required to inject the transaction interceptor script into Web3 application pages. This allows the extension to detect when users initiate blockchain transactions and display the security analysis overlay.

### `storage`
**Justification:** Required to store user settings (API endpoint URL, firewall enabled/disabled state) and local scan history. All data is stored locally in the user's browser using chrome.storage.local.

---

## Optional Host Permissions

**Question: Why does your extension request optional host permissions?**

**Answer:**

```
ShieldAI uses optional_host_permissions to allow users to configure their own API endpoint for transaction security analysis.

When a user configures an API URL in the extension settings:
1. The extension requests permission for that specific origin using chrome.permissions.request()
2. Chrome shows a permission prompt asking the user to approve access to that domain
3. If granted, the extension can make fetch() requests to analyze transactions
4. If denied, the extension displays an error and asks the user to reconfigure

This model provides maximum security:
- No permissions granted by default
- User explicitly approves each API endpoint
- Permissions can be revoked at any time in chrome://extensions
- Least-privilege principle - only request what's needed, when it's needed

Optional permissions requested:
- https://*/* - Allows users to configure any HTTPS API endpoint (production use)
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

The extension ONLY analyzes blockchain transaction data - it does not read, modify, or collect any other website content, form data, or user interactions.

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

- ✅ PRIVACY_POLICY.md is published and accessible via GitHub URL
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
   - Transaction metadata is sent only to the user-configured API endpoint for analysis. The extension developer does not operate any backend servers and does not receive user data.

3. **How can users verify privacy claims?**
   - The extension is fully open source at https://github.com/Ridwannurudeen/shieldbot. Users can audit the code to verify no data is sent to third parties.

4. **Is blockchain transaction data considered sensitive?**
   - Yes, which is why we enforce HTTPS communication, store data only locally, and do not collect private keys or seed phrases. Transaction metadata (addresses, values, function calls) is necessary for security analysis.

---

**Last Updated:** February 16, 2026
