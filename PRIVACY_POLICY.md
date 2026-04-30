# Privacy Policy for ShieldAI Transaction Firewall

**Effective Date:** February 16, 2026
**Last Updated:** April 30, 2026

## Overview

ShieldAI Transaction Firewall is a browser extension that provides real-time security analysis for BNB Chain transactions. This privacy policy explains what data we collect, how we use it, and your rights regarding your information.

## Information We Collect

### Transaction Metadata

When you interact with a Web3 application that initiates a transaction, ShieldAI intercepts and analyzes the following transaction data:

- **Transaction recipient address** (`to` field)
- **Transaction sender address** (`from` field)
- **Transaction value** (amount being sent)
- **Transaction data** (encoded function call data)
- **Chain ID** (blockchain network identifier)

### Phishing Check Metadata

When the firewall is enabled, ShieldAI checks the current website origin (scheme, host, and port only) against phishing intelligence so it can warn you before you interact with known malicious sites. Full URL paths and query strings are stripped before the request leaves the browser.

**IMPORTANT:** We do NOT collect, store, or transmit:
- Private keys
- Seed phrases
- Wallet passwords
- Personal identifying information
- Page contents, form data, or full browsing history

### Configuration Data

The extension stores your settings locally in your browser:

- API endpoint URL (the server address you configure for security analysis)
- Firewall enabled/disabled state
- Scan history (last 50 transactions analyzed)

## How We Use Your Information

### Local Storage Only

All configuration data and scan history are stored **locally in your browser** using Chrome's `chrome.storage.local` API. This data:

- Never leaves your device unless you explicitly configure an API endpoint
- Is not transmitted to any third party by the extension itself
- Can be cleared at any time by removing the extension

### API Communication

When the firewall analyzes a transaction:

1. Transaction metadata is sent to the configured API endpoint. The extension ships with `https://api.shieldbotsecurity.online` as the default endpoint, and you can change it in settings.
2. The API server performs security analysis (contract verification, risk scoring, threat detection)
3. Analysis results are returned to the extension and displayed to you
4. You decide whether to proceed with or block the transaction

**You control the API endpoint.** You can replace the default endpoint with your own HTTPS server, or use localhost during development.

## Data Retention

### Scan History

The extension stores a maximum of **50 transaction scans** locally in your browser. Older scans are automatically removed when this limit is reached.

You can clear scan history at any time by:
- Removing the extension
- Clearing browser extension data
- Clearing Chrome's local storage

### Configuration Settings

API endpoint and firewall settings persist until you:
- Change them in the extension popup
- Remove the extension
- Clear browser extension data

## Third-Party Services

### Configured API Endpoint

Transaction data is sent to the configured API endpoint for analysis. The default endpoint is `https://api.shieldbotsecurity.online`, and you can replace it with your own HTTPS endpoint. If you use a third-party or self-hosted endpoint, the extension does not control or have visibility into:

- What data the API server logs or retains
- How the API server uses transaction metadata
- Third-party services the API server may use

**You are responsible for reviewing the privacy policy of any non-default API service you configure.**

### No Built-In Tracking or Analytics

ShieldAI does not include:
- Google Analytics or similar tracking services
- Advertising networks
- Usage telemetry or crash reporting
- Remote logging or monitoring

## Security

### HTTPS Enforcement

The extension enforces HTTPS for all API endpoints (except `localhost` for development). This ensures:

- Encrypted communication with your API server
- Protection against man-in-the-middle attacks
- Secure transmission of transaction metadata

### Least-Privilege Permissions

The extension requests only the permissions required for transaction security analysis:

- **`storage`**: Stores settings and scan history locally in your browser
- **`permissions`**: Allows requesting user-approved API origin access at runtime via `chrome.permissions.request()`
- **`sidePanel`**: Opens the ShieldAI assistant and scanner panel
- **`tabs`**: Opens extension pages and reads the active tab URL/title only when an extension page requests the "Scan this page" workflow

The extension also includes content script access on HTTPS websites so it can detect Web3 transaction requests across dApps hosted on different domains.

The extension does **NOT** request:
- Browsing history access
- Access to sensitive browser APIs unrelated to its core security function

## Your Rights

You have the right to:

- **Access your data**: View scan history in the extension popup (History tab)
- **Delete your data**: Remove the extension to permanently delete all local data
- **Control API communication**: Enable/disable the firewall or configure a different API endpoint at any time
- **Opt-out**: Disable the firewall toggle to bypass transaction analysis

## Children's Privacy

ShieldAI is not directed to individuals under the age of 13. We do not knowingly collect personal information from children.

## Changes to This Policy

We may update this privacy policy from time to time. Changes will be reflected in the "Last Updated" date at the top of this document. Continued use of the extension after changes constitutes acceptance of the updated policy.

## Open Source

ShieldAI is open source software. You can review the code to verify our privacy practices:

**Repository:** https://github.com/Ridwannurudeen/shieldbot

## Contact Us

If you have questions or concerns about this privacy policy or ShieldAI's data practices, please contact:

**Email:** support@shieldbotsecurity.online
**GitHub Issues:** https://github.com/Ridwannurudeen/shieldbot/issues

## Compliance

This extension complies with:

- Chrome Web Store Developer Program Policies
- Chrome Extension Privacy Requirements
- General Data Protection Regulation (GDPR) principles
- California Consumer Privacy Act (CCPA) requirements

---

**By installing and using ShieldAI Transaction Firewall, you acknowledge that you have read and understood this privacy policy.**
