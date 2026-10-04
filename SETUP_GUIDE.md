# ShieldAI extension setup

The browser extension is in [`extension/`](extension/), version 3.1.0. It needs no build step, no API key and no account.

## Load it unpacked

1. Open `chrome://extensions` and turn on Developer mode.
2. Choose Load unpacked and select the `extension/` directory of this checkout.
3. The card reads **ShieldAI Transaction Firewall 3.1.0**. Chrome warns that it cannot verify where an unpacked extension comes from; that applies to any unpacked extension.

The Chrome Web Store listing serves 3.0.1, which predates the chain-identification fix in 3.1.0. Evaluate the unpacked build.

## What you see

- **Welcome tab.** A fresh install opens it. Its Activate Protection button asks Chrome for access to https sites, which the extension already holds from its manifest, and to `localhost` and `127.0.0.1`, which are optional and only matter for a local API server.
- **Popup.** It says ShieldAI is ready with no setup needed: the API endpoint is pre-configured to `https://api.shieldbotsecurity.online` and stored on install and on every update unless you saved your own. The status line reads "Checking connection..." and then "Connected" once that server's `/api/health` answers. The popup also holds the firewall switch, the Balanced and Strict policy modes, the language, the scan history, an approval scan with its own chain selector, and a threat feed.
- **Signing overlay.** On an https page that talks to an injected wallet (`window.ethereum` or EIP-6963), a transaction or signature request shows ShieldAI's verdict **before** the wallet prompt. Declining it rejects the request, so the wallet is never asked. A signature request is the cheapest thing to try, because it moves no value. The [demo page](https://shieldbotsecurity.online/try/) sends one Robinhood Chain transaction per outcome.
- **Side panel.** "Ask ShieldBot AI" in the popup opens it, with Chat, Guardian and Scanner tabs. The assistant behind Chat can answer that it is unavailable; scanning, the firewall and the guard do not use it.

WalletConnect sessions and anything started inside the wallet are not checked. Switching the firewall off forwards requests to the wallet untouched, with the exceptions listed in the [extension README](extension/README.md#switching-it-off).

## If it does not connect

- Check the server answers: `curl https://api.shieldbotsecurity.online/api/health` returns `{"status":"ok","service":"shieldai-firewall","supported_chains":[...]}`.
- A custom endpoint goes in the popup's API Endpoint field. It must be https, or http on `localhost` or `127.0.0.1`. Saving it asks Chrome for access to that host when the extension does not already have it.

What the extension does and does not do, in detail, is in [extension/README.md](extension/README.md). Data handling is in [PRIVACY_POLICY.md](PRIVACY_POLICY.md).
