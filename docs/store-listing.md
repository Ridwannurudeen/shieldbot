# Chrome Web Store listing and release checklist for 3.1.0

The published listing (checked 23 September 2026) is version 3.0.1, English only, and says the
extension "blocks the transaction", offers "Tenderly pre-execution simulation" and "Permit2
signature analysis". The shipped code does none of those things from the extension, so the text
below replaces it. Everything in it is true of the 3.1.0 code in this repository.

## 1. Text to paste

**Name** (unchanged; the manifest reads it from `_locales`):

```
ShieldAI Transaction Firewall
```

**Summary** (the manifest description, 116 of 132 characters; Vietnamese and Chinese versions ship
in `extension/_locales` and appear automatically for those languages):

```
Warns before you sign on 8 EVM chains, reports Unknown when a check cannot complete, and flags known phishing sites.
```

**Description** (Store listing tab, English):

```
ShieldAI Transaction Firewall checks a transaction before your wallet asks you to sign it, and tells you plainly what it found.

When a website asks your wallet to send a transaction, the extension shows an overlay first. It decodes common calls such as approvals, transfers and swaps, shows how much of your chain's own coin you are sending, what spending rights the call grants, and the full recipient address, and gives a verdict: Safe, Caution, High Risk or Block Recommended. You choose whether to continue or cancel. The extension warns you; it does not stop you.

When a check cannot finish, for example because a data provider did not answer or a contract's age is not available, the verdict is Unknown and the overlay says why. An incomplete check is never shown as Safe.

What it covers
• Transactions on 8 EVM chains: BNB Chain, opBNB, Ethereum, Base, Arbitrum, Polygon, Optimism and Robinhood Chain.
• Wallets that give web pages a standard provider (window.ethereum or EIP-6963).
• Signature requests are shown in readable form, and typed data that looks like a spending approval (a permit) is flagged. Signatures are checked in your browser only; they are not sent to the server.
• Phishing: the address of each https site you open is checked against phishing intelligence, and a warning banner appears when the site is flagged.

Settings
• Balanced mode shows every verdict and leaves the choice to you.
• Strict mode removes the option to continue when a check fails, the verdict is Unknown, or the verdict is Block Recommended.
• English, Tiếng Việt and 中文.

Privacy
• Sent for analysis: the transaction's recipient, sender, value, call data and chain ID, and the origin (scheme, host and port) of the sites you visit, for the phishing check.
• Never collected: private keys, seed phrases, passwords or page content.
• The default server is api.shieldbotsecurity.online. You can point the extension at your own server in its settings.

Limits
• This is a warning layer, not a guarantee. A site built to evade it can hide or cover its warning, or send wallet requests where the extension cannot see them, so always read your wallet's own confirmation screen.
• It runs on https pages only, in Chrome 111 or later.
```

Do not add claims the 3.1.0 extension does not make good on: no "blocks", no simulation or asset
change claims (they depend on a server-side Tenderly key that is not confirmed), no "Permit2
analysis", no wallet approval scanning (the Health tab's approval scan returned 503 in production on
BNB Chain, Ethereum and Base on 23 September), and no wallet names until the smoke test in section 3
has passed with them.

## 2. Release checklist (owner)

1. Merge the release branches into main and run `python -m pytest -q -p no:cacheprovider`.
2. Confirm `extension/manifest.json` says `"version": "3.1.0"`. The store refuses a package whose
   version is not higher than the published 3.0.1.
3. Build the package from the `extension` folder, leaving out `screenshots/` (capture notes, not
   extension code). `manifest.json` must sit at the root of the zip. This command, run from the
   repository root, writes it with forward-slash entry names on any system:

   ```
   python -c "import pathlib, zipfile; root = pathlib.Path('extension'); z = zipfile.ZipFile('shieldbot-extension-v3.1.0.zip', 'w', zipfile.ZIP_DEFLATED); [z.write(p, p.relative_to(root).as_posix()) for p in sorted(root.rglob('*')) if p.is_file() and 'screenshots' not in p.relative_to(root).parts]; z.close()"
   ```

4. In a clean Chrome profile (Chrome 111 or later, which the manifest now requires) open
   `chrome://extensions`, turn on Developer mode, use Load unpacked
   on the `extension` folder, and check: name "ShieldAI Transaction Firewall", version 3.1.0,
   no Errors button. Then run the smoke test below.
5. Developer Dashboard, Package tab: upload the zip.
6. Store listing tab: paste the description above. Replace the screenshots with real 3.1.0 captures
   (see `extension/screenshots/CAPTURE-GUIDE.md`). Do not upload any image that shows screens the
   extension does not have, such as the light "Threat Dashboard" mock, or the promo tile that says
   v1.0.8 and BNB Chain only.
7. Privacy practices tab: `docs/CHROME_WEB_STORE_DISCLOSURE.md` still says the chain-resolution fix
   is unreleased; with 3.1.0 it ships, so update that sentence before copying from the file.
8. Submit for review. After approval, confirm the listing shows 3.1.0 and the new text, and that
   an existing 3.0.1 install updates without a "Setup Required" message.

## 3. Fifteen-minute smoke test (MetaMask, then Rabby)

Use a test wallet with a small balance on one cheap chain (BNB Chain or Base). Load 3.1.0 unpacked
with the default API. Run the list with MetaMask as the only wallet, then with Rabby as the only
wallet. Reject every wallet popup unless you mean to spend.

1. **Swap** (about 3 minutes). On PancakeSwap or Uniswap start a small swap. The overlay appears
   before the wallet: it has keyboard focus, Tab cycles its buttons, Escape rejects and the dApp
   reports a rejection. Start again, wait at least 70 seconds with the overlay open, then press
   Proceed: the wallet popup must still appear. The Sending row names the chain's coin (BNB, ETH
   or POL), never BNB on another chain.
2. **Approve** (2 minutes). Approve a token with a custom limited amount (the dApp's approval
   step or revoke.cash). Granting Access reads "Limited approval: <amount>", an unlimited approval
   reads UNLIMITED, and the Recipient row shows the full 42-character address.
3. **Permit signature** (2 minutes). Trigger a typed-data signature (a Uniswap swap that asks for a
   Permit2 signature). The overlay says APPROVAL SIGNATURE and lists the typed-data fields. Reject
   reaches the dApp as a rejection; Sign Anyway opens the wallet.
4. **Native send** (2 minutes). On https://metamask.github.io/test-dapp/ use a Send button (sends
   made inside the wallet's own UI never pass through a web page, so they are not checked). The
   overlay names the right coin and shows the full recipient.
5. **Phishing page** (1 minute). Pick a domain the API reports as phishing
   (`https://api.shieldbotsecurity.online/api/phishing?url=https://<domain>/` returns
   `"is_phishing": true`) and open it in a throwaway profile without a funded wallet. The red
   banner appears. Do not connect a wallet there.
6. **API offline** (2 minutes). In the popup set the API endpoint to `https://localhost:9` and save.
   Start a transaction: the overlay says ANALYSIS UNAVAILABLE with Block and Proceed in Balanced
   mode; switch to Strict and repeat: only Block remains, with a note on how to switch back. Restore
   the default endpoint afterwards.
7. **Popup** (2 minutes). In a fresh profile the dashboard (expand button) says Nothing checked yet,
   not PROTECTED 100. After the tests, History shows Unknown results in a grey hatched badge with a
   reason line. Arrow keys move between the popup tabs. Switch the language to Tiếng Việt and 中文:
   no raw key names (such as tabFeed) appear, and the version label reads v3.1.0.

Record for each wallet: pass or fail per step, and a screenshot of any failure.
