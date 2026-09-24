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
• Strict mode removes the option to continue when a check fails, the verdict is Unknown or Block Recommended, or the extension cannot read the request or its typed data.
• Switching the extension off removes the warning, so requests go to your wallet without one. Requests from frames and popups the page can script are still rejected, the kinds of request it checks are still refused when they come through the older send and sendAsync methods, and transactions are still held to your wallet's current network.
• English, Tiếng Việt and 中文.

Privacy
• Sent for analysis: the transaction's recipient, sender, value, call data and chain ID, and the origin (scheme, host and port) of the sites you visit, for the phishing check.
• Never collected: private keys, seed phrases, passwords or page content.
• The default server is api.shieldbotsecurity.online. You can point the extension at your own server in its settings.

Limits
• This is a warning layer, not a guarantee. Always read your wallet's own confirmation screen.
• It checks the wallet requests a page makes through the standard provider's request method (window.ethereum or an EIP-6963 provider), in the page itself and in frames from other origins (an origin is a scheme, host and port). The same kinds of request sent through the older send and sendAsync methods are refused, and a short notice says so. A page that reaches your wallet another way, such as through the wallet's own messaging, is not checked.
• It rejects every wallet request it checks from a frame or popup that the page can script itself: a frame whose parent page has the same origin, a blank (about:blank) or srcdoc document, or a popup opened by a page of the same origin. It cannot keep its check private there, and a short notice says so. Open the dApp in its own tab instead.
• While it is switched on, it never passes a request it checks to your wallet without showing it to you first, and a page cannot make it approve a request for you: only your own click or key press on the warning counts, and your wallet receives exactly the request you approved. This covers the ways listed above; a page that reaches your wallet through the wallet's own internal methods or messaging is not checked at all. If no warning appears within 60 seconds, or the page takes it away, or keeps it out of view for 10 seconds while you are on the tab, the request is rejected.
• A page can still hide or cover the warning, or lay something over it to trick you into clicking (clickjacking). The extension makes this harder (continue and sign buttons wait half a second after the warning appears, and work only once the warning has been fully visible for half a second since it last became visible) but cannot fully prevent it. If the page covers or alters the warning, those buttons do nothing and the warning says why. A page that makes the warning invisible without moving it away leaves the request waiting; nothing is sent. A page-wide filter from another extension (for example a dark-mode filter) can keep the continue button unavailable on that site.
• A batch of calls (wallet_sendCalls) is checked one call at a time, each with its own warning. How the calls work together is not analysed.
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
   extension code) and `README.md`. `manifest.json` must sit at the root of the zip. This command,
   run from the repository root, writes it with forward-slash entry names on any system:

   ```
   python -c "import pathlib, zipfile; root = pathlib.Path('extension'); z = zipfile.ZipFile('shieldbot-extension-v3.1.0.zip', 'w', zipfile.ZIP_DEFLATED); [z.write(p, p.relative_to(root).as_posix()) for p in sorted(root.rglob('*')) if p.is_file() and 'screenshots' not in p.relative_to(root).parts and p.relative_to(root).as_posix() != 'README.md']; z.close()"
   ```

4. In a clean Chrome profile (Chrome 111 or later, which the manifest now requires) open
   `chrome://extensions`, turn on Developer mode, use Load unpacked
   on the `extension` folder, and check: name "ShieldAI Transaction Firewall", version 3.1.0,
   no Errors button. Then run the smoke test below. Do not upload until its release gate (steps 8
   to 19) has passed on both MetaMask and Rabby.
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

**Release gate.** Steps 8 to 19 check what the automated tests cannot: how this build's request
handling (the frozen request copies, the chain it names, the wrapped prototypes, send and
sendAsync) and its warning work with a real wallet and a real page. They have not been run yet.
All must pass on MetaMask and on Rabby before the package is uploaded.

8. **Everyday calls** (2 minutes). On a dApp, connect the wallet, see the balance, and switch the
   network from the dApp. All work as without the extension, with no ShieldAI warning.
9. **Chain** (3 minutes). Start a transaction and Proceed: the wallet shows it on the network the
   warning named. Start another, switch the network in the wallet while the warning is open, then
   Proceed: the dApp gets a rejection saying the wallet chain changed, and the wallet shows nothing.
10. **Same-origin popup** (2 minutes). From a dApp page, open another page of the same site in a
   popup (for example with `window.open` in the console) and start a transaction there: it is
   rejected with the "embedded frame or popup" message, a short notice appears, and the wallet
   shows nothing.
11. **Batch** (2 minutes). On a dApp or test page that sends `wallet_sendCalls` (for example the
   EIP-5792 section of https://metamask.github.io/test-dapp/), send a batch of two calls: one
   warning per call, in turn, and the wallet shows the batch only after both are continued.
12. **Legacy typed data** (1 minute). Trigger `eth_signTypedData_v1` (the test dApp's Sign Typed
   Data button): the warning lists each field's name, type and value, and Sign Anyway opens the
   wallet.
13. **send and sendAsync** (2 minutes). In the console of a dApp page, `ethereum.sendAsync({id: 1,
   jsonrpc: '2.0', method: 'eth_chainId'}, console.log)` answers the chain id, and a batch
   `ethereum.sendAsync([{id: 1, jsonrpc: '2.0', method: 'eth_chainId'}, {id: 2, jsonrpc: '2.0',
   method: 'eth_blockNumber'}], console.log)` answers both. With `eth_sendTransaction` in the
   payload instead, the callback gets an error, a notice appears, and the wallet shows nothing.
14. **document.open()** (1 minute). Start a transaction, and while the warning is open run
   `document.open(); document.write('replaced'); document.close()` in the console: the dApp's
   request is rejected and the wallet shows nothing.
15. **Covered warning** (3 minutes). Start a transaction, and in the console lay an element over
   the warning that lets clicks through: `const c = document.createElement('div');
   c.style.cssText = 'position:fixed;inset:0;z-index:2147483647;pointer-events:none;background:rgba(0,0,0,.01)';
   document.body.append(c)`. Proceed does nothing and the warning says the page is covering it.
   Remove the element (`c.remove()`), wait a second, and Proceed works. Repeat with an opaque cover
   (the same element with `background:#fff` and without `pointer-events:none`): press Tab until
   Proceed has focus and press Enter; nothing reaches the wallet. Remove the cover, wait a second,
   and Proceed works.
16. **Block Recommended** (1 minute). On a warning that says BLOCK RECOMMENDED (its border pulses),
   Proceed still works in Balanced mode: the pulse does not count as the page covering it.
17. **Cross-origin frame** (2 minutes). Open a dApp that runs inside a frame from another site (or
   embed one on a test page): the warning appears in the frame, and Proceed works there.
18. **Frozen requests** (with steps 8, 9, 11 and 12). The wallet receives a frozen copy of each
   request. If the wallet shows an error about a read-only or non-extensible object instead of its
   confirmation, it writes into the request; the request fails closed, and the release is blocked
   until that is resolved.
19. **Hidden tab** (2 minutes). Start a transaction, switch to another tab for 15 seconds and come
   back: the warning is still there and Proceed works. Repeat with the dApp in a cross-origin frame
   (step 17).

Record for each wallet: pass or fail per step, and a screenshot of any failure.
