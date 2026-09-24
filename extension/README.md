# ShieldAI browser extension

A Chrome extension (Manifest V3, Chrome 111 or later) that shows a warning before a web page's
wallet request reaches the wallet, and waits for the user to decide. It runs on https pages only.
This file states what it does and what it does not do; `docs/store-listing.md` has the user-facing
version.

## How a request is checked

- `inject.js` runs in the page's own JavaScript world at document_start, in every frame. It wraps
  `request` on `window.ethereum` and on providers announced through EIP-6963, and also on the
  prototype that defines `request`, so calling the prototype's method on the provider is checked
  too. It takes every built-in it uses at startup, before any page script runs.
- It checks these methods: `eth_sendTransaction`, `eth_signTransaction`, `wallet_sendCalls`,
  `personal_sign`, `eth_sign`, `eth_signTypedData`, `eth_signTypedData_v1`, `eth_signTypedData_v3`
  and `eth_signTypedData_v4`. A request whose method is not a string is rejected. Other methods go
  to the wallet with the method string that was read and the page's params.
- `content.js` runs in the extension's isolated world and shows the warning in a closed shadow root.
  The two scripts share a per-document key, handed over once at document_start, and every message
  between them carries an HMAC proof made with it; the key itself is never posted.
- Transactions are sent to the API (`/api/firewall`, through `background.js`) for analysis.
  Signature requests are shown in the browser only. Typed data that is not a readable object is
  shown as UNPARSEABLE TYPED DATA at High.
- Transactions and batches are bound to the wallet's current chain: it is read before the analysis
  and again before forwarding, a mismatch rejects the request, and a forwarded request that did not
  name a chain gets the analysed one as `chainId`.
- `wallet_sendCalls` (EIP-5792): each call is analysed as one transaction and shown in turn, and the
  batch goes to the wallet only after the user continues on every call. A request whose structure
  cannot be read (a transaction that is not an object, a batch without a non-empty list of call
  objects) is shown as UNKNOWN STRUCTURE and waits for the user.

## What it guarantees while switched on

These hold in a document where the extension's scripts ran before any of the page's own code; the
second limit below is the case where they did not.

- It never passes a request it checks to the wallet without showing it to the user first. If no
  warning is on screen within 60 seconds, or the page removes it (including by replacing the root
  element), the request is rejected. `document.open()` also removes the extension's message
  listeners, so a request that was waiting on the warning is then never forwarded but never
  answered either, and later requests in that document are rejected after 60 seconds. Strict mode
  leaves no Proceed button when the analysis failed, the verdict is Unknown or Block Recommended,
  or the structure is unknown.
- A page cannot make it approve a request on the user's behalf: only real input (a trusted click or
  key press) on the warning decides, and a verdict counts only with a proof the page cannot make.
- It rejects every request it checks from a document that the page can script before the key
  handover completes: a frame whose parent is same-origin, an `about:blank` or `about:srcdoc`
  document (a frame's initial empty document is `about:blank`), or a popup whose opener is
  same-origin. No key is handed over there, and the request is rejected with "ShieldAI cannot check
  wallet requests made from this embedded frame or popup. Open the dApp in its own tab." Cross-origin
  frames and top-level pages without a same-origin opener are checked normally.

## What it does not do

- It sees only the `request` method of `window.ethereum` and EIP-6963 providers. A page that reaches
  the wallet another way is not seen: through the wallet's own messaging or internal methods instead
  of `window.ethereum`, or through the older `send` and `sendAsync` methods.
- The check runs inside the page. A page that runs its own code in a document before `inject.js`
  does there (for example in a same-origin frame it creates) can change what `inject.js` relies on,
  and the rejection described above runs in `inject.js` too, so it does not hold against a page
  that goes that far.
- A page can hide or cover the warning, or lay something over it to trick a click (clickjacking).
  The extension cannot prevent that. Users should always read the wallet's own confirmation.
- The calls of a batch are analysed one by one; how they work together, and any batch
  capabilities such as a paymaster, are not analysed.
- When the user switches it off in its settings, requests go to the wallet unchecked.

## Tests

`tests/test_extension_overlay_behaviour.py` runs `inject.js` and `content.js` in Node's `vm` against
DOM and Chrome doubles; `tests/test_extension_chain_resolution.py`, `tests/test_extension_manifest.py`
and `tests/test_extension_i18n.py` cover chain binding, the manifest and the translations. They need
Node.js on the PATH.
