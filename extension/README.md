# ShieldAI browser extension

A Chrome extension (Manifest V3, Chrome 111 or later) that shows a warning before a web page's
wallet request reaches the wallet, and waits for the user to decide. It runs on https pages only.
This file states what it does and what it does not do; `docs/store-listing.md` has the user-facing
version.

## How a request is checked

- `inject.js` runs in the page's own JavaScript world at document_start, in every frame. It wraps
  `request` on `window.ethereum` and on providers announced through EIP-6963, and replaces
  `request` on every prototype of the provider that defines one (up to `Object.prototype`, and
  stopping at a function that reads as native code, which is never replaced), so calling a
  prototype's method on the provider is checked too. It takes every built-in it uses at startup,
  before any page script runs.
- A request is checked once and a copy of it is handed to the wallet. While that call runs, the
  copy is marked for the provider it was checked for, so a subclass's `super.request(copy)` made
  before its first `await` goes through that provider's prototypes without a second check; made
  after an `await`, it is checked again (a second warning, the safe way round). A copy handed
  anywhere else, or later, is just another request and is checked like one.
- It checks these methods: `eth_sendTransaction`, `eth_signTransaction`, `wallet_sendCalls`,
  `personal_sign`, `eth_sign`, `eth_signTypedData`, `eth_signTypedData_v1`, `eth_signTypedData_v3`
  and `eth_signTypedData_v4`. A request whose method is not a string is rejected. Other methods go
  to the wallet as a plain `{ method, params }` object, with the method string that was read.
- `send` and `sendAsync`, the older provider methods, are replaced the same way, on the provider and
  its prototypes. A call through them is refused when any method it asks for is one of the checked
  methods above or cannot be read (a method is a string first argument, a payload object's own
  `method`, or the own `method` of each payload in an array): through the callback, as a rejected
  promise for `send(method, params)`, or by throwing for the synchronous form, and the first time a
  notice in that document says so (no buttons; it decides nothing). Other calls reach the wallet
  with their own `this` and arguments, a payload object being handed on as the copy its methods
  were read from.
- `content.js` runs in the extension's isolated world and shows the warning in a closed shadow root.
  The two scripts share a per-document key, handed over once at document_start, and every message
  between them carries an HMAC proof made with it; the key itself is never posted.
- Transactions are sent to the API (`/api/firewall`, through `background.js`) for analysis.
  Signature requests are shown in the browser only. MetaMask's legacy typed-data form (a list of
  fields, for `eth_signTypedData` and `_v1`) is shown field by field; typed data that cannot be read
  is shown as UNPARSEABLE TYPED DATA at High.
- Transactions and batches are bound to the wallet's current chain: it is read before the analysis
  and again before forwarding, a mismatch rejects the request, and a forwarded request that did not
  name a chain gets the analysed one as `chainId`.
- `wallet_sendCalls` (EIP-5792): each call is analysed as one transaction and shown in turn, and the
  batch goes to the wallet only after the user continues on every call. A request whose structure
  cannot be read (a transaction that is not an object, a batch without a non-empty list of call
  objects) is shown as UNKNOWN STRUCTURE and waits for the user. A batch with a call that names a
  chain other than the bound one is shown as UNKNOWN STRUCTURE and then rejected as a chain
  mismatch.

## What it guarantees while switched on

These hold in a document where the extension's scripts ran before any of the page's own code; the
second limit below is the case where they did not.

- It never passes a request it checks to the wallet without showing it to the user first. If no
  warning is on screen within 60 seconds, or the page removes it (including by replacing the root
  element, calling `document.open()` or moving it into another document), or keeps it out of view
  (not intersecting the viewport) for 10 seconds, the request is rejected. `document.open()` also
  removes the extension's message listeners, so later checked requests in that document fail
  closed only when the 60-second timer runs out. Strict mode leaves no Proceed or Sign Anyway
  button when the analysis failed, the verdict is Unknown or Block Recommended, the structure is
  unknown, or typed data cannot be read.
- A page cannot make it approve a request on the user's behalf: only real input (a trusted click or
  key press) on the warning decides, and a verdict counts only with a proof the page cannot make.
- It rejects every request it checks from a document that the page can script before the key
  handover completes: a frame whose parent is same-origin, an `about:blank` or `about:srcdoc`
  document (a frame's initial empty document is `about:blank`), or a popup whose opener is
  same-origin. No key is handed over there, and the request is rejected with EIP-1193 code 4100 and
  the message "ShieldAI cannot check wallet requests made from this embedded frame or popup. Open the
  dApp in its own tab." The first time, a notice in that document says so; it has no buttons and
  decides nothing. Cross-origin frames and top-level pages without a same-origin opener are checked
  normally.

## Switching it off

Switching the extension off in its settings removes the warning and the analysis: requests of the
checked kinds then go to the wallet without being shown. `inject.js` still runs, and what it does
without anyone's decision still applies: requests from frames and popups the page can script are
rejected, transactions and batches are still bound to the wallet's chain (a mismatch or an unknown
chain is rejected, and the chain is named in the forwarded request), requests without a string
method are rejected, and checked methods sent through `send` or `sendAsync` are refused. A switch
that stops the scripts altogether would need them unregistered through `chrome.scripting` (and the
`scripting` permission); that is an owner decision.

## What it does not do

- A page that reaches the wallet some other way than these methods is not seen: through the
  wallet's own messaging or internal methods, or a provider reachable only through
  `window.ethereum.providers[]` or `selectedProvider` that was not also announced through EIP-6963.
- A `window.ethereum` that replaces one `inject.js` already wrapped (the one present at startup, or
  the first one set afterwards) is not wrapped on assignment. It is checked only if it is also
  announced through EIP-6963 or its `request` comes from a prototype already replaced.
- The check runs inside the page. A page that runs its own code in a document before `inject.js`
  does there (for example in a same-origin frame it creates) can change what `inject.js` relies on,
  and the rejection described above runs in `inject.js` too, so it does not hold against a page
  that goes that far.
- A prototype's `request`, `send` or `sendAsync` that is neither writable nor configurable cannot be
  replaced; calling that prototype's function on the provider reaches the wallet unchecked.
- A prototype's function that reads as native code (a platform method, or a bound function stored
  on a prototype) is not replaced, and neither is anything above it on the prototype chain.
- Replacing a prototype's `request` cannot tell the provider from other objects: another object of
  the page that shares a base-class prototype with the provider is wrapped and checked like a
  provider when it calls that prototype's `request`, and the checked copies it receives are bound
  to itself, so it can only replay them on itself. And a page may have taken such a prototype's own
  function before the provider was wrapped (for example before a late EIP-6963 announcement); that
  function reaches the wallet unchecked.
- A provider the page announces itself can make requests too. The warning shows one request at a
  time, so the page's request replaces the warning of a real one that is waiting, and that real
  request is rejected (it fails closed; nothing is sent).
- The copy handed to the wallet is not frozen: code that runs inside the wallet's own request before
  it reads the copy could still change it. Freezing it is an owner decision, since a wallet that
  writes into `params` would then fail; it would need the release gate run again.
- A page can hide or cover the warning, or lay something over it to trick a click (clickjacking).
  This is made harder, not prevented: Proceed and Sign Anyway stay disabled for half a second after
  the warning appears, and count only once IntersectionObserver v2 has reported the whole dialog
  visible (on screen, not covered, not made transparent, filtered or transformed) without a break
  for that half second. A click that does not count because the dialog is not visible makes the
  dialog say so. Users should always read the wallet's own confirmation.
- The calls of a batch are analysed one by one; how they work together, and any batch
  capabilities such as a paymaster, are not analysed.

## Tests

`tests/test_extension_overlay_behaviour.py` runs `inject.js` and `content.js` in Node's `vm` against
DOM and Chrome doubles; `tests/test_extension_chain_resolution.py`, `tests/test_extension_manifest.py`
and `tests/test_extension_i18n.py` cover chain binding, the manifest and the translations. They need
Node.js on the PATH. None of them runs a real wallet: the release gate in `docs/store-listing.md`
does.
