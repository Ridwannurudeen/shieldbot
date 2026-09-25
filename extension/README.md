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
- A request is checked once and a copy of it is handed to the wallet, frozen with everything in
  it, so code that runs while the wallet reads it (through a built-in the page replaced and the
  wallet calls, for example) cannot change what was approved. While that call runs, the copy is
  marked for the provider it was checked for, so a subclass's `super.request(copy)` made before its
  first `await` goes through that provider's prototypes without a second check; made after an
  `await`, it is checked again (a second warning, the safe way round). A copy handed anywhere else,
  or later, is just another request and is checked like one.
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
- Transactions and signature requests are sent to the API (`/api/firewall`, through
  `background.js`) for analysis, and the overlay shows the API's verdict. A transaction's value is
  sent as minimal 0x-hex whatever form the page wrote it in (a decimal or 0x-hex string, or a safe
  integer); a value in any other form, or not below 2^256, is not analysed, and the overlay says
  the analysis failed. A signature's overlay also
  shows what would be signed: MetaMask's legacy typed-data form (a list of fields, for
  `eth_signTypedData` and `_v1`) field by field, EIP-712 typed data by domain and message, and a
  `personal_sign` message as text. What the overlay sees for itself only raises the API's verdict:
  typed data that cannot be read is shown as UNPARSEABLE TYPED DATA at High Risk or above, and
  `eth_sign`, which signs a raw hash that can be a transaction, is always Block Recommended with a
  note saying so. A `personal_sign` message is read as MetaMask signs it: a string of hex digits,
  with or without `0x` or `0X`, is bytes (an odd count padded with a leading 0), and anything else
  is the text as written, so `12345678` is four bytes and `0x` alone is text. Rabby signs hex only
  with a lowercase `0x` prefix, so for bare hex the warning there is stricter than needed, never
  weaker. A message that is not readable text (bytes that are not UTF-8, or text with a control
  character other than a tab or a line break) is at least High Risk and shown as sent, and one of
  exactly 32 such bytes, which can be a hash a contract accepts as the user's
  signature, is Block Recommended with the same kind of note; a 32-character text message is not
  raised. The text of a `personal_sign` message and the hash of an `eth_sign` request are not
  sent, nor is the signer's address for those two methods (the API judges them by their method),
  and the legacy list of fields is not sent as typed data (the API answers a signature without
  typed data as Unknown).
- A signature is analysed on the wallet's current chain, read once when the request is made. It is
  not bound to that chain: the wallet receives it as the page sent it. When the chain cannot be read,
  the signature is not analysed, the overlay offers only Reject, and the request is rejected.
- Sign-In with Ethereum (EIP-4361): for a `personal_sign` message that says it is a sign-in message,
  `background.js` first compares the domain it claims with the host of the frame that asked,
  whatever the rest of the message looks like. The claimed domain is the text just before the first
  "wants you to sign in with your Ethereum account:", wherever it is, read as a URL, so line endings,
  a character before it, a scheme, a port, a path or a zero-width character cannot hide it. The
  frame's host comes from Chrome, as the sender of the content script's message; the page has no
  say in it, and the API receives no page origin with a firewall call, so the check is made here.
  When the domain matches, the rest is parsed in the standard's layout, every field in its order
  and form and nothing else (with no statement, a statement, or the empty statement siwe's
  `toMessage()` writes), and the `URI`'s host, when it has one, is compared too. That parse is
  stricter than the reference parser on URIs, each of which must be a URL a browser can parse, and
  looser on the address's checksum and the statement's characters. A mismatch is Block Recommended
  without asking the API, and the overlay names both domains. A message with nothing before that
  header, or with something there that is not a host, or one for this site whose rest the parse
  does not read, goes to the API and comes back Unknown. A `personal_sign` whose first parameter is
  an address and whose second is not is read as MetaMask signs it, message second; otherwise the
  message is first.
- EIP-7702: a transaction with an `authorizationList` (type 0x04) is Block Recommended and its
  overlay lists each delegate address in full, with or without the API. The API adds whether each
  delegate is a verified contract and how old it is: every delegation is Block Recommended (90 for a
  verified contract live seven days or more with no theft label, 100 for anything else), and facts
  that cannot be looked up leave the verdict Unknown. Only each authorization's address is sent,
  never its signature. An authorization list that is not a non-empty list of objects makes the
  request UNKNOWN STRUCTURE.
- Look-alike recipients (address poisoning): `content.js` keeps, in `chrome.storage.local` only, the
  last 100 recipients the user proceeded with (the recipient of a native send, or of an ERC-20
  `transfer` or `transferFrom`). A later recipient with the same first and last four hex characters
  as one of them but a different middle is shown with both addresses in full, their middles marked,
  and the verdict at least High Risk. Only a Proceed the user chose adds to the list, never an
  address a page merely asked for, and the list is never sent anywhere.
- Phishing verdicts are cached by host, a flagged site for an hour and a site not flagged for five
  minutes, in the service worker and in `chrome.storage.session` (not readable by content scripts,
  cleared when the browser closes), so a verdict outlives the worker being stopped. Only a verdict
  is kept, never a failed check, and a failed read of the session cache is tried again.
- "Why is this risky?" is offered for Caution and above and for Unknown, not on a Safe verdict.
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
  (not intersecting the viewport) for 10 seconds while its tab is showing (a hidden tab does not
  count), the request is rejected. `document.open()` also
  removes the extension's message listeners, so later checked requests in that document fail
  closed only when the 60-second timer runs out. Strict mode leaves no Proceed or Sign Anyway
  button when the analysis failed, the result is incomplete (shown as Unknown, or as High Risk with
  the reason checks are missing), the verdict is Block Recommended, the structure is unknown, or
  typed data cannot be read. A verdict the overlay raised itself (a look-alike recipient, a message
  that is not readable text) keeps Strict mode's reading of the API's result: an incomplete one
  stays without Proceed or Sign Anyway.
- When the wallet's chain cannot be read, does not match the request, or is one the API does not
  support (it refuses it as `Unsupported chain ID`), the overlay offers only Block, in Balanced and
  in Strict mode, and says why. This holds for transactions, signatures and a `wallet_sendCalls`
  batch with a call on another chain.
- On a Block Recommended overlay in Balanced mode, and on a transaction the API did not analyse (it
  could not be reached, or refused the request), Proceed or Sign Anyway counts only when held down
  for 1.5 seconds, with the pointer or with Enter or Space, by real input: a click does nothing,
  letting go early cancels, and a fill shows the progress. The half-second delay and visibility rule
  below apply when the hold starts, and the dialog must stay visible until it ends. Block and Reject
  stay a single click.
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
chain is rejected, and the chain is named in the forwarded request), a signature is rejected when
the wallet does not say which chain it is on, requests without a string
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
- A prototype's function that reads as native code is not replaced: a platform method, and also a
  bound function or a Proxy around a function stored on a prototype, whose route to the wallet is
  therefore not covered. Wallet code above it on the prototype chain is still replaced.
- Replacing a prototype's `request` cannot tell the provider from other objects: another object of
  the page that shares a base-class prototype with the provider is wrapped and checked like a
  provider when it calls that prototype's `request`, and the checked copies it receives are bound
  to itself, so it can only replay them on itself. And a page may have taken such a prototype's own
  function before the provider was wrapped (for example before a late EIP-6963 announcement); that
  function reaches the wallet unchecked.
- A provider the page announces itself can make requests too. The warning shows one request at a
  time, so the page's request replaces the warning of a real one that is waiting, and that real
  request is rejected (it fails closed; nothing is sent).
- The copy handed to the wallet is frozen. A wallet whose own request writes into the params it is
  given would fail on it and the request would be rejected (nothing sent); the release gate checks
  MetaMask and Rabby for this.
- A page can hide or cover the warning, or lay something over it to trick a click (clickjacking).
  This is made harder, not prevented: Proceed and Sign Anyway stay disabled for half a second after
  the warning appears, and count only when IntersectionObserver v2 reports the whole dialog
  visible (on screen, not covered, not made transparent, filtered or transformed) and it has
  stayed so for half a second since it last became visible. A click that does not count because
  the dialog is not visible makes the dialog say so. Users should always read the wallet's own
  confirmation.
- A page that makes the warning transparent or `visibility: hidden` without moving it out of view
  leaves the request waiting: the 10-second out-of-view rule does not apply, the fail-closed timer
  stopped when the warning appeared, and nothing is sent until the user decides or leaves the page.
- A page-wide CSS filter, for example a dark-mode filter another extension puts on the page's root
  element, makes the dialog count as altered, so its button to continue stays unavailable on that
  site.
- The calls of a batch are analysed one by one; how they work together, and any batch
  capabilities such as a paymaster, are not analysed.
- EIP-7702 authorizations a wallet signs by itself are not seen: no standard request method signs
  one (some SDKs propose `wallet_signAuthorization` or `eth_signAuthorization`, which no major wallet
  implements; MetaMask also refuses a page's `authorizationList`). Only a transaction that carries an
  `authorizationList` through the checked methods is checked.
- Sign-In with Ethereum: the scheme a message may name and its address's EIP-55 checksum (which the
  standard only recommends) are not checked, and a URI without a host (a `did:` URI, for example)
  leaves the domain as the only thing compared. The check runs in the extension only: the API, SDK
  and MCP callers get no domain check.
- The look-alike check knows only recipients the user proceeded with in this browser profile: a
  first send to a poisoned address is not warned about, a send made in the wallet's own screens is
  not recorded, and a Proceed on one call of a batch the user then blocks is recorded. Only native
  sends and ERC-20 `transfer` and `transferFrom` recipients are compared.
- The RPC proxy (`rpc/proxy.py`) does not check for look-alike recipients: nothing gives it a
  sender's recent recipients cheaply and reliably (native sends leave no logs, and explorer lists
  need a key per chain). It passes an `eth_sendTransaction`'s `authorizationList` to the same
  delegation check and never forwards that transaction: one the check did not judge high risk (an
  analyzer error, say) is refused as well. It also rejects a signed type 0x04 transaction sent with
  `eth_sendRawTransaction`, which it cannot decode (eth-account 0.11 in production).
- Blur listings are shown as HIGH RISK and Unknown. Blur Exchange's current listing (an `Order`
  with `listingsRoot` and `numberOfListings`) and its older bulk listing (`Root`) sign only a Merkle
  root of what is listed, so no price can be read, and they are judged as zero-price listings; the
  warning says "Blur listing signs only a root of its listings, so its items and price cannot be
  read before signing". Only Blur's older single `Order` (with `side`, `price` and `fees`) is judged
  on its price; any other type under Blur Exchange's domain is Unknown too.
- A Seaport order is judged only when its offer includes an NFT (item type 2 to 5). An order whose
  offer is only native coin or ERC-20 tokens (item type 0 or 1), a bid for example, is not judged
  on what it pays back.
- Typed data over 100,000 characters (a large Seaport bulk order, for example) is refused by the
  API, and the signature is shown as Unknown with the API's error as the reason.
- With the wallet on a network the API does not support, nothing can be sent or signed through the
  overlay, which offers only Block: switch networks, or switch the extension off.

## What a page can tell

A page can find out that the extension is installed, in these ways:

- The window messages between `inject.js` and `content.js` (`SHIELDAI_TX_INTERCEPT`,
  `SHIELDAI_TX_SHOWN`, `SHIELDAI_TX_VERDICT`, `SHIELDAI_UNCHECKABLE` and `SHIELDAI_LEGACY_REFUSED`)
  reach every `message` listener of the page. They carry proofs, never the key, so the page can read
  them but not make them. While a warning shows, its host element is in the page's DOM (what it
  holds is in a closed shadow root).
- The files `manifest.json` lists under `web_accessible_resources` (`overlay.css`, `welcome.html`,
  `i18n.js`, `locales/en/messages.json`, `locales/zh/messages.json` and `locales/vi/messages.json`)
  can be fetched by any https page from `chrome-extension://<extension id>/`. The ID of a Web Store
  install is the same for everyone, so a fetch that succeeds shows the extension is there. Chrome's
  `use_dynamic_url` would put them behind a per-session ID instead; it is not used.
- A wrapped provider's `request` becomes a property of the provider itself (a wallet's usually comes
  from its prototype), holding a function that is not native code, and `send` and `sendAsync` are
  replaced the same way, on the provider and its prototypes. `Object.getOwnPropertyDescriptor` or
  `Function.prototype.toString` shows the wrapper.
- When the page has no `window.ethereum` at startup, `inject.js` defines `window.ethereum` as an
  accessor (a getter and a setter) until a provider is assigned to it, and as a plain value from one
  task after that. A page can see the accessor, on a page without a wallet too.

## Translations awaiting review

The Vietnamese and Chinese texts of these keys in `extension/locales/vi` and `extension/locales/zh`
were written without a native speaker and need the owner's review before release:
`overlayEthSign`, `overlayEthSignNote`, `overlayChainNoProceed`, `siweMismatch`, `siweUnreadable`,
`overlayBtnHoldProceed`, `overlayBtnHoldSign`, `overlayHoldNote`, `overlayLookalikeTitle`,
`overlayLookalikeNote`, `overlayLookalikeNew`, `overlayLookalikePast`, `overlayDelegationTitle`,
`overlayDelegationNote`, `overlayDelegate`, `overlayDelegateUnreadable`, `overlayHashMessage`,
`overlayHashMessageNote`, `overlayOpaqueMessage`, `overlayOpaqueMessageNote`, `overlayNotes`,
`overlayHoldNoteUnchecked`, `overlayIncompleteCoverage`, `overlayExplainAnalyzing`,
`healthNoApprovals`, `healthNoApprovalsDash`, `healthScanSubtext`, `healthScanning`,
`dashDeployerBlockSub`, `step1Desc`, `scanInjectionFound`, `scanNoInjectionPatterns`.

## Tests

`tests/test_extension_overlay_behaviour.py` runs `inject.js` and `content.js` in Node's `vm` against
DOM and Chrome doubles; `tests/test_extension_signatures.py` covers signatures, sign-in messages,
delegations, look-alike recipients, the hold, the unknown-chain rule and the phishing cache there and
in `background.js`; `tests/test_extension_chain_resolution.py`, `tests/test_extension_manifest.py`
and `tests/test_extension_i18n.py` cover chain binding, the manifest and the translations. They need
Node.js on the PATH. None of them runs a real wallet: the release gate in `docs/store-listing.md`
does.
