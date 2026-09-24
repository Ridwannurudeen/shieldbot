/**
 * ShieldAI Content Script
 * Bridges between inject.js (page context) and background.js (service worker).
 * Shows the firewall overlay with analysis results.
 */
(function () {
  "use strict";

  // Run once per document. This flag lives in the content script's isolated
  // world, so unlike a flag on the page's window, the page cannot read it to
  // learn that the extension is installed.
  if (window.__shieldaiContentLoaded) return;
  window.__shieldaiContentLoaded = true;

  // --- i18n mini-loader (content script context, no ES module import) ---
  let _ct18n = {};
  async function _loadContentLang() {
    try {
      const { language } = await new Promise((r) =>
        chrome.storage.local.get({ language: "en" }, r)
      );
      const lang = ["en", "zh", "vi"].includes(language) ? language : "en";
      const url = chrome.runtime.getURL(`locales/${lang}/messages.json`);
      const resp = await fetch(url);
      _ct18n = await resp.json();
    } catch (_) {
      _ct18n = {};
    }
  }
  function _t(key, repl) {
    let s = _ct18n[key] !== undefined ? _ct18n[key] : key;
    if (repl) {
      Object.entries(repl).forEach(([k, v]) => {
        s = s.replace(`{${k}}`, v);
      });
    }
    return s;
  }

  // Per-document secret shared with inject.js, which runs in the page's own
  // JavaScript world. It is handed over once, below, before any page script
  // runs, and never posted: messages on the page-visible window channel carry
  // an HMAC made with it instead, which the page can see but cannot make.
  const _CHANNEL_TOKEN = crypto.randomUUID
    ? crypto.randomUUID()
    : Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

  // HMAC of `${requestId}:${purpose}` under the channel token, as 32 bytes.
  // The purpose ("intercept", "shown", "block" or "proceed") is part of the
  // input, so a proof seen for one message cannot be replayed as another.
  async function channelProof(requestId, purpose) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(_CHANNEL_TOKEN), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(`${requestId}:${purpose}`)));
  }

  // Compare a received proof with the expected one byte by byte, as inject.js
  // does.
  function sameProof(expected, received) {
    if (typeof received !== "object" || received === null) return false;
    for (let i = 0; i < 32; i++) {
      if (received[i] !== expected[i]) return false;
    }
    return true;
  }

  // Whether another script of this page can reach this document before the
  // handover below completes: a frame whose parent is same-origin, an
  // about:blank or about:srcdoc document (a frame's initial empty document is
  // about:blank), or a popup whose opener is same-origin. Such a script could
  // take the token, or pose as inject.js, so these documents get no handover
  // at all: inject.js, which applies the same rule, then holds no key and
  // rejects every wallet request it checks there.
  function reachableByPage() {
    if (window.location.protocol === "about:" || window.frameElement !== null) return true;
    const opener = window.opener;
    if (!opener) return false;
    try {
      return Boolean(opener.document);
    } catch (_) {
      // Reading a cross-origin window's document throws.
      return false;
    }
  }

  // Hand the token to inject.js. Both are manifest content scripts that run at
  // document_start, before any page script. If inject.js is already listening
  // it takes the offer and cancels the event; otherwise it asks when it starts
  // and this script answers that one request. No page script runs in between,
  // so none can see or pre-empt the exchange.
  function offerToken() {
    return !document.dispatchEvent(
      new CustomEvent("shieldai:channel", { detail: _CHANNEL_TOKEN, cancelable: true })
    );
  }
  const reachable = reachableByPage();
  if (!reachable && !offerToken()) {
    const answer = () => {
      document.removeEventListener("shieldai:channel-request", answer);
      offerToken();
    };
    document.addEventListener("shieldai:channel-request", answer);
    // inject.js asks at document_start or not at all. Stop listening once that
    // has passed, so a later request, which only a page script could send,
    // gets no answer.
    setTimeout(() => document.removeEventListener("shieldai:channel-request", answer), 0);
  }

  // inject.js says so when it rejects a request without asking the user: in
  // such a document, and for a checked method sent through send or
  // sendAsync. The messages are unsigned (a page can post them too), so all
  // they do is show the user a notice, once per kind per document; a notice
  // has no buttons and decides nothing. The frame notice is shown only where
  // this script made the same refusal decision.
  const _shownNotices = new Set();
  window.addEventListener("message", (event) => {
    if (event.source !== window || !event.data) return;
    const type = event.data.type;
    const key = type === "SHIELDAI_LEGACY_REFUSED" ? "legacyRefusedNotice"
      : type === "SHIELDAI_UNCHECKABLE" && reachable ? "uncheckableNotice" : null;
    if (key === null || _shownNotices.has(key)) return;
    _shownNotices.add(key);
    showNotice(key);
  });

  // Request ids already seen. inject.js makes a fresh random id per request,
  // so a second intercept with a seen id is the page replaying one (perhaps
  // with a harmless-looking payload) and is dropped. The id is recorded before
  // the proof is checked so a replay cannot overtake the original, and removed
  // again if the proof fails, so only proven ids stay and a page cannot flood
  // the set to push a real one out. The oldest proven ids are dropped past the
  // limit; by then their requests are long settled.
  const _seenRequests = new Set();
  const SEEN_REQUESTS_LIMIT = 100;

  // inject.js fails closed 60 seconds after it posts an intercept. A result
  // that arrives later than this is too late for the user to decide on, so it
  // gets a timed-out screen instead of a decision overlay.
  const DECISION_WINDOW_MS = 50000;

  // Listen for intercepted transactions from inject.js
  window.addEventListener("message", async (event) => {
    if (
      event.source !== window ||
      !event.data ||
      event.data.type !== "SHIELDAI_TX_INTERCEPT"
    ) {
      return;
    }

    const { requestId, tx, proof } = event.data;
    if (typeof requestId !== "string" || _seenRequests.has(requestId)) return;
    _seenRequests.add(requestId);
    // The page can post intercepts too; only inject.js can prove this one.
    if (!sameProof(await channelProof(requestId, "intercept"), proof)) {
      _seenRequests.delete(requestId);
      return;
    }
    if (_seenRequests.size > SEEN_REQUESTS_LIMIT) {
      _seenRequests.delete(_seenRequests.values().next().value);
    }
    const received = Date.now();

    // Check if extension is enabled
    const settings = await getSettings();
    if (!settings.enabled) {
      // Extension disabled — auto-proceed
      postVerdict(requestId, "proceed");
      return;
    }
    const strict = settings.policyMode === "STRICT";

    // Signing requests are analysed by the API like transactions, and shown
    // in their own overlay, next to what would be signed.
    const SIGN_ONLY_METHODS = new Set([
      "personal_sign", "eth_sign",
      "eth_signTypedData_v4", "eth_signTypedData_v3",
      "eth_signTypedData", "eth_signTypedData_v1",
    ]);
    const isSignature = Boolean(tx.signMethod) && SIGN_ONLY_METHODS.has(tx.signMethod);
    // inject.js could not read the request's structure, so there is nothing
    // to analyse: the user is told so and decides.
    if (tx.unknownStructure === true) {
      showUnknownStructureOverlay(requestId, strict, tx.wrongChain === true);
      return;
    }

    // Show loading overlay; it must be on screen before any result replaces it
    await showLoadingOverlay();

    let response;
    try {
      // Send to background for API analysis. The background worker owns the
      // API URL and its default.
      response = await chrome.runtime.sendMessage({
        type: "SHIELDAI_ANALYZE",
        tx,
      });
    } catch (err) {
      response = { error: err.message || "Extension communication error. Check extension settings." };
    }

    // A send to an address that looks like one the user sent to before, but
    // is another (address poisoning).
    const recipient = isSignature ? null : recipientOf(tx);
    const lookalike = recipient === null ? null : await pastLookalike(recipient);

    if (Date.now() - received > DECISION_WINDOW_MS) {
      showTimedOutOverlay(requestId);
    } else if (isSignature) {
      showSignatureOverlay(requestId, tx, strict, response);
    } else if (response.error) {
      // API error — show warning and let user decide
      showErrorOverlay(requestId, response.error, strict, tx, recipient, lookalike);
    } else {
      // Show analysis overlay
      showAnalysisOverlay(requestId, response.result, strict, tx, recipient, lookalike);
    }
  });

  // --- Settings ---
  function getSettings() {
    return new Promise((resolve) => {
      chrome.storage.local.get(
        { enabled: true, policyMode: "BALANCED" },
        resolve
      );
    });
  }

  // --- Overlay Management ---

  // The overlay and the phishing banner live in closed shadow roots. The page
  // sees the host element in its DOM but cannot reach, click or restyle
  // anything inside, and the stylesheet link stays out of the page's head.
  function createShadow() {
    const host = document.createElement("div");
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("link");
    style.rel = "stylesheet";
    style.href = chrome.runtime.getURL("overlay.css");
    root.appendChild(style);
    return { host, root };
  }

  // Host element of the overlay on screen, if any.
  let _overlayHost = null;

  // A page can hide the overlay, cover it or make it see-through, and lay
  // something of its own over it so a click the user means for the page lands
  // on Proceed (clickjacking). This cannot be fully prevented; two things
  // make it harder. Proceed and Sign Anyway stay disabled for half a second
  // after an overlay appears, so a click aimed at what was there before does
  // not land on them. And they count only once IntersectionObserver v2 has
  // reported the dialog visible (on screen, not covered, not made transparent,
  // filtered or transformed) without a break for that half second: the time
  // it last became visible is kept (Infinity while it is not). The
  // whole dialog is watched, not only its buttons, so the verdict text
  // cannot be covered either; and the dialog rather than the host, which
  // has no area of its own (its content is position: fixed).
  const PROCEED_DELAY_MS = 500;
  // On a Block Recommended overlay in Balanced mode, how long Proceed (or
  // Sign Anyway) must be held down.
  const HOLD_TO_CONFIRM_MS = 1500;
  let _dialogVisible = false;
  let _visibleSince = Infinity;
  let _visibilityObserver = null;

  // A dialog the page keeps out of view (not intersecting the viewport:
  // display: none, or moved off screen) this long is taken as gone, and its
  // request is rejected rather than left waiting.
  const OUT_OF_VIEW_LIMIT_MS = 10000;
  let _outOfViewTimer = null;

  // The request whose overlay is waiting for the user. inject.js stops its
  // no-verdict timeout once it knows the overlay is on screen, so a request
  // whose overlay goes away without a decision is rejected here.
  let _awaitingRequestId = null;

  // Verdicts carry a proof for their own action, never the token, so the page
  // learns nothing it could use to forge or relabel a verdict.
  function postVerdict(requestId, action) {
    channelProof(requestId, action).then((proof) => {
      window.postMessage({ type: "SHIELDAI_TX_VERDICT", requestId, action, proof }, "*");
    });
  }

  function removeOverlay() {
    if (_overlayHost) {
      _overlayHost.remove();
      _overlayHost = null;
    }
    if (_visibilityObserver) {
      _visibilityObserver.disconnect();
      _visibilityObserver = null;
    }
    if (_outOfViewTimer !== null) {
      clearTimeout(_outOfViewTimer);
      _outOfViewTimer = null;
    }
    if (_awaitingRequestId !== null) {
      const requestId = _awaitingRequestId;
      _awaitingRequestId = null;
      postVerdict(requestId, "block");
    }
  }

  function sendVerdict(requestId, action) {
    _awaitingRequestId = null;
    removeOverlay();
    postVerdict(requestId, action);
  }

  // A decision button acts only on real user input: a synthetic click from a
  // page script is an untrusted event and is ignored. Proceed also needs the
  // button enabled and the dialog visible without a break for
  // PROCEED_DELAY_MS; when it is not visible, the dialog says so rather than
  // leave a button that silently does nothing. afterProceed, when given, runs
  // once Proceed has counted.
  function onDecision(root, id, requestId, action, afterProceed) {
    const button = root.getElementById(id);
    button.addEventListener("click", (event) => {
      if (!event.isTrusted) return;
      if (action === "proceed") {
        if (button.disabled) return;
        if (!_dialogVisible) {
          root.getElementById("shieldai-covered").textContent = _t("overlayCoveredNote");
          return;
        }
        if (Date.now() - _visibleSince < PROCEED_DELAY_MS) return;
      }
      sendVerdict(requestId, action);
      if (afterProceed) afterProceed();
    });
  }

  // Proceed on a Block Recommended overlay counts only when held down for
  // HOLD_TO_CONFIRM_MS, with the primary pointer's main button or with a new
  // press of Enter or Space, by real input; a click alone does nothing, and
  // letting go early cancels. The
  // click's rules apply when the hold starts, and the dialog must stay visible
  // until it ends.
  function onHold(root, requestId, afterProceed) {
    const button = root.getElementById("shieldai-proceed");
    let timer = null;
    const cancel = () => {
      clearTimeout(timer);
      timer = null;
      button.classList.remove("shieldai-holding");
    };
    const start = (event) => {
      if (!event.isTrusted || timer !== null || button.disabled) return;
      if (!_dialogVisible) {
        root.getElementById("shieldai-covered").textContent = _t("overlayCoveredNote");
        return;
      }
      if (Date.now() - _visibleSince < PROCEED_DELAY_MS) return;
      const startedAt = Date.now();
      button.classList.add("shieldai-holding");
      timer = setTimeout(() => {
        cancel();
        // The overlay was replaced or removed during the hold.
        if (_awaitingRequestId !== requestId) return;
        if (!_dialogVisible || _visibleSince > startedAt) {
          root.getElementById("shieldai-covered").textContent = _t("overlayCoveredNote");
          return;
        }
        sendVerdict(requestId, "proceed");
        if (afterProceed) afterProceed();
      }, HOLD_TO_CONFIRM_MS);
    };
    const holdKey = (event) => event.key === "Enter" || event.key === " ";
    button.addEventListener("pointerdown", (event) => {
      if (event.button === 0 && event.isPrimary) start(event);
    });
    button.addEventListener("keydown", (event) => {
      if (holdKey(event) && !event.repeat) start(event);
    });
    button.addEventListener("keyup", (event) => {
      if (holdKey(event)) cancel();
    });
    for (const type of ["pointerup", "pointerleave", "pointercancel", "blur"]) {
      button.addEventListener(type, cancel);
    }
  }

  // Show an overlay as a modal dialog in its own closed shadow root: focus
  // moves into it and Tab stays in it. For a decision overlay, Escape rejects,
  // and inject.js is told the user now holds the decision so it waits instead
  // of timing out. Returns the shadow root, the only way to reach the overlay.
  function mountOverlay(overlay, requestId) {
    const { host, root } = createShadow();
    root.appendChild(overlay);
    const modal = overlay.querySelector(".shieldai-modal");
    overlay.tabIndex = -1;
    overlay.addEventListener("keydown", (event) => {
      if (!event.isTrusted) return;
      if (event.key === "Escape" && requestId) {
        event.preventDefault();
        sendVerdict(requestId, "block");
      } else if (event.key === "Tab") {
        event.preventDefault();
        const buttons = Array.from(modal.querySelectorAll("button:not([disabled])"));
        if (!buttons.length) return;
        const index = buttons.indexOf(root.activeElement);
        const next = event.shiftKey
          ? (index <= 0 ? buttons.length : index) - 1
          : (index + 1) % buttons.length;
        buttons[next].focus();
      }
    });
    // Focus that leaves the overlay (for example from a button that becomes
    // disabled) returns to the dialog, so Tab and Escape keep working.
    overlay.addEventListener("focusout", (event) => {
      if (!overlay.contains(event.relatedTarget)) modal.focus();
    });
    (document.body || document.documentElement).appendChild(host);
    _overlayHost = host;
    const proceed = root.getElementById("shieldai-proceed");
    if (proceed) {
      proceed.disabled = true;
      setTimeout(() => {
        proceed.disabled = false;
      }, PROCEED_DELAY_MS);
    }
    _dialogVisible = false;
    _visibleSince = Infinity;
    _visibilityObserver = new IntersectionObserver((entries) => {
      if (_overlayHost !== host) return;
      const entry = entries[entries.length - 1];
      // The observer reports changes only, so a cover shows up as one entry
      // when it starts and one when it ends: the half second counts from the
      // end.
      const visible = entry.isVisible === true;
      if (!visible) _visibleSince = Infinity;
      else if (!_dialogVisible) _visibleSince = Date.now();
      _dialogVisible = visible;
      if (entry.isIntersecting !== false) {
        clearTimeout(_outOfViewTimer);
        _outOfViewTimer = null;
      } else if (_outOfViewTimer === null) {
        _outOfViewTimer = setTimeout(function outOfView() {
          if (_overlayHost !== host) return;
          // A hidden tab shows nothing: wait until the user is back on it.
          if (document.visibilityState !== "visible") {
            _outOfViewTimer = setTimeout(outOfView, OUT_OF_VIEW_LIMIT_MS);
            return;
          }
          removeOverlay();
        }, OUT_OF_VIEW_LIMIT_MS);
      }
    }, { trackVisibility: true, delay: 100 });
    _visibilityObserver.observe(modal);
    // If the page removes the overlay, the user can no longer decide here:
    // reject the request so the dApp is not left waiting. The whole document
    // is watched, so replacing the root element or document.open() counts.
    // document.contains, not isConnected: the page could move the host into
    // another document, where it would still count as connected.
    const observer = new MutationObserver(() => {
      if (document.contains(host)) return;
      observer.disconnect();
      if (_overlayHost === host) removeOverlay();
    });
    observer.observe(document, { childList: true, subtree: true });
    modal.focus();
    if (requestId) {
      _awaitingRequestId = requestId;
      channelProof(requestId, "shown").then((proof) => {
        window.postMessage({ type: "SHIELDAI_TX_SHOWN", requestId, proof }, "*");
      });
    }
    return root;
  }

  // One line saying why a result is Unknown, from its coverage reasons.
  function unknownReason(result) {
    return Object.values(result.coverage_reasons || {}).filter(Boolean).join("; ") ||
      _t("unknownNoReason");
  }

  // The class a result is shown as. One that is not complete is Unknown,
  // never Safe or Caution; High Risk and Block Recommended stay.
  function verdictOf(result) {
    const incomplete = result.status !== "ok" || result.partial === true ||
      result.risk_level === "UNKNOWN" || result.classification === "UNKNOWN" ||
      !Number.isFinite(result.risk_score) ||
      Object.values(result.coverage || {}).some(value => Number(value) < 1);
    const classification = incomplete && !["HIGH_RISK", "BLOCK_RECOMMENDED"].includes(result.classification)
      ? "UNKNOWN" : result.classification || "CAUTION";
    return { incomplete, classification };
  }

  // Classes from least to most severe. What the overlay sees for itself only
  // raises the API's verdict, never lowers it.
  const SEVERITY = ["SAFE", "CAUTION", "UNKNOWN", "HIGH_RISK", "BLOCK_RECOMMENDED"];
  function atLeast(classification, floor) {
    return SEVERITY.indexOf(floor) > SEVERITY.indexOf(classification) ? floor : classification;
  }

  const BADGE_CLASSES = {
    BLOCK_RECOMMENDED: "shieldai-badge-block",
    HIGH_RISK: "shieldai-badge-high",
    CAUTION: "shieldai-badge-caution",
    SAFE: "shieldai-badge-safe",
    UNKNOWN: "shieldai-badge-unknown",
  };

  function classLabel(classification) {
    const labels = {
      BLOCK_RECOMMENDED: _t("classBlock"),
      HIGH_RISK: _t("classHighRisk"),
      CAUTION: _t("classCaution"),
      SAFE: _t("classSafe"),
      UNKNOWN: _t("classUnknown"),
    };
    return labels[classification] || classification;
  }

  // For one call of a wallet_sendCalls batch, which call it is. inject.js
  // shows the calls one after another and sends the batch only when the user
  // continues on every one.
  function batchNote(tx) {
    if (!tx.callCount) return "";
    const note = _t("overlayBatchCall", { index: tx.callIndex, count: tx.callCount });
    return `<div class="shieldai-section shieldai-sig-note"><p>${escapeHtml(note)}</p></div>`;
  }

  // The address a transaction sends to: the recipient of a native send (no
  // call data), or of an ERC-20 transfer or transferFrom, in lower case; null
  // for any other call.
  function recipientOf(tx) {
    const data = String(tx.data || "0x").toLowerCase();
    if (data === "0x") {
      return typeof tx.to === "string" && /^0x[0-9a-f]{40}$/i.test(tx.to) ? tx.to.toLowerCase() : null;
    }
    const call = /^0xa9059cbb0{24}([0-9a-f]{40})[0-9a-f]{64}$/.exec(data) ||
      /^0x23b872dd0{24}[0-9a-f]{40}0{24}([0-9a-f]{40})[0-9a-f]{64}$/.exec(data);
    return call ? `0x${call[1]}` : null;
  }

  // Recipients the user proceeded with, newest first, kept in this browser
  // only (chrome.storage.local, never sent anywhere) and capped. A page adds
  // none: only a Proceed the user chose does.
  const MAX_SENT_RECIPIENTS = 100;

  function rememberRecipient(recipient) {
    chrome.storage.local.get({ sentRecipients: [] }, ({ sentRecipients }) => {
      chrome.storage.local.set({
        sentRecipients: [recipient, ...sentRecipients.filter((past) => past !== recipient)]
          .slice(0, MAX_SENT_RECIPIENTS),
      });
    });
  }

  // A past recipient with the same first and last four hex characters as this
  // one but another middle, or null; none when the user has sent to this very
  // address before.
  function pastLookalike(recipient) {
    return new Promise((resolve) => {
      chrome.storage.local.get({ sentRecipients: [] }, ({ sentRecipients }) => {
        resolve(sentRecipients.includes(recipient) ? null : sentRecipients.find((past) =>
          past.slice(2, 6) === recipient.slice(2, 6) && past.slice(-4) === recipient.slice(-4)) || null);
      });
    });
  }

  // An EIP-7702 transaction's delegates, from the request itself: its
  // account's code would become theirs.
  function delegationSection(tx) {
    if (!Array.isArray(tx.authorizationList)) return "";
    const rows = tx.authorizationList.map((authorization) => {
      const address = typeof authorization.address === "string" ? authorization.address : _t("overlayDelegateUnreadable");
      return `<tr><td>${_t("overlayDelegate")}</td><td class="shieldai-mono">${escapeHtml(address)}</td></tr>`;
    }).join("");
    return `
      <div class="shieldai-section shieldai-delegation" role="alert">
        <h3>${_t("overlayDelegationTitle")}</h3>
        <p>${_t("overlayDelegationNote")}</p>
        <table class="shieldai-impact">${rows}</table>
      </div>`;
  }

  // Both addresses in full, the middle of each marked, so the difference shows.
  function lookalikeSection(recipient, past) {
    if (!past) return "";
    const marked = (address) => `${escapeHtml(address.slice(0, 6))}<mark class="shieldai-diff">` +
      `${escapeHtml(address.slice(6, -4))}</mark>${escapeHtml(address.slice(-4))}`;
    return `
      <div class="shieldai-section shieldai-lookalike" role="alert">
        <h3>${_t("overlayLookalikeTitle")}</h3>
        <p>${_t("overlayLookalikeNote")}</p>
        <table class="shieldai-impact">
          <tr><td>${_t("overlayLookalikeNew")}</td><td class="shieldai-mono">${marked(recipient)}</td></tr>
          <tr><td>${_t("overlayLookalikePast")}</td><td class="shieldai-mono">${marked(past)}</td></tr>
        </table>
      </div>`;
  }

  // Where a decision dialog says why a Proceed did nothing: the page is
  // covering or altering it. Empty (and not shown) until then.
  const COVERED_NOTE = `<p class="shieldai-covered-note" id="shieldai-covered" role="alert"></p>`;

  async function showLoadingOverlay() {
    await _loadContentLang();
    removeOverlay();

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";
    overlay.innerHTML = `
      <div class="shieldai-modal" role="dialog" aria-modal="true" aria-labelledby="shieldai-title" aria-busy="true" tabindex="-1">
        <div class="shieldai-header">
          <div class="shieldai-logo" aria-hidden="true">&#128737;</div>
          <h2 id="shieldai-title">${_t("overlayTitle")}</h2>
        </div>
        <div class="shieldai-loading">
          <div class="shieldai-spinner"></div>
          <p>${_t("overlayAnalyzing")}</p>
          <p class="shieldai-subtext">${_t("overlaySubtext")}</p>
        </div>
      </div>
    `;
    mountOverlay(overlay);
  }

  // --- Helpers ---

  function hexToUtf8(hex) {
    try {
      const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
      if (!clean) return null;
      const bytes = new Uint8Array(clean.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (_) {
      return null;
    }
  }

  // The text a signed message says, read as MetaMask reads it: a string of
  // hex digits, with or without 0x, is bytes (an odd count padded with a
  // leading 0) decoded as UTF-8, and any other string is signed as written.
  // null when it is not readable text: not a string, bytes that are not
  // UTF-8, or text holding a control character other than a tab or a line
  // break.
  function readableText(data) {
    if (typeof data !== "string") return null;
    const digits = data.replace(/^0x/i, "");
    const text = /^[0-9a-f]+$/i.test(digits) ? hexToUtf8(digits.length % 2 ? `0${digits}` : digits) : data;
    return text !== null && !/(?![\t\n\r])\p{Cc}/u.test(text) ? text : null;
  }

  // Typed data the overlay can show: a plain object whose domain and message,
  // when present, are plain objects and whose primaryType, when present, is a
  // string.
  function isReadableTypedData(typedData) {
    return isPlainObject(typedData) &&
      (typedData.domain === undefined || isPlainObject(typedData.domain)) &&
      (typedData.message === undefined || isPlainObject(typedData.message)) &&
      (typedData.primaryType === undefined || typeof typedData.primaryType === "string");
  }

  // The legacy form eth_signTypedData and _v1 take in MetaMask: a list of
  // fields, each with a string name and type, and a value.
  function isLegacyTypedData(typedData) {
    return Array.isArray(typedData) && typedData.every((field) =>
      isPlainObject(field) && typeof field.name === "string" && typeof field.type === "string");
  }

  function isPlainObject(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
  }

  function shortAddr(addr) {
    if (!addr || addr.length < 10) return addr || "";
    return addr.slice(0, 6) + "..." + addr.slice(-4);
  }

  function isAddressLikeSegment(value) {
    return /^0x[a-fA-F0-9]{40}$/.test(value) || /^0x[a-fA-F0-9]{4,}\.\.\.[a-fA-F0-9]{4}$/.test(value);
  }

  function isAddressParam(label, value) {
    const labelText = String(label || "").toLowerCase();
    const valueText = String(value || "").trim();
    if (!valueText) return false;

    if (
      ["address", "spender", "recipient", "owner", "from", "to", "router", "contract", "path"].some((term) =>
        labelText.includes(term)
      )
    ) {
      return true;
    }

    if (isAddressLikeSegment(valueText)) {
      return true;
    }

    if (valueText.includes("→")) {
      return valueText.split("→").every((part) => isAddressLikeSegment(part.trim()));
    }

    return false;
  }

  function buildCalldataSection(calldataDetails) {
    const fields = Array.isArray(calldataDetails?.fields) ? calldataDetails.fields : [];
    if (!fields.length) {
      return "";
    }

    const functionField = fields.find((field) => String(field?.label || "").toLowerCase() === "function");
    const functionName = functionField?.value ? String(functionField.value) : "";
    const params = fields.filter((field) => String(field?.label || "").toLowerCase() !== "function");
    const paramsHtml = params.length
      ? params
          .map((field) => {
            const value = field?.value == null ? "Unknown" : String(field.value);
            const valueClasses = [
              "shieldai-calldata-param-value",
              field?.danger ? "shieldai-calldata-danger" : "",
              isAddressParam(field?.label, value) ? "shieldai-calldata-address" : "",
            ]
              .filter(Boolean)
              .join(" ");

            return `
              <div class="shieldai-calldata-param">
                <div class="shieldai-calldata-param-name">${escapeHtml(field?.label || "Parameter")}</div>
                <div class="${valueClasses}">${escapeHtml(value)}</div>
              </div>
            `;
          })
          .join("")
      : `<div class="shieldai-calldata-param">
           <div class="shieldai-calldata-param-name">${_t("overlayNoFields")}</div>
           <div class="shieldai-calldata-param-value">-</div>
         </div>`;

    return `
      <div class="shieldai-section shieldai-calldata-section">
        <button
          type="button"
          class="shieldai-calldata-toggle"
          id="shieldai-calldata-toggle"
          aria-expanded="true"
          aria-controls="shieldai-calldata-body"
        >
          <span class="shieldai-calldata-toggle-label">${_t("overlayDecodedCalldata")}</span>
          <span class="shieldai-calldata-chevron" aria-hidden="true">▾</span>
        </button>
        <div class="shieldai-calldata-body" id="shieldai-calldata-body">
          ${functionName ? `<div class="shieldai-calldata-fn">${escapeHtml(functionName)}</div>` : ""}
          ${paramsHtml}
        </div>
      </div>
    `;
  }

  // --- Signature Request Overlay ---
  // Shown instead of the firewall overlay for personal_sign / eth_signTypedData
  // etc., with the API's verdict on it, or its error.

  async function showSignatureOverlay(requestId, tx, strict, response) {
    await _loadContentLang();
    removeOverlay();

    const signMethod = tx.signMethod || "personal_sign";
    const isLegacy = signMethod === "eth_signTypedData" || signMethod === "eth_signTypedData_v1";
    const isTyped = isLegacy || signMethod === "eth_signTypedData_v4" || signMethod === "eth_signTypedData_v3";
    const isPersonal = signMethod === "personal_sign" || signMethod === "eth_sign";
    const legacyFields = isLegacy && isLegacyTypedData(tx.typedData);
    // Typed data that cannot be read is shown as such, at High: the user
    // cannot see what they would sign. Strict mode leaves no Sign Anyway.
    const unparseable = isTyped && !legacyFields && !isReadableTypedData(tx.typedData);

    let bodyHtml = "";
    let isPermitLike = false;
    // A personal_sign whose message is not readable text hides what is
    // signed, and 32 bytes of it can be a hash (an order's, a permit's) that a
    // contract accepts through toEthSignedMessageHash, as eth_sign's can.
    let opaque = false;
    let opaqueHash = false;

    if (legacyFields) {
      const rows = tx.typedData.map((field) => {
        let display = typeof field.value === "object" ? JSON.stringify(field.value) : String(field.value);
        if (display.length > 80) display = display.slice(0, 77) + "...";
        return `<tr><td>${escapeHtml(field.name)}</td><td>${escapeHtml(field.type)}</td><td>${escapeHtml(display)}</td></tr>`;
      }).join("");
      bodyHtml = `
        <div class="shieldai-section">
          <h3>${_t("overlayMessage")}</h3>
          <table class="shieldai-impact">${rows || `<tr><td colspan='3'>${_t("overlayNoFields")}</td></tr>`}</table>
        </div>
      `;
    } else if (isTyped && !unparseable) {
      const td = tx.typedData;
      const domain = td.domain || {};
      const primaryType = td.primaryType || "Unknown";
      const message = td.message || {};

      // Detect Permit / approval-style signatures
      const ptLower = primaryType.toLowerCase();
      isPermitLike =
        ptLower.includes("permit") ||
        ptLower.includes("approve") ||
        "spender" in message ||
        "allowed" in message;

      // Domain rows
      const domainRows = [];
      if (domain.name) domainRows.push(`<tr><td>Protocol</td><td>${escapeHtml(domain.name)}</td></tr>`);
      if (domain.verifyingContract) domainRows.push(`<tr><td>Contract</td><td class="shieldai-mono">${escapeHtml(shortAddr(domain.verifyingContract))}</td></tr>`);
      if (domain.chainId !== undefined) domainRows.push(`<tr><td>Chain ID</td><td>${escapeHtml(String(domain.chainId))}</td></tr>`);

      // Message rows (up to 8 fields)
      const msgRows = Object.entries(message)
        .slice(0, 8)
        .map(([k, v]) => {
          let display = typeof v === "object" ? JSON.stringify(v) : String(v);
          if (display.length > 80) display = display.slice(0, 77) + "...";
          return `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(display)}</td></tr>`;
        })
        .join("");

      bodyHtml = `
        ${domainRows.length ? `
          <div class="shieldai-section">
            <h3>${_t("overlayDomain")}</h3>
            <table class="shieldai-impact">${domainRows.join("")}</table>
          </div>` : ""}
        <div class="shieldai-section">
          <h3>${_t("overlayType") || "Type:"} ${escapeHtml(primaryType)}</h3>
          <table class="shieldai-impact">${msgRows || `<tr><td colspan='2'>${_t("overlayNoFields")}</td></tr>`}</table>
        </div>
      `;
    } else if (isPersonal) {
      // The message as the wallet signs it; one that is not readable text is
      // shown as it was sent.
      const raw = tx.data || "";
      const decoded = readableText(raw);
      const display = decoded === null ? String(raw) : decoded;
      const isBinary = decoded === null && String(raw).length > 2;
      opaque = signMethod === "personal_sign" && decoded === null;
      // 63 or 64 hex digits, with or without 0x, are the 32 bytes the wallet signs.
      opaqueHash = opaque && typeof raw === "string" && /^(0x)?[0-9a-f]{63,64}$/i.test(raw);

      bodyHtml = `
        <div class="shieldai-section">
          <h3>${_t("overlayMessage")}</h3>
          <div class="shieldai-sig-message ${isBinary ? "shieldai-sig-binary" : ""}">${escapeHtml(display)}</div>
        </div>
      `;
    }

    // The verdict is the API's, and Unknown when the API could not be
    // reached. What the overlay sees for itself only raises it: typed data it
    // cannot read, and a personal_sign message that is not readable text, are
    // at least High Risk; eth_sign, which signs a raw hash that can be a
    // transaction, and a personal_sign of 32 bytes that are not text, are
    // Block Recommended.
    const result = response.result;
    const { incomplete, classification: verdict } = result
      ? verdictOf(result) : { incomplete: true, classification: "UNKNOWN" };
    const ethSign = signMethod === "eth_sign";
    const classification = ethSign || opaqueHash ? atLeast(verdict, "BLOCK_RECOMMENDED")
      : unparseable || opaque ? atLeast(verdict, "HIGH_RISK") : verdict;
    const why = response.error ? `${_t("overlayCannotReach")} ${response.error}` : incomplete ? unknownReason(result) : "";
    // A signature whose chain could not be read, or is not supported, was
    // not analysed, and inject.js rejects it: there is no Sign Anyway.
    const chainUnknown = Boolean(result) && (result.coverage || {}).chain === false;
    const canSign = !chainUnknown &&
      !(strict && (unparseable || classification === "UNKNOWN" || classification === "BLOCK_RECOMMENDED"));
    const hold = canSign && classification === "BLOCK_RECOMMENDED";
    // What background.js found in a Sign-In with Ethereum message leads.
    const signIn = (result && result.siwe) || {};
    const signInSignals = signIn.state === "mismatch"
      ? [_t("siweMismatch", { domain: signIn.domain, origin: signIn.origin })]
      : signIn.state === "unreadable" ? [_t("siweUnreadable")] : [];
    const signalsHtml = [...signInSignals, ...((result && result.danger_signals) || [])]
      .map((s) => `<li>${escapeHtml(s)}</li>`)
      .join("");

    const label = ethSign ? _t("overlayEthSign") : opaqueHash ? _t("overlayHashMessage")
      : opaque ? _t("overlayOpaqueMessage") : unparseable ? _t("overlayUnparseableTyped")
      : isPermitLike ? _t("overlayApprovalSig") : _t("overlaySigRequest");
    const note = ethSign ? _t("overlayEthSignNote") : opaqueHash ? _t("overlayHashMessageNote")
      : opaque ? _t("overlayOpaqueMessageNote") : unparseable ? _t("overlayUnparseableTypedNote")
      : isPermitLike ? _t("overlayApprovalNote") : _t("overlaySigNote");

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";
    overlay.innerHTML = `
      <div class="shieldai-modal ${classification === "BLOCK_RECOMMENDED" ? "shieldai-modal-danger" : ""}" role="dialog" aria-modal="true" aria-labelledby="shieldai-title" tabindex="-1">
        <div class="shieldai-header">
          <div class="shieldai-logo" aria-hidden="true">&#128737;</div>
          <h2 id="shieldai-title">${_t("overlayTitle")}</h2>
        </div>

        <div class="shieldai-badge ${BADGE_CLASSES[classification] || "shieldai-badge-caution"}">${escapeHtml(classLabel(classification))}</div>
        ${why ? `<p class="shieldai-unknown-why">${_t("unknownWhy")} ${escapeHtml(why)}</p>` : ""}

        <div class="shieldai-section shieldai-sig-note">
          <h3>${label}</h3>
          <p>${escapeHtml(note)}</p>
        </div>

        ${signalsHtml ? `
          <div class="shieldai-section">
            <h3>${_t("overlayDangerSignals")}</h3>
            <ul class="shieldai-signals">${signalsHtml}</ul>
          </div>` : ""}

        ${bodyHtml}

        <div class="shieldai-actions">
          <button class="shieldai-btn shieldai-btn-block" id="shieldai-block">${_t("overlayBtnReject")}</button>
          ${!canSign ? "" : hold
            ? `<button class="shieldai-btn shieldai-btn-proceed shieldai-btn-hold" id="shieldai-proceed" aria-describedby="shieldai-hold-note">${_t("overlayBtnHoldSign")}</button>`
            : `<button class="shieldai-btn shieldai-btn-proceed" id="shieldai-proceed">${_t("overlayBtnSignAnyway")}</button>`}
        </div>
        ${hold ? `<p class="shieldai-hold-note" id="shieldai-hold-note">${_t("overlayHoldNote")}</p>` : ""}
        ${COVERED_NOTE}
        ${canSign ? "" : `<p class="shieldai-strict-note">${chainUnknown ? _t("overlayChainNoProceed") : _t("overlayStrictNoProceed")}</p>`}
      </div>
    `;

    const root = mountOverlay(overlay, requestId);
    onDecision(root, "shieldai-block", requestId, "block");
    if (hold) {
      onHold(root, requestId);
    } else if (canSign) {
      onDecision(root, "shieldai-proceed", requestId, "proceed");
    }
  }

  async function showAnalysisOverlay(requestId, result, strict, tx, recipient, lookalike) {
    await _loadContentLang();
    removeOverlay();

    const { incomplete, classification: verdict } = verdictOf(result);
    // An EIP-7702 delegation is Block Recommended, and a look-alike recipient
    // at least High Risk, whatever the API found.
    const classification = Array.isArray(tx.authorizationList) ? "BLOCK_RECOMMENDED"
      : lookalike ? atLeast(verdict, "HIGH_RISK") : verdict;
    const badgeClass = BADGE_CLASSES[classification] || "shieldai-badge-caution";
    const label = classLabel(classification);
    const isBlock = classification === "BLOCK_RECOMMENDED";
    // The wallet's chain could not be read, does not match the request, or is
    // not one the API supports: nothing was analysed, and there is no Proceed.
    const chainUnknown = (result.coverage || {}).chain === false;
    // Strict mode leaves no way to send a transaction the firewall recommends
    // blocking or could not fully check.
    const canProceed = !chainUnknown && !(strict && (isBlock || verdict === "UNKNOWN"));
    // On Block Recommended (so Balanced mode), Proceed needs a hold.
    const hold = canProceed && isBlock;

    // Display as safety score (100 - risk) so higher = better
    const scoreDisplay = incomplete ? "Unknown (incomplete provider coverage)" :
      `${_t("overlaySafety")} ${100 - result.risk_score}/100`;

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";

    // Danger signals HTML
    const signalsHtml = (result.danger_signals || [])
      .map((s) => `<li>${escapeHtml(s)}</li>`)
      .join("");

    // Transaction impact HTML
    const impact = result.transaction_impact || {};

    // Asset delta HTML (simulated token in/out)
    const assetDelta = result.asset_delta || [];
    const deltaHtml = assetDelta.length
      ? `<div class="shieldai-section">
           <h3>${_t("overlayAssetDelta")} <span class="shieldai-sim-badge">${_t("overlaySimulated")}</span></h3>
           <ul class="shieldai-delta-list">
             ${assetDelta.map((d) => {
               const isOut = d.startsWith("-");
               return `<li class="${isOut ? "shieldai-delta-out" : "shieldai-delta-in"}">${escapeHtml(d)}</li>`;
             }).join("")}
           </ul>
         </div>`
      : "";
    const calldataHtml = buildCalldataSection(result.calldata_details);

    overlay.innerHTML = `
      <div class="shieldai-modal ${isBlock ? "shieldai-modal-danger" : ""}" role="dialog" aria-modal="true" aria-labelledby="shieldai-title" tabindex="-1">
        <div class="shieldai-header">
          <div class="shieldai-logo" aria-hidden="true">&#128737;</div>
          <h2 id="shieldai-title">${_t("overlayTitle")}</h2>
        </div>

        <div class="shieldai-badge ${badgeClass}">${escapeHtml(label)}${classification === "UNKNOWN" || classification !== verdict ? "" : ` &mdash; ${escapeHtml(scoreDisplay)}`}</div>
        ${incomplete ? `
          <p class="shieldai-unknown-why">${_t("unknownWhy")} ${escapeHtml(unknownReason(result))}</p>
        ` : ""}
        ${batchNote(tx)}
        ${delegationSection(tx)}
        ${lookalikeSection(recipient, lookalike)}

        ${result.partial ? `
          <div class="shieldai-section" style="background:#78350f;border-radius:6px;padding:8px 12px;margin-bottom:8px;">
            <p style="color:#fbbf24;font-size:12px;margin:0;">
              <strong>${_t("overlayPartialAnalysis")}</strong> — ${escapeHtml((result.failed_sources || []).join(', '))} ${_t("overlayResultsIncomplete")}
              ${result.policy_mode === 'STRICT' ? _t("overlayStrictBlock") : ''}
            </p>
          </div>
        ` : ''}

        ${calldataHtml || (result.decoded_action ? `
          <div class="shieldai-section shieldai-action-section">
            <h3>${_t("overlayTxType")}</h3>
            <div class="shieldai-action-label">${escapeHtml(result.decoded_action)}</div>
          </div>
        ` : "")}

        ${
          signalsHtml
            ? `<div class="shieldai-section">
                <h3>${_t("overlayDangerSignals")}</h3>
                <ul class="shieldai-signals">${signalsHtml}</ul>
               </div>`
            : ""
        }

        <div class="shieldai-section">
          <h3>${_t("overlayTxImpact")}</h3>
          <table class="shieldai-impact">
            <tr><td>${_t("overlaySending")}</td><td>${escapeHtml(impact.sending || "N/A")}</td></tr>
            <tr><td>${_t("overlayGrantingAccess")}</td><td>${escapeHtml(impact.granting_access || "Unknown")}</td></tr>
            <tr><td>${_t("overlayRecipient")}</td><td class="shieldai-mono">${escapeHtml(impact.recipient || "N/A")}</td></tr>
            <tr><td>${_t("overlayAfterTx")}</td><td>${escapeHtml(impact.post_tx_state || "N/A")}</td></tr>
          </table>
        </div>

        ${deltaHtml}

        <div class="shieldai-section">
          <h3>${_t("overlayAnalysis")}</h3>
          <p>${escapeHtml(incomplete ? "Unknown (incomplete provider coverage)" : result.plain_english || result.analysis || _t("overlayNoAnalysis"))}</p>
        </div>

        <div class="shieldai-verdict">
          ${escapeHtml(incomplete ? "Unknown (incomplete provider coverage)" : classification !== verdict ? label : result.verdict || "")}
        </div>

        <div class="shieldai-actions">
          <button class="shieldai-btn shieldai-btn-block" id="shieldai-block">
            ${_t("overlayBtnBlock")}
          </button>
          ${!canProceed ? "" : hold ? `
          <button class="shieldai-btn shieldai-btn-proceed shieldai-btn-hold" id="shieldai-proceed" aria-describedby="shieldai-hold-note">
            ${_t("overlayBtnHoldProceed")}
          </button>
          ` : `
          <button class="shieldai-btn shieldai-btn-proceed" id="shieldai-proceed">
            ${_t("overlayBtnProceed")}
          </button>
          `}
        </div>
        ${hold ? `<p class="shieldai-hold-note" id="shieldai-hold-note">${_t("overlayHoldNote")}</p>` : ""}
        ${COVERED_NOTE}
        ${canProceed ? "" : `<p class="shieldai-strict-note">${chainUnknown ? _t("overlayChainNoProceed") : _t("overlayStrictNoProceed")}</p>`}

        ${classification === "SAFE" ? "" : `
        <div class="shieldai-explain-row">
          <button class="shieldai-btn shieldai-btn-explain" id="shieldai-explain">
            ${_t("overlayBtnWhy") || "Why is this risky?"}
          </button>
        </div>
        <div class="shieldai-explain-response" id="shieldai-explain-response" style="display:none;">
          <p class="shieldai-explain-loading" id="shieldai-explain-loading">Analyzing...</p>
          <p class="shieldai-explain-text" id="shieldai-explain-text"></p>
        </div>
        `}
      </div>
    `;

    const root = mountOverlay(overlay, requestId);

    const calldataToggle = root.getElementById("shieldai-calldata-toggle");
    if (calldataToggle) {
      calldataToggle.addEventListener("click", () => {
        const body = root.getElementById("shieldai-calldata-body");
        const isExpanded = calldataToggle.getAttribute("aria-expanded") !== "false";
        const nextExpanded = !isExpanded;
        calldataToggle.setAttribute("aria-expanded", String(nextExpanded));
        if (body) {
          body.hidden = !nextExpanded;
        }
      });
    }

    // Button handlers. A recipient the user proceeds with is remembered.
    const remember = recipient ? () => rememberRecipient(recipient) : null;
    onDecision(root, "shieldai-block", requestId, "block");
    if (hold) {
      onHold(root, requestId, remember);
    } else if (canProceed) {
      onDecision(root, "shieldai-proceed", requestId, "proceed", remember);
    }

    // A SAFE verdict has nothing to explain, so it has no "Why is this risky?".
    if (classification === "SAFE") return;

    // "Why is this risky?" handler
    root.getElementById("shieldai-explain").addEventListener("click", () => {
      const btn = root.getElementById("shieldai-explain");
      const responseDiv = root.getElementById("shieldai-explain-response");
      const loadingEl = root.getElementById("shieldai-explain-loading");
      const textEl = root.getElementById("shieldai-explain-text");

      btn.disabled = true;
      btn.textContent = "Analyzing...";
      responseDiv.style.display = "block";
      loadingEl.style.display = "block";
      textEl.style.display = "none";

      if (incomplete) {
        loadingEl.style.display = "none";
        textEl.style.display = "block";
        textEl.textContent = "Unknown (incomplete provider coverage). " +
          Object.values(result.coverage_reasons || {}).join("; ");
        return;
      }

      chrome.runtime.sendMessage(
        { type: "SHIELDAI_EXPLAIN", scanResult: result },
        (resp) => {
          loadingEl.style.display = "none";
          textEl.style.display = "block";
          if (resp && resp.explanation) {
            textEl.textContent = resp.explanation;
          } else {
            textEl.textContent = "Unable to generate explanation.";
          }
        }
      );
    });
  }

  // Shown when no analysis came back (429, 400, timeout, unreachable API). In
  // Strict mode there is no Proceed: an unchecked transaction stays blocked.
  async function showErrorOverlay(requestId, errorMsg, strict, tx, recipient, lookalike) {
    await _loadContentLang();
    removeOverlay();
    // An EIP-7702 delegation is Block Recommended without the API too.
    const delegation = Array.isArray(tx.authorizationList);
    const hold = delegation && !strict;

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";
    overlay.innerHTML = `
      <div class="shieldai-modal ${delegation ? "shieldai-modal-danger" : ""}" role="dialog" aria-modal="true" aria-labelledby="shieldai-title" tabindex="-1">
        <div class="shieldai-header">
          <div class="shieldai-logo" aria-hidden="true">&#128737;</div>
          <h2 id="shieldai-title">${_t("overlayTitle")}</h2>
        </div>
        <div class="shieldai-badge ${delegation ? "shieldai-badge-block" : "shieldai-badge-high"}">
          ${delegation ? _t("classBlock") : _t("overlayAnalysisUnavail")}
        </div>
        ${batchNote(tx)}
        ${delegationSection(tx)}
        ${lookalikeSection(recipient, lookalike)}
        <div class="shieldai-section">
          <p>${_t("overlayCannotReach")}</p>
          <p class="shieldai-error">${escapeHtml(errorMsg)}</p>
          <p>${strict ? _t("overlayStrictNoProceed") : _t("overlayProceedRisk")}</p>
        </div>
        <div class="shieldai-actions">
          <button class="shieldai-btn shieldai-btn-block" id="shieldai-block">
            ${_t("overlayBtnBlock")}
          </button>
          ${strict ? "" : hold ? `
          <button class="shieldai-btn shieldai-btn-proceed shieldai-btn-hold" id="shieldai-proceed" aria-describedby="shieldai-hold-note">
            ${_t("overlayBtnHoldProceed")}
          </button>
          ` : `
          <button class="shieldai-btn shieldai-btn-proceed" id="shieldai-proceed">
            ${_t("overlayBtnProceed")}
          </button>
          `}
        </div>
        ${hold ? `<p class="shieldai-hold-note" id="shieldai-hold-note">${_t("overlayHoldNote")}</p>` : ""}
        ${COVERED_NOTE}
      </div>
    `;

    const root = mountOverlay(overlay, requestId);
    const remember = recipient ? () => rememberRecipient(recipient) : null;
    onDecision(root, "shieldai-block", requestId, "block");
    if (hold) {
      onHold(root, requestId, remember);
    } else if (!strict) {
      onDecision(root, "shieldai-proceed", requestId, "proceed", remember);
    }
  }

  // Shown for a request inject.js could not read (a transaction that is not
  // an object, or a wallet_sendCalls batch without a list of call objects),
  // so nothing in it was checked. In Strict mode there is no Proceed, and
  // none either for a batch with a call on another chain, which inject.js
  // rejects whatever the user decides.
  async function showUnknownStructureOverlay(requestId, strict, wrongChain) {
    await _loadContentLang();
    removeOverlay();
    const canProceed = !strict && !wrongChain;

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";
    overlay.innerHTML = `
      <div class="shieldai-modal" role="dialog" aria-modal="true" aria-labelledby="shieldai-title" tabindex="-1">
        <div class="shieldai-header">
          <div class="shieldai-logo" aria-hidden="true">&#128737;</div>
          <h2 id="shieldai-title">${_t("overlayTitle")}</h2>
        </div>
        <div class="shieldai-badge shieldai-badge-high">${_t("overlayUnknownStructure")}</div>
        <div class="shieldai-section">
          <p>${_t("overlayUnknownStructureNote")}</p>
          <p>${wrongChain ? _t("overlayChainNoProceed") : strict ? _t("overlayStrictNoProceed") : _t("overlayProceedRisk")}</p>
        </div>
        <div class="shieldai-actions">
          <button class="shieldai-btn shieldai-btn-block" id="shieldai-block">
            ${_t("overlayBtnBlock")}
          </button>
          ${canProceed ? `
          <button class="shieldai-btn shieldai-btn-proceed" id="shieldai-proceed">
            ${_t("overlayBtnProceed")}
          </button>
          ` : ""}
        </div>
        ${COVERED_NOTE}
      </div>
    `;

    const root = mountOverlay(overlay, requestId);
    onDecision(root, "shieldai-block", requestId, "block");
    if (canProceed) {
      onDecision(root, "shieldai-proceed", requestId, "proceed");
    }
  }

  // Shown when the analysis came back too late to still decide: the request
  // is rejected now, and the user is asked to try again.
  async function showTimedOutOverlay(requestId) {
    await _loadContentLang();
    removeOverlay();
    postVerdict(requestId, "block");

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";
    overlay.innerHTML = `
      <div class="shieldai-modal" role="dialog" aria-modal="true" aria-labelledby="shieldai-title" tabindex="-1">
        <div class="shieldai-header">
          <div class="shieldai-logo" aria-hidden="true">&#128737;</div>
          <h2 id="shieldai-title">${_t("overlayTitle")}</h2>
        </div>
        <div class="shieldai-badge shieldai-badge-unknown">${_t("overlayTimedOut")}</div>
        <div class="shieldai-section">
          <p>${_t("overlayTimedOutNote")}</p>
        </div>
        <div class="shieldai-actions">
          <button class="shieldai-btn shieldai-btn-proceed" id="shieldai-close">${_t("overlayBtnClose")}</button>
        </div>
      </div>
    `;

    const root = mountOverlay(overlay);
    root.getElementById("shieldai-close").addEventListener("click", () => removeOverlay());
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // A notice that fades out on its own (see overlay.css), lets clicks through
  // to the page, and leaves once faded.
  async function showNotice(key) {
    await _loadContentLang();
    const notice = document.createElement("div");
    notice.className = "shieldai-notice";
    notice.setAttribute("role", "status");
    notice.textContent = _t(key);
    const { host, root } = createShadow();
    notice.addEventListener("animationend", () => host.remove());
    root.appendChild(notice);
    (document.body || document.documentElement).appendChild(host);
  }

  // --- Phishing Site Check ---
  // Runs asynchronously on every page load. Does not block the page.

  async function runPhishingCheck() {
    try {
      const settings = await getSettings();
      if (!settings.enabled) return;

      const response = await chrome.runtime.sendMessage({
        type: "SHIELDAI_CHECK_PHISHING",
        url: window.location.href,
      });

      if (response?.result?.is_phishing) {
        await showPhishingBanner(window.location.hostname);
      }
    } catch {
      // Best-effort — never crash the page
    }
  }

  async function showPhishingBanner(domain) {
    await _loadContentLang();

    const banner = document.createElement("div");
    banner.id = "shieldai-phishing-banner";
    banner.className = "shieldai-phishing-banner";
    banner.innerHTML = `
      <div class="shieldai-phishing-content">
        <span class="shieldai-phishing-icon">&#9888;</span>
        <div class="shieldai-phishing-text">
          <strong>${_t("phishingWarning")}</strong>
          <span>${escapeHtml(domain)}</span> ${_t("phishingFlagged")}
        </div>
        <div class="shieldai-phishing-actions">
          <button class="shieldai-phishing-btn-leave" id="shieldai-leave">${_t("phishingLeavePage")}</button>
          <button class="shieldai-phishing-btn-dismiss" id="shieldai-dismiss">${_t("phishingKnowRisk")}</button>
        </div>
      </div>
    `;

    const { host, root } = createShadow();
    root.appendChild(banner);
    // Prepend to <html> — safe at document_start before <body> exists
    document.documentElement.insertBefore(host, document.documentElement.firstChild);

    root.getElementById("shieldai-leave").addEventListener("click", (event) => {
      if (!event.isTrusted) return;
      window.history.length > 1 ? window.history.back() : window.close();
    });

    root.getElementById("shieldai-dismiss").addEventListener("click", (event) => {
      if (!event.isTrusted) return;
      host.remove();
    });
  }

  // The warning is for the page in the tab; frames would only repeat the
  // lookup against the shared API rate limit.
  if (window.top === window) runPhishingCheck();
})();
