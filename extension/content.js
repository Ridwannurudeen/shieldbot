/**
 * ShieldAI Content Script
 * Bridges between inject.js (page context) and background.js (service worker).
 * Shows the firewall overlay with analysis results.
 */
(function () {
  "use strict";

  // Generate a per-session channel token BEFORE inject.js loads.
  // This token is kept in the isolated content-script world and passed to
  // inject.js via its script URL — page scripts cannot read it after
  // document_start because the <script> element is removed immediately onload.
  // Every verdict message must include this token; forge attempts without it
  // are silently ignored by inject.js.
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

  const _CHANNEL_TOKEN = crypto.randomUUID
    ? crypto.randomUUID()
    : Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

  // Inject the page-level script — token is NOT in the URL to prevent
  // extraction via performance.getEntriesByType("resource").
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("inject.js");
  script.onload = function () {
    // Send the channel token via one-time postMessage handshake.
    // At document_start, no page scripts have loaded yet, so this
    // message cannot be intercepted by malicious page code.
    window.postMessage({ type: "__SHIELDAI_INIT__", _ct: _CHANNEL_TOKEN }, "*");
    this.remove();
  };
  (document.head || document.documentElement).appendChild(script);

  // Inject overlay CSS
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = chrome.runtime.getURL("overlay.css");
  (document.head || document.documentElement).appendChild(link);

  // Listen for intercepted transactions from inject.js
  window.addEventListener("message", async (event) => {
    if (
      event.source !== window ||
      !event.data ||
      event.data.type !== "SHIELDAI_TX_INTERCEPT"
    ) {
      return;
    }

    const { requestId, tx, method } = event.data;

    // Check if extension is enabled
    const settings = await getSettings();
    if (!settings.enabled) {
      // Extension disabled — auto-proceed
      window.postMessage(
        { type: "SHIELDAI_TX_VERDICT", requestId, action: "proceed", _ct: _CHANNEL_TOKEN },
        "*"
      );
      return;
    }

    // Signing requests are NOT transactions — route to dedicated overlay
    // instead of the firewall API which expects calldata + contract address.
    const SIGN_ONLY_METHODS = new Set([
      "personal_sign", "eth_sign",
      "eth_signTypedData_v4", "eth_signTypedData_v3",
    ]);
    if (tx.signMethod && SIGN_ONLY_METHODS.has(tx.signMethod)) {
      showSignatureOverlay(requestId, tx);
      return;
    }

    // Show loading overlay
    showLoadingOverlay();

    try {
      // Check if API URL is configured
      if (!settings.apiUrl) {
        showErrorOverlay(
          requestId,
          "ShieldAI Setup Required: Click the extension icon in your toolbar, enter your API server URL, and grant permission when prompted. Then try this transaction again."
        );
        return;
      }

      // Send to background for API analysis
      const response = await chrome.runtime.sendMessage({
        type: "SHIELDAI_ANALYZE",
        tx,
      });

      if (response.error) {
        // API error — show warning and let user decide
        showErrorOverlay(requestId, response.error);
      } else {
        // Show analysis overlay
        showAnalysisOverlay(requestId, response.result);
      }
    } catch (err) {
      showErrorOverlay(
        requestId,
        err.message || "Extension communication error. Check extension settings."
      );
    }
  });

  // --- Settings ---
  function getSettings() {
    return new Promise((resolve) => {
      chrome.storage.local.get(
        { enabled: true, apiUrl: "" },
        resolve
      );
    });
  }

  // --- Overlay Management ---

  function removeOverlay() {
    const existing = document.getElementById("shieldai-overlay");
    if (existing) existing.remove();
  }

  async function showLoadingOverlay() {
    await _loadContentLang();
    removeOverlay();

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";
    overlay.innerHTML = `
      <div class="shieldai-modal">
        <div class="shieldai-header">
          <div class="shieldai-logo">&#128737;</div>
          <h2>${_t("overlayTitle")}</h2>
        </div>
        <div class="shieldai-loading">
          <div class="shieldai-spinner"></div>
          <p>${_t("overlayAnalyzing")}</p>
          <p class="shieldai-subtext">${_t("overlaySubtext")}</p>
        </div>
      </div>
    `;
    (document.body || document.documentElement).appendChild(overlay);
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
  // Shown instead of the firewall overlay for personal_sign / eth_signTypedData etc.

  async function showSignatureOverlay(requestId, tx) {
    await _loadContentLang();
    removeOverlay();

    const signMethod = tx.signMethod || "personal_sign";
    const isTyped = signMethod === "eth_signTypedData_v4" || signMethod === "eth_signTypedData_v3";
    const isPersonal = signMethod === "personal_sign" || signMethod === "eth_sign";

    let bodyHtml = "";
    let isPermitLike = false;

    if (isTyped && tx.typedData) {
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
      // Decode hex message to readable text
      const raw = tx.data || "";
      const decoded = hexToUtf8(raw);
      const display = decoded || raw;
      const isBinary = !decoded && raw.length > 2;

      bodyHtml = `
        <div class="shieldai-section">
          <h3>${_t("overlayMessage")}</h3>
          <div class="shieldai-sig-message ${isBinary ? "shieldai-sig-binary" : ""}">${escapeHtml(display)}</div>
        </div>
      `;
    }

    // Risk classification
    const color = isPermitLike ? "#f97316" : "#eab308";
    const label = isPermitLike ? _t("overlayApprovalSig") : _t("overlaySigRequest");
    const note = isPermitLike ? _t("overlayApprovalNote") : _t("overlaySigNote");

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";
    overlay.innerHTML = `
      <div class="shieldai-modal">
        <div class="shieldai-header">
          <div class="shieldai-logo">&#128737;</div>
          <h2>${_t("overlayTitle")}</h2>
        </div>

        <div class="shieldai-badge" style="background:${color}">${label}</div>

        <div class="shieldai-section shieldai-sig-note">
          <p>${escapeHtml(note)}</p>
        </div>

        ${bodyHtml}

        <div class="shieldai-actions">
          <button class="shieldai-btn shieldai-btn-block" id="shieldai-block">${_t("overlayBtnReject")}</button>
          <button class="shieldai-btn shieldai-btn-proceed" id="shieldai-proceed">${_t("overlayBtnSignAnyway")}</button>
        </div>
      </div>
    `;

    (document.body || document.documentElement).appendChild(overlay);

    document.getElementById("shieldai-block").addEventListener("click", () => {
      removeOverlay();
      window.postMessage(
        { type: "SHIELDAI_TX_VERDICT", requestId, action: "block", _ct: _CHANNEL_TOKEN },
        "*"
      );
    });
    document.getElementById("shieldai-proceed").addEventListener("click", () => {
      removeOverlay();
      window.postMessage(
        { type: "SHIELDAI_TX_VERDICT", requestId, action: "proceed", _ct: _CHANNEL_TOKEN },
        "*"
      );
    });
  }

  async function showAnalysisOverlay(requestId, result) {
    await _loadContentLang();
    removeOverlay();

    const classColors = {
      BLOCK_RECOMMENDED: "#ef4444",
      HIGH_RISK: "#f97316",
      CAUTION: "#eab308",
      SAFE: "#22c55e",
    };

    const classLabels = {
      BLOCK_RECOMMENDED: _t("classBlock"),
      HIGH_RISK: _t("classHighRisk"),
      CAUTION: _t("classCaution"),
      SAFE: _t("classSafe"),
    };

    const classification = result.classification || "CAUTION";
    const color = classColors[classification] || "#eab308";
    const label = classLabels[classification] || classification;
    const isBlock = classification === "BLOCK_RECOMMENDED";

    // Display as safety score (100 - risk) so higher = better
    const riskScore = result.risk_score || 0;
    const safetyScore = 100 - riskScore;

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
      <div class="shieldai-modal ${isBlock ? "shieldai-modal-danger" : ""}">
        <div class="shieldai-header">
          <div class="shieldai-logo">&#128737;</div>
          <h2>${_t("overlayTitle")}</h2>
        </div>

        <div class="shieldai-badge" style="background:${color}">
          ${escapeHtml(label)} &mdash; ${_t("overlaySafety")} ${safetyScore}/100
        </div>

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
            <tr><td>${_t("overlayGrantingAccess")}</td><td>${escapeHtml(impact.granting_access || "None")}</td></tr>
            <tr><td>${_t("overlayRecipient")}</td><td class="shieldai-mono">${escapeHtml(impact.recipient || "N/A")}</td></tr>
            <tr><td>${_t("overlayAfterTx")}</td><td>${escapeHtml(impact.post_tx_state || "N/A")}</td></tr>
          </table>
        </div>

        ${deltaHtml}

        <div class="shieldai-section">
          <h3>${_t("overlayAnalysis")}</h3>
          <p>${escapeHtml(result.plain_english || result.analysis || _t("overlayNoAnalysis"))}</p>
        </div>

        <div class="shieldai-verdict">
          ${escapeHtml(result.verdict || "")}
        </div>

        <div class="shieldai-actions">
          <button class="shieldai-btn shieldai-btn-block" id="shieldai-block">
            ${_t("overlayBtnBlock")}
          </button>
          <button class="shieldai-btn shieldai-btn-proceed" id="shieldai-proceed">
            ${_t("overlayBtnProceed")}
          </button>
        </div>

        <div class="shieldai-explain-row">
          <button class="shieldai-btn shieldai-btn-explain" id="shieldai-explain">
            ${_t("overlayBtnWhy") || "Why is this risky?"}
          </button>
        </div>
        <div class="shieldai-explain-response" id="shieldai-explain-response" style="display:none;">
          <p class="shieldai-explain-loading" id="shieldai-explain-loading">Analyzing...</p>
          <p class="shieldai-explain-text" id="shieldai-explain-text"></p>
        </div>
      </div>
    `;

    (document.body || document.documentElement).appendChild(overlay);

    const calldataToggle = document.getElementById("shieldai-calldata-toggle");
    if (calldataToggle) {
      calldataToggle.addEventListener("click", () => {
        const body = document.getElementById("shieldai-calldata-body");
        const isExpanded = calldataToggle.getAttribute("aria-expanded") !== "false";
        const nextExpanded = !isExpanded;
        calldataToggle.setAttribute("aria-expanded", String(nextExpanded));
        if (body) {
          body.hidden = !nextExpanded;
        }
      });
    }

    // Button handlers
    document.getElementById("shieldai-block").addEventListener("click", () => {
      removeOverlay();
      window.postMessage(
        { type: "SHIELDAI_TX_VERDICT", requestId, action: "block", _ct: _CHANNEL_TOKEN },
        "*"
      );
    });

    document
      .getElementById("shieldai-proceed")
      .addEventListener("click", () => {
        removeOverlay();
        window.postMessage(
          { type: "SHIELDAI_TX_VERDICT", requestId, action: "proceed", _ct: _CHANNEL_TOKEN },
          "*"
        );
      });

    // "Why is this risky?" handler
    document.getElementById("shieldai-explain").addEventListener("click", () => {
      const btn = document.getElementById("shieldai-explain");
      const responseDiv = document.getElementById("shieldai-explain-response");
      const loadingEl = document.getElementById("shieldai-explain-loading");
      const textEl = document.getElementById("shieldai-explain-text");

      btn.disabled = true;
      btn.textContent = "Analyzing...";
      responseDiv.style.display = "block";
      loadingEl.style.display = "block";
      textEl.style.display = "none";

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

  async function showErrorOverlay(requestId, errorMsg) {
    await _loadContentLang();
    removeOverlay();

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";
    overlay.innerHTML = `
      <div class="shieldai-modal">
        <div class="shieldai-header">
          <div class="shieldai-logo">&#128737;</div>
          <h2>${_t("overlayTitle")}</h2>
        </div>
        <div class="shieldai-badge" style="background:#f97316">
          ${_t("overlayAnalysisUnavail")}
        </div>
        <div class="shieldai-section">
          <p>${_t("overlayCannotReach")}</p>
          <p class="shieldai-error">${escapeHtml(errorMsg)}</p>
          <p>${_t("overlayProceedRisk")}</p>
        </div>
        <div class="shieldai-actions">
          <button class="shieldai-btn shieldai-btn-block" id="shieldai-block">
            ${_t("overlayBtnBlock")}
          </button>
          <button class="shieldai-btn shieldai-btn-proceed" id="shieldai-proceed">
            ${_t("overlayBtnProceed")}
          </button>
        </div>
      </div>
    `;

    (document.body || document.documentElement).appendChild(overlay);

    document.getElementById("shieldai-block").addEventListener("click", () => {
      removeOverlay();
      window.postMessage(
        { type: "SHIELDAI_TX_VERDICT", requestId, action: "block", _ct: _CHANNEL_TOKEN },
        "*"
      );
    });

    document
      .getElementById("shieldai-proceed")
      .addEventListener("click", () => {
        removeOverlay();
        window.postMessage(
          { type: "SHIELDAI_TX_VERDICT", requestId, action: "proceed", _ct: _CHANNEL_TOKEN },
          "*"
        );
      });
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // --- Phishing Site Check ---
  // Runs asynchronously on every page load. Does not block the page.

  async function runPhishingCheck() {
    try {
      const settings = await getSettings();
      if (!settings.enabled || !settings.apiUrl) return;

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
    if (document.getElementById("shieldai-phishing-banner")) return;
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

    // Prepend to <html> — safe at document_start before <body> exists
    document.documentElement.insertBefore(
      banner,
      document.documentElement.firstChild
    );

    document.getElementById("shieldai-leave").addEventListener("click", () => {
      window.history.length > 1 ? window.history.back() : window.close();
    });

    document
      .getElementById("shieldai-dismiss")
      .addEventListener("click", () => {
        banner.remove();
      });
  }

  runPhishingCheck();
})();
