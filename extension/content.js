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
  const _CHANNEL_TOKEN = crypto.randomUUID
    ? crypto.randomUUID()
    : Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

  // Inject the page-level script, embedding the channel token in the URL
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("inject.js") + "?ct=" + _CHANNEL_TOKEN;
  script.onload = function () {
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

  function showLoadingOverlay() {
    removeOverlay();

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";
    overlay.innerHTML = `
      <div class="shieldai-modal">
        <div class="shieldai-header">
          <div class="shieldai-logo">&#128737;</div>
          <h2>ShieldAI Firewall</h2>
        </div>
        <div class="shieldai-loading">
          <div class="shieldai-spinner"></div>
          <p>Analyzing transaction...</p>
          <p class="shieldai-subtext">Checking contract, decoding calldata, scanning for threats</p>
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

  // --- Signature Request Overlay ---
  // Shown instead of the firewall overlay for personal_sign / eth_signTypedData etc.

  function showSignatureOverlay(requestId, tx) {
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
            <h3>Domain</h3>
            <table class="shieldai-impact">${domainRows.join("")}</table>
          </div>` : ""}
        <div class="shieldai-section">
          <h3>Type: ${escapeHtml(primaryType)}</h3>
          <table class="shieldai-impact">${msgRows || "<tr><td colspan='2'>No fields</td></tr>"}</table>
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
          <h3>Message</h3>
          <div class="shieldai-sig-message ${isBinary ? "shieldai-sig-binary" : ""}">${escapeHtml(display)}</div>
        </div>
      `;
    }

    // Risk classification
    const color = isPermitLike ? "#f97316" : "#eab308";
    const label = isPermitLike ? "APPROVAL SIGNATURE" : "SIGNATURE REQUEST";
    const note = isPermitLike
      ? "This signature grants token spending rights — no gas needed. Only sign for protocols you fully trust."
      : "Signing this message costs no gas, but malicious sites can use signatures to drain wallets or impersonate you.";

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";
    overlay.innerHTML = `
      <div class="shieldai-modal">
        <div class="shieldai-header">
          <div class="shieldai-logo">&#128737;</div>
          <h2>ShieldAI Firewall</h2>
        </div>

        <div class="shieldai-badge" style="background:${color}">${label}</div>

        <div class="shieldai-section shieldai-sig-note">
          <p>${escapeHtml(note)}</p>
        </div>

        ${bodyHtml}

        <div class="shieldai-actions">
          <button class="shieldai-btn shieldai-btn-block" id="shieldai-block">Reject</button>
          <button class="shieldai-btn shieldai-btn-proceed" id="shieldai-proceed">Sign Anyway</button>
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

  function showAnalysisOverlay(requestId, result) {
    removeOverlay();

    const classColors = {
      BLOCK_RECOMMENDED: "#ef4444",
      HIGH_RISK: "#f97316",
      CAUTION: "#eab308",
      SAFE: "#22c55e",
    };

    const classLabels = {
      BLOCK_RECOMMENDED: "BLOCK RECOMMENDED",
      HIGH_RISK: "HIGH RISK",
      CAUTION: "CAUTION",
      SAFE: "SAFE",
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
           <h3>Asset Delta <span class="shieldai-sim-badge">SIMULATED</span></h3>
           <ul class="shieldai-delta-list">
             ${assetDelta.map((d) => {
               const isOut = d.startsWith("-");
               return `<li class="${isOut ? "shieldai-delta-out" : "shieldai-delta-in"}">${escapeHtml(d)}</li>`;
             }).join("")}
           </ul>
         </div>`
      : "";

    overlay.innerHTML = `
      <div class="shieldai-modal ${isBlock ? "shieldai-modal-danger" : ""}">
        <div class="shieldai-header">
          <div class="shieldai-logo">&#128737;</div>
          <h2>ShieldAI Firewall</h2>
        </div>

        <div class="shieldai-badge" style="background:${color}">
          ${escapeHtml(label)} &mdash; Safety: ${safetyScore}/100
        </div>

        ${result.partial ? `
          <div class="shieldai-section" style="background:#78350f;border-radius:6px;padding:8px 12px;margin-bottom:8px;">
            <p style="color:#fbbf24;font-size:12px;margin:0;">
              <strong>Partial Analysis</strong> — ${escapeHtml((result.failed_sources || []).join(', '))} unavailable.
              ${result.policy_mode === 'STRICT' ? 'Strict mode: blocking recommended.' : 'Results may be incomplete.'}
            </p>
          </div>
        ` : ''}

        ${result.calldata_details && result.calldata_details.fields && result.calldata_details.fields.length ? `
          <div class="shieldai-section">
            <h3>Decoded Calldata</h3>
            <table class="shieldai-impact shieldai-calldata">
              ${result.calldata_details.fields.map((f) =>
                `<tr>
                  <td>${escapeHtml(f.label)}</td>
                  <td class="${f.danger ? 'shieldai-calldata-danger' : ''}">${escapeHtml(String(f.value))}</td>
                </tr>`
              ).join("")}
            </table>
          </div>
        ` : result.decoded_action ? `
          <div class="shieldai-section shieldai-action-section">
            <h3>Transaction Type</h3>
            <div class="shieldai-action-label">${escapeHtml(result.decoded_action)}</div>
          </div>
        ` : ""}

        ${
          signalsHtml
            ? `<div class="shieldai-section">
                <h3>Danger Signals</h3>
                <ul class="shieldai-signals">${signalsHtml}</ul>
               </div>`
            : ""
        }

        <div class="shieldai-section">
          <h3>Transaction Impact</h3>
          <table class="shieldai-impact">
            <tr><td>Sending</td><td>${escapeHtml(impact.sending || "N/A")}</td></tr>
            <tr><td>Granting Access</td><td>${escapeHtml(impact.granting_access || "None")}</td></tr>
            <tr><td>Recipient</td><td class="shieldai-mono">${escapeHtml(impact.recipient || "N/A")}</td></tr>
            <tr><td>After TX</td><td>${escapeHtml(impact.post_tx_state || "N/A")}</td></tr>
          </table>
        </div>

        ${deltaHtml}

        <div class="shieldai-section">
          <h3>Analysis</h3>
          <p>${escapeHtml(result.plain_english || result.analysis || "No analysis available")}</p>
        </div>

        <div class="shieldai-verdict">
          ${escapeHtml(result.verdict || "")}
        </div>

        <div class="shieldai-actions">
          <button class="shieldai-btn shieldai-btn-block" id="shieldai-block">
            Block Transaction
          </button>
          <button class="shieldai-btn shieldai-btn-proceed" id="shieldai-proceed">
            Proceed Anyway
          </button>
        </div>
      </div>
    `;

    (document.body || document.documentElement).appendChild(overlay);

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
  }

  function showErrorOverlay(requestId, errorMsg) {
    removeOverlay();

    const overlay = document.createElement("div");
    overlay.id = "shieldai-overlay";
    overlay.className = "shieldai-overlay";
    overlay.innerHTML = `
      <div class="shieldai-modal">
        <div class="shieldai-header">
          <div class="shieldai-logo">&#128737;</div>
          <h2>ShieldAI Firewall</h2>
        </div>
        <div class="shieldai-badge" style="background:#f97316">
          ANALYSIS UNAVAILABLE
        </div>
        <div class="shieldai-section">
          <p>Could not reach the ShieldAI API:</p>
          <p class="shieldai-error">${escapeHtml(errorMsg)}</p>
          <p>Proceed at your own risk.</p>
        </div>
        <div class="shieldai-actions">
          <button class="shieldai-btn shieldai-btn-block" id="shieldai-block">
            Block Transaction
          </button>
          <button class="shieldai-btn shieldai-btn-proceed" id="shieldai-proceed">
            Proceed Anyway
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
        showPhishingBanner(window.location.hostname);
      }
    } catch {
      // Best-effort — never crash the page
    }
  }

  function showPhishingBanner(domain) {
    if (document.getElementById("shieldai-phishing-banner")) return;

    const banner = document.createElement("div");
    banner.id = "shieldai-phishing-banner";
    banner.className = "shieldai-phishing-banner";
    banner.innerHTML = `
      <div class="shieldai-phishing-content">
        <span class="shieldai-phishing-icon">&#9888;</span>
        <div class="shieldai-phishing-text">
          <strong>ShieldBot Warning:</strong>
          <span>${escapeHtml(domain)}</span> has been flagged as a phishing site.
          Your wallet and funds may be at risk.
        </div>
        <div class="shieldai-phishing-actions">
          <button class="shieldai-phishing-btn-leave" id="shieldai-leave">Leave Page</button>
          <button class="shieldai-phishing-btn-dismiss" id="shieldai-dismiss">I know the risk</button>
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
