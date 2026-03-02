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

        ${result.decoded_action ? `
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
