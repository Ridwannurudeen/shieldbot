/**
 * ShieldAI Content Script
 * Bridges between inject.js (page context) and background.js (service worker).
 * Shows the firewall overlay with analysis results.
 */
(function () {
  "use strict";

  // Inject the page-level script
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("inject.js");
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
        { type: "SHIELDAI_TX_VERDICT", requestId, action: "proceed" },
        "*"
      );
      return;
    }

    // Show loading overlay
    showLoadingOverlay();

    try {
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
      showErrorOverlay(requestId, err.message || "Extension communication error");
    }
  });

  // --- Settings ---
  function getSettings() {
    return new Promise((resolve) => {
      chrome.storage.local.get(
        { enabled: true, apiUrl: "https://38.49.212.108:8000" },
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
    document.body.appendChild(overlay);
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

    overlay.innerHTML = `
      <div class="shieldai-modal ${isBlock ? "shieldai-modal-danger" : ""}">
        <div class="shieldai-header">
          <div class="shieldai-logo">&#128737;</div>
          <h2>ShieldAI Firewall</h2>
        </div>

        <div class="shieldai-badge" style="background:${color}">
          ${escapeHtml(label)} &mdash; Safety: ${safetyScore}/100
        </div>

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

    document.body.appendChild(overlay);

    // Button handlers
    document.getElementById("shieldai-block").addEventListener("click", () => {
      removeOverlay();
      window.postMessage(
        { type: "SHIELDAI_TX_VERDICT", requestId, action: "block" },
        "*"
      );
    });

    document
      .getElementById("shieldai-proceed")
      .addEventListener("click", () => {
        removeOverlay();
        window.postMessage(
          { type: "SHIELDAI_TX_VERDICT", requestId, action: "proceed" },
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

    document.body.appendChild(overlay);

    document.getElementById("shieldai-block").addEventListener("click", () => {
      removeOverlay();
      window.postMessage(
        { type: "SHIELDAI_TX_VERDICT", requestId, action: "block" },
        "*"
      );
    });

    document
      .getElementById("shieldai-proceed")
      .addEventListener("click", () => {
        removeOverlay();
        window.postMessage(
          { type: "SHIELDAI_TX_VERDICT", requestId, action: "proceed" },
          "*"
        );
      });
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
})();
