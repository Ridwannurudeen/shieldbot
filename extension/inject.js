/**
 * ShieldAI Inject Script
 * Runs in the PAGE context (not content script sandbox) to access window.ethereum.
 * Communicates with content.js via window.postMessage.
 */
(function () {
  "use strict";

  if (!window.ethereum) return;

  // Avoid double-injection
  if (window.__shieldai_injected) return;
  window.__shieldai_injected = true;

  const originalRequest = window.ethereum.request.bind(window.ethereum);

  // Methods we intercept
  const INTERCEPTED_METHODS = new Set([
    "eth_sendTransaction",
    "eth_signTransaction",
  ]);

  window.ethereum.request = function (args) {
    if (!args || !INTERCEPTED_METHODS.has(args.method)) {
      return originalRequest(args);
    }

    const txParams = args.params?.[0];
    if (!txParams) {
      return originalRequest(args);
    }

    return new Promise((resolve, reject) => {
      // Generate unique request ID
      const requestId = "shieldai_" + Date.now() + "_" + Math.random().toString(36).slice(2);

      // Send tx data to content script for analysis
      window.postMessage(
        {
          type: "SHIELDAI_TX_INTERCEPT",
          requestId,
          method: args.method,
          tx: {
            to: txParams.to || "",
            from: txParams.from || "",
            value: txParams.value || "0x0",
            data: txParams.data || "0x",
            chainId: txParams.chainId || undefined,
          },
        },
        "*"
      );

      // Listen for verdict from content script
      function handleVerdict(event) {
        if (
          event.source !== window ||
          !event.data ||
          event.data.type !== "SHIELDAI_TX_VERDICT" ||
          event.data.requestId !== requestId
        ) {
          return;
        }

        window.removeEventListener("message", handleVerdict);

        if (event.data.action === "proceed") {
          // User chose to proceed — forward original request
          originalRequest(args).then(resolve).catch(reject);
        } else {
          // User blocked the transaction
          reject(new Error("Transaction blocked by ShieldAI Firewall"));
        }
      }

      window.addEventListener("message", handleVerdict);

      // Timeout after 5 minutes (user might walk away)
      setTimeout(() => {
        window.removeEventListener("message", handleVerdict);
        reject(new Error("ShieldAI Firewall: Analysis timed out"));
      }, 300000);
    });
  };

  // Also proxy the legacy sendAsync / send if present
  if (window.ethereum.sendAsync) {
    const originalSendAsync = window.ethereum.sendAsync.bind(window.ethereum);
    window.ethereum.sendAsync = function (payload, callback) {
      if (payload && INTERCEPTED_METHODS.has(payload.method)) {
        window.ethereum
          .request({ method: payload.method, params: payload.params })
          .then((result) =>
            callback(null, { id: payload.id, jsonrpc: "2.0", result })
          )
          .catch((err) => callback(err, null));
      } else {
        originalSendAsync(payload, callback);
      }
    };
  }
})();
