/**
 * ShieldAI Inject Script
 * Runs in the PAGE context to intercept wallet transactions.
 * Wraps provider.request() directly — compatible with MetaMask's
 * protected window.ethereum property.
 */
(function () {
  "use strict";

  if (window.__shieldai_injected) return;
  window.__shieldai_injected = true;

  const INTERCEPTED_METHODS = new Set([
    "eth_sendTransaction",
    "eth_signTransaction",
    "eth_signTypedData_v4",
    "eth_signTypedData_v3",
    "personal_sign",
    "eth_sign",
  ]);

  /**
   * Wrap a provider's request method to intercept transactions.
   * Modifies the provider in-place (no Proxy, no Object.defineProperty).
   */
  function wrapProvider(provider, label) {
    if (!provider || !provider.request || provider.__shieldai_proxied) return;

    const originalRequest = provider.request.bind(provider);

    provider.request = async function (args) {
      if (!args || !INTERCEPTED_METHODS.has(args.method)) {
        return originalRequest(args);
      }

      const txParams = args.params?.[0];
      if (!txParams) return originalRequest(args);

      console.log("[ShieldAI] Intercepted:", args.method, txParams);

      // For typed data methods, extract typed data for signature analysis
      let interceptData = txParams;
      const typedDataMethods = new Set([
        "eth_signTypedData_v4",
        "eth_signTypedData_v3",
      ]);

      if (typedDataMethods.has(args.method)) {
        // params[0] is address, params[1] is the typed data JSON string
        const rawTypedData = args.params?.[1];
        let parsedTypedData = null;
        try {
          parsedTypedData =
            typeof rawTypedData === "string"
              ? JSON.parse(rawTypedData)
              : rawTypedData;
        } catch (e) {
          console.warn("[ShieldAI] Failed to parse typed data:", e);
        }
        interceptData = {
          from: txParams,
          to: "",
          value: "0x0",
          data: "0x",
          typedData: parsedTypedData,
          signMethod: args.method,
        };
      }

      // Ask content script to analyze via background
      const verdict = await requestAnalysis(args.method, interceptData);

      if (verdict.action === "block") {
        throw new Error("Transaction blocked by ShieldAI Firewall");
      }

      // proceed — forward to original wallet
      return originalRequest(args);
    };

    provider.__shieldai_proxied = true;
    console.log("[ShieldAI] Firewall active — intercepting " + (label || "provider"));
  }

  /**
   * Post message to content script and wait for verdict.
   */
  function requestAnalysis(method, txParams) {
    return new Promise((resolve) => {
      const requestId =
        "shieldai_" + Date.now() + "_" + Math.random().toString(36).slice(2);

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
        resolve(event.data);
      }

      window.addEventListener("message", handleVerdict);

      window.postMessage(
        {
          type: "SHIELDAI_TX_INTERCEPT",
          requestId,
          method,
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

      // Timeout after 5 minutes
      setTimeout(() => {
        window.removeEventListener("message", handleVerdict);
        resolve({ action: "proceed", reason: "Analysis timed out" });
      }, 300000);
    });
  }

  // --- Hook window.ethereum ---

  function tryWrap() {
    if (window.ethereum && !window.ethereum.__shieldai_proxied) {
      wrapProvider(window.ethereum, "window.ethereum");
      return true;
    }
    return false;
  }

  if (!tryWrap()) {
    // Provider not ready yet — watch for it via defineProperty or polling
    let _pending = window.ethereum;

    try {
      Object.defineProperty(window, "ethereum", {
        configurable: true,
        enumerable: true,
        get() {
          return _pending;
        },
        set(provider) {
          _pending = provider;
          if (provider && !provider.__shieldai_proxied) {
            setTimeout(() => wrapProvider(provider, "window.ethereum (deferred)"), 0);
          }
        },
      });
    } catch (e) {
      // MetaMask may have locked window.ethereum — poll instead
      const poll = setInterval(() => {
        if (tryWrap()) clearInterval(poll);
      }, 200);
      setTimeout(() => clearInterval(poll), 30000);
    }
  }

  // --- Hook EIP-6963 providers (Rabby, modern MetaMask, etc.) ---

  window.addEventListener("eip6963:announceProvider", (event) => {
    const detail = event.detail;
    if (detail?.provider && !detail.provider.__shieldai_proxied) {
      wrapProvider(detail.provider, "EIP-6963: " + (detail.info?.name || "unknown"));
    }
  });

  // Re-dispatch in case providers were already announced
  window.dispatchEvent(new Event("eip6963:requestProvider"));
})();
