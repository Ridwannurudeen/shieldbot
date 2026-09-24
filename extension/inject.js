/**
 * ShieldAI Inject Script
 * Runs in the PAGE context to intercept wallet transactions.
 * Wraps provider.request() directly — compatible with MetaMask's
 * protected window.ethereum property.
 */
(function () {
  "use strict";

  // Clear resource timing entries so extension URLs are not leaked
  // to page scripts via performance.getEntriesByType("resource").
  try { performance.clearResourceTimings(); } catch (_) {}

  // Channel token for verdict authentication — starts null (reject all
  // verdicts until init handshake from content.js completes).
  let _CHANNEL_TOKEN = null;

  // Receive the token from content.js via a one-time postMessage handshake.
  // content.js runs at document_start (before any page scripts) and sends
  // the init message immediately on inject.js load, so page scripts cannot
  // register a listener in time to intercept it.
  window.addEventListener("message", function _initHandler(event) {
    if (
      event.source !== window ||
      !event.data ||
      event.data.type !== "__SHIELDAI_INIT__"
    ) {
      return;
    }
    _CHANNEL_TOKEN = event.data._ct || "";
    window.removeEventListener("message", _initHandler);
  });

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
  const TYPED_DATA_METHODS = new Set([
    "eth_signTypedData_v4",
    "eth_signTypedData_v3",
  ]);

  const SIGN_METHODS = new Set(["personal_sign", "eth_sign"]);

  // Providers already wrapped. Kept in this closure rather than as a flag on
  // the provider, which the page could read to detect the extension.
  const wrappedProviders = new WeakSet();

  // Stores the original (un-wrapped) provider.request — used by the revoke handler
  // so revoke TXs bypass ShieldAI analysis and go straight to the wallet.
  let _lastOriginalRequest = null;

  function parseChainId(value) {
    if (typeof value !== "number" &&
        !(typeof value === "string" && /^(0x[0-9a-f]+|[0-9]+)$/i.test(value))) {
      return null;
    }
    const chainId = Number(value);
    return Number.isSafeInteger(chainId) && chainId > 0 ? chainId : null;
  }

  /**
   * Wrap a provider's request method to intercept transactions.
   * Uses Object.defineProperty for compatibility with MetaMask v11+
   * where provider.request may be non-writable.
   */
  function wrapProvider(provider) {
    if (!provider || !provider.request || wrappedProviders.has(provider)) return;

    const originalRequest = provider.request.bind(provider);
    _lastOriginalRequest = originalRequest;
    let currentChainId = null;
    let chainRevision = 0;

    if (typeof provider.on === "function") {
      provider.on("chainChanged", (chainId) => {
        currentChainId = parseChainId(chainId);
        chainRevision++;
      });
    }

    async function resolveChainId() {
      const revision = chainRevision;
      let timeout;
      try {
        const chainId = await Promise.race([
          originalRequest({ method: "eth_chainId" }),
          new Promise((resolve) => { timeout = setTimeout(() => resolve(null), 5000); }),
        ]);
        currentChainId = revision === chainRevision ? parseChainId(chainId) : null;
      } catch (_) {
        currentChainId = null;
      } finally {
        clearTimeout(timeout);
      }
      return currentChainId;
    }

    const wrappedRequest = async function (args) {
      if (!args || !INTERCEPTED_METHODS.has(args.method)) {
        return originalRequest(args);
      }

      const txParams = args.params?.[0];
      if (!txParams) return originalRequest(args);

      let interceptData;

      if (TYPED_DATA_METHODS.has(args.method)) {
        // EIP-712: params[0] is address, params[1] is typed data JSON
        const rawTypedData = args.params?.[1];
        let parsedTypedData = null;
        try {
          parsedTypedData =
            typeof rawTypedData === "string"
              ? JSON.parse(rawTypedData)
              : rawTypedData;
        } catch (_) {
          // Unparseable typed data goes to the overlay without its fields.
        }
        interceptData = {
          from: txParams,
          to: "",
          value: "0x0",
          data: "0x",
          typedData: parsedTypedData,
          signMethod: args.method,
        };
      } else if (SIGN_METHODS.has(args.method)) {
        // personal_sign: params[0] is message, params[1] is address
        // eth_sign: params[0] is address, params[1] is message
        const isPersonal = args.method === "personal_sign";
        interceptData = {
          from: isPersonal ? (args.params?.[1] || "") : txParams,
          to: "",
          value: "0x0",
          data: isPersonal ? txParams : (args.params?.[1] || "0x"),
          signMethod: args.method,
        };
      } else {
        // eth_sendTransaction / eth_signTransaction — standard tx object
        interceptData = txParams;
      }

      const isTransaction = args.method === "eth_sendTransaction" || args.method === "eth_signTransaction";
      const revision = chainRevision;
      let chainId = null;
      if (isTransaction) {
        chainId = await resolveChainId();
        if (interceptData.chainId !== undefined && parseChainId(interceptData.chainId) !== chainId) {
          chainId = null;
        }
      }

      // Ask content script to analyze via background
      const verdict = await requestAnalysis(args.method, isTransaction ? { ...interceptData, chainId } : interceptData);

      if (isTransaction && chainId === null) {
        throw new Error("Transaction blocked by ShieldAI: wallet chain is unknown or mismatched");
      }

      if (verdict.action === "block") {
        throw new Error("Transaction blocked by ShieldAI Firewall");
      }

      // A verdict only covers the chain observed before analysis. Recheck even
      // when the provider does not implement chainChanged events.
      if (isTransaction) {
        const latestChainId = await resolveChainId();
        if (revision !== chainRevision || latestChainId !== chainId) {
          throw new Error("Transaction blocked by ShieldAI: wallet chain changed; retry analysis");
        }
      }

      // proceed — forward to original wallet
      return originalRequest(args);
    };

    // Use Object.defineProperty for MetaMask v11+ compatibility
    try {
      Object.defineProperty(provider, "request", {
        value: wrappedRequest,
        writable: true,
        configurable: true,
      });
    } catch (e) {
      // Fallback to direct assignment if defineProperty fails
      try {
        provider.request = wrappedRequest;
      } catch (_) {
        return;
      }
    }

    wrappedProviders.add(provider);
  }

  // HMAC of a request id under the channel token: content.js sends it with
  // SHIELDAI_TX_SHOWN, so that message cannot be forged without the token and
  // does not reveal it to the page.
  async function channelProof(requestId) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(_CHANNEL_TOKEN), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(requestId));
    return Array.from(new Uint8Array(mac), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Post message to content script and wait for verdict.
   */
  function requestAnalysis(method, txParams) {
    return new Promise((resolve) => {
      // Use cryptographically random ID (replaces Math.random)
      const requestId = crypto.randomUUID
        ? crypto.randomUUID()
        : "shieldai_" +
          Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");

      function handleMessage(event) {
        if (
          event.source !== window ||
          !event.data ||
          event.data.requestId !== requestId
        ) {
          return;
        }
        if (event.data.type === "SHIELDAI_TX_SHOWN") {
          // The overlay is on screen: wait for the user's decision instead
          // of failing closed on the timer.
          const proof = event.data.proof;
          if (_CHANNEL_TOKEN) {
            channelProof(requestId).then((expected) => {
              if (proof === expected) clearTimeout(timeout);
            });
          }
          return;
        }
        if (event.data.type !== "SHIELDAI_TX_VERDICT") {
          return;
        }
        // Reject verdicts without a valid channel token — prevents page
        // scripts from forging verdicts.  null = init not yet received.
        if (_CHANNEL_TOKEN === null || event.data._ct !== _CHANNEL_TOKEN) {
          return;
        }
        clearTimeout(timeout);
        window.removeEventListener("message", handleMessage);
        resolve(event.data);
      }

      // Fail closed: if no verdict arrives within 60 seconds, block rather than
      // forward a transaction nobody checked. The timer stops once content.js
      // proves the overlay is showing, so a user reading it is never cut off.
      const timeout = setTimeout(() => {
        window.removeEventListener("message", handleMessage);
        resolve({ action: "block", reason: "Analysis timed out" });
      }, 60000);

      window.addEventListener("message", handleMessage);

      const txPayload = {
        to: txParams.to || "",
        from: txParams.from || "",
        value: txParams.value || "0x0",
        data: txParams.data || "0x",
        chainId: txParams.chainId,
      };

      // Forward typed data and sign method for EIP-712 / signature analysis
      if (txParams.typedData) txPayload.typedData = txParams.typedData;
      if (txParams.signMethod) txPayload.signMethod = txParams.signMethod;

      window.postMessage(
        {
          type: "SHIELDAI_TX_INTERCEPT",
          requestId,
          method,
          tx: txPayload,
        },
        "*"
      );
    });
  }

  // --- Hook window.ethereum ---

  function tryWrap() {
    if (window.ethereum && !wrappedProviders.has(window.ethereum)) {
      wrapProvider(window.ethereum);
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
          if (provider && !wrappedProviders.has(provider)) {
            setTimeout(() => {
              wrapProvider(provider);
              // Restore normal property so wallet detection isn't affected
              try {
                Object.defineProperty(window, "ethereum", {
                  configurable: true,
                  enumerable: true,
                  writable: true,
                  value: provider,
                });
              } catch (_) { /* ignore */ }
            }, 0);
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
    if (detail?.provider && !wrappedProviders.has(detail.provider)) {
      wrapProvider(detail.provider);
    }
  });

  // Re-dispatch in case providers were already announced
  window.dispatchEvent(new Event("eip6963:requestProvider"));
})();
