/**
 * ShieldAI Inject Script
 * Runs in the PAGE context to proxy window.ethereum.
 * Uses Proxy object for robust interception that can't be bypassed.
 */
(function () {
  "use strict";

  if (window.__shieldai_injected) return;
  window.__shieldai_injected = true;

  const INTERCEPTED_METHODS = new Set([
    "eth_sendTransaction",
    "eth_signTransaction",
  ]);

  function interceptedRequest(originalRequest, provider, args) {
    if (!args || !INTERCEPTED_METHODS.has(args.method)) {
      return originalRequest.call(provider, args);
    }

    const txParams = args.params?.[0];
    if (!txParams) {
      return originalRequest.call(provider, args);
    }

    console.log("[ShieldAI] Intercepted:", args.method, txParams);

    return new Promise((resolve, reject) => {
      const requestId =
        "shieldai_" + Date.now() + "_" + Math.random().toString(36).slice(2);

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
          originalRequest.call(provider, args).then(resolve).catch(reject);
        } else {
          reject(new Error("Transaction blocked by ShieldAI Firewall"));
        }
      }

      window.addEventListener("message", handleVerdict);

      setTimeout(() => {
        window.removeEventListener("message", handleVerdict);
        reject(new Error("ShieldAI Firewall: Analysis timed out"));
      }, 300000);
    });
  }

  function createProviderProxy(provider) {
    if (!provider || provider.__shieldai_proxied) return provider;

    const originalRequest = provider.request;

    const handler = {
      get(target, prop, receiver) {
        if (prop === "__shieldai_proxied") return true;

        if (prop === "request") {
          return function (args) {
            return interceptedRequest(originalRequest, target, args);
          };
        }

        const value = Reflect.get(target, prop, receiver);
        if (typeof value === "function") {
          return value.bind(target);
        }
        return value;
      },
    };

    return new Proxy(provider, handler);
  }

  // Wrap and replace window.ethereum
  function installProxy() {
    if (window.ethereum && !window.ethereum.__shieldai_proxied) {
      const proxied = createProviderProxy(window.ethereum);

      // Try to replace window.ethereum with our proxy
      try {
        Object.defineProperty(window, "ethereum", {
          configurable: true,
          enumerable: true,
          get() {
            return proxied;
          },
          set(newVal) {
            // If something tries to set a new provider, proxy that too
            if (newVal && !newVal.__shieldai_proxied) {
              const newProxied = createProviderProxy(newVal);
              Object.defineProperty(window, "ethereum", {
                configurable: true,
                enumerable: true,
                get() { return newProxied; },
                set: arguments.callee,
              });
            }
          },
        });
      } catch (e) {
        // Fallback: direct property override
        try {
          window.ethereum = proxied;
        } catch (e2) {
          console.warn("[ShieldAI] Could not proxy ethereum provider:", e2);
          return false;
        }
      }

      console.log("[ShieldAI] Firewall active — intercepting transactions");
      return true;
    }
    return false;
  }

  // Try immediately
  if (!installProxy()) {
    // MetaMask not ready yet — watch for it
    let _pendingEthereum = window.ethereum;
    let installed = false;

    try {
      Object.defineProperty(window, "ethereum", {
        configurable: true,
        enumerable: true,
        get() {
          return _pendingEthereum;
        },
        set(provider) {
          _pendingEthereum = provider;
          if (provider && !installed) {
            installed = true;
            // Let MetaMask finish initialization, then proxy
            setTimeout(() => {
              _pendingEthereum = createProviderProxy(provider);
              console.log("[ShieldAI] Firewall active — intercepting transactions");
            }, 10);
          }
        },
      });
    } catch (e) {
      // Last resort: poll
      const poll = setInterval(() => {
        if (installProxy()) {
          clearInterval(poll);
        }
      }, 200);
      setTimeout(() => clearInterval(poll), 30000);
    }
  }

  // Also handle EIP-6963 provider announcements (modern wallet discovery)
  window.addEventListener("eip6963:announceProvider", (event) => {
    const info = event.detail;
    if (info?.provider && !info.provider.__shieldai_proxied) {
      const originalRequest = info.provider.request;
      info.provider.request = function (args) {
        return interceptedRequest(originalRequest, info.provider, args);
      };
      info.provider.__shieldai_proxied = true;
      console.log("[ShieldAI] Wrapped EIP-6963 provider:", info.info?.name);
    }
  });
})();
