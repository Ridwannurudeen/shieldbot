/**
 * ShieldAI Inject Script
 * A manifest content script that runs in the page's own JavaScript world
 * ("world": "MAIN") at document_start, in every frame, to intercept wallet
 * requests. Wraps provider.request() directly — compatible with MetaMask's
 * protected window.ethereum property.
 */
(function () {
  "use strict";

  // Page scripts share this JavaScript world and run after this file, so they
  // can replace any built-in (Set.prototype.has, Object.defineProperty,
  // crypto.subtle.sign, Promise.prototype.then, ...) before a wallet call.
  // Every built-in used after startup is taken here, while it is still the
  // browser's own, and only these references are used later.
  const uncurry = Function.prototype.bind.bind(Function.prototype.call);
  const bindTo = uncurry(Function.prototype.bind);
  // Promises are read with this then and a callback, never with await: await
  // looks up the promise's constructor and then, which a page can replace,
  // while the original then always calls back with the real value.
  const then = uncurry(Promise.prototype.then);
  const NativePromise = Promise;
  const NativeError = Error;
  const defineProperty = Object.defineProperty;
  const getPrototypeOf = Object.getPrototypeOf;
  const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const objectPrototype = Object.prototype;
  const hasOwn = Object.hasOwn;
  const setPrototypeOf = Object.setPrototypeOf;
  const isArray = Array.isArray;
  const parseJSON = JSON.parse;
  const clone = structuredClone;
  const toNumber = Number;
  const isSafeInteger = Number.isSafeInteger;
  const toRadix = uncurry(Number.prototype.toString);
  const execRegExp = uncurry(RegExp.prototype.exec);
  const Bytes = Uint8Array;
  const importKey = bindTo(crypto.subtle.importKey, crypto.subtle);
  const sign = bindTo(crypto.subtle.sign, crypto.subtle);
  const randomUUID = bindTo(crypto.randomUUID, crypto);
  const encode = bindTo(TextEncoder.prototype.encode, new TextEncoder());
  const postMessage = bindTo(window.postMessage, window);
  const addWindowListener = bindTo(window.addEventListener, window);
  const removeWindowListener = bindTo(window.removeEventListener, window);
  const removeDocumentListener = bindTo(document.removeEventListener, document);
  const setTimer = setTimeout;
  const clearTimer = clearTimeout;
  const clearTicker = clearInterval;
  const eventDetail = uncurry(Object.getOwnPropertyDescriptor(CustomEvent.prototype, "detail").get);

  // HMAC key for the channel shared with content.js. content.js hands over
  // its token once, at document_start, before any page script runs (see
  // offerToken there). It is imported straight into a non-extractable key
  // and not kept, so no later page script can read it. null until then.
  let _channelKey = null;

  // content.js hands over no token in a document another script of this page
  // can reach before the handover completes (see reachableByPage there), and
  // the same rule applies here: in such a document a key offered here could
  // come from that script. So none is taken there, and every wallet request
  // checked there is rejected.
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
  const reachable = reachableByPage();

  function takeToken(event) {
    const token = eventDetail(event);
    if (typeof token !== "string" || !token) return;
    event.preventDefault();
    removeDocumentListener("shieldai:channel", takeToken);
    _channelKey = importKey(
      "raw", encode(token), { __proto__: null, name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
  }
  if (!reachable) {
    document.addEventListener("shieldai:channel", takeToken);
    document.dispatchEvent(new CustomEvent("shieldai:channel-request"));
    // content.js offers its token at document_start or not at all. Stop
    // listening once that has passed, so a later offer, which only a page
    // script could make, cannot set the key.
    setTimer(() => removeDocumentListener("shieldai:channel", takeToken), 0);
  }

  // What kind of request a method is, or null when it is not intercepted. A
  // switch rather than a Set, so no replaceable built-in decides it.
  function requestKind(method) {
    switch (method) {
      case "eth_sendTransaction":
      case "eth_signTransaction":
        return "transaction";
      case "eth_signTypedData_v4":
      case "eth_signTypedData_v3":
      case "eth_signTypedData":
      case "eth_signTypedData_v1":
        return "typed";
      case "personal_sign":
      case "eth_sign":
        return "sign";
      case "wallet_sendCalls":
        return "calls";
      default:
        return null;
    }
  }

  // Per wrapped provider, the wrapper that checks its requests, which keeps
  // that provider's own state. Kept in this closure rather than as a flag on
  // the provider, which the page could read to detect the extension.
  const wrappedProviders = new WeakMap();
  const wrapperOf = bindTo(WeakMap.prototype.get, wrappedProviders);
  const keepWrapper = bindTo(WeakMap.prototype.set, wrappedProviders);
  const isWrapped = (provider) => wrapperOf(provider) !== undefined;

  // The wallet's own request behind each replacement put on a prototype.
  const inheritedRequests = new WeakMap();
  const inheritedRequestOf = bindTo(WeakMap.prototype.get, inheritedRequests);
  const keepInheritedRequest = bindTo(WeakMap.prototype.set, inheritedRequests);

  const CHAIN_ID_PATTERN = /^(0x[0-9a-f]+|[0-9]+)$/i;
  const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/i;

  function isPlainObject(value) {
    return typeof value === "object" && value !== null && !isArray(value);
  }

  // A property the object holds itself. A plain read of one it lacks falls
  // through to prototypes, which the page can fill.
  function ownValue(object, key) {
    return typeof object === "object" && object !== null && hasOwn(object, key) ? object[key] : undefined;
  }

  // Take the prototype off an object in the copy of a request, so a field it
  // lacks reads as undefined, for the wallet as for the analysis, instead of
  // as whatever the page put on Object.prototype.
  function ownFieldsOnly(value) {
    if (isPlainObject(value)) setPrototypeOf(value, null);
    return value;
  }

  function parseChainId(value) {
    if (typeof value !== "number" &&
        !(typeof value === "string" && execRegExp(CHAIN_ID_PATTERN, value) !== null)) {
      return null;
    }
    const chainId = toNumber(value);
    return isSafeInteger(chainId) && chainId > 0 ? chainId : null;
  }

  // Call back with the HMAC of `${requestId}:${purpose}` under the channel key:
  // the proof content.js makes too, which the page can see but cannot make.
  function withProof(requestId, purpose, callback) {
    then(_channelKey, (key) => {
      then(sign("HMAC", key, encode(`${requestId}:${purpose}`)), (mac) => callback(new Bytes(mac)));
    });
  }

  // Compare a received proof with the expected one byte by byte, using no
  // built-in a page could replace.
  function sameProof(expected, received) {
    if (typeof received !== "object" || received === null) return false;
    for (let i = 0; i < 32; i++) {
      if (received[i] !== expected[i]) return false;
    }
    return true;
  }

  /**
   * Wrap a provider's request method to intercept transactions.
   * Uses Object.defineProperty for compatibility with MetaMask v11+
   * where provider.request may be non-writable.
   */
  function wrapProvider(provider) {
    if (!provider || !provider.request || isWrapped(provider)) return;

    // A provider that inherits request from a prototype already replaced for
    // another provider gets the wallet's own request behind the replacement.
    const request = provider.request;
    const originalRequest = bindTo(inheritedRequestOf(request) || request, provider);
    wrapInheritedRequest(provider);
    let currentChainId = null;
    let chainRevision = 0;

    if (typeof provider.on === "function") {
      provider.on("chainChanged", (chainId) => {
        currentChainId = parseChainId(chainId);
        chainRevision++;
      });
    }

    // Call back with the wallet's current chain id, or null when it does not
    // answer within 5 seconds, answers something invalid, or the chain changes
    // while asking.
    function resolveChainId(callback) {
      const revision = chainRevision;
      let answered = false;
      const answer = (chainId) => {
        if (answered) return;
        answered = true;
        clearTimer(timeout);
        currentChainId = revision === chainRevision ? parseChainId(chainId) : null;
        callback(currentChainId);
      };
      const timeout = setTimer(() => answer(null), 5000);
      try {
        then(originalRequest({ method: "eth_chainId" }), answer, () => answer(null));
      } catch (_) {
        answer(null);
      }
    }

    const wrappedRequest = function (args) {
      // The method is read once, and the wallet is handed that string rather
      // than the page's object, which could answer the wallet's own read of
      // method with another one.
      const method = ownValue(args, "method");
      if (typeof method !== "string") {
        return new NativePromise((resolve, reject) => {
          reject(new NativeError("ShieldAI rejected a wallet request without a string method"));
        });
      }
      const kind = requestKind(method);
      if (kind === null) {
        const forwarded = { __proto__: null, method };
        if (hasOwn(args, "params")) forwarded.params = args.params;
        return originalRequest(forwarded);
      }

      return new NativePromise((resolve, reject) => {
        if (reachable) {
          reject(new NativeError("ShieldAI cannot check wallet requests made from this embedded frame or popup. " +
            "Open the dApp in its own tab."));
          return;
        }
        // Analyse and forward one copy of the request: a getter or proxy in
        // the page's own object could otherwise show the analysis one
        // transaction and hand the wallet another. Only values the request
        // holds itself are read from the copy.
        const request = { __proto__: null, method, params: clone(ownValue(args, "params")) };
        const forward = () => {
          try {
            resolve(originalRequest(request));
          } catch (error) {
            reject(error);
          }
        };
        const txParams = ownFieldsOnly(ownValue(request.params, 0));
        const calls = kind === "calls" ? ownValue(txParams, "calls") : undefined;

        // A transaction must be an object, and a wallet_sendCalls batch an
        // object whose calls are a non-empty list of objects. Anything else
        // cannot be analysed: the user is told so and decides.
        let structured = true;
        if (kind === "transaction") structured = isPlainObject(txParams);
        if (kind === "calls") {
          structured = isPlainObject(txParams) && isArray(calls) && calls.length > 0;
          for (let index = 0; structured && index < calls.length; index++) {
            structured = isPlainObject(ownFieldsOnly(ownValue(calls, index)));
          }
        }

        let interceptData;

        if (!structured) {
          interceptData = { __proto__: null, unknownStructure: true };
        } else if (kind === "typed") {
          // eth_signTypedData_v3 and _v4 take [address, data]. The older
          // eth_signTypedData and _v1 take [data, address] in MetaMask and
          // [address, data] in some other wallets, so the data is taken to be
          // the parameter that is not the address.
          const second = ownValue(request.params, 1);
          const dataFirst = !(typeof txParams === "string" && execRegExp(ADDRESS_PATTERN, txParams) !== null);
          const rawTypedData = ownFieldsOnly(dataFirst ? txParams : second);
          let parsedTypedData = null;
          try {
            parsedTypedData =
              typeof rawTypedData === "string"
                ? parseJSON(rawTypedData)
                : rawTypedData;
          } catch (_) {
            // Unparseable typed data goes to the overlay without its fields.
          }
          interceptData = {
            __proto__: null,
            from: dataFirst ? second : txParams,
            to: "",
            value: "0x0",
            data: "0x",
            typedData: parsedTypedData,
            signMethod: method,
          };
        } else if (kind === "sign") {
          // personal_sign: params[0] is message, params[1] is address
          // eth_sign: params[0] is address, params[1] is message
          const isPersonal = method === "personal_sign";
          interceptData = {
            __proto__: null,
            from: isPersonal ? (ownValue(request.params, 1) || "") : txParams,
            to: "",
            value: "0x0",
            data: isPersonal ? txParams : (ownValue(request.params, 1) || "0x"),
            signMethod: method,
          };
        }

        // Transactions and batches are analysed on the wallet's chain. A
        // batch is shown one call at a time, and each call is its own
        // decision; the batch goes to the wallet only once all are proceeded.
        const isTransaction = structured && (kind === "transaction" || kind === "calls");
        const count = structured && kind === "calls" ? calls.length : 1;
        // Only the fields the analysis reads are taken from the page's
        // transaction or call: any other field on it, such as a signMethod,
        // could change how content.js shows the request.
        const payloadAt = (index, chainId) => {
          if (!isTransaction) return interceptData;
          const isCall = kind === "calls";
          const source = isCall ? ownValue(calls, index) : txParams;
          return {
            __proto__: null,
            to: source.to,
            from: txParams.from,
            value: source.value,
            data: source.data,
            chainId,
            callIndex: isCall ? index + 1 : undefined,
            callCount: isCall ? count : undefined,
          };
        };
        const revision = chainRevision;

        // Ask content script to analyze via background
        const analyze = (chainId) => {
          const decide = (index) => {
            if (index < count) {
              requestAnalysis(method, payloadAt(index, chainId), (action) => {
                if (isTransaction && chainId === null) {
                  reject(new NativeError("Transaction blocked by ShieldAI: wallet chain is unknown or mismatched"));
                  return;
                }
                if (action !== "proceed") {
                  reject(new NativeError("Transaction blocked by ShieldAI Firewall"));
                  return;
                }
                decide(index + 1);
              });
              return;
            }
            if (!isTransaction) {
              forward();
              return;
            }
            // A verdict only covers the chain observed before analysis. Recheck
            // even when the provider does not implement chainChanged events.
            resolveChainId((latestChainId) => {
              if (revision !== chainRevision || latestChainId !== chainId) {
                reject(new NativeError("Transaction blocked by ShieldAI: wallet chain changed; retry analysis"));
                return;
              }
              // The wallet holds the request to the analysed chain only when
              // the request names one, so name it if the page left it out.
              if (txParams.chainId === undefined) txParams.chainId = `0x${toRadix(chainId, 16)}`;
              // proceed — forward to original wallet
              forward();
            });
          };
          decide(0);
        };

        if (!isTransaction) {
          analyze(null);
          return;
        }
        resolveChainId((chainId) => {
          if (txParams.chainId !== undefined && parseChainId(txParams.chainId) !== chainId) {
            analyze(null);
            return;
          }
          analyze(chainId);
        });
      });
    };

    // Use Object.defineProperty for MetaMask v11+ compatibility. The
    // descriptor has no prototype, so a page that adds get or set to
    // Object.prototype cannot turn it into an accessor.
    try {
      defineProperty(provider, "request", {
        __proto__: null,
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

    keepWrapper(provider, wrappedRequest);
  }

  // A page could take request from the provider's prototype and call it on
  // the provider (Object.getPrototypeOf(ethereum).request.call(ethereum, ...)),
  // going round the wrapper defined on the provider itself. So the request of
  // the nearest prototype that defines one is replaced too, by one that checks
  // the request for whichever provider it is called on, wrapping that provider
  // first if need be. A call on anything that cannot be wrapped is rejected.
  function wrapInheritedRequest(provider) {
    let owner = getPrototypeOf(provider);
    while (owner !== null && owner !== objectPrototype &&
        getOwnPropertyDescriptor(owner, "request") === undefined) {
      owner = getPrototypeOf(owner);
    }
    if (owner === null || owner === objectPrototype) return;
    const inherited = getOwnPropertyDescriptor(owner, "request").value;
    if (typeof inherited !== "function" || inheritedRequestOf(inherited) !== undefined) return;

    const replacement = function (args) {
      // Called on the prototype itself, there is no provider to check for.
      if (this !== owner) wrapProvider(this);
      const wrapper = wrapperOf(this);
      if (wrapper === undefined) {
        return new NativePromise((resolve, reject) => {
          reject(new NativeError("Transaction blocked by ShieldAI Firewall"));
        });
      }
      return wrapper(args);
    };
    keepInheritedRequest(replacement, inherited);
    try {
      defineProperty(owner, "request", { __proto__: null, value: replacement });
    } catch (_) {
      // A prototype that forbids it keeps the wallet's request there.
    }
  }

  /**
   * Post the request to the content script and call back with "block" or
   * "proceed" once a verdict with a valid proof arrives.
   */
  function requestAnalysis(method, txParams, decide) {
    // Without the channel no verdict can be trusted, so fail closed now.
    if (_channelKey === null) {
      decide("block");
      return;
    }

    const requestId = randomUUID();
    let decided = false;
    const finish = (action) => {
      if (decided) return;
      decided = true;
      clearTimer(timeout);
      removeWindowListener("message", handleMessage);
      decide(action);
    };

    function handleMessage(event) {
      // Anything read here comes from a page-visible message and counts only
      // once its proof checks out.
      const data = event.data;
      if (event.source !== window || !data || data.requestId !== requestId) {
        return;
      }
      const { type, action, proof } = data;
      if (type === "SHIELDAI_TX_SHOWN") {
        // The overlay is on screen: wait for the user's decision instead
        // of failing closed on the timer.
        withProof(requestId, "shown", (expected) => {
          if (sameProof(expected, proof)) clearTimer(timeout);
        });
        return;
      }
      // A verdict counts only with the proof content.js makes for that exact
      // action, so the page can neither forge one nor relabel a Block.
      if (type !== "SHIELDAI_TX_VERDICT" || (action !== "block" && action !== "proceed")) {
        return;
      }
      withProof(requestId, action, (expected) => {
        if (sameProof(expected, proof)) finish(action);
      });
    }

    // Fail closed: if no verdict arrives within 60 seconds, block rather than
    // forward a transaction nobody checked. The timer stops once content.js
    // proves the overlay is showing, so a user reading it is never cut off.
    const timeout = setTimer(() => finish("block"), 60000);

    addWindowListener("message", handleMessage);

    const txPayload = {
      __proto__: null,
      to: txParams.to || "",
      from: txParams.from || "",
      value: txParams.value || "0x0",
      data: txParams.data || "0x",
      chainId: txParams.chainId,
    };

    // Forward typed data and sign method for EIP-712 / signature analysis
    if (txParams.typedData) txPayload.typedData = txParams.typedData;
    if (txParams.signMethod) txPayload.signMethod = txParams.signMethod;
    if (txParams.callCount) {
      txPayload.callIndex = txParams.callIndex;
      txPayload.callCount = txParams.callCount;
    }
    if (txParams.unknownStructure) txPayload.unknownStructure = true;

    withProof(requestId, "intercept", (proof) => {
      postMessage(
        {
          type: "SHIELDAI_TX_INTERCEPT",
          requestId,
          method,
          tx: txPayload,
          proof,
        },
        "*"
      );
    });
  }

  // --- Hook window.ethereum ---

  function tryWrap() {
    const provider = window.ethereum;
    if (provider && !isWrapped(provider)) {
      wrapProvider(provider);
      return true;
    }
    return false;
  }

  if (!tryWrap()) {
    // Provider not ready yet — watch for it via defineProperty or polling
    let _pending = window.ethereum;

    try {
      defineProperty(window, "ethereum", {
        __proto__: null,
        configurable: true,
        enumerable: true,
        get() {
          return _pending;
        },
        set(provider) {
          _pending = provider;
          if (provider && !isWrapped(provider)) {
            // Wrap before anything else can use the provider.
            wrapProvider(provider);
            // Restore normal property so wallet detection isn't affected
            setTimer(() => {
              try {
                defineProperty(window, "ethereum", {
                  __proto__: null,
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
        if (tryWrap()) clearTicker(poll);
      }, 200);
      setTimer(() => clearTicker(poll), 30000);
    }
  }


  // --- Hook EIP-6963 providers (Rabby, modern MetaMask, etc.) ---

  addWindowListener("eip6963:announceProvider", (event) => {
    const detail = eventDetail(event);
    if (detail?.provider && !isWrapped(detail.provider)) {
      wrapProvider(detail.provider);
    }
  });

  // Re-dispatch in case providers were already announced
  window.dispatchEvent(new Event("eip6963:requestProvider"));
})();
