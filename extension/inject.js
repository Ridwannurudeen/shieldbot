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
  const callFunction = uncurry(Function.prototype.call);
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
  const NativeMutationObserver = MutationObserver;
  const observeMutations = uncurry(MutationObserver.prototype.observe);
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

  // Requests waiting for a verdict, by id, with the function that ends each.
  const pendingRequests = new Map();
  const keepPending = bindTo(Map.prototype.set, pendingRequests);
  const dropPending = bindTo(Map.prototype.delete, pendingRequests);
  const forEachPending = bindTo(Map.prototype.forEach, pendingRequests);

  // document.open() takes the extension's listeners away with the document,
  // so the Block content.js posts for a request whose overlay went with it
  // would never arrive. When the root element is replaced, every request
  // waiting for a verdict is rejected instead.
  let rootElement = document.documentElement;
  observeMutations(new NativeMutationObserver(() => {
    if (document.documentElement === rootElement) return;
    rootElement = document.documentElement;
    forEachPending((finish) => finish("block"));
  }), document, { __proto__: null, childList: true });

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

  // Per wrapped provider, the function that checks its requests, which keeps
  // that provider's own state. Kept in this closure rather than as a flag on
  // the provider, which the page could read to detect the extension.
  const wrappedProviders = new WeakMap();
  const checkOf = bindTo(WeakMap.prototype.get, wrappedProviders);
  const keepCheck = bindTo(WeakMap.prototype.set, wrappedProviders);
  const isWrapped = (provider) => checkOf(provider) !== undefined;

  // The wallet's own function (request, send or sendAsync) behind each
  // replacement put on a prototype.
  const inheritedOriginals = new WeakMap();
  const originalOf = bindTo(WeakMap.prototype.get, inheritedOriginals);
  const keepOriginal = bindTo(WeakMap.prototype.set, inheritedOriginals);

  // A prototype's function that could not be replaced (it is neither writable
  // nor configurable), so it is not tried again. The README says that route
  // is not covered.
  const uncoveredFunctions = new WeakSet();
  const isUncovered = bindTo(WeakSet.prototype.has, uncoveredFunctions);
  const markUncovered = bindTo(WeakSet.prototype.add, uncoveredFunctions);

  // Checked copies on their way to the wallet. When the wallet's own code
  // hands one on to a prototype's request (a subclass calling
  // super.request(args)), it goes through unchecked rather than twice.
  const forwardedCopies = new WeakSet();
  const isForwarded = bindTo(WeakSet.prototype.has, forwardedCopies);
  const markForwarded = bindTo(WeakSet.prototype.add, forwardedCopies);

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
    // A prototype whose request was replaced is not a provider to wrap.
    if (originalOf(ownValue(provider, "request")) !== undefined) return;

    // A provider that inherits request from a prototype already replaced for
    // another provider gets the wallet's own request behind the replacement.
    const request = provider.request;
    const originalRequest = bindTo(originalOf(request) || request, provider);
    let currentChainId = null;
    let chainRevision = 0;

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

    // Run a request past the user and hand it to forwardTo: the wallet's own
    // request that was called, applied to this provider.
    const check = function (args, forwardTo) {
      return new NativePromise((resolve, reject) => {
        // The method is read once, here so that a request object that throws
        // rejects, and the wallet is handed that string rather than the page's
        // object, which could answer the wallet's own read of method with
        // another one.
        const method = ownValue(args, "method");
        if (typeof method !== "string") {
          reject(new NativeError("ShieldAI rejected a wallet request without a string method"));
          return;
        }
        const kind = requestKind(method);
        if (kind === null) {
          resolve(forwardTo(hasOwn(args, "params") ? { method, params: args.params } : { method }));
          return;
        }
        if (reachable) {
          const error = new NativeError("ShieldAI cannot check wallet requests made from this embedded frame or " +
            "popup. Open the dApp in its own tab.");
          // EIP-1193 4100: Unauthorized.
          defineProperty(error, "code", {
            __proto__: null,
            value: 4100,
            writable: true,
            enumerable: true,
            configurable: true,
          });
          // content.js shows the user a notice saying why, once.
          postMessage({ type: "SHIELDAI_UNCHECKABLE" }, "*");
          reject(error);
          return;
        }
        // Analyse and forward one copy of the request: a getter or proxy in
        // the page's own object could otherwise show the analysis one
        // transaction and hand the wallet another. Only values the request
        // holds itself are read from the copy.
        const request = { __proto__: null, method, params: clone(ownValue(args, "params")) };
        const forward = () => {
          try {
            markForwarded(request);
            resolve(forwardTo(request));
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

        const unknownStructure = { __proto__: null, unknownStructure: true };
        let interceptData;

        if (!structured) {
          interceptData = unknownStructure;
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

        // Ask content script to analyze via background. A batch that cannot be
        // analysed as it stands is shown as one request of unknown structure.
        const analyze = (chainId, unreadable) => {
          const decisions = unreadable ? 1 : count;
          const decide = (index) => {
            if (index < decisions) {
              requestAnalysis(method, unreadable ? unknownStructure : payloadAt(index, chainId), (action) => {
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
        // A batch call that names a chain of its own other than the bound one
        // cannot be analysed on that chain.
        const callOnAnotherChain = (chainId) => {
          for (let index = 0; index < count; index++) {
            const callChainId = ownValue(calls, index).chainId;
            if (callChainId !== undefined && parseChainId(callChainId) !== chainId) return true;
          }
          return false;
        };

        resolveChainId((chainId) => {
          if (txParams.chainId !== undefined && parseChainId(txParams.chainId) !== chainId) {
            analyze(null);
            return;
          }
          if (kind === "calls" && callOnAnotherChain(chainId)) {
            analyze(null, true);
            return;
          }
          analyze(chainId);
        });
      });
    };

    const wrappedRequest = function (args) {
      return check(args, originalRequest);
    };

    // Recorded before anything below can call back into the page, which
    // could otherwise reach this code again for the same provider.
    keepCheck(provider, check);
    wrapInherited(provider, "request", requestReplacement);
    wrapLegacy(provider, "send");
    wrapLegacy(provider, "sendAsync");
    if (typeof provider.on === "function") {
      provider.on("chainChanged", (chainId) => {
        currentChainId = parseChainId(chainId);
        chainRevision++;
      });
    }

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
        // The provider's own request stays the wallet's.
      }
    }
  }

  // A page could take a method from one of the provider's prototypes and call
  // it on the provider (Object.getPrototypeOf(ethereum).request.call(ethereum,
  // ...)), going round the wrapper defined on the provider itself. So the
  // method of every prototype that defines one, up to Object.prototype, is
  // replaced too, by the function makeReplacement makes from that prototype's
  // own one.
  function wrapInherited(provider, name, makeReplacement) {
    for (let owner = getPrototypeOf(provider); owner !== null && owner !== objectPrototype;
      owner = getPrototypeOf(owner)) {
      const inherited = ownValue(getOwnPropertyDescriptor(owner, name), "value");
      if (typeof inherited !== "function" || originalOf(inherited) !== undefined || isUncovered(inherited)) {
        continue;
      }
      const replacement = makeReplacement(inherited);
      try {
        defineProperty(owner, name, { __proto__: null, value: replacement });
        keepOriginal(replacement, inherited);
      } catch (_) {
        markUncovered(inherited);
      }
    }
  }

  // A prototype's request is replaced by one that checks the request for
  // whichever provider it is called on (wrapping that provider first if need
  // be) and then hands it to that prototype's own request. A call on anything
  // that cannot be wrapped, such as a prototype itself, is rejected.
  function requestReplacement(inherited) {
    return function (args) {
      if (isForwarded(args)) return callFunction(inherited, this, args);
      wrapProvider(this);
      const check = checkOf(this);
      if (check === undefined) {
        return new NativePromise((resolve, reject) => {
          reject(new NativeError("Transaction blocked by ShieldAI Firewall"));
        });
      }
      const target = this;
      return check(args, (copy) => callFunction(inherited, target, copy));
    };
  }

  // Refuses the methods request would check when they come through send or
  // sendAsync, a provider's older methods, which the check cannot hold for
  // the user's decision. A call is refused, in the shape its caller expects,
  // when any method it asks for is checked or cannot be read. A method is a
  // string first argument, a payload object's own method, or the own method
  // of each payload in an array. Any other call goes to the wallet with its
  // own this and arguments, except that a payload object is handed on as the
  // copy its methods were read from, so a getter or proxy cannot show one
  // method here and another to the wallet.
  function legacyReplacement(original) {
    return function (first, second) {
      let payload = first;
      let refused;
      if (typeof first === "string") {
        refused = requestKind(first) !== null;
      } else {
        try {
          payload = clone(first);
          refused = refusesPayloads(payload);
        } catch (_) {
          // A payload that cannot be copied cannot be read either.
          refused = true;
        }
      }
      if (!refused) {
        return arguments.length < 2
          ? callFunction(original, this, payload)
          : callFunction(original, this, payload, second);
      }
      const error = new NativeError("ShieldAI cannot check wallet requests made with send or sendAsync. " +
        "Use request instead.");
      if (typeof second === "function") {
        setTimer(() => second(error), 0);
        return undefined;
      }
      if (typeof first === "string") {
        return new NativePromise((resolve, reject) => {
          reject(error);
        });
      }
      throw error;
    };
  }

  function refusesPayloads(payload) {
    if (!isArray(payload)) return refusesPayload(payload);
    for (let index = 0; index < payload.length; index++) {
      if (refusesPayload(ownValue(payload, index))) return true;
    }
    return false;
  }

  function refusesPayload(payload) {
    const method = isPlainObject(payload) ? ownValue(payload, "method") : undefined;
    return typeof method !== "string" || requestKind(method) !== null;
  }

  // send and sendAsync are replaced on the provider itself and on its
  // prototypes, as request is.
  function wrapLegacy(provider, name) {
    const own = provider[name];
    if (typeof own !== "function") return;
    wrapInherited(provider, name, legacyReplacement);
    const replacement = legacyReplacement(bindTo(originalOf(own) || own, provider));
    try {
      defineProperty(provider, name, {
        __proto__: null,
        value: replacement,
        writable: true,
        configurable: true,
      });
    } catch (_) {
      try {
        provider[name] = replacement;
      } catch (_) {
        // The provider's own method stays the wallet's.
      }
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
      dropPending(requestId);
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

    keepPending(requestId, finish);
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
