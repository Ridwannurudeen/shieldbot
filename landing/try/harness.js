// Fires one transaction per firewall outcome so the extension's overlay can be watched deciding.
// Every case is read-only in effect: the firewall answers before the wallet is asked, and a request
// that reaches the wallet still needs the user to confirm it there.
(function () {
  "use strict";

  var CHAIN_HEX = "0x1237"; // 4663
  var BLOCKED_TOKEN = "0x473b2f540a5457b839d0bb89af6419c53f4b0714";
  var UNKNOWN_TOKEN = "0x0b9907ea996b7b407cbeda47c65125aa3749d777";
  var BURN = "0x000000000000000000000000000000000000dEaD";
  var SPENDER = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

  var logEl = document.getElementById("log");
  var acctEl = document.getElementById("acct");
  var chainEl = document.getElementById("chain");
  var account = null;

  function log(line) {
    logEl.textContent = new Date().toLocaleTimeString() + "  " + line + "\n" + logEl.textContent;
  }

  function provider() {
    if (!window.ethereum) {
      log("No injected wallet on this page. Install one, then reload.");
      return null;
    }
    return window.ethereum;
  }

  // approve(address,uint256) with the maximum allowance
  function approveData(spender) {
    return "0x095ea7b3" + spender.slice(2).toLowerCase().padStart(64, "0") + "f".repeat(64);
  }

  function refresh() {
    var p = provider();
    if (!p) return;
    p.request({ method: "eth_chainId" }).then(function (id) {
      chainEl.textContent = id === CHAIN_HEX ? "Robinhood Chain (4663)" : "chain " + parseInt(id, 16);
    }).catch(function () { chainEl.textContent = "chain unknown"; });
  }

  document.getElementById("connect").onclick = function () {
    var p = provider();
    if (!p) return;
    p.request({ method: "eth_requestAccounts" }).then(function (accounts) {
      account = accounts[0];
      acctEl.textContent = account.slice(0, 6) + "..." + account.slice(-4);
      log("Connected " + account);
      refresh();
    }).catch(function (e) { log("Connect refused: " + (e && e.message)); });
  };

  document.getElementById("switch").onclick = function () {
    var p = provider();
    if (!p) return;
    p.request({ method: "wallet_switchEthereumChain", params: [{ chainId: CHAIN_HEX }] })
      .then(function () { log("Switched to Robinhood Chain."); refresh(); })
      .catch(function (e) {
        if (e && e.code === 4902) {
          p.request({ method: "wallet_addEthereumChain", params: [{
            chainId: CHAIN_HEX,
            chainName: "Robinhood Chain",
            nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
            rpcUrls: ["https://robinhood-rpc.publicnode.com"],
            blockExplorerUrls: ["https://robin.etherscan.io"]
          }]}).then(function () { log("Robinhood Chain added."); refresh(); })
            .catch(function (addErr) { log("Could not add the chain: " + (addErr && addErr.message)); });
        } else {
          log("Switch refused: " + (e && e.message));
        }
      });
  };

  var CASES = {
    block: { to: BLOCKED_TOKEN, data: approveData(SPENDER), value: "0x0", label: "unlimited approval to a plain address" },
    unknown: { to: UNKNOWN_TOKEN, data: "0x", value: "0x0", label: "transfer to an unsettled token" },
    safe: { to: BURN, data: "0x", value: "0x0", label: "transfer to the burn address" }
  };

  Array.prototype.forEach.call(document.querySelectorAll("[data-test]"), function (button) {
    button.onclick = function () {
      var p = provider();
      if (!p) return;
      if (!account) { log("Connect a wallet first."); return; }
      var c = CASES[button.getAttribute("data-test")];
      log("Sending: " + c.label + " -> " + c.to);
      button.disabled = true;
      p.request({ method: "eth_sendTransaction", params: [{ from: account, to: c.to, data: c.data, value: c.value }] })
        .then(function (hash) {
          log("REACHED THE WALLET and was submitted: " + hash + "  (the firewall did not stop it)");
        })
        .catch(function (e) {
          var msg = (e && e.message) || String(e);
          if (/ShieldAI/i.test(msg)) log("STOPPED BY SHIELDBOT: " + msg);
          else log("Rejected: " + msg);
        })
        .then(function () { button.disabled = false; });
    };
  });

  if (window.ethereum) {
    if (window.ethereum.on) window.ethereum.on("chainChanged", refresh);
    refresh();
  } else {
    log("No injected wallet detected on this page.");
  }
})();
