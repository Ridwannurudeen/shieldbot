// Plausible Analytics' queue and settings, as a file: the site's Content-Security-Policy allows scripts
// from this origin only, so the inline snippet Plausible gives is not an option. nginx proxies both
// /js/script.js and /stats/event to Plausible (deploy/nginx-shieldbotsecurity-new.conf).
window.plausible =
  window.plausible ||
  function () {
    (plausible.q = plausible.q || []).push(arguments);
  };
plausible.init =
  plausible.init ||
  function (i) {
    plausible.o = i || {};
  };
plausible.init({ endpoint: "/stats/event" });
