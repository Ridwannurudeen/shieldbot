/**
 * ShieldAI i18n module
 * Supports: en (English), zh (Chinese Simplified), vi (Vietnamese)
 * Attaches to window — loaded via <script src="i18n.js"> in popup.html and welcome.html
 */
(function () {
  const SUPPORTED = ["en", "zh", "vi"];
  const DEFAULT = "en";
  let _tr = {};
  let _lang = DEFAULT;

  function _chromeGet(defaults) {
    return new Promise((resolve) =>
      chrome.storage.local.get(defaults, resolve)
    );
  }

  async function _loadBundle(lang) {
    const url = chrome.runtime.getURL(`locales/${lang}/messages.json`);
    try {
      const resp = await fetch(url);
      _tr = await resp.json();
    } catch (_) {
      if (lang !== DEFAULT) {
        try {
          const fallback = chrome.runtime.getURL(`locales/${DEFAULT}/messages.json`);
          const resp = await fetch(fallback);
          _tr = await resp.json();
        } catch (__) {
          _tr = {};
        }
      } else {
        _tr = {};
      }
    }
  }

  async function initI18n() {
    const stored = await _chromeGet({ language: DEFAULT });
    _lang = SUPPORTED.includes(stored.language) ? stored.language : DEFAULT;
    await _loadBundle(_lang);
  }

  function t(key, replacements) {
    let str = _tr[key] !== undefined ? _tr[key] : key;
    if (replacements) {
      Object.entries(replacements).forEach(([k, v]) => {
        str = str.replace(`{${k}}`, v);
      });
    }
    return str;
  }

  async function setLanguage(lang) {
    if (!SUPPORTED.includes(lang)) return;
    _lang = lang;
    await chrome.storage.local.set({ language: lang });
    await _loadBundle(lang);
  }

  function getCurrentLang() {
    return _lang;
  }

  function applyTranslations() {
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      el.textContent = t(el.dataset.i18n);
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
      el.placeholder = t(el.dataset.i18nPlaceholder);
    });
  }

  // Expose to window
  window.initI18n = initI18n;
  window.t = t;
  window.setLanguage = setLanguage;
  window.getCurrentLang = getCurrentLang;
  window.applyTranslations = applyTranslations;
})();
