(function () {
  var toggle = document.querySelector('[role="switch"]');
  if (!toggle) return;
  var themeColor = document.querySelector('meta[name="theme-color"]');
  toggle.setAttribute("aria-checked", String(document.documentElement.dataset.theme === "light"));
  toggle.addEventListener("click", function () {
    var light = toggle.getAttribute("aria-checked") !== "true";
    if (light) document.documentElement.setAttribute("data-theme", "light");
    else document.documentElement.removeAttribute("data-theme");
    toggle.setAttribute("aria-checked", String(light));
    if (themeColor) themeColor.setAttribute("content", light ? "#FFFFFF" : "#0B0B0A");
    localStorage.setItem("sb-theme", light ? "light" : "dark");
  });
})();
