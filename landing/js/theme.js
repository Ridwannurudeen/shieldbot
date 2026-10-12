(function () {
  var t;
  try { t = localStorage.getItem("sb-theme"); } catch (e) { return; }
  if (t === "light") document.documentElement.setAttribute("data-theme", "light");
  var m = document.querySelector('meta[name="theme-color"]');
  if (m) m.setAttribute("content", t === "light" ? "#FFFFFF" : "#0B0B0A");
})();
