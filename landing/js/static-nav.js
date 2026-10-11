const menu = document.querySelector(".mobile-menu");
const toggle = menu.querySelector("summary");

menu.addEventListener("toggle", () => {
  toggle.setAttribute("aria-expanded", String(menu.open));
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape" || !menu.open) return;

  menu.open = false;
  toggle.focus();
});
