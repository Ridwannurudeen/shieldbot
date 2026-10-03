import { useState } from "react";
import Icon from "./Icon";

const STORAGE_KEY = "shieldbot-theme"; // the same literal as the restore script in index.html
const THEME_COLOR = { dark: "#0F172A", light: "#FFFFFF" } as const;

export default function ThemeToggle({ className }: { className?: string }) {
  const [dark, setDark] = useState(() => document.documentElement.getAttribute("data-theme") !== "light");

  function toggle() {
    const next = dark ? "light" : "dark";
    const root = document.documentElement;
    root.setAttribute("data-theme-switching", "");
    root.setAttribute("data-theme", next);
    document.querySelector('meta[name="theme-color"]')!.setAttribute("content", THEME_COLOR[next]);
    document.querySelector('meta[name="color-scheme"]')!.setAttribute("content", next);
    requestAnimationFrame(() => requestAnimationFrame(() => root.removeAttribute("data-theme-switching")));
    setDark(!dark);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Storage unavailable: the theme applies for this page and is not remembered.
    }
  }

  return (
    <button
      type="button"
      role="switch"
      aria-checked={dark}
      aria-label="Dark theme"
      onClick={toggle}
      className={["inline-flex h-11 w-11 items-center justify-center rounded-lg text-muted hover:bg-surface-3 hover:text-ink transition-colors duration-150 ease-out", className].filter(Boolean).join(" ")}
    >
      <Icon name={dark ? "moon" : "sun"} size={20} />
    </button>
  );
}
