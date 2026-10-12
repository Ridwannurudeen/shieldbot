import { useSyncExternalStore } from "react";

// The site's theme (THEME-SPEC 4): dark is the default and needs no attribute; light is
// <html data-theme="light">. /js/theme.js restores a stored choice before first paint; this store is the
// toggle's side: it reads the attribute, and setTheme writes the attribute, the theme-color meta and
// localStorage["sb-theme"], then tells every reader.
export type Theme = "dark" | "light";

const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function current(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function useTheme(): Theme {
  return useSyncExternalStore(subscribe, current);
}

export function setTheme(theme: Theme) {
  if (theme === "light") document.documentElement.dataset.theme = "light";
  else delete document.documentElement.dataset.theme;
  document
    .querySelector('meta[name="theme-color"]')
    ?.setAttribute("content", theme === "light" ? "#FFFFFF" : "#0B0B0A");
  listeners.forEach((listener) => listener());
  try {
    localStorage.setItem("sb-theme", theme);
  } catch {
    // Storage is blocked (a private window): the choice applies to this page and is not remembered.
    return;
  }
}
