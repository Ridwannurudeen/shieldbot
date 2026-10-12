import Icon from "./Icon";
import { setTheme, useTheme } from "../theme";

// The theme switch (THEME-SPEC 4.2): a native button with role="switch", checked when the light theme is on. Enter
// and Space toggle it; the glyph is a sun while dark and a moon while light.
export default function ThemeToggle() {
  const light = useTheme() === "light";
  return (
    <button
      type="button"
      role="switch"
      aria-checked={light}
      aria-label="Light theme"
      title="Light theme"
      onClick={() => setTheme(light ? "dark" : "light")}
      className="inline-flex h-9 w-9 flex-none items-center justify-center rounded-lg text-ink transition-colors duration-150 ease-out hover:bg-ground-alt"
    >
      <Icon name={light ? "moon" : "sun"} size={16} />
    </button>
  );
}
