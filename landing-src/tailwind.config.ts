import type { Config } from "tailwindcss";

// Every colour is a named token backed by a CSS custom property in src/index.css.
// Values are channel triplets so opacity modifiers work.
const token = (name: string) => `rgb(var(--c-${name}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    colors: {
      transparent: "transparent",
      current: "currentColor",
      white: "#FFFFFF",
      ground: { DEFAULT: token("ground"), alt: token("ground-alt") },
      ink: token("ink"),
      secondary: token("secondary"),
      hairline: {
        DEFAULT: token("hairline"),
        strong: token("hairline-strong"),
      },
      accent: {
        DEFAULT: token("accent"),
        hover: token("accent-hover"),
        tint: token("accent-tint"),
        "on-panel": token("accent-on-panel"),
      },
      "on-accent": token("on-accent"),
      panel: token("panel"),
      "on-panel": { DEFAULT: token("on-panel"), 2: token("on-panel-2") },

      safe: { DEFAULT: token("safe"), text: token("safe-text") },
      block: {
        DEFAULT: token("block"),
        text: token("block-text"),
        "on-panel": token("block-on-panel"),
      },
      unknown: token("unknown"),
    },
    extend: {
      fontFamily: {
        sans: [
          '"Geist"',
          '"Geist Fallback"',
          "Arial",
          "Helvetica",
          "sans-serif",
        ],
        mono: [
          '"IBM Plex Mono"',
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          '"Liberation Mono"',
          "monospace",
        ],
      },
      fontSize: {
        display: [
          "4rem",
          { lineHeight: "1.04", letterSpacing: "-0.03em", fontWeight: "500" },
        ],
        "display-sm": [
          "2.5rem",
          { lineHeight: "1.04", letterSpacing: "-0.03em", fontWeight: "500" },
        ],
        h2: [
          "2.5rem",
          { lineHeight: "1.125", letterSpacing: "-0.025em", fontWeight: "500" },
        ],
        "h2-sm": [
          "1.875rem",
          { lineHeight: "1.125", letterSpacing: "-0.025em", fontWeight: "500" },
        ],
      },
      borderRadius: { lg: "6px" },
      boxShadow: {
        sm: "0 1px 2px rgba(20, 20, 20, 0.06)",
        md: "0 1px 2px rgba(20, 20, 20, 0.04), 0 4px 16px rgba(20, 20, 20, 0.06)",
        lg: "0 2px 8px rgba(20, 20, 20, 0.18)",
        button:
          "inset 0 2px 0 rgba(255, 255, 255, 0.2), 0 1px 3px rgba(0, 0, 0, 0.12)",
      },
      transitionTimingFunction: { out: "cubic-bezier(0.2, 0, 0, 1)" },
    },
  },
  plugins: [],
} satisfies Config;
