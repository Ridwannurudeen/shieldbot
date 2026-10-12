import type { Config } from "tailwindcss";
import plugin from "tailwindcss/plugin";

// Every colour is a named token backed by a CSS custom property in src/index.css, dark on :root and light under
// :root[data-theme="light"]. Values are channel triplets so opacity modifiers work.
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
      "on-ink": token("on-ink"),
      secondary: token("secondary"),
      hairline: {
        DEFAULT: token("hairline"),
        strong: token("hairline-strong"),
      },
      edge: token("edge"),
      accent: {
        DEFAULT: token("accent"),
        fill: token("accent-fill"),
        "fill-hover": token("accent-fill-hover"),
        tint: token("accent-tint"),
        "on-panel": token("accent-on-panel"),
      },
      "on-accent": token("on-accent"),
      focus: token("focus"),
      paper: token("paper"),
      "on-paper": { DEFAULT: token("on-paper"), 2: token("on-paper-2") },
      panel: token("panel"),
      "on-panel": { DEFAULT: token("on-panel"), 2: token("on-panel-2") },

      safe: { DEFAULT: token("safe"), text: token("safe-text") },
      block: {
        DEFAULT: token("block"),
        edge: token("block-edge"),
        text: token("block-text"),
        "on-panel": token("block-on-panel"),
        "on-paper": token("block-on-paper"),
      },
      unknown: token("unknown"),
      "on-unknown": token("on-unknown"),
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
        // The alphas are per theme (src/index.css --a-*): a shadow on black needs more weight to read.
        sm: "0 1px 2px rgb(var(--c-shadow) / var(--a-sm))",
        md: "0 1px 2px rgb(var(--c-shadow) / var(--a-md1)), 0 4px 16px rgb(var(--c-shadow) / var(--a-md2))",
        lg: "0 2px 8px rgb(var(--c-shadow) / var(--a-lg))",
        button:
          "inset 0 2px 0 rgba(255, 255, 255, 0.2), 0 1px 3px rgba(0, 0, 0, 0.12)",
      },
      transitionTimingFunction: { out: "cubic-bezier(0.2, 0, 0, 1)" },
    },
  },
  // light: the one place a class differs by theme beyond its token (the hero stage's edge).
  plugins: [plugin(({ addVariant }) => addVariant("light", ':root[data-theme="light"] &'))],
} satisfies Config;
