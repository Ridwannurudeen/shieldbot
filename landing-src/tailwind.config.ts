import type { Config } from "tailwindcss";

// Every colour is a named token backed by a CSS custom property in src/index.css.
// Values are channel triplets so opacity modifiers work.
const token = (name: string) => `rgb(var(--c-${name}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["selector", '[data-theme="dark"]'],
  theme: {
    colors: {
      transparent: "transparent",
      current: "currentColor",
      white: "#FFFFFF",
      ink: token("ink"),
      body: token("body"),
      muted: token("muted"),
      faint: token("faint"),
      surface: { DEFAULT: token("surface"), 2: token("surface-2"), 3: token("surface-3") },
      panel: token("panel"),
      field: token("field"),
      line: { DEFAULT: token("line"), strong: token("line-strong") },
      emerald: {
        DEFAULT: token("emerald"),
        deep: token("emerald-deep"),
        bright: token("emerald-bright"),
        tint: token("emerald-tint"),
        line: token("emerald-line"),
        onink: token("emerald-onink"),
      },
      onink: { DEFAULT: token("onink"), muted: token("onink-muted"), error: token("onink-error") },
      onfill: token("onfill"),
      safe: { fg: token("safe-fg"), tint: token("safe-tint"), line: token("safe-line") },
      caution: { fg: token("caution-fg"), tint: token("caution-tint"), line: token("caution-line") },
      high: { fg: token("high-fg"), tint: token("high-tint"), line: token("high-line") },
      block: { fg: token("block-fg"), tint: token("block-tint"), line: token("block-line") },
      unknown: { fg: token("unknown-fg"), tint: token("unknown-tint"), stripe: token("unknown-stripe"), line: token("unknown-line"), deep: "#3F4B5E" },
    },
    extend: {
      fontFamily: {
        sans: ['"Manrope Variable"', '"Manrope Fallback"', "Arial", "Helvetica", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", '"Liberation Mono"', "monospace"],
      },
      fontSize: {
        display: ["4rem", { lineHeight: "1.04", letterSpacing: "-0.03em", fontWeight: "800" }],
        "display-sm": ["2.5rem", { lineHeight: "1.04", letterSpacing: "-0.03em", fontWeight: "800" }],
        h2: ["2.5rem", { lineHeight: "1.1", letterSpacing: "-0.025em", fontWeight: "700" }],
        "h2-sm": ["1.875rem", { lineHeight: "1.1", letterSpacing: "-0.025em", fontWeight: "700" }],
      },
      borderRadius: { lg: "10px" },
      boxShadow: {
        sm: "var(--shadow-sm)",
        md: "var(--shadow-md)",
        lg: "var(--shadow-lg)",
        button: "var(--shadow-button)",
      },
      backgroundImage: {
        "unknown-hatch": "repeating-linear-gradient(135deg, rgb(var(--c-unknown-tint)) 0 6px, rgb(var(--c-unknown-stripe)) 6px 12px)",
        "unknown-hatch-solid": "repeating-linear-gradient(135deg, #475569 0 6px, #3F4B5E 6px 12px)",
      },
      transitionTimingFunction: { out: "cubic-bezier(0.2, 0, 0, 1)" },
    },
  },
  plugins: [],
} satisfies Config;
