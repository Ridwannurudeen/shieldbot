import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    // No default palette: every colour on the site is a named token (src/index.css mirrors them).
    colors: {
      transparent: "transparent",
      current: "currentColor",
      white: "#FFFFFF",
      ink: "#0B1220",
      body: "#334155",
      muted: "#475569",
      faint: "#64748B",
      surface: { DEFAULT: "#FFFFFF", 2: "#F6F8FA", 3: "#EEF2F6" },
      line: { DEFAULT: "#E3E8EF", strong: "#CBD5E1" },
      emerald: {
        DEFAULT: "#047857",
        deep: "#065F46",
        bright: "#10B981",
        tint: "#ECFDF5",
        line: "#A7F3D0",
        onink: "#34D399",
      },
      onink: { DEFAULT: "#CBD5E1", muted: "#94A3B8" },
      safe: { fg: "#166534", tint: "#DCFCE7", line: "#86EFAC" },
      caution: { fg: "#854D0E", tint: "#FEF9C3", line: "#FDE047" },
      high: { fg: "#9A3412", tint: "#FFEDD5", line: "#FDBA74" },
      block: { fg: "#B91C1C", tint: "#FEE2E2", line: "#FCA5A5" },
      unknown: { fg: "#475569", tint: "#F1F5F9", stripe: "#E2E8F0", line: "#94A3B8", deep: "#3F4B5E" },
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
        sm: "0 1px 2px rgba(11,18,32,0.06)",
        md: "0 4px 12px rgba(11,18,32,0.08)",
        lg: "0 24px 48px -12px rgba(11,18,32,0.18)",
      },
      backgroundImage: {
        "unknown-hatch": "repeating-linear-gradient(135deg, #F1F5F9 0 6px, #E2E8F0 6px 12px)",
        "unknown-hatch-solid": "repeating-linear-gradient(135deg, #475569 0 6px, #3F4B5E 6px 12px)",
      },
      transitionTimingFunction: { out: "cubic-bezier(0.2, 0, 0, 1)" },
    },
  },
  plugins: [],
} satisfies Config;
