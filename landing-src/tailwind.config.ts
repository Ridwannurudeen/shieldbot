import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: {
          DEFAULT: "#0A0F1C",
          light: "#111827",
        },
        neon: "#00FF88",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      boxShadow: {
        neon: "0 0 20px rgba(0,255,136,0.3)",
        "neon-lg": "0 0 40px rgba(0,255,136,0.4)",
      },
    },
  },
  plugins: [],
} satisfies Config;
