/** Scans the authored source for utility classes used in the dashboard JSX. */
module.exports = {
  content: ["../index.src.html"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
    },
  },
};
