/** Scans the authored source for utility classes used in the dashboard JSX. */
const token = (name) => `rgb(from var(--${name}) r g b / <alpha-value>)`;
const colors = [
  'ground', 'ground-alt', 'panel', 'ink', 'on-ink', 'secondary', 'hairline',
  'hairline-strong', 'edge', 'accent', 'accent-fill', 'accent-fill-hover',
  'on-accent', 'accent-tint', 'on-panel', 'on-panel-2', 'accent-on-panel',
  'block-on-panel', 'paper', 'on-paper', 'on-paper-2', 'focus', 'shadow', 'block',
  'block-edge', 'block-text', 'safe', 'safe-text', 'unknown', 'on-unknown',
  'block-on-paper',
].reduce((theme, name) => ({ ...theme, [name]: token(name) }), {});

module.exports = {
  content: ["../index.src.html"],
  theme: {
    extend: {
      colors,
      fontFamily: {
        sans: ["Geist", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "monospace"],
      },
    },
  },
};
