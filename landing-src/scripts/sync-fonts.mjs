// Copies the font files the site serves from the pinned @fontsource packages into public/fonts,
// so the build ships self-hosted fonts with stable names that index.html can preload.
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const files = [
  ["@fontsource-variable/manrope/files/manrope-latin-wght-normal.woff2", "manrope-latin-wght-normal.woff2"],
  ["@fontsource/jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff2", "jetbrains-mono-latin-400-normal.woff2"],
  ["@fontsource/jetbrains-mono/files/jetbrains-mono-latin-700-normal.woff2", "jetbrains-mono-latin-700-normal.woff2"],
];
const out = join(here, "..", "public", "fonts");
mkdirSync(out, { recursive: true });
for (const [from, to] of files) {
  copyFileSync(join(here, "..", "node_modules", from), join(out, to));
}
