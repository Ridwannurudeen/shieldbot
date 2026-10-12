// Copies the font files the site serves from the pinned @fontsource packages into public/fonts,
// so the build ships self-hosted fonts with stable names that index.html can preload.
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const files = [
  ["@fontsource/geist/files/geist-latin-400-normal.woff2", "geist-latin-400-normal.woff2"],
  ["@fontsource/geist/files/geist-latin-500-normal.woff2", "geist-latin-500-normal.woff2"],
  ["@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2", "ibm-plex-mono-latin-400-normal.woff2"],
];
const out = join(here, "..", "public", "fonts");
mkdirSync(out, { recursive: true });
for (const [from, to] of files) {
  copyFileSync(join(here, "..", "node_modules", from), join(out, to));
}
