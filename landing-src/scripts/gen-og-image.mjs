// Writes the interim wordmark-only link preview (public/og-image.png) and favicon (public/favicon.png and
// public/favicon.ico) until the brand mark is chosen. Text is set in Geist from the pinned @fontsource
// package (run `npm ci` first); the shapes are SVG.
import sharp from "sharp";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dir = dirname(fileURLToPath(import.meta.url));
const fontFiles = join(__dir, "../node_modules/@fontsource/geist/files");
// Pango font descriptions. The 400 file's family is "Geist" and the 500 file's is "Geist Medium"; a bare
// "Geist" description falls back to a system face, while "Geist Book" (family Geist, weight 380) resolves to
// the 400 file.
const FACES = {
  400: { family: "Geist Book", file: join(fontFiles, "geist-latin-400-normal.woff") },
  500: { family: "Geist Medium", file: join(fontFiles, "geist-latin-500-normal.woff") },
};

const INK = "#141414";
const SECONDARY = "#6B6B66";
const ACCENT = "#A3168F";
const SAFE = "#1D8A5A";
const SAFE_TEXT = "#176E48";
const BLOCK = "#C21F30";
const UNKNOWN = "#8B8B86";

async function text(content, weight, size, color) {
  const face = FACES[weight];
  const { data, info } = await sharp({
    text: { text: `<span foreground="${color}">${content}</span>`, font: `${face.family} ${size}`, fontfile: face.file, dpi: 72, rgba: true },
  }).png().toBuffer({ resolveWithObject: true });
  return { input: data, width: info.width, height: info.height };
}

async function render(width, height, shapes, layers, outPaths) {
  const svg = `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">${shapes}</svg>`;
  const png = await sharp(Buffer.from(svg)).composite(layers).png().toBuffer();
  for (const outPath of outPaths) {
    await sharp(png).toFile(outPath);
    console.log(`Written ${outPath}`);
  }
}

// Link preview, 1200 x 630: wordmark, headline, tagline, three verdict chips in the site's chip grammar.
const W = 1200;
const H = 630;
const chips = [
  { label: "SAFE", x: 72, width: 104, fill: "none", stroke: SAFE, dash: "", color: SAFE_TEXT },
  { label: "? UNKNOWN", x: 192, width: 168, fill: UNKNOWN, stroke: INK, dash: ' stroke-dasharray="5 4"', color: INK },
  { label: "BLOCK RECOMMENDED", x: 376, width: 268, fill: BLOCK, stroke: BLOCK, dash: "", color: "#FFFFFF" },
];
const chipY = 470;
const chipH = 44;
const ogShapes = [
  `<rect width="${W}" height="${H}" fill="#FFFFFF"/>`,
  `<rect width="8" height="${H}" fill="${ACCENT}"/>`,
  ...chips.map((chip) => `<rect x="${chip.x + 0.5}" y="${chipY + 0.5}" width="${chip.width - 1}" height="${chipH - 1}" rx="4" fill="${chip.fill}" stroke="${chip.stroke}"${chip.dash}/>`),
].join("");
const ogLayers = [
  { ...(await text("ShieldBot", 500, 40, INK)), left: 72, top: 64 },
  { ...(await text("Know before you sign.", 500, 68, INK)), left: 72, top: 214 },
  { ...(await text("And know when we don't.", 500, 68, ACCENT)), left: 72, top: 296 },
  { ...(await text("Checks a transaction before you sign, and says Unknown when it cannot.", 400, 26, SECONDARY)), left: 72, top: 396 },
  { ...(await text("shieldbotsecurity.online", 400, 22, SECONDARY)), left: 72, top: 560 },
];
const chainsLine = await text("9 chains incl. Robinhood Chain and BOT Chain", 400, 22, SECONDARY);
ogLayers.push({ ...chainsLine, left: W - 72 - chainsLine.width, top: 560 });
for (const chip of chips) {
  const label = await text(chip.label, 500, 18, chip.color);
  ogLayers.push({ ...label, left: Math.round(chip.x + (chip.width - label.width) / 2), top: Math.round(chipY + (chipH - label.height) / 2) });
}
await render(W, H, ogShapes, ogLayers, [join(__dir, "../public/og-image.png")]);

// Favicon, 128 x 128: the wordmark initial on the accent square.
const F = 128;
const initial = await text("S", 500, 92, "#FFFFFF");
await render(
  F,
  F,
  `<rect width="${F}" height="${F}" rx="20" fill="${ACCENT}"/>`,
  [{ ...initial, left: Math.round((F - initial.width) / 2), top: Math.round((F - initial.height) / 2) }],
  [join(__dir, "../public/favicon.png"), join(__dir, "../public/favicon.ico")],
);
