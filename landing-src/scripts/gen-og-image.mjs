import sharp from "sharp";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dir = dirname(fileURLToPath(import.meta.url));

const W = 1200;
const H = 630;

const svg = `
<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">
  <rect width="${W}" height="${H}" fill="#0F172A"/>
  <rect width="6" height="${H}" fill="#34D399"/>

  <g transform="translate(72,72) scale(1.75)" stroke="#34D399" stroke-width="2" fill="#0F2A22" stroke-linecap="round" stroke-linejoin="round">
    <path d="M16 2L4 8v8c0 7.73 5.12 14.95 12 16 6.88-1.05 12-8.27 12-16V8L16 2z"/>
    <path d="M12 16l3 3 5-6" fill="none"/>
  </g>
  <text x="144" y="113" font-family="'Arial Black', Arial, sans-serif" font-size="40" font-weight="900" fill="#F8FAFC">ShieldBot</text>

  <text x="72" y="290" font-family="'Arial Black', Arial, sans-serif" font-size="64" font-weight="900" fill="#F8FAFC">Know before you sign.</text>
  <text x="72" y="370" font-family="'Arial Black', Arial, sans-serif" font-size="64" font-weight="900" fill="#34D399">And know when we don't.</text>
  <text x="72" y="428" font-family="Arial, sans-serif" font-size="26" fill="#CBD5E1">Checks a transaction before you sign, and says Unknown when it cannot.</text>

  <rect x="72" y="470" width="96" height="40" rx="20" fill="#0F2E1D"/>
  <text x="120" y="496" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#4ADE80" text-anchor="middle">SAFE</text>
  <rect x="180" y="470" width="136" height="40" rx="20" fill="#1E293B" stroke="#94A3B8" stroke-dasharray="4 3"/>
  <text x="248" y="496" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#E2E8F0" text-anchor="middle">UNKNOWN</text>
  <rect x="328" y="470" width="252" height="40" rx="20" fill="#3A1418"/>
  <text x="454" y="496" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#F87171" text-anchor="middle">BLOCK RECOMMENDED</text>

  <text x="72" y="578" font-family="Arial, sans-serif" font-size="20" fill="#94A3B8">shieldbotsecurity.online</text>
  <text x="1128" y="578" font-family="Arial, sans-serif" font-size="20" fill="#94A3B8" text-anchor="end">8 chains incl. Robinhood Chain</text>
</svg>
`;

const outPath = join(__dir, "../public/og-image.png");

await sharp(Buffer.from(svg))
  .resize(W, H)
  .png({ quality: 95 })
  .toFile(outPath);

console.log(`OG image written to ${outPath}`);
