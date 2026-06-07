// Builds the self-contained dashboard/index.html from dashboard/index.src.html.
//
// Why: the authored source (index.src.html) loads React/ReactDOM/Recharts/Tailwind
// from public CDNs and transpiles JSX in-browser via @babel/standalone. That
// remote-script + client-side-eval pattern trips Google Safe Browsing's malware
// heuristics. This build self-hosts every library and pre-compiles the JSX so the
// shipped index.html has zero remote executable scripts and zero runtime eval.
//
// Run: npm install && npm run build   (from this directory)

const fs = require("fs");
const path = require("path");
const babel = require("@babel/core");

const here = __dirname;
const SRC = path.join(here, "..", "index.src.html");
const OUT = path.join(here, "..", "index.html");
const vendor = (p) => path.join(here, "node_modules", p);

let html = fs.readFileSync(SRC, "utf8");

// 1. Extract the inline JSX body and transpile (preset-react only — matches text/babel).
const babelMatch = html.match(
  /<script type="text\/babel">([\s\S]*?)<\/script>/,
);
if (!babelMatch)
  throw new Error("text/babel script not found in index.src.html");
const compiled = babel.transformSync(babelMatch[1], {
  presets: [["@babel/preset-react"]],
  compact: false,
}).code;

// 2. Read pinned vendor UMD bundles + the built Tailwind CSS.
const read = (p) => fs.readFileSync(p, "utf8");
const reactJs = read(vendor("react/umd/react.production.min.js"));
const reactDomJs = read(vendor("react-dom/umd/react-dom.production.min.js"));
const propTypesJs = read(vendor("prop-types/prop-types.min.js"));
const rechartsJs = read(vendor("recharts/umd/Recharts.js"));
const twCss = read(path.join(here, "tw.css"));

// 3. Strip all remote CDN script tags + the inline tailwind.config + now-dangling comments.
html = html.replace(/\s*<!-- Tailwind CDN -->/g, "");
html = html.replace(
  /\s*<script src="https?:\/\/(?:cdn\.tailwindcss\.com|unpkg\.com)[^"]*"[^>]*><\/script>/g,
  "",
);
html = html.replace(/\s*<script>\s*tailwind\.config[\s\S]*?<\/script>/g, "");
html = html.replace(/\s*<!-- React \+ ReactDOM -->/g, "");
html = html.replace(/\s*<!-- prop-types \(required by Recharts UMD\) -->/g, "");
html = html.replace(/\s*<!-- Recharts -->/g, "");
html = html.replace(/\s*<!-- Babel \(JSX in browser\) -->/g, "");

// 4. Inject built Tailwind CSS immediately BEFORE the custom <style> (so custom rules win).
//    Function replacers are required: the inlined content contains $-sequences that
//    String.replace would otherwise interpret as special replacement patterns.
html = html.replace(
  /<style>/,
  () => `<style>\n${twCss}\n  </style>\n\n  <style>`,
);

// 5. Replace the text/babel script with inlined vendor bundles + the compiled app.
const inlined =
  `<script>${reactJs}</script>\n` +
  `  <script>${reactDomJs}</script>\n` +
  `  <script>${propTypesJs}</script>\n` +
  `  <script>${rechartsJs}</script>\n` +
  `  <script>\n${compiled}\n  </script>`;
html = html.replace(
  /<script type="text\/babel">[\s\S]*?<\/script>/,
  () => inlined,
);

fs.writeFileSync(OUT, html);

// Guardrails: the shipped file must have no remote executable scripts and no eval.
const remoteLeft =
  html.match(/https?:\/\/(?:unpkg\.com|cdn\.tailwindcss\.com)[^"' )]*/g) || [];
if (remoteLeft.length)
  throw new Error("remote CDN refs survived: " + remoteLeft.slice(0, 3));
if (html.includes('type="text/babel"'))
  throw new Error("text/babel script survived");
console.log(
  "built",
  path.relative(process.cwd(), OUT),
  Buffer.byteLength(html),
  "bytes — no remote scripts, no eval",
);
