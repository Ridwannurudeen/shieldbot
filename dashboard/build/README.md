# Dashboard build

`../index.html` is **generated** — do not hand-edit it. Edit `../index.src.html`
(the authored React source) and rebuild.

## Why this build exists

`index.src.html` loads React, ReactDOM, Recharts and Tailwind from public CDNs
(`unpkg.com`, `cdn.tailwindcss.com`) and transpiles its JSX in the browser with
`@babel/standalone`. That combination — remote executable scripts plus client-side
`eval` — trips Google Safe Browsing's malware heuristics and got the dashboard
flagged. This build self-hosts every library and pre-compiles the JSX, so the
shipped `index.html` has **no remote scripts and no runtime eval**. (Google Fonts
is the only external resource left, which is trusted and not a flag trigger.)

The backend serves `dashboard/index.html` directly via `FileResponse`
(`api.py` → `/dashboard`), so the built file must stay self-contained.

## Rebuild

```bash
cd dashboard/build
npm install
npm run build      # → writes ../index.html
```

`assemble.js` fails the build if any remote CDN reference or `text/babel` script
survives, so a broken build can't ship.
