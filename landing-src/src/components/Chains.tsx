import type { CSSProperties, ReactNode } from "react";

// Per-chain coverage. tests/test_website_claims.py checks each row against the chain adapters
// (sell simulation), services/mempool_service.py (mempool) and services/launch_discovery.py.
interface Chain {
  name: string;
  // Who simulates a buy and a sell: honeypot.is, ShieldBot's own simulator, or nobody.
  simulation: "honeypot.is" | "ShieldBot" | null;
  mempool: boolean;
  launches: boolean;
  // Shown under the simulator when it covers only some of the chain's pools.
  simulationScope?: string;
  logo: ReactNode;
}

// Chains the scanner accepts (utils/chain_info.py). tests/test_website_claims.py keeps this in sync.
const SUPPORTED_CHAINS = 8;

const chains: Chain[] = [
  {
    name: "Ethereum",
    simulation: "honeypot.is",
    mempool: true,
    launches: false,
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" aria-hidden="true">
        <circle cx="16" cy="16" r="16" fill="#627EEA"/>
        <path d="M16.498 4v8.87l7.497 3.35L16.498 4z" fill="#fff" fillOpacity=".6"/>
        <path d="M16.498 4 9 16.22l7.498-3.35V4z" fill="#fff"/>
        <path d="M16.498 21.968v6.027L24 17.616l-7.502 4.352z" fill="#fff" fillOpacity=".6"/>
        <path d="M16.498 27.995v-6.028L9 17.616l7.498 10.379z" fill="#fff"/>
        <path d="m16.498 20.573 7.497-4.353-7.497-3.348v7.701z" fill="#fff" fillOpacity=".2"/>
        <path d="m9 16.22 7.498 4.353v-7.701L9 16.22z" fill="#fff" fillOpacity=".6"/>
      </svg>
    ),
  },
  {
    name: "BNB Chain",
    simulation: "honeypot.is",
    mempool: true,
    launches: false,
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" aria-hidden="true">
        <circle cx="16" cy="16" r="16" fill="#F3BA2F"/>
        <path d="M12.116 14.404 16 10.52l3.886 3.886 2.26-2.26L16 6l-6.144 6.144 2.26 2.26zM6 16l2.26-2.26L10.52 16l-2.26 2.26L6 16zm6.116 1.596L16 21.48l3.886-3.886 2.26 2.259L16 26l-6.144-6.144-.002-.003 2.262-2.257zM21.48 16l2.26-2.26L26 16l-2.26 2.26L21.48 16zm-3.188-.002h.002V16L16 18.292 13.708 16v-.004L16 13.708l2.292 2.29z" fill="#fff"/>
      </svg>
    ),
  },
  {
    name: "Base",
    simulation: "honeypot.is",
    mempool: false,
    launches: false,
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" aria-hidden="true">
        <circle cx="16" cy="16" r="16" fill="#0052FF"/>
        <path d="M16.004 26c5.52 0 9.996-4.477 9.996-10S21.524 6 16.004 6C10.756 6 6.44 10.02 6 15.155h13.243v1.69H6C6.44 21.98 10.756 26 16.004 26z" fill="#fff"/>
      </svg>
    ),
  },
  {
    name: "Arbitrum",
    simulation: "ShieldBot",
    mempool: false,
    launches: false,
    simulationScope: "Some WETH pools, see below",
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" aria-hidden="true">
        <circle cx="16" cy="16" r="16" fill="#213147"/>
        <path d="M16 6L7 11v10l9 5 9-5V11L16 6zm0 2.3 7 3.9v7.6l-7 3.9-7-3.9v-7.6l7-3.9z" fill="#12AAFF"/>
        <path d="m13.5 19.5-1.5-2.6 4-6.9h3l-5.5 9.5zm5 0-1.5-2.6 2-3.4 1.5 2.6-2 3.4z" fill="#fff"/>
      </svg>
    ),
  },
  {
    name: "Polygon",
    simulation: null,
    mempool: true,
    launches: false,
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" aria-hidden="true">
        <circle cx="16" cy="16" r="16" fill="#8247E5"/>
        <path d="M21.188 13.063a1.21 1.21 0 0 0-1.188 0l-2.729 1.604-1.854 1.042-2.729 1.604a1.21 1.21 0 0 1-1.188 0l-2.146-1.25a1.177 1.177 0 0 1-.594-1.02v-2.396c0-.417.22-.808.594-1.021l2.146-1.23a1.21 1.21 0 0 1 1.188 0l2.146 1.23c.374.213.594.604.594 1.021v1.604l1.854-1.083v-1.604a1.177 1.177 0 0 0-.594-1.021l-3.958-2.292a1.21 1.21 0 0 0-1.188 0L7.594 10.5A1.177 1.177 0 0 0 7 11.521v4.604c0 .417.22.808.594 1.021l4 2.312a1.21 1.21 0 0 0 1.188 0l2.729-1.583 1.854-1.063 2.729-1.583a1.21 1.21 0 0 1 1.188 0l2.146 1.23c.374.212.594.604.594 1.02v2.396c0 .417-.22.808-.594 1.021l-2.125 1.25a1.21 1.21 0 0 1-1.188 0l-2.146-1.25a1.177 1.177 0 0 1-.594-1.021v-1.583l-1.854 1.083v1.583c0 .417.22.808.594 1.021l4 2.313a1.21 1.21 0 0 0 1.188 0l4-2.313c.374-.213.594-.604.594-1.021v-4.625a1.177 1.177 0 0 0-.594-1.021l-4.062-2.354z" fill="#fff"/>
      </svg>
    ),
  },
  {
    name: "Optimism",
    simulation: null,
    mempool: false,
    launches: false,
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" aria-hidden="true">
        <circle cx="16" cy="16" r="16" fill="#FF0420"/>
        <path d="M11.36 20.12c-1.04 0-1.88-.27-2.52-.8-.64-.55-.96-1.3-.96-2.25 0-.19.02-.43.07-.71.13-.73.34-1.6.63-2.59.82-2.74 2.42-4.1 4.8-4.1.69 0 1.3.14 1.83.43.54.29.95.71 1.24 1.26.29.54.43 1.18.43 1.9 0 .18-.02.41-.06.7-.17.92-.38 1.79-.64 2.6-.41 1.32-1.02 2.31-1.83 2.97-.8.66-1.77.99-2.99.99zm.19-1.89c.49 0 .91-.16 1.27-.47.36-.32.65-.82.86-1.5.28-.9.49-1.74.62-2.52.04-.2.05-.38.05-.55 0-.93-.42-1.39-1.27-1.39-.5 0-.93.16-1.29.48-.36.31-.64.81-.86 1.5-.25.83-.46 1.67-.62 2.52-.03.19-.05.37-.05.54 0 .93.43 1.39 1.29 1.39zm7.83 1.77c-.1 0-.18-.03-.23-.1-.05-.07-.06-.16-.03-.26l2.15-8.36c.04-.13.1-.23.2-.3.1-.08.2-.12.33-.12h3.01c.89 0 1.6.2 2.12.61.53.4.79.97.79 1.7 0 .21-.03.43-.08.67-.25 1.12-.75 1.96-1.5 2.51-.74.55-1.74.82-2.99.82h-1.55l-.64 2.47c-.04.13-.11.23-.21.3-.1.08-.21.12-.34.12h-1.03zm4.08-4.97c.4 0 .74-.11 1.02-.32.28-.22.47-.54.57-.96.03-.14.05-.27.05-.39 0-.27-.07-.48-.22-.62-.15-.15-.39-.22-.72-.22h-1.44l-.55 2.51h1.29z" fill="#fff"/>
      </svg>
    ),
  },
  {
    name: "opBNB",
    simulation: null,
    mempool: true,
    launches: false,
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" aria-hidden="true">
        <circle cx="16" cy="16" r="16" fill="#1A1A2E"/>
        <path d="M12.116 14.404 16 10.52l3.886 3.886 2.26-2.26L16 6l-6.144 6.144 2.26 2.26zM6 16l2.26-2.26L10.52 16l-2.26 2.26L6 16zm6.116 1.596L16 21.48l3.886-3.886 2.26 2.259L16 26l-6.144-6.144-.002-.003 2.262-2.257zM21.48 16l2.26-2.26L26 16l-2.26 2.26L21.48 16zm-3.188-.002h.002V16L16 18.292 13.708 16v-.004L16 13.708l2.292 2.29z" fill="#F3BA2F"/>
      </svg>
    ),
  },
  {
    // Generic chain-link mark: no third-party logo.
    name: "Robinhood Chain",
    simulation: "ShieldBot",
    mempool: false,
    launches: true,
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" aria-hidden="true">
        <circle cx="16" cy="16" r="16" fill="#1A2E05"/>
        <path d="M13.5 18.5 18.5 13.5M11.2 16.2l-1.4 1.4a3.2 3.2 0 0 0 4.5 4.5l1.4-1.4M20.8 15.8l1.4-1.4a3.2 3.2 0 0 0-4.5-4.5l-1.4 1.4" stroke="#84CC16" strokeWidth="2" strokeLinecap="round"/>
      </svg>
    ),
  },
];


export default function Chains() {
  return (
    <section id="chains" aria-labelledby="chains-title" className="bg-surface-2 py-14 md:py-[72px] lg:py-24">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="mx-auto max-w-3xl text-center">
          <p className="text-sm font-medium text-accent">Coverage</p>
          <h2 id="chains-title" className="mt-3 text-h2-sm md:text-h2 text-ink">8 chains</h2>
          <p className="mt-4 text-[17px] md:text-lg leading-relaxed text-secondary">
            Contract scans run on all 8 chains. The other checks depend on the chain, and a check that cannot run is reported as Unknown, never as Safe.
          </p>
        </div>

        <div className="orbit relative mt-6 h-[300px] overflow-hidden md:h-[420px]" aria-hidden="true">
          <svg className="absolute inset-0 hidden h-full w-full md:block" viewBox="0 0 1104 420" preserveAspectRatio="none">
            <ellipse cx="552" cy="226" rx="360" ry="92" fill="none" stroke="rgb(var(--c-hairline-strong))" />
            <ellipse cx="552" cy="222" rx="250" ry="62" fill="none" stroke="rgb(var(--c-hairline-strong))" strokeDasharray="2 6" />
            <ellipse cx="552" cy="232" rx="470" ry="124" fill="none" stroke="rgb(var(--c-hairline-strong))" strokeDasharray="2 6" />
          </svg>
          <div className="absolute left-1/2 top-[38%] z-10 -translate-x-1/2 -translate-y-1/2 text-center md:top-1/2">
            <b className="block font-medium text-[64px] leading-none tracking-[-0.04em] text-ink md:text-[88px]">{SUPPORTED_CHAINS}</b>
            <span className="mt-1.5 block text-[15px] text-secondary">EVM chains</span>
          </div>
          <div className="orbit-tilt">
            <ul className="orbit-ring">
              {chains.map((c, i) => (
                <li key={c.name} className="orbit-item" style={{ "--a": `${i * 45}deg`, "--d": `${i * -1500}ms` } as CSSProperties}>
                  <div className="orbit-face">
                    <span className="orbit-pill inline-flex items-center gap-2.5 whitespace-nowrap rounded-full border border-hairline bg-ground p-1.5 text-[15px] font-medium text-ink shadow-md md:h-[52px] md:py-0 md:pl-2 md:pr-[18px]">
                      <span className="grid h-9 w-9 flex-none place-items-center rounded-full bg-ground-alt">{c.logo}</span>
                      <span className="hidden md:inline">{c.name}</span>
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="mt-10 max-w-4xl overflow-x-auto rounded-2xl border border-line bg-surface px-3 py-2 shadow-sm sm:px-6" tabIndex={0} aria-label="Coverage by chain">
          <table className="w-full text-[13px] sm:text-sm">
            <caption className="sr-only">
              Which checks run on each supported chain
            </caption>
            <thead>
              <tr className="text-left text-[11px] uppercase text-muted md:tracking-wider sm:text-xs">
                <th scope="col" className="py-3 pr-1.5 font-semibold sm:pr-2">Chain</th>
                <th scope="col" className="py-3 px-1.5 sm:px-2 font-semibold">Sell simulation</th>
                <th scope="col" className="py-3 px-1.5 sm:px-2 font-semibold">Mempool watch</th>
                <th scope="col" className="py-3 pl-1.5 sm:pl-2 font-semibold">Launch scans</th>
              </tr>
            </thead>
            <tbody>
              {chains.map((c) => (
                <tr key={c.name} className="border-t border-line">
                  <th scope="row" className="py-3 pr-1.5 text-left font-semibold text-ink sm:pr-2">
                    <span className="flex items-center gap-1.5 sm:gap-3">
                      {c.logo}
                      {c.name}
                    </span>
                  </th>
                  <td className={`py-3 px-1.5 sm:px-2 ${c.simulation ? "text-body" : "text-caution-fg"}`}>
                    {c.simulation ?? "None"}
                    {c.simulationScope && (
                      <span className="block text-xs text-muted">{c.simulationScope}</span>
                    )}
                  </td>
                  <td className="py-3 px-1.5 text-body sm:px-2">{c.mempool ? "Yes" : "No"}</td>
                  <td className="py-3 pl-1.5 text-body sm:pl-2">{c.launches ? "Yes" : "No"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <ul className="mt-6 max-w-3xl space-y-2 text-sm leading-relaxed text-muted">
          <li>
            <span className="text-ink">Sell simulation:</span> honeypot.is
            simulates a buy and a sell on Ethereum, BNB Chain and Base, and
            ShieldBot runs its own on supported Arbitrum and Robinhood Chain pool
            routes. On Arbitrum those are pools pairing the token with WETH on
            Uniswap V3, Uniswap V2 or SushiSwap.
            Where it says None, and for an Arbitrum token with no such pool (for
            example one traded only on Camelot, or only against stablecoins),
            honeypot and tax flags come from GoPlus alone, and they read Unknown
            when GoPlus has no answer. ARBROKER
            (<span className="font-mono text-[13px] break-all">0x8328ffdecbd36294b4fcc50c1c25cde18f4a8b2b</span>)
            is the case that shows why: GoPlus reported it as not a honeypot on 29 September 2026, and
            ShieldBot's own simulation found that its sell reverts.
          </li>
          <li>
            <span className="text-ink">Mempool watch:</span> pending
            transactions are watched on the 4 chains with a public mempool.
          </li>
          <li>
            <span className="text-ink">Launch scans:</span> new Robinhood
            Chain tokens are found as their pools open and reported with
            /launchalerts in Telegram.
          </li>
          <li>
            Version 3.1.0 of the browser extension, on the Chrome Web Store, asks the wallet which chain it is on and sends Robinhood Chain requests to the API for analysis. It has been tested with Rabby; MetaMask testing is still outstanding.
          </li>
        </ul>
      </div>
    </section>
  );
}
