import { useLayoutEffect, useState, type CSSProperties, type ReactNode } from "react";
import { useStats, type Stats } from "../liveStats";
import { useAlive, useReading } from "../reading";
import { PauseButton } from "./Button";

// Per-chain coverage. tests/test_website_claims.py checks each row against the chain adapters
// (sell simulation), services/mempool_service.py (mempool) and services/launch_discovery.py.
// The sell simulation and launch scan columns are drawn from these rows. GET /api/coverage/{chain_id} serves the same
// adapter configuration for sell simulation, so asking it for each chain would add eight requests and no information;
// it has no launch scan field, so that column is from services/launch_discovery.py alone. Whether a
// public mempool was read is live: GET /api/stats (src/liveStats.ts, the request Mechanism already makes) lists
// the chains the monitor read on its last poll.
interface Chain {
  chainId: number;
  name: string;
  // Who simulates a buy and a sell: honeypot.is, ShieldBot's own simulator, or nobody.
  simulation: "honeypot.is" | "ShieldBot" | null;
  mempool: boolean;
  launches: boolean;
  // Shown under the simulator when it covers only some of the chain's pools.
  simulationScope?: string;
  // The sell simulation cell's label when nobody simulates; "GoPlus flags only" when unset.
  unavailableLabel?: string;
  logo: ReactNode;
}

// Chains the scanner accepts (utils/chain_info.py). tests/test_website_claims.py keeps this in sync.
const SUPPORTED_CHAINS = 9;

// Chains with a ShieldBot verdict registry (docs/DEPLOYMENTS.md): Robinhood Chain and BOT Chain.
const REGISTRY_CHAINS = [4663, 677];

const chains: Chain[] = [
  {
    chainId: 1,
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
    chainId: 56,
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
    chainId: 8453,
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
    chainId: 42161,
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
    chainId: 137,
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
    chainId: 10,
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
    chainId: 204,
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
    chainId: 4663,
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
  {
    // Official BOT Chain mark (scan.botchain.ai/static/address/bot-balance-icon.svg), scaled: identifies the chain, no endorsement implied.
    chainId: 677,
    name: "BOT Chain",
    simulation: "ShieldBot",
    mempool: false,
    launches: false,
    simulationScope: "BDEX V2 and V3 pools with WBOT",
    logo: (
      <svg viewBox="0 0 32 32" fill="none" className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" aria-hidden="true">
        <circle cx="16" cy="16" r="16" fill="#10A37F"/>
        <path transform="scale(2)" d="M6.5918 3.00057L11.2781 5.66503V7.61119C10.8127 7.82311 10.3657 8.08547 9.92456 8.34411C9.84403 8.39154 9.73943 8.33465 9.7741 8.49356L11.2733 9.30701L11.3407 11.1516L8.14405 13L5 11.2605V9.3659L9.69845 12.094V10.3129L6.59122 8.53182V6.63725L9.69845 8.3805V6.75131C9.69845 6.72924 9.80678 6.66562 9.70418 6.60157L6.59122 4.78108V3L6.5918 3.00057Z" fill="#fff"/>
      </svg>
    ),
  },
];


type CellState = "available" | "unavailable" | "unknown";

function CapabilityCell({
  state,
  label,
  note,
  late,
}: {
  state: CellState;
  label: string;
  note?: string;
  late?: boolean;
}) {
  const square =
    state === "available"
      ? "border-ink bg-ink"
      : state === "unavailable"
        ? "border-dashed border-ink"
        : "border-ink bg-ground";

  return (
    <span className="inline-flex min-w-0 max-w-full items-start gap-1 text-[11px] leading-4 text-ink sm:items-center sm:gap-2 sm:text-[13px] sm:leading-5">
      <span
        aria-hidden="true"
        className={`rd-cell rd-${state}${late ? " rd-late" : ""} h-3 w-3 sm:h-3.5 sm:w-3.5 flex-none rounded-[2px] border ${square}`}
      />
      <span className="min-w-0 whitespace-normal">
        {label}
        {note && <span className="block text-secondary">{note}</span>}
      </span>
    </span>
  );
}

function simulationCell(chain: Chain): { state: CellState; label: string; note?: string } {
  if (chain.simulation === null) {
    return { state: "unavailable", label: chain.unavailableLabel ?? "GoPlus flags only" };
  }
  return {
    state: "available",
    label: chain.simulation === "ShieldBot" ? "ShieldBot simulator" : chain.simulation,
    note: chain.simulationScope,
  };
}

function mempoolCell(
  chain: Chain,
  stats: Stats | null | undefined,
): { state: CellState; label: string } {
  if (!chain.mempool) return { state: "unavailable", label: "No public mempool" };
  if (stats === undefined) return { state: "unknown", label: "Loading" };
  const observable = stats?.mempool_chains_observable;
  if (!observable) return { state: "unknown", label: "Unavailable" };
  // A public mempool the monitor did not read on its last poll is a reading not taken, not a check that does not
  // run here: the legend's outline, never the dashed cell.
  return observable.includes(chain.chainId)
    ? { state: "available", label: "Observed on last poll" }
    : { state: "unknown", label: "Not read on last poll" };
}

function launchCell(chain: Chain): { state: CellState; label: string } {
  return chain.launches
    ? { state: "available", label: "/launchalerts" }
    : { state: "unavailable", label: "No" };
}

// The chains in orbit (index.css, "Orbits"): each chain on its own ellipse, inner ones faster, logos upright; the
// magenta ellipses are Robinhood Chain's and BOT Chain's, the chains with a verdict registry. A picture of the table below, which carries the facts,
// so it is hidden from assistive technology. It moves only while on screen (useAlive). Below 1024 px the planets
// carry no names (the table does): nine labels do not fit those rings without clipping or overlapping.
function Orbits() {
  const { ref, on, paused, setPaused } = useAlive<HTMLDivElement>();
  return (
    <div ref={ref} data-paused={on ? undefined : ""} className="mt-10">
      <div aria-hidden="true" className="orbits relative mx-auto max-w-[920px]">
        {chains.map((chain, i) => (
          <div
            key={chain.chainId}
            className={REGISTRY_CHAINS.includes(chain.chainId) ? "orbit orbit-mark" : "orbit"}
            style={{ "--o": i } as CSSProperties}
          >
            <div className="orbit-arm">
              <div className="orbit-up flex flex-col items-center gap-1 whitespace-nowrap font-mono text-[11px] text-secondary">
                {chain.logo}
                <span className="max-lg:hidden">{chain.name}</span>
              </div>
            </div>
          </div>
        ))}
        <p className="absolute inset-0 grid place-content-center text-center font-mono text-[11px] uppercase tracking-[0.08em] text-secondary">
          <span className="font-sans text-[44px] font-medium normal-case leading-none tracking-[-0.03em] text-ink">9</span>
          chains
        </p>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-x-4">
        <p className="font-mono text-[11px] text-secondary">Accent ring: a chain with a ShieldBot verdict registry.</p>
        <PauseButton paused={paused} setPaused={setPaused} />
      </div>
    </div>
  );
}

export default function Chains() {
  const { stats, fetchedAt } = useStats();
  // The matrix takes its reading on view: a magenta needle sweeps across each row and the row's cells resolve
  // behind it, left to right (index.css).
  const matrix = useReading<HTMLDivElement>();
  // A /api/stats reply that lands after the matrix has started its reading switches the mempool squares in place:
  // no replay, so a square never vanishes for its row's delay (rd-late, index.css).
  const [late, setLate] = useState(false);
  useLayoutEffect(() => {
    if (stats !== undefined && matrix.current!.dataset.read === "go") setLate(true);
  }, [stats, matrix]);
  return (
    <section id="chains" aria-labelledby="chains-title" className="bg-ground-alt py-14 md:py-[72px] lg:py-24">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="mx-auto max-w-3xl text-center">
          <p className="text-sm font-medium text-accent">Coverage</p>
          <h2 id="chains-title" className="mt-3 text-h2-sm md:text-h2 text-ink">9 chains</h2>
          <p className="mt-4 text-[17px] md:text-lg leading-relaxed text-secondary">
            Contract scans run on all 9 chains. The other checks depend on the chain, and a check that cannot run is reported as Unknown, never as Safe.
          </p>
        </div>

        <Orbits />

        <div className="mt-10">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <h3 className="font-mono text-[11px] uppercase leading-4 tracking-[0.08em] text-secondary">
              Chain capabilities
            </h3>
            <div
              role="group"
              aria-label="Capability cell legend"
              className="flex flex-wrap gap-x-5 gap-y-2 text-xs text-secondary"
            >
              <span className="inline-flex items-center gap-2">
                <span aria-hidden="true" className="h-3 w-3 rounded-[2px] border border-ink bg-ink" />
                Filled: runs
              </span>
              <span className="inline-flex items-center gap-2">
                <span aria-hidden="true" className="h-3 w-3 rounded-[2px] border border-dashed border-ink" />
                Dashed: does not run on this chain
              </span>
              <span className="inline-flex items-center gap-2">
                <span aria-hidden="true" className="h-3 w-3 rounded-[2px] border border-ink bg-ground" />
                Outline: Unavailable
              </span>
            </div>
          </div>

          <div
            ref={matrix}
            data-read="wait"
            role="region"
            className="mt-4 overflow-x-auto rounded-lg border border-hairline bg-ground"
            tabIndex={0}
            aria-label="Capability matrix by chain"
          >
            <table className="w-full table-fixed text-xs sm:text-sm">
              <colgroup>
                <col style={{ width: "30%" }} />
                <col style={{ width: "23.3333%" }} />
                <col style={{ width: "23.3333%" }} />
                <col style={{ width: "23.3333%" }} />
              </colgroup>
              <caption className="sr-only">
                Sell simulation and launch scans by supported chain, from the code; public mempool
                from the monitor's last poll, live from GET /api/stats.
              </caption>
              <thead>
                <tr className="text-left text-[11px] uppercase text-secondary sm:text-xs">
                  <th scope="col" className="py-3 pl-2 pr-1 text-left font-medium sm:pl-4 sm:pr-3">Chain</th>
                  <th scope="col" className="px-1.5 py-3 text-left font-medium sm:px-3">Sell simulation</th>
                  <th scope="col" className="px-1.5 py-3 text-left font-medium sm:px-3">Public mempool</th>
                  <th scope="col" className="py-3 pl-1.5 pr-2 text-left font-medium sm:pl-3 sm:pr-4">Launch scans</th>
                </tr>
              </thead>
              <tbody>
                {chains.map((chain, i) => {
                  const simulation = simulationCell(chain);
                  const mempool = mempoolCell(chain, stats);

                  return (
                    <tr
                      key={chain.chainId}
                      className="border-t border-hairline"
                      style={{ "--r": i } as CSSProperties}
                    >
                      <th
                        scope="row"
                        className="rd-row py-3 pl-2 pr-1 text-left font-medium text-ink sm:pl-4 sm:pr-3"
                      >
                        <span className="flex min-w-0 items-center gap-1.5 sm:gap-3">
                          {chain.logo}
                          <span className="min-w-0">{chain.name}</span>
                        </span>
                      </th>
                      <td className="px-0.5 py-3 sm:px-3">
                        <CapabilityCell {...simulation} />
                      </td>
                      <td className="px-0.5 py-3 sm:px-3">
                        <CapabilityCell {...mempool} late={late} />
                      </td>
                      <td className="py-3 pl-0.5 pr-1 sm:pl-3 sm:pr-4">
                        <CapabilityCell {...launchCell(chain)} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <p className="mt-4 text-xs leading-[18px] text-secondary">
            Sell simulation: from the code, the chain adapters, the configuration GET /api/coverage/{"{chain_id}"} serves.
            Launch scans: from the code, services/launch_discovery.py, Robinhood Chain only.{" "}
            {stats === null
              ? "Public mempool: Unavailable. GET /api/stats did not answer, so no chain is shown as observed."
              : stats === undefined
                ? "Public mempool: loading GET /api/stats."
                : !stats.mempool_chains_observable
                  ? "Public mempool: Unavailable. GET /api/stats did not report which mempools the monitor read."
                  : `Public mempool: live from GET /api/stats, the monitor's last poll${fetchedAt ? `, fetched ${fetchedAt.toISOString().slice(11, 16)} UTC` : ""}.`}
          </p>
        </div>

        <ul className="mt-6 max-w-3xl space-y-2 text-sm leading-relaxed text-secondary">
          <li>
            <span className="text-ink">Sell simulation:</span> honeypot.is
            simulates a buy and a sell on Ethereum, BNB Chain and Base, and
            ShieldBot runs its own on supported Arbitrum, Robinhood Chain and BOT
            Chain pool routes. On Arbitrum those are pools pairing the token with
            WETH on Uniswap V3, Uniswap V2 or SushiSwap. On BOT Chain they are
            BDEX V2 and V3 pools pairing the token with WBOT. Elsewhere honeypot and tax flags
            come from GoPlus alone and read Unknown when GoPlus has no answer.
            <details className="disclose">
              <summary>Why ShieldBot simulates on Arbitrum itself</summary>
              <p>
                ARBROKER (<span className="font-mono text-[13px] break-all">0x8328ffdecbd36294b4fcc50c1c25cde18f4a8b2b</span>):
                GoPlus reported it as not a honeypot on 29 September 2026;
                ShieldBot's own simulation found that its sell reverts.
              </p>
            </details>
          </li>
          <li>
            The Chrome Web Store serves extension 3.1.0, which sends Robinhood Chain requests to the API for analysis. BOT Chain support is in extension 3.4.0 in the repository and is not yet on the Store. It has been tested with Rabby; MetaMask testing is still outstanding.
          </li>
        </ul>
      </div>
    </section>
  );
}
