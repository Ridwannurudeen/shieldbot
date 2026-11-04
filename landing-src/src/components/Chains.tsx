import { useStats, type Stats } from "../liveStats";
import Section from "./Section";

interface Chain {
  chainId: number;
  name: string;
  simulation: "honeypot.is" | "ShieldBot" | null;
  mempool: boolean;
  launches: boolean;
  simulationScope?: string;
}

const chains: Chain[] = [
  { chainId: 1, name: "Ethereum", simulation: "honeypot.is", mempool: true, launches: false },
  { chainId: 56, name: "BNB Chain", simulation: "honeypot.is", mempool: true, launches: false },
  { chainId: 8453, name: "Base", simulation: "honeypot.is", mempool: false, launches: false },
  {
    chainId: 42161,
    name: "Arbitrum",
    simulation: "ShieldBot",
    mempool: false,
    launches: false,
    simulationScope:
      "pools pairing the token with WETH on Uniswap V3, Uniswap V2 or SushiSwap",
  },
  { chainId: 137, name: "Polygon", simulation: null, mempool: true, launches: false },
  { chainId: 10, name: "Optimism", simulation: null, mempool: false, launches: false },
  { chainId: 204, name: "opBNB", simulation: null, mempool: true, launches: false },
  {
    chainId: 4663,
    name: "Robinhood Chain",
    simulation: "ShieldBot",
    mempool: false,
    launches: true,
    simulationScope: "Supported pool routes only",
  },
  {
    chainId: 677,
    name: "BOT Chain",
    simulation: "ShieldBot",
    mempool: false,
    launches: false,
    simulationScope: "BDEX V2 and V3 pools pairing the token with WBOT",
  },
];

function simulation(chain: Chain) {
  if (chain.simulation === null) return "GoPlus flags only";
  return chain.simulation === "ShieldBot"
    ? "ShieldBot simulator"
    : "honeypot.is";
}

function mempool(chain: Chain, stats: Stats | null | undefined) {
  if (!chain.mempool) return "No public mempool";
  if (stats === undefined) return "Loading";
  if (stats === null || !stats.mempool_chains_observable)
    return "Unavailable";
  return stats.mempool_chains_observable.includes(chain.chainId)
    ? "Observed on last poll"
    : "Not read on last poll";
}

function launchScans(chain: Chain) {
  return chain.launches ? "Yes, /launchalerts" : "No";
}

function MempoolCaption({
  stats,
  fetchedAt,
}: {
  stats: Stats | null | undefined;
  fetchedAt: Date | null;
}) {
  if (stats === undefined) return <>Mempool readings loading</>;
  if (stats === null) return <>Mempool readings unavailable</>;
  if (!stats.mempool_chains_observable) return <>Mempool readings unavailable</>;
  if (!fetchedAt) return <>Mempool readings updated</>;

  const time = fetchedAt.toISOString().slice(11, 16);
  return (
    <>
      Mempool readings at{" "}
      <a
        href="https://api.shieldbotsecurity.online/api/stats"
        target="_blank"
        rel="noopener noreferrer"
        className="text-ink underline decoration-hairline-strong underline-offset-4"
        aria-label={`GET /api/stats at ${time} UTC`}
      >
        {time} UTC
      </a>
    </>
  );
}

export default function Chains() {
  const { stats, fetchedAt } = useStats();

  return (
    <Section id="coverage" title="Coverage">
      <div className="overflow-x-auto">
        <table className="w-full table-fixed text-left text-xs sm:text-sm">
          <colgroup>
            <col className="w-[23%] sm:w-[22%]" />
            <col className="w-[27%] sm:w-[26%]" />
            <col className="w-[28%] sm:w-[28%]" />
            <col className="w-[22%] sm:w-[24%]" />
          </colgroup>
          <caption className="caption-bottom pt-4 text-left text-xs leading-5 text-secondary">
            <MempoolCaption stats={stats} fetchedAt={fetchedAt} />
          </caption>
          <thead>
            <tr className="border-y border-hairline text-[11px] uppercase tracking-wide text-secondary">
              <th scope="col" className="py-3 pr-2 font-medium">Chain</th>
              <th scope="col" className="px-1 py-3 font-medium sm:px-3">Sell simulation</th>
              <th scope="col" className="px-1 py-3 font-medium sm:px-3">Public mempool</th>
              <th scope="col" className="py-3 pl-1 font-medium sm:pl-3">Launch scans</th>
            </tr>
          </thead>
          <tbody>
            {chains.map((chain) => (
              <tr key={chain.chainId} className="border-b border-hairline align-top">
                <th scope="row" className="py-3 pr-2 text-left font-medium text-ink">
                  <span className="block">{chain.name}</span>
                  <span className="mt-1 block font-mono text-xs text-secondary">
                    {chain.chainId}
                  </span>
                </th>
                <td className="break-words px-1 py-3 leading-5 text-ink sm:px-3">
                  {simulation(chain)}
                  {chain.simulationScope && (
                    <span className="mt-1 block text-secondary">
                      {chain.simulationScope}
                    </span>
                  )}
                </td>
                <td className="break-words px-1 py-3 leading-5 text-ink sm:px-3">
                  {mempool(chain, stats)}
                </td>
                <td className="break-words py-3 pl-1 leading-5 text-ink sm:pl-3">
                  {launchScans(chain)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}
