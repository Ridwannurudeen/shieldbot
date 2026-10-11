import { useEffect, useState } from "react";
import VerdictRecord from "./VerdictRecord";
import { registryChip } from "../registryVerdict";
import { REGISTRY_CHAIN } from "../registryFeed";

// Two records from the API, fetched when the page loads: the newest blocked Robinhood Chain launch as the
// registry holds it (GET /api/verdict/4663/{subject}), drawn as a verdict record whose check-row is the coverage
// in its published evidence, and that chain's coverage (GET /api/coverage/4663) as a row of cells. A route that
// does not answer leaves each of its fields reading Unavailable; nothing is filled in.
const API = "https://api.shieldbotsecurity.online";
const SUBJECT = "0x34357625e8b7414b47c0410327c29361a70c26dd";

interface RegistryReply {
  verdict: string | null;
  verdict_code: number | null;
  evidence_hash: string | null;
  observed_block: number | null;
  published_at: number | null;
  onchain_status: string | null;
  tx_hash: string | null;
  evidence: {
    coverage?: Record<string, number | boolean>;
    coverage_reasons?: Record<string, string | null>;
  } | null;
}

interface Coverage {
  capabilities: {
    sell_simulation: string | null;
    router_allowlist: { present: boolean; routers: number } | null;
    public_mempool: string | null;
  } | null;
}

const reasons = [
  "The data provider did not answer, so the overlay says Unknown and why.",
  "The chain has no sell simulation route, so the overlay says Unknown and why.",
  "The contract's age is not available, so the overlay says Unknown and why.",
  "The typed data could not be read, so the overlay says Unknown and why.",
];

function short(hex: string) {
  return `${hex.slice(0, 6)}…${hex.slice(-4)}`;
}

function useRecord<T>(url: string) {
  // undefined while loading, null when the route did not answer.
  const [data, setData] = useState<T | null | undefined>(undefined);
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    const timeout = setTimeout(() => controller.abort(), 10_000);

    fetch(url, { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: T) => {
        if (active) setData(d);
      })
      .catch(() => {
        if (active) setData(null);
      })
      .finally(() => clearTimeout(timeout));
    return () => {
      active = false;
      clearTimeout(timeout);
      controller.abort();
    };
  }, [url]);
  return data;
}

function Source({ path, failed }: { path: string; failed: boolean }) {
  return (
    <p className="text-xs leading-[18px] text-secondary">
      {failed && <span className="font-medium text-ink">Unavailable. </span>}
      {failed ? `GET ${path} did not answer.` : `Live from GET ${path}.`}
    </p>
  );
}

// One coverage capability as a check cell: filled when the chain has it, dashed when the API says it has not,
// an empty hairline cell while loading or when the route did not answer.
function Capability({
  label,
  value,
  has,
  loading,
}: {
  label: string;
  value: string | null | undefined;
  has: boolean;
  loading: boolean;
}) {
  return (
    <li className="grid grid-cols-[12px_minmax(0,1fr)_auto] items-center gap-3 py-2.5">
      <span
        aria-hidden="true"
        className={`h-3 w-3 rounded-[2px] border ${value == null ? "border-hairline-strong" : has ? "border-ink bg-ink" : "border-dashed border-ink"}`}
      />
      <span className="text-secondary">{label}</span>
      <span className="min-w-0 text-right text-ink [overflow-wrap:anywhere]">
        {value ?? (loading ? "…" : "Unavailable")}
      </span>
    </li>
  );
}

export default function WhyUnknown() {
  const record = useRecord<RegistryReply>(`${API}/api/verdict/4663/${SUBJECT}`);
  const coverage = useRecord<Coverage>(`${API}/api/coverage/4663`);

  const caps = coverage?.capabilities;
  const routers = caps?.router_allowlist?.routers;
  const mempool = caps?.public_mempool;
  const recordPath = `/api/verdict/4663/${short(SUBJECT)}`;

  return (
    <section
      id="why-unknown"
      aria-labelledby="why-unknown-title"
      className="border-b border-hairline py-16 md:py-24"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6 grid grid-cols-1 items-start gap-12 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:gap-16">
        <div className="min-w-0">
          <p className="font-mono text-xs uppercase tracking-[0.08em] text-secondary">
            Why Unknown exists
          </p>
          <h2
            id="why-unknown-title"
            className="mt-3 text-h2-sm md:text-h2 text-ink"
          >
            A check that did not run is not a pass.
          </h2>
          <p className="mt-4 max-w-[30em] text-[17px] md:text-lg leading-relaxed text-secondary">
            A verdict is only as good as the checks behind it. When one of them
            cannot run, ShieldBot does not fill the gap with a guess.
          </p>
          <ul className="mt-7 grid gap-3.5">
            {reasons.map((reason) => (
              <li
                key={reason}
                className="grid grid-cols-[12px_1fr] gap-3 text-base leading-6 text-ink"
              >
                <span
                  aria-hidden="true"
                  className="mt-1.5 h-3 w-3 rounded-[2px] border border-dashed border-ink"
                />
                {reason}
              </li>
            ))}
          </ul>
        </div>

        <div className="grid min-w-0 gap-8">
          <figure className="grid min-w-0 gap-3">
            <figcaption className="font-mono text-xs leading-4 text-secondary">
              Registry record, Robinhood Chain · token {short(SUBJECT)}
            </figcaption>
            {record ? (
              <VerdictRecord
                chip={registryChip(record.verdict, record.verdict_code)}
                coverage={record.evidence?.coverage}
                reasons={record.evidence?.coverage_reasons}
                chain={REGISTRY_CHAIN}
                block={record.observed_block}
                publishedAt={record.published_at}
                evidenceHash={record.evidence_hash}
              />
            ) : (
              <div className="grid min-h-[120px] place-items-center rounded-lg border border-dashed border-hairline-strong px-5 font-mono text-[13px] text-secondary">
                {record === undefined ? `GET ${recordPath} …` : "Unavailable"}
              </div>
            )}
            <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
              <Source path={recordPath} failed={record === null} />
              {record && (
                <p className="font-mono text-xs leading-[18px] text-secondary">
                  Registry status {record.onchain_status ?? "Unavailable"}
                  {record.tx_hash && (
                    <>
                      {" · tx "}
                      <a
                        href={`https://robin.etherscan.io/tx/${record.tx_hash}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-accent underline underline-offset-2 transition-colors duration-150 hover:text-accent-hover"
                      >
                        {short(record.tx_hash)}
                      </a>
                    </>
                  )}
                </p>
              )}
            </div>
          </figure>

          <figure className="grid min-w-0 gap-3">
            <figcaption className="font-mono text-xs leading-4 text-secondary">
              Coverage, Robinhood Chain
            </figcaption>
            <ul className="divide-y divide-hairline rounded-lg border border-hairline bg-ground px-5 font-mono text-[13px] leading-5">
              <Capability
                label="Sell simulation"
                value={caps?.sell_simulation}
                has={!!caps?.sell_simulation && caps.sell_simulation !== "no"}
                loading={coverage === undefined}
              />
              <Capability
                label="Pool routers"
                value={
                  typeof routers === "number" ? `${routers} allowlisted` : null
                }
                has={caps?.router_allowlist?.present === true}
                loading={coverage === undefined}
              />
              <Capability
                label="Public mempool"
                value={mempool === "no" ? "No public mempool" : mempool}
                has={!!mempool && mempool !== "no"}
                loading={coverage === undefined}
              />
            </ul>
            <Source path="/api/coverage/4663" failed={coverage === null} />
          </figure>
        </div>
      </div>
    </section>
  );
}
