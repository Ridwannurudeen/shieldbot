import { useEffect, useState } from "react";
import Icon from "./Icon";

// Two records from the API, fetched when the page loads: the newest blocked Robinhood Chain launch as the
// registry holds it (GET /api/verdict/4663/{subject}), and that chain's coverage (GET /api/coverage/4663).
// A route that does not answer leaves each of its fields reading Unavailable; nothing is filled in.
const API = "https://api.shieldbotsecurity.online";
const SUBJECT = "0x34357625e8b7414b47c0410327c29361a70c26dd";

interface VerdictRecord {
  verdict: string | null;
  observed_block: number | null;
  published_at: number | null;
  onchain_status: string | null;
  tx_hash: string | null;
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
    fetch(url)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: T) => setData(d))
      .catch(() => setData(null));
  }, [url]);
  return data;
}

function Row({
  label,
  value,
  loading,
}: {
  label: string;
  value: string | null | undefined;
  loading: boolean;
}) {
  return (
    <>
      <dt className="text-secondary">{label}</dt>
      <dd className="min-w-0 font-medium text-ink [overflow-wrap:anywhere]">
        {value ?? (loading ? "…" : "—")}
      </dd>
    </>
  );
}

function Source({ path, failed }: { path: string; failed: boolean }) {
  return (
    <p className="mt-4 border-t border-hairline pt-3 text-xs leading-[18px] text-secondary">
      {failed && <span className="font-medium text-ink">Unavailable. </span>}
      {failed ? `GET ${path} did not answer.` : `Live from GET ${path}.`}
    </p>
  );
}

export default function WhyUnknown() {
  const record = useRecord<VerdictRecord>(`${API}/api/verdict/4663/${SUBJECT}`);
  const coverage = useRecord<Coverage>(`${API}/api/coverage/4663`);

  const published =
    typeof record?.published_at === "number"
      ? new Date(record.published_at * 1000).toLocaleDateString("en-GB", {
          day: "numeric",
          month: "long",
          year: "numeric",
        })
      : null;
  const caps = coverage?.capabilities;
  const routers = caps?.router_allowlist?.routers;
  const mempool = caps?.public_mempool;

  return (
    <section
      id="why-unknown"
      aria-labelledby="why-unknown-title"
      className="border-b border-hairline py-16 md:py-24"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6 grid grid-cols-1 items-center gap-12 lg:grid-cols-2 lg:gap-16">
        <div className="min-w-0">
          <p className="text-sm font-medium text-accent">Why Unknown exists</p>
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
                className="grid grid-cols-[22px_1fr] gap-3 text-base leading-6 text-ink"
              >
                <Icon name="check" size={20} className="mt-0.5 text-accent" />
                {reason}
              </li>
            ))}
          </ul>
        </div>

        <div className="relative grid min-w-0 gap-4 lg:block lg:h-[440px]">
          <div className="float-a rounded-[14px] border border-hairline bg-ground p-5 shadow-[0_1px_2px_rgba(16,24,40,0.04),0_4px_16px_rgba(16,24,40,0.06)] lg:absolute lg:left-0 lg:top-2 lg:w-[360px]">
            <p className="text-[13px] font-medium text-secondary">
              Registry record, Robinhood Chain
            </p>
            <p className="mt-2 font-mono text-xl text-ink">
              {record?.verdict ?? (record === undefined ? "…" : "—")}
            </p>
            <dl className="mt-3 grid grid-cols-[112px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-sm">
              <Row label="Token" value={short(SUBJECT)} loading={false} />
              <Row
                label="Observed block"
                value={
                  typeof record?.observed_block === "number"
                    ? String(record.observed_block)
                    : null
                }
                loading={record === undefined}
              />
              <Row
                label="Published"
                value={published}
                loading={record === undefined}
              />
              <Row
                label="Registry status"
                value={record?.onchain_status}
                loading={record === undefined}
              />
              <dt className="text-secondary">Transaction</dt>
              <dd className="min-w-0 font-medium text-ink">
                {record?.tx_hash ? (
                  <a
                    href={`https://robin.etherscan.io/tx/${record.tx_hash}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono font-normal text-accent underline underline-offset-2 transition-colors duration-150 hover:text-accent-hover"
                  >
                    {short(record.tx_hash)}
                  </a>
                ) : record === undefined ? (
                  "…"
                ) : (
                  "—"
                )}
              </dd>
            </dl>
            <Source
              path={`/api/verdict/4663/${short(SUBJECT)}`}
              failed={record === null}
            />
          </div>

          <div className="float-b rounded-[14px] border border-hairline bg-ground p-5 shadow-[0_1px_2px_rgba(16,24,40,0.04),0_4px_16px_rgba(16,24,40,0.06)] lg:absolute lg:bottom-2 lg:right-0 lg:w-[330px]">
            <p className="text-[13px] font-medium text-secondary">
              Coverage, Robinhood Chain
            </p>
            <dl className="mt-3 grid grid-cols-[124px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-sm">
              <Row
                label="Sell simulation"
                value={caps?.sell_simulation}
                loading={coverage === undefined}
              />
              <Row
                label="Pool routers"
                value={
                  typeof routers === "number" ? `${routers} allowlisted` : null
                }
                loading={coverage === undefined}
              />
              <Row
                label="Public mempool"
                value={mempool === "no" ? "None" : mempool}
                loading={coverage === undefined}
              />
            </dl>
            <Source path="/api/coverage/4663" failed={coverage === null} />
          </div>
        </div>
      </div>
    </section>
  );
}
