import { useEffect, useState } from "react";
import Badge from "./Badge";
import SectionHeader from "./SectionHeader";

// Figures from GET /api/stats (api.py public_stats), fetched when the page loads. A source that is not
// running reports null there, and each figure then reads Unavailable; nothing is filled in.
interface Stats {
  transactions_monitored: number | null;
  mempool_counting_since: number | null;
  mempool_chains_observable: number[] | null;
  launch_discovery: {
    scanned_share: { window_hours: number; launches: number; scanned: number };
  } | null;
  registry_records_confirmed: number | null;
  evidence_documents: Record<string, number> | null;
  contracts_scanned: number | null;
  transactions_blocked: number | null;
}

const chainNames: Record<number, string> = {
  1: "Ethereum",
  56: "BNB Chain",
  8453: "Base",
  42161: "Arbitrum",
  137: "Polygon",
  10: "Optimism",
  204: "opBNB",
  4663: "Robinhood Chain",
};

const checks = [
  "Contract code",
  "Sell simulation",
  "Market data",
  "Typed data",
];

function count(n: number | null | undefined) {
  return typeof n === "number" ? n.toLocaleString("en-US") : null;
}

function list(names: string[]) {
  return names.length > 1
    ? `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`
    : (names[0] ?? "");
}

function Figure({
  value,
  label,
  loading,
}: {
  value: string | null;
  label: string;
  loading: boolean;
}) {
  return (
    <div className="border-t border-hairline pt-5">
      <p className="text-[32px] font-medium leading-none tracking-[-0.03em] text-ink tabular-nums md:text-[40px]">
        {value ?? (loading ? "…" : "—")}
      </p>
      <p className="mt-3 text-sm leading-[21px] text-secondary">
        {value === null && !loading && (
          <span className="font-medium text-ink">Unavailable. </span>
        )}
        {label}
      </p>
    </div>
  );
}

export default function Mechanism() {
  // undefined while loading, null when /api/stats did not answer.
  const [stats, setStats] = useState<Stats | null | undefined>(undefined);
  const [fetchedAt, setFetchedAt] = useState<Date | null>(null);

  useEffect(() => {
    fetch("https://api.shieldbotsecurity.online/api/stats")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: Stats) => {
        setStats(d);
        setFetchedAt(new Date());
      })
      .catch(() => setStats(null));
  }, []);

  const loading = stats === undefined;
  const share = stats?.launch_discovery?.scanned_share;
  const since = stats?.mempool_counting_since
    ? new Date(stats.mempool_counting_since * 1000).toLocaleDateString(
        "en-GB",
        { day: "numeric", month: "long", year: "numeric" },
      )
    : null;
  const mempoolChains = list(
    (stats?.mempool_chains_observable ?? []).map(
      (id) => chainNames[id] ?? `chain ${id}`,
    ),
  );
  const evidence = stats?.evidence_documents?.["4663"];

  return (
    <section
      id="mechanism"
      aria-labelledby="mechanism-title"
      className="border-b border-hairline py-16 md:py-24"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <SectionHeader
          id="mechanism-title"
          eyebrow="How a check ends"
          title="Each check runs, or it says it did not."
          lead="Every request goes through the same checks. When one cannot run, ShieldBot names it and the verdict reads Unknown. Robinhood Chain verdicts from Telegram scans, guard rescans, and launches it blocks or the guard watches are published to the on-chain registry."
        />

        <div className="mt-12 grid grid-cols-1 items-center gap-12 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] lg:gap-16">
          <div
            className="relative mx-auto aspect-square w-full max-w-[400px]"
            aria-hidden="true"
          >
            <svg
              viewBox="0 0 400 400"
              className="absolute inset-0 h-full w-full"
            >
              <circle
                cx="200"
                cy="200"
                r="190"
                fill="none"
                stroke="rgb(var(--c-hairline-strong))"
                strokeDasharray="2 6"
              />
              <circle
                cx="200"
                cy="200"
                r="132"
                fill="none"
                stroke="rgb(var(--c-hairline-strong))"
              />
              <circle
                cx="200"
                cy="200"
                r="74"
                fill="none"
                stroke="rgb(var(--c-hairline-strong))"
                strokeDasharray="2 6"
              />
            </svg>
            <div className="absolute inset-0 grid place-items-center">
              <Badge verdict="unknown" size="lg">
                UNKNOWN
              </Badge>
            </div>
            {checks.map((check, i) => (
              <span
                key={check}
                className="absolute flex h-8 -translate-x-1/2 -translate-y-1/2 items-center gap-2 whitespace-nowrap rounded-full border border-hairline bg-ground px-3 text-[13px] text-ink shadow-sm"
                style={{
                  left: `${50 + 33 * Math.cos(((i * 90 - 45) * Math.PI) / 180)}%`,
                  top: `${50 + 33 * Math.sin(((i * 90 - 45) * Math.PI) / 180)}%`,
                }}
              >
                <span className="h-1.5 w-1.5 rounded-full bg-unknown" />
                {check}
              </span>
            ))}
          </div>

          <div>
            <div className="grid grid-cols-1 gap-x-10 gap-y-8 sm:grid-cols-2">
              <Figure
                loading={loading}
                value={count(stats?.transactions_monitored)}
                label={`Pending transactions seen${since ? ` since ${since}` : ""}${mempoolChains ? ` on ${mempoolChains}` : ""}, the mempools the monitor could read on its last poll.`}
              />
              <Figure
                loading={loading}
                value={
                  share
                    ? `${count(share.scanned)} of ${count(share.launches)}`
                    : null
                }
                label={`New Robinhood Chain launches in the last ${share?.window_hours ?? 24} hours that have a scan outcome.`}
              />
              <Figure
                loading={loading}
                value={count(stats?.registry_records_confirmed)}
                label={`Verdict records confirmed in the Robinhood Chain registry, all time${typeof evidence === "number" ? `, from ${evidence.toLocaleString("en-US")} stored evidence documents` : ""}.`}
              />
              <div className="border-t border-hairline pt-5 text-sm leading-[21px] text-secondary">
                <p>
                  <span className="font-medium text-ink tabular-nums">
                    {count(stats?.contracts_scanned) ?? (loading ? "…" : "—")}
                  </span>{" "}
                  contracts scored by the extension and agent firewalls, all
                  time.
                </p>
                <p className="mt-2">
                  <span className="font-medium text-ink tabular-nums">
                    {count(stats?.transactions_blocked) ??
                      (loading ? "…" : "—")}
                  </span>{" "}
                  {stats?.transactions_blocked === 1 ? "transaction" : "transactions"} blocked, all time.
                </p>
              </div>
            </div>
            <p className="mt-8 text-xs leading-[18px] text-secondary">
              {stats
                ? `GET /api/stats, as of ${fetchedAt?.toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" })} in your time zone. A source that is not running reads Unavailable, never 0.`
                : stats === null
                  ? "GET /api/stats did not answer, so every figure reads Unavailable."
                  : "Loading GET /api/stats."}
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
