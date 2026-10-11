import SectionHeader from "./SectionHeader";
import { CHECK_ORDER, type CheckKey } from "./CheckRow";
import { useStats } from "../liveStats";

// Figures from GET /api/stats (api.py public_stats, src/liveStats.ts), fetched when the page loads. A source
// that is not running reports null there, and each figure then reads Unavailable; nothing is filled in.
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

const CHECK_MEANINGS: Record<CheckKey, string> = {
  structural: "Contract verification, age, bytecode risks, holder concentration, and scam matches.",
  market: "Liquidity, pair age, price movement, and wash-trading signals.",
  behavioral: "Ethos reputation and scam flags for a transaction counterparty.",
  honeypot: "Buy and sell behavior, transfer taxes, and sellability.",
  intent: "Decoded calls, approval grants, recipients, and mismatches between a call and its apparent purpose.",
  signature: "EIP-712 permits and signed NFT orders, including spender, amount, and deadline.",
};

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
  const { stats, fetchedAt } = useStats();

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

        <div className="mt-12 grid grid-cols-1 items-start gap-12 lg:grid-cols-[minmax(0,6fr)_minmax(0,5fr)] lg:gap-16">
          <figure className="rounded-lg border border-hairline bg-ground p-5 sm:p-6">
            <figcaption id="check-definition-title" className="font-mono text-[11px] uppercase leading-4 tracking-[0.08em] text-secondary">
              The six check keys
            </figcaption>
            <div aria-label="Check cell legend" className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-xs text-secondary">
              <span className="inline-flex items-center gap-2">
                <span aria-hidden="true" className="h-4 w-4 rounded-[2px] border border-ink bg-ink" />
                Filled: ran
              </span>
              <span className="inline-flex items-center gap-2">
                <span aria-hidden="true" className="h-4 w-4 rounded-[2px] border border-dashed border-ink" />
                Dashed: partial or no run
              </span>
              <span className="inline-flex items-center gap-2">
                <span aria-hidden="true" className="h-4 w-4 rounded-[2px] border border-ink bg-ground" />
                Outline: Unavailable
              </span>
            </div>
            <ol className="mt-5 divide-y divide-hairline border-t border-hairline">
              {CHECK_ORDER.map((key) => (
                <li key={key} className="grid grid-cols-[minmax(92px,max-content)_minmax(0,1fr)] gap-x-4 py-3 sm:grid-cols-[minmax(110px,max-content)_minmax(0,1fr)]">
                  <code className="font-mono text-xs leading-5 text-ink">{key}</code>
                  <p className="text-[13px] leading-5 text-secondary">{CHECK_MEANINGS[key]}</p>
                </li>
              ))}
            </ol>
            <p className="mt-4 border-t border-hairline pt-3 text-xs leading-[18px] text-secondary">
              A dashed cell is not a pass. If a provider does not return a check, its cell reads Unavailable.
            </p>
          </figure>

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
