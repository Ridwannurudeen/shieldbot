import { useFeed, REGISTRY_CHAIN, short, shortenHex, utc } from "../registryFeed";
import { registryChip } from "../registryVerdict";
import { useStats, type Stats } from "../liveStats";
import VerdictRecord from "./VerdictRecord";
import Section from "./Section";

const API = "https://api.shieldbotsecurity.online";
const launchesUrl = `${API}/api/launches/4663?outcome=blocked&limit=3`;

const chainNames: Record<number, string> = {
  1: "Ethereum",
  56: "BNB Chain",
  8453: "Base",
  42161: "Arbitrum",
  137: "Polygon",
  10: "Optimism",
  204: "opBNB",
  4663: "Robinhood Chain",
  677: "BOT Chain",
};

function count(value: number | null | undefined) {
  return typeof value === "number" ? value.toLocaleString("en-US") : null;
}

function list(names: string[]) {
  return names.length > 1
    ? `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`
    : (names[0] ?? "");
}

function SourceTime({
  href,
  at,
}: {
  href: string;
  at: Date | null;
}) {
  if (!at) return null;
  const time = at.toISOString().slice(11, 16);
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="mt-2 inline-flex min-h-11 items-center font-mono text-xs text-secondary underline decoration-hairline-strong underline-offset-4 hover:text-ink"
      aria-label={`Source fetched at ${time} UTC`}
    >
      {time} UTC
    </a>
  );
}

function Figure({
  value,
  label,
  loading,
  fetchedAt,
}: {
  value: string | null;
  label: string;
  loading: boolean;
  fetchedAt: Date | null;
}) {
  return (
    <div className="grid grid-cols-[minmax(88px,0.5fr)_minmax(0,1.5fr)] gap-x-5 border-b border-hairline py-5 sm:grid-cols-[minmax(110px,0.55fr)_minmax(0,1.45fr)]">
      <p className="font-mono text-xl leading-7 text-ink tabular-nums sm:text-2xl">
        {value ?? (loading ? "Loading" : "Unavailable")}
      </p>
      <div>
        <p className="text-sm leading-6 text-secondary">{label}</p>
        <SourceTime
          href={`${API}/api/stats`}
          at={loading ? null : fetchedAt}
        />
      </div>
    </div>
  );
}

function Metrics({ stats, fetchedAt }: { stats: Stats | null | undefined; fetchedAt: Date | null }) {
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

  return (
    <dl className="border-t border-hairline">
      <Figure
        loading={loading}
        fetchedAt={fetchedAt}
        value={count(stats?.transactions_monitored)}
        label={`Pending transactions seen${since ? ` since ${since}` : ""}${mempoolChains ? ` on ${mempoolChains}` : ""}`}
      />
      <Figure
        loading={loading}
        fetchedAt={fetchedAt}
        value={
          share
            ? `${count(share.scanned) ?? "Unavailable"} of ${count(share.launches) ?? "Unavailable"}`
            : null
        }
        label={`Robinhood Chain launches in the last ${share?.window_hours ?? 24} hours with a scan outcome`}
      />
      <Figure
        loading={loading}
        fetchedAt={fetchedAt}
        value={count(
          stats?.registry_records_confirmed_by_chain?.["4663"] ??
            stats?.registry_records_confirmed,
        )}
        label="Verdict records confirmed in the Robinhood Chain registry, all time"
      />
      <Figure
        loading={loading}
        fetchedAt={fetchedAt}
        value={count(stats?.registry_records_confirmed_by_chain?.["677"])}
        label="Verdict records confirmed in the BOT Chain registry, all time"
      />
    </dl>
  );
}

function simulationSteps(reason: string | null) {
  if (!reason) return null;
  const sell = /sell reverted: ([^;]+)/.exec(reason)?.[1];
  const transfer = /(a plain transfer [^;]+)/.exec(reason)?.[1];
  return sell && transfer
    ? { sell: shortenHex(sell), transfer: shortenHex(transfer) }
    : null;
}

function WorkedExample() {
  const { launches, records, launchesFetchedAt, recordFetchedAt } = useFeed();
  const launch = launches?.[0];
  const record = launch ? records[launch.token_address] : undefined;
  const reason = launch?.scan?.coverage_reasons?.honeypot ?? null;
  const steps = simulationSteps(reason);
  const recordUrl = record
    ? `${API}/api/verdict/4663/${record.subject}`
    : launchesUrl;

  return (
    <div className="min-w-0">
      <h3 className="text-lg font-medium text-ink">
        One token. Two simulated transactions.
      </h3>
      {launch ? (
        <p className="mt-3 text-sm leading-6 text-secondary">
          Blocked launch on Robinhood Chain, token{" "}
          <span className="font-mono text-ink">{short(launch.token_address)}</span>.
          {launch.launchpad && utc(launch.block_timestamp)
            ? ` Pool opened on ${launch.launchpad} at ${utc(launch.block_timestamp)}.`
            : ""}
        </p>
      ) : (
        <p role="status" className="mt-3 text-sm text-secondary">
          {launches === undefined ? "Loading" : "Unavailable"}
        </p>
      )}
      <SourceTime
        href={launchesUrl}
        at={launchesFetchedAt}
      />

      {steps ? (
        <dl className="mt-5 divide-y divide-hairline border-y border-hairline">
          <div className="grid gap-2 py-4 sm:grid-cols-[minmax(170px,0.75fr)_minmax(0,1.25fr)] sm:gap-5">
            <dt className="text-sm font-medium text-ink">Simulated sell to the pool</dt>
            <dd className="font-mono text-xs leading-5 text-secondary [overflow-wrap:anywhere]">
              {steps.sell}
            </dd>
          </div>
          <div className="grid gap-2 py-4 sm:grid-cols-[minmax(170px,0.75fr)_minmax(0,1.25fr)] sm:gap-5">
            <dt className="text-sm font-medium text-ink">Simulated transfer to a fresh address</dt>
            <dd className="font-mono text-xs leading-5 text-secondary [overflow-wrap:anywhere]">
              {steps.transfer}
            </dd>
          </div>
        </dl>
      ) : (
        <p className="mt-5 text-sm text-secondary">
          {reason ? shortenHex(reason) : "Simulation details unavailable"}
        </p>
      )}

      {record ? (
        <div className="mt-6">
          <SourceTime href={recordUrl} at={recordFetchedAt[record.subject] ?? null} />
          <VerdictRecord
            chip={registryChip(record.verdict, record.verdict_code)}
            chain={REGISTRY_CHAIN}
            block={record.observed_block}
            publishedAt={record.published_at}
            evidenceHash={record.evidence_hash}
          />
          <p className="mt-2 font-mono text-xs text-secondary">
            {record.onchain_status}
            {" · "}
            {record.tx_hash ? (
              <a
                href={`https://robin.etherscan.io/tx/${record.tx_hash}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-ink underline decoration-hairline-strong underline-offset-4"
              >
                Transaction {short(record.tx_hash)}
              </a>
            ) : (
              "Transaction unavailable"
            )}
          </p>
        </div>
      ) : (
        <p role="status" className="mt-5 text-sm text-secondary">
          {record === undefined && launch
            ? "Loading registry record"
            : record === null && launch
              ? "Registry record unavailable"
                : launches === undefined
                  ? "Loading registry record"
                  : launches === null
                    ? "Launch data unavailable"
                  : "No registry record is available for this launch"}
        </p>
      )}
    </div>
  );
}

export default function Proof() {
  const { stats, fetchedAt: statsFetchedAt } = useStats();

  return (
    <Section id="proof" title="Proof">
      <div className="grid items-start gap-12 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)] lg:gap-16">
        <WorkedExample />
        <Metrics stats={stats} fetchedAt={statsFetchedAt} />
      </div>
    </Section>
  );
}
