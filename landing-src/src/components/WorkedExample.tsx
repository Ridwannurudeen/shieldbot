import Icon from "./Icon";
import { short, shortenHex, useFeed, utc } from "../registryFeed";

// The newest launch ShieldBot blocked on Robinhood Chain, told by its own scan: the two simulated transactions
// are quoted from scan.coverage_reasons.honeypot as GET /api/launches serves it, and the record beside them is
// GET /api/verdict/4663/{address}. Both are live; nothing on this section is baked into the page.
function simulations(reason: string) {
  const sell = /sell reverted: ([^;]+)/.exec(reason)?.[1];
  const transfer = /(a plain transfer [^;]+)/.exec(reason)?.[1];
  return sell && transfer
    ? { sell: shortenHex(sell), transfer: shortenHex(transfer) }
    : null;
}

function Field({
  label,
  value,
  loading,
}: {
  label: string;
  value: string | null | undefined;
  loading: boolean;
}) {
  return (
    <div className="min-w-0 bg-ground p-4">
      <dt className="text-xs text-secondary">{label}</dt>
      <dd className="mt-1.5 font-mono text-[13px] leading-5 text-ink [overflow-wrap:anywhere]">
        {value ?? (loading ? "…" : "—")}
      </dd>
    </div>
  );
}

export default function WorkedExample() {
  const { launches, records, fetchedAt } = useFeed();
  const launch = launches?.[0];
  const record = launch ? records[launch.token_address] : undefined;
  const reason = launch?.scan?.coverage_reasons?.honeypot ?? null;
  const steps = reason ? simulations(reason) : null;
  const recordLoading =
    launches === undefined || (!!launch && record === undefined);
  const score = launch?.scan?.risk_score;

  return (
    <section
      id="worked-example"
      aria-labelledby="worked-example-title"
      className="border-y border-hairline bg-ground-alt py-16 md:py-24"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6 grid grid-cols-1 items-center gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] lg:gap-16">
        <div className="min-w-0 lg:order-2">
          <p className="text-sm font-medium text-accent">Proof, not promises</p>
          <h2
            id="worked-example-title"
            className="mt-3 text-h2-sm md:text-h2 text-ink"
          >
            One token. Two transactions.
          </h2>
          <p className="mt-4 text-[17px] md:text-lg leading-relaxed text-secondary">
            {launch ? (
              <>
                The newest launch ShieldBot blocked on Robinhood Chain,{" "}
                <span className="font-mono text-[0.92em] text-ink">
                  {short(launch.token_address)}
                </span>
                {launch.launchpad && utc(launch.block_timestamp)
                  ? `, opened a ${launch.launchpad} pool on ${utc(launch.block_timestamp)}.`
                  : "."}{" "}
                ShieldBot simulated a sell of it and a plain transfer of it.
                {launch.scan?.risk_level && typeof score === "number"
                  ? ` The scan read ${launch.scan.risk_level}, risk ${score}.`
                  : ""}
              </>
            ) : launches === undefined ? (
              "Loading the newest launch ShieldBot blocked on Robinhood Chain…"
            ) : (
              <>
                <span className="font-medium text-ink">Unavailable. </span>
                GET /api/launches/4663 did not answer, so the newest blocked
                launch is not shown.
              </>
            )}
          </p>

          <dl className="mt-8 grid grid-cols-2 gap-px overflow-hidden rounded-[10px] border border-hairline bg-hairline sm:grid-cols-3">
            <Field
              label="Registry verdict"
              value={
                record ? `${record.verdict} · ${record.verdict_code}` : null
              }
              loading={recordLoading}
            />
            <Field
              label="Observed block"
              value={
                typeof record?.observed_block === "number"
                  ? record.observed_block.toLocaleString("en-US")
                  : null
              }
              loading={recordLoading}
            />
            <Field
              label="Published"
              value={record ? utc(record.published_at) : null}
              loading={recordLoading}
            />
            <div className="min-w-0 bg-ground p-4">
              <dt className="text-xs text-secondary">Registry transaction</dt>
              <dd className="mt-1.5 font-mono text-[13px] leading-5 text-ink">
                {record?.tx_hash ? (
                  <a
                    href={`https://robin.etherscan.io/tx/${record.tx_hash}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-accent underline underline-offset-2 transition-colors duration-150 hover:text-accent-hover"
                  >
                    {short(record.tx_hash)}
                  </a>
                ) : recordLoading ? (
                  "…"
                ) : (
                  "—"
                )}
              </dd>
            </div>
            <Field
              label="Token"
              value={launch ? short(launch.token_address) : null}
              loading={launches === undefined}
            />
            <Field
              label="Status"
              value={record?.onchain_status}
              loading={recordLoading}
            />
          </dl>
          <p className="mt-3 text-xs leading-[18px] text-secondary">
            {record === null && (
              <span className="font-medium text-ink">Unavailable. </span>
            )}
            {launch
              ? record === null
                ? `GET /api/verdict/4663/${short(launch.token_address)} did not answer.`
                : `Live from GET /api/verdict/4663/${short(launch.token_address)}${fetchedAt ? `, fetched ${utc(fetchedAt.getTime() / 1000)}` : ""}. Anyone can recompute the evidence hash: keccak256 of the served document must equal it.`
              : "Live from GET /api/launches/4663?outcome=blocked, then GET /api/verdict/4663/{address}."}
          </p>
        </div>

        <figure className="min-w-0 rounded-[14px] border border-hairline bg-ground p-6 shadow-md md:p-7 lg:order-1">
          <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-hairline pb-4">
            <p className="font-medium text-ink">Two simulated transactions</p>
            <p className="text-xs text-secondary">
              Neither was sent to the chain
            </p>
          </div>
          {steps ? (
            <ol>
              <li className="grid grid-cols-[36px_minmax(0,1fr)] gap-4 border-b border-dashed border-hairline-strong py-5">
                <span
                  className="grid h-9 w-9 place-items-center rounded-full bg-block/10 text-block-text"
                  aria-hidden="true"
                >
                  <Icon name="cross" size={16} />
                </span>
                <div className="min-w-0">
                  <p className="text-xs text-secondary">
                    1 · Simulated sell to the pool
                  </p>
                  <h3 className="mt-1 text-lg font-medium text-ink">
                    Selling it reverted
                  </h3>
                  <p className="mt-2 font-mono text-[13px] leading-5 text-secondary [overflow-wrap:anywhere]">
                    {steps.sell}
                  </p>
                </div>
              </li>
              <li className="grid grid-cols-[36px_minmax(0,1fr)] gap-4 py-5">
                <span
                  className="grid h-9 w-9 place-items-center rounded-full bg-safe/10 text-safe-text"
                  aria-hidden="true"
                >
                  <Icon name="check" size={16} />
                </span>
                <div className="min-w-0">
                  <p className="text-xs text-secondary">
                    2 · Simulated transfer to a fresh address
                  </p>
                  <h3 className="mt-1 text-lg font-medium text-ink">
                    Moving it worked
                  </h3>
                  <p className="mt-2 font-mono text-[13px] leading-5 text-secondary [overflow-wrap:anywhere]">
                    {steps.transfer}
                  </p>
                </div>
              </li>
            </ol>
          ) : (
            <p className="py-5 font-mono text-[13px] leading-5 text-secondary [overflow-wrap:anywhere]">
              {reason
                ? shortenHex(reason)
                : launches === undefined
                  ? "…"
                  : "— The scan's honeypot reason is not available."}
            </p>
          )}
          <figcaption className="rounded-lg bg-ground-alt px-4 py-3 text-sm text-ink">
            {steps
              ? "The token moves; selling it fails. That is a sell trap, on its own evidence."
              : "The scan's honeypot reason, as GET /api/launches serves it."}
          </figcaption>
        </figure>
      </div>
    </section>
  );
}
