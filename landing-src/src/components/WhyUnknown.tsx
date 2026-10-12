import VerdictRecord from "./VerdictRecord";
import { registryChip } from "../registryVerdict";
import { REGISTRY_CHAIN, useRecord } from "../registryFeed";

// A blocked Robinhood Chain launch as the registry holds it, fetched when the page loads (GET
// /api/verdict/4663/{subject}, through the shared feed in src/registryFeed.ts, so the recent-records strip does not
// ask for it again), drawn as a verdict record whose check-row is the coverage in its published evidence. A route
// that does not answer leaves each of its fields reading Unavailable; nothing is filled in.
const SUBJECT = "0x34357625e8b7414b47c0410327c29361a70c26dd";

const reasons = [
  "The data provider did not answer, so the overlay says Unknown and why.",
  "The chain has no sell simulation route, so the overlay says Unknown and why.",
  "The typed data could not be read, so the overlay says Unknown and why.",
];

function short(hex: string) {
  return `${hex.slice(0, 6)}…${hex.slice(-4)}`;
}

export default function WhyUnknown() {
  const record = useRecord(SUBJECT);
  const recordPath = `/api/verdict/4663/${short(SUBJECT)}`;

  return (
    <section
      id="why-unknown"
      aria-labelledby="why-unknown-title"
      className="pt-16 pb-12 md:pt-24 md:pb-16"
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
            When a check cannot run, ShieldBot does not fill the gap with a
            guess.
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
            <p className="text-xs leading-[18px] text-secondary">
              {record === null ? (
                <>
                  <span className="font-medium text-ink">Unavailable. </span>
                  {`GET ${recordPath} did not answer.`}
                </>
              ) : (
                <>
                  {`Live from GET ${recordPath}`}
                  {record && ` · ${record.onchain_status ?? "Unavailable"}`}
                  {record?.tx_hash && (
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
                </>
              )}
            </p>
          </figure>
        </div>
      </div>
    </section>
  );
}
