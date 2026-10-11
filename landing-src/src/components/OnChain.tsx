import { useEffect } from "react";
import CodeBlock from "./CodeBlock";
import ContractCard from "./ContractCard";
import SectionHeader from "./SectionHeader";
import Icon from "./Icon";
import type { CSSProperties } from "react";
import VerdictRecord from "./VerdictRecord";
import { registryChip } from "../registryVerdict";
import { useReading } from "../reading";
import {
  REGISTRY_CHAIN,
  loadRecentRecords,
  short,
  useFeed,
  utc,
  type RegistryRecord,
} from "../registryFeed";

const contracts = [
  {
    name: "ShieldBotVerdictRegistry",
    role: "Records an authorised recorder's verdict and the keccak256 hash of its evidence document. The owner can rotate the recorder.",
    address: "0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
    links: [
      {
        label: "Explorer",
        href: "https://robin.etherscan.io/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
      },
      {
        label: "Blockscout",
        href: "https://robinhoodchain.blockscout.com/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138?tab=contract",
      },
      {
        label: "Sourcify exact match",
        href: "https://sourcify.dev/server/v2/contract/4663/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
      },
    ],
  },
  {
    name: "ShieldBotVerdictGuard",
    role: "Reads the registry and allows only a LOW or MEDIUM verdict published within the caller's maxAge. check() returns allowed and a reason code; requireAllowed() reverts with NotAllowed.",
    address: "0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
    links: [
      {
        label: "Explorer",
        href: "https://robin.etherscan.io/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
      },
      {
        label: "Blockscout",
        href: "https://robinhoodchain.blockscout.com/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e?tab=contract",
      },
      {
        label: "Sourcify exact match",
        href: "https://sourcify.dev/server/v2/contract/4663/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
      },
    ],
  },
  {
    name: "ShieldBotGuardedTransfer",
    role: "Asks the guard, then moves the caller's approved USDG and reverts unless the recipient's balance rises by exactly the amount. Its subject is VIRTUAL. No live guarded USDG payment is claimed.",
    address: "0x336254bA85406D9af39357101b688E2B757751b3",
    links: [
      {
        label: "Explorer",
        href: "https://robin.etherscan.io/address/0x336254bA85406D9af39357101b688E2B757751b3",
      },
      {
        label: "Blockscout",
        href: "https://robinhoodchain.blockscout.com/address/0x336254bA85406D9af39357101b688E2B757751b3?tab=contract",
      },
      {
        label: "Sourcify exact match",
        href: "https://sourcify.dev/server/v2/contract/4663/0x336254bA85406D9af39357101b688E2B757751b3",
      },
    ],
  },
];

const reasonCodes = [
  [
    "0 ALLOWED",
    "Recorded LOW or MEDIUM, not future-dated, within a positive maxAge",
  ],
  ["1 NO_RECORD", "No evidence hash has been recorded"],
  ["2 UNKNOWN", "Fresh record with incomplete evidence"],
  ["3 HIGH", "High risk, even when expired"],
  ["4 HONEYPOT", "Proven sell trap, even when expired"],
  ["5 EXPIRED", "Non-adverse record older than maxAge, or maxAge is zero"],
  ["6 FUTURE_TIMESTAMP", "Non-adverse publication ahead of the check clock"],
];

const figures = [
  { value: "68,666", label: "new tokens first seen in a liquidity pool" },
  { value: "~8,000", label: "new tokens a day" },
  {
    value: "28.76%",
    label: "of mature tokens met a minimal liquidity or activity bar",
  },
  {
    value: "49%",
    label: "could not be resolved either way and are reported as unknown",
  },
];

const verificationCode = `export API_BASE='https://api.shieldbotsecurity.online'
export RPC_URL='https://robinhood-rpc.publicnode.com'
export REGISTRY='0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138'
export SUBJECT='0xf8bc08092c06db6148114dcf82af881f1085f92b'`;

const API = "https://api.shieldbotsecurity.online";

type Row = { subject: string; record: RegistryRecord | null | undefined };

// Each record reads itself as it arrives, once the list is in view, 120 ms after the row above it (index.css).

function RecordRow({ subject, record, index }: Row & { index: number }) {
  const loading = record === undefined;
  return (
    <li
      className="border-t border-hairline px-5 py-4 lg:py-5"
      style={{ "--vr-d": `${index * 120}ms` } as CSSProperties}
    >
      <div className="grid gap-4 sm:grid-cols-[minmax(120px,0.7fr)_minmax(0,2.4fr)] lg:grid-cols-[minmax(140px,0.65fr)_minmax(0,2fr)] lg:items-start">
        <div className="min-w-0">
          <p className="text-xs text-secondary">Token</p>
          <a
            href={`${API}/api/verdict/4663/${subject}`}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={`Record for token ${subject}`}
            className="mt-1 inline-block font-mono text-[13px] text-accent underline underline-offset-2 transition-colors duration-150 hover:text-accent-hover"
          >
            {short(subject)}
          </a>
        </div>
        <div className="min-w-0">
          {record ? (
            <>
              <VerdictRecord
                animate
                chip={registryChip(record.verdict, record.verdict_code)}
                chain={REGISTRY_CHAIN}
                block={record.observed_block}
                publishedAt={record.published_at}
                evidenceHash={record.evidence_hash}
                variant="compact"
              />
              <div className="mt-2 grid gap-2 text-xs leading-[18px] sm:grid-cols-2">
                <p className="min-w-0">
                  <span className="mr-2 text-secondary">Transaction</span>
                  {record.tx_hash ? (
                    <a
                      href={`https://robin.etherscan.io/tx/${record.tx_hash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-accent underline underline-offset-2 transition-colors duration-150 hover:text-accent-hover"
                    >
                      {short(record.tx_hash)}
                    </a>
                  ) : (
                    <span className="font-mono text-ink">Unavailable</span>
                  )}
                </p>
                <p className="min-w-0">
                  <span className="mr-2 text-secondary">Status</span>
                  <span className="font-mono text-ink">{record.onchain_status}</span>
                </p>
              </div>
            </>
          ) : (
            <p aria-busy={loading} className="text-sm text-secondary">
              {loading ? (
                "Loading registry record…"
              ) : (
                <>
                  <span className="font-medium text-ink">Unavailable. </span>
                  GET /api/verdict/4663/{subject} did not answer.
                </>
              )}
            </p>
          )}
        </div>
      </div>
    </li>
  );
}

function RecentRecords() {
  const { recent, launches, records, fetchedAt } = useFeed();
  const strip = useReading<HTMLDivElement>();

  // In the fallback each row needs its own record request; they are sent only once the strip is about a screen
  // away, so a visitor who never scrolls here does not spend the API's per-minute allowance on them.
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (!entries.some((entry) => entry.isIntersecting)) return;
        observer.disconnect();
        loadRecentRecords();
      },
      { rootMargin: "800px 0px" },
    );
    if (strip.current) observer.observe(strip.current);
    return () => observer.disconnect();
  }, []);
  const fallback = recent === "fallback";
  const rows: Row[] | null | undefined = Array.isArray(recent)
    ? recent.map((record) => ({ subject: record.subject, record }))
    : fallback
      ? launches &&
        launches.map((launch) => ({
          subject: launch.token_address,
          record: records[launch.token_address],
        }))
      : recent;
  const at = fetchedAt ? `, fetched ${utc(fetchedAt.getTime() / 1000)}` : "";

  return (
    <div
      ref={strip}
      data-read="wait"
      className="mt-10 overflow-hidden rounded-[14px] border border-hairline bg-ground shadow-md"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1 px-5 py-4">
        <h3 className="text-lg font-medium text-ink">
          {fallback
            ? "Records of the newest launches ShieldBot blocked"
            : "Newest confirmed records in the registry"}
        </h3>
        <a
          href="/dashboard"
          className="inline-flex min-h-[44px] items-center gap-1.5 text-sm font-medium text-accent transition-colors duration-150 hover:text-accent-hover"
        >
          Every record on the dashboard
          <Icon name="chevron" size={16} className="-rotate-90" />
        </a>
      </div>
      {rows === undefined ? (
        <ol aria-busy="true">
          {Array.from({ length: 5 }, (_, i) => (
            <li
              key={i}
              className="border-t border-hairline px-5 py-4 font-mono text-[13px] text-secondary"
            >
              …
            </li>
          ))}
        </ol>
      ) : rows === null || rows.length === 0 ? (
        <p className="border-t border-hairline px-5 py-5 text-sm text-secondary">
          <span className="font-medium text-ink">Unavailable. </span>
          {rows === null
            ? "The registry feed did not answer, so no record is shown."
            : "No record has been published yet."}
        </p>
      ) : (
        <ol>
          {rows.map((row, index) => (
            <RecordRow key={row.subject} {...row} index={index} />
          ))}
        </ol>
      )}
      <p className="border-t border-hairline bg-ground-alt px-5 py-3 text-xs leading-[18px] text-secondary">
        {recent === null
          ? "GET /api/verdicts/recent?chain_id=4663&limit=5 did not answer."
          : fallback && launches === null
            ? "GET /api/launches/4663?outcome=blocked&limit=5 did not answer."
            : fallback
              ? `Live from GET /api/launches/4663?outcome=blocked&limit=5, then GET /api/verdict/4663/{address} for each launch${at}. Each row is that token's newest record.`
              : `Live from GET /api/verdicts/recent?chain_id=4663&limit=5${at}: confirmed records, newest first.`}
      </p>
    </div>
  );
}

export default function OnChain() {
  return (
    <section
      id="on-chain"
      aria-labelledby="on-chain-title"
      className="bg-ground py-16 md:py-24"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <SectionHeader
          id="on-chain-title"
          eyebrow="On Robinhood Chain (4663)"
          title="A contract can check the verdict before it moves funds."
          lead="ShieldBot records on-chain the Robinhood Chain verdicts of its Telegram scans, guard rescans, and launches it blocks or the guard watches, each with the hash of its evidence document. A guard contract allows only a recent LOW or MEDIUM record, and a guarded transfer asks the guard before it moves USDG. Missing, Unknown, high-risk, honeypot, expired and future-dated records are denied."
        />

        <RecentRecords />

        <div className="mt-16 grid grid-cols-1 gap-6 lg:grid-cols-3">
          {contracts.map((contract) => (
            <ContractCard key={contract.address} {...contract} />
          ))}
        </div>
        <p className="mt-4 text-sm text-secondary">
          All three deployed on 27 September 2026 from the registry owner's
          account, built from main at c9ae9c9, with full exact source matches on
          Sourcify.
        </p>

        <div className="mt-16 grid grid-cols-1 gap-12 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
          <div className="min-w-0">
            <h3 className="text-xl font-medium tracking-[-0.01em] text-ink">
              Verify a verdict without trusting the API
            </h3>
            <p className="mt-3 text-[15px] leading-relaxed text-secondary">
              The judge guide's section 3 checks a published verdict against the
              registry with any Robinhood Chain RPC. No API key, wallet or
              signing is needed.
            </p>
            <ol className="mt-5 grid gap-3">
              {[
                <>
                  Fetch the evidence document from GET /api/verdict/4663/
                  {"{address}"}.
                </>,
                <>Hash the served canonical string with keccak256.</>,
                <>
                  Read the recording transaction's receipt from an independent
                  RPC and match the VerdictRecorded event's subject, verdict and
                  evidence hash.
                </>,
              ].map((step, i) => (
                <li
                  key={i}
                  className="grid grid-cols-[28px_minmax(0,1fr)] gap-3 text-[15px] leading-6 text-ink"
                >
                  <span className="grid h-7 w-7 place-items-center rounded-full border border-hairline-strong text-xs text-secondary">
                    {i + 1}
                  </span>
                  <span className="pt-0.5">{step}</span>
                </li>
              ))}
            </ol>
            <p className="mt-6 text-sm text-secondary">
              From the judge guide, section 3. The published example is WOOD.
              Any Robinhood Chain RPC works; the API does not use this one.
            </p>
            <div className="mt-3">
              <CodeBlock code={verificationCode} />
            </div>
            <p className="mt-3 text-[15px] text-secondary">
              Then set RECORD_TX to the full hash of 0x7578ca9e…f0c772a4 from
              the judge guide, section 3, and run the guide's Python block.
            </p>
            <a
              className="mt-2 inline-flex min-h-[44px] items-center gap-1.5 self-start text-sm font-medium text-accent underline underline-offset-4 transition-colors duration-150 hover:text-accent-hover"
              href="https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api"
              target="_blank"
              rel="noopener noreferrer"
            >
              Open the judge guide
              <Icon name="external" size={16} />
            </a>
            <p className="mt-2 text-sm text-secondary">
              A match proves the recorder committed those bytes. It does not
              prove the scan was right, that an issuer is genuine, or that a
              token will stay sellable.
            </p>
          </div>
          <div className="min-w-0">
            <h3 className="text-xl font-medium tracking-[-0.01em] text-ink">
              What the guard answers
            </h3>
            <ul className="mt-5 overflow-hidden rounded-[10px] border border-hairline">
              {reasonCodes.map(([code, description]) => (
                <li
                  key={code}
                  className="grid grid-cols-[minmax(0,148px)_minmax(0,1fr)] gap-3 border-t border-hairline px-4 py-3 text-sm first:border-t-0"
                >
                  <code className="font-mono text-xs leading-5 text-ink">
                    {code}
                  </code>
                  <span className="text-secondary">{description}</span>
                </li>
              ))}
            </ul>
            <p className="mt-5 text-sm text-secondary">
              Permission lasts only while a subject is actively watched and
              republished; freshness is publication age, not observation age.
            </p>
          </div>
        </div>

        <div className="mt-16">
          <h3 className="text-xl font-medium tracking-[-0.01em] text-ink">
            What we saw on the chain
          </h3>
          <div className="mt-6 grid grid-cols-2 gap-x-6 gap-y-8 lg:grid-cols-4">
            {figures.map((figure) => (
              <div key={figure.label} className="border-t border-hairline pt-5">
                <div className="text-[32px] font-medium leading-none tracking-[-0.03em] text-ink tabular-nums md:text-[40px]">
                  {figure.value}
                </div>
                <div className="mt-3 text-sm leading-[21px] text-secondary">
                  {figure.label}
                </div>
              </div>
            ))}
          </div>
          <p className="mt-6 text-[13px] text-secondary">
            Observed from 14 to 22 September 2026, about 8.6 days. These figures
            describe the chain, not ShieldBot scans. A token is counted when it
            first appears in a liquidity pool, not when it is deployed, and
            missing evidence is reported as unknown, never as zero.{" "}
            <a
              className="text-accent underline underline-offset-4 transition-colors duration-150 hover:text-accent-hover"
              href="https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/census-4663.md"
              target="_blank"
              rel="noopener noreferrer"
            >
              Method and limits
            </a>
          </p>
        </div>
      </div>
    </section>
  );
}
