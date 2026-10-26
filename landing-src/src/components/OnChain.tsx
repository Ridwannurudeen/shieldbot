import { useEffect, useState } from "react";
import CodeBlock from "./CodeBlock";
import ContractCard from "./ContractCard";
import SectionHeader from "./SectionHeader";
import Icon from "./Icon";
import { PauseButton } from "./Button";
import type { CSSProperties } from "react";
import VerdictRecord from "./VerdictRecord";
import { registryChip } from "../registryVerdict";
import { useAlive, useReading } from "../reading";
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
    role: "Records an authorised recorder's verdict and the keccak256 hash of its evidence.",
    address: "0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
    links: [
      {
        label: "Explorer",
        href: "https://robin.etherscan.io/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
      },
      {
        label: "Sourcify exact match",
        href: "https://sourcify.dev/server/v2/contract/4663/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
      },
    ],
  },
  {
    name: "ShieldBotVerdictGuard",
    role: "Allows only a LOW or MEDIUM record published within the caller's maxAge; requireAllowed() reverts otherwise.",
    address: "0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
    links: [
      {
        label: "Explorer",
        href: "https://robin.etherscan.io/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
      },
      {
        label: "Sourcify exact match",
        href: "https://sourcify.dev/server/v2/contract/4663/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
      },
    ],
  },
  {
    name: "ShieldBotGuardedTransfer",
    role: "Asks the guard, then moves approved USDG. Its subject is VIRTUAL; no live guarded USDG payment is claimed.",
    address: "0x336254bA85406D9af39357101b688E2B757751b3",
    links: [
      {
        label: "Explorer",
        href: "https://robin.etherscan.io/address/0x336254bA85406D9af39357101b688E2B757751b3",
      },
      {
        label: "Sourcify exact match",
        href: "https://sourcify.dev/server/v2/contract/4663/0x336254bA85406D9af39357101b688E2B757751b3",
      },
    ],
  },
];

// The BOT Chain registry, as docs/DEPLOYMENTS.md records it. The same owner deployed both registries at nonce 0, so
// the address equals the Robinhood Chain one: the chain is always named beside it. No records feed reads it yet.
const botRegistry = {
  address: "0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
  href: "https://scan.botchain.ai/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
};

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

const verificationCode = `export API_BASE='https://api.shieldbotsecurity.online'
export RPC_URL='https://robinhood-rpc.publicnode.com'
export REGISTRY='0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138'
export SUBJECT='0xf8bc08092c06db6148114dcf82af881f1085f92b'`;

const API = "https://api.shieldbotsecurity.online";

type Row = { subject: string; record: RegistryRecord | null | undefined };

// Each record reads itself as it arrives, once the list is in view, 120 ms after the row above it (index.css). Then,
// while the strip is on screen, one record at a time reads itself again (again counts its turns; live marks the row
// whose turn it is): the records already fetched, never a new request. Off screen, in a hidden tab or paused, the
// strip holds its frame (data-paused).

function RecordRow({ subject, record, index, again, live }: Row & { index: number; again: number; live: boolean }) {
  const loading = record === undefined;
  return (
    <li
      className={`${live ? "rr-live " : ""}relative isolate border-t border-hairline px-5 py-4 lg:py-5`}
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
            className="mt-1 inline-block font-mono text-[13px] text-accent underline underline-offset-2 transition-colors duration-150 hover:text-ink"
          >
            {short(subject)}
          </a>
        </div>
        <div className="min-w-0">
          {record ? (
            <>
              <VerdictRecord
                key={again}
                animate
                chip={registryChip(record.verdict, record.verdict_code)}
                chain={REGISTRY_CHAIN}
                block={record.observed_block}
                publishedAt={record.published_at}
                evidenceHash={record.evidence_hash}
                variant="compact"
              />
              <p className="mt-2 font-mono text-xs leading-[18px] text-ink">
                {record.onchain_status}
                {" · tx "}
                {record.tx_hash ? (
                  <a
                    href={`https://robin.etherscan.io/tx/${record.tx_hash}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-accent underline underline-offset-2 transition-colors duration-150 hover:text-ink"
                  >
                    {short(record.tx_hash)}
                  </a>
                ) : (
                  "Unavailable"
                )}
              </p>
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
  const { ref: alive, on, paused, setPaused } = useAlive<HTMLDivElement>();
  const [turn, setTurn] = useState(0);
  useEffect(() => {
    if (!on) return;
    const timer = setTimeout(() => setTurn(turn + 1), 4_500);
    return () => clearTimeout(timer);
  }, [on, turn]);

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
      <div ref={alive} data-paused={on ? undefined : ""}>
        <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-1 px-5 py-4">
          <h3 className="text-lg font-medium text-ink">
            {fallback
              ? "Records of the newest launches ShieldBot blocked"
              : "Newest confirmed records in the registry"}
          </h3>
          <a
            href="/dashboard"
            className="inline-flex min-h-[44px] items-center gap-1.5 text-sm font-medium text-accent transition-colors duration-150 hover:text-ink"
          >
            Every record on the dashboard
            <Icon name="chevron" size={16} className="-rotate-90" />
          </a>
          <PauseButton paused={paused} setPaused={setPaused} />
        </div>
        {rows === undefined ? (
          <ol aria-busy="true">
            {Array.from({ length: 3 }, (_, i) => (
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
              <RecordRow
                key={row.subject}
                {...row}
                index={index}
                again={turn > index ? Math.floor((turn - 1 - index) / rows.length) + 1 : 0}
                live={turn > 0 && (turn - 1) % rows.length === index}
              />
            ))}
          </ol>
        )}
        <p className="border-t border-hairline bg-ground-alt px-5 py-3 text-xs leading-[18px] text-secondary">
          {recent === null
            ? "GET /api/verdicts/recent?chain_id=4663&limit=3 did not answer."
            : fallback && launches === null
              ? "GET /api/launches/4663?outcome=blocked&limit=3 did not answer."
              : fallback
                ? `Live from GET /api/launches/4663?outcome=blocked&limit=3, then GET /api/verdict/4663/{address}${at}. While in view, one record at a time reads itself again; no new request.`
                : `Live from GET /api/verdicts/recent?chain_id=4663&limit=3${at}. While in view, one record at a time reads itself again; no new request.`}
        </p>
      </div>
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
          lead="ShieldBot publishes the Robinhood Chain verdicts of its Telegram scans, guard rescans, and launches it blocks or the guard watches, each with the hash of its evidence. A guard contract allows only a fresh LOW or MEDIUM record; everything else is denied. Permission is not a safety guarantee: the guard accepts MEDIUM risk."
        />

        <RecentRecords />

        <div className="mt-12 grid grid-cols-1 gap-6 lg:grid-cols-3">
          {contracts.map((contract) => (
            <ContractCard key={contract.address} {...contract} />
          ))}
        </div>

        <div className="mt-6 rounded-lg border border-hairline bg-ground-alt p-5 sm:p-6">
          <h3 className="font-mono text-[11px] uppercase leading-4 tracking-[0.08em] text-secondary">
            Also on BOT Chain (677)
          </h3>
          <div className="mt-3 grid grid-cols-1 gap-x-10 gap-y-3 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
            <div className="min-w-0">
              <p className="font-mono text-sm font-medium text-ink">ShieldBotVerdictRegistry</p>
              <a
                href={botRegistry.href}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-1 inline-flex min-h-[44px] items-center gap-1.5 font-mono text-[13px] text-accent underline underline-offset-4 transition-colors duration-150 hover:text-ink"
              >
                <span className="lg:hidden">{short(botRegistry.address)}</span>
                <span className="hidden lg:inline">{botRegistry.address}</span>
                <Icon name="external" size={16} />
              </a>
              <p className="text-[13px] text-secondary">Deployed on BOT Chain on 26 October 2026</p>
            </div>
            <p className="min-w-0 text-sm leading-relaxed text-secondary">
              Telegram /scan and /token results on BOT Chain can be recorded here, each with the hash of its
              evidence. Any contract can read it with a BOT Chain RPC such as https://rpc.botchain.ai. No guard or
              guarded transfer on BOT Chain. Source not yet verified on the explorer; the bytecode matches a local
              build.
            </p>
          </div>
        </div>

        <div className="mt-12 grid grid-cols-1 gap-x-12 gap-y-8 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
          <div className="min-w-0">
            <details className="disclose border-t border-hairline pt-1">
              <summary>Verify a verdict without trusting the API</summary>
              <p className="mt-2 text-[15px] leading-relaxed text-secondary">
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
                From the judge guide, section 3; the example is WOOD.
              </p>
              <div className="mt-3">
                <CodeBlock code={verificationCode} />
              </div>
              <p className="mt-3 text-[15px] text-secondary">
                Then set RECORD_TX to the full hash of 0x7578ca9e…f0c772a4 (judge
                guide, section 3) and run its Python block.
              </p>
              <a
                className="mt-2 inline-flex min-h-[44px] items-center gap-1.5 self-start text-sm font-medium text-accent underline underline-offset-4 transition-colors duration-150 hover:text-ink"
                href="https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api"
                target="_blank"
                rel="noopener noreferrer"
              >
                Open the judge guide
                <Icon name="external" size={16} />
              </a>
            </details>
            <p className="mt-2 text-sm text-secondary">
              A match proves the recorder committed those bytes. It does not
              prove the scan was right, that an issuer is genuine, or that a
              token will stay sellable.
            </p>
          </div>
          <div className="min-w-0">
            <details className="disclose border-t border-hairline pt-1">
              <summary>The guard's seven reason codes</summary>
              <ul className="mt-2 overflow-hidden rounded-[10px] border border-hairline">
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
            </details>
            <p className="mt-2 text-sm text-secondary">
              Permission lasts only while a subject is actively watched and
              republished; freshness is publication age, not observation age.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
