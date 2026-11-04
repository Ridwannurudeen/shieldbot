import { useEffect, useRef } from "react";
import Badge from "./Badge";
import CodeBlock from "./CodeBlock";
import Section from "./Section";
import { loadRecentRecords, short, useFeed } from "../registryFeed";
import type { RegistryRecord } from "../registryFeed";
import { registryChip } from "../registryVerdict";
import SourceTime from "./SourceTime";

const API = "https://api.shieldbotsecurity.online";
const VIRTUAL = "0xc6911796042b15d7fa4f6cde69e245ddcd3d9c31";
const submissionUrl =
  "https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/SUBMISSION.md";
const judgeGuideUrl =
  "https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api";

interface Contract {
  name: string;
  address: string;
  chain: string;
  chainId: number;
  deployed: string;
  note?: string;
  explorer: string;
  sourcify: string | null;
}

const contracts: Contract[] = [
  {
    name: "ShieldBotVerdictRegistry",
    address: "0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
    chain: "Robinhood Chain",
    chainId: 4663,
    deployed: "27 September 2026",
    explorer: "https://robin.etherscan.io/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
    sourcify: "https://sourcify.dev/server/v2/contract/4663/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
  },
  {
    name: "ShieldBotVerdictGuard",
    address: "0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
    chain: "Robinhood Chain",
    chainId: 4663,
    deployed: "27 September 2026",
    explorer: "https://robin.etherscan.io/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
    sourcify: "https://sourcify.dev/server/v2/contract/4663/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
  },
  {
    name: "ShieldBotGuardedTransfer",
    address: "0x336254bA85406D9af39357101b688E2B757751b3",
    chain: "Robinhood Chain",
    chainId: 4663,
    deployed: "27 September 2026",
    note: "Asks the guard, then moves approved USDG. Its subject is VIRTUAL; no live guarded USDG payment is claimed.",
    explorer: "https://robin.etherscan.io/address/0x336254bA85406D9af39357101b688E2B757751b3",
    sourcify: "https://sourcify.dev/server/v2/contract/4663/0x336254bA85406D9af39357101b688E2B757751b3",
  },
  {
    name: "ShieldBotVerdictRegistry",
    address: "0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
    chain: "BOT Chain",
    chainId: 677,
    deployed: "26 October 2026",
    explorer: "https://scan.botchain.ai/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
    sourcify: null,
  },
  {
    name: "ShieldBotVerdictGuard",
    address: "0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
    chain: "BOT Chain",
    chainId: 677,
    deployed: "29 October 2026",
    explorer: "https://scan.botchain.ai/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
    sourcify: null,
  },
  {
    name: "ShieldBotGuardedTransfer",
    address: "0x336254bA85406D9af39357101b688E2B757751b3",
    chain: "BOT Chain",
    chainId: 677,
    deployed: "29 October 2026",
    explorer: "https://scan.botchain.ai/address/0x336254bA85406D9af39357101b688E2B757751b3",
    sourcify: null,
  },
];

const guardCall = `interface IShieldBotVerdictGuard {
    function check(address subject, uint64 maxAge)
        external view returns (bool allowed, uint8 reason);
    function requireAllowed(address subject, uint64 maxAge)
        external view;
}

address constant GUARD = 0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e;
address constant VIRTUAL = ${VIRTUAL};

IShieldBotVerdictGuard(GUARD).requireAllowed(token, 900);

// Recorded on Robinhood Chain, 27 September 2026
guard.check(VIRTUAL, 900)  // allowed=True, reason=0

// Derived, not a recorded call
guard.check(0x3435…26dd, 900)  // allowed=False, reason=4 HONEYPOT`;

const integrations = [
  {
    name: "REST API",
    href: `${API}/docs`,
  },
  {
    name: "TypeScript and Python SDKs",
    href: "https://github.com/Ridwannurudeen/shieldbot/tree/main/sdk",
  },
  {
    name: "MCP server",
    href: "https://github.com/Ridwannurudeen/shieldbot/tree/main/mcp_server",
  },
];

interface Row {
  subject: string;
  record: RegistryRecord | null | undefined;
}

function RecentRecords() {
  const {
    recent,
    launches,
    records,
    recentFetchedAt,
    launchesFetchedAt,
  } = useFeed();
  const table = useRef<HTMLDivElement>(null);
  const fallback = recent === "fallback";

  useEffect(() => {
    if (!fallback) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (!entries.some((entry) => entry.isIntersecting)) return;
        observer.disconnect();
        loadRecentRecords();
      },
      { rootMargin: "800px 0px" },
    );
    if (table.current) observer.observe(table.current);
    return () => observer.disconnect();
  }, [fallback]);

  const rows: Row[] | null | undefined = Array.isArray(recent)
    ? recent.map((record) => ({ subject: record.subject, record }))
    : fallback
      ? launches === undefined
        ? undefined
        : launches === null
          ? null
          : launches.map((launch) => ({
              subject: launch.token_address,
              record: records[launch.token_address],
            }))
      : recent;
  const sourceUrl = fallback
    ? `${API}/api/launches/4663?outcome=blocked&limit=3`
    : `${API}/api/verdicts/recent?chain_id=4663&limit=3`;
  const heading = fallback
    ? "Records of the newest launches ShieldBot blocked"
    : "Recent registry records";

  return (
    <div ref={table}>
      <div className="mb-4 flex flex-wrap items-baseline justify-between gap-3">
        <h3 id="registry-records-heading" className="text-lg font-medium text-ink">
          {heading}
        </h3>
        <SourceTime
          href={sourceUrl}
          at={fallback ? launchesFetchedAt : recentFetchedAt}
        />
      </div>
      {rows === undefined ? (
        <p role="status" className="border-y border-hairline py-5 text-sm text-secondary">
          Loading registry records
        </p>
      ) : rows === null ? (
        <p role="status" className="border-y border-hairline py-5 text-sm text-secondary">
          Unavailable
        </p>
      ) : rows.length === 0 ? (
        <p className="border-y border-hairline py-5 text-sm text-secondary">
          No record has been published yet
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table
            aria-labelledby="registry-records-heading"
            className="w-full table-fixed text-left text-xs sm:text-sm"
          >
            <colgroup>
              <col className="w-[27%]" />
              <col className="w-[20%]" />
              <col className="w-[18%]" />
              <col className="w-[16%]" />
              <col className="w-[19%]" />
            </colgroup>
            <thead>
              <tr className="border-y border-hairline text-[11px] uppercase tracking-wide text-secondary">
                <th scope="col" className="py-3 pr-2 font-medium">Token</th>
                <th scope="col" className="px-1 py-3 font-medium sm:px-2">Verdict</th>
                <th scope="col" className="px-1 py-3 font-medium sm:px-2">Status</th>
                <th scope="col" className="px-1 py-3 font-medium sm:px-2">Block</th>
                <th scope="col" className="py-3 pl-1 font-medium sm:pl-2">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ subject, record }) => {
                const verdict = record
                  ? registryChip(record.verdict, record.verdict_code)
                  : null;
                return (
                  <tr key={subject} className="border-b border-hairline align-top">
                    <th scope="row" className="py-3 pr-2 text-left font-mono font-normal">
                      <a
                        href={`${API}/api/verdict/4663/${subject}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-ink underline decoration-hairline-strong underline-offset-4"
                        aria-label={`Registry record for ${subject}`}
                      >
                        {short(subject)}
                      </a>
                    </th>
                    <td className="break-words px-1 py-3 sm:px-2">
                      {verdict ? (
                        <Badge verdict={verdict.verdict}>{verdict.label}</Badge>
                      ) : record === undefined ? (
                        "Loading"
                      ) : (
                        "Unavailable"
                      )}
                    </td>
                    <td className="break-words px-1 py-3 text-secondary sm:px-2">
                      {record?.onchain_status ?? "Unavailable"}
                    </td>
                    <td className="break-words px-1 py-3 font-mono text-secondary sm:px-2">
                      {record?.observed_block ?? "Unavailable"}
                    </td>
                    <td className="break-words py-3 pl-1 font-mono text-secondary sm:pl-2">
                      <span className="block">
                        {record?.evidence_hash ? short(record.evidence_hash) : "Unavailable"}
                      </span>
                      {record?.tx_hash ? (
                        <a
                          href={`https://robin.etherscan.io/tx/${record.tx_hash}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex min-h-11 items-center whitespace-nowrap text-ink underline decoration-hairline-strong underline-offset-4 hover:text-accent"
                        >
                          tx {short(record.tx_hash)}
                        </a>
                      ) : (
                        <span className="block">tx unavailable</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ContractLinks({
  contract,
}: {
  contract: Contract;
}) {
  return (
    <div className="flex flex-nowrap items-center gap-3 text-xs">
      <a
        href={contract.explorer}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex min-h-11 shrink-0 items-center whitespace-nowrap text-ink underline decoration-hairline-strong underline-offset-4 hover:text-accent"
      >
        {contract.chainId === 677 ? "Source verified on the explorer" : "Explorer"}
      </a>
      {contract.sourcify ? (
        <a
          href={contract.sourcify}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex min-h-11 shrink-0 items-center whitespace-nowrap text-ink underline decoration-hairline-strong underline-offset-4 hover:text-accent"
        >
          Sourcify
        </a>
      ) : (
        <span className="shrink-0 whitespace-nowrap text-secondary">
          No Sourcify on 677
        </span>
      )}
    </div>
  );
}

export default function Registry() {
  return (
    <Section id="registry" title="Registry">
      <div className="space-y-14">
        <RecentRecords />

        <div>
          <h3
            id="deployed-contracts-heading"
            className="mb-4 text-lg font-medium text-ink"
          >
            Deployed contracts
          </h3>
          <div className="sm:hidden">
            <ul className="divide-y divide-hairline border-y border-hairline">
              {contracts.map((contract) => (
                <li
                  key={`${contract.chainId}-${contract.name}`}
                  className="space-y-1 py-4"
                >
                  <h4 className="text-sm font-medium text-ink">{contract.name}</h4>
                  {contract.note && (
                    <p className="text-xs leading-5 text-secondary">
                      {contract.note}
                    </p>
                  )}
                  <p className="break-all font-mono text-xs text-ink">
                    {contract.address}
                  </p>
                  <p className="whitespace-nowrap text-xs text-secondary">
                    {contract.chain} ({contract.chainId}) · {contract.deployed}
                  </p>
                  <ContractLinks contract={contract} />
                </li>
              ))}
            </ul>
          </div>
          <div className="hidden overflow-x-auto sm:block">
            <table
              aria-labelledby="deployed-contracts-heading"
              className="w-full min-w-[900px] table-fixed text-left text-xs sm:text-sm"
            >
              <colgroup>
                <col className="w-[22%]" />
                <col className="w-[29%]" />
                <col className="w-[16%]" />
                <col className="w-[13%]" />
                <col className="w-[20%]" />
              </colgroup>
              <thead>
                <tr className="border-y border-hairline text-[11px] uppercase tracking-wide text-secondary">
                  <th scope="col" className="py-3 pr-2 font-medium">Contract</th>
                  <th scope="col" className="px-1 py-3 font-medium sm:px-2">Address</th>
                  <th scope="col" className="px-1 py-3 font-medium sm:px-2">Chain</th>
                  <th scope="col" className="px-1 py-3 font-medium sm:px-2">Deployed</th>
                  <th scope="col" className="py-3 pl-1 font-medium sm:pl-2">Links</th>
                </tr>
              </thead>
              <tbody>
                {contracts.map((contract) => (
                  <tr
                    key={`${contract.chainId}-${contract.name}`}
                    className="border-b border-hairline align-top"
                  >
                    <th scope="row" className="py-3 pr-2 text-left font-medium text-ink">
                      <span className="block whitespace-nowrap">{contract.name}</span>
                      {contract.note && (
                        <span className="mt-1 block whitespace-normal text-xs font-normal leading-5 text-secondary">
                          {contract.note}
                        </span>
                      )}
                    </th>
                    <td className="break-all px-1 py-3 font-mono text-xs text-ink sm:px-2">
                      {contract.address}
                    </td>
                    <td className="whitespace-nowrap px-1 py-3 text-ink sm:px-2">
                      {contract.chain}
                      <span className="mt-1 block font-mono text-xs text-secondary">
                        {contract.chainId}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-1 py-3 text-secondary sm:px-2">
                      {contract.deployed}
                    </td>
                    <td className="py-3 pl-1 sm:pl-2">
                      <ContractLinks contract={contract} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="grid items-start gap-10 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)] lg:gap-16">
          <div className="min-w-0">
            <h3 className="mb-4 text-lg font-medium text-ink">Guard call</h3>
            <CodeBlock code={guardCall} />
            <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-sm">
              <a
                href={`https://robin.etherscan.io/address/${VIRTUAL}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-ink underline decoration-hairline-strong underline-offset-4 hover:text-accent"
              >
                VIRTUAL
              </a>
              <a
                href={submissionUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-ink underline decoration-hairline-strong underline-offset-4 hover:text-accent"
              >
                Recorded call: docs/SUBMISSION.md
              </a>
            </div>
            <p className="mt-3 text-sm leading-6 text-secondary">
              Permission is not a safety guarantee: the guard accepts MEDIUM risk. Permission lasts only while a subject is actively watched and republished.
            </p>
          </div>
          <ul className="divide-y divide-hairline border-y border-hairline">
            {integrations.map((integration) => (
              <li key={integration.name} className="py-4">
                <a
                  href={integration.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-medium text-ink underline decoration-hairline-strong underline-offset-4 hover:text-accent"
                >
                  {integration.name}
                </a>
              </li>
            ))}
            <li className="py-4">
              <a
                href={judgeGuideUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="font-medium text-ink underline decoration-hairline-strong underline-offset-4 hover:text-accent"
              >
                Verify a verdict without trusting the API
              </a>
              <p className="mt-1 text-sm leading-6 text-secondary">
                A match proves the recorder committed those bytes. It does not prove the scan was right, that an issuer is genuine, or that a token will stay sellable.
              </p>
            </li>
          </ul>
        </div>
      </div>
    </Section>
  );
}
