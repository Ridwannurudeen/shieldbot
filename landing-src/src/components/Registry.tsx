import { useEffect, useRef } from "react";
import Badge from "./Badge";
import CodeBlock from "./CodeBlock";
import Section from "./Section";
import { loadRecentRecords, short, useFeed } from "../registryFeed";
import type { RegistryRecord } from "../registryFeed";
import { registryChip } from "../registryVerdict";

const API = "https://api.shieldbotsecurity.online";

const contracts = [
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
address constant VIRTUAL = 0xc6911796042b15d7fa4f6cde69e245ddcd3d9c31;

IShieldBotVerdictGuard(GUARD).requireAllowed(token, 900);

// Recorded, 27 September 2026
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
      className="font-mono text-xs text-secondary underline decoration-hairline-strong underline-offset-4 hover:text-ink"
      aria-label={`${href.slice(API.length)} fetched at ${time} UTC`}
    >
      {time} UTC
    </a>
  );
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

  return (
    <div ref={table}>
      <div className="mb-4 flex flex-wrap items-baseline justify-between gap-3">
        <h3 className="text-lg font-medium text-ink">Recent registry records</h3>
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
          <table className="w-full table-fixed text-left text-xs sm:text-sm">
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
                      {record?.evidence_hash ? short(record.evidence_hash) : "Unavailable"}
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

export default function Registry() {
  return (
    <Section id="registry" title="Registry">
      <div className="space-y-14">
        <RecentRecords />

        <div>
          <h3 className="mb-4 text-lg font-medium text-ink">Deployed contracts</h3>
          <div className="overflow-x-auto">
            <table className="w-full table-fixed text-left text-xs sm:text-sm">
              <colgroup>
                <col className="w-[27%] sm:w-[25%]" />
                <col className="w-[30%] sm:w-[31%]" />
                <col className="w-[17%] sm:w-[16%]" />
                <col className="w-[14%] sm:w-[14%]" />
                <col className="w-[12%] sm:w-[14%]" />
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
                    <th scope="row" className="py-3 pr-2 text-left font-medium text-ink [overflow-wrap:anywhere]">
                      {contract.name}
                    </th>
                    <td className="break-all px-1 py-3 font-mono text-xs text-ink sm:px-2">
                      {contract.address}
                    </td>
                    <td className="break-words px-1 py-3 text-ink sm:px-2">
                      {contract.chain}
                      <span className="mt-1 block font-mono text-xs text-secondary">
                        {contract.chainId}
                      </span>
                    </td>
                    <td className="break-words px-1 py-3 text-secondary sm:px-2">
                      {contract.deployed}
                    </td>
                    <td className="py-3 pl-1 sm:pl-2">
                      <ul className="grid gap-2">
                        <li>
                          <a
                            href={contract.explorer}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex min-h-11 items-center text-ink underline decoration-hairline-strong underline-offset-4 hover:text-accent"
                          >
                            Explorer
                          </a>
                        </li>
                        <li>
                          {contract.sourcify ? (
                            <a
                              href={contract.sourcify}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex min-h-11 items-center text-ink underline decoration-hairline-strong underline-offset-4 hover:text-accent"
                            >
                              Sourcify
                            </a>
                          ) : (
                            <span className="text-secondary">Not supported</span>
                          )}
                        </li>
                      </ul>
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
            <p className="mt-3 text-sm leading-6 text-secondary">
              Permission does not guarantee safety. The guard accepts MEDIUM risk.
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
          </ul>
        </div>
      </div>
    </Section>
  );
}
