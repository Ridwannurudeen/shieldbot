import CheckRow from "./CheckRow";
import Section from "./Section";
import { recordedReply } from "../recordedReplies";

const chromeStoreUrl =
  "https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk";
const telegramUrl = "https://t.me/shieldbot_bnb_bot";
const apiUrl = "https://api.shieldbotsecurity.online/docs";
const mcpUrl = "https://github.com/Ridwannurudeen/shieldbot/tree/main/mcp_server";

const commands = [
  ["/token <address>", "Sellability checks and Unknown when a check cannot run."],
  ["/scan <address>", "A contract risk report."],
  ["/rescue <wallet>", "Lists risky ERC-20 allowances. It never revokes them."],
  ["/report <address> <reason>", "Reports are counted, not reviewed."],
  ["/launchalerts", "Robinhood Chain blocked launches and token impostors."],
] as const;

const surfaces = [
  {
    name: "Chrome extension",
    href: chromeStoreUrl,
    description: "Checks transactions and signatures before your wallet signs.",
  },
  {
    name: "Telegram bot",
    href: telegramUrl,
    description: "Token checks, contract scans, ERC-20 allowances, reports and launch alerts.",
  },
  {
    name: "REST API",
    href: apiUrl,
    description: "Contract scans for applications and agents.",
  },
  {
    name: "MCP server",
    href: mcpUrl,
    description: "Model Context Protocol server for AI agents, over SSE.",
  },
];

export default function HowItWorks() {
  return (
    <Section id="how" title="How it works">
      <ol className="grid gap-8 border-y border-hairline py-6 md:grid-cols-3 md:gap-10 md:py-8">
        <li className="min-w-0">
          <h3 className="text-lg font-medium text-ink">Intercept</h3>
          <p className="mt-2 text-sm leading-6 text-secondary">
            Decodes a transaction before your wallet signs it.
          </p>
        </li>
        <li className="min-w-0">
          <h3 className="text-lg font-medium text-ink">Check</h3>
          <p className="mt-2 text-sm leading-6 text-secondary">
            Runs each check the chain supports.
          </p>
        </li>
        <li className="min-w-0">
          <h3 className="text-lg font-medium text-ink">Report</h3>
          <p className="mt-2 text-sm leading-6 text-secondary">
            Shows the verdict and reason, or Unknown when a check cannot run.
          </p>
        </li>
      </ol>

      <div className="mt-10">
        <h3 className="mb-4 text-sm font-medium text-ink">
          Recorded checks, 26 Sep 2026
        </h3>
        <CheckRow coverage={recordedReply.coverage} />
      </div>

      <div className="mt-10 grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] lg:gap-12">
        <dl className="divide-y divide-hairline border-y border-hairline">
          {surfaces.map((surface) => (
            <div
              key={surface.name}
              className="grid gap-1 py-4 sm:grid-cols-[minmax(130px,0.7fr)_minmax(0,1.3fr)] sm:gap-6"
            >
              <dt>
                <a
                  href={surface.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-medium text-ink underline decoration-hairline-strong underline-offset-4 hover:text-accent"
                >
                  {surface.name}
                </a>
              </dt>
              <dd className="text-sm leading-6 text-secondary">
                {surface.description}
              </dd>
            </div>
          ))}
        </dl>

        <ul
          aria-label="Telegram bot commands"
          className="divide-y divide-hairline border-y border-hairline"
        >
          {commands.map(([command, description]) => (
            <li
              key={command}
              className="grid gap-1 py-3 sm:grid-cols-[minmax(170px,0.85fr)_minmax(0,1.15fr)] sm:gap-5"
            >
              <code className="whitespace-nowrap font-mono text-xs leading-5 text-ink">
                {command}
              </code>
              <span className="text-sm leading-5 text-secondary">
                {description}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </Section>
  );
}
