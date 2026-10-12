import CodeBlock from "./CodeBlock";
import Icon from "./Icon";
import SectionHeader from "./SectionHeader";

const guardCall = `interface IShieldBotVerdictGuard {
    function check(address subject, uint64 maxAge)
        external view returns (bool allowed, uint8 reason);
    function requireAllowed(address subject, uint64 maxAge)
        external view;
}

// ShieldBotVerdictGuard on Robinhood Chain (4663)
address constant GUARD = 0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e;

// Reverts with NotAllowed(subject, reason) unless the token's
// newest record is LOW or MEDIUM, published in the last 900 s.
IShieldBotVerdictGuard(GUARD).requireAllowed(token, 900);`;

const features: { title: string; desc: string; link?: { label: string; href: string } }[] = [
  {
    title: "REST API",
    desc: "POST /api/firewall runs the full check. POST /api/scan is a quick contract check with no sell simulation, so a token it recognises reads Unknown there, never SAFE.",
    link: { label: "API docs", href: "https://api.shieldbotsecurity.online/docs" },
  },
  {
    title: "Agent firewall",
    desc: "POST /api/agent/firewall returns ALLOW, WARN or BLOCK from a spend-limit policy. Incomplete coverage, or a value with no USD price, turns ALLOW into WARN.",
  },
  {
    title: "TypeScript and Python SDKs",
    desc: "TypeScript and Python, source in the GitHub repository, not yet on npm or PyPI. They keep every verdict's coverage; the caller enforces the decision.",
    link: { label: "GitHub", href: "https://github.com/Ridwannurudeen/shieldbot/tree/main/sdk" },
  },
  {
    title: "Wallet Health",
    desc: "GET /api/rescue/{wallet} scans a wallet's ERC-20 token approvals and returns an unsigned revoke transaction for each risky one.",
  },
  {
    title: "MCP server",
    desc: "Model Context Protocol server for AI agents over SSE, with 9 tools (one lists Robinhood Chain launches), a threat feed resource, an agent health resource and 2 analysis prompts. The approval risk and threat graph tools and the wallet guardian resource are stubs that return Unknown.",
  },
];

export default function AgentSecurity() {
  return (
    <section id="agent-security" aria-labelledby="agent-security-title" className="border-t border-hairline bg-ground-alt py-16 md:py-24">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <SectionHeader
          id="agent-security-title"
          eyebrow="For builders and agents"
          title="The same verdict, on-chain or over an API."
          lead="Every answer carries its status, coverage and the reason a check did not run, so a caller can refuse to act on anything Unknown."
        />

        <div className="mt-12 grid grid-cols-1 items-start gap-10 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:gap-12">
          <div className="min-w-0">
            <p className="font-mono text-xs text-secondary">01 · Registry and guard</p>
            <h3 className="mt-3 text-2xl font-medium tracking-[-0.015em] text-ink">Ask the guard in the transaction that moves funds.</h3>
            <p className="mt-3 text-[15px] leading-relaxed text-secondary">
              A contract calls requireAllowed before it acts. The guard reads the registry and reverts unless the token's newest record is LOW or MEDIUM and was published within the maxAge the caller sets. No API key and no off-chain call.
            </p>
            <div className="mt-4 flex flex-col items-start">
              <a
                href="https://robin.etherscan.io/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex min-h-[44px] items-center gap-1.5 text-sm font-medium text-accent underline underline-offset-4 transition-colors duration-150 hover:text-accent-hover"
              >
                The guard on the explorer
                <Icon name="external" size={16} />
              </a>
              <a
                href="https://github.com/Ridwannurudeen/shieldbot/blob/main/contracts/base/GUARDED_TRANSFER.md"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex min-h-[44px] items-center gap-1.5 text-sm font-medium text-accent underline underline-offset-4 transition-colors duration-150 hover:text-accent-hover"
              >
                The guarded transfer, a worked consumer
                <Icon name="external" size={16} />
              </a>
            </div>
          </div>
          <div className="min-w-0">
            <CodeBlock label="Solidity, ShieldBotVerdictGuard" code={guardCall} />
          </div>
        </div>

        <p className="mt-16 font-mono text-xs text-secondary">02 · API, SDKs and MCP</p>
        <ul className="mt-4 grid grid-cols-1 gap-px overflow-hidden rounded-[14px] border border-hairline bg-hairline md:grid-cols-2 lg:grid-cols-3">
          {features.map((feature) => (
            <li key={feature.title} className="flex min-w-0 flex-col bg-ground p-6">
              <h3 className="text-lg font-medium tracking-[-0.01em] text-ink">{feature.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-secondary">{feature.desc}</p>
              {feature.link && (
                <a
                  className="mt-auto inline-flex min-h-[44px] items-center gap-1.5 self-start pt-2 text-sm font-medium text-accent underline underline-offset-4 transition-colors duration-150 hover:text-accent-hover"
                  href={feature.link.href}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {feature.link.label}
                  <Icon name="external" size={16} />
                </a>
              )}
            </li>
          ))}
        </ul>

      </div>
    </section>
  );
}
