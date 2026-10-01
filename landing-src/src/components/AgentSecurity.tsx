import CodeBlock from "./CodeBlock";
import FeatureCard from "./FeatureCard";
import SectionHeader from "./SectionHeader";

const features: { title: string; desc: string; link?: { label: string; href: string } }[] = [
  {
    title: "REST API",
    desc: "POST /api/firewall checks a transaction and runs the full token check. POST /api/scan is a quick contract check with no sell simulation, so a token reads Unknown there, never SAFE.",
    link: { label: "API docs", href: "https://api.shieldbotsecurity.online/docs" },
  },
  {
    title: "Agent firewall",
    desc: "POST /api/agent/firewall returns ALLOW, WARN or BLOCK from a threshold policy with per-transaction and daily spend limits. Incomplete coverage, or a value with no USD price, turns ALLOW into WARN so the owner approves.",
  },
  {
    title: "MCP server",
    desc: "Model Context Protocol server for AI agents over SSE, with 9 tools (one lists Robinhood Chain launches), a threat feed resource, an agent health resource and 2 analysis prompts. The approval risk and threat graph tools and the wallet guardian resource are stubs that return Unknown.",
  },
  {
    title: "TypeScript and Python SDKs",
    desc: "Source in the GitHub repository, not yet published to npm or PyPI. They keep the coverage metadata of every verdict, and the caller enforces the returned decision.",
    link: { label: "GitHub", href: "https://github.com/Ridwannurudeen/shieldbot/tree/main/sdk" },
  },
  {
    title: "Wallet Health",
    desc: "GET /api/rescue/{wallet} scans a wallet's ERC-20 token approvals and returns an unsigned revoke transaction for each risky one. Revoking stays with the wallet's owner.",
  },
  {
    title: "Campaign graph",
    desc: "A cross-chain graph links deployers and funders to spot coordinated scam campaigns, and a token tied to a known campaign scores higher.",
  },
];

const firewallRequest = `curl -X POST https://api.shieldbotsecurity.online/api/firewall \\
  -H "Content-Type: application/json" \\
  -d '{"from":"0x…","to":"0x…","value":"0x0","data":"0x095ea7b3…","chainId":1}'
# the answer carries classification, risk_score, status, coverage, coverage_reasons,
# danger_signals, evidence_hash and evidence_url`;

export default function AgentSecurity() {
  return (
    <section id="agent-security" aria-labelledby="agent-security-title" className="bg-surface py-14 md:py-[72px] lg:py-24">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <SectionHeader
          id="agent-security-title"
          eyebrow="For builders and agents"
          title="The same verdict, with its coverage, over an API."
          lead="Every answer carries its status, coverage and the reason a check did not run, so a caller can refuse to act on anything Unknown."
        />

        <div className="mt-10 grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
          {features.map((feature) => (
            <FeatureCard key={feature.title} title={feature.title} link={feature.link}>
              {feature.desc}
            </FeatureCard>
          ))}
        </div>

        <div className="mt-10">
          <CodeBlock label="The firewall request the extension sends" code={firewallRequest} />
        </div>
      </div>
    </section>
  );
}
