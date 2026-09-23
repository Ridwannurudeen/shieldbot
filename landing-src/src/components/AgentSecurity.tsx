import { motion } from "framer-motion";

const agentFeatures = [
  {
    version: "V3",
    title: "Agent Transaction Firewall",
    desc: "Risk checks for autonomous agents before they send a transaction. The policy engine applies risk thresholds and per transaction and daily spend limits, and returns ALLOW, WARN or BLOCK. Incomplete data never returns ALLOW.",
    code: `const verdict = await shield.check({
  from: '0xAgent', to: '0xTarget',
  data: '0x...', value: '0', chainId: 56,
});
if (verdict.blocked) stop();`,
  },
  {
    version: "V3.1",
    title: "MCP Server",
    desc: "Model Context Protocol server exposing 9 security tools, 3 threat resources and 2 analysis prompts over SSE, including Robinhood Chain launch data for AI agents.",
    code: null,
  },
  {
    version: "V3.2",
    title: "Portfolio Guardian",
    desc: "Continuous wallet health monitoring with 5-component scoring: dangerous approvals, flagged token exposure, approval staleness, concentration risk, and deployer risk — from 0 to 100.",
    code: null,
  },
  {
    version: "V3",
    title: "TypeScript & Python SDK",
    desc: "SDKs for both ecosystems in the GitHub repository (not yet published to npm or PyPI). Scan contracts, check agent transactions, query reputation scores and scan for prompt injection. The caller enforces the returned decision.",
    code: `import { ShieldBot } from '@shieldbot/sdk';
const shield = new ShieldBot({ apiKey: 'sb_...' });
const scan = await shield.scan('0x...', { chainId: 56 });`,
  },
  {
    version: "V3.3",
    title: "Reputation Oracle",
    desc: "Composite trust scoring combining on-chain activity, firewall verdict history, ERC-8004 registration status, and cross-protocol signals into a single 0\u2013100 reputation score per agent.",
    code: null,
  },
  {
    version: "V3.5",
    title: "Threat Intelligence Graph",
    desc: "Cross-chain graph connecting deployers, funders, and flagged contracts via BFS traversal. Union-Find clustering detects coordinated scam campaigns spanning multiple chains.",
    code: null,
  },
];

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.1 } },
};

const item = {
  hidden: { y: 30, opacity: 0 },
  show: { y: 0, opacity: 1, transition: { duration: 0.5 } },
};

export default function AgentSecurity() {
  return (
    <section id="agent-security" className="py-24 bg-white/[0.02] border-y border-white/5">
      <div className="max-w-6xl mx-auto px-6">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-4 tracking-tight">
          Agent Security Suite
        </h2>
        <p className="text-gray-400 text-center max-w-lg mx-auto mb-14">
          Purpose-built infrastructure for autonomous AI agents operating on-chain.
        </p>

        <motion.div
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, amount: 0.1 }}
          className="grid md:grid-cols-2 lg:grid-cols-3 gap-6"
        >
          {agentFeatures.map((f) => (
            <motion.div
              key={f.title}
              variants={item}
              className="min-w-0 bg-white/5 backdrop-blur-md border border-neon/15 rounded-2xl p-7 group
                         hover:border-neon/40 hover:-translate-y-1 hover:shadow-neon transition-all duration-300"
            >
              <div className="flex items-start justify-between mb-4">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-md tracking-widest bg-neon/10 border border-neon/30 text-neon">
                  {f.version}
                </span>
              </div>
              <h3 className="text-lg font-bold mb-2">{f.title}</h3>
              <p className="text-gray-400 text-sm leading-relaxed mb-3">{f.desc}</p>
              {f.code && (
                <pre className="bg-black/40 border border-white/10 rounded-lg p-3 text-xs text-emerald-400 font-mono overflow-x-auto whitespace-pre">
                  {f.code}
                </pre>
              )}
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
