import Button from "./Button";
import Icon from "./Icon";

// The five commands a visitor needs first (bot.py set_my_commands). /threats, /campaign, /chain, /help and /start
// work but are left out; /history is registered and answers that history is not available, so it is never listed.
const commands = [
  {
    command: "/token <address>",
    desc: "Can this token be sold? Honeypot, taxes, ownership and liquidity checks. Unknown when a check cannot run. Telegram /scan and /token results can be recorded in on-chain registries on Robinhood Chain and BOT Chain.",
  },
  {
    command: "/scan <address>",
    desc: "Contract risk report: scam database matches, verification, code and market checks. Results on Robinhood Chain and BOT Chain can be recorded in the on-chain registries.",
  },
  {
    command: "/rescue <wallet>",
    desc: "Counts the wallet's ERC-20 allowances and lists the risky ones. It never revokes; you do that in your wallet or at revoke.cash. NFT approvals and signed permits are not scanned.",
  },
  {
    command: "/report <address> <reason>",
    desc: "Community scam report. Three independent reports mark an address as community-reported in scans. Reports are counted, not reviewed.",
  },
  {
    command: "/launchalerts",
    desc: "Robinhood Chain only. Alerts this chat to blocked launches and impostors of official tokens. /launchalerts all for every scanned launch, /stopalerts to stop.",
  },
];

export default function Telegram() {
  return (
    <section
      id="telegram"
      aria-labelledby="telegram-title"
      className="border-t border-hairline bg-ground py-16 md:py-24"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6 grid grid-cols-1 items-start gap-10 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:gap-16">
        <div className="min-w-0">
          <p className="font-mono text-xs uppercase tracking-[0.08em] text-secondary">
            Telegram
          </p>
          <h2
            id="telegram-title"
            className="mt-3 text-h2-sm md:text-h2 text-ink"
          >
            Check an address in Telegram
          </h2>
          <p className="mt-4 max-w-[30em] text-[17px] md:text-lg leading-relaxed text-secondary">
            Paste a contract or token address and the bot asks which chain it is
            on, then runs ShieldBot's contract and token checks. Free, no
            account. The bot never asks for keys and never sends a transaction
            for you.
          </p>
          <div className="mt-8">
            <Button href="https://t.me/shieldbot_bnb_bot">
              Open in Telegram
              <Icon name="external" size={16} />
            </Button>
          </div>
          <p className="mt-3 max-w-[30em] text-sm leading-relaxed text-secondary">
            <span className="font-mono text-ink">@shieldbot_bnb_bot</span>. A
            chain prefix such as <code className="font-mono text-ink">rh:</code>{" "}
            or <code className="font-mono text-ink">eth:</code> skips the chain
            question.
          </p>
        </div>
        <ul className="min-w-0 border-t border-hairline-strong">
          {commands.map(({ command, desc }) => (
            <li
              key={command}
              className="grid gap-1.5 border-b border-hairline-strong py-4 sm:grid-cols-[minmax(0,15rem)_minmax(0,1fr)] sm:gap-6"
            >
              <code className="font-mono text-sm leading-6 text-ink [overflow-wrap:anywhere]">
                {command}
              </code>
              <p className="text-[15px] leading-relaxed text-secondary">
                {desc}
              </p>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
