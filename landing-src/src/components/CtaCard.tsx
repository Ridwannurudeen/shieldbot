import Icon from "./Icon";

const chromeStoreUrl =
  "https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk";
const judgeGuideUrl =
  "https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api";

// The two paths, at equal weight: the extension for a person about to sign, the registry and the API for a
// contract or a bot about to move funds.
export default function CtaCard() {
  return (
    <section aria-label="Get started" className="bg-ground py-16 md:py-24">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 grid gap-6">
        <div className="band grid overflow-hidden rounded-2xl bg-accent text-white lg:grid-cols-[minmax(0,1fr)_440px]">
          <div className="flex min-w-0 flex-col p-8 sm:p-12 lg:p-14">
            <h2 className="max-w-[14em] text-h2-sm md:text-h2 text-white">
              Check before you sign.
            </h2>
            <p className="mt-4 max-w-[30em] text-[17px] leading-relaxed text-white/90">
              Install once. The extension checks each request before your wallet
              opens, and says plainly when a check could not run.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-x-5 gap-y-3">
              <a
                href={chromeStoreUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex h-11 items-center gap-2 rounded-lg bg-white px-5 text-[15px] font-medium text-ink shadow-button transition-colors duration-150 ease-out hover:bg-ground-alt"
              >
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="currentColor"
                  aria-hidden="true"
                >
                  <circle cx="12" cy="12" r="4" />
                  <path
                    d="M12 2a10 10 0 0 1 8.66 5H12a5 5 0 0 0-4.58 3H3.34A10 10 0 0 1 12 2z"
                    opacity=".6"
                  />
                  <path
                    d="M12 22A10 10 0 0 1 3.34 17H7.42A5 5 0 0 0 12 19.92V22z"
                    opacity=".6"
                  />
                  <path
                    d="M22 12a10 10 0 0 1-5.34 8.9l-2.08-3.6A5 5 0 0 0 17 12h5z"
                    opacity=".6"
                  />
                </svg>
                Add to Chrome
              </a>
              <span className="text-sm text-white/90">Free, no account.</span>
            </div>
            <p className="mt-auto hidden pt-10 text-xs sm:block leading-[18px] text-white/90">
              The dialog is a capture of the extension's overlay at unreleased
              commit 2b54a1b, fed the recorded reply of 26 September 2026, chain
              1, BLOCK RECOMMENDED.
            </p>
          </div>
          <div className="relative hidden min-w-0 px-8 pt-10 sm:block lg:px-0 lg:pr-12 lg:pt-12">
            <div className="mx-auto h-[300px] max-w-[380px] overflow-hidden rounded-t-[10px] bg-ground story-fade shadow-[0_20px_40px_rgba(0,0,0,0.18)] lg:h-[340px]">
              <img
                src="/hero-overlay.webp"
                width={490}
                height={1019}
                loading="lazy"
                alt="The ShieldBot extension's warning dialog for a request that approves unlimited USDC spending on Ethereum. The verdict badge reads BLOCK RECOMMENDED — Safety: 0/100. The danger signals include Spender flagged by GoPlus: stealing_attack (SlowMist,BlockSec)."
                className="block w-full h-auto"
              />
            </div>
          </div>
        </div>

        <div className="band grid overflow-hidden rounded-2xl bg-panel text-on-panel lg:grid-cols-[minmax(0,1fr)_440px]">
          <div className="min-w-0 p-8 sm:p-12 lg:p-14">
            <h2 className="max-w-[14em] text-h2-sm md:text-h2 text-on-panel">
              Ask the registry before funds move.
            </h2>
            <p className="mt-4 max-w-[30em] text-[17px] leading-relaxed text-on-panel">
              A contract asks the guard on Robinhood Chain in the same
              transaction. A bot asks the API before it signs. Both get the
              reason when a check did not run.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <a
                href={judgeGuideUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex h-11 items-center gap-2 rounded-lg bg-white px-5 text-[15px] font-medium text-ink shadow-button transition-colors duration-150 ease-out hover:bg-ground-alt"
              >
                Read the judge guide
                <Icon name="external" size={16} />
              </a>
              <a
                href="https://api.shieldbotsecurity.online/docs"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex h-11 items-center gap-2 rounded-lg border border-white/30 px-5 text-[15px] font-medium text-white transition-colors duration-150 ease-out hover:bg-white/10"
              >
                API docs
                <Icon name="external" size={16} />
              </a>
            </div>
          </div>
          <div className="min-w-0 px-8 pb-8 sm:px-12 sm:pb-12 lg:px-0 lg:pr-12 lg:pt-14">
            <div className="rounded-[10px] border border-white/15 bg-white/[0.04] p-5 font-mono text-[13px] leading-6">
              <p className="text-on-panel-2">
                ShieldBotVerdictGuard, Robinhood Chain
              </p>
              <p className="mt-3 text-on-panel [overflow-wrap:anywhere]">
                check(address subject, uint64 maxAge)
              </p>
              <p className="text-on-panel-2">
                returns (bool allowed, uint8 reason)
              </p>
              <p className="mt-3 text-on-panel [overflow-wrap:anywhere]">
                requireAllowed(address subject, uint64 maxAge)
              </p>
              <p className="text-on-panel-2">
                reverts with NotAllowed(subject, reason)
              </p>
              <p className="mt-3 flex flex-wrap gap-x-3 gap-y-1 border-t border-white/15 pt-3 text-accent-on-panel">
                {["0 ALLOWED", "1 NO_RECORD", "2 UNKNOWN", "3 HIGH", "4 HONEYPOT", "5 EXPIRED", "6 FUTURE_TIMESTAMP"].map((code) => (
                  <span key={code} className="whitespace-nowrap">{code}</span>
                ))}
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
