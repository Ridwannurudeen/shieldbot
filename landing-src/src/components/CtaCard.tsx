import Button from "./Button";
import Icon from "./Icon";

const chromeStoreUrl =
  "https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk";
const judgeGuideUrl =
  "https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api";

// The two paths, at equal weight in one frame: the extension for a person about to sign, the registry and the API
// for a contract or a bot about to move funds.
export default function CtaCard() {
  return (
    <section aria-label="Get started" className="bg-ground py-16 md:py-24">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="grid overflow-hidden rounded-lg border border-hairline-strong lg:grid-cols-2">
          <div className="flex min-w-0 flex-col border-t-2 border-accent p-6 sm:p-10 lg:p-12">
            <p className="font-mono text-xs uppercase tracking-[0.08em] text-secondary">01 · For wallets</p>
            <h2 className="mt-3 max-w-[10em] text-h2-sm md:text-h2 text-ink">Check before you sign.</h2>
            <p className="mt-4 max-w-[30em] text-[17px] leading-relaxed text-secondary">
              The extension checks each request before your wallet opens, and says when a check could not run.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-x-5 gap-y-3">
              <Button href={chromeStoreUrl}>Add to Chrome</Button>
              <span className="text-sm text-secondary">Free, no account.</span>
            </div>
          </div>

          <div className="flex min-w-0 flex-col border-t-2 border-ink p-6 sm:p-10 lg:border-l lg:border-l-hairline-strong lg:p-12">
            <p className="font-mono text-xs uppercase tracking-[0.08em] text-secondary">02 · For contracts and agents</p>
            <h2 className="mt-3 max-w-[10em] text-h2-sm md:text-h2 text-ink">Ask the registry before funds move.</h2>
            <p className="mt-4 max-w-[30em] text-[17px] leading-relaxed text-secondary">
              A contract asks the guard on Robinhood Chain in the same transaction; a bot asks the API before it signs.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Button href={judgeGuideUrl}>
                Read the judge guide
                <Icon name="external" size={16} />
              </Button>
              <Button href="https://api.shieldbotsecurity.online/docs" variant="secondary">
                API docs
                <Icon name="external" size={16} />
              </Button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
