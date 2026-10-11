import Button from "./Button";
import HeroRecord from "./HeroRecord";

export default function Hero() {
  return (
    <section className="relative border-b border-hairline bg-ground-alt pt-28 pb-14 md:pt-32 md:pb-20">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <p className="font-mono text-xs uppercase tracking-[0.08em] text-secondary">
          Transaction firewall for wallets, contracts and agents
        </p>
        <div className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] lg:items-end lg:gap-12">
          <h1 className="max-w-[13em] text-[36px] leading-[1.12] tracking-[-0.028em] font-medium text-ink md:text-[48px] md:tracking-[-0.032em] lg:text-[56px] lg:leading-[1.06]">
            Know before you sign. And know when we&nbsp;don't.
          </h1>
          <div className="min-w-0">
            <p className="text-base leading-[26px] text-secondary md:text-lg md:leading-7">
              ShieldBot checks a transaction before your wallet signs it and
              says what it found. When a check cannot run it says Unknown, never
              Safe. Its published Robinhood Chain verdicts live in a public
              registry any contract can read.
            </p>
            <div className="mt-6 flex flex-col gap-3 sm:flex-row">
              <Button
                href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk"
                className="sm:min-w-[180px]"
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
              </Button>
              <Button
                variant="secondary"
                href="#on-chain"
                className="sm:min-w-[180px]"
              >
                Read the registry
              </Button>
            </div>
            <p className="mt-4 text-sm text-secondary">
              Free, no account. ShieldBot{" "}
              <span className="font-medium text-ink">never</span> asks for your
              private keys or seed phrase.
            </p>
          </div>
        </div>
        <div className="mt-12 md:mt-14">
          <HeroRecord />
        </div>
      </div>
    </section>
  );
}
