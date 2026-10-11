import Button from "./Button";
import HeroStory from "./HeroStory";
import TryIt from "./TryIt";

export default function Hero() {
  return (
    <section className="relative border-b border-hairline bg-ground-alt pt-28 pb-14 md:pt-32 md:pb-20">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 grid grid-cols-1 items-start gap-12 xl:grid-cols-[minmax(0,1fr)_540px] xl:gap-14">
        <div className="min-w-0">
          <p className="flex items-center gap-4 text-sm font-medium text-accent after:h-px after:flex-1 after:bg-hairline-strong">
            Transaction firewall for wallets, contracts and agents
          </p>
          <h1 className="mt-[18px] max-w-[13em] text-[36px] leading-[1.12] tracking-[-0.028em] font-medium text-ink md:text-[48px] md:tracking-[-0.032em]">
            Know before you sign. And know when we&nbsp;don't.
          </h1>
          <p className="mt-5 max-w-[34em] text-base leading-[26px] text-secondary md:text-lg md:leading-7">
            ShieldBot checks a transaction before your wallet signs it and says
            what it found. When a check cannot run it says Unknown, never Safe.
            Its published Robinhood Chain verdicts live in a public registry any
            contract can read.
          </p>
          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <Button
              href="https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk"
              className="sm:min-w-[200px]"
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
              className="sm:min-w-[200px]"
            >
              Read the registry
            </Button>
          </div>
          <p className="mt-4 text-sm text-secondary">
            Free, no account. ShieldBot{" "}
            <span className="font-medium text-ink">never</span> asks for your
            private keys or seed phrase.
          </p>
          <TryIt />
        </div>
        <HeroStory />
      </div>
    </section>
  );
}
