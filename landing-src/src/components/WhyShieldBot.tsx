const chromeStoreUrl =
  "https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk";

const linkClass =
  "text-accent underline underline-offset-4 transition-colors duration-150 hover:text-ink";

// What ShieldBot does and for whom, right under the hero: one paragraph, then a line for a first visit and one for a
// return visit.
export default function WhyShieldBot() {
  return (
    <section
      id="why"
      aria-labelledby="why-title"
      className="border-b border-hairline bg-ground py-14 md:py-20"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6 grid grid-cols-1 items-end gap-10 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] lg:gap-16">
        <div className="min-w-0">
          <p className="font-mono text-xs uppercase tracking-[0.08em] text-secondary">
            Overview
          </p>
          <h2 id="why-title" className="mt-3 text-h2-sm md:text-h2 text-ink">
            Why ShieldBot
          </h2>
          <p className="mt-4 max-w-[36em] text-[17px] md:text-lg leading-relaxed text-secondary">
            ShieldBot checks a transaction or signature before your wallet signs
            it, and says what it checked. The usual drain is a signature the
            owner gave: an unlimited approval, a Permit, a blind signature on a
            fake site, or a token you cannot sell. The goal: a verdict you can
            read before signing, and an honest Unknown when a check cannot run.
          </p>
        </div>
        <dl className="min-w-0 border-t border-hairline-strong">
          <div className="grid gap-1 border-b border-hairline-strong py-4">
            <dt className="font-mono text-xs uppercase tracking-[0.08em] text-secondary">
              First time here:
            </dt>
            <dd className="text-base leading-relaxed text-ink">
              <a
                href={chromeStoreUrl}
                target="_blank"
                rel="noopener noreferrer"
                className={linkClass}
              >
                add the extension
              </a>{" "}
              and sign as usual.
            </dd>
          </div>
          <div className="grid gap-1 border-b border-hairline-strong py-4">
            <dt className="font-mono text-xs uppercase tracking-[0.08em] text-secondary">
              Been here before:
            </dt>
            <dd className="text-base leading-relaxed text-ink">
              <a href="#telegram" className={linkClass}>
                check a token in Telegram
              </a>
              ,{" "}
              <a href="#on-chain" className={linkClass}>
                read the registry
              </a>
              , or{" "}
              <a href="/safety.html" className={linkClass}>
                the Safety guide
              </a>
              .
            </dd>
          </div>
        </dl>
      </div>
    </section>
  );
}
