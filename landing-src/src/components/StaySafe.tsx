import type { ReactNode } from "react";

const linkClass =
  "text-accent underline underline-offset-4 transition-colors duration-150 hover:text-ink";

const rules: ReactNode[] = [
  "Approve the amount you are spending now, not unlimited.",
  "A signature can move funds; treat a Permit or a spender field as an approval.",
  "Open sites from bookmarks, not from links in messages or ads.",
  <>
    Before buying a token, check that it can be sold; run{" "}
    <a href="#telegram" className={linkClass}>
      /token
    </a>{" "}
    first.
  </>,
  "Compare the whole address, not just its ends.",
  "Revoke unused allowances; keep most funds in a wallet that never signs on new sites.",
  "Unknown is not Safe; if a check did not run, wait or walk away.",
];

// Seven one-line rules; the depth is on the Safety guide page (public/safety.html).
export default function StaySafe() {
  return (
    <section
      id="stay-safe"
      aria-labelledby="stay-safe-title"
      className="border-t border-hairline bg-ground-alt py-16 md:py-24"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6 grid grid-cols-1 items-start gap-10 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:gap-16">
        <div className="min-w-0">
          <h2 id="stay-safe-title" className="text-h2-sm md:text-h2 text-ink">
            Stay safe
          </h2>
          <p className="mt-4 text-[17px] md:text-lg leading-relaxed">
            <a href="/safety.html" className={linkClass}>
              Read the Safety guide
            </a>
          </p>
        </div>
        <ol className="min-w-0 border-t border-hairline-strong">
          {rules.map((rule, i) => (
            <li
              key={i}
              className="grid grid-cols-[32px_minmax(0,1fr)] items-baseline gap-x-3 border-b border-hairline-strong py-4 sm:grid-cols-[44px_minmax(0,1fr)]"
            >
              <span className="font-mono text-xs text-secondary">
                {String(i + 1).padStart(2, "0")}
              </span>
              <span className="text-base leading-6 text-ink">{rule}</span>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
