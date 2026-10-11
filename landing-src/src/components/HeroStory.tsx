import { useState } from "react";

// The hero story: a drawn browser and placeholder dApp page, a cursor that presses Approve, then two
// captures of the real extension overlay (landing-src/scripts/capture-hero-overlay.py): the loading
// dialog, then the BLOCK verdict for the recorded reply in scripts/hero-overlay-response.json. CSS
// keyframes in index.css run it once and hold on the verdict; the final frame is the base style, so
// reduced motion shows it at once. Nothing here talks to the network.
export default function HeroStory() {
  const [run, setRun] = useState(0);

  return (
    <figure className="min-w-0 w-full sm:w-[540px] sm:justify-self-center xl:mt-6 xl:justify-self-end">
      <div
        key={run}
        className="story relative w-full sm:h-[500px] sm:[perspective:1200px]"
      >
        <div className="story-browser relative flex h-full flex-col overflow-hidden rounded-[10px] bg-ground shadow-[0_2px_8px_rgba(99,99,99,0.3)]">
          <div
            className="hidden h-10 flex-none items-center gap-3.5 border-b border-hairline px-3.5 sm:flex"
            aria-hidden="true"
          >
            <span className="flex gap-1.5">
              <i className="h-2.5 w-2.5 rounded-full bg-hairline" />
              <i className="h-2.5 w-2.5 rounded-full bg-hairline" />
              <i className="h-2.5 w-2.5 rounded-full bg-hairline" />
            </span>
            <span className="flex h-6 flex-1 items-center justify-center rounded-full bg-ground-alt text-xs text-secondary">
              dapp.example
            </span>
            <span className="h-4 w-4" />
          </div>
          <div className="relative flex-1 overflow-hidden bg-ground-alt">
            <div
              className="absolute inset-0 hidden px-5 py-[18px] sm:block"
              aria-hidden="true"
            >
              <div className="flex items-center justify-between">
                <span className="h-3.5 w-20 rounded bg-hairline-strong" />
                <span className="flex gap-2.5">
                  <i className="h-2 w-10 rounded bg-hairline" />
                  <i className="h-2 w-10 rounded bg-hairline" />
                  <i className="h-2 w-10 rounded bg-hairline" />
                </span>
                <span className="flex h-[26px] items-center rounded-full border border-hairline-strong bg-ground px-3 text-[11px] text-secondary">
                  Wallet connected
                </span>
              </div>
              <div className="mt-5 grid grid-cols-[1fr_216px] gap-4">
                <div className="grid content-start gap-3">
                  <div className="h-[124px] rounded-lg bg-hairline/70" />
                  <div className="grid grid-cols-2 gap-3">
                    <div className="h-20 rounded-lg bg-hairline/70" />
                    <div className="h-20 rounded-lg bg-hairline/70" />
                  </div>
                  <div className="h-3 w-[70%] rounded-lg bg-hairline/70" />
                  <div className="h-3 w-[48%] rounded-lg bg-hairline/70" />
                </div>
                <div className="rounded-[14px] border border-hairline bg-ground p-4 shadow-sm">
                  <p className="text-[13px] font-medium text-ink">
                    Approve token
                  </p>
                  <div className="mt-2.5 flex items-center justify-between rounded-[10px] bg-ground-alt px-3 py-2.5 text-xs text-secondary">
                    <span>Token</span>
                    <b className="text-[15px] font-medium text-ink">USDC</b>
                  </div>
                  <div className="mt-2.5 flex items-center justify-between rounded-[10px] bg-ground-alt px-3 py-2.5 text-xs text-secondary">
                    <span>Allowance</span>
                    <b className="text-[15px] font-medium text-ink">
                      Unlimited
                    </b>
                  </div>
                  <div className="relative mt-3">
                    <div className="story-approve grid h-10 place-items-center rounded-[10px] bg-ink text-[13px] font-medium text-white">
                      Approve
                    </div>
                    <svg
                      className="story-cursor pointer-events-none absolute left-1/2 top-1/2 h-[22px] w-[22px]"
                      viewBox="0 0 24 24"
                    >
                      <path
                        d="M4 2l15 11-6.6 1.2L16 21.5l-2.8 1.3-3.6-7.3L4 20z"
                        fill="#141414"
                        stroke="#fff"
                        strokeWidth="1.4"
                        strokeLinejoin="round"
                      />
                    </svg>
                  </div>
                  <p className="mt-2 text-center text-[10.5px] text-secondary">
                    Placeholder page
                  </p>
                </div>
              </div>
            </div>
            <div
              className="story-dim absolute inset-0 hidden bg-[rgba(0,0,0,0.75)] sm:block"
              aria-hidden="true"
            />
            <div className="story-loading absolute inset-0 hidden place-items-center sm:grid">
              <img
                src="/hero-overlay-loading.webp"
                width={490}
                height={246}
                alt="The ShieldBot extension's dialog while it checks the request. It reads Analyzing transaction..."
                className="w-[380px] h-auto rounded"
              />
            </div>
            <div className="story-verdict relative sm:absolute sm:inset-0 sm:flex sm:justify-center sm:px-6 sm:pt-6">
              <div className="story-fade overflow-hidden rounded sm:h-[436px] sm:w-[400px]">
                <picture>
                  <source
                    media="(max-width: 639px)"
                    srcSet="/hero-overlay-mobile.webp"
                    width={390}
                    height={496}
                  />
                  <img
                    src="/hero-overlay.webp"
                    width={490}
                    height={1019}
                    alt="The ShieldBot extension's warning dialog for a request that approves unlimited USDC spending on Ethereum. The verdict badge reads BLOCK RECOMMENDED — Safety: 0/100. The danger signals include Spender flagged by GoPlus: stealing_attack (SlowMist,BlockSec)."
                    className="block w-full h-auto"
                  />
                </picture>
              </div>
            </div>
          </div>
        </div>
      </div>
      <figcaption className="mt-3.5 text-xs leading-[18px] text-secondary">
        Recorded reply of 26 September 2026, chain 1, BLOCK RECOMMENDED.
        Recorded examples, not live scans. The page, the cursor and the dimmed
        backdrop are drawn; the two dialogs are captures of the extension's
        overlay at unreleased commit 2b54a1b, fed that reply.{" "}
        <button
          type="button"
          onClick={() => setRun(run + 1)}
          className="hidden text-accent underline underline-offset-2 transition-colors duration-150 hover:text-accent-hover motion-safe:sm:inline"
        >
          Play again
        </button>
      </figcaption>
    </figure>
  );
}
