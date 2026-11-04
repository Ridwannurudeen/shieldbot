export default function HeroRecord() {
  return (
    <figure className="mx-auto w-full max-w-[490px]">
      <div className="relative rounded-md border border-hairline bg-ground-alt p-4">
        <div className="relative h-[620px] overflow-hidden rounded-md bg-ground-alt">
          <div className="hero-loading absolute inset-0 flex items-center justify-center">
            <div
              aria-hidden="true"
              className="hero-loading-backdrop absolute inset-0"
            />
            <img
              src="/hero-overlay-loading.webp"
              width={490}
              height={246}
              alt="The ShieldBot extension's dialog while it checks the request. It reads Analyzing transaction..."
              className="hero-loading-image relative z-10 block h-auto w-full max-w-[365px]"
            />
          </div>
          <div className="hero-verdict absolute inset-0 overflow-hidden rounded-md">
            <img
              src="/hero-overlay.webp"
              width={490}
              height={1019}
              alt="The ShieldBot extension's warning dialog for a request that approves unlimited USDC spending on Ethereum. The verdict badge reads BLOCK RECOMMENDED. Safety: 0/100. The danger signals include Spender flagged by GoPlus: stealing_attack (SlowMist,BlockSec)."
              className="mx-auto block h-auto w-full max-w-[365px]"
            />
          </div>
        </div>
      </div>
      <figcaption className="mt-3 text-xs text-secondary">
        Recorded reply, 26 Sep 2026
      </figcaption>
    </figure>
  );
}
