export default function HeroRecord() {
  return (
    <figure className="mx-auto w-full max-w-[490px]">
      <div className="hero-stage relative h-[560px] overflow-hidden rounded-md border border-hairline bg-ground-alt sm:h-[640px]">
        <div className="hero-loading absolute inset-x-4 top-4 overflow-hidden rounded-md bg-paper">
          <img
            src="/hero-overlay-loading.webp"
            width={490}
            height={246}
            alt="The ShieldBot extension's dialog while it checks the request. It reads Analyzing transaction..."
            className="block h-auto w-full"
          />
        </div>
        <div className="hero-verdict absolute inset-x-4 top-4 max-h-[420px] overflow-hidden rounded-md bg-paper">
          <img
            src="/hero-overlay.webp"
            width={490}
            height={1019}
            alt="The ShieldBot extension's warning dialog for a request that approves unlimited USDC spending on Ethereum. The verdict badge reads BLOCK RECOMMENDED. Safety: 0/100. The danger signals include Spender flagged by GoPlus: stealing_attack (SlowMist,BlockSec)."
            className="block h-auto w-full"
          />
        </div>
      </div>
      <figcaption className="mt-3 text-xs text-secondary">
        Recorded reply, 26 Sep 2026
      </figcaption>
    </figure>
  );
}
