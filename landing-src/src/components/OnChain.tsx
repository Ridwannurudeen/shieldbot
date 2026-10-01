import CodeBlock from "./CodeBlock";
import ContractCard from "./ContractCard";
import SectionHeader from "./SectionHeader";
import StatTile from "./StatTile";

const contracts = [
  {
    name: "ShieldBotVerdictRegistry",
    role: "Records an authorised recorder's verdict and the keccak256 hash of its evidence document. The owner can rotate the recorder.",
    address: "0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138",
    links: [
      { label: "Explorer", href: "https://robin.etherscan.io/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138" },
      { label: "Blockscout", href: "https://robinhoodchain.blockscout.com/address/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138?tab=contract" },
      { label: "Sourcify exact match", href: "https://sourcify.dev/server/v2/contract/4663/0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138" },
    ],
  },
  {
    name: "ShieldBotVerdictGuard",
    role: "Reads the registry and allows only a LOW or MEDIUM verdict published within the caller's maxAge. check() returns allowed and a reason code; requireAllowed() reverts with NotAllowed.",
    address: "0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e",
    links: [
      { label: "Explorer", href: "https://robin.etherscan.io/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e" },
      { label: "Blockscout", href: "https://robinhoodchain.blockscout.com/address/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e?tab=contract" },
      { label: "Sourcify exact match", href: "https://sourcify.dev/server/v2/contract/4663/0x47fbF2cfcb98B02Ffbc50037A9A65072c58b129e" },
    ],
  },
  {
    name: "ShieldBotGuardedTransfer",
    role: "Asks the guard, then moves the caller's approved USDG and reverts unless the recipient's balance rises by exactly the amount. Its subject is VIRTUAL. No live guarded USDG payment is claimed.",
    address: "0x336254bA85406D9af39357101b688E2B757751b3",
    links: [
      { label: "Explorer", href: "https://robin.etherscan.io/address/0x336254bA85406D9af39357101b688E2B757751b3" },
      { label: "Blockscout", href: "https://robinhoodchain.blockscout.com/address/0x336254bA85406D9af39357101b688E2B757751b3?tab=contract" },
      { label: "Sourcify exact match", href: "https://sourcify.dev/server/v2/contract/4663/0x336254bA85406D9af39357101b688E2B757751b3" },
    ],
  },
];

const reasonCodes = [
  ["0 ALLOWED", "Recorded LOW or MEDIUM, not future-dated, within a positive maxAge"],
  ["1 NO_RECORD", "No evidence hash has been recorded"],
  ["2 UNKNOWN", "Fresh record with incomplete evidence"],
  ["3 HIGH", "High risk, even when expired"],
  ["4 HONEYPOT", "Proven sell trap, even when expired"],
  ["5 EXPIRED", "Non-adverse record older than maxAge, or maxAge is zero"],
  ["6 FUTURE_TIMESTAMP", "Non-adverse publication ahead of the check clock"],
];

const figures = [
  { value: "68,666", label: "new tokens first seen in a liquidity pool" },
  { value: "~8,000", label: "new tokens a day" },
  { value: "28.76%", label: "of mature tokens met a minimal liquidity or activity bar" },
  { value: "49%", label: "could not be resolved either way and are reported as unknown" },
];

const verificationCode = `# docs/JUDGE_GUIDE.md, section 3. The published example is WOOD.
export API_BASE='https://api.shieldbotsecurity.online'
export RPC_URL='https://robinhood-rpc.publicnode.com'   # any chain-4663 RPC; the API does not use this one
export REGISTRY='0xB7cfB87579f232dBa70CDC8Ba063AA7b500D5138'
export SUBJECT='0xf8bc08092c06db6148114dcf82af881f1085f92b'
# RECORD_TX: copy the full hash of 0x7578ca9e…f0c772a4 from the judge guide, section 3
# then run the Python block from the guide`;

export default function OnChain() {
  return (
    <section id="on-chain" aria-labelledby="on-chain-title" className="bg-surface-2 py-14 md:py-[72px] lg:py-24">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <SectionHeader
          id="on-chain-title"
          eyebrow="On Robinhood Chain (4663)"
          title="A contract can check the verdict before it moves funds."
          lead="ShieldBot records each Robinhood Chain verdict on-chain with the hash of its evidence document. A guard contract allows only a recent LOW or MEDIUM record, and a guarded transfer asks the guard before it moves USDG. Missing, Unknown, high-risk, honeypot, expired and future-dated records are denied."
        />

        <div className="mt-10 grid gap-6 lg:grid-cols-3" data-deployed="Deployed 27 September 2026">
          {contracts.map((contract) => (
            <ContractCard key={contract.address} {...contract} />
          ))}
        </div>
        <p className="mt-4 text-[13px] text-muted">All three deployed on 27 September 2026 from the registry owner's account, built from main at c9ae9c9, with full exact source matches on Sourcify.</p>

        <div className="mt-12 grid gap-10 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
          <div>
            <h3 className="text-xl font-semibold text-ink">Verify a verdict without trusting the API</h3>
            <p className="mt-3 text-[15px] text-body">The judge guide's section 3 checks a published verdict against the registry with any Robinhood Chain RPC. No API key, wallet or signing is needed.</p>
            <ol className="mt-5 list-decimal space-y-2 pl-5 text-[15px] text-body">
              <li>Fetch the evidence document from GET /api/verdict/4663/{"{address}"}.</li>
              <li>Hash the served canonical string with keccak256.</li>
              <li>Read the recording transaction's receipt from an independent RPC and match the VerdictRecorded event's subject, verdict and evidence hash.</li>
            </ol>
            <div className="mt-5">
              <CodeBlock code={verificationCode} />
            </div>
            <a
              className="mt-3 inline-flex min-h-[44px] items-center text-[13px] text-emerald underline underline-offset-4 hover:text-emerald-deep"
              href="https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/JUDGE_GUIDE.md#3-verify-a-verdict-without-trusting-the-api"
              target="_blank"
              rel="noopener noreferrer"
            >
              Open the judge guide
            </a>
            <p className="mt-3 text-[13px] text-muted">A match proves the recorder committed those bytes. It does not prove the scan was right, that an issuer is genuine, or that a token will stay sellable.</p>
          </div>
          <div>
            <h3 className="text-xl font-semibold text-ink">What the guard answers</h3>
            <ul className="mt-5 space-y-3">
              {reasonCodes.map(([code, description]) => (
                <li key={code} className="flex gap-3 text-sm">
                  <code className="shrink-0 rounded-md bg-surface-3 px-2 py-0.5 font-mono text-xs text-ink">{code}</code>
                  <span className="text-body">{description}</span>
                </li>
              ))}
            </ul>
            <p className="mt-5 text-[13px] text-muted">Permission lasts only while a subject is actively watched and republished; freshness is publication age, not observation age.</p>
          </div>
        </div>

        <div className="mt-12">
          <h3 className="text-xl font-semibold text-ink">What we saw on the chain</h3>
          <div className="mt-5 grid grid-cols-2 gap-4 lg:grid-cols-4">
            {figures.map((figure) => <StatTile key={figure.label} {...figure} />)}
          </div>
          <p className="mt-4 text-[13px] text-muted">Observed from 14 to 22 September 2026, about 8.6 days. These figures describe the chain, not ShieldBot scans. A token is counted when it first appears in a liquidity pool, not when it is deployed, and missing evidence is reported as unknown, never as zero. <a className="text-emerald underline underline-offset-4 hover:text-emerald-deep" href="https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/census-4663.md" target="_blank" rel="noopener noreferrer">Method and limits</a></p>
        </div>
      </div>
    </section>
  );
}
