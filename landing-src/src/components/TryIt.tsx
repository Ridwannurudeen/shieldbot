import { useState, type FormEvent } from "react";
import Badge from "./Badge";
import { verdictOf, type ScanReply } from "../firewallVerdict";

// The try-it section, right after the hero: POST /api/scan, the quick contract scan (api.py). No key is
// sent, so the API's per-IP limiter answers 429 when it is reached.
const SCAN_URL = "https://api.shieldbotsecurity.online/api/scan";
// The scan's own deadline is 25 seconds; give up a little after it.
const TIMEOUT_MS = 30_000;

const chainOptions = [
  { id: 1, name: "Ethereum" },
  { id: 56, name: "BNB Chain" },
  { id: 8453, name: "Base" },
  { id: 42161, name: "Arbitrum" },
  { id: 137, name: "Polygon" },
  { id: 10, name: "Optimism" },
  { id: 204, name: "opBNB" },
  { id: 4663, name: "Robinhood Chain" },
];

type State =
  | { kind: "idle" }
  | { kind: "invalid" }
  | { kind: "loading" }
  | { kind: "result"; reply: ScanReply; address: string; chain: string }
  | { kind: "bad-request" }
  | { kind: "rate-limited" }
  | { kind: "unavailable" };

function short(address: string) {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

function Result({ state }: { state: State }) {
  if (state.kind === "idle") return null;
  if (state.kind === "invalid")
    return <p className="text-sm text-ink">Enter a 40-character hex address</p>;
  if (state.kind === "loading")
    return (
      <p className="text-sm text-secondary">
        Checking, this can take up to 25 seconds
      </p>
    );
  if (state.kind === "bad-request")
    return (
      <p className="text-sm text-ink">
        That address is not valid on this chain
      </p>
    );
  if (state.kind === "rate-limited")
    return (
      <p className="text-sm text-ink">
        Too many checks from this connection. Wait a minute and try again.
      </p>
    );
  if (state.kind === "unavailable")
    return (
      <p className="flex items-center gap-3 text-sm text-ink">
        <span
          aria-hidden="true"
          className="inline-flex h-6 min-w-[2.5rem] items-center justify-center rounded border border-hairline-strong text-secondary"
        >
          —
        </span>
        Unavailable right now
      </p>
    );

  const { reply, address, chain } = state;
  const { incomplete, label } = verdictOf(reply);
  const reasons = Object.values(reply.coverage_reasons ?? {}).filter(
    (reason): reason is string => Boolean(reason),
  );
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="font-mono text-[13px] text-ink">
          {short(address)} · {chain}
        </span>
        <Badge verdict={label.verdict}>{label.text}</Badge>
      </div>
      <p className="mt-2 text-sm text-secondary">
        {incomplete || !Number.isFinite(reply.risk_score)
          ? "Incomplete coverage: no safety score"
          : `Safety ${Math.round((100 - (reply.risk_score as number)) * 10) / 10}/100`}
      </p>
      {reasons.length > 0 && (
        <ul className="mt-2 space-y-1 text-sm leading-[21px] text-ink">
          {reasons.map((reason) => (
            <li key={reason} className="flex gap-2">
              <span aria-hidden="true" className="text-secondary">
                ?
              </span>
              {reason}
            </li>
          ))}
        </ul>
      )}
      {reply.evidence_url && (
        <a
          href={reply.evidence_url}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-3 inline-flex min-h-[44px] items-center text-sm font-medium text-accent underline underline-offset-4 transition-colors duration-150 hover:text-accent-hover"
        >
          Evidence
        </a>
      )}
    </div>
  );
}

export default function TryIt() {
  const [chainId, setChainId] = useState(1);
  const [address, setAddress] = useState("");
  const [state, setState] = useState<State>({ kind: "idle" });

  async function check(event: FormEvent) {
    event.preventDefault();
    if (state.kind === "loading") return;
    const value = address.trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
      setState({ kind: "invalid" });
      return;
    }
    const chain =
      chainOptions.find((option) => option.id === chainId)?.name ?? "";
    setState({ kind: "loading" });
    try {
      const response = await fetch(SCAN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: value, chainId }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (response.status === 400) setState({ kind: "bad-request" });
      else if (response.status === 429) setState({ kind: "rate-limited" });
      else if (!response.ok) setState({ kind: "unavailable" });
      else
        setState({
          kind: "result",
          reply: (await response.json()) as ScanReply,
          address: value,
          chain,
        });
    } catch {
      // A timeout, a network failure or a body that is not JSON all read the same to a visitor.
      setState({ kind: "unavailable" });
    }
  }

  return (
    <section
      id="try"
      aria-labelledby="try-label"
      className="border-b border-hairline bg-ground py-12 md:py-16"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <form
          onSubmit={check}
          aria-labelledby="try-label"
          className="max-w-[520px]"
          noValidate
        >
          <p
            id="try-label"
            className="flex items-center gap-4 text-[15px] text-secondary before:h-px before:flex-1 before:bg-hairline-strong after:h-px after:flex-1 after:bg-hairline-strong"
          >
            Check a token or address
          </p>
          <div className="mt-3.5 flex flex-wrap items-center gap-1 rounded-2xl border border-unknown bg-ground p-1 shadow-sm transition-[border-color,box-shadow] duration-150 focus-within:border-accent focus-within:shadow-[0_0_0_3px_rgba(163,22,143,0.22)] sm:flex-nowrap sm:rounded-full">
            <label htmlFor="try-chain" className="sr-only">
              Chain
            </label>
            <select
              id="try-chain"
              value={chainId}
              onChange={(event) => setChainId(Number(event.target.value))}
              className="try-select h-11 w-full cursor-pointer appearance-none rounded-full bg-ground-alt pl-3.5 pr-8 text-sm text-ink focus:outline-none sm:h-10 sm:w-auto"
            >
              {chainOptions.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.name}
                </option>
              ))}
            </select>
            <label htmlFor="try-address" className="sr-only">
              Token or contract address
            </label>
            <input
              id="try-address"
              type="text"
              inputMode="text"
              autoComplete="off"
              spellCheck={false}
              placeholder="Token or contract address"
              value={address}
              onChange={(event) => setAddress(event.target.value)}
              className="h-11 min-w-0 flex-1 basis-full bg-transparent px-2 font-mono text-sm text-ink placeholder:font-sans placeholder:text-secondary focus:outline-none sm:h-10 sm:basis-auto"
            />
            <button
              type="submit"
              disabled={state.kind === "loading"}
              className="inline-flex h-11 w-full items-center justify-center gap-2 rounded-full bg-ink px-[18px] text-sm font-medium text-white shadow-button transition-colors duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] hover:bg-[#000] disabled:cursor-wait disabled:bg-secondary sm:h-10 sm:w-auto"
            >
              Check now
              <svg
                viewBox="0 0 16 16"
                width="16"
                height="16"
                aria-hidden="true"
              >
                <path
                  d="M3 8h10M9 4l4 4-4 4"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.6"
                />
              </svg>
            </button>
          </div>
          <div
            aria-live="polite"
            className={
              state.kind === "idle"
                ? ""
                : "mt-3 rounded-xl border border-hairline bg-ground px-4 py-3.5 shadow-md"
            }
          >
            <Result state={state} />
          </div>
          <p className="mt-3 text-xs leading-[18px] text-secondary">
            Quick check: no sell simulation, so a token reads Unknown here. The
            extension and POST /api/firewall run the full check.
          </p>
          <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2">
            <figure className="min-w-0">
              <img
                src="/hero-overlay-safe.webp"
                width={490}
                height={480}
                loading="lazy"
                alt="The ShieldBot extension's dialog for a 250 ARB approval to Uniswap's SwapRouter02 on Arbitrum One. The verdict badge reads SAFE — Safety: 93.6/100. The danger signals include Proxy/upgradeable contract."
                className="w-full h-auto rounded-md ring-1 ring-hairline"
              />
              <figcaption className="mt-1.5 text-xs leading-[18px] text-secondary">
                {"Recorded /api/firewall reply of 11 October 2026, chain 42161, SAFE. Upper part of the dialog, overlay at unreleased commit 2b54a1b."}
              </figcaption>
            </figure>
            <figure className="min-w-0">
              <img
                src="/hero-overlay-unknown.webp"
                width={490}
                height={480}
                loading="lazy"
                alt="The ShieldBot extension's dialog for a token approval on Robinhood Chain whose token has no supported pool. The verdict badge reads UNKNOWN. Why: No DexScreener pairs on requested chain (robinhood); Initialize logs scanned over blocks 85694876-85724875; No supported pool found; Unknown fields: buy_tax, sell_tax, can_sell. The danger signals include Top 10 holders own 100.0% of supply (burn, locked, pool and locker addresses excluded)."
                className="w-full h-auto rounded-md ring-1 ring-hairline"
              />
              <figcaption className="mt-1.5 text-xs leading-[18px] text-secondary">
                {"Recorded /api/firewall reply of 11 October 2026, chain 4663, UNKNOWN. Upper part of the dialog, overlay at unreleased commit 2b54a1b."}
              </figcaption>
            </figure>
          </div>
        </form>
      </div>
    </section>
  );
}
