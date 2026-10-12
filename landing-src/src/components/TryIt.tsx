import { useEffect, useRef, useState, type FormEvent } from "react";
import { verdictOf, type ScanReply } from "../firewallVerdict";
import VerdictRecord from "./VerdictRecord";

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

type ScanResult = ScanReply & {
  address?: string;
  chain_id?: number;
  network?: string;
  evidence_hash?: string | null;
};

type State =
  | { kind: "idle" }
  | { kind: "invalid" }
  | { kind: "loading" }
  | { kind: "result"; reply: ScanResult }
  | { kind: "bad-request" }
  | { kind: "rate-limited" }
  | { kind: "unavailable" };

function short(address: string) {
  return `${address.slice(0, 6)}\u2026${address.slice(-4)}`;
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
    return <p className="text-sm text-ink">Unavailable right now</p>;

  const { reply } = state;
  const { label } = verdictOf(reply);
  const chain =
    typeof reply.chain_id === "number" && typeof reply.network === "string"
      ? { id: reply.chain_id, name: reply.network }
      : undefined;

  return (
    <div>
      {reply.address && (
        <p className="mb-3 font-mono text-[13px] text-ink [overflow-wrap:anywhere]">
          {short(reply.address)}
        </p>
      )}
      <VerdictRecord
        chip={{ verdict: label.verdict, label: label.text }}
        reasons={reply.coverage_reasons}
        chain={chain}
        evidenceHash={reply.evidence_hash}
        variant="full"
      />
      {reply.evidence_url && (
        <a
          href={reply.evidence_url}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-3 inline-flex min-h-[44px] items-center text-sm font-medium text-accent underline underline-offset-4 transition-colors duration-150 hover:text-ink"
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
  // The scan in flight, aborted if the section unmounts before it answers.
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);

  async function check(event: FormEvent) {
    event.preventDefault();
    if (state.kind === "loading") return;
    const value = address.trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
      setState({ kind: "invalid" });
      return;
    }
    setState({ kind: "loading" });
    const controller = new AbortController();
    request.current = controller;
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const response = await fetch(SCAN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: value, chainId }),
        signal: controller.signal,
      });
      if (response.status === 400) setState({ kind: "bad-request" });
      else if (response.status === 429) setState({ kind: "rate-limited" });
      else if (!response.ok) setState({ kind: "unavailable" });
      else
        setState({
          kind: "result",
          reply: (await response.json()) as ScanResult,
        });
    } catch {
      // A timeout, a network failure or a body that is not JSON all read the same to a visitor.
      setState({ kind: "unavailable" });
    } finally {
      clearTimeout(timeout);
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
          <h2 id="try-label" className="text-base font-semibold text-ink">
            Check a token or address
          </h2>
          <div className="mt-4 grid gap-3 sm:grid-cols-[minmax(0,0.38fr)_minmax(0,1fr)]">
            <div>
              <label
                htmlFor="try-chain"
                className="mb-1.5 block text-sm font-medium text-ink"
              >
                Chain
              </label>
              <select
                id="try-chain"
                value={chainId}
                onChange={(event) => setChainId(Number(event.target.value))}
                className="try-select h-11 w-full cursor-pointer appearance-none rounded-md border border-secondary bg-ground pl-3 pr-8 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
              >
                {chainOptions.map((option) => (
                  <option key={option.id} value={option.id}>
                    {option.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label
                htmlFor="try-address"
                className="mb-1.5 block text-sm font-medium text-ink"
              >
                Token or contract address
              </label>
              <input
                id="try-address"
                type="text"
                inputMode="text"
                autoComplete="off"
                spellCheck={false}
                placeholder="0x..."
                value={address}
                onChange={(event) => setAddress(event.target.value)}
                className="h-11 w-full rounded-md border border-secondary bg-ground px-3 font-mono text-sm text-ink placeholder:font-sans placeholder:text-secondary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
              />
            </div>
          </div>
          <div className="mt-3 flex justify-end">
            <button
              type="submit"
              disabled={state.kind === "loading"}
              className="inline-flex h-11 w-full items-center justify-center gap-2 rounded-md bg-ink px-[18px] text-sm font-medium text-on-ink shadow-button transition-colors duration-150 hover:bg-ink/85 disabled:cursor-wait disabled:bg-secondary sm:w-auto"
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
                : state.kind === "result"
                  ? "mt-4"
                  : "mt-4 rounded-md border border-hairline bg-ground px-4 py-3.5"
            }
          >
            <Result state={state} />
          </div>
          <p className="mt-3 text-xs leading-[18px] text-secondary">
            Quick check: no sell simulation, so a token reads Unknown here. The
            extension runs the full check.
          </p>
        </form>
      </div>
    </section>
  );
}
