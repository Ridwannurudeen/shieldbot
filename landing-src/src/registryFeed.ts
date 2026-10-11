import { useSyncExternalStore } from "react";

// The worked example and the recent-records strip read one shared feed, fetched once when the page loads:
// - GET /api/verdicts/recent?chain_id=4663&limit=5, the registry's confirmed records, newest first. Until that
//   route is deployed it answers 404, and the strip falls back to the newest blocked launches below.
// - GET /api/launches/4663?outcome=blocked&limit=5, the newest launches ShieldBot blocked. The worked example
//   quotes the first one's sell simulation.
// - GET /api/verdict/4663/{address}, one at a time (the API allows 10 requests in 5 seconds per visitor):
//   the first launch's record, and in the fallback each other launch's record too.
// undefined while loading, null when a route did not answer in 10 seconds; nothing is filled in.
// When the last component reading the feed unmounts, its requests are aborted and the feed is cleared, so a
// later reader fetches it again.
const API = "https://api.shieldbotsecurity.online";
const LIMIT = 5;

// Every route above is on Robinhood Chain, so a record's chain line is the route's chain, the same in every
// section that draws one.
export const REGISTRY_CHAIN = { id: 4663, name: "Robinhood Chain" };

export interface RegistryRecord {
  subject: string;
  verdict: string;
  verdict_code: number;
  observed_block: number | null;
  published_at: number | null;
  onchain_status: string;
  tx_hash: string | null;
  evidence_hash?: string | null;
}

export interface Launch {
  token_address: string;
  launchpad: string | null;
  block_timestamp: number | null;
  scan: {
    risk_level: string | null;
    risk_score: number | null;
    coverage_reasons: Record<string, string> | null;
  } | null;
}

export interface Feed {
  // The records the strip lists, from the new route, or "fallback" when that route answered 404.
  recent: RegistryRecord[] | "fallback" | null | undefined;
  launches: Launch[] | null | undefined;
  // Per token address: undefined while loading, null when /api/verdict did not answer.
  records: Record<string, RegistryRecord | null | undefined>;
  fetchedAt: Date | null;
}

const EMPTY: Feed = {
  recent: undefined,
  launches: undefined,
  records: {},
  fetchedAt: null,
};

// One page-load fetch of the feed and its requests that have not reached their deadline.
interface Run {
  requests: Set<{ controller: AbortController; timer: ReturnType<typeof setTimeout> }>;
}

let feed = EMPTY;
const listeners = new Set<() => void>();
let run: Run | null = null;

// A run that was stopped no longer writes to the feed.
function update(current: Run, patch: Partial<Feed>) {
  if (current !== run) return;
  feed = { ...feed, ...patch };
  listeners.forEach((listener) => listener());
}

function setRecord(
  current: Run,
  address: string,
  record: RegistryRecord | null | undefined,
) {
  update(current, { records: { ...feed.records, [address]: record } });
}

// A request that has not finished in 10 seconds is abandoned and its route reads as not answering, as in
// WhyUnknown.tsx. Aborting after the reply has been read does nothing.
function request(current: Run, path: string): Promise<Response> {
  const controller = new AbortController();
  const entry = {
    controller,
    timer: setTimeout(() => {
      current.requests.delete(entry);
      controller.abort();
    }, 10_000),
  };
  current.requests.add(entry);
  return fetch(`${API}${path}`, { signal: controller.signal });
}

async function getJson<T>(current: Run, path: string): Promise<T> {
  const response = await request(current, path);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json() as Promise<T>;
}

async function loadRecent(current: Run): Promise<boolean> {
  try {
    const response = await request(
      current,
      `/api/verdicts/recent?chain_id=4663&limit=${LIMIT}`,
    );
    if (response.status === 404) {
      update(current, { recent: "fallback" });
      return true;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = (await response.json()) as { records: RegistryRecord[] };
    update(current, { recent: body.records, fetchedAt: new Date() });
  } catch {
    update(current, { recent: null });
  }
  return false;
}

async function loadLaunches(current: Run): Promise<Launch[]> {
  try {
    const body = await getJson<{ launches: Launch[] }>(
      current,
      `/api/launches/4663?outcome=blocked&limit=${LIMIT}`,
    );
    update(current, { launches: body.launches, fetchedAt: new Date() });
    return body.launches;
  } catch {
    update(current, { launches: null });
    return [];
  }
}

async function loadRecord(current: Run, address: string) {
  setRecord(current, address, undefined);
  try {
    setRecord(
      current,
      address,
      await getJson<RegistryRecord>(current, `/api/verdict/4663/${address}`),
    );
  } catch {
    setRecord(current, address, null);
  }
}

async function load(current: Run) {
  const [fallback, launches] = await Promise.all([
    loadRecent(current),
    loadLaunches(current),
  ]);
  const addresses = launches.map((launch) => launch.token_address);
  for (const address of fallback ? addresses : addresses.slice(0, 1)) {
    if (current !== run) return;
    await loadRecord(current, address);
  }
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (!run) {
    run = { requests: new Set() };
    void load(run);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size || !run) return;
    run.requests.forEach(({ controller, timer }) => {
      clearTimeout(timer);
      controller.abort();
    });
    run = null;
    feed = EMPTY;
  };
}

export function useFeed(): Feed {
  return useSyncExternalStore(subscribe, () => feed);
}

export function short(hex: string) {
  return `${hex.slice(0, 6)}…${hex.slice(-4)}`;
}

// Long hex strings (pool ids, hashes) in a served sentence are shown truncated, as everywhere on the page.
export function shortenHex(text: string) {
  return text.replace(/0x[0-9a-fA-F]{40,}/g, (hex) => short(hex));
}

export function utc(seconds: number | null | undefined) {
  if (typeof seconds !== "number") return null;
  return `${new Date(seconds * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}
