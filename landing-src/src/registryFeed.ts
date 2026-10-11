import { useSyncExternalStore } from "react";

// The worked example and the recent-records strip read one shared feed, fetched once when the page loads:
// - GET /api/verdicts/recent?chain_id=4663&limit=5, the registry's confirmed records, newest first. Until that
//   route is deployed it answers 404, and the strip falls back to the newest blocked launches below.
// - GET /api/launches/4663?outcome=blocked&limit=5, the newest launches ShieldBot blocked. The worked example
//   quotes the first one's sell simulation.
// - GET /api/verdict/4663/{address}, one at a time (the API allows 10 requests in 5 seconds per visitor):
//   the first launch's record, and in the fallback each other launch's record too.
// undefined while loading, null when a route did not answer; nothing is filled in.
const API = "https://api.shieldbotsecurity.online";
const LIMIT = 5;

export interface RegistryRecord {
  subject: string;
  verdict: string;
  verdict_code: number;
  observed_block: number | null;
  published_at: number | null;
  onchain_status: string;
  tx_hash: string | null;
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

let feed: Feed = {
  recent: undefined,
  launches: undefined,
  records: {},
  fetchedAt: null,
};
const listeners = new Set<() => void>();
let started = false;

function update(patch: Partial<Feed>) {
  feed = { ...feed, ...patch };
  listeners.forEach((listener) => listener());
}

function setRecord(address: string, record: RegistryRecord | null | undefined) {
  update({ records: { ...feed.records, [address]: record } });
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json() as Promise<T>;
}

async function loadRecent(): Promise<boolean> {
  try {
    const response = await fetch(
      `${API}/api/verdicts/recent?chain_id=4663&limit=${LIMIT}`,
    );
    if (response.status === 404) {
      update({ recent: "fallback" });
      return true;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = (await response.json()) as { records: RegistryRecord[] };
    update({ recent: body.records, fetchedAt: new Date() });
  } catch {
    update({ recent: null });
  }
  return false;
}

async function loadLaunches(): Promise<Launch[]> {
  try {
    const body = await getJson<{ launches: Launch[] }>(
      `/api/launches/4663?outcome=blocked&limit=${LIMIT}`,
    );
    update({ launches: body.launches, fetchedAt: new Date() });
    return body.launches;
  } catch {
    update({ launches: null });
    return [];
  }
}

async function loadRecord(address: string) {
  setRecord(address, undefined);
  try {
    setRecord(
      address,
      await getJson<RegistryRecord>(`/api/verdict/4663/${address}`),
    );
  } catch {
    setRecord(address, null);
  }
}

async function load() {
  const [fallback, launches] = await Promise.all([
    loadRecent(),
    loadLaunches(),
  ]);
  const addresses = launches.map((launch) => launch.token_address);
  for (const address of fallback ? addresses : addresses.slice(0, 1)) {
    await loadRecord(address);
  }
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (!started) {
    started = true;
    void load();
  }
  return () => {
    listeners.delete(listener);
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
