import { useSyncExternalStore } from "react";

// GET /api/stats (api.py public_stats), fetched once when the page loads and read by Mechanism and the chain
// matrix, so the page asks for it once. undefined while loading, null when it did not answer in 10 seconds or
// answered with an error (a 429 included); nothing is filled in. When the last reader unmounts, the request is
// aborted and the reply cleared, so a later reader fetches it again.
export interface Stats {
  transactions_monitored: number | null;
  mempool_counting_since: number | null;
  mempool_chains_observable: number[] | null;
  launch_discovery: {
    scanned_share: { window_hours: number; launches: number; scanned: number };
  } | null;
  registry_records_confirmed: number | null;
  evidence_documents: Record<string, number> | null;
  contracts_scanned: number | null;
  transactions_blocked: number | null;
}

export interface LiveStats {
  stats: Stats | null | undefined;
  fetchedAt: Date | null;
}

const EMPTY: LiveStats = { stats: undefined, fetchedAt: null };

let state = EMPTY;
const listeners = new Set<() => void>();
let controller: AbortController | null = null;

function load(current: AbortController) {
  const timeout = setTimeout(() => current.abort(), 10_000);
  const settle = (next: LiveStats) => {
    if (current !== controller) return;
    state = next;
    listeners.forEach((listener) => listener());
  };
  fetch("https://api.shieldbotsecurity.online/api/stats", {
    signal: current.signal,
  })
    .then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    })
    .then((d: Stats) => settle({ stats: d, fetchedAt: new Date() }))
    .catch(() => settle({ stats: null, fetchedAt: null }))
    .finally(() => clearTimeout(timeout));
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (!controller) {
    controller = new AbortController();
    load(controller);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size || !controller) return;
    controller.abort();
    controller = null;
    state = EMPTY;
  };
}

export function useStats(): LiveStats {
  return useSyncExternalStore(subscribe, () => state);
}
