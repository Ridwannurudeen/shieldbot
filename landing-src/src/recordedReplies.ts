import type { ScanReply } from "./firewallVerdict";

// Three recorded POST /api/firewall replies, landing-src/scripts/hero-overlay{,-unknown,-safe}-response.json,
// with sent_at from hero-overlay-recordings.json. The JSON is not imported: each reply carries its full 64-hex
// evidence hash, which the page never shows. Instead the fields the page renders are transcribed here, the
// hash already shortened, and tests/test_website_claims.py checks every one against its fixture.
// request is the recorded call itself (hero-overlay{,-unknown,-safe}-request.json): the method its 4-byte selector
// names, its target address (the token contract) and the spender its calldata approves, both shortened; the rest of
// the calldata is not transcribed.
// A recorded reply has no observed block, publication time or guard outcome; those are registry fields.
export interface RecordedReply extends ScanReply {
  fixture: string;
  sent_at: string;
  request: { method: string; to: string; spender: string };
  coverage: Record<string, number>;
  chain_id: number;
  network: string;
  plain_english: string;
  evidence_hash: string;
}

export const recordedReplies: Record<
  "block" | "unknown" | "safe",
  RecordedReply
> = {
  block: {
    fixture: "hero-overlay-response.json",
    sent_at: "2026-09-26T07:14Z",
    request: {
      method: "approve(address,uint256)",
      to: "0xa0b8…eb48",
      spender: "0x1fcd…9107",
    },
    status: "ok",
    partial: false,
    classification: "BLOCK_RECOMMENDED",
    risk_score: 100,
    coverage: {
      structural: 1,
      market: 1,
      behavioral: 1,
      honeypot: 1,
      intent: 1,
      signature: 1,
    },
    chain_id: 1,
    coverage_reasons: {},
    network: "Ethereum",
    plain_english: "Do not proceed with this transaction.",
    evidence_hash: "0x719c…fe17",
  },
  unknown: {
    fixture: "hero-overlay-unknown-response.json",
    sent_at: "2026-10-11T09:21:20Z",
    request: {
      method: "approve(address,uint256)",
      to: "0x8adb…8900",
      spender: "0x89e5…9eba",
    },
    status: "unknown",
    partial: true,
    classification: "CAUTION",
    risk_score: 9.4,
    coverage: {
      structural: 1,
      market: 0,
      behavioral: 1,
      honeypot: 0.4,
      intent: 1,
      signature: 1,
    },
    coverage_reasons: {
      market: "No DexScreener pairs on requested chain (robinhood)",
      honeypot:
        "Initialize logs scanned over blocks 85694876-85724875; No supported pool found; Unknown fields: buy_tax, sell_tax, can_sell",
    },
    chain_id: 4663,
    network: "Robinhood Chain",
    plain_english:
      "Unknown: No DexScreener pairs on requested chain (robinhood); Initialize logs scanned over blocks 85694876-85724875; No supported pool found; Unknown fields: buy_tax, sell_tax, can_sell. Review the missing data before proceeding.",
    evidence_hash: "0xac32…ee05",
  },
  safe: {
    fixture: "hero-overlay-safe-response.json",
    sent_at: "2026-10-11T09:21:15Z",
    request: {
      method: "approve(address,uint256)",
      to: "0x912c…6548",
      spender: "0x68b3…fc45",
    },
    status: "ok",
    partial: false,
    classification: "SAFE",
    risk_score: 6.4,
    coverage: {
      structural: 1,
      market: 1,
      behavioral: 1,
      honeypot: 1,
      intent: 1,
      signature: 1,
    },
    chain_id: 42161,
    coverage_reasons: {},
    network: "Arbitrum",
    plain_english: "No major risks detected. Standard precautions apply.",
    evidence_hash: "0x306f…be8f",
  },
};
