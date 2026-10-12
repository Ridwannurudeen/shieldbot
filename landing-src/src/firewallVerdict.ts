import type { Verdict } from "./components/Badge";

// The fields of an /api/firewall or /api/scan reply that decide the verdict chip.
export interface ScanReply {
  status?: string;
  partial?: boolean;
  risk_level?: string;
  classification?: string;
  risk_score?: number;
  coverage?: Record<string, number | boolean | null>;
  coverage_reasons?: Record<string, string | null>;
  evidence_url?: string | null;
}

export const labels: Record<string, { verdict: Verdict; text: string }> = {
  SAFE: { verdict: "safe", text: "SAFE" },
  CAUTION: { verdict: "caution", text: "CAUTION" },
  HIGH_RISK: { verdict: "high", text: "HIGH RISK" },
  BLOCK_RECOMMENDED: { verdict: "block", text: "BLOCK RECOMMENDED" },
  UNKNOWN: { verdict: "unknown", text: "UNKNOWN" },
};

// The extension's rule (verdictOf in extension/content.js): an incomplete check reads Unknown unless the
// API already found high risk.
export function verdictOf(reply: ScanReply) {
  const incomplete =
    reply.status !== "ok" ||
    reply.partial === true ||
    reply.risk_level === "UNKNOWN" ||
    reply.classification === "UNKNOWN" ||
    !Number.isFinite(reply.risk_score) ||
    Object.values(reply.coverage ?? {}).some((value) => Number(value) < 1);
  const classification =
    incomplete &&
    !["HIGH_RISK", "BLOCK_RECOMMENDED"].includes(reply.classification ?? "")
      ? "UNKNOWN"
      : reply.classification || "CAUTION";
  return { incomplete, label: labels[classification] ?? labels.CAUTION };
}
