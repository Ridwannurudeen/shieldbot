import type { Verdict } from "./components/Badge";

// A registry record's verdict (ShieldBotVerdictRegistry on Robinhood Chain and BOT Chain: LOW, MEDIUM, HIGH, HONEYPOT,
// UNKNOWN) as a chip. It is not a firewall verdict: a registry LOW or MEDIUM is a token's risk level as published
// at one moment, and the guard allows the two alike, only while the record is fresh. So both take the neutral
// registry shape, never SAFE's green or CAUTION's "!". HIGH, HONEYPOT and UNKNOWN take the firewall's HIGH RISK,
// BLOCK and UNKNOWN shapes, and any other word reads as UNKNOWN. The label is the registry's own word and its
// code ("LOW · 1"). Extension and API replies are drawn through src/firewallVerdict.ts instead.
function shapeOf(verdict: string | null): Verdict {
  switch (verdict) {
    case "LOW":
    case "MEDIUM":
      return "registry";
    case "HIGH":
      return "high";
    case "HONEYPOT":
      return "block";
    default:
      return "unknown";
  }
}

export function registryChip(
  verdict: string | null,
  code: number | null | undefined,
): { verdict: Verdict; label: string } {
  return {
    verdict: shapeOf(verdict),
    label:
      verdict === null
        ? "Unavailable"
        : typeof code === "number"
          ? `${verdict} · ${code}`
          : verdict,
  };
}
