export type RowState = "ok" | "fail" | "unmeasured" | "info";

export interface SceneRow {
  state: RowState;
  name: string;
  note: string;
}

export interface Scene {
  id: "arbroker" | "virtual" | "unknown";
  title: string;
  subtitle: string;
  address?: string;
  chain: string;
  rows: SceneRow[];
  verdict: {
    label: string;
    tone: "block" | "safe" | "unknown";
    chips: string[];
  };
  explanation: string;
  footnote: string;
  source: { label: string; href: string };
  announcement: string;
}

export const SCENES: readonly Scene[] = [
  {
    id: "arbroker",
    title: "ARBROKER on Arbitrum One",
    subtitle: "A token check before you sign",
    address: "0x8328ffdecbd36294b4fcc50c1c25cde18f4a8b2b",
    chain: "Arbitrum One · 42161",
    rows: [
      { state: "ok", name: "Contract code", note: "Read" },
      {
        state: "info",
        name: "GoPlus honeypot flag",
        note: "Reported not a honeypot on 29 September 2026",
      },
      {
        state: "fail",
        name: "ShieldBot sell simulation",
        note: "Buy succeeds, sell reverts: TRANSFER_FROM_FAILED",
      },
      {
        state: "unmeasured",
        name: "Sell tax and pair data",
        note: "Unmeasured: the sell never completed, and DexScreener lists no Arbitrum One pair",
      },
    ],
    verdict: {
      label: "BLOCK RECOMMENDED",
      tone: "block",
      chips: ["Risk 80", "Status UNKNOWN"],
    },
    explanation:
      "Honeypot detected. Every sell forwards the token's ETH to a tax wallet that refuses it, so the sell reverts. A clean answer from a third party does not settle what ShieldBot's own simulation left open.",
    footnote:
      "Recorded eth_simulateV1 call of 29 September 2026 at block 509,946,490 and the API's answer of 30 September 2026. Source: ",
    source: {
      label: "docs/SUBMISSION.md",
      href: "https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/SUBMISSION.md",
    },
    announcement:
      "Example 1 of 3: ARBROKER on Arbitrum One. Verdict: Block recommended, status Unknown.",
  },
  {
    id: "virtual",
    title: "VIRTUAL on Robinhood Chain",
    subtitle: "The on-chain guard, asked whether a USDG transfer may go ahead",
    address: "0xc6911796042b15d7fa4f6cde69e245ddcd3d9c31",
    chain: "Robinhood Chain · 4663",
    rows: [
      {
        state: "ok",
        name: "Registry record",
        note: "Found, recorded by the verdict drain",
      },
      {
        state: "ok",
        name: "Verdict class",
        note: "LOW or MEDIUM, not Unknown, high risk or honeypot",
      },
      {
        state: "ok",
        name: "Freshness",
        note: "Published within the caller's 900-second limit",
      },
      { state: "ok", name: "Timestamp", note: "Not ahead of the chain clock" },
    ],
    verdict: {
      label: "ALLOWED",
      tone: "safe",
      chips: ["reason 0", "maxAge 900 s"],
    },
    explanation:
      "The guard answers that the transfer may go ahead. Permission is not a safety guarantee: the guard deliberately accepts MEDIUM risk, and a record that expires or turns Unknown is denied.",
    footnote:
      "scripts/verify_deployment.py against the live contracts on 27 September 2026: allowed=True, reason=0. Source: ",
    source: {
      label: "docs/SUBMISSION.md",
      href: "https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/SUBMISSION.md",
    },
    announcement:
      "Example 2 of 3: VIRTUAL on Robinhood Chain. Guard check: allowed.",
  },
  {
    id: "unknown",
    title: "An agent asks to buy a token",
    subtitle: "Modelled example from the judge guide",
    chain: "No supported simulation route",
    rows: [
      {
        state: "unmeasured",
        name: "Sell simulation",
        note: "No supported simulation route, so honeypot coverage is 0",
      },
      {
        state: "info",
        name: "Risk score",
        note: "0, a placeholder, not a measurement",
      },
    ],
    verdict: {
      label: "UNKNOWN",
      tone: "unknown",
      chips: ["WARN", "allowed = false"],
    },
    explanation:
      "Missing evidence is not a low-risk measurement. The agent must ask its owner. In the extension, Strict mode blocks an Unknown result and Balanced mode warns and leaves the choice to you.",
    footnote:
      "docs/JUDGE_GUIDE.md, section 2: the SDK model turns an incomplete ALLOW into WARN.",
    source: {
      label: "docs/JUDGE_GUIDE.md",
      href: "https://github.com/Ridwannurudeen/shieldbot/blob/main/docs/JUDGE_GUIDE.md",
    },
    announcement:
      "Example 3 of 3: a modelled agent request with no simulation route. Verdict: Unknown, not allowed automatically.",
  },
];

export const DEMO_TIMING = {
  firstRow: 400,
  rowGap: 450,
  verdictGap: 450,
  hold: 4000,
} as const;
