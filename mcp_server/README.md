# ShieldBot MCP server

The API serves a [Model Context Protocol](https://modelcontextprotocol.io) server under `/mcp` (mounted in `api.py`). It reports itself as `shieldbot-mcp` version 3.1.0 and speaks protocol version `2024-11-05` over the HTTP+SSE transport. It does not implement the newer Streamable HTTP transport.

Production URL: `https://api.shieldbotsecurity.online/mcp/sse`

## Endpoints

| Endpoint | Purpose | Auth |
|----------|---------|------|
| `GET /mcp/sse` | Event stream. The first event is `endpoint` with `/mcp/messages?session_id=<id>`; responses follow as `message` events. | `X-API-Key` |
| `POST /mcp/messages?session_id=<id>` | One JSON-RPC 2.0 message per request. | `X-API-Key` |
| `GET /mcp/health` | Status and open session count. | none |

How the transport behaves (`server.py`):

- A request's response is pushed to its session's stream and also returned in the POST body (HTTP 200), so a client without a stream can read it from the body. A POST with no `session_id` gets the body only. A `session_id` that is unknown or whose stream has closed gets 404, and a session opened with a different API key gets 403.
- A notification (a message with no `id`, such as `notifications/initialized` or `notifications/cancelled`) is never answered: the POST returns 202 with an empty body and nothing is sent on the stream. Cancellation is ignored; a running request cannot be interrupted.
- A message with no `id` is dropped silently even when it is invalid (wrong `jsonrpc`, missing or unknown method), because a notification can never be answered.
- A JSON array (a batch) or any other non-object body is answered with an Invalid Request error (-32600).
- The stream sends a `: heartbeat` comment every 30 seconds while idle and closes after 30 minutes without a message; a client that disconnects is noticed sooner. Heartbeats do not count as activity. One API key can hold at most 5 open streams (the 6th gets HTTP 429) and the server at most 50 (the 51st gets 503); idle sessions are dropped before either limit is checked.

## Protocol

- `initialize` always answers `protocolVersion: "2024-11-05"`, whatever version the client asks for; the client decides whether to continue.
- Declared capabilities: `tools`, `resources` and `prompts`, with no sub-capabilities (no `listChanged`, no `subscribe`).
- Methods handled: `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/templates/list`, `resources/read`, `prompts/list`, `prompts/get`. Anything else is Method not found (-32601). A request whose `method` is not a string is Invalid Request (-32600); `params` that is not an object, or a `name`, `uri` or `arguments` of the wrong type inside it, is Invalid params (-32602). Not implemented: `resources/subscribe`, `logging/setLevel`, `completion/complete`.
- A tool that fails validation (a missing or non-string required argument, which the error names; bad address; missing, non-integer or unsupported `chain_id`; unknown tool name) returns a result with `isError: true` and `{"error": "..."}` as its text, delivered on the stream like any other result, and no analysis runs.

## Authentication

- Both `/mcp/sse` and `/mcp/messages` require an `X-API-Key` header. Without a valid key the request is refused (401 or 403).
- Keys start with `sb_`. They are issued by an administrator only: `POST /api/keys` with the `X-Admin-Secret` header. There is no self-service signup, so an outside user cannot get a key today.
- Every request made with a key counts against that key's per-minute and daily limits (free tier 60 per minute and 1,000 per day, pro tier 300 and 50,000). Opening a stream counts once; each POST counts once. Over the limit the API answers 429.

## Tools (9)

Every tool result is JSON in a single `text` content item.

| Tool | Required arguments | Notes |
|------|--------------------|-------|
| `scan_contract` | `address`, `chain_id` | All analyzers and the risk engine. Incomplete coverage gives `status: "unknown"`, `verdict: "UNKNOWN"`, `risk_display: "Unknown (incomplete provider coverage)"` and `coverage_reasons`. |
| `simulate_transaction` | `from`, `to`, `data`, `chain_id` | Tenderly simulation. `from` and `to` must be addresses; the optional `value` is wei as a decimal or `0x` hex string (default `"0"`), and anything else is a tool error rather than a simulation with value 0. Approval changes are not measured (`approvals_granted` is always null), so every result is `status: "unknown"` with `coverage_reasons.approvals`. When Tenderly is not configured or the simulation fails, `coverage_reasons.simulation` says so and every measurement is null. |
| `check_deployer` | `address`, `chain_id` | Local deployer index. Always `status: "unknown"`: see below. An unindexed contract has null counts. Counts span every chain the deployer is indexed on, and `flagged_count` counts only contracts with a stored HIGH score. `funded_by` is always null. |
| `check_agent_reputation` | `agent_id` | Block rate over at most 1,000 local firewall records. An unregistered agent, or one with no firewall history, gives `status: "unknown"` with null `trust_score` and `block_rate`. |
| `check_approval_risk` | `wallet_address`, `chain_id` | Not implemented: always `status: "unknown"` with null `approvals`. |
| `scan_for_injection` | `content` | A fixed regex list. `clean: true` means no listed pattern matched, not that the text is safe. |
| `query_threat_graph` | `address`, `chain_id` | Not implemented: always `status: "unknown"` with null connections. |
| `get_threat_feed` | none | Latest agent findings (`limit` 1 to 100, default 20). |
| `get_robinhood_launches` | none | Robinhood Chain (4663) launches with their latest scan outcome; `chain_id` defaults to 4663, the only chain with launch discovery. `unknown` and `not_scanned` launches are never safe. Page with `next_cursor`. |

`chain_id` has no default on the address and transaction tools: a call without it is a tool error, and so is a chain the API does not support. Supported chains are the ones the API registers an adapter for, including 56 (BNB Chain) and 4663 (Robinhood Chain).

Two tools never answer `status: "ok"`, even when they succeed, because part of what they report is never measured:

- `simulate_transaction` does not measure approval changes, so a clean simulation says nothing about approvals it grants.
- `check_deployer` reads an index that holds only contracts ShieldBot has scanned. The deployer's other contracts are not in it, so `contracts_deployed` and `flagged_count` are lower bounds, and a `flagged_count` of 0 does not mean the deployer has no flagged contracts.

Adverse findings from either still stand: a reverted simulation, an outgoing asset change or a non-zero `flagged_count` is real.

A tool call:

```json
{"jsonrpc": "2.0", "id": 3, "method": "tools/call",
 "params": {"name": "scan_contract", "arguments": {"address": "0x...", "chain_id": 4663}}}
```

## Resources (3)

| URI | Listed by | Content |
|-----|-----------|---------|
| `shieldbot://threat-feed` | `resources/list` | The 50 latest agent findings. |
| `shieldbot://agent/{agent_id}/health` | `resources/templates/list` | Policy and the 20 latest firewall verdicts of a registered agent. |
| `shieldbot://wallet/{address}/guardian` | `resources/templates/list` | Not implemented: always `status: "unknown"` with null `approvals`. |

The two parameterised resources are URI templates (`uriTemplate`); substitute the value before calling `resources/read`.

## Prompts (2)

- `security-analysis` (optional `contract_address`, `transaction_hash`): steps that call `scan_contract`, `check_deployer` and `simulate_transaction`, and ask for an UNKNOWN verdict when coverage is incomplete.
- `agent-evaluation` (required `agent_id`): steps that call `check_agent_reputation` and read the agent health resource.

## Connecting a client

The snippets follow each client's documentation as checked on 2026-09-24. None of them has been run against this server end to end. Replace `sb_...` with a real key.

**Claude Code**

```bash
claude mcp add --transport sse shieldbot https://api.shieldbotsecurity.online/mcp/sse --header "X-API-Key: sb_..."
```

Add `--scope user` to use it in every project. To share it through a project's `.mcp.json` without committing the key:

```json
{
  "mcpServers": {
    "shieldbot": {
      "type": "sse",
      "url": "https://api.shieldbotsecurity.online/mcp/sse",
      "headers": { "X-API-Key": "${SHIELDBOT_API_KEY}" }
    }
  }
}
```

**Cursor** (`.cursor/mcp.json` in a project, or `~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "shieldbot": {
      "url": "https://api.shieldbotsecurity.online/mcp/sse",
      "headers": { "X-API-Key": "${env:SHIELDBOT_API_KEY}" }
    }
  }
}
```

**Claude Desktop** runs local servers from its config file, so it reaches this server through the [`mcp-remote`](https://github.com/geelen/mcp-remote) bridge (needs Node.js). In `claude_desktop_config.json` (macOS `~/Library/Application Support/Claude/`, Windows `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "shieldbot": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://api.shieldbotsecurity.online/mcp/sse",
        "--transport", "sse-only",
        "--header", "X-API-Key:${SHIELDBOT_API_KEY}"
      ],
      "env": { "SHIELDBOT_API_KEY": "sb_..." }
    }
  }
}
```

`--transport sse-only` stops the bridge from trying Streamable HTTP first. The header has no space after the colon because Claude Desktop on Windows does not escape spaces inside `args`.
