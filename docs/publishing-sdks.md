# Publishing the SDKs and listing the MCP server

Owner steps. Nothing in this document has been done: no package is published, no account or token was created and nothing was submitted to a directory. Registry and documentation facts were checked on 2026-09-24.

## Where things stand

| Package | Source | Planned name | Registry today |
|---------|--------|--------------|----------------|
| TypeScript SDK | `sdk/` (`package.json`) | `@shieldbot/sdk` 3.0.0 | npm: 404, never published |
| Python SDK | `sdk/python/` (`setup.py`) | `shieldbot` 3.0.0 | PyPI: 404 on `/pypi/shieldbot/json` and `/simple/shieldbot/` |

Both packages build cleanly: `npm pack --dry-run` in `sdk/` lists `LICENSE`, `README.md`, `package.json` and `dist/index.{js,mjs,d.ts,d.mts}`; `python -m build` in `sdk/python/` produces a wheel that contains only the `shieldbot` package and its license, and `twine check` passes on both files. Until you publish, both READMEs tell people to install from the repository.

## Step 0: settle the npm name (decision needed)

`@shieldbot/sdk` cannot be published by you as things stand. The npm scope `shieldbot` already exists and is not yours: `GET https://registry.npmjs.org/-/org/shieldbot/package` returns `{"libshield":"write"}` (`libshield` is maintained by the npm user `wiletki`), while a scope that does not exist returns 404 `Scope not found`. Publishing into a scope needs membership of it.

Names checked on 2026-09-24:

- `shieldbot-sdk` (unscoped): free. No existing package differs from it only by punctuation (`shieldbotsdk`, `shield-bot-sdk`, `shieldbot_sdk`, `shieldbot.sdk` and `shield-botsdk` are all 404).
- `shieldbot` (unscoped): 404, but npm refuses new names that differ from an existing package only by punctuation, and `shield-bot` exists (a 2018 Discord bot). Expect it to be rejected.
- `@gudman/shieldbot-sdk`: free, and `@gudman` is already your publishing scope (`@gudman/backstop-sdk`, `@gudman/warden-guard`).

**Recommendation: publish as `shieldbot-sdk`.** It is what people will search for, it matches the PyPI name, and it depends on nobody else's scope. Unscoped names go to whoever publishes first, so publish soon after deciding. If npm rejects it, use `@gudman/shieldbot-sdk`.

Renaming means changing `"name"` in `sdk/package.json`, the import lines in `sdk/README.md` and the usage comment at the top of `sdk/src/index.ts`, and the SDK snippet in `landing-src/src/components/AgentSecurity.tsx`. Treat the first real publish as the test of whether a name is available to you.

## npm

### One-time setup

1. Sign in to npmjs.com with the account that will own the package and make sure two-factor authentication is on. npm requires 2FA, or a granular token with "Bypass 2FA" enabled, to publish.
2. Do the first release interactively from your own machine: `npm login`, then publish and answer the 2FA prompt. No token is created, so none can leak.
3. For later releases from CI, use trusted publishing instead of a token. It uses GitHub Actions OIDC, needs npm CLI 11.5.1 or later and Node 22.14.0 or later, the workflow needs `permissions: id-token: write`, and it adds provenance for a public repository. It is configured on the package's own settings page (Packages, the package, Settings, Trusted publishing), which is another reason to do the first publish by hand. No release workflow exists in this repository yet.
4. Only if you must use a token: classic tokens were removed in November 2025, so create a granular access token with "Read and write" limited to this one package, a short expiry, an allowed IP range if you publish from a fixed address, and "Bypass 2FA" off unless a CI job needs it. npm's documentation says direct publishing with bypass-2FA tokens ends in January 2027. Put it in `~/.npmrc` as `//registry.npmjs.org/:_authToken=...`, never in the repository.

### Release

```bash
cd sdk
npm ci
npm test                          # compiles and runs tests/*.cjs
npm run lint
npm audit --audit-level=moderate  # the CI gate; one low-severity esbuild advisory is open today
npm pack --dry-run                # prepack rebuilds dist/ from a clean directory; check the file list
npm publish --dry-run
npm publish                       # publishConfig.access is already "public"
```

Then check `npm view <name>` and install the package into an empty project. Once the package exists, npm recommends the package setting "Require two-factor authentication and disallow tokens"; choose it unless you move to trusted publishing. A published version number can never be reused, so bump `version` before every release.

## PyPI

### One-time setup

1. Create an account on pypi.org; two-factor authentication is required. TestPyPI (test.pypi.org) is a separate site with a separate account, useful for a rehearsal.
2. Create an API token on each site. The upload username is `__token__` and the password is the token. A token can cover the whole account or a single project; the project `shieldbot` does not exist until the first upload, so if the scope list does not offer it, use an account-wide token for the first upload, then replace it with a token scoped to `shieldbot` and delete the account-wide one.
3. Alternative for later releases: trusted publishing. For a project that does not exist yet, add a "pending publisher" under Publishing in your account (project name, repository owner, repository name, workflow file, optional environment). A pending publisher does not reserve the name: if someone else registers `shieldbot` first, it is invalidated. This also needs a release workflow the repository does not have yet.

PyPI can refuse a name that is too similar to an existing project; the upload is the definitive check.

### Release

```bash
cd sdk/python
python -m pip install --upgrade build twine
python -m build                   # dist/shieldbot-3.0.0.tar.gz and dist/shieldbot-3.0.0-py3-none-any.whl
python -m twine check dist/*
python -m twine upload --repository testpypi dist/*
```

Rehearse the install in a fresh virtual environment (the extra index supplies `httpx`):

```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ shieldbot
python -c "import shieldbot; print(shieldbot.__version__)"
```

Then upload for real with `python -m twine upload dist/*` and repeat the check with a plain `pip install shieldbot`. PyPI never accepts the same file name twice, even after a deletion, so bump `version` in `setup.py` and `__version__` in `shieldbot/__init__.py` together before every release; `tests/test_sdk_drift.py` fails if they differ.

## After publishing

- Replace the "Install" sections of `sdk/README.md` and `sdk/python/README.md` with the registry commands.
- Update the website copy that says the SDKs are not on npm or PyPI yet: `landing-src/src/components/Channels.tsx` and `landing-src/src/components/AgentSecurity.tsx`, then rebuild `landing/`.

## MCP server

### What it exposes

The API serves an MCP server under `/mcp` (server name `shieldbot-mcp`, version 3.1.0). It speaks the older HTTP+SSE transport and reports protocol version `2024-11-05`.

| Endpoint | Purpose | Auth |
|----------|---------|------|
| `GET /mcp/sse` | Event stream; the first event names the message endpoint (`/mcp/messages?session_id=...`) | `X-API-Key` required (401 without) |
| `POST /mcp/messages?session_id=...` | JSON-RPC 2.0 requests; responses go to the stream and are also returned inline | `X-API-Key` required |
| `GET /mcp/health` | Status and session count | none |

It handles `initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list` and `prompts/get`, with at most 50 open streams and a 5 minute idle timeout.

- Tools (9): `scan_contract`, `simulate_transaction`, `check_deployer`, `check_agent_reputation`, `check_approval_risk`, `scan_for_injection`, `query_threat_graph`, `get_threat_feed`, `get_robinhood_launches`.
- Resources (3): `shieldbot://threat-feed`, `shieldbot://agent/{agent_id}/health`, `shieldbot://wallet/{address}/guardian`.
- Prompts (2): `security-analysis`, `agent-evaluation`.

Limits to state wherever it is listed (details in `docs/TECHNICAL.md`): `check_approval_risk` and `query_threat_graph` are unimplemented and always return `status: "unknown"`; `scan_for_injection` is a fixed regex list; `check_agent_reputation` is a heuristic over local firewall records; every tool that takes `chain_id` except `get_robinhood_launches` defaults it to 56 (BNB Chain) when it is left out, unlike the SDKs. The server does not implement `ping` and answers notifications such as `notifications/initialized` with a method-not-found error. It has not been tested against the clients below; connect each one to a development instance before listing it.

### How a client connects

Every client needs the SSE URL `https://api.shieldbotsecurity.online/mcp/sse` and an `X-API-Key` header. Syntax taken from each client's documentation:

- **Claude Code:**

  ```bash
  claude mcp add --transport sse shieldbot https://api.shieldbotsecurity.online/mcp/sse --header "X-API-Key: sb_..."
  ```

- **Cursor** (`.cursor/mcp.json` in a project or `~/.cursor/mcp.json`):

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

- **Claude Desktop and other clients that only run local (stdio) servers**, through the `mcp-remote` bridge:

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

### Where it could be listed

The official MCP Registry (registry.modelcontextprotocol.io) accepts remote-only servers:

1. Install `mcp-publisher` (a release binary from github.com/modelcontextprotocol/registry, or `brew install mcp-publisher`).
2. Run `mcp-publisher init` to generate `server.json`, then describe the hosted server with a `remotes` entry and no `packages`:

   ```json
   "remotes": [{
     "type": "sse",
     "url": "https://api.shieldbotsecurity.online/mcp/sse",
     "headers": [{
       "name": "X-API-Key",
       "description": "ShieldBot API key",
       "isRequired": true,
       "isSecret": true
     }]
   }]
   ```

3. Prove the namespace. `mcp-publisher login github` grants `io.github.<your GitHub user>/...`. For a name under the domain (`online.shieldbotsecurity/...`), use `mcp-publisher login dns` with a TXT record on the apex of shieldbotsecurity.online, or `mcp-publisher login http` with a file at `https://shieldbotsecurity.online/.well-known/mcp-registry-auth`.
4. Run `mcp-publisher publish`.

The registry marks `sse` as deprecated in favour of `streamable-http`, which this server does not implement.

**Recommendation: do not list the server yet.** API keys are created only through `POST /api/keys` with the admin secret, so anyone who finds a listing has no way to use it. List it once there is a way for outsiders to get a key; adding the Streamable HTTP transport first would also avoid launching on a deprecated one. Both are your decisions.
