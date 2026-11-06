# MetaVault OSS MCP server

Thin MCP adapter over the `vaultd` HTTP API. It never sees secrets: it
validates tool inputs with the shared Effect Schemas from
`packages/daemon/src/schemas.ts`, forwards calls to the daemon with plain
`fetch`, and returns the daemon's structured result verbatim (including
`awaiting-approval` with `grantId` + `metavault://approve` deeplink, or
`vault-locked` with `metavault://unlock`).

## Surface

- **Handshake `instructions`:** Automatic agent workflow & zero-secret rules injected during MCP initialization.
- **Tools (8):**
  - `list_aliases()` — lists credential aliases, `scopeCeiling`, `baseUrl`, `authStyle`, and `supportedTools`.
  - `request_capability({alias, scope, reason, tool?, payload?})` — requests a scoped capability (`rest.call`, `graphql.call`, `cloudflare.dns`, `stripe.charge.list`).
  - `grant_status({grantId})` — polls a pending capability grant using the session receipt.
  - `request_enrollment({alias, scope, website?, reason?})` — opens `metavault://add?...` so the user enters a missing credential directly in MetaVault OSS.
  - `enrollment_status({enrollmentId})` — long-polls (`waitMs`) until the user saves or cancels the enrollment.
  - `register_agent({agentId?, name?})` — starts 6-digit verified-agent registration (`metavault://register?...`).
  - `registration_status({registrationId})` — long-polls (`waitMs`) and claims the verified agent token into an owner-only file.
  - `revoke({target})` — revokes an agent or alias session.
- **Resources:** `metavault://context/guide`, `metavault://context/status`
- **Prompts:** `use-secret`, `enroll-secret`

## Run

```bash
npx tsc -p tsconfig.json --outDir dist   # once, from the repo root
node dist/packages/mcp/src/server.js     # stdio MCP server
```

Environment: `METAVAULT_DAEMON_URL` (default `http://127.0.0.1:7077`),
`METAVAULT_AGENT_ID` (default `mcp-agent`), `METAVAULT_IDE` (default `mcp`),
`METAVAULT_AGENT_TOKEN` (optional enrollment bearer token).

See [docs/MCP.md](../../docs/MCP.md) for host-specific configurations across
Claude Code, Cursor, Antigravity, VS Code, Codex, and OpenCode.
