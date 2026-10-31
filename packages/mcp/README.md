# OpenVault MCP server

Thin MCP adapter over the `vaultd` HTTP API. It never sees secrets: it
validates tool inputs with the shared Effect Schemas from
`packages/daemon/src/schemas.ts`, forwards calls to the daemon with plain
`fetch`, and returns the daemon's structured result verbatim (including
`awaiting-approval` with the `grantId`).

Tools: `request_capability({alias, scope, reason, tool?, payload?})`,
`list_aliases()`, `revoke({target})`.

## Run

```bash
npx tsc -p tsconfig.json --outDir dist   # once, from the repo root
node dist/packages/mcp/src/server.js     # stdio MCP server
```

Environment: `OPENVAULT_DAEMON_URL` (default `http://127.0.0.1:7077`),
`OPENVAULT_AGENT_ID` (default `mcp-agent`), `OPENVAULT_IDE` (default `mcp`).

## IDE config snippet

Paste into the IDE's MCP config (adjust the path and identity per IDE):

```json
{
  "mcpServers": {
    "openvault": {
      "command": "node",
      "args": ["C:/path/to/openvault/dist/packages/mcp/src/server.js"],
      "env": {
        "OPENVAULT_DAEMON_URL": "http://127.0.0.1:7077",
        "OPENVAULT_AGENT_ID": "cursor-agent",
        "OPENVAULT_IDE": "Cursor"
      }
    }
  }
}
```

## Manual IDE gate — PENDING

Task 7 Step 4 (paste the snippet into two demo IDEs, ask each agent to call
`list_aliases`, expect `stripe · charges.read` with no secret in the
transcript) is a manual gate. It has NOT been run yet; the in-process MCP
client test (`test/mcp.test.ts`) and a stdio subprocess smoke cover the
same tool paths automatically. Record the two passing IDEs in the root
README (Task 10) once the manual check is done.
