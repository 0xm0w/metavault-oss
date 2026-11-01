# MetaVault OSS MCP Server

MetaVault OSS ships a stdio MCP server that IDE hosts launch as a local process.
It is a thin adapter over the vault daemon (`vaultd`, `127.0.0.1:7077`): it
never sees secret values, validates tool inputs, forwards calls to the
daemon, and returns the daemon result verbatim.

Current version: `0.1.0` (reported as `serverInfo.version` in the
MCP handshake; exported in code as `MCP_VERSION` from
`packages/mcp/src/server.ts`).

Tools (exactly five): `request_capability`, `list_aliases`,
`request_enrollment`, `enrollment_status`, `revoke`.

## Prerequisites

1. Start the MetaVault OSS daemon / desktop app so `vaultd` is listening.
2. Build once from the repository root:

```bash
npx tsc -p tsconfig.json --outDir dist
```

Hosts then launch:

```bash
node dist/packages/mcp/src/server.js
```

or the packaged bin `openvault-mcp` declared in `packages/mcp/package.json`
(`bin: openvault-mcp`, built by that package's `build` script).

Environment consumed by the server:

| Variable | Default | Purpose |
| --- | --- | --- |
| `OPENVAULT_DAEMON_URL` | `http://127.0.0.1:7077` | Daemon HTTP API base URL |
| `OPENVAULT_AGENT_ID` | `mcp-agent` | Agent identity presented to the daemon (set per IDE) |
| `OPENVAULT_IDE` | `mcp` | IDE label presented to the daemon |
| `OPENVAULT_AGENT_TOKEN` | *(none)* | Secret enrollment bearer token proving agent identity to prevent spoofing |

Replace `C:/path/to/openvault` below with your checkout path. Keep the
per-IDE `OPENVAULT_AGENT_ID` values: audit and revoke are keyed by them.

## Claude Code

`.mcp.json` in the project root (or `~/.claude.json`):

```json
{
  "mcpServers": {
    "openvault": {
      "command": "node",
      "args": ["C:/path/to/openvault/dist/packages/mcp/src/server.js"],
      "env": {
        "OPENVAULT_DAEMON_URL": "http://127.0.0.1:7077",
        "OPENVAULT_AGENT_ID": "claude-code",
        "OPENVAULT_AGENT_TOKEN": "ov_agent_claude_xxxxxxxx",
        "OPENVAULT_IDE": "Claude Code"
      }
    }
  }
}
```

## Cursor

`~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project):

```json
{
  "mcpServers": {
    "openvault": {
      "command": "node",
      "args": ["C:/path/to/openvault/dist/packages/mcp/src/server.js"],
      "env": {
        "OPENVAULT_DAEMON_URL": "http://127.0.0.1:7077",
        "OPENVAULT_AGENT_ID": "cursor",
        "OPENVAULT_AGENT_TOKEN": "ov_agent_cursor_xxxxxxxx",
        "OPENVAULT_IDE": "Cursor"
      }
    }
  }
}
```

## VS Code

`.vscode/mcp.json` in the workspace (VS Code uses `servers`, not
`mcpServers`):

```json
{
  "servers": {
    "openvault": {
      "type": "stdio",
      "command": "node",
      "args": ["C:/path/to/openvault/dist/packages/mcp/src/server.js"],
      "env": {
        "OPENVAULT_DAEMON_URL": "http://127.0.0.1:7077",
        "OPENVAULT_AGENT_ID": "vscode",
        "OPENVAULT_AGENT_TOKEN": "ov_agent_vscode_xxxxxxxx",
        "OPENVAULT_IDE": "VS Code"
      }
    }
  }
}
```

## Codex

`~/.codex/config.toml`:

```toml
[mcp_servers.openvault]
command = "node"
args = ["C:/path/to/openvault/dist/packages/mcp/src/server.js"]

[mcp_servers.openvault.env]
OPENVAULT_DAEMON_URL = "http://127.0.0.1:7077"
OPENVAULT_AGENT_ID = "codex"
OPENVAULT_IDE = "Codex"
```

## OpenCode

`opencode.json` in the project root (or the global OpenCode config):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "openvault": {
      "type": "local",
      "command": ["node", "C:/path/to/openvault/dist/packages/mcp/src/server.js"],
      "enabled": true,
      "environment": {
        "OPENVAULT_DAEMON_URL": "http://127.0.0.1:7077",
        "OPENVAULT_AGENT_ID": "opencode",
        "OPENVAULT_IDE": "OpenCode"
      }
    }
  }
}
```

## Verify

With the daemon running and the repo built, the two-host gate boots a
daemon plus two independent MCP stdio clients and asserts both hosts can
list aliases, request a capability, and see exactly the five tools above —
without any secret reaching the MCP transcript:

```bash
node scripts/check-mcp-hosts.mjs
```
