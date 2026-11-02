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

or the packaged bin `metavault-mcp` declared in `packages/mcp/package.json`
(`bin: metavault-mcp`, built by that package's `build` script).

Environment consumed by the server:

| Variable | Default | Purpose |
| --- | --- | --- |
| `METAVAULT_DAEMON_URL` | `http://127.0.0.1:7077` | Daemon HTTP API base URL |
| `METAVAULT_AGENT_ID` | `mcp-agent` | Agent identity presented to the daemon (set per IDE) |
| `METAVAULT_IDE` | `mcp` | IDE label presented to the daemon |
| `METAVAULT_AGENT_TOKEN` | *(none)* | Secret enrollment bearer token proving agent identity to prevent spoofing |

Replace `C:/path/to/metavault-oss` below with your checkout path. Keep the
per-IDE `METAVAULT_AGENT_ID` values: audit and revoke are keyed by them.

## Claude Code

`.mcp.json` in the project root (or `~/.claude.json`):

```json
{
  "mcpServers": {
    "metavault": {
      "command": "node",
      "args": ["C:/path/to/metavault-oss/dist/packages/mcp/src/server.js"],
      "env": {
        "METAVAULT_DAEMON_URL": "http://127.0.0.1:7077",
        "METAVAULT_AGENT_ID": "claude-code",
        "METAVAULT_AGENT_TOKEN": "ov_agent_claude_xxxxxxxx",
        "METAVAULT_IDE": "Claude Code"
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
    "metavault": {
      "command": "node",
      "args": ["C:/path/to/metavault-oss/dist/packages/mcp/src/server.js"],
      "env": {
        "METAVAULT_DAEMON_URL": "http://127.0.0.1:7077",
        "METAVAULT_AGENT_ID": "cursor",
        "METAVAULT_AGENT_TOKEN": "ov_agent_cursor_xxxxxxxx",
        "METAVAULT_IDE": "Cursor"
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
    "metavault": {
      "type": "stdio",
      "command": "node",
      "args": ["C:/path/to/metavault-oss/dist/packages/mcp/src/server.js"],
      "env": {
        "METAVAULT_DAEMON_URL": "http://127.0.0.1:7077",
        "METAVAULT_AGENT_ID": "vscode",
        "METAVAULT_AGENT_TOKEN": "ov_agent_vscode_xxxxxxxx",
        "METAVAULT_IDE": "VS Code"
      }
    }
  }
}
```

## Codex

`~/.codex/config.toml`:

```toml
[mcp_servers.metavault]
command = "node"
args = ["C:/path/to/metavault-oss/dist/packages/mcp/src/server.js"]

[mcp_servers.metavault.env]
METAVAULT_DAEMON_URL = "http://127.0.0.1:7077"
METAVAULT_AGENT_ID = "codex"
METAVAULT_IDE = "Codex"
```

## OpenCode

`opencode.json` in the project root (or the global OpenCode config):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "metavault": {
      "type": "local",
      "command": ["node", "C:/path/to/metavault-oss/dist/packages/mcp/src/server.js"],
      "enabled": true,
      "environment": {
        "METAVAULT_DAEMON_URL": "http://127.0.0.1:7077",
        "METAVAULT_AGENT_ID": "opencode",
        "METAVAULT_IDE": "OpenCode"
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
