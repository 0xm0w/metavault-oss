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

## Installed Windows app (no source checkout or separate Node required)

The installed app ships `resources/vaultd/mcp.cjs`. In MetaVault OSS, open
Settings > Agent Integration & MCP, select your host, and copy its config.
The app supplies absolute paths to its own executable and bundled MCP server,
plus `ELECTRON_RUN_AS_NODE=1`, so spaces in the install path and a stale PATH
in an already-running IDE do not require a workaround. Reload the host MCP
connection after changing config. Keep the agent token private.

The installer also includes `bin/metavault-mcp.cmd` and
`bin/metavault-mcp.ps1` for terminal use. The GUI-generated config uses the
executable directly, not a shell wrapper. If paths change after moving the
app, copy a fresh config. Settings also has **Copy agent instructions** for
the static vault workflow. Prompts guide the agent; policy and human approval
enforce access.

The source-checkout examples below are for development, not installed users.

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

## Agent token lifecycle

In Settings > Agent Integration & MCP, generate a token for an inactive host,
or rotate an existing token, then copy the host config during this app session.
Raw tokens are returned only at generation and cannot be retrieved from agent
listings. Restarting the app clears its temporary copy; rotate again if you
need a replacement. A private local SQLite backup is taken before the first hash migration; that backup still contains the old raw agent tokens, so retain it privately or remove it after checking recovery. Existing tokens migrate to SHA-256 hashes and keep working
until rotated. Hashing does not invalidate a token exposed by an older build:
rotate existing tokens and replace the IDE config after upgrading.

Rotation and revocation cancel that agent's pending requests and standing
approvals. Revocation rejects further requests. Rotate a revoked identity to
issue a replacement token. Custom identities can be created in the same panel.

CLI: `metavault agents list`, `metavault agents add <id> --name <name> --out <new-private-file>`,
`metavault agents rotate <id> --out <new-private-file>`, and
`metavault agents revoke <id>`. Tokens are written to an exclusive new file,
never stdout. Keep that file private (the Windows profile ACL applies), install
the token in the host config, then remove the file. Do not put it in chat or
source control. Existing files are not overwritten.

Migration backups are stored next to the DB in a `before-agent-hash` directory.
The directory is private before the snapshot is written: POSIX owner-only or a
Windows ACL granting only the current user and SYSTEM. Keep it while checking
the upgrade. Restoring an old app requires stopping the app/daemon and restoring
the old DB snapshot as a unit, not opening the new schema with an old binary.
Tokens created after the snapshot will not exist in that rollback, and tokens
rotated since it may become valid again. Revoke/rotate affected credentials after
rollback. Delete the backup after validating recovery if you do not need it.
Neither SQLite compaction nor deletion is a promise of forensic disk erasure.
