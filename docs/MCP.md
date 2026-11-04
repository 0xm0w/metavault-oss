# MetaVault OSS MCP Server

MetaVault OSS ships a stdio MCP server that IDE hosts launch as a local process.
It is a thin adapter over the vault daemon (`vaultd`, `127.0.0.1:7077`): it
never sees secret values, validates tool inputs, forwards calls to the
daemon, and returns the daemon result verbatim.

Current source version: `0.1.2-alpha` (reported as `serverInfo.version` in the
MCP handshake; exported in code as `MCP_VERSION` from
`packages/mcp/src/server.ts`).

Tools (exactly eight): `request_capability`, `list_aliases`,
`request_enrollment`, `enrollment_status`, `revoke`.

## Installed Windows app (no source checkout or separate Node required)

The installed app ships `resources/vaultd/mcp.cjs`. In MetaVault OSS, open
Settings > Daemon > Agent Integration & MCP, select your host, and copy its config.
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

The installed path has been tested in actual VS Code1.144.1 on disposable Windows:
`lm.invokeTool(request_capability)` reaches an awaiting-approval request whose daemon
identity is verified. This is not proof for other IDEs, their model chat behavior or
macOS/Linux installation. `list_aliases` alone is an open read and does not prove
agent authentication. See [verification](VERIFICATION.md).

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

In Settings > Daemon > Agent Integration & MCP, generate a token for an inactive host,
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

## Learning the outcome of a request

`request_capability` waits a short time (about 20 seconds) for the user's decision when approval is needed. It then returns one of:

- `executed`: the call ran, and the result is included once. The credential itself is never returned.
- `denied`, `expired`, `revoked`: final. Nothing ran. The agent should stop and ask the user, not retry or look for another route.
- `awaiting-approval` with `timedOut`: still pending. This is not a denial. Call `grant_status` with the `grantId`.

`grant_status` reads the outcome with a request-scoped receipt that only the MCP process that made the request holds. A grant id, an agent name or an agent token alone reads nothing. An approved result is kept by vaultd for at most 5 minutes, handed over once to the holder of that receipt, and discarded if the agent is revoked or its credential changes first. `unavailable` (daemon or network problem) and `unknown` (this session did not make that request) are not decisions.

## Verified agents

An unverified agent is flagged on every request. To become a Verified agent, the agent calls `register_agent`, tells the user the 6-digit code it returns, and the user approves the matching request in MetaVault OSS by typing that code. The agent's MCP process then calls `registration_status` and receives its own credential, which it keeps in an owner-only file (`~/.metavault/agents/<agent id>.token`; on Windows the inherited permissions are removed and only the current user is granted access, and the credential is not stored if that fails). The credential never passes through the model, logs or the clipboard.

What this proves, and what it does not:

- Verified means the user approved this agent's credential, and the process holding it is the one that asked (it proved this with a claim secret only it knows).
- It does not prove which program the agent is, or who published it. A different local program that reads the same file as the same user could use the credential.
- It grants no capability. Every request still needs its own approval.
- A hostile local process can hold an agent id as "pending" for up to 10 minutes. It cannot obtain a credential without the user approving the exact request. The user can deny it. Claims are single-use, five wrong claims cancel the registration, and registrations are rate limited.
- Remote devices keep their own pairing. Registration routes are not exposed through the gateway.

## Adding a token from the IDE

`request_enrollment` opens MetaVault OSS on the user's computer (`metavault://add?...`) with the add form prefilled and the secure input ready, and returns `launched: true`. The user types the token in MetaVault only. If the app could not be opened, or the daemon is not on the same machine, the link is returned instead.
