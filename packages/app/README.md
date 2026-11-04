# MetaVault OSS desktop app (Electron, Direction B)

A tray-resident Electron shell over `vaultd`. The daemon holds the keys;
this window only shows requests and collects decisions. The renderer is
plain TypeScript and never receives secret values: the daemon's payloads
contain agent, scope, reason, marshal decision, and expiry only, and the
renderer rebuilds every payload from whitelisted fields before rendering.

## Layout

- `src/main.ts` — Electron main: hardened window, tray, close-to-tray.
  Quitting stops a daemon owned by the app; an independently started daemon
  remains independent. Closing the window can hide it to the tray.
- `src/window-options.ts` — window security contract (unit-tested):
  `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`.
- `src/preload.ts` — context bridge exposing only the daemon API calls
  (`request/approve/deny/approveAlways/revoke/aliases/audit/pending`)
  against `http://127.0.0.1:7077` (`METAVAULT_DAEMON_URL` overrides).
- `src/renderer/` — plain TypeScript UI (no `effect`/`@effect/*` imports;
  enforced by ESLint `no-restricted-imports`). Approval hero first, then
  Vault home, Audit, Policies. Direction B tokens in `model.ts`/`styles.css`.

## Daemon additions this app needs

The original daemon API could not surface queued approvals (the audit log
carries no `grantId`), so two additive endpoints were added:

- `GET /pending` → `{ approvals: PendingApproval[] }` (metadata only).
- `POST /approve-always { grantId }` → executes the grant and records a
  standing approval. The daemon re-checks eligibility server-side:
  read-only scope + marshal risk `low`, otherwise `403 PolicyDenied`.

## Installed Windows candidate

The installed app bundles its daemon, CLI and MCP runtime and starts its owned
daemon on launch. Fresh launch shows password setup; later locked launches show
password unlock. Settings > Daemon shows actual vault path and an unlocked key
fingerprint, plus host config and one-time agent generate/rotate/revoke controls.
Copy agent instructions there. No external Node or source checkout is required.

Deliberate uninstall warns then deletes the fixed app profile; Cancel preserves it.
Silent `/S` means the same wipe without a prompt. In-place update preserves data.
Shared legacy keys and links block cleanup before deletion. External/custom data
is not deleted. See [recovery](../../docs/RECOVERY.md).

Windows Hello verifies the app screen lock only, not encryption-key custody.
This is unreleased candidate behavior; see [validation](../../docs/VERIFICATION.md).

## Run from source

```powershell
# 1. Start vaultd (separate terminal), then unlock it with your passphrase
node --experimental-strip-types packages/daemon/src/server.ts  # or the compiled daemon entry
node dist/packages/cli/src/cli.js unlock   # or use the app password screen

# 2. Build the app (CommonJS preload.cjs + renderer assets staged into dist)
npm --prefix packages/app run build

# 3. Launch
npx electron packages/app/dist/main.js
```

Demo rehearsal (brief Step 4, to be timed on the demo machine): seed a
credential, send a fake pending request (`POST /request` or via MCP),
approve it in the app, watch the grant execute and expire; revoke the agent
mid-task and watch the next request deny.
