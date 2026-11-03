# MetaVault OSS desktop app (Electron, Direction B)

A tray-resident Electron shell over `vaultd`. The daemon holds the keys;
this window only shows requests and collects decisions. The renderer is
plain TypeScript and never receives secret values: the daemon's payloads
contain agent, scope, reason, marshal decision, and expiry only, and the
renderer rebuilds every payload from whitelisted fields before rendering.

## Layout

- `src/main.ts` — Electron main: hardened window, tray, close-to-tray.
  Quitting from the tray stops only the UI; `vaultd` keeps queueing
  approvals (bounded by grant TTL) until the UI or CLI next connects.
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

## Run (manual gate — pending, see task-9 report)

```powershell
# 1. Start vaultd (separate terminal), then unlock it with your passphrase
node --experimental-strip-types packages/daemon/src/server.ts  # or the compiled daemon entry
node dist/packages/cli/src/cli.js unlock   # the app has no passphrase screen yet

# 2. Build the app (CommonJS preload.cjs + renderer assets staged into dist)
npm --prefix packages/app run build

# 3. Launch
npx electron packages/app/dist/main.js
```

Demo rehearsal (brief Step 4, to be timed on the demo machine): seed a
credential, send a fake pending request (`POST /request` or via MCP),
approve it in the app, watch the grant execute and expire; revoke the agent
mid-task and watch the next request deny.
