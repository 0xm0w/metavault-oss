# MetaVault OSS — Implementation Spec: Agent Speed, Deep-Linking, Context & Desktop Tray/Toast/Audio UX

**Status:** Ready for Agent Execution  
**Target Codebase:** `metavault-oss` (`0.1.4-alpha`+)  
**Scope Boundary:** Another agent is concurrently addressing the core **P0 / P1 / P2 security findings** (`SEC-01` through `SEC-12` — redirect stripping, `ide-config` IPC sanitization, `process.env` token isolation, `approveSession` / `isWriteScope` hardening, Windows ACLs, crypto tag/KDF bounds, etc.). **Do NOT re-implement or revert those security fixes.** If you touch shared files (`packages/connectors/src/http.ts`, `packages/daemon/src/server.ts`, `packages/daemon/src/service.ts`, `packages/app/src/main.ts`, `packages/app/src/renderer/main.ts`), preserve all security guards and merge cleanly.

---

## 0. Confirmed Product Decisions & Repo Constraints

### Confirmed Product Decisions (Locked In)
1. **Workspace Artifact & Build Cleanup:** Delete local dev `openvault.db`, `openvault.key`, and `openvault.token` from the repository root (if still present), harden `.gitignore` for `metavault.*` / SQLite WAL / backup artifacts, and clean `packages/app/dist/` prior to builds so stale deleted `.js` modules are never packaged into `app.asar`.
2. **Two Explicit Lock Options:** Provide **two distinct, clearly labeled lock actions** everywhere locking is surfaced (App Header lock dropdown, Settings > Security, Tray Flyout, and Tray Right-Click Menu):
   * **`Lock UI`** — Locks the desktop window + tray flyout behind Windows Hello / App PIN, while keeping `vaultd`'s master key unlocked in memory so pre-authorized read-only standing approvals continue executing seamlessly for background IDE agents.
   * **`Lock Vault Daemon`** — Calls `POST /lock` on `vaultd` (zeroing the master key in daemon memory and halting all secret execution until passphrase unlock) **and** locks the UI.
3. **Standard Desktop Wallet Tray Pattern (1Password / Bitwarden / Tailscale convention):**
   * **Windows / Linux Left-Click on Tray Icon:** Toggles a compact `360×480` frameless **Tray Flyout popover** anchored to the tray icon for 1-click status, quick Approve/Deny, and Lock controls without covering the IDE.
   * **Right-Click on Tray Icon:** Opens the native OS **Context Menu** (`Menu.buildFromTemplate`) with status summary, pending count, Add Credential, `Lock UI`, `Lock Vault Daemon`, `Mute Notification Sounds`, `Start Minimized at Login`, `Open MetaVault OSS`, and `Quit MetaVault OSS`.
   * **macOS Nuance:** Do **not** call `tray.setContextMenu(menu)` on `darwin` (Electron intercepts left-click when `setContextMenu` is set on macOS). Instead, bind `tray.on("click")` to toggle the Tray Flyout and `tray.on("right-click", () => tray.popUpContextMenu(menu))` for the context menu.
4. **Non-Intrusive Approval Alerts by Default:**
   * Default behavior on new pending approvals / agent registrations is **OS Toast Notification + Dynamic Tray Badge + Taskbar Flash (`window.flashFrame(true)`) + Synthesized Audio Chime** — **NO focus-stealing `bringToFront()` window pop** unless the user clicks the toast/tray OR explicitly enables `"Pop window to front on pending approval"` (default `false`) in Settings.
   * **Never auto-focus `.btn-approve`**, and enforce a **500ms focus-activation guard** after window/flyout focus so an in-flight `Enter` or `Space` keystroke can never accidentally approve a grant.

### Strict Compiler & Lint Invariants (`eslint.config.js` & `tsconfig.json`)
* **No `console.*` in backend/CLI/MCP packages:** `packages/{core,brain,connectors,daemon,mcp,cli}/**/*.ts` enforces `"no-console": "error"`.
* **No `effect` in Electron renderer:** `packages/app/src/renderer/**/*.ts` enforces `"no-restricted-imports"` banning `effect` and `@effect/*`. Keep all renderer code pure TypeScript + DOM APIs.
* **Strict TypeScript flags:** `exactOptionalPropertyTypes: true`, `noUncheckedIndexedAccess: true`, `noPropertyAccessFromIndexSignature: true`, `@typescript-eslint/no-floating-promises: "error"`, `@typescript-eslint/no-explicit-any: "error"`.
* **Preload build output:** Electron preload must compile to CommonJS `preload.cjs` (`tsconfig.preload.json`).

---

## Workstream 1: Workspace Hygiene & Clean App Builds

*(Skip any item below already completed by the P0–P2 security branch.)*

1. **Root Cleanup & `.gitignore` (`/.gitignore`):**
   * Delete untracked local throwaway files `openvault.db`, `openvault.key`, and `openvault.token` from repo root if present.
   * Ensure `.gitignore` covers:
     ```gitignore
     *.db
     *.db-wal
     *.db-shm
     *.db-journal
     *.token
     *.key
     *.key.json
     *.before-agent-hash*
     .env
     .env.*
     !.env.example
     .dev.vars
     .wrangler/
     packages/app/dist/
     packages/app/release/
     ```
2. **Clean `packages/app/dist` on Build (`packages/app/package.json`):**
   * Update `"build"` in `packages/app/package.json` (line 18) to remove `dist/` before running `tsc` (e.g., `node -e "require('node:fs').rmSync('dist',{recursive:true,force:true})"` prior to `tsc -p tsconfig.preload.json && tsc -p tsconfig.json && node scripts/copy-assets.mjs`) so deleted legacy files (`dist/builtin-ai-ipc.js`, `dist/model-downloader.js`, etc.) never ship inside `app.asar`.
   * Ensure `pack:mac` and `pack:win:store` (lines 20–21) also run `npm run build && npm run bundle` beforehand, and add `"!**/*.db*"`, `"!**/*.key*"`, `"!**/*.token"`, `"!**/*.log"`, `"!**/*.map"` to `build.files`.

---

## Workstream 2: Custom Connectors & Sub-10ms Agent Speed

### 2.1 Unblock Non-Preset Custom Connectors
* **Files:** `packages/connectors/src/http.ts` (`lines 475-597`), `packages/app/src/renderer/model.ts` (`lines 122-156`)
* **Problem:** `makeConnectorLive` checks `const url = presets[alias]; if (url === undefined) return Effect.fail(... "UnknownAlias")` at lines 483–490 **before** reaching `dynamicTool` (`rest.call`, `graphql.call`, or `route?.baseUrl`) at lines 554–588. Any credential outside `stripe`, `github`, `cloudflare` currently fails 100% of the time with `UnknownAlias`. Additionally, `normalizeWebsite()` in `packages/app/src/renderer/model.ts` strips `https://` and base paths (like `/v1`), breaking `new URL(baseUrl)` in `resolveScopedRest`.
* **Required Changes:**
  1. In `makeConnectorLive` (`packages/connectors/src/http.ts`), run the `isCardSecretPayload(secret)` guard first, then check fixed `toolRoutes`, `cloudflare.dns`, and `dynamicTool` (`tool === "rest.call" || tool === "graphql.call" || (baseUrl !== "" && isRestPayload(payload))`) **before** requiring `presets[alias]`.
  2. If `payload === undefined` and `presets[alias]` is `undefined` but `baseUrl !== ""` is a valid `https://` URL (or loopback `http://`) and `isReadScope(scope)` holds, either execute `GET baseUrl` or fail with an actionable message: `'NoDefaultEndpoint: pass tool "rest.call" with { method, path } or "graphql.call" with { query }'`. Only return `UnknownAlias` when neither `presets[alias]` nor `baseUrl` exists.
  3. In `packages/app/src/renderer/model.ts` & `packages/app/src/renderer/main.ts`, preserve full `https://host[:port][/basePath]` URLs on credential add/edit (only default bare hostnames like `api.openai.com` -> `https://api.openai.com` when used as `baseUrl`, without stripping `/v1` or `https://`).

### 2.2 Eliminate Daemon Request Latency Bottlenecks
* **Files:**
  * `packages/daemon/src/server.ts` (`lines 1186-1191`, `1701-1748`)
  * `packages/daemon/src/process-inspector.ts` (`lines 100-145`)
  * `packages/core/src/storage.ts` (`lines 237-320`, `500-590`)
  * `packages/daemon/src/service.ts` (`lines 620`, `1264-1295`, `1340-1495`)
  * `packages/brain/src/rules.ts` (`lines 61`, `104-128`)
  * `packages/brain/src/bft.ts` (`lines 62-105`)
  * `packages/app/src/renderer/model.ts` (`lines 241-302`)
* **Required Changes:**
  1. **Stop Unconditional Synchronous `tasklist` Spawns (`50–300ms` saved per call on Windows):**
     * In `packages/daemon/src/server.ts:1186-1191`, do **not** call `inspectProcess(clientPid)` when `secSettings.verifyCallerProcess === false`.
     * Convert `inspectProcess` (`packages/daemon/src/process-inspector.ts`) from blocking `execSync` to async `execFile` and add a bounded in-memory LRU/TTL cache (`Map<number, { result: ProcessInspectionResult; expiresAt: number }>`, max 256 entries, 30s TTL).
  2. **Enable SQLite WAL + Replace `O(N)` `store.listAudit()` Scan (`5–100ms+` saved per call):**
     * In `makeStore` (`packages/core/src/storage.ts:238`), set `db.pragma("journal_mode = WAL"); db.pragma("synchronous = NORMAL"); db.pragma("busy_timeout = 5000");` (skip WAL only for `:memory:` DBs if needed).
     * Add schema index: `CREATE INDEX IF NOT EXISTS idx_audit_agent_ts ON audit(agent, ts);`.
     * Add a dedicated `VaultStore` method `getAgentAuditStats(agentId: string, since1hIso: string, since24hIso: string)` using a prepared `SELECT` aggregate query, replacing `yield* store.listAudit()` inside `requestCapability` (`packages/daemon/src/service.ts:1264`).
  3. **Make Read-Only Standing Approvals & Session Leases Hit `<5ms` Fast Path:**
     * **Fix `rules.ts` false-positive medium risk:** In `packages/brain/src/rules.ts:104-106`, do **not** emit a risk-elevating `"carries-declared-http-method"` signal when `payload.declaredMethod` is `"GET"` or `"HEAD"`; only mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`, `PATCH`) should elevate risk. Likewise, do not elevate `standingFastPath` read requests to `"medium"` solely because `reason` names an API hostname (`api.cloudflare.com`).
     * **Persist Standing Approvals in SQLite:** Add a `standing_approvals` table in `packages/core/src/storage.ts` (`agent_id TEXT, alias TEXT, scope TEXT, verified_only INTEGER, created_at TEXT, PRIMARY KEY (agent_id, alias, scope)`) loaded into `service.ts` on boot, written on `approveAlways`, and pruned when an agent or credential is revoked/deleted.
     * **Session Lease Fast Path & UI Fix:** Check valid low-risk read-only `sessionLeases` alongside `standingFastPath` (`service.ts:1345`) so 15-minute leases skip the LLM Marshal call too. In `projectApproval` (`packages/app/src/renderer/model.ts:241-302`), project `verified: typeof r["verified"] === "boolean" ? r["verified"] : false` so verified agents display the **Verified** badge and unlock the `"Approve for 15 minutes"` / `"Always allow"` buttons in the UI!
  4. **Parallelize BFT & Cache Warden Config:**
     * In `packages/brain/src/bft.ts:62-95`, execute `deps.cloud(...)` and `deps.local(...)` concurrently via `Effect.all([cloudEffect, localEffect], { concurrency: 2 })` instead of sequentially.
     * In `packages/daemon/src/server.ts:1701-1748`, cache `warden_settings` and the decrypted `warden-meta-api` key in memory while unlocked, invalidating the cache (and `.fill(0)`ing any buffer copy) on `PATCH /settings/warden`, `PUT`/`DELETE /settings/warden/key`, and `POST /lock` / auto-lock.

### 2.3 Zero-Polling Human-in-the-Loop Lifecycle
* **Files:**
  * `packages/daemon/src/service.ts` (`lines 486`, `571-612`, `904`, `1029-1075`)
  * `packages/daemon/src/registrations.ts` (`lines 114-141`)
  * `packages/daemon/src/server.ts` (`lines 877-887`, `1232-1263`, plus new `GET /events`)
  * `packages/mcp/src/server.ts` (`lines 271-320`, `388-392`, `434-460`)
* **Required Changes:**
  1. **Add Daemon SSE Event Stream (`GET /events`):**
     * Expose token-guarded (`x-metavault-token`) Server-Sent Events endpoint `GET /events` on `vaultd` (`Content-Type: text/event-stream`, `Cache-Control: no-cache`, 15s `: keepalive\n\n` heartbeat).
     * Emit lightweight JSON events (never containing secrets!) whenever state changes:
       * `pending.changed` (`{ pendingCount, addedGrantId?, risk?, origin? }`)
       * `registration.changed` (`{ pendingRegistrationsCount, addedRegistrationId? }`)
       * `enrollment.changed` (`{ enrollmentId, status }`)
       * `vault.lock_changed` (`{ daemonLocked: boolean }`)
       * `audit.appended` (`{ requestId, stage }`)
  2. **Eliminate 50ms Busy-Poll in `waitForGrant`:**
     * In `packages/daemon/src/service.ts:578-612`, if `existing.status === "executed"` while `grantExecution.has(id)` is still in flight, await completion of `grantExecution.get(id)` (up to `waitMs`) before returning, so `packages/mcp/src/server.ts:316` receives `{ status: "executed", terminal: true }` in one long-poll round-trip instead of polling every 50ms.
  3. **Raise Grant TTL to 180s:**
     * Increase `DEFAULT_GRANT_TTL_MS` in `packages/daemon/src/service.ts:486` from `60_000` (60s) to `180_000` (180s) so users have time to see a toast, unlock the vault/UI if needed, read the Warden assessment, and click Approve.
  4. **Add Long-Polling (`?waitMs=25000`) to `enrollment_status` and `registration_status`:**
     * Support `?waitMs=0..25000` on `GET /enrollments/:id` (`daemon/src/server.ts:877`) and `waitMs?: number` on `POST /agent-registrations/:id/claim` (`daemon/src/registrations.ts:114`).
     * Update `enrollment_status` and `registration_status` in `packages/mcp/src/server.ts` to default to `waitMs = 20_000` so an agent waits silently on one tool call while the human pastes the secret or enters the 6-digit verification code — **zero wasted LLM turns**.

---

## Workstream 3: Deep-Linking (`metavault://`) & First-Turn Agent Context

### 3.1 Cross-Platform Protocol Packaging & Multi-Route Deep-Linking
* **Files:**
  * `packages/app/package.json` (`build` section)
  * `packages/app/src/main.ts` (`lines 59-71`, `122-136`, `198-205`, `240-261`)
  * `packages/app/src/deeplink.ts` (`lines 1-111`)
  * `packages/app/src/preload.ts` (`lines 83-99`)
  * `packages/app/src/renderer/main.ts` (`lines 4791-4835`)
  * `packages/app/scripts/installer.nsh`
* **Required Changes:**
  1. **OS Packaging Registration:**
     * Add to `packages/app/package.json` under `"build"`:
       ```json
       "protocols": [
         {
           "name": "MetaVault OSS",
           "schemes": ["metavault", "openvault"]
         }
       ]
       ```
     * In `packages/app/src/main.ts:61-67`, register both `"metavault"` and legacy `"openvault"` schemes, using `[resolve(script)]` (`import { resolve } from "node:path"`) when `process.defaultApp` is true on Windows.
     * In `packages/app/scripts/installer.nsh` (`customUnInstall`), clean up `HKCU\Software\Classes\metavault` and `HKCU\Software\Classes\openvault`.
  2. **Expand `VaultDeeplink` Discriminated Union (`packages/app/src/deeplink.ts`):**
     * Accept both `metavault:` and `openvault:` protocols (fixing the duplicate `url.protocol !== "metavault:"` bug at line 49), enforce `MAX_URL_LENGTH = 2048`, reject ASCII control chars and Unicode Bidi overrides (`[\u0000-\u001f\u007f\u200e\u200f\u202a-\u202e\u2066-\u2069]`), reject duplicate search params, and parse these 6 routes:
       ```ts
       export type VaultDeeplinkAction =
         | {
             readonly kind: "add";
             readonly alias: string;
             readonly scope: string;
             readonly website: string;
             readonly enrollmentId: string;
           }
         | { readonly kind: "approve"; readonly grantId: string }
         | { readonly kind: "register"; readonly registrationId: string }
         | { readonly kind: "unlock"; readonly target: "ui" | "daemon" | "auto" }
         | { readonly kind: "audit"; readonly requestId: string }
         | {
             readonly kind: "settings";
             readonly section: "warden" | "agents" | "security" | "notifications" | "connections";
           };
       ```
     * Keep backward compatibility for `DEEPLINK_CHANNEL` (or introduce `metavault:deeplink` while keeping `onDeeplinkAdd` working for existing tests in `packages/app/test/`).
     * If `uiLocked` or `daemonLocked` is active when a deeplink arrives (other than `unlock`), stash `pendingNavigation` in memory, show the Unlock prompt, and automatically route to the target modal/card/tab immediately after unlock succeeds.
  3. **Return & Launch Deep-Links from MCP (`packages/mcp/src/server.ts`):**
     * `request_capability` returning `awaiting-approval` (`timedOut: true`): include `deeplink: "metavault://approve?grantId=<grantId>"` in `structuredContent` and the `instruction` text so the agent can render a clickable link in chat if the user missed the toast.
     * `request_capability` when `vaultd` reports `vaultLocked: true`: return `{ status: "vault-locked", grantId?, deeplink: "metavault://unlock?target=daemon", instruction: "..." }` (and optionally launch `metavault://unlock` on loopback).
     * `register_agent`: return `deeplink: "metavault://register?registrationId=<id>"` and auto-launch on loopback (updating `defaultLaunchDeeplink` allowlist regex in `packages/mcp/src/server.ts:42` to permit `^metavault://(add|approve|register|unlock)\?[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$`).

### 3.2 Complete First-Turn Agent Context in MCP
* **Files:**
  * `packages/mcp/src/server.ts` (`lines 59-165`, `327-492`)
  * `packages/daemon/src/server.ts` (`lines 640-655`, `1080-1115`)
  * `packages/app/src/renderer/onboarding.ts` (`lines 15-63`)
  * `packages/mcp/SKILL.md`, `packages/mcp/README.md`, `docs/MCP.md`, `README.md`
* **Required Changes:**
  1. **Populate MCP `ServerOptions.instructions` (`packages/mcp/src/server.ts:403-409`):**
     Pass a concise (<1,500 chars), high-signal `instructions` string to `new Server({ name: "metavault", version: MCP_VERSION }, { capabilities: { tools: {}, resources: {}, prompts: {} }, instructions: METAVAULT_MCP_INSTRUCTIONS })` covering:
     * **Golden rule:** Never ask the user to paste raw API keys, tokens, or card details into chat or `.env` files. MetaVault executes calls inside `vaultd` and returns only results.
     * **Fast workflow:** Call `list_aliases` first to inspect each credential's `alias`, `scopeCeiling`, `baseUrl`, `authStyle`, and `supportedTools`.
     * **Scope rule:** Scopes use `<resource>.read` (for `GET`/`HEAD`/GraphQL queries) or `<resource>.write` (for `POST`/`PUT`/`PATCH`/`DELETE`/GraphQL mutations) matching the resource prefix in `scopeCeiling` (e.g. ceiling `charges.write` allows `charges.read` or `charges.write`).
     * **Tool & payload shapes:**
       * Preset verify/read (`stripe`, `github`, `cloudflare`): omit `tool` & `payload`.
       * Website-pinned REST (`tool: "rest.call"`): `payload: { method: "GET"|"POST"|"PUT"|"PATCH"|"DELETE", path: "/v1/...", query?: { k: "v" }, body?: {...} }`.
       * Website-pinned GraphQL (`tool: "graphql.call"`): `payload: { query: "...", variables?: {...}, operationName?: "..." }`.
       * Cloudflare DNS (`alias: "cloudflare"`, `tool: "cloudflare.dns"`): `payload: { method, path: "/zones/<32hex>/dns_records", query?, body? }`.
       * Cloudflare Analytics (`alias: "cloudflare"`, `tool: "cloudflare-graphql.analytics"`): `payload: { query, variables }`.
     * **Async recovery:**
       * `status === "awaiting-approval"` with `timedOut: true` -> share `metavault://approve?grantId=...` if helpful and call `grant_status({ grantId })`.
       * `status === "vault-locked"` -> share `metavault://unlock` and wait for the user to unlock before calling `grant_status` / retrying.
       * Missing alias -> call `request_enrollment({ alias, scope, website })` (opens `metavault://add` on user's desktop), then call `enrollment_status({ enrollmentId })` (long-polls automatically).
       * Unverified / `401 strict mode` -> call `register_agent`, show the 6-digit code + `metavault://register?registrationId=...` to the user, then call `registration_status({ registrationId })`.
  2. **Enrich `GET /aliases` (`packages/daemon/src/server.ts:640-655`):**
     * Return `{ aliases, credentials: [{ alias, kind, scopeCeiling, website, baseUrl, authStyle, supportedTools }] }` (single SQLite query via `listCredentialMeta()`, zero secret material).
     * When `evaluatePolicy` returns `reason: "scope-above-ceiling"`, include `allowedCeiling: credential.scopeCeiling` in the daemon & MCP response, and update `annotateRequestResult` (`packages/mcp/src/server.ts:342-344`) so `scope-above-ceiling` instructs the agent: `"Requested scope exceeds this credential's ceiling (<allowedCeiling>). Retry with <resource>.read within that ceiling, or ask the user before requesting enrollment for a wider scope."` (Keep `"Do not retry"` for explicit human `"denied"` and `"revoked"`).
     * Make `agentId` **optional** in `RequestCapabilityToolSchema` (`packages/mcp/src/server.ts:88-102`), defaulting to `defaultAgentId` (`METAVAULT_AGENT_ID` or `"mcp-agent"`), since `vaultd` overwrites `agentId` from the authenticated token anyway.
  3. **Expose MCP `resources` & `prompts` (`packages/mcp/src/server.ts`):**
     * `ListResourcesRequestSchema` / `ReadResourceRequestSchema`:
       * `metavault://context/guide` (`text/markdown`): full connector, scope, payload, and deeplink quick-reference.
       * `metavault://context/status` (`application/json`): live summary from `/health` + `/aliases` + `/key/status` (`locked` boolean only, omitting fingerprint if desired).
     * `ListPromptsRequestSchema` / `GetPromptRequestSchema`:
       * `use-secret` (`alias?`) and `enroll-secret` (`alias`, `website?`) prompt templates.
  4. **Fix Per-IDE Config Snippets (`packages/app/src/renderer/onboarding.ts:44-63`, `packages/app/src/ide-config.ts`, `docs/MCP.md`, `packages/mcp/README.md`, `README.md`):**
     * Fix `buildAgentSetupPrompt` in `onboarding.ts` so it emits the **exact host-specific schema** (`mcpServers` for Claude Code / Cursor / Windsurf / Antigravity, `servers` with `type: "stdio"` for VS Code, TOML `[mcp_servers.metavault]` for Codex, and `mcp` with `type: "local"` for OpenCode) instead of hardcoding OpenCode's schema for every IDE.
     * Add **Google Antigravity** (`mcp_config.json`) support in `ide-config.ts` / Settings > Agent Integration & MCP, and update `packages/mcp/README.md` (currently stuck at 3 tools) and `README.md` (currently says 5 tools instead of 8).

---

## Workstream 4: Desktop UX — Two-Tier Lock, Tray, Flyout Dialog, OS Toasts & Sounds

### 4.1 Desktop Preferences Schema (`packages/app/src/desktop-prefs.ts` — New Module)
Store lightweight UI/Tray/Toast/Audio preferences in `%APPDATA%\MetaVault OSS\desktop-preferences.json` (read/written only by Electron `main`, exposed to renderer via typed IPC `metavault:desktop-prefs:get` and `metavault:desktop-prefs:update`):

```ts
export type SoundMode = "all" | "high-risk-only" | "off";

export interface DesktopPreferences {
  readonly minimizeToTrayOnClose: boolean;      // default: true
  readonly startMinimizedAtLogin: boolean;      // default: true on packaged Win32, synced via app.setLoginItemSettings
  readonly popWindowOnApproval: boolean;        // default: false (OS Toast + Tray badge + Chime instead!)
  readonly toastNotificationsEnabled: boolean;  // default: true
  readonly redactToastWhenLocked: boolean;      // default: true
  readonly soundMode: SoundMode;                // default: "all"
  readonly firstCloseNoticeShown: boolean;      // default: false
}
```

### 4.2 Two Explicit Lock Options (`Lock UI` vs. `Lock Vault Daemon`)
* **Files:** `packages/app/src/main.ts`, `packages/app/src/preload.ts`, `packages/app/src/renderer/main.ts`, `packages/app/src/renderer/styles.css`
* **Specification:**
  1. **State Tracking in `main`:** Track `uiLocked: boolean` and `daemonLocked: boolean` (hydrated from `/key/status` + `GET /events` `vault.lock_changed`) in Electron `main`, broadcasting `metavault:lock-state` (`{ uiLocked, daemonLocked }`) to both the main `BrowserWindow` and the Tray Flyout window.
  2. **UI Surface:**
     * Replace the single ambiguous Header `#lock-session-btn` (`packages/app/src/renderer/main.ts:4888`) with a clean split button or compact popover menu offering **two explicit choices** with 1-line subtitles:
       * **`Lock UI`** *(Requires PIN / Windows Hello to view app; background standing approvals stay active)* -> sets `uiLocked = true` in `main`, closes any open `.vault-modal-overlay`, hides/locks flyout, updates tray icon & menu.
       * **`Lock Vault Daemon`** *(Zeroes master key in `vaultd` via `POST /lock` and locks UI; halts all secret execution until passphrase unlock)* -> calls `window.metavault.lockVault()` (`POST /lock`) **and** sets `uiLocked = true`.
     * Surface the exact same two actions in **Settings > Security**, the **Tray Flyout**, and the **Tray Right-Click Menu** (disabling `Lock UI` when no PIN/Windows Hello is configured with a hint `"Set App PIN to enable UI Lock"`, while `Lock Vault Daemon` is enabled whenever `vaultd` uses passphrase key custody and is currently unlocked).
  3. **Unlock Routing:**
     * When `daemonLocked === true`, show the **Vault Passphrase Unlock** screen (`POST /unlock`). If `localAuth` `requireOnLaunch` is also enabled and `uiLocked === true`, either unlock UI in the same step or chain smoothly without flashing vault contents.
     * When only `uiLocked === true` (`daemonLocked === false`), show the **UI Lock** screen (App PIN / Windows Hello).

### 4.3 Minimize-to-Tray Fixes, Dynamic Tray Badges & Rich Right-Click Menu
* **Files:** `packages/app/src/window-options.ts`, `packages/app/src/main.ts`, `packages/app/src/tray-icons.ts` (new programmatic icon/badge generator)
* **Specification:**
  1. **Fix `--minimized` Login Window Flash (`packages/app/src/window-options.ts:34-57` & `packages/app/src/main.ts:168-186`):**
     * Add `show?: boolean` to `VaultWindowOptions` (`buildWindowOptions(preloadPath, { show: false })`) — **always construct `BrowserWindow` with `show: false`**, and show it inside `ready-to-show` (and the 1000ms fallback timer) **only** when `!isMinimizedStart`!
  2. **Respect `minimizeToTrayOnClose` & First-Close Toast:**
     * In `window.on("close")` (`main.ts:187`), check `shouldHideOnClose(isQuitting, prefs.minimizeToTrayOnClose)`.
     * On the very first close-to-tray (`!prefs.firstCloseNoticeShown`), fire a single informational OS Toast (`"MetaVault OSS is still running in the system tray"` / `"Agents can still request capabilities. Right-click the tray icon to lock or quit."`, `silent: true`) and persist `firstCloseNoticeShown: true`.
  3. **Sync `"Start Minimized at Login"` via Electron API:**
     * Use `app.setLoginItemSettings({ openAtLogin: prefs.startMinimizedAtLogin, args: ["--minimized"] })` (guarded by `app.isPackaged`) so users can toggle login autostart at runtime without NSIS overwriting their choice.
  4. **Dynamic Tray Icon States, Taskbar Overlay & Tooltip (`packages/app/src/tray-icons.ts`):**
     * Composite a crisp 16×16 / 32×32 status dot onto the base tray `NativeImage` (pure RGBA buffer overlay — zero native canvas dependency!) and set `mainWindow.setOverlayIcon(...)` on Windows for:
       * `unlocked-idle`: clean brand icon — tooltip `"MetaVault OSS — Unlocked"`
       * `pending` (`pendingCount > 0`): high-contrast amber/red badge dot — tooltip `"MetaVault OSS — <N> approval(s) waiting"`
       * `ui-locked`: slate/blue lock badge — tooltip `"MetaVault OSS — UI Locked"`
       * `daemon-locked`: red/dark lock badge — tooltip `"MetaVault OSS — Vault Locked"`
  5. **Right-Click Context Menu (`Menu.buildFromTemplate`):**
     * `[enabled: false]` Status label: `"MetaVault: Unlocked"` / `"MetaVault: UI Locked"` / `"MetaVault: Vault Locked"`
     * `[visible: totalPending > 0]` `"Review Pending Approvals (<totalPending>)"` -> opens Main Window to Approvals view
     * `"Add Credential…"` -> opens Main Window to Add Credential modal
     * `separator`
     * `"Lock UI"` (enabled if local auth configured & `!uiLocked`)
     * `"Lock Vault Daemon"` (enabled if `!daemonLocked`)
     * `separator`
     * `[type: "checkbox", checked: prefs.soundMode === "off"]` `"Mute Notification Sounds"` -> toggles between `"off"` and `"all"`
     * `[type: "checkbox", checked: prefs.startMinimizedAtLogin]` `"Start Minimized at Login"`
     * `separator`
     * `"Open MetaVault OSS"` -> `showWindow()`
     * `"Quit MetaVault OSS"` -> `isQuitting = true; app.quit()`

### 4.4 Left-Click Compact Tray Flyout Dialog (`360×480`)
* **Files:** `packages/app/src/tray-flyout.ts` (new main-process controller), `packages/app/src/renderer/flyout.html`, `packages/app/src/renderer/flyout.ts`, `packages/app/src/renderer/flyout.css` (copied in `scripts/copy-assets.mjs`)
* **Specification:**
  1. **Window Configuration:**
     * Lazily create a single reusable `BrowserWindow` (`width: 360, height: 480, show: false, frame: false, resizable: false, movable: false, minimizable: false, maximizable: false, fullscreenable: false, skipTaskbar: true, alwaysOnTop: true`, using the **exact same hardened `webPreferences`**: `preload: preloadPath, nodeIntegration: false, contextIsolation: true, sandbox: true` plus `will-navigate` / `setWindowOpenHandler` deny guards).
  2. **Positioning Math (`positionFlyoutNearTray(trayBounds, workArea)` — pure unit-testable helper):**
     * Use `screen.getDisplayNearestPoint({ x: trayBounds.x, y: trayBounds.y }).workArea`.
     * Clamp `x = Math.round(clamp(trayBounds.x + trayBounds.width / 2 - 180, workArea.x + 8, workArea.x + workArea.width - 368))`.
     * Place above taskbar when taskbar is at bottom (`trayBounds.y > workArea.y + workArea.height / 2` -> `y = workArea.y + workArea.height - 488`), or below top bar on macOS / top-taskbar Windows (`y = workArea.y + 8`).
  3. **Toggle & Auto-Dismiss Behavior:**
     * Left-clicking the tray icon toggles the flyout (`if (flyout.isVisible()) flyout.hide(); else showFlyoutAtTray()`).
     * Hide automatically on `flyout.on("blur")` (with a 150ms debounce on Tray click so clicking the tray icon while visible toggles cleanly rather than blur-then-reopen!) and on `Escape` keydown.
  4. **Flyout Contents & Security Guards:**
     * **Header:** Brand mark + live status badge (`Unlocked` / `UI Locked` / `Vault Locked`) + Mute icon button + `"Open App ↗"` button.
     * **Locked State:** Shows a compact `"Unlock in MetaVault"` CTA button (or inline App PIN input for `uiLocked`) — never renders pending metadata while `redactToastWhenLocked && (uiLocked || daemonLocked)`.
     * **Unlocked Queue:**
       * Top pending capability card: Agent (`Verified` / `⚠️ Unverified`), Alias, Scope, HTTP method + path summary (`payloadSummary`), Risk pill, 1-sentence Warden explanation, and **Approve Once** / **Deny** buttons (for **remote-origin** grants requiring App PIN presence proof, clicking Approve either prompts inline PIN or opens the full window to complete presence verification).
       * Pending Agent Registration card (if any): 6-digit code input + Confirm / Deny.
       * Empty state: `"All clear — no pending agent requests"` + quick credential count.
     * **Footer Bar:** Two explicit buttons: **`Lock UI`** and **`Lock Vault`** (`Lock Vault Daemon`).
     * **500ms Focus Guard:** Approval buttons stay `disabled` (or ignore keyboard/click activation) for `500ms` after `window.focus` / flyout open, and `.btn-approve` is **never** `.focus()`ed automatically.

### 4.5 Native OS Toast Notifications & Click-to-Target Navigation
* **Files:** `packages/app/src/notifications.ts` (new main-process manager), `packages/app/src/main.ts`, `packages/app/src/preload.ts`, `packages/app/src/renderer/main.ts`
* **Specification:**
  1. **Windows AUMID Registration (`packages/app/src/main.ts`):**
     * Call `if (process.platform === "win32") { app.setAppUserModelId("dev.metavault.app"); }` at module startup before `app.whenReady()` (matches `build.appId` in `packages/app/package.json:25` so Windows 10/11 displays `"MetaVault OSS"` + app icon in toast banners and Action Center).
  2. **Main-Process Event Watcher (Unthrottled While Hidden in Tray):**
     * Connect to `vaultd` `GET /events` SSE inside Electron `main` (with automatic exponential-backoff reconnect if `vaultd` restarts) so `main` detects new `pending` grants, `agent-registrations`, and `vault.lock_changed` in **<50ms** even when `mainWindow` is hidden in the tray!
     * Remove the renderer's unconditional `window.metavault.bringToFront()` calls at `packages/app/src/renderer/main.ts:4587, 4605` (only call `bringWindowToFront()` if `prefs.popWindowOnApproval === true`, and even then use `window.flashFrame(true)` + focus guard without auto-focusing `.btn-approve` at line `612`!).
  3. **When Toasts Fire & Privacy Redaction:**
     * Check `Notification.isSupported() && prefs.toastNotificationsEnabled`.
     * **New Pending Capability Grant (`grantId` not yet notified):**
       * When unlocked (or `!prefs.redactToastWhenLocked`):
         * Title: `High-Risk Approval Needed — <alias>` (if `risk === "high"` or write/card/remote) or `Agent Request — <alias>`
         * Body: `<agentId> requests <requestedScope>. Click to review in MetaVault.`
       * When `uiLocked || daemonLocked` and `prefs.redactToastWhenLocked === true`:
         * Title: `MetaVault OSS — Approval Waiting`
         * Body: `An agent capability request is waiting. Click to unlock and review.`
     * **New Agent Registration (`registrationId`):**
       * Title: `Verify Agent — <name || agentId>`
       * Body: `Click to enter the 6-digit verification code in MetaVault.` (redacted if locked).
     * **Unexpected SSH Remote Tunnel Drop / Host-Key Alert:**
       * Title: `MetaVault Remote Connection Stopped`
       * Body: Concise status reason; click routes to `Settings > Connections`.
     * **Toast `silent` Coordination:** Always pass `silent: true` to `new Notification({ ..., silent: true })` whenever `prefs.soundMode` will play a custom Web Audio earcon (or when `prefs.soundMode === "off"`!), so Windows never plays its default system toast chime on top of MetaVault's earcon!
  4. **Click-to-Target Routing & Stale Toast Auto-Dismissal:**
     * Store active notifications in `activeToasts = new Map<string, Notification>()` keyed by `grant:<grantId>` or `reg:<registrationId>`.
     * On `toast.on("click")`:
       1. Hide Tray Flyout if open, call `showWindow()` to restore and focus `mainWindow`.
       2. Send IPC `metavault:navigate` (`{ kind: "approval", grantId }` or `{ kind: "registration", registrationId }` or `{ kind: "settings", section: "connections" }`).
       3. In `packages/app/src/renderer/main.ts`, if `uiLocked || daemonLocked`, stash the navigation target until unlock completes, then switch `currentView = "approval"`, select `grantId` (re-opening the approval modal even if `approvalDialogDismissed` was previously set), and scroll the card into view!
     * Whenever `GET /events` / `/pending` shows a `grantId` or `registrationId` is no longer pending (approved, denied, or expired), call `activeToasts.get(key)?.close()` and delete it from `activeToasts` so stale banners vanish from Windows Action Center immediately.

### 4.6 Synthesized Web Audio Earcons (`packages/app/src/renderer/audio.ts` — New Module)
* **Files:** `packages/app/src/main.ts`, `packages/app/src/preload.ts`, `packages/app/src/renderer/audio.ts`, `packages/app/src/renderer/main.ts`
* **Specification:**
  1. **Zero Media Assets & Strict CSP Safe:**
     * Synthesize short, clean earcons via standard `AudioContext` + `OscillatorNode` + `GainNode` (exponential gain attack/release envelopes to eliminate speaker clicks). Works under `default-src 'self'` with zero `.wav`/`.mp3` bloat.
  2. **Enable Background Chimes on `--minimized` Boot:**
     * Call `app.commandLine.appendSwitch("autoplay-policy", "no-user-gesture-required")` in `packages/app/src/main.ts` **before** `app.whenReady()` so `AudioContext` is not suspended when MetaVault boots minimized at Windows login.
     * Trigger playback from `main` via IPC `metavault:play-sound` (`{ cue: SoundCue }`) whenever `prefs.soundMode` permits it.
  3. **Earcon Palette & `SoundMode` Rules:**
     * `"approval-standard"` *(soft two-note rising sine/triangle fifth: `523.25 Hz -> 783.99 Hz`, 180ms total, peak gain `0.12`)* — plays when `soundMode === "all"`.
     * `"approval-high-risk"` *(distinct three-note urgent motif: `440 Hz -> 587.33 Hz -> 880 Hz` or double-pulse amber alert, 280ms total, peak gain `0.18`)* — plays when `soundMode === "all" || soundMode === "high-risk-only"` (used for `risk === "high"`, write scopes, payment cards, and remote-origin requests).
     * `"agent-registration"` *(gentle bell ping: `659.25 Hz -> 987.77 Hz`, 160ms)* — plays when `soundMode === "all"`.
     * `"decision-approved"` *(subtle crisp up-tick: `880 Hz`, 60ms, gain `0.06`)* & `"decision-denied"` *(soft low down-tick: `261.63 Hz`, 80ms, gain `0.07`)* — plays when `soundMode === "all"`.
     * `"vault-locked"` *(short descending lock click: `587.33 Hz -> 392 Hz`, 110ms, gain `0.08`)* — plays when `soundMode === "all"`.
  4. **Burst Coalescing / Cooldown:**
     * Enforce a `2,500ms` cooldown across background arrival chimes (`approval-*`, `agent-registration`), with `"approval-high-risk"` allowed to preempt/upgrade a `"approval-standard"` cue within the window so parallel agent tool calls never machine-gun the user's speakers.
  5. **Settings UI Section (`Settings > Notifications & Tray`):**
     * Add clean controls in Settings for:
       * `Minimize to tray when closing window` (toggle)
       * `Start minimized at Windows login` (toggle)
       * `Show OS toast notifications` (toggle)
       * `Hide request details in notifications while locked` (toggle)
       * `Pop window to front on pending approval` (toggle, default **Off**)
       * `Notification sounds`: segmented select (`All events` / `High-risk & writes only` / `Muted`) + `"Preview sound"` button.

---

## 5. Verification & Test Matrix Required Before Completion

1. **Unit & Integration Tests (`npm test` / `vitest run`):**
   * `packages/connectors/test/http.test.ts`: Non-preset custom alias (`openai`, `custom-internal`) succeeds with `tool: "rest.call"` and `tool: "graphql.call"` against a pinned `baseUrl`; URL paths like `https://api.example.com/v1` survive UI projection/edit round-trips.
   * `packages/daemon/test/` & `packages/core/test/`:
     * SQLite WAL index & `getAgentAuditStats` match exact 1h / 24h counts.
     * `standing_approvals` persist across `VaultStore` reopen, and `GET` `rest.call` / `cloudflare.dns` requests with a standing approval execute via `standingFastPath` without invoking `Brain.assess`.
     * `GET /events` emits `pending.changed` and `vault.lock_changed`; `GET /enrollments/:id?waitMs=5000` and `POST /agent-registrations/:id/claim` (`waitMs`) resolve immediately upon completion.
     * `GET /aliases` includes `scopeCeiling`, `baseUrl`, `authStyle`, and `supportedTools` and leaks zero canary secrets (`test/canary.test.ts` must pass!).
   * `packages/mcp/test/`:
     * Handshake exposes `instructions`, `resources` (`metavault://context/guide`, `metavault://context/status`), and `prompts`.
     * `request_capability` works with omitted `agentId`, includes `allowedCeiling` on `scope-above-ceiling`, returns `metavault://approve?grantId=...` on timeout, and returns `status: "vault-locked"` + `metavault://unlock` when `vaultd` is locked.
   * `packages/app/test/`:
     * `window-options.test.ts`: `buildWindowOptions` defaults `show: false` (preventing `--minimized` window flash), and `.btn-approve` is never auto-focused + obeys the 500ms focus guard.
     * `deeplink.test.ts`: Validates all 6 `metavault://` and `openvault://` routes (`add`, `approve`, `register`, `unlock`, `audit`, `settings`), rejects Bidi/control chars and oversized/duplicate params.
     * `tray-flyout.test.ts` & `notifications.test.ts`: Pure positioning math across bottom/top/left/right taskbars, toast lifecycle auto-close on grant resolution, lock-state redaction, `silent: true` coordination, and two-option lock (`Lock UI` vs `Lock Vault Daemon`).
2. **Quality Gates:**
   * `bun run lint --fix` (or `npm run lint` — 0 errors, 0 warnings)
   * `npm run typecheck` (0 errors)
   * `npm test` (all suites + `test/canary.test.ts` green)
   * `bun run build` (clean `packages/app/dist` build)
