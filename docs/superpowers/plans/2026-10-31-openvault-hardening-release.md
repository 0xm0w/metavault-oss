# OpenVault Hardening + Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship OpenVault v0.1.0-alpha.1: deployable MCP server, Settings page with warden provider/model/effort + encrypted Meta API key path, structured AI audit trails in the Audit page, hardened test suite with coverage gates, CI/CD + OSS rules, a documented security audit + pen-test pass, docs with real screenshots/flows, and a tagged Windows release.

**Architecture:** Unchanged core split — dumb encrypted vault (`vaultd`, 127.0.0.1:7077) + smart marshal. New: a `WardenSettings` record persisted by the daemon (provider, model, effort, key alias only — never a raw key), a `Brain` provider layer with Ollama and Meta-API implementations behind the existing `Brain` Effect tag, and structured audit fields (`requestId`, `risk`, `recommendedScope`, `decisionSource`, `latencyMs`) appended to `AuditEvent` as optional fields so old DBs keep working. Settings mutations ride the existing daemon-token guard; the Meta API key is stored as an ordinary encrypted credential under alias `warden-meta-api` and is only ever decrypted inside the daemon at call time.

**Tech Stack:** TypeScript, Effect (core/daemon/brain), plain-TS Electron renderer, Vitest, ESLint flat config, GitHub Actions, electron-builder (Windows NSIS).

**Spec:** User brief 2026-10-31 (this session) + `docs/superpowers/specs/2026-10-31-openvault-design.md`.

## Global Constraints

- Secrets never reach agents, the marshal prompt, the renderer after save, logs, or audit rows. Audit stores verdict metadata only.
- Deterministic policy is law: the marshal may narrow or escalate, never widen. Settings change *who judges*, never *the rules*.
- All human-mutation routes require header `x-openvault-token`; MCP/agent routes must never accept it.
- Windows first. macOS DMG/signing parked.
- Baseline before Task 1: `npm run test` = 191 passed, `npm run typecheck` exit 0, `npm run lint` exit 0. No task may drop below its own new baseline.
- Semantic charting of data flow is explicitly deferred until after this plan (user instruction).

---

### Task 1: MCP server as a deployable IDE component

**Files:**
- Modify: `packages/mcp/src/server.ts` (server version reads from a single `VERSION` export)
- Create: `packages/mcp/package.json` (`bin: openvault-mcp`, `main`, build script mirroring app pattern)
- Create: `docs/MCP.md` (host config snippets: Claude Code, Cursor, VS Code, Codex, OpenCode)
- Modify: `scripts/check-mcp-hosts.mjs` (also assert `tools/list` returns exactly 5 tools)
- Test: `packages/mcp/test/mcp.test.ts` (extend)

**Interfaces:**
- Produces: `export const MCP_VERSION: string` in `packages/mcp/src/server.ts`; hosts launch `node dist/packages/mcp/src/server.js` (documented) or the packaged bin.
- Consumes: daemon HTTP API only; env `OPENVAULT_DAEMON_URL`, `OPENVAULT_AGENT_ID`, `OPENVAULT_IDE`.

- [ ] Write failing test: handshake reports `serverInfo.version === MCP_VERSION` and tools list is exactly `request_capability, list_aliases, request_enrollment, enrollment_status, revoke`.
- [ ] Run `npx vitest run packages/mcp/test/mcp.test.ts` — expect FAIL on `MCP_VERSION` import.
- [ ] Implement `MCP_VERSION = "0.1.0-alpha.1"`, use it in the `Server` constructor; add `packages/mcp/package.json` bin.
- [ ] Write `docs/MCP.md` with one copy-paste config block per host; each block sets `OPENVAULT_AGENT_ID` per IDE.
- [ ] Extend `scripts/check-mcp-hosts.mjs` tool-name assertion; run it against a live daemon.
- [ ] Run full gates; commit `feat(mcp): package openvault-mcp for IDE hosts + host config docs`.

### Task 2: Warden settings store + encrypted Meta API key path (daemon)

**Files:**
- Create: `packages/core/src/settings.ts` (`WardenSettings` type + defaults + Schema)
- Modify: `packages/core/src/storage.ts` (settings table get/set; reuse credential store for the key)
- Modify: `packages/daemon/src/schemas.ts` (`WardenSettingsPatchSchema`, `WardenKeyPutSchema`)
- Modify: `packages/daemon/src/service.ts` (`getWardenSettings`, `updateWardenSettings`, `setWardenKey`, `deleteWardenKey`, `wardenKeyStatus`)
- Modify: `packages/daemon/src/server.ts` (`GET /settings/warden`, `PATCH /settings/warden`, `PUT /settings/warden/key`, `DELETE /settings/warden/key` — all token-guarded)
- Test: `packages/daemon/test/settings.test.ts` (create)

**Interfaces:**
- `WardenSettings = { provider: "none" | "ollama" | "meta-api"; model: string; effort: "fast" | "standard" | "deep"; metaApiBaseUrl: string }`, default `{ provider: "ollama", model: "llama3.2:3b", effort: "standard", metaApiBaseUrl: "https://api.llama.com/v1" }`.
- Key status response is exactly `{ configured: boolean, last4: string | null }`. The raw key is accepted only in the PUT body, stored via existing `addCredential("warden-meta-api", key, "warden.meta")`, and never returned.
- Consumes: existing token guard (`requireToken`) and credential encryption.

- [ ] Write failing tests: default settings returned; PATCH persists provider/model/effort; PUT key then status shows `last4` and no field contains the key; DELETE clears; all four routes 401 without token, and MCP-side fetch (no token) cannot read settings.
- [ ] Run the new test file — expect FAIL (routes missing).
- [ ] Implement core type, storage, schemas, service methods, routes.
- [ ] Re-run tests; assert audit gains a `settings-changed` event with provider/model only (no key material) — add `"settings-changed"` to `AuditEvent.stage` union in `packages/core/src/types.ts`.
- [ ] Run full gates; commit `feat(daemon): warden settings + encrypted Meta API key path`.

### Task 3: Brain providers — Ollama + Meta API, model + effort switcher

**Files:**
- Create: `packages/brain/src/meta-api.ts` (OpenAI-compatible chat call, JSON decision parse via existing `parseMarshalDecision`)
- Modify: `packages/brain/src/brain.ts` (`BrainFromSettings(settings, getKey)` layer factory; keep `BrainOllamaLive` for tests)
- Modify: `packages/brain/src/ollama.ts` (export `OLLAMA_MODELS` catalogue: `llama3.2:3b`, `llama3.1:8b`, `llama3.3:70b` with tier labels)
- Modify: `packages/daemon/src/server.ts` (build Brain layer from stored settings at startup; rebuild on settings PATCH via a `Ref` swap — daemon restart not required)
- Modify: `packages/daemon/src/service.ts` (effort behaviour below; settings read per request)
- Test: `packages/brain/test/meta-api.test.ts`, extend `packages/brain/test/brain.test.ts`

**Interfaces:**
- Effort semantics (identical across providers): `fast` = single marshal pass, 10s timeout; `standard` = single pass, 30s timeout; `deep` = two passes (assess + verify pass that re-checks the first verdict against the request; on disagreement escalate to `requireApproval: true`, keep the narrower scope), 60s timeout. Effort never changes policy ceilings.
- Meta API call: `POST {metaApiBaseUrl}/chat/completions`, `Authorization: Bearer <key>` (key fetched via daemon callback, decrypted in-daemon), same marshal prompt + `response_format: json`. HTTP/parse failure ⇒ `MarshalUnavailable`/`MarshalInvalidOutput` exactly like Ollama, so policy fallback behaviour is unchanged.
- Provider `none` ⇒ skip marshal entirely; audit records `decisionSource: "policy"`.
- Before coding the Meta call, verify the current Meta/Llama API base URL + model ids from official Meta docs and record the source URL in `packages/brain/src/meta-api.ts` header comment; the Settings base-URL field stays user-editable so an endpoint change is config, not code.

- [ ] Write failing tests with a fake fetch: meta-api decision parsed; bad JSON ⇒ `MarshalInvalidOutput`; 401 ⇒ `MarshalUnavailable`; deep effort disagreement escalates approval and keeps narrower scope; effort timeouts map to the values above.
- [ ] Run brain tests — expect FAIL.
- [ ] Implement `meta-api.ts`, effort wrapper in `brain.ts`, daemon wiring.
- [ ] Live smoke (manual gate, recorded in `docs/verification/`): Ollama 3B decision + (if a key is available) Meta API decision; absence of a key is a recorded skip, not a pass.
- [ ] Run full gates; commit `feat(brain): Meta API warden provider + effort levels`.

### Task 4: Structured AI audit trails (daemon + core)

**Files:**
- Modify: `packages/core/src/types.ts` (extend `AuditEvent`)
- Modify: `packages/daemon/src/service.ts` (populate new fields; generate one `requestId` per capability request and thread it through requested→marshal→policy→approved/denied→executed)
- Modify: `packages/core/src/storage.ts` (add nullable columns via `ALTER TABLE ... ADD COLUMN` guarded by `PRAGMA table_info`, so existing vaults migrate in place)
- Test: `packages/daemon/test/audit-trail.test.ts` (create)

**Interfaces:**
- `AuditEvent` gains optional: `requestId?: string; risk?: Risk; recommendedScope?: string; decisionSource?: "policy" | "marshal" | "marshal+policy" | "human"; latencyMs?: number; explanation?: string` (marshal explanation moves here; `detail` keeps the short human label).
- Invariant test target: for one executed request, filtering audit by its `requestId` yields the full chain in order, and `JSON.stringify(chain)` contains no credential value (canary secret asserted absent).

- [ ] Write failing tests: full chain shares one `requestId`; marshal event carries `risk`, `recommendedScope`, `modelId`, `decisionSource: "marshal"`, numeric `latencyMs`; policy-denied chain has `decisionSource: "policy"` and no marshal event when provider is `none`; canary secret absent from every serialized event.
- [ ] Run — expect FAIL.
- [ ] Implement migration + field population (latency measured around `brain.assess` only).
- [ ] Run full gates; commit `feat(core): structured warden audit trails keyed by requestId`.

### Task 5: Audit page — warden verification view (renderer)

**Files:**
- Modify: `packages/app/src/renderer/types.ts` (`AuditEventLike` gains the Task 4 fields)
- Modify: `packages/app/src/renderer/model.ts` (`groupAuditByRequest(events)`, `wardenVerdict(row)` pure helpers)
- Modify: `packages/app/src/renderer/main.ts` (`renderAudit`: request-grouped rows, expandable verdict panel)
- Modify: `packages/app/src/renderer/index.html` (nav unchanged; Audit view gains filter input)
- Test: `packages/app/test/model.test.ts` (extend)

**Interfaces:**
- Audit view lists one row per `requestId` (legacy events without one group under `legacy`): time, agent, alias, requested scope → allowed scope, final outcome chip (executed/denied/expired/revoked), warden chip (`risk` + model or `policy-only`).
- Expanding a row shows the verification timeline: each stage with `detail`, marshal `explanation`, `recommendedScope`, `latencyMs`, `decisionSource`. Filter box matches agent/alias/outcome text. No secret-shaped strings are rendered (events never contain any — asserted in Task 4).

- [ ] Write failing model tests: grouping order, verdict derivation for executed vs policy-denied vs marshal-escalated chains.
- [ ] Run app tests — expect FAIL.
- [ ] Implement helpers + `renderAudit` rework in the unified warm theme.
- [ ] Run full gates; commit `feat(app): Audit page shows per-request warden verdicts`.

### Task 6: Settings page (renderer + IPC)

**Files:**
- Modify: `packages/app/src/renderer/index.html` (add Settings nav button)
- Modify: `packages/app/src/renderer/main.ts` (`ViewName` += `"settings"`, `renderSettings`)
- Modify: `packages/app/src/daemon-client.ts` + `packages/app/src/main.ts` + `packages/app/src/preload.ts` (whitelisted IPC: `getWardenSettings`, `updateWardenSettings`, `setWardenKey`, `deleteWardenKey`, `wardenKeyStatus` — token stays in main process)
- Test: `packages/app/test/daemon-ipc.test.ts` (extend), `packages/app/test/model.test.ts` (settings form state helpers)

**Interfaces — Settings page sections:**
1. **Warden provider:** radio `None (policy only)` / `Local — Ollama` / `Meta API (cloud)`. Copy states plainly that Meta API sends request metadata (never secrets) off-device.
2. **Model switcher:** for Ollama, select from `OLLAMA_MODELS` with security-tier labels (3B = Medium, 8B = High, 70B = Maximum-local); for Meta API, text/select of API model id. Free-text fallback allowed.
3. **Effort switcher:** `Fast / Standard / Deep` with one-line latency/strictness descriptions from Task 3.
4. **Meta API key:** password input + Save, status line (`Not configured` / `Configured ••••1234`), Test connection button (issues one marshal self-check request through the daemon and reports ok/fail), Delete key. Key field clears after save and is never repopulated.
5. **Daemon:** daemon URL (read-only), vault path, version, Restart-daemon hint text.
6. **Security defaults (read-only summary):** policy floor summary + link-style jump to Policies view. (Editing policy stays on Policies.)

- [ ] Write failing IPC tests: each new channel is whitelisted, forwards to the right daemon route with token, and rejects unknown channels.
- [ ] Run — expect FAIL.
- [ ] Implement client/main/preload + `renderSettings` in the unified warm theme.
- [ ] Manual smoke with screenshot to `docs/verification/settings.png` (key field empty in shot).
- [ ] Run full gates; commit `feat(app): Settings page with warden provider, model, effort, Meta key`.

### Task 7: Test-suite hardening + coverage gates

**Files:**
- Modify: `vitest.config.ts` (coverage provider `v8`, thresholds)
- Create: `test/security/canary.test.ts` (extend existing canary: assert canary absent from audit JSON, MCP results, deeplink URLs, settings responses, renderer IPC payloads)
- Create: `test/e2e/mcp-daemon.e2e.test.ts` (spawn daemon on an ephemeral port + real MCP stdio client: enroll → approve → execute → revoke)
- Modify: `package.json` (`test:coverage` script)
- Test: everything above is the test

**Interfaces:**
- Coverage thresholds (statements/lines): `packages/core` ≥ 90%, `packages/daemon` ≥ 85%, `packages/brain` ≥ 85%, `packages/mcp` ≥ 85%, `packages/app/src/renderer/model.ts` ≥ 90%. Renderer DOM code and Electron main are excluded from thresholds and covered by smoke screenshots instead — stated in the config comments.
- E2E uses a fake upstream connector (existing test connector pattern); no network, no Ollama (Brain stub layer), deterministic.

- [ ] Add coverage config; run `npm run test:coverage`; record the baseline numbers in `docs/VERIFICATION.md` before setting thresholds, then set thresholds at or below measured values per package above (raise a package only by adding tests, never by lowering the target silently).
- [ ] Write canary extensions + MCP↔daemon e2e; run full suite.
- [ ] Commit `test: coverage gates, canary sweep, MCP-daemon e2e`.

### Task 8: CI/CD + OSS repo rules

**Files:**
- Create: `.github/workflows/ci.yml` (windows-latest + ubuntu-latest matrix, Node 22: install, lint, typecheck, test, coverage on ubuntu)
- Create: `.github/workflows/codeql.yml` (javascript-typescript, weekly + PR)
- Create: `.github/workflows/release.yml` (on tag `v*`: windows-latest, build app, `electron-builder --win`, upload NSIS installer + SHA256SUMS to a GitHub prerelease)
- Create: `.github/CODEOWNERS` (`* @0xm0w`, `/packages/core/ @0xm0w`, `/packages/daemon/ @0xm0w`)
- Create: `.github/pull_request_template.md` (tests run, secret-handling checklist, screenshots for UI)
- Create: `.github/ISSUE_TEMPLATE/bug.yml`, `.github/ISSUE_TEMPLATE/feature.yml`, `.github/dependabot.yml` (npm + github-actions, weekly)
- Modify: `CONTRIBUTING.md` (branch rules: PR-only to main, CI green, one review, no direct push; commit style; how to run gates)

**Interfaces:**
- Repo-side settings that cannot live in files (branch protection/ruleset, secret scanning, Dependabot alerts) are listed as a manual checklist at the end of `CONTRIBUTING.md` for the repo owner to toggle; the plan does not claim they are enforced until checked.

- [ ] Write workflows + templates; validate YAML locally (`npx -y yaml` parse or python `yaml.safe_load`).
- [ ] Push a throwaway branch to watch CI go green; record run URL in `docs/VERIFICATION.md`.
- [ ] Commit `ci: GitHub Actions (test, CodeQL, release) + OSS repo rules`.

### Task 9: Security audit + penetration-test pass

**Files:**
- Create: `docs/SECURITY-AUDIT.md` (threat model, findings table with severity/status, residual risks)
- Create: `scripts/pentest.mjs` (black-box probes against a running daemon)
- Create: `test/security/pentest.test.ts` (the same probes as CI tests against an ephemeral daemon)

**Interfaces — probe list (each asserts the secure outcome):**
1. Approve/deny/settings/credential-mutation without token ⇒ 401; with a wrong token ⇒ 401.
2. MCP-side request attempting `x-openvault-token` header injection ⇒ daemon still treats it as agent traffic (settings read denied).
3. Scope escalation: request above ceiling, marshal stub recommending above ceiling ⇒ denied `scope-above-ceiling`.
4. Standing-approval abuse: write scope, unknown alias, after credential delete+re-add ⇒ approval required again.
5. Deeplink fuzz: `openvault://add` with `../`, `%00`, 10k-char alias, duplicate params ⇒ clean 400/no modal crash.
6. Enrollment flood: 200 rapid creates ⇒ bounded registry (expired eviction holds), no 500s.
7. Malformed percent-encoding + oversized JSON body on every route ⇒ 400/413, never 500.
8. Secret canary: run probes 1–7 with a canary credential stored; grep daemon stdout, audit JSON, and HTTP responses for the canary ⇒ absent.
9. Renderer: credential detail never renders a secret field (DOM assertion in existing app tests).

- [ ] Write `test/security/pentest.test.ts` first; run against current code; fix every failure in the owning package (small fix commits, each with its probe as the regression test).
- [ ] Write `scripts/pentest.mjs` as the manual equivalent; run against the live local daemon; paste summary into `docs/SECURITY-AUDIT.md`.
- [ ] Fill the findings table honestly (fixed / accepted-risk / parked); commit `docs+test: security audit and pen-test suite`.

### Task 10: Docs finalization — screenshots + agent flows

**Files:**
- Modify: `site/docs/index.html` (or docs source that generates it — follow existing site structure)
- Create: `docs/verification/settings.png`, `docs/verification/audit-verdict.png`, `docs/verification/approval-dialog.png`, `docs/verification/enroll-flow.png`
- Modify: `docs/VERIFICATION.md`, `README.md` (install via MCP config, Settings/warden section, security levels table aligned with Task 3 tiers)

**Interfaces — required doc flows, each with a real screenshot:**
1. Agent asks to save a key: MCP `request_enrollment` → deeplink → prefilled modal → human pastes secret → agent polls `enrollment_status` → completed.
2. Agent requests a capability: Approval dialog with **Allow once / Allow always / Deny** visible, risk + scope + warden explanation shown.
3. Audit page: one expanded request showing the warden verdict timeline.
4. Settings page: provider/model/effort + Meta key status (key field empty).

- [ ] Capture screenshots from the real running app (no mockups); wire them into docs + README.
- [ ] Redeploy site (`npx -y wrangler pages deploy site --project-name openvault --branch main --commit-dirty=true`); verify `/`, `/docs/`, `/architecture/`, `/hackathon/` return 200.
- [ ] Commit `docs: screenshots and end-to-end agent flows`.

### Task 11: Release v0.1.0-alpha.1

**Files:**
- Modify: `packages/app/package.json` (`version: "0.1.0-alpha.1"`), root `package.json` (`version: "0.1.0-alpha.1"`), `packages/mcp/src/server.ts` (`MCP_VERSION` already set in Task 1 — assert equality in a test)
- Create: `CHANGELOG.md` (`## [0.1.0-alpha.1] — 2026-…` with Added/Security/Known limitations)
- Modify: `packages/app/package.json` build config only if electron-builder demands it; add `electron-builder` devDependency at root.

**Versioning decision:** `0.1.0-alpha.1` is correct — SemVer prerelease of the first public feature line. Alpha (not beta) because: unsigned Windows installer, no macOS build, Meta API warden path is new, and the API/daemon contract may still change. Drop `-alpha.N` at the first signed, feature-frozen public release (`0.1.0`), then `1.0.0` when the daemon/MCP contract is declared stable.

- [ ] Bump versions; add version-equality test (app package vs `MCP_VERSION`).
- [ ] Full gates + `npm run test:coverage` green; CI green on main.
- [ ] Build: `cd packages/app && npm run build && npx electron-builder --win`; record installer size + SHA256 in `docs/VERIFICATION.md`; smoke-install on this machine and screenshot first run.
- [ ] Tag `v0.1.0-alpha.1`, push tag; confirm the release workflow produced a prerelease with installer + checksums; link it from README + site.
- [ ] Commit `chore(release): v0.1.0-alpha.1`.

## Order + gates

Tasks run 1→11 in order (7–9 may interleave fixes back into 2–6). Every task ends with `npm run test`, `npm run typecheck`, `npm run lint` green in-session before commit. Deferred by user instruction: semantic data-flow charting (docs) comes after Task 11.




