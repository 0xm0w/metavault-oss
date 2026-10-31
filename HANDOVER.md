# OpenVault — Handover (2026-10-31)

Read this first when resuming. Repo: `C:\Users\Mowreez.DESKTOP-D1GHS6J\openvault`
Private remote: `https://github.com/0xm0w/openvault`

## Where things stand

- Branch `main` ready for push.
- Hardening plan (11 tasks) + Final Review Fix Wave are implemented: Tasks 1–11 all built and reviewed, plus must-fix #1, must-fix #3, and Low issues resolved and verified. Plan: `docs/superpowers/plans/2026-10-31-openvault-hardening-release.md`
- SDD ledger (task-by-task record, deferred minors, rulings):
  `.superpowers/sdd/2026-10-31-openvault-hardening-release/progress.md`
  Per-task reports + review diffs are in the same folder (`task-N-report.md`, `task-N-review.md`).
- Last verified gates: **271 tests passed**,
  `npm run test:coverage` at plan targets, `npm run typecheck` exit 0, `npm run lint` exit 0.
  Coverage baseline: core 97.46%, daemon 89.94%, brain 96.34%, mcp 87.98%, renderer model 95.13%.
- Windows installer built locally (unpacked-launch smoke passed):
  `packages/app/release/OpenVault-0.1.0-alpha.1-win-x64.exe` — 121,250,505 bytes,
  SHA256 `60cb6baf2923d9f4415f23b364e30985d1df029e7a32fdfbe0f991a753cd1e5a`.
- Site already redeployed (Task 10): `https://openvault-4dn.pages.dev/` plus
  `/docs/`, `/architecture/`, `/hackathon/` all verified HTTP 200.

## What was built in this hardening round

- **MCP is required and shipped** — local stdio server (`packages/mcp/src/server.ts`),
  `MCP_VERSION = 0.1.0-alpha.1`, 5 tools, host configs in `docs/MCP.md`.
  "Deploy" = IDEs launch it locally; nothing cloud-hosted. Real-stdio e2e test exists.
- **Settings page** (Approval/Vault/Audit/Policies/Settings): warden provider
  (None / Ollama / Meta API), model switcher, effort switcher, Meta API key path.
  Key stored encrypted as credential `warden-meta-api`, only `last4` ever shown,
  routes token-guarded (`GET/PATCH /settings/warden`, `PUT/DELETE/GET /settings/warden/key`,
  real self-check `POST /settings/warden/test`).
- **Warden providers**: Ollama (default `llama3.2:3b`) + Meta API
  (`https://api.llama.com/v1/chat/completions`, verified from official docs, cited in
  `packages/brain/src/meta-api.ts`). Effort: fast 1 pass/10s, standard 1 pass/30s,
  deep 2 passes/60s (disagreement escalates, keeps narrower scope).
- **Audit page**: every request grouped by `requestId` with warden verdict timeline
  (risk, recommended scope, decision source, latency, explanation). No secrets in audit.
- **Pen test done**: `docs/SECURITY-AUDIT.md`, `test/security/pentest.test.ts`,
  `scripts/pentest.mjs` (live run 13 PASS / 0 FAIL). Fixed: 1 High (fail-open token
  guard), 2 Medium, 2 Low. 3 accepted risks documented (A1–A3 + info).
- **CI/CD**: `.github/workflows/{ci,codeql,release}.yml`, CODEOWNERS, PR/issue
  templates, Dependabot. `CONTRIBUTING.md` has an honestly-labelled *manual*
  repo-settings checklist (branch protection, secret scanning) — not yet toggled on GitHub.

## Final review fix wave (Completed)

- **Must-fix #1 (phantom `modelId`)**: Fixed in `packages/daemon/src/service.ts`. Stamped `modelId` only when marshal actually ran (`marshalRan`). Dropped `modelId` from policy-only chains (pre-check denials, revoked denials, provider-`none` chains) and policy-only pendings in `listPendingApprovals`. Regression tests added in `packages/daemon/test/audit-trail.test.ts`.
- **Must-fix #3 (version test surface)**: Added fifth surface `packages/mcp/package.json` to `test/version.test.ts`.
- **Low (phantom Policies rows)**: Updated `derivePolicies` in `packages/app/src/renderer/model.ts` to skip administrative/lifecycle events (`settings-changed`, `enrollment-created`, `enrollment-completed`). Regression test added in `packages/app/test/model.test.ts`.
- **Full gates & rebuild**: 271 tests passing, coverage targets met, typecheck/lint exit 0, Windows installer rebuilt (121,250,505 bytes, SHA256 `60cb6baf2923d9f4415f23b364e30985d1df029e7a32fdfbe0f991a753cd1e5a`).

## Remaining tasks (in order)

### 4. Push and get CI green BEFORE tagging (final-review must-fix #2)

- **Authority: the user/owner does the push, tag, and release — or explicitly
  tells the agent to.** An agent resuming from this file should stop after
  Task 3 (fix wave committed locally), report ready, and wait for that go-ahead.
- Push `main` (22 local commits + the Task 3 fix-wave commit = 23). This is the first-ever CI/CodeQL run —
  there is no run URL yet; nothing may claim CI passes until observed.
- Watch `.github/workflows/ci.yml` (windows + ubuntu) and `codeql.yml`; fix any
  first-run failures. Record the green run URL in `docs/VERIFICATION.md`.
- Only after CI is green: `git tag v0.1.0-alpha.1` and push the tag.
  `release.yml` (SHA-pinned `softprops/action-gh-release@v2.6.2`, locked
  `electron-builder@26.18.0`, `prerelease: true`) will build the Windows NSIS
  installer + SHA256SUMS and attach them to a GitHub prerelease.
- Verify the prerelease page shows the installer + checksums; link it from
  `README.md` and the site, then redeploy the site:
  `npx -y wrangler pages deploy site --project-name openvault --branch main --commit-dirty=true`
- Note: push/tag/release are external side effects — they were deliberately left
  for the user. Do not tag from a red CI.

### 5. Manual GitHub repo settings (owner only, ~5 minutes)

Per `CONTRIBUTING.md` manual checklist: enable branch protection/ruleset on
`main` (PR-only, CI green, one review), secret scanning + push protection,
Dependabot alerts. Not enforced by any file in the repo until toggled.

### 6. Hackathon submission leftovers

- Record the full 3-minute live demo video on the user's machine (only a
  screenshot walkthrough exists in `docs/verification/`).
- Semantic data-flow charting for docs was explicitly deferred until after this
  hardening round — it is the next docs task, not yet started.
- macOS DMG + code signing remain parked (Windows-first decision).

## Deferred minors (can ship in alpha; fix opportunistically)

From the ledger/final review: no audit event for Meta key set/delete;
`wardenKeyStatus` reports `configured: true` on corrupt ciphertext; unbounded
model/baseUrl free text (bounded in practice by 64 KiB body cap); key draft
retained on ambiguous save response; completed enrollments never purged from
memory; MCP bin unshebanged/monorepo-relative (documented `node dist/...` path
works); `prerelease: true` hardcoded in release.yml for future non-alpha tags;
stale `OpenVault-0.1.0-win-x64.exe` name in the old VERIFICATION installer section;
settings/brain double-read race (self-healing next request); provider-`none`
skip lives only at the service layer; standard/deep timeouts asserted as
constants, not clock-tested; Meta API model ids user-editable, not docs-verified.

## Hard rules that still bind

- Secrets never reach agents, the marshal prompt, audit rows, logs, or the
  renderer after save. Policy is law; the model may narrow/escalate, never widen.
- Human-mutation routes require `x-openvault-token`; agent/MCP traffic must never carry it.
- Windows first. Effect TS in core/daemon/brain; plain TypeScript UI.
- Versioning: `0.1.0-alpha.1` is correct (unsigned, no macOS, contract may change).
  Drop `-alpha.N` at the first signed feature-frozen release.
