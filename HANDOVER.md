# OpenVault — Handover (2026-10-31)

Read this first when resuming. Repo: `C:\Users\Mowreez.DESKTOP-D1GHS6J\openvault`
Private remote: `https://github.com/0xm0w/openvault`

## Where things stand

- Branch `main` at `057d106` (`chore(release): v0.1.0-alpha.1 (local build)`).
- Working tree clean. **`main` is 22 commits ahead of `origin/main` — NOT pushed.**
  Last pushed commit: `77a9405`. Everything after that is local only. Push when ready.
- Hardening plan (11 tasks) is implemented: Tasks 1–11 all built, each with a
  task review + fix round. Plan: `docs/superpowers/plans/2026-10-31-openvault-hardening-release.md`
- SDD ledger (task-by-task record, deferred minors, rulings):
  `.superpowers/sdd/2026-10-31-openvault-hardening-release/progress.md`
  Per-task reports + review diffs are in the same folder (`task-N-report.md`, `task-N-review.md`).
- Last verified gates (Task 11, commit `057d106`): **269 tests passed**,
  `npm run test:coverage` at plan targets, `npm run typecheck` exit 0, `npm run lint` exit 0.
  Coverage baseline: core 97.46%, daemon 88.96%, brain 96.34%, mcp 87.98%, renderer model 95.09%.
- Windows installer built locally (not installed/run as installer; unpacked-launch smoke passed):
  `packages/app/release/OpenVault-0.1.0-alpha.1-win-x64.exe` — 121,250,465 bytes,
  SHA256 `df8bb027808d8cbd876122283dcc874a10e9828fc1f6d35c1aea5a0486155cb8`.
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

## Remaining tasks (in order)

### 1. Fix final-review must-fix #1 — phantom `modelId` (Medium, do first)

Whole-branch final review verdict: **NOT READY TO TAG** until this is fixed.
Root cause already traced (do not re-investigate from scratch):

- In `packages/daemon/src/service.ts`, `requestCapability` stamps the static default
  `modelId` (`llama3.2:3b`) on audit events where **no marshal ran**: the
  revoked-denial path (~line 564) and the unknown-alias/rate-limit policy+denied pair
  (~line 589) call `audit(..., withModel=true)` with no override. Post-marshal
  policy/denied events (~line 657) stamp `marshalModelId` even on provider-`none`
  chains, and `listPendingApprovals` (~line 818) attaches the static model to
  policy-only pendings.
- Symptom: Audit page timeline shows a model "deciding" requests that policy alone
  denied. These rows persist in user vaults, so alpha users' history would be
  permanently misattributed. The chip label hides it (`policy-only` when risk is
  null); the expanded timeline in `packages/app/src/renderer/main.ts` (~line 782) does not.
- Fix: stamp `modelId` only when a marshal decision/failure actually occurred;
  drop `modelId` from policy-only pendings.
- Regression test (TDD, failing first): provider-`none` / policy-denied audit chain
  events carry **no** `modelId`. Existing test
  `packages/daemon/test/audit-trail.test.ts` (~line 117) asserts stages/sources but
  never `modelId` absence — extend it. This gap is how it slipped through 3 reviews.
- Process note: `systematic-debugging` skill was loaded for this fix; root cause is
  confirmed above, so go straight to Phase 4 (failing test → fix → verify).
  Dispatch ONE fix subagent, then a scoped re-review of the fix diff (SDD pattern
  used all session: implementer → review package via `git diff BASE..HEAD` →
  reviewer → fix round if needed). For this fix round, BASE is `057d106`.
  Tasks 1+2 below land as that single fix-wave commit (see Task 3).

### 2. Fix final-review must-fix #3 + Low (same commit is fine)

- Must-fix #3: `test/version.test.ts` (~line 20) pins root, app, `MCP_VERSION`,
  `APP_VERSION_DISPLAY` — add the fifth surface `packages/mcp/package.json`
  (currently correct at `0.1.0-alpha.1`, just unpinned by the test).
- Low: phantom Policies rows. `derivePolicies` in
  `packages/app/src/renderer/model.ts` (~line 507) skips only
  `credential-added`/`credential-deleted`, so `settings-changed` creates a bogus
  "human" agent row and `enrollment-completed` (audited as literal `"agent"` in
  `service.ts` ~line 440) creates an "agent" row. One-line skip-list fix + test.

### 3. Re-run full gates and rebuild installer

```powershell
npm run test            # expect >= 269 passed
npm run test:coverage
npm run typecheck
npm run lint
cd packages/app; npm run build; npx electron-builder --win
```

Record the new installer size + SHA256 in `docs/VERIFICATION.md`
(replaces the `057d106` numbers above). Commit the fix wave as one commit.
Update the SDD ledger (`progress.md`) with fix-round + completion lines.

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
