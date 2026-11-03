# MetaVault OSS — Handover (2026-10-31, repo renamed from metavault)

Read this first when resuming. Repo: `C:\Users\Mowreez.DESKTOP-D1GHS6J\metavault`
Private remote: `https://github.com/0xm0w/metavault-oss` (renamed from 0xm0w/metavault; old URL redirects)

## Where things stand

- Branch `main` pushed and merged via PR #1 (https://github.com/0xm0w/metavault-oss/pull/1).
- Working tree clean. `main` is up to date with `origin/main`.
- CI/CD verified green on GitHub Actions:
  - CI: https://github.com/0xm0w/metavault-oss/actions/runs/41223410981 (Windows + Ubuntu exit 0)
  - CodeQL: https://github.com/0xm0w/metavault-oss/actions/runs/41223410962 (exit 0)
- Hardening plan (11 tasks) + Final Review Fix Wave are implemented: Tasks 1–11 all built and reviewed, plus must-fix #1, must-fix #3, and Low issues resolved and verified. (The implementation plans were removed in #70 as obsolete; see git history.)
- SDD ledger (task-by-task record, deferred minors, rulings):
  `.superpowers/sdd/2026-10-31-metavault-hardening-release/progress.md`
  Per-task reports + review diffs are in the same folder (`task-N-report.md`, `task-N-review.md`).
- Last verified gates: **271 tests passed**,
  `npm run test:coverage` at plan targets, `npm run typecheck` exit 0, `npm run lint` exit 0.
  Coverage baseline: core 97.46%, daemon 89.94%, brain 96.34%, mcp 87.98%, renderer model 95.13%.
- Windows installer built locally (unpacked-launch smoke passed):
  `packages/app/release/MetaVault OSS-0.1.0-alpha.1-win-x64.exe` — 121,250,505 bytes,
  SHA256 `60cb6baf2923d9f4415f23b364e30985d1df029e7a32fdfbe0f991a753cd1e5a`.
- Site already redeployed (Task 10): `https://metavault-4dn.pages.dev/` plus
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
- **Warden providers**: Ollama / built-in on-device (default `muse-glimmer:30b`, Meta
  Muse Glimmer 30B Q4_K_M, #70) + Meta API (`https://api.meta.ai/v1/chat/completions`,
  default `muse-spark-1.3`, per https://dev.meta.ai/docs/models, cited in
  `packages/brain/src/meta-api.ts`). Effort: fast 1 pass, standard 1 pass, deep 2 passes
  (disagreement escalates, keeps narrower scope); timeouts cloud 10/30/60 s, local 60/120/240 s.
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
- **Release v0.1.0-alpha.1 published**: Tag `v0.1.0-alpha.1` pushed. GitHub Release created at https://github.com/0xm0w/metavault-oss/releases/tag/v0.1.0-alpha.1 with NSIS installer and SHA256SUMS attached. Site and README links updated and redeployed.

## Remaining tasks (in order)

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
works); release.yml marks a tag as a prerelease only when its name contains a hyphen;
stale `MetaVault OSS-0.1.0-win-x64.exe` name in the old VERIFICATION installer section;
settings/brain double-read race (self-healing next request); provider-`none`
skip lives only at the service layer; standard/deep timeouts asserted as
constants, not clock-tested; Meta API model ids user-editable, not docs-verified.

## Hard rules that still bind

- Secrets never reach agents, the marshal prompt, audit rows, logs, or the
  renderer after save. Policy is law; the model may narrow/escalate, never widen.
- Human-mutation routes require `x-metavault-token`; agent/MCP traffic must never carry it.
- Windows first. Effect TS in core/daemon/brain; plain TypeScript UI.
- Versioning: `0.1.0` is the first public release (2026-11-01). The Windows
  installer is still unsigned, and there is still no macOS build.
  `v0.1.0-alpha.1` remains the earlier prerelease.
