# Verification — measured gates (2026-10-31)

Every number below was produced by running the gate on the demo-class
machine (Windows, NVIDIA GeForce RTX 3070 8 GB, Node 24, Ollama with
`llama3.2:3b` Q4, 2.0 GB model download) and saving the raw output next
to this file. Re-run any gate with the commands shown.

## Gate results

| Gate | Command | Result |
|---|---|---|
| Unit + integration tests | `npm test` | **268 passed** (33 files), 0 failed |
| Typecheck (strict) | `npm run typecheck` | exit 0 |
| Lint (max-warnings 0) | `npm run lint` | exit 0 |
| Brain eval, fake brain | `node dist/packages/brain/eval/run-eval.js --fake` | risk 76.5%, approval 100%, **safety 100%, gate PASS** (1.2 s wall) |
| Brain eval, live marshal | `node dist/packages/brain/eval/run-eval.js --live` | risk 23.5%, approval 64.7%, **safety 100%, gate PASS** (59.7 s / 17 scenarios) |
| Demo rehearsal (live) | `node scripts/rehearse-demo.mjs` | **7/7 PASS**, 3.6 s wall |
| Two-host MCP check | `node scripts/check-mcp-hosts.mjs` | **PASS** for both hosts (4.3 s / 4.8 s incl. model call) |
| Electron GUI | manual CDP-driven run, screenshots below | Approval, Audit, Vault verified live |
| Windows installer | `npx electron-builder --win nsis` | built, 115.6 MB, unsigned |
| Demo walkthrough video | ffmpeg from live screenshots | 21 s, 1280x720, h264 |

Raw outputs: `eval-fake.txt`, `eval-live.txt`, `rehearsal.txt`,
`mcp-two-host.txt` in this directory.

## Coverage baseline (Task 7, measured before thresholds)

Measured with `npm run test:coverage` (Vitest + `@vitest/coverage-v8`,
247 tests passing) **before** any coverage thresholds were configured and
before the Task 7 canary/e2e tests were added. Statements and lines are
identical for every row in this codebase (V8 provider, one statement per
line in the measured output).

| Package / file | Statements | Lines | Plan target (statements/lines) | Meets target? |
|---|---|---|---|---|
| `packages/core` | 97.46% | 97.46% | ≥ 90% | yes |
| `packages/daemon` | 88.96% | 88.96% | ≥ 85% | yes |
| `packages/brain` | 96.34% | 96.34% | ≥ 85% | yes |
| `packages/mcp` | 87.98% | 87.98% | ≥ 85% | yes |
| `packages/app/src/renderer/model.ts` | 95.09% | 95.09% | ≥ 90% | yes |

All five measured values already met the plan targets, so the thresholds
in `vitest.config.ts` were set exactly at the plan targets (90 / 85 / 85 /
85 / 90) with no lowering. Renderer DOM code (`main.ts`) and the Electron
main process are excluded from thresholds and covered by smoke
screenshots instead, as stated in the config comments.

## How to read the live eval

The 3B marshal's risk labels are weak (23.5% risk accuracy live) and we
say so in the README. The number that matters is the safety rate:
**100% in both modes** — across benign reads, writes phrased as reads,
scope escalation, prompt injection in the reason field, bursts, and a
marshal that is down or lying, no write ever executed without approval
and no scope ever escaped its ceiling. Policy is the floor; the marshal
is discretion within bounds. That is the design working as designed.

Warm marshal latency: the rehearsal's live `charges.read` request
completed marshal + policy in **1,872 ms** (model already loaded).
Cold eval averaged ~3.5 s per scenario including model variance.

## Rehearsal detail (`scripts/rehearse-demo.mjs`)

Boots the real `vaultd` against a mock Stripe upstream with the real
Ollama marshal, seeds one ciphertext credential, then asserts:

1. Agent request vetted by the live marshal (executed or parked).
2. `POST /approve` without the daemon token returns **401**.
3. Mock upstream received `Authorization: Bearer <secret>` — injected
   inside the daemon; the secret appears in **no** response.
4. A requested write under a read ceiling is **denied** (this gate
   caught a real downgrade-to-read bug; fixed in `policy.ts`).
5. After revoke, the agent's next request is denied in ~10 ms.
6. The audit log records requested → marshal → policy → approved →
   executed → denied → revoked with zero secret leakage.

## Two-host MCP gate (`scripts/check-mcp-hosts.mjs`)

Two independent MCP stdio processes, configured the way VS Code and
Claude Code hosts configure MCP servers (`METAVAULT_AGENT_ID` /
`METAVAULT_IDE` per host), connected to one daemon. Both listed aliases
and requested a capability; neither transcript contained the secret.
This is the protocol-level equivalent of pasting the snippet into two
IDEs; both IDEs are present on this machine and use this exact transport.

## Electron GUI (live screenshots)

- `electron-approval.png` — a real pending request in the Approval hero:
  marshal assessment, expiry countdown, Approve/Deny/Always allow.
  (The 3B marshal labelled this one LOW RISK while still requiring
  approval — the human gate held. We show it because it is honest.)
- `electron-audit.png` — the Audit timeline after clicking **Deny** in
  the real window: Requested → Marshal → Policy → Denied by human, each
  marshal row naming `llama3.2:3b`.
- `electron-vault.png` — the Vault home: `stripe · charges.read`,
  values never displayed.

Two real bugs were found by this gate and fixed: the preload was
emitted as ESM (blank app) and sandboxed preloads cannot fetch (daemon
client moved to the main process behind a whitelisted IPC channel).

## Installer

`MetaVault OSS-0.1.0-win-x64.exe` (NSIS, 115.6 MB) builds cleanly and is
unsigned (no certificate in this environment). The macOS DMG config is
declared but building it requires a Mac; it is the one remaining
packaging item, along with code signing.

## Demo video

`demo-walkthrough.mp4` (21 s) is assembled from the live screenshots
above. It is a walkthrough, not a screen recording of a live session;
record the full 3-minute script (README) on demo day as the fallback.

## Task 10 — docs screenshots + agent flows (2026-10-31)

Four screenshots were captured from the **real running app** (built
Electron renderer + real preload + real main-process daemon client)
against a real daemon (`startVaultDaemon`) with a stub warden brain and a
mock upstream. State was generated through the daemon HTTP API only,
seeded with a fake test credential (`sk-test-FAKE-…`, never a real
secret); the executed chain was produced by `POST /request` →
`POST /approve` (token-guarded) against the mock upstream, and the
enrollment by `POST /enrollments` → the real `openvault://add` deeplink.
The harness asserted the fake secret appears in no daemon response and
in no rendered view before saving each shot.

| Screenshot | What it proves |
|---|---|
| `docs/verification/approval-dialog.png` | Pending request with agent/scope/reason, LOW RISK marshal assessment + explanation, expiry, and **Approve once / Deny / Always allow** buttons |
| `docs/verification/audit-verdict.png` | Audit view with one executed request expanded: Requested → Marshal → Policy → Approved → Executed, with explanation, recommended scope, `1ms` latency, decision sources and model `llama3.2:3b` |
| `docs/verification/enroll-flow.png` | Deeplink-prefilled Add-credential modal (`github` / `repos.read` / `github.com`), secret field empty |
| `docs/verification/settings.png` | Settings page (refreshed): warden provider radios, Ollama model catalogue, effort — key field empty |

The same four images are wired into the site docs page
(`site/docs/index.html`, served at `/docs/` under
`/assets/shots/`) and into the README's end-to-end flows section. The
site docs and README gained an MCP install section (five hosts, five
tools), a Settings/warden section, and a security-levels table aligned
with the Task 3 tiers (`none` / `llama3.2:3b` Medium / `llama3.1:8b`
High / `llama3.3:70b` Maximum-local / Meta API cloud; effort
Fast 10s / Standard 30s / Deep 60s). Semantic data-flow charting stays
deferred, per the plan.

Gates for this task (run in-session): `npm run test` — **268 passed**
(33 files); `npm run typecheck` — exit 0; `npm run lint` — exit 0.

Site redeploy: `npx -y wrangler deploy --config wrangler.worker.jsonc` (the `metahackathon-vault` Worker serves `metahackathon.whativedone.xyz`; the `openvault` Pages project is a preview mirror only). Deployment and route
checks (`/`, `/docs/`, `/architecture/`, `/hackathon/` → 200) are
recorded in the Task 10 report
(`.superpowers/sdd/2026-10-31-openvault-hardening-release/task-10-report.md`).

## Task 11 — v0.1.0-alpha.1 local release build (2026-10-31)

Local build only: no tag, no push, no GitHub release (the tag-triggered
release workflow remains unproven until its first `v*` run).

| Item | Value |
|---|---|
| Installer | `MetaVault OSS-0.1.0-alpha.1-win-x64.exe` (NSIS, x64, unsigned) |
| Size | 121,250,505 bytes (115.6 MB) |
| SHA256 | `60cb6baf2923d9f4415f23b364e30985d1df029e7a32fdfbe0f991a753cd1e5a` |
| Built with | `cd packages/app && npm run build && npx electron-builder --win --publish never` (locked root devDependency `electron-builder@26.18.0`, Electron 45.2.1) |

Gates (in-session, after the version bump and final review fix wave): `npm run test` — **271
passed** (34 files, including the extended `test/version.test.ts` asserting
root `package.json` = `packages/app/package.json` = `packages/mcp/package.json` = `MCP_VERSION` =
renderer `APP_VERSION_DISPLAY` = `0.1.0-alpha.1`);
`npm run test:coverage` — exit 0 (all package thresholds met);
`npm run typecheck` — exit 0; `npm run lint` — exit 0.

GitHub Actions CI / CodeQL verification on `main`:
- **CI run** (Windows + Ubuntu): https://github.com/0xm0w/metavault-oss/actions/runs/41223410981 — **PASS** (exit 0).
- **CodeQL run**: https://github.com/0xm0w/metavault-oss/actions/runs/41223410962 — **PASS** (exit 0).

Smoke: the NSIS installer itself was **not** run (install requires
interactive per-user install steps); instead the packaged app was
launched from `packages/app/release/win-unpacked/MetaVault OSS.exe` with an
isolated `--user-data-dir`. It stayed alive with a window titled
“MetaVault OSS” (main + 3 child processes) and was then stopped. Renderer
daemon calls returned 401/404 during the smoke because the isolated
profile holds no daemon token — expected without a configured daemon,
and recorded here rather than hidden. A first launch against the
default profile exited immediately via the single-instance lock, which
is the designed behaviour when another instance/profile is present.

## Codebase

43 TypeScript files, 6,649 lines (packages + root canary test), 268
tests. Secrets appear in the repo only as fake canary/test strings.
