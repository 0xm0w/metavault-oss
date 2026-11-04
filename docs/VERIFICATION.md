# Verification — measured gates (2026-10-31)

Every number below was produced by running the gate on the demo-class
machine (Windows, NVIDIA GeForce RTX 3070 8 GB, Node 24, Ollama with the
previous ~2 GB local model) and saving the raw output next to this file.
Re-run any gate with the commands shown.

> **#70 (2026-11-03):** the local warden is now Meta **Muse Glimmer 30B
> Q4_K_M** (`muse-glimmer:30b`). The fake-brain eval was re-run on the agent
> box (`eval-fake.txt`). No live Muse Glimmer eval output is committed, so no
> local Glimmer numbers are published here (see
> `verification/eval-live-muse-glimmer-quants.md`). The old live output was removed.
> The rehearsal and two-host MCP rows below predate #70 and used the previous local model.

## Gate results

| Gate | Command | Result |
|---|---|---|
| Unit + integration tests | `npm test` | Node 22.23.4 (CI version, Ubuntu + Windows, run 41659945365 on main ccb12d1): **521 passed, 3 skipped** (65 files, 1 skipped); Node 24.22.1: **522 passed, 2 skipped**. The extra skip on Node 22 is the argon2id keywrap test (`runIf(argon2Available())`; Node 22 has no `crypto.argon2`). Re-run 2026-11-03 on the box |
| Typecheck (strict) | `npm run typecheck` | exit 0 |
| Lint (max-warnings 0) | `npm run lint` | exit 0 |
| Brain eval, fake brain | `node dist/packages/brain/eval/run-eval.js --fake` | risk 76.5%, approval 100%, **safety 100%, gate PASS** (re-run 2026-11-03) |
| Brain eval, live marshal (Muse Glimmer 30B) | `scripts\eval-windows.ps1 -Compare` | no committed result (raw output not in the repo) |
| Demo rehearsal (live) | `node scripts/rehearse-demo.mjs` | **7/7 PASS** (previous local model) |
| Two-host MCP check | `node scripts/check-mcp-hosts.mjs` | **PASS** for both hosts (366 ms / 378 ms, [`mcp-two-host.txt`](verification/mcp-two-host.txt)) |
| Electron GUI | manual CDP-driven run, screenshots below | Approval, Audit, Vault verified live |
| Windows installer | CI `Windows installer` workflow (`electron-builder --win --publish never`) | `MetaVault-OSS-0.1.0-alpha-win-x64.exe`, 121,940,486 bytes, unsigned; clean-install smoke test PASS ([log](verification/windows-installer-smoke.txt)) |
| Demo walkthrough video | ffmpeg from live screenshots | 21 s, 1280x720, h264 |

Raw outputs: `eval-fake.txt`, `rehearsal.txt`,
`mcp-two-host.txt` in this directory.

## Research thesis benchmark (`packages/brain/eval/run-thesis.ts`)

Four arms on the same vault policy: always-ask, rules-only (`packages/brain/src/rules.ts`,
frozen in `793371d` before the held-out set in `702bb2b`), warden, rules+warden.
Box run (Linux, commit `342f39f`), held-out set, 60 cases:

| arm | high-risk read recall | policy floor | FPR all | FPR hard | FPR plain | median / p95 |
|-----|-----|-----|-----|-----|-----|-----|
| always-ask | 28/28 | 4/4 | 28/28 | 20/20 | 8/8 | - |
| rules | 12/28 (42.9%) | 4/4 | 9/28 (32.1%) | 9/20 | 0/8 | 6.8 us / 21.3 us |
| warden: Muse Spark 1.3, Meta API (2 runs) | 25/28 (89.3%) both runs | 4/4 | 0/28 (0%) | 0/20 | 0/8 | 8,940 / 17,320 ms; 8,209 / 14,751 ms |
| rules + Muse Spark 1.3 (2 runs) | 27/28 (96.4%) both runs | 4/4 | 9/28 (32.1%) | 9/20 | 0/8 | 8,940 / 17,321 ms; 8,209 / 14,754 ms |
| warden, rules+warden: Muse Glimmer, local | not run | | | | | |

Muse Spark runs: `verification/thesis-muse-spark-1.3-heldout-2026-11-03T08-14-24-236Z.*` and
`...T08-25-08-673Z.*` (16:14 and 16:25 PHT), `max_tokens` 2048, JSON mode, one repeat each.
Each run had 1/60 warden failures, both at the 2,048-token output cap (invalid JSON on
`ho-email-finance` in run 1, empty content on `ho-browser-logins` in run 2), both paraphrased
high-risk reads. **Counting rule: a failed warden call counts as a miss**, so recall above is
real decisions only. A failure still fails closed to a human, so the request was stopped; counted
that way the numbers would be 26/28 and 28/28. Paraphrased high-risk reads: warden 21/22 in
both runs. The warden alone missed both
history-only anomalies (`ho-burst`, `ho-denied-retry`) in both runs; rules catch them. The rules
latencies in those files (40-42 us median) are from the same box under network load; the table
row above is the dedicated rules-only run. Muse Glimmer is not offered by the Meta API
(`GET https://api.meta.ai/v1/models` on 2026-11-03 listed muse-wonder-1.0, sam-3.1,
muse-spark-1.3, muse-spark-1.3-contributor, muse-spark-1.2, muse-spark-1.2-contributor,
muse-spark-1.1, muse-voice-transcribe-1.0, muse-image-1.0), so it was not run there.

Dev set (20 cases): rules 10/10 recall, 0/10 FPR. Oracle runs (`--oracle`) are harness
checks only. Raw: `verification/thesis-*.txt|json`. Review: `research/thesis-review.md`.

### Comparison baselines: free models on OpenCode Zen (not shipped)

These are comparison points only; the shipped warden stays a Meta model. Harness:
`--provider openai-compat --base-url https://opencode.ai/zen/v1 --api-key-env OPENCODE_API_KEY
--price-in 0 --price-out 0 --pricing-url https://opencode.ai/docs/zen --min-interval-ms 3000`
(retries 429/5xx with backoff and `Retry-After`; logs `usage` tokens per call; a quota
refusal aborts the run so nothing else is sent).

| Zen model id | maker | model card | status (2026-11-03 15:57 PHT, held-out) |
|---|---|---|---|
| `deepseek-v4.1-flash-free` | DeepSeek | https://huggingface.co/deepseek-ai/DeepSeek-V4.1-Flash | blocked |
| `glm-5.3-flash-free` | Z.ai | https://huggingface.co/zai-org/GLM-5.3-Flash | blocked |
| `mimo-v2.6-flash-free` | Xiaomi | https://huggingface.co/XiaomiMiMo/MiMo-V2.6-Flash-RL | blocked |
| `nemotron-3.5-lightning-free` | NVIDIA | https://huggingface.co/nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16 | blocked |
| `nemotron-3.5-super-vl-free` | NVIDIA | https://huggingface.co/nvidia/NVIDIA-Nemotron-3.5-Super-VL-120B-A12B-BF16 | blocked |
| `flint-40b-free` | Recursive | https://huggingface.co/RecursiveSI/flint | blocked |
| `beam-free` | Reflection | https://huggingface.co/reflection/Beam-1.0-501B-A23B | blocked |

Excluded: `big-pickle` and `pulse-alpha-free`, which Zen lists as stealth models with no
named maker or card, so their benchmarks are unknown.

Every run stopped at its first request with HTTP 429 `FreeUsageLimitError` ("Free usage
limit reached. Free models work in OpenCode ..."). That is a quota refusal, not a rate
limit, so it is not retried; the other 59 cases are recorded as "not sent". Result:
0/60 answered per model, 0 tokens, so **no recall, FPR, latency or token figures exist
for these models**. Raw: `verification/thesis-<model>-heldout-2026-11-03T07-57-*.txt|json`.

### Dollars per gated request

One gated request = one warden call (60 per held-out run). Cost =
`prompt_tokens x input price + completion_tokens x output price` (cached input at its own
rate), from the `usage` field of each response; the run report prints tokens and dollars per
gated request. `--budget-usd` (default 0.50) refuses any call whose worst-case cost would
pass the cap.

| tier | price source | $ per gated request | tokens per gated request |
|---|---|---|---|
| Policy only | none | $0 (no model) | 0 |
| Muse Glimmer quants, local | none | $0 in API fees (electricity excluded) | not measured (held-out run not done) |
| Free baselines (Zen) | https://opencode.ai/docs/zen lists them as Free | $0 | not measured (quota refused every call) |
| Muse Spark 1.3, Meta API | https://dev.meta.ai/docs/pricing-rate-limits: $1.25 in / $4.25 out / $0.15 cached per 1M | $0.005309 (run 1), $0.005159 (run 2) | 1,537.2 (run 1), 1,505.2 (run 2); about 397 prompt + 1,108-1,140 completion |

Meta API spend on 2026-11-03, from `usage`: run 1 $0.318518 (92,232 tokens), run 2 $0.309563
(90,313 tokens), $0.628081 measured. An earlier run was stopped after 18 calls before it wrote
its report, so its `usage` was not kept; the same 18 cases cost $0.120539 in run 1, and their
ceiling at `max_tokens` 2048 is $0.165757. Total Meta API spend: about $0.749, at most $0.794.
Per-call logs (`*.calls.jsonl`, no key) now record spend as it happens.

Meta run, once a key is set: `META_API_KEY=... npx tsx packages/brain/eval/run-thesis.ts --live
--provider meta-api` (defaults: `muse-spark-1.3`, `https://api.meta.ai/v1`, $0.50 cap).

## Coverage today (2026-11-03, Node 22.23.4)

`npm run test:coverage` exits 0 with every threshold met. Statements / lines:
core 93.11% / 95.38% (threshold 90), daemon 89.96% / 89.92% (85), brain 95.16% / 94.57% (85),
mcp 88.11% / 89.24% (85), renderer `model.ts` 93.77% / 95.27% (90). Core was 89.51% before
`packages/core/test/keychain-platforms.test.ts` added real tests for the macOS, Windows and
Linux keychain paths.

## Coverage baseline (Task 7, measured before thresholds)

Historical baseline: measured with `npm run test:coverage` (Vitest + `@vitest/coverage-v8`,
247 tests passing at the time) **before** any coverage thresholds were configured and
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

## How to read the brain eval

The fake-brain eval (`eval-fake.txt`) scores risk labels at 76.5%: the fake
brain is deliberately fooled on four scenarios. The number that matters is
the safety rate: **100%** — across benign reads, writes phrased as reads,
scope escalation, prompt injection in the reason field, bursts, and a
marshal that is down or lying, no write ever executed without approval
and no scope ever escaped its ceiling. Policy is the floor; the marshal
is discretion within bounds.

Warm marshal latency (previous local model, before #70): the rehearsal's
live `charges.read` request completed marshal + policy in **1,872 ms**
(`rehearsal.txt`). No Muse Glimmer latency is committed.

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
  (The previous local marshal labelled this one LOW RISK while still requiring
  approval — the human gate held. We show it because it is honest.)
- `electron-audit.png` — the Audit timeline after clicking **Deny** in
  the real window: Requested → Marshal → Policy → Denied by human, each
  marshal row naming the previous local model (screenshot predates #70).
- `electron-vault.png` — the Vault home: `stripe · charges.read`,
  values never displayed.

Two real bugs were found by this gate and fixed: the preload was
emitted as ESM (blank app) and sandboxed preloads cannot fetch (daemon
client moved to the main process behind a whitelisted IPC channel).

## Installer

`MetaVault-OSS-0.1.0-alpha-win-x64.exe` (NSIS, x64, 121,940,486 bytes,
SHA256 `79a76ca029bbcbf774e830ff4ca8094a35c15f8f0e9c6a778ad9411bdfac7f78`)
is built by CI run
[41627209888](https://github.com/0xm0w/metavault-oss/actions/runs/41627209888)
and attached to the draft `v0.1.0-alpha` release. It is unsigned (no
certificate). The same run's clean-install smoke test passed:
[`verification/windows-installer-smoke.txt`](verification/windows-installer-smoke.txt). The macOS DMG config is
declared but building it requires a Mac; it is the one remaining
packaging item, along with code signing.

## Task 10 — docs screenshots + agent flows (2026-10-31)

Four screenshots were captured from the **real running app** (built
Electron renderer + real preload + real main-process daemon client)
against a real daemon (`startVaultDaemon`) with a stub warden brain and a
mock upstream. State was generated through the daemon HTTP API only,
seeded with a fake test credential (`sk-test-FAKE-…`, never a real
secret); the executed chain was produced by `POST /request` →
`POST /approve` (token-guarded) against the mock upstream, and the
enrollment by `POST /enrollments` → the real `metavault://add` deeplink.
The harness asserted the fake secret appears in no daemon response and
in no rendered view before saving each shot.

| Screenshot | What it proves |
|---|---|
| `docs/verification/approval-dialog.png` | Pending request with agent/scope/reason, policy-only MEDIUM RISK assessment (no local AI) + explanation, expiry, and **Approve once / Deny / Block agent** buttons (**Always allow** appears only for low-risk read-only verified requests) |
| `docs/verification/audit-verdict.png` | Audit view with one request expanded: Requested → Policy (approval-required) timeline in policy-only mode |
| `docs/verification/enroll-flow.png` | Deeplink-prefilled Add-credential modal (`github` / `repos.read` / `github.com`), secret field empty |
| `docs/verification/settings.png` | Settings modal, Warden tab: hardware recommendation, warden provider radios (policy-only selected) |

The same four images are wired into the site docs page
(`site/docs/index.html`, served at `/docs/` under
`/assets/shots/`) and into the README's end-to-end flows section. The
site docs and README gained an MCP install section (five hosts, five
tools), a Settings/warden section, and a security-levels table aligned
with the Task 3 tiers (at the time: `none`, three local sizes, and Meta
API cloud; effort Fast 10s / Standard 30s / Deep 60s). Since 2026-11-03 MetaVault
ships and downloads no model: the default is Muse Spark via the Meta API, a local model is the
user's own endpoint (Muse Glimmer recommended), and local timeouts are 60 / 120 / 240 s. Semantic data-flow charting stays
deferred, per the plan.

Gates for this task (run in-session, 2026-10-31; historical): `npm run test` — **268 passed**
(33 files); `npm run typecheck` — exit 0; `npm run lint` — exit 0.

Site redeploy: `npx -y wrangler deploy --config wrangler.worker.jsonc` (the `metahackathon-vault` Worker serves `metahackathon.whativedone.xyz`; the `metavault` Pages project is a preview mirror only). Deployment and route
checks (`/`, `/docs/`, `/architecture/`, `/hackathon/` → 200) were
recorded at the time of that deploy.

## Task 11 — v0.1.0-alpha.1 local release build (2026-10-31)

Local build only: no tag, no push, no GitHub release (the tag-triggered
release workflow remains unproven until its first `v*` run).

| Item | Value |
|---|---|
| Installer | `MetaVault OSS-0.1.0-alpha.1-win-x64.exe` (NSIS, x64, unsigned) |
| Size | 121,250,505 bytes (115.6 MB) |
| SHA256 | `60cb6baf2923d9f4415f23b364e30985d1df029e7a32fdfbe0f991a753cd1e5a` |
| Built with | `cd packages/app && npm run build && npx electron-builder --win --publish never` (locked root devDependency `electron-builder@26.18.0`, Electron 45.2.1) |

Gates (in-session, 2026-10-31, historical; see the gate table for today's count): `npm run test` — **271
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

Test count today: see the gate table above (504 on Node 24, 503 on Node 22). Secrets appear in the repo only as fake canary/test strings.


## Local-hardening candidate - November 4, 2026

This is unreleased candidate evidence, not a production certification. Historical
"two-host" config tests above are not actual editor-host proof.

| Gate | Current evidence | Limit |
| --- | --- | --- |
| Uninstall warning/Cancel, fixed-profile wipe, fresh reinstall, protected shared key, encrypted install-over-install | Passed exacta06f60c, then88c91c1 on actual Windows CI; runs41711642268 and41716116132 | Synthetic disposable profile only; external/custom DBs/IDE config/exported tokens not deleted |
| Actual installed IDE host | VS Code1.144.1, exact88c91c1, official archive SHA, isolated profile/workspace, `lm.invokeTool(request_capability)` awaiting approval plus daemon `verified=true`; run41716116132 | No execution/approval/model account; other IDEs/model chat not proved |
| Unit/coverage/build |547 passed /3 skipped on exact88c91c1, Windows and Ubuntu CI41716116234 | Live model tests skipped, no paid model calls |
| Published working0.1.2 upgrade | PASS on final tested60f1db7; Windows41749962736 and41749961003: old artifact SHA, original password, exact wrapped key, alias and actual ciphertext decryption | Distinct from same-artifact reinstall; no0.1.0 compatibility claim |
| Key identity and restore | Matching DB/key restore, unrelated/mixed key rejection, unchanged bytes, rejected buffer zeroing; final555 passed /3 skipped on Windows+Ubuntu41749962842 | Windows upgrade fingerprint/lock/reunlock passed; empty DB cannot authenticate pairing |
| Main-base CodeQL | Initial PR analysis41749962861 had zero differential findings; final full-baseline analysis41755194499 passed after108 fixes; PR102/109 closed NOT merged | PR105 removed continue-on-error;108 disables diff-informed optimization; private SARIF zero findings required |

Links: https://github.com/0xm0w/metavault-oss/actions/runs/41711642268 ,
https://github.com/0xm0w/metavault-oss/actions/runs/41716116132 ,
https://github.com/0xm0w/metavault-oss/actions/runs/41716116234 .

Use actual commands from package.json: `npm test`, `npm run test:coverage`,
`npm run typecheck`, `npm run lint`, `npm run build`. Screenshot work-package
commands such as `npm test:crypto-prf` are not implemented test suites.
Passkey custody requires a packaged target-device create/get/restart/provider/
cancellation/recovery spike. Windows Hello consent is not that test. Legacy0.1.0
startup compatibility remains unverified. JS heap inspection cannot establish
that secrets never remain in runtime copies. No new public release is authorized
by these tests, and remote Connections are not implemented in this local candidate.


Final local merge: individual PR96-101 and103-106 merged after the above gates.
Main645bda60f30b7f579cb89f67255fec5e4a667621 has exactly the tested60f1db7
git tree17e7c59beeaa26dad0aebf10d83312fb3a0da077. No new release was made.
The parallel9c95018 Windows run failed cleanup of disposable VS Code's native
module after host proof;60f1db7 fixes owned-helper process cleanup with bounded
removal retries. Both exact60f1db7 Windows runs passed afterward.

Final evidence:
- https://github.com/0xm0w/metavault-oss/actions/runs/41749962736
- https://github.com/0xm0w/metavault-oss/actions/runs/41749961003
- https://github.com/0xm0w/metavault-oss/actions/runs/41749962842
- https://github.com/0xm0w/metavault-oss/actions/runs/41749962861

CodeQL initially found one incomplete-sanitization result in prompt.ts. PR106
changed untrusted angle-boundary escaping to global replacements and added
regressions. The final actual analysis reports zero findings. This is defined
query coverage, not proof of absence of all vulnerabilities. Remote work and
packaged target PRF feasibility remain separate from this local validation.


### Full-baseline correction after local merge

A zero-result PR analysis is not proof that the full baseline is clear. Postmerge
main645bda6 run41753200728 found two existing baseline findings hidden by
PR changed-lines optimization: DOM-derived favicon URL and polynomial-time
trailing-slash regex. PR108 adds strict bounded hostname validation, a linear
suffix scan, adversarial URL/100k-slash regressions and
`CODEQL_ACTION_DIFF_INFORMED_QUERIES=false` for future PR scans.

Exact93da80d full-baseline CodeQL41755194499 explicitly skipped diff-informed
analysis, completed queries and passed private SARIF with zero findings. CI
41755194437 and both Windows41755194672/41755170778 passed all prior upgrade,
verified IDE and uninstall gates. Individual107/108 merged into
main13185d625a3359fc98205d0451d7bdc0b67fab04, tree
7996d6c8f4341b933fade4f5304eb2213343051f identical to tested93da80d.
Validation-only109 closed NOT merged. No release was made.

- https://github.com/0xm0w/metavault-oss/actions/runs/41753200728 (baseline findings)
- https://github.com/0xm0w/metavault-oss/actions/runs/41755194499 (full analysis, zero findings)
- https://github.com/0xm0w/metavault-oss/actions/runs/41755194437 (CI)
- https://github.com/0xm0w/metavault-oss/actions/runs/41755194672 (Windows)
- https://github.com/0xm0w/metavault-oss/actions/runs/41755170778 (parallel Windows)

This correction supersedes any earlier implication that differential PR zero
findings established a clean full baseline. Query coverage remains bounded;
zero results are not a formal absence-of-vulnerabilities guarantee.

## Remote Connections candidate - November 4, 2026

Unreleased candidate evidence, not a production certification. Covers the
loopback-isolated gateway, mTLS 1.3 pairing/session/revocation, and remote
approval presence enforcement documented in [REMOTE.md](REMOTE.md). All
numbers below are on the exact candidate branch head recorded at merge time.

| Gate | Current evidence | Limit |
| --- | --- | --- |
| Unit/integration suite (Ubuntu) | 630 passed / 7 skipped at head 1596256 (`npm test`); tsc and eslint clean | 3 skips are pre-existing live-model tests; 4 skips are Windows-only ACL tests that run on the Windows CI leg |
| Dependency audit | `npm audit`: 0 vulnerabilities at head 1596256 | Point-in-time; advisory feed changes |
| Remote approval presence | Daemon route tests: direct `/approve` and `/approve-always` without proof rejected 403, with PIN proof executed, replay rejected, expired proof rejected, opt-out honored only while explicitly off; main-process guard fails closed on unknown/unreadable grant origin | Presence protects the remote client and app/renderer paths; NOT local-admin resistance (daemon token is full local admin by design). Windows Hello never mints proofs (caller-attested) |
| Direct mutation resistance | Token-authenticated `PATCH /settings/remote` disabling presence rejected 403 without proof and setting verified unchanged; PIN replacement without current PIN rejected; biometric route mints nothing; disabling local-auth keeps the PIN hash | First-PIN setup by a local caller is unrestricted when no PIN exists (vault already fully local-admin at that point) |
| Black-box probes | `scripts/pentest.mjs` probes 8-11 run live against an ephemeral daemon via `test/security/pentest-remote-live.test.ts`: 23 PASS / 0 FAIL / 0 SKIP - device-stamp spoofing without valid gateway MAC (plain and fully forged) 403, `/internal/*` raw-secret guard 401, pairing routes token-guarded, settings weakening 403 + unchanged | One defect found and fixed by these probes: unknown pairingId on confirm returned 500, now 409 `PairingNotConfirmable` |
| UI pixel verification | Real built renderer bundle (CSP `script-src 'self'`) driven in headless Chrome against a stubbed bridge: remote-origin approval banner, Connections tab (loopback copy, gateway bind, PIN-requirement row, SAS comparison, paired devices, revoke) | Mock-bridge pixels prove layout only. Two real defects found and fixed this way: the Connections tab was unreachable by click (dispatcher whitelist), and the PIN-requirement row never rendered (element built but not appended) |
| Pairing/e2e | Gateway suite 32 passed / 4 skipped (16 device-client tests incl. mTLS handshake, pairing code/SAS lifecycle, SAS-bound device-port cross-check, inert pairing window, revocation, in-flight revoke next-request rejection) plus daemon route tests | Loopback-only; no tailnet/LAN/public listener shipped. The 4 skips are the Windows ACL tests below |
| Windows ACL verification | Trustee SIDs are read through mscorlib APIs (`Directory.GetAccessControl` / `File.GetAccessControl` + `IdentityReference.Translate`) via Windows PowerShell - never account names, icacls text, or `/save` SDDL. SDDL aliases are machine-relative: the runner's hardened ACL `D:PAI(A;;FA;;;LA)` is owner-only with `LA` aliasing S-1-5-21-<machine>-500, so no static alias table can resolve it. `Get-Acl` is avoided because `Microsoft.PowerShell.Security` module autoload fails on hosted runners. Unresolvable trustees and PowerShell absence fail closed (credential storage refused) | Verified on a real windows-2025 runner through the exact node spawn path: focused diagnostic run 41778610721 (directory + file PASS) and the CI integration tests below |
| Windows CI leg (windows-latest) | All 4 Windows ACL integration tests pass on the real runner (CI run 41778615619): directory and credential file, positive and preexisting-`Everyone`-grant strip, effective trustee SIDs == exactly the current user's SID | The same run's only other failure was a POSIX mode-bit assertion (mode bits are no-ops on Windows; owner-only is the verified ACL), now platform-gated at head 1596256 |
| Packaged gateway smoke (installer CI) | Clean-install smoke passes on three consecutive heads (runs 41770201090, 41773296043, 41778615579): `gateway.cjs` installed; both listeners absent while remote is disabled; fail-closed unconfigured start; `PATCH /settings/remote` mints the vault CA, gateway cert and gateway token; pairing listener up on 127.0.0.1:7078; strict-mTLS device listener up on 127.0.0.1:7080; both close on shutdown | Packaged proof of the two-listener topology; pairing/session behavior is covered by the gateway e2e tests |
| Merge gates | Full-baseline CodeQL zero findings on exact head (consecutive runs incl. 41778615837 on 2e31545); ubuntu-latest + windows-latest CI legs green; installer clean-install smoke green. Final exact-head gate runs on the merge head are recorded on PR #111 checks | CodeQL zero is a static-query result; the two-listener security claims rest on the behavioral tests and probes above |

This candidate does not change the preserved limits from the local-hardening
candidate above: packaged target PRF custody unproved, legacy 0.1.0
compatibility unproved, no automatic legacy adoption or encrypted export,
other IDE/model chat/platform onboarding unproved, saved-key-only Warden
Test/Delete unchanged. No new public release is authorized by these tests.
