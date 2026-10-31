# Verification — measured gates (2026-10-31)

Every number below was produced by running the gate on the demo-class
machine (Windows, NVIDIA GeForce RTX 3070 8 GB, Node 24, Ollama with
`llama3.2:3b` Q4, 2.0 GB model download) and saving the raw output next
to this file. Re-run any gate with the commands shown.

## Gate results

| Gate | Command | Result |
|---|---|---|
| Unit + integration tests | `npm test` | **146 passed**, 0 failed |
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
Claude Code hosts configure MCP servers (`OPENVAULT_AGENT_ID` /
`OPENVAULT_IDE` per host), connected to one daemon. Both listed aliases
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

`OpenVault-0.1.0-win-x64.exe` (NSIS, 115.6 MB) builds cleanly and is
unsigned (no certificate in this environment). The macOS DMG config is
declared but building it requires a Mac; it is the one remaining
packaging item, along with code signing.

## Demo video

`demo-walkthrough.mp4` (21 s) is assembled from the live screenshots
above. It is a walkthrough, not a screen recording of a live session;
record the full 3-minute script (README) on demo day as the fallback.

## Codebase

43 TypeScript files, 6,649 lines (packages + root canary test), 146
tests. Secrets appear in the repo only as fake canary/test strings.
