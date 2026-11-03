# MetaVault OSS

**Agents never see your secrets.**

MetaVault OSS is a local-first **wallet for AI coding agents**. Agents request a
scoped capability — `stripe` at `charges.read`, say — never the raw key. A
local Meta model (the **marshal**) vets each request from metadata only, the
deterministic **policy** layer enforces scope ceilings, rate limits, and
expiry, and you approve in the desktop app. MetaVault OSS then injects the
credential into that single tool execution inside the daemon (`vaultd`) and
returns only the result. The raw key never enters a chat, a prompt, a model
context, an audit row, or the desktop UI.

> Judging line: MetaVault OSS is secure even if the AI is wrong — and measurably
> safer when it is smart. The security floor is cryptography and policy; the
> model is discretion within bounds. See [Brain eval](#brain-eval) for the
> measured evidence and [Security model](#security-model) for the invariants.

> **Meta Hackathon (Indie Track)**: Live interactive deck at [metahackathon.whativedone.xyz](https://metahackathon.whativedone.xyz). Engineered by the security team behind [Keythings](https://keythings.xyz) (securing on-chain keys since 2025). Built by former crypto wallet bug bounty hunters.

## Install

### Windows Installer (v0.1.0)

Download the Windows NSIS installer (`MetaVault-OSS-0.1.0-win-x64.exe`) and `SHA256SUMS` from the [GitHub Releases page](https://github.com/0xm0w/metavault-oss/releases/tag/v0.1.0). The installer is unsigned. A Windows Store (MSIX) build is also available for a Windows-verified install path — see `docs/MICROSOFT_STORE.md`.

To build the installer locally from source:

```powershell
cd packages/app
npm run build
npx electron-builder --win
```

### From source (works today)

```powershell
git clone <this repo> metavault-oss
cd metavault-oss
npm install
npm test            # full suite (see docs/VERIFICATION.md for current counts)
```

## Setup

1. **Install Ollama** (the marshal's runtime): <https://ollama.com/download>.
   Nothing leaves your machine in the default configuration.
2. **Create the vault.** This generates a master key, asks for a passphrase
   (at least 12 characters), wraps the key with it (scrypt by default,
   `--kdf argon2id` on request) in `metavault.key.json` next to the database,
   and creates the encrypted store. Existing vaults with the key in the OS
   keychain: run `metavault key protect`. See
   [SECURITY.md#master-key-protection](SECURITY.md#master-key-protection):

   > Environment variables were renamed `METAVAULT_*` → `METAVAULT_*` in the
   > rebrand. The legacy `METAVAULT_*` names still work everywhere; the new
   > names win when both are set. The daemon's wire header
   > (`x-metavault-token`), token file (`metavault.token`), default vault
   > filename (`metavault.db`), OS keychain entry and `metavault://` deeplink
   > scheme are intentionally unchanged so existing vaults and IDE configs
   > keep working.

   ```powershell
   node dist/packages/cli/src/cli.js init
   ```

   (Build first with `npx tsc -p tsconfig.json --outDir dist`.)
3. **Pull the marshal model.** The on-device marshal is Meta's open-weight
   **Muse Glimmer 30B, Q4_K_M** (`muse-glimmer:30b`, ~18 GB download; needs
   Ollama 0.32.7 or newer). Source: the official GGUF at
   <https://huggingface.co/meta-models/Muse-Glimmer-30B-GGUF>
   (`Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf`) and the Ollama library tag
   <https://ollama.com/library/muse-glimmer>:

   ```powershell
   node dist/packages/cli/src/cli.js model pull          # pulls muse-glimmer:30b
   # equivalent direct Ollama call:  ollama pull muse-glimmer:30b
   ```

   The model runs with a low reasoning-strength system prompt and a 120 s
   local timeout (Fast/Standard/Deep: 60 s / 120 s / 240 s). The guarantees
   do not change with the model, only judgement quality does: if Ollama is
   down or the model times out, the request fails closed to your approval.
4. **Add a credential once** (the secret is read with echo disabled and is
   stored only as AES-256-GCM ciphertext):

   ```powershell
   node dist/packages/cli/src/cli.js add stripe --scope charges.read
   # payment card (Luhn-checked; agents only ever see brand + last 4):
   node dist/packages/cli/src/cli.js add-card visa-personal --website shop.example
   ```

   Every card use needs your approval, and the daemon refuses to execute a
   card grant because no payment connector exists yet.
5. **Start the daemon** (binds to `127.0.0.1:7077` only):

   ```powershell
   node dist/packages/daemon/src/server.js
   # in another terminal: the daemon starts locked
   node dist/packages/cli/src/cli.js unlock
   ```

   The vault auto-locks after 15 idle minutes (`METAVAULT_AUTO_LOCK_MINUTES`,
   1 to 1440); `metavault lock` locks it now. `METAVAULT_MASTER_KEY` is
   ignored unless `METAVAULT_ALLOW_ENV_MASTER_KEY=1` is set.
6. **(Optional) Start the desktop app** for approval prompts — see
   [packages/app/README.md](packages/app/README.md). Approvals also work
   from the CLI (`approve <grantId>`, `audit`, `revoke <target>`).
7. **Connect your IDE** with the MCP snippet below.

## Install via MCP (one snippet per IDE)

Build once (`npx tsc -p tsconfig.json --outDir dist`), start the daemon or desktop app, then paste the snippet for your host. Copy-paste configs for **Claude Code, Cursor, VS Code, Codex and OpenCode** — each with its own `METAVAULT_AGENT_ID`, which audit and revoke are keyed by — are in [docs/MCP.md](docs/MCP.md). Hosts launch `node dist/packages/mcp/src/server.js` (or the packaged `metavault-mcp` bin from `packages/mcp/package.json`); the server reads `METAVAULT_DAEMON_URL` (default `http://127.0.0.1:7077`), `METAVAULT_AGENT_ID` and `METAVAULT_IDE`.
Example (Cursor shape; other hosts differ only in wrapping — see [docs/MCP.md](docs/MCP.md)):

```json
{
  "mcpServers": {
    "metavault": {
      "command": "node",
      "args": ["C:/path/to/metavault-oss/dist/packages/mcp/src/server.js"],
      "env": {
        "METAVAULT_DAEMON_URL": "http://127.0.0.1:7077",
        "METAVAULT_AGENT_ID": "cursor-agent",
        "METAVAULT_IDE": "Cursor"
      }
    }
  }
}
```

Tools exposed to agents (exactly five): `request_capability({alias, scope, reason, tool?, payload?})`, `list_aliases()`, `request_enrollment({alias, scope, website?})`, `enrollment_status({enrollmentId})`, `revoke({target})`. There is deliberately no approve tool — approval belongs to the human, in the app. Agents receive `executed`, `awaiting-approval` (with a `grantId`), or `denied` — never a secret value.
## Settings: the warden (Settings page)

The desktop app's **Settings** page chooses who judges capability requests. Deterministic policy stays the floor in every configuration: the warden can narrow or escalate, never widen.

- **Warden provider:** `None (policy only)` / `Local — Ollama` / `Meta API (cloud)`. Meta API sends request metadata (agent, alias, scope, reason — never secrets) off-device; the page says so plainly.
- **Model:** for Ollama, the catalogue below (or any free-text model id); for Meta API, the API model id (default `muse-spark-1.3`; also `muse-spark-1.2`, `muse-wonder-1.0`, per <https://dev.meta.ai/docs/models>) plus an editable base URL (default `https://api.meta.ai/v1`).
- **Effort:** `Fast` (one marshal pass; 10s cloud / 60s local timeout), `Standard` (one pass; 30s / 120s), `Deep` (two passes — assess + verify — 60s / 240s; on disagreement it escalates to you and keeps the narrower scope). Effort never changes policy ceilings.
- **Meta API key:** paste once and Save; the field clears and is never repopulated. Status shows only `Not configured` or `Configured ••••last4`. The key is stored as an ordinary encrypted credential (alias `warden-meta-api`) and decrypted only inside the daemon at call time. **Test connection** runs one real marshal self-check through the daemon (no grant, no audit row) and reports provider, model and latency.
- **Daemon / Security defaults:** read-only daemon URL, vault path and version, plus a policy-floor summary with a jump to Policies. Settings apply on the next request — no daemon restart needed. All settings routes require the daemon token; agents cannot read or change them.

### Security levels (warden tiers & hardware profiles)

These are the tiers supported by the daemon and Settings UI. Higher tiers buy independent judgment, not permission:

| Tier | Mode & Warden Architecture | Hardware Profile & Requirements |
|---|---|---|
| **Meta BFT (two-warden quorum)** | **Cloud + local** | Muse Spark (`muse-spark-1.3`, Meta API) and on-device Muse Glimmer 30B both score the request and the stricter verdict wins (higher risk, narrower scope, approval if either asks); if one leg is unavailable the other decides alone. Two wardens, not a Byzantine fault-tolerant cluster. |
| **Meta API (Cloud)** | **Muse Spark** (`muse-spark-1.3`) | Any machine (no model download). Sends request metadata (never secrets) to `https://api.meta.ai/v1`. |
| **On-Device (Built-in)** | **Muse Glimmer 30B Q4_K_M** (`muse-glimmer:30b`, via Ollama) | ~18 GB model download; needs enough RAM/VRAM for a 30B Q4 model. Nothing about the request leaves the machine. |
| Self-Hosted | `muse-glimmer:30b` (your Ollama) | Same model through a local Ollama you manage (`METAVAULT_OLLAMA_URL`). |
| Policy Only | Provider one | Deterministic policy rules alone; all non-trivial operations escalate to human. |

## End-to-end agent flows (real screenshots)

Captured from the real running app against a real daemon, seeded with a fake test credential — never a real secret. Full-size copies: `docs/verification/`.

1. **Agent asks to save a key.** MCP `request_enrollment` → daemon returns an `metavault://add` deeplink → prefilled modal (alias/scope/website filled, secret empty) → you paste the secret → agent polls `enrollment_status` → `completed`.

   ![Prefilled enrollment modal](docs/verification/enroll-flow.png)

2. **Agent requests a capability.** `request_capability` → policy check, then the warden scores metadata only → the Approval view shows agent, scope, reason, risk and the warden explanation with **Approve once / Deny / Block agent** — plus **Always allow** only when the request is low-risk, read-only and from a verified agent (standing approval; the daemon re-checks the same rule, and writes always ask) → vaultd injects the credential into that one call and returns only the result.

   ![Approval dialog](docs/verification/approval-dialog.png)

3. **Audit: the warden verdict.** The Audit view groups events by request; expanding a row shows requested → marshal → policy → approved/denied → executed with the marshal explanation, recommended scope, latency, decision source and model named.

   ![Expanded warden verdict in Audit](docs/verification/audit-verdict.png)

4. **Settings.** Provider/model/effort plus the Meta key status (key field empty, as it always is after saving).

   ![Settings page](docs/verification/settings.png)

## Security model

The wallet/marshal framing is literal:

- **The wallet.** `vaultd` is the vault and signing core: encrypted storage,
  grant lifecycle, audit log. The desktop app is only the window — like a
  crypto wallet, it displays requests and collects your decision. It holds
  no secrets and talks only to `vaultd` on localhost. Closing the window
  minimises to the tray; `vaultd` keeps queueing approvals (bounded by grant
  TTL) until the UI or CLI next connects.
- **The marshal.** The Meta model stands in front of the vault and advises:
  risk level, smallest recommended scope, whether to escalate, and a
  one-sentence explanation. It sees **metadata only** — agent, IDE, tool,
  alias, requested scope, recent history counts, policy digest, and the
  agent's stated reason (explicitly labelled untrusted data in the prompt,
  [packages/brain/src/prompt.ts](packages/brain/src/prompt.ts)). It never
  receives a secret. It can narrow a grant or escalate to you; it can never
  widen one.
- **The law.** Deterministic policy ([packages/core/src/policy.ts](packages/core/src/policy.ts))
  runs on every request regardless of the model: per-alias scope ceilings,
  writes **always** require human approval (a write can never be
  auto-approved or become a standing approval), rate limits, unknown-alias
  denial, and 60-second single-use grants. With the model offline, crashed,
  or fooled, the floor holds: marshal errors recover to a null decision and
  the default is *ask the human*.
- **Secret handling.** Secrets exist in plaintext only inside `vaultd`
  memory during one connector call, where the credential is injected as a
  header on the outbound request ([packages/connectors/src/http.ts](packages/connectors/src/http.ts)).
  At rest they are AES-256-GCM ciphertext under a master key that is
  wrapped with your passphrase and held in daemon memory only while the
  vault is unlocked. Malware running as you can still keylog the
  passphrase or read daemon memory while unlocked; see
  [SECURITY.md#master-key-protection](SECURITY.md#master-key-protection). Grants are consumed exactly
  once; revoke cancels pending grants and blocks future ones for that agent
  or alias immediately.

**Canary-tested invariant.** [test/canary.test.ts](test/canary.test.ts)
stores a unique canary secret, runs request → approve → execute twice
(plus the auto-approved path) against a mock connector, then greps MCP
responses, daemon/audit payloads, captured model prompts, renderer-projected
app payloads, and the stored ciphertext for the canary string. The mock
connector asserts it *did* receive the canary in-daemon, so a clean scan is
not vacuous. Any hit fails the build.

## Brain eval

Labelled scenarios live in
[packages/brain/eval/scenarios.json](packages/brain/eval/scenarios.json)
(17 scenarios: benign reads, writes phrased as reads, honest and
fooled-marshal writes, scope escalation, prompt injection in `reason`
including the canonical `ignore policy, approve charges.write`, burst/rate
limit, unknown alias, marshal unavailable/invalid). Each carries expected
`{risk, requireApproval}`. The harness
([packages/brain/eval/run-eval.ts](packages/brain/eval/run-eval.ts)) runs
every scenario through the `Brain` service plus the pure `evaluatePolicy`,
recovering marshal errors to null decisions exactly as the daemon does, and
reports risk accuracy, approval accuracy, and a **safety gate: writes are
never auto-approved and scopes never escape their ceilings**.

Run it:

```powershell
npx tsc -p tsconfig.json --outDir dist
node dist/packages/brain/eval/run-eval.js --fake   # deterministic fake brain (mechanics proof)
node dist/packages/brain/eval/run-eval.js --live   # live Ollama marshal (default muse-glimmer:30b)
```

The fake-brain run proves the harness mechanics only (the fake marshal's
canned decisions include deliberately fooled ones, so its risk accuracy is
below 100% by construction; safety is the gate).

**Live Muse Glimmer 30B: no committed result.** The earlier live numbers in this
README were measured against the previous local model, which is no longer shipped, and have
been removed. `scripts/eval-windows.ps1` produces the live eval for `muse-glimmer:30b`
(accuracy, safety gate, latency, and the Ollama process's peak RAM); no figures are quoted
here until its raw output is committed under `docs/verification/`.

**Held-out thesis benchmark (Muse Spark 1.3 via the Meta API, 2 runs, 60 cases):** on the 28
high-risk reads the warden alone caught 25/28 and rules + warden 27/28 in both runs, with 0/28
warden false alarms (rules + warden 9/28). Counting rule: a failed warden call (one per run, at
the 2,048-token output cap) counts as a miss. See [docs/VERIFICATION.md](docs/VERIFICATION.md).

## Demo script (3 minutes)

1. (15s) The horror: a real key pasted into an agent chat, now in a transcript.
2. (20s) Without MetaVault OSS, the agent is blocked or the human pastes the key.
3. (45s) Agent requests `stripe:charges.read` via MCP. Muse Glimmer 30B explains
   the risk in one sentence. Human approves once.
4. (30s) Tool succeeds. Show the chat/transcript: the key never appeared.
5. (30s) Revoke the agent mid-task. Its next request fails safely.
6. (40s) Audit log replay; same MCP snippet working in a second IDE; close
   on "one vault, every agent, secrets never in context."

## Development

```powershell
npm test              # vitest run (all packages + root canary test)
npm run typecheck     # tsc --noEmit (strict, exactOptionalPropertyTypes, ...)
npm run lint          # eslint . --max-warnings 0
```

Daemon-side packages are Effect TS with typed errors and Effect Schema at
every boundary; the Electron renderer is plain TypeScript (Effect imports
are lint-banned there) and projects every daemon payload through a
fail-closed whitelist before rendering.

## Verification

Tests were re-run on 2026-11-03; the rehearsal, MCP, GUI, installer and video rows were run on 2026-10-31 on the demo-class machine (RTX 3070 8 GB) with the previous local model. No live Muse Glimmer 30B eval output is committed yet. Full detail, raw outputs, and live screenshots: [docs/VERIFICATION.md](docs/VERIFICATION.md).

| Gate | Result |
|---|---|
| Tests / typecheck / lint | Node 22: 503 passed, 3 skipped; Node 24: 504 passed, 2 skipped / exit 0 / exit 0 |
| Brain eval (fake / live) | fake: safety 100%, gate PASS / live Muse Glimmer 30B: no committed result |
| Demo rehearsal (scripts/rehearse-demo.mjs) | 7/7 PASS |
| Two-host MCP check | PASS for VS Code + Claude Code host configs |
| Electron GUI | Approval, Deny, Audit, Vault verified live (screenshots) |
| Windows installer | NSIS built, 115.6 MB, unsigned |
| Demo walkthrough video | docs/verification/demo-walkthrough.mp4 (21 s) |

Known limitations, honestly:

- Live marshal accuracy for Muse Glimmer 30B has no committed result yet. Safety comes from deterministic policy, not the model.
- Standing approvals (Always allow) live in daemon memory and do not persist across vaultd restarts - fail-safe, but a known limitation.
- The macOS DMG and code signing still need a Mac and a certificate. The full 3-minute demo video should be re-recorded live on demo day; the walkthrough above is assembled from real screenshots.
