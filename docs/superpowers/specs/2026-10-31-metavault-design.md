# MetaVault OSS — Design Spec

- Date: 2026-10-31
- Track: Indie Developer
- Challenge: Push the Frontier (primary) + Build for Your World (secondary)
- Status: Draft for user review. No implementation until this spec is approved.
- Target bonuses: Best Agentic Use-Case, Best Build on Meta Open Weight Models, Most Viral Project, Community Vote

## 1. One-line pitch

MetaVault OSS is an open-source, local-first vault where AI coding agents request
scoped capabilities — never raw secrets. A local Meta model vets each request,
the human approves, MetaVault OSS injects the credential into that single tool
execution, and the grant expires. The raw key never enters chat, prompt, or
model context.

Tagline: **Agents never see your secrets.**

Official framing (use this language in the README, demo, and submission):

- MetaVault OSS is a **wallet for agents**. Like a crypto wallet, the desktop app
  is the window, not the vault. The local daemon (`vaultd`) holds the keys,
  the app shows requests, and the human approves. Secrets are used inside
  the daemon the way a wallet uses a seed phrase to sign: the credential
  authorises one action and is never displayed, copied, or handed over.
- Meta models are the **security marshals**. They stand in front of the
  vault, check who is asking and why, recommend the smallest safe scope,
  and explain the decision to the human. They guide access; they do not
  grant it on their own.
- The law the marshals enforce is deterministic policy. Policy sets scope
  ceilings, expiry, and rate limits. A marshal can narrow a grant or
  escalate it to the human. A marshal can never widen a grant beyond
  policy, and never sees a secret value.
- The vault is secure with no marshal on duty. With the model offline,
  crashed, or fooled, encrypted storage, policy ceilings, human approval,
  and expiring grants still hold. A better model improves judgement; it
  does not raise or lower the security floor. The floor is cryptography
  and policy. The model is discretion within bounds.

Judging line: **MetaVault OSS is secure even if the AI is wrong — and
measurably safer when it is smart.**

## 2. Problem

Developers using Cursor, Claude Code, Codex, Copilot, and similar agents
routinely paste API keys into chats, `.env` files, and prompts. Those secrets
then live in transcripts, context windows, logs, and third-party servers.
Existing vaults (HashiCorp Vault, 1Password, Infisical, Doppler) were built
for humans and servers, not for autonomous agents that ask for access in
natural language, mid-task, many times a day.

## 3. Why this can win

- Generic vaults already exist. MetaVault OSS is not "another vault." The novel
  claim is capability-based access for agents: request a scope, not a secret.
- The demo moment is filmable in 10 seconds and solves a pain every AI-coding
  developer recognises. That supports viral and community-vote potential.
- Meta-model use is load-bearing, not decorative. The Meta model is the
  policy brain that risk-scores, scopes, and explains access decisions.
- Local-first execution is the privacy story: secrets and, by default, even
  request metadata never leave the user's machine.

## 4. Eligibility strategy (Meta models)

Meta's model landscape changed in 2026: the hosted Llama API was wound down,
the flagship moved to closed Muse Spark via the Meta Model API, Muse Spark
Open shipped as a very large open-weight model, and Muse Glimmer shipped as
a 30B Apache-2.0 open-weight model for local agents. Exact hackathon rule
wording must be re-checked against the official rules before submission.

MetaVault OSS therefore treats the Meta model as pluggable, Meta-first:

| Tier | Model | When used |
|---|---|---|
| Default (this project) | Llama 3.2 3B Q4 via Ollama / llama.cpp | Developer machine has an 8 GB GPU. Default for the hackathon build and demo. |
| Baseline fallback | Llama 3.2 3B Q4 on CPU / unified memory | No discrete GPU. Slower, still usable for approval decisions. |
| Recommended upgrade | Muse Glimmer 30B Q4 | 24 GB-class GPU. Same policy interface, stronger reasoning. |
| Large open-weight option | Muse Spark Open (hosted) | No suitable local GPU; served via a hosted provider. Metadata only. |
| Hosted fallback | Muse Spark via Meta Model API | Demo-day backup and zero-GPU users. Metadata only, off by default. |

Rules that hold for every tier:

1. No secret value is ever sent to any model, local or hosted.
2. The model sees metadata only: agent identity, IDE, tool, requested scope,
   credential alias (never value), recent request history, and policy text.
3. The model advises; deterministic policy also gates. If the model is
   unavailable, unreachable, or returns malformed output, hard rules decide
   and the default is deny for sensitive scopes.
4. Model ID, provider, prompt template version, and decision are recorded
   in the audit log for every request, so Meta-model use is provable to judges.

### 4.1 Why Llama 3.2 3B Q4 is the default

- The developer's machine has an 8 GB GPU. The default must run well there,
  not merely fit.
- Llama 3.2 3B Q4 is roughly a 2 GB download and leaves most of the 8 GB
  card free for the IDE, the agent, and context. Llama 3.1 8B Q4 (~4.9 GB
  file, ~7 GB VRAM at 8K context) fits an 8 GB card only tightly.
- Policy-brain work is small and structured: classify intent, score risk,
  recommend a scope, write a short explanation. It does not need a large
  model's context window or long-form generation.
- Trade-off accepted: 3B reasoning is weaker than 8B/Glimmer. Mitigations
  are structured JSON output, a small fixed label set, deterministic rules
  underneath, and human approval on anything sensitive. See Section 9.

### 4.2 Marshal seniority (what a bigger model actually buys)

Models are marshals of different seniority enforcing the same law. A more
capable model improves judgement quality — risk accuracy, resistance to a
request phrased to sound safer than it is, pattern-spotting across request
history, fewer false interruptions, better explanations. It does not
change the guarantees: policy ceilings, human approval, expiry, and
secret-injection inside `vaultd` hold identically on every tier.

| Tier | Marshal equivalent | Practical difference |
|---|---|---|
| No model (rules only) | Locked door + checklist | Safe, but blunt: sensitive requests always interrupt the human. |
| Llama 3.2 3B Q4 (default, 8 GB GPU) | Junior marshal | Spots obvious risk, follows the checklist, escalates when unsure. |
| Llama 3.1 8B | Experienced marshal | Better grey-area judgement, fewer false alarms. |
| Muse Glimmer 30B | Senior investigator | Reads history for slow scope-creep; strongest local explanations. |
| Muse Spark (hosted, opt-in) | Chief of security | Strongest reasoning; can audit lower-tier decisions. |

Even a fully compromised or prompt-injected marshal cannot exfiltrate a
secret it never receives. Its worst failures are a bad recommendation
(still bounded by policy and the human's click) or needless denials.
Seniority is measured, not asserted: the brain eval in Section 11 runs
the same labelled scenarios per tier and publishes the scores.

## 5. How users run it

MetaVault OSS runs locally. There is no MetaVault OSS cloud account in v1.

1. Install: the Electron app installer for Windows or macOS (the daemon
   is bundled and started by the app), or `docker compose up` from the repo.
2. `metavault init` creates the encrypted vault and unlocks it with the OS
   keychain (Windows Credential Manager / macOS Keychain / Linux secret
   service) holding the master key.
3. `metavault model pull` auto-detects VRAM/RAM and pulls the right model
   via Ollama. On an 8 GB GPU this is Llama 3.2 3B Q4. First run prints the
   detected tier so there are no surprises.
4. The user adds credentials once in the desktop app or CLI:
   `metavault add stripe --scope charges:read`.
5. The user pastes one MCP config snippet into their IDE/agent
   (Cursor, Claude Code, Codex, VS Code). That is the only per-IDE step.
6. From then on, agents talk to the local MetaVault OSS daemon over MCP on
   localhost. Approvals appear in the desktop app, which talks only to
   `vaultd` on localhost. A localhost web UI remains as a dev/fallback
   surface over the same daemon API.

Packaging: the desktop app is an Electron shell over `vaultd`, like a
crypto-wallet app over its signing core. Electron is the first build
because one TypeScript codebase ships on Windows, macOS, and Linux with
no per-platform UI development: Chromium renders the same UI everywhere
and Node talks to the local daemon. Platform differences are confined to
packaging (installer, code signing, tray/menu conventions) and to
`vaultd`'s OS-keychain backend, not to the app itself. A Tauri port is a
post-hackathon option for a smaller binary; it would reuse the same UI
and daemon API. Docker (`docker compose up`) is an alternative
distribution for Linux/dev users, not the default on Windows/macOS,
because it makes OS-keychain access and desktop approval prompts awkward.
The daemon is identical in every distribution; only packaging changes.

Nothing leaves the machine in the default configuration. Hosted model
fallback is opt-in, clearly labelled, and still receives metadata only.

### 5.1 Hardware tiers (honest promises)

| Hardware | Default model | Experience |
|---|---|---|
| 8 GB GPU, 16 GB RAM (demo machine) | Llama 3.2 3B Q4 | Fast approvals. Target demo config. |
| 16 GB GPU | Llama 3.1 8B Q4 or 3.2 3B Q4 | More headroom, longer history context. |
| 24 GB+ GPU | Muse Glimmer 30B Q4 | Recommended upgrade path. |
| No GPU, 16 GB RAM | Llama 3.2 3B Q4 on CPU | Usable. Approvals take seconds, not milliseconds. |
| Apple Silicon 16 GB unified | Llama 3.2 3B Q4 via Ollama/MLX | Usable local path. |

We do not promise Muse Spark Open locally (816B) or Llama 4 Scout locally
(~67 GB at Q4). Both are hosted-only in MetaVault OSS's tiers.

## 6. Core loop

1. Agent needs a credential-backed action. It calls the MetaVault OSS MCP tool
   with a capability request, e.g. `stripe:charges.read` plus a reason.
2. MetaVault OSS resolves the credential alias. The agent never learns the value.
3. The policy brain (default Llama 3.2 3B Q4) scores the request from
   metadata only and returns strict JSON: risk level, recommended scope,
   whether human approval is required, and a one-sentence explanation.
4. Deterministic policy checks run regardless: allow/deny lists, scope
   ceilings per agent, rate limits, expiry defaults.
5. If approval is required, the human approves or denies locally. The
   human may also choose "Always allow" to remember a standing policy —
   but only for read-only scopes the marshal rated low-risk and that sit
   inside the policy ceiling. Writes and high-risk scopes can never
   become standing approvals; they ask every time.
6. MetaVault OSS injects the credential into that single tool execution
   server-side (inside the daemon) and returns only the tool result to the
   agent.
7. The grant expires immediately after the call or after a short TTL.
8. Every step is appended to the audit log. One-click revoke kills pending
   and live grants for an agent or credential.

Demo climax: revoke an agent mid-task and watch it fail safely.

## 7. Architecture

Official shape: **a wallet, its marshals, and the law.** The desktop app is
a shell over a local daemon, in the crypto-wallet pattern. The app is the
window; `vaultd` is the vault. Each unit below has one purpose and a
testable interface.

- `vaultd` — the vault daemon and signing core. Owns encrypted storage,
  grant lifecycle, audit log, and the MCP server. This is the only
  component that ever holds a secret, and only in memory during a single
  tool execution — the equivalent of a wallet using a seed phrase to sign
  one transaction without ever displaying it.
- Desktop app (Electron; Tauri port post-hackathon) — the wallet window. Approvals,
  policies, audit log, credential management. It talks only to `vaultd`
  over localhost and holds no secrets itself. Closing the window
  minimises the app to the system tray (the wallet pattern) so approval
  prompts can still surface; quitting from the tray stops the UI, and
  `vaultd` then queues approval requests until the UI or CLI next
  connects — agents receive a clear "awaiting approval" response, never
  a silent grant. A localhost web UI over the same daemon API is kept
  as a dev/fallback surface.
- `policy` — the law. Deterministic rules engine: allow/deny, per-agent
  scope ceilings, rate limits, TTLs. Always runs; no model output can
  override it. Secure by default with no model present.
- `brain` (the marshals) — Meta-model adapter. One interface, pluggable
  providers. v1 ships the Ollama provider only (default Llama 3.2 3B Q4;
  Muse Glimmer via Ollama is a config change on the same provider). The
  Meta Model API and hosted Muse Spark Open providers are interface-
  compatible follow-ups, built only if official rules require them or
  time remains after the core loop. Sees metadata only, emits strict
  JSON only, can narrow or escalate, never widen.
- `connectors` — credential-backed tool executors. v1: a generic
  HTTP-with-injected-header executor, plus Stripe and GitHub examples.
  Connectors receive the secret from `vaultd` at call time and return only
  results.
- `mcp` — MCP server surface: `request_capability`, `list_aliases`
  (aliases and scopes only, never values), `revoke`. This is how every IDE
  integrates with one snippet.
- `cli` — `metavault` CLI for init/add/approve/audit/revoke, exposing the
  same daemon API as the desktop app and MCP.
- Storage: SQLite under the user's data dir for aliases, policies, grants,
  and audit events. Secret values themselves are stored only as ciphertext,
  each encrypted with AES-256-GCM under a master key held in the OS keychain.
  The database never contains a plaintext secret.
- Stack: TypeScript in one repo, split by discipline. The daemon-side
  packages (`core`, `brain`, `connectors`, `daemon`, `mcp`, `cli`) are
  idiomatic Effect TS: services as `Context.Tag` + `Layer`, all failures
  as typed errors in the Effect channel (no thrown exceptions across
  module boundaries), Effect Schema validation at every boundary
  (marshal JSON, MCP inputs, daemon API payloads), and Effect timeout /
  interruption for marshal calls, grant TTLs, and revoke cancellation.
  The Electron renderer is plain TypeScript with no Effect — it only
  renders daemon responses over HTTP. Ollama is reached over its local
  HTTP API, wrapped as an Effect service.
- Linting is super-strict, as a security control: `strict`,
  `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`,
  `noImplicitReturns`, `noFallthroughCasesInSwitch`; ESLint
  typescript-eslint strict-type-checked with `no-floating-promises` and
  `no-explicit-any` outside test fakes; and a hard ban on `console.log`
  in daemon-side packages so secrets cannot reach logs by accident.

Distribution: the Electron-app-over-daemon install is the default on
Windows and macOS (one codebase, per-OS installers). Docker (`docker compose` running `vaultd` plus the web UI)
is an alternative distribution for Linux/dev users. Same daemon, same
security model; only packaging differs.

Data flow per request: agent -> MCP -> policy (pre-check) -> brain
(metadata-only JSON decision) -> human approval in the desktop app if
required -> connector executes with injected secret inside `vaultd` ->
result only -> agent. Audit events are written at each transition.

### 7.1 UI/UX direction

Chosen direction: **Direction B — Marshal Light** (selected by the user
from mockups in `metavault-oss/mockups/directions.html`, Directions A–C).

- Default Electron theme is Direction B: clean light surfaces
  (`#FFFFFF` / `#F8FAFC`), navy `#1E3A5F` as the trust colour, green
  `#16A34A` for approve, amber `#D97706` for warnings, red `#DC2626` for deny.
  System UI font (Segoe UI on Windows, San Francisco on macOS) with
  JetBrains Mono reserved for scopes, aliases, and audit rows.
- Rationale: MetaVault OSS asks users to trust it with every credential they
  own. Bank-app clarity beats crypto-wallet drama for that job, and a
  light UI reads as an OS-native utility on both Windows and macOS.
- Direction A (Vault Noir, dark) is kept as a documented dark-mode
  alternate using the same components and layout. Direction C (Terminal)
  is deferred as an optional post-hackathon developer theme. Neither is
  in v1 scope beyond the theme tokens Direction B already defines.
- Hero surface is the approval prompt: requesting agent and IDE, the
  requested scope in mono, the agent's stated reason, the marshal's
  one-paragraph assessment with risk level, expiry terms, and
  Approve once / Deny / Always allow (scoped) actions.
- The marshal status line ("Marshal · Llama 3.2 3B · On-device") is
  always visible in the app header. It is both a trust signal for users
  and visible evidence of Meta-model use for judges.
- Supporting surfaces: Vault home (credential cards showing alias, scope
  chips, last used — never values), Audit log (timeline of agent, scope,
  marshal decision, human decision, expiry), and Policies (per-agent
  ceilings and standing approvals). All UI talks only to `vaultd` on
  localhost; the UI never handles secret values.

## 8. Scope

### In scope for the hackathon build

- Local daemon, encrypted vault, OS-keychain master key.
- MCP server + CLI + desktop app (Electron shell over `vaultd`) for
  approvals, policies, and the audit log. Localhost web UI as fallback.
- Policy brain on Llama 3.2 3B Q4 via Ollama, with the model-pluggable
  interface and rule-based fallback.
- Generic HTTP connector + Stripe and GitHub demo connectors.
- Scoped, expiring grants; one-click revoke; full audit log.
- One MCP snippet proven in at least two IDEs/agents on the demo machine.
- Public open-source repo (Apache-2.0), README with an installer-first
  setup (install the app, first run pulls the model), demo video script,
  and a recorded fallback demo.

### Out of scope (explicit cuts)

- Cloud-hosted vault, accounts, sync, billing, SSO, team roles.
- Five bespoke IDE plugins. MCP + CLI is the universal surface.
- 50 connector integrations. Depth on 2–3, not breadth.
- Sending any secret, fragment, or hash of a secret to a model.
- Local hosting of Muse Spark Open or Llama 4 Scout.
- Mobile approval app. The Electron desktop app (tray-resident) plus the
  CLI approval path is enough for v1.

## 9. Marshal contract (brain)

The marshal's interface. `brain` is the module name; "marshal" is the
product language for the same component.

Input (metadata only, enforced by construction — the brain module never
receives vault handles or secret values):

```json
{
  "agent_id": "cursor",
  "ide": "Cursor",
  "tool": "http",
  "alias": "stripe",
  "requested_scope": "charges.read",
  "reason": "List last 5 failed charges",
  "history_summary": {"requests_24h": 3, "denials_24h": 0},
  "policy_digest": "stripe ceiling=charges.read; writes require approval"
}
```

Output (strict JSON, schema-validated; anything else is treated as
"escalate to human"):

```json
{
  "risk": "low | medium | high",
  "recommended_scope": "charges.read",
  "require_approval": true,
  "explanation": "Read-only Stripe scope from a known agent with clean history."
}
```

Failure behaviour:

- Model timeout, connection failure, or invalid JSON -> deterministic
  policy decides alone; sensitive scopes default to human approval or deny.
- Model recommends a scope wider than the policy ceiling -> clamped to the
  ceiling and flagged in the audit log. The model can narrow, never widen.
- Prompt-injection via the agent's `reason` field: the reason is data, not
  instructions. The brain prompt is a fixed template; output is schema-
  checked; the deterministic layer and human approval bound the blast radius.

Because a 3B model is the default, the task is deliberately small: fixed
labels, short history summaries, no free-form tool plans. Accuracy is
measured on a labelled test set of request scenarios (see Section 11), not
assumed.

## 10. Error handling and security invariants

Invariants (tested, not just documented):

1. No MCP response, log line, audit entry, UI payload, or model prompt ever
   contains a secret value. A canary-secret test scans all of them.
2. Secrets are plaintext only inside `vaultd` during one connector call.
3. The brain can narrow scope, never widen it beyond policy ceilings.
4. Grants are single-purpose and expiring. Revoke cancels pending
   approvals and blocks all new grants for that agent or credential
   immediately; a tool call already executing is aborted where the
   connector supports cancellation, otherwise it completes and is
   flagged in the audit log as revoked mid-flight.
5. The daemon binds to localhost only in v1.

Error behaviour: unknown alias -> structured denial the agent can act on;
denied scope -> agent receives the denial reason and the allowed ceiling,
so it can re-ask correctly; connector failure -> error result without the
credential or request headers that carried it.

## 11. Testing

- Unit: policy rules, scope clamping, grant expiry, brain JSON parsing and
  fallback paths (model down, model malformed, model over-recommending).
- Canary security test: store a unique fake secret, run the full loop, then
  grep MCP transcripts, logs, audit entries, and captured model prompts for
  the canary. Any hit fails the build.
- Brain evaluation: a fixed set of labelled request scenarios (benign read,
  sneaky write, scope escalation, injection in the reason field, burst
  requests) scored against expected risk/approval outcomes on Llama 3.2 3B
  Q4. This eval doubles as judging evidence for Meta-model quality.
- Integration: MCP request -> approval -> connector call -> result ->
  expiry, against Stripe/GitHub test-mode or a local mock HTTP server.
- Manual demo rehearsal on the actual 8 GB GPU machine, timed.

## 12. Demo script (3 minutes)

1. (15s) The horror: a real key pasted into an agent chat, now in a transcript.
2. (20s) Without MetaVault OSS, the agent is blocked or the human pastes the key.
3. (45s) Agent requests `stripe:charges.read` via MCP. Llama 3.2 3B explains
   the risk in one sentence. Human approves once.
4. (30s) Tool succeeds. Show the chat/transcript: the key never appeared.
5. (30s) Revoke the agent mid-task. Its next request fails safely.
6. (40s) Audit log replay; same MCP snippet working in a second IDE; close
   on "one vault, every agent, secrets never in context."

A pre-recorded fallback demo is captured before submission day.

## 13. Judging and bonus mapping

| Criterion / bonus | How MetaVault OSS answers it |
|---|---|
| Impact | Stops credential leakage into agent transcripts for every AI-coding user. |
| Use of Meta AI tooling | Meta model makes access decisions on every request; model ID and decisions in the audit log; brain eval published in the repo. |
| Demo | Live secret-free agent task plus mid-task revoke. Recorded fallback. |
| Technical depth | Capability-based grants, injection-inside-daemon, policy+brain defence in depth, canary-tested secrecy invariant. |
| Best Agentic Use-Case | Agents negotiate scope, act, expire, and get revoked — a full agent access loop. |
| Best Build on Meta Open Weight Models | Default brain is an open-weight Meta model running locally; Glimmer is the documented upgrade on the same interface. |
| Viral / Community Vote | "Stop pasting API keys into your coding agent" launch post, one-command install, public repo from day one. |

## 14. Risks and mitigations

- Official rules may define eligible Meta models more narrowly than the
  secondary sources suggest. Mitigation: pluggable brain already supports
  Meta Model API and hosted Muse Spark Open; re-check official rules
  before submission and flip the default provider if required.
- 3B model misjudges a request. Mitigation: deterministic ceilings, scope
  clamping, human approval for sensitive scopes, brain eval in CI.
- MCP surface changes across IDEs. Mitigation: CLI path exposes the same
  operations; MCP is a thin adapter over the daemon API.
- Demo-day model or network failure. Mitigation: local model by default,
  rule-based fallback, pre-recorded demo.
- Scope creep. Mitigation: Section 8 cuts are binding. New ideas go to a
  post-hackathon list, not into the build.

## 15. Open questions

- Confirm official hackathon rules: eligible Meta models, build window,
  submission requirements, and track eligibility for this entrant.
- Confirm which two IDEs/agents are available on the demo machine for the
  "works everywhere" beat.
- Decide Stripe test-mode vs local mock for the recorded demo. A local mock
  is more reliable; Stripe test-mode is more convincing. Default: mock for
  the live run, Stripe test-mode captured in the recorded version if time
  allows.

## 16. Approval gate

This spec is the design. Implementation planning (via the writing-plans
skill) starts only after the user reviews and approves this file.
No product code has been written yet. The only artifact besides this
spec is the static UI mockup (`metavault-oss/mockups/directions.html`),
which is a design sample, not implementation.

Self-review (2026-10-31): placeholder scan clean (no TBD/TODO outside
the intentional Section 15 checklist); consistency pass unified the
Electron-first packaging, Direction B UI, marshal naming, and storage
design; ambiguity pass pinned the encryption scheme (AES-256-GCM,
master key in OS keychain), the stack (Effect TS in daemon-side
packages, plain TypeScript renderer, super-strict linting), v1 brain providers
(Ollama only), standing-approval limits (read-only, low-risk only), and
revoke semantics for in-flight calls. Scope check: the build is one
TypeScript repo with four testable units (vaultd, policy, brain,
connectors) behind MCP/CLI/UI surfaces — large but decomposable, and
Section 8 cuts remain binding.


