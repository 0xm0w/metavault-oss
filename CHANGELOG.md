# Changelog

All notable changes to MetaVault OSS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Security-hardening candidate - 2026-11-06 (unreleased)

### Breaking

- **The daemon never writes `metavault.token`.** The admin token for the
  human-decision routes travels only via `METAVAULT_DAEMON_TOKEN` in the
  environment (the desktop app mints a per-session token for the bundled
  daemon it spawns; a standalone daemon without it keeps an in-memory token
  nobody can read back, so guarded routes stay 401). Any leftover
  `metavault.token` from an older version is destroyed at daemon start and
  nothing reads one.

### Fixed / hardened

- **Caller-process inspection (gate: Settings > Security).** Linux resolves
  the caller binary from `readlink /proc/<pid>/exe` instead of the
  `prctl`-renamable `/proc/<pid>/comm` and fails closed when the link is
  unreadable; generic runtimes (`node`, `bun`, `deno`) are no longer
  treated as proof of identity - such callers are admitted only with an
  enrolled agent token, and a request claiming the daemon's own PID is
  rejected. UDS + `SO_PEERCRED` remains researched follow-up work.
- **Warden and deterministic rules see the payload.** Both the rules
  baseline and the marshal prompt now include a canonical payload summary
  (declared HTTP method, sha-256 digest, bounded preview). The policy floor
  denies any request whose payload declares a mutating method
  (POST/PUT/PATCH/DELETE) under a read-only scope, whatever the stated
  reason (`payload-mutates-readonly-scope`).
- **Connector responses redact the credential.** Occurrences of the
  injected secret (exact, percent-encoded, Base64, Base64-URL) in upstream
  response bodies are replaced with `[REDACTED]` before the body reaches
  the agent.
- **BFT quorum no longer degrades to one warden.** When both the Meta API
  and a local endpoint are configured and only one responds, the assessment
  fails closed (`MarshalUnavailable`) and the request goes to a human
  decision instead of silently trusting a single model.

The entries below are historical. They do not override the current
candidates' uninstall contract or prove their validation.

## Local-hardening candidate - 2026-11-04 (unreleased)

- Installed Windows MCP paths/runtime and static agent instructions, tested in
  actual VS Code with a verified synthetic request, not model chat or all IDEs.
- One-time agent token creation, rotation/revocation and backed-up hash migration.
- Active vault path and unlocked key fingerprint; fail-closed missing/mismatched
  key handling and synthetic matching DB/key restore tests.
- Deliberate uninstall wipes fixed app data, warning/Cancel, fresh reinstall;
  in-place update preserves. Shared legacy keys and linked profiles fail closed.
- Published0.1.2-to-candidate Windows upgrade gate added; its final exact-head
  result must be checked in verification evidence before handoff.
- Password wording preserves stored/API passphrase compatibility.
- Not included/proven: Windows PRF key custody, legacy0.1.0 compatibility,
  other-platform onboarding fixes, remote Connections or zero-memory guarantees.

The entries below are historical. They do not override the current candidate's
uninstall contract or prove its validation.

## [0.1.0-alpha] - Unreleased (draft release only)

### Breaking

- **No bundled or downloaded model.** MetaVault no longer ships, bundles or downloads a local model. The built-in engine, the Settings model download, `metavault model pull`, `METAVAULT_WARDEN_MODEL` and `METAVAULT_OLLAMA_URL` are removed.
- **Default warden is Muse Spark (`muse-spark-1.3`) via the Meta API.** New vaults start on `meta-api`. Without a Meta API key the warden is unavailable and every request that needs judgement fails closed to you.
- Saved settings with provider `ollama` or `builtin` migrate to `local`. A row that had no explicit endpoint migrates with an empty base URL, so it fails closed until you set one.

### Added

- **Bring-your-own local endpoint** in Settings (provider `local`): API style (Ollama `POST {base}/api/chat`, or OpenAI-compatible `POST {base}/chat/completions`), base URL and model name. Placeholder and docs recommend a Meta open model such as Muse Glimmer (`muse-glimmer:30b`). The daemon rejects base URLs that are not `http`/`https` or that carry a username or password (`400`).
- BFT uses Muse Spark plus your local endpoint when one is set.
- **Windows installer (`MetaVault-OSS-0.1.0-alpha-win-x64.exe`, unsigned).** Assisted NSIS install with a choice of folder, a desktop and a Start menu shortcut, a short alpha terms page (`packages/app/TERMS.txt`), and an uninstaller. The daemon, CLI and MCP server are bundled into `resources/vaultd` and run on the app's own Electron runtime (`ELECTRON_RUN_AS_NODE=1`), so no Node install is needed. The app starts the bundled daemon when none is running and stops it on quit.
- **First-run passphrase setup.** A fresh vault opens on a "create a passphrase" screen (`POST /setup`, which needs the token and works once, only on an uninitialized vault), and a locked vault opens on an unlock screen.
- **CI: `Windows installer` workflow** on `windows-latest`. It builds the installer, uploads it as an artifact, and runs a clean-install smoke test: silent install, launch, `/health`, silent uninstall, then checks that files, shortcuts, registry and PATH entries are gone. On a `v*` tag or a manual run it creates or updates a **draft** prerelease only. It replaces `release.yml`, which published releases on tags.
- Tests: no reachable warden fails closed to the human (no Meta key, empty local endpoint, unreachable local port, BFT with neither), with no request to `api.meta.ai` when no key is set.

### Changed

- Site, docs page, README, design doc and security audit no longer mention an 18 GB download, lazy loading, or RAM/VRAM requirements. Requirement copy describes the app only.
- Marshal status line defaults to `Marshal · muse-spark-1.3 · Meta API`.
- Version is `0.1.0-alpha` across root, app, MCP package and MCP server.
- Installer hooks: the user PATH add and remove are idempotent and keep `REG_EXPAND_SZ`. The duplicate shortcuts are gone. The "delete vault data?" prompt answers No on a silent uninstall and is skipped on updates.
- Prerelease builds do not check for updates on launch, so a published stable release cannot replace an alpha without you asking. "Check for updates" still works.

### Removed

- `pack:win:ai` (the "with AI" installer variant).
- `packages/app/src/model-downloader.ts`, `model-resolver.ts`, `builtin-ai-ipc.ts`, `packages/brain/src/builtin.ts`, the hardware-capacity card and the built-in download UI.

## [Unreleased]

### Breaking

- **Legacy env var prefix dropped.** Only `METAVAULT_*` variables are read. The pre-rebrand `OPENVAULT_*` names (`OPENVAULT_MASTER_KEY`, `OPENVAULT_OLLAMA_URL`, `OPENVAULT_DB_PATH`, `OPENVAULT_DAEMON_URL`, `OPENVAULT_DAEMON_TOKEN` and the rest) are ignored. Rename them to `METAVAULT_*` in shells, IDE MCP configs and scripts. The fallback was documented but had silently stopped working after the rename; it is now removed on purpose and pinned by `packages/core/test/env.test.ts`.

### Added

- Payment-card credential type: `metavault add-card`, `POST /cards`, and an app add form. Luhn-checked number, name, expiry and CVV, sealed as one AES-256-GCM ciphertext; agents and the app see only brand, last 4 and a masked number. Every card use needs a human approval, can't be standing-approved, and execute is refused because no payment connector exists.
- Passphrase-wrapped master key (`metavault.key.json`, scrypt N=2^17 r=8 p=1 by default, Argon2id 19 MiB t=2 p=1 opt-in), `metavault key status`, `key protect`, `unlock`, `lock`; daemon `/unlock`, `/lock`, `/key/status`; starts locked; 15-minute idle auto-lock (`METAVAULT_AUTO_LOCK_MINUTES`); unlock backoff after 5 failures. Migration: `SECURITY.md#master-key-protection`.
- `METAVAULT_WARDEN_MODEL` makes the default warden model configurable. The shipped default stays `muse-glimmer:30b`.
- Optional `hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-IQ3_XXS` (13,130,658,848 bytes) in the model lists, `-Quant` and `-Compare` in `scripts/eval-windows.ps1` and `scripts/thesis-windows.ps1`. Not benchmarked yet.

- `run-thesis.ts --provider openai-compat|meta-api`: OpenAI-compatible warden for comparison runs (polite pacing, 429/5xx retry with `Retry-After`, quota refusal aborts the run, per-call `usage` tokens, dollars per gated request from published prices, `--budget-usd` cap, default $0.50). `meta-api` reads `META_API_KEY` and defaults to `muse-spark-1.3` at `https://api.meta.ai/v1`.
- Docs Warden slide reworked into tiers (policy only, Muse Glimmer quants, Muse Spark via Meta API, BFT quorum) with measured-only charts for high-risk recall, false-alarm rate, and latency and cost; unmeasured tiers show as "not run".

- Measured Muse Spark 1.3 (Meta API) on the 60-case held-out set, two runs: warden 25/28 recall (21/22 paraphrased), 0/28 false alarms; rules + warden 27/28 recall, 9/28 false alarms (a failed warden call, one per run, counts as a miss); median 8.2-8.9 s; $0.0052-$0.0053 and about 1.5k tokens per gated request. No local Muse Glimmer eval output is committed, so no local quant numbers are published; the local held-out run was not run. `run-thesis.ts --call-log` writes per-call usage and spend as it happens.

### Changed

- `METAVAULT_MASTER_KEY` is ignored unless `METAVAULT_ALLOW_ENV_MASTER_KEY=1`. The dev plaintext key in `scripts/run-daemon.mjs` needs `METAVAULT_DEV_PLAINTEXT_KEY=1`.
- Eval memory measurement now walks the Ollama process tree (including child runners) and records `/api/ps` size and `size_vram`, `ollama ps` SIZE and PROCESSOR (GPU/CPU split), system memory delta and NVIDIA usage (`scripts/ollama-mem.ps1`). The earlier process-name-only sum missed the runner.
- Removed the unsupported privacy-proof wording from the research page and thesis review; copy now describes the actual encryption and key handling.

- Local warden is now Meta **Muse Glimmer 30B Q4_K_M** (`muse-glimmer:30b` via Ollama) for the Ollama, built-in and BFT paths; earlier local models removed from code, settings, UI and docs (#70).
- The built-in on-device engine is wired: it runs Muse Glimmer through local Ollama and the Settings download pulls it via `/api/pull` (previously it wrote placeholder files and always failed closed) (#70).
- Low reasoning-strength system prompt for Glimmer; local timeouts raised to 60 / 120 / 240 s (was 10 / 30 / 60 s) (#70).
- Meta API cloud default is now `https://api.meta.ai/v1` with `muse-spark-1.3` (#70).
- BFT copy describes a two-warden quorum (#70).

### Removed

- `site/research/` and every link to it (#70).
- `docs/verification/eval-live.txt` (old model); the live Muse Glimmer eval (`scripts/eval-windows.ps1`) has no committed result yet (#70).

## [0.1.1-hackathon.sprint] — 2026-11-02

Meta Hackathon (Indie Track) release sprint.

### Added

- Meta Hackathon portal & interactive snap deck live at `metahackathon.whativedone.xyz`.
- Background note: From the crypto industry, securing wallets since 2025.
- Live carousel and real GitHub shipping timeline showcasing the security researcher heritage.
- Hardened adversarial prompt defenses, unverified caller quarantine, and an adversarial defense benchmark against the then-default local model (#55).

## [0.1.0] — 2026-11-01

First public release. `v0.1.0-alpha.1` stays available as a prerelease.
The Windows installer is still unsigned, and there is still no macOS build.

### Added

- Desktop shell. Vault is the home page. Approval is second and shows how
  many requests are waiting. A new request opens an approval dialog on the
  current page instead of navigating away.
- Posture is its own page: grade, control table, and short next-step
  prompts. Policies no longer contains that box.
- Vault, Audit, and policy ceilings use a single-line data table. Revoke
  is a red text action.
- The caption row carries the view title, the marshal line, and the daemon
  status. The application menu is removed. Settings stays at the bottom of
  the sidebar.

### Known limitations

- The Windows installer is unsigned. SmartScreen will warn on first run.
- No macOS build.

## [0.1.0-alpha.1] — 2026-10-31

First public feature line. Alpha because the installer is unsigned, there
is no macOS build, the Meta API warden path is new, and the daemon/MCP
contract may still change before `0.1.0`.

### Added

- MCP server packaged as a deployable IDE component (`metavault-mcp` bin,
  `MCP_VERSION = "0.1.0-alpha.1"`) with copy-paste host configs for Claude
  Code, Cursor, VS Code, Codex and OpenCode in `docs/MCP.md`. The server
  exposes exactly five tools: `request_capability`, `list_aliases`,
  `request_enrollment`, `enrollment_status`, `revoke`.
- Warden settings store in the daemon (provider, model, effort, Meta API
  base URL) behind the daemon-token guard, with the Meta API key stored as
  an ordinary encrypted credential under alias `warden-meta-api` and only
  ever decrypted inside the daemon at call time.
- Brain providers: local Ollama and Meta API (OpenAI-compatible chat) with
  effort levels (Fast 10s / Standard 30s / Deep 60s; Deep runs a second
  verify pass that can only narrow or escalate, never widen).
- Structured AI audit trails: every capability request carries one
  `requestId` through requested → marshal → policy → approved/denied →
  executed, with `risk`, `recommendedScope`, `decisionSource`, `latencyMs`
  and marshal `explanation` on the relevant events.
- Audit page grouped per request with an expandable warden-verdict
  timeline and a text filter.
- Settings page: warden provider, model and effort switchers, encrypted
  Meta API key management (never repopulated after save), daemon info and
  a read-only security-defaults summary.
- Test hardening: V8 coverage gates (core ≥ 90%, daemon/brain/mcp ≥ 85%,
  renderer `model.ts` ≥ 90%), a secret-canary sweep across audit/MCP/
  deeplink/settings/IPC surfaces, and a real MCP ↔ daemon end-to-end test.
- CI/CD: GitHub Actions test matrix (Windows + Ubuntu), CodeQL, a tagged
  Windows release workflow, CODEOWNERS, issue/PR templates and Dependabot.
- Security audit document (`docs/SECURITY-AUDIT.md`) and a black-box
  pen-test suite covering token guards, scope escalation, deeplink fuzz,
  enrollment flooding, malformed bodies and canary leakage.
- Documentation with real running-app screenshots: enrolment flow,
  approval dialog, audit verdict and settings (`docs/verification/`).
- `electron-builder` as a locked root devDependency; the release workflow
  now builds with the local binary, pins
  `softprops/action-gh-release` to its v2.6.2 commit SHA, sets job
  timeouts, and checks out with `persist-credentials: false`.

### Security

- Deterministic policy is law: the marshal may narrow or escalate, never
  widen; effort and provider changes never change policy ceilings.
- All human-mutation daemon routes require the `x-openvault-token` header;
  MCP/agent traffic can never read settings or present that token.
- Secrets never reach agents, prompts, the renderer after save, logs or
  audit rows; audit stores verdict metadata only.

### Known limitations

- The Windows installer is **unsigned**; SmartScreen will warn on first
  run. Code signing is planned before `0.1.0`.
- **No macOS build** yet; the DMG config is declared but unbuilt and
  unsigned. Windows is the only shipped platform.
- Meta model ids in Settings are **user-editable** free text; a typo'd id
  surfaces as a warden-unavailable policy fallback, not a hard error.
- CI has not completed a first run yet (**CI first-run pending**); the
  workflows are committed and YAML-valid but unverified on GitHub until
  the next push. The tag-triggered release workflow is likewise unproven
  until the first `v*` tag is pushed (not part of this local build).
