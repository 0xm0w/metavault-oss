# Changelog

All notable changes to OpenVault are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.1] — 2026-10-31

First public feature line. Alpha because the installer is unsigned, there
is no macOS build, the Meta API warden path is new, and the daemon/MCP
contract may still change before `0.1.0`.

### Added

- MCP server packaged as a deployable IDE component (`openvault-mcp` bin,
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
