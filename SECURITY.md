# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability — this project
will be public later, and reports should not disclose exploit details
before a fix exists.

Report privately to the maintainers with:

- A description of the issue and its impact.
- The exact component (`vaultd`, policy, brain, connectors, MCP, CLI, or
  the Electron app) and file/line if known.
- Reproduction steps or a proof of concept that does not use real
  credentials. Use fake/canary secrets only.


## Agent Identity & Anti-Spoofing Architecture

OpenVault implements multi-tiered, defense-in-depth protections to prevent agent identity spoofing, approval phishing, and token hijacking:

1. **Authoritative Cryptographic Enrollment Tokens**:
   - Registered agents (Cursor, Claude Code, VS Code, Codex) receive persistent bearer tokens (`ov_agent_<id>_<hex32>`).
   - The daemon (`vaultd`) resolves the agent identity **authoritatively from the token** (`x-openvault-agent-token` header or Authorization bearer token). Any `agentId` self-reported in untrusted JSON bodies is overwritten by the registered identity.
   - Requests presenting an invalid token are immediately rejected with HTTP `401 Unauthorized`.

2. **Standing Approval Isolation**:
   - Standing approvals created for verified agents enforce `verifiedOnly: true`.
   - Unverified callers (requests lacking a token) can never inherit, consume, or bypass human authorization using existing standing approvals.

3. **Strict Agent Verification Mode (Configurable in Settings > Security)**:
   - When enabled, `vaultd` enforces zero-trust: any capability request from an unverified caller without an authentic enrollment token is immediately rejected with HTTP `403 Forbidden` (`strict-mode-unverified-blocked`). Unverified callers cannot even open approval modals.

4. **Caller Process & Binary Boundary Inspection (Defense-in-Depth)**:
   - When enabled in Settings, `vaultd` inspects the client's OS process ID (PID) and executable binary.
   - Cross-references the caller binary against approved agent runtimes (`Cursor.exe`, `Code.exe`, `node.exe`, `electron.exe`, `claude.exe`).
   - If an unauthorized script runner or tool (`python.exe`, `curl.exe`, `powershell.exe`, `cmd.exe`, `bash`) attempts to exploit a stolen agent token, the process inspection engine blocks the call with HTTP `403 Forbidden` (`process-verification-failed`).

## Security model (summary)

- Secrets are stored only as AES-256-GCM ciphertext; the master key
  lives in the OS keychain. Plaintext exists only inside `vaultd`
  during a single connector execution.
- Agents request scoped capabilities, never secret values. The local
  marshal model sees metadata only — never a secret, fragment, or hash.
- Deterministic policy ceilings cannot be widened by the model.
  Standing approvals cover read-only, low-risk scopes only.
- Prompt injection and scope escalation are neutralized via nonce-delimited
  XML tags and automated scope clamping (OWASP LLM01/LLM02 compliance).
- Post-quantum hybrid envelope encryption (NIST FIPS 203 ML-KEM-768 + X25519)
  is available for long-term vault export and inter-daemon synchronization.
- The daemon binds to `127.0.0.1`; human-decision routes require the
  daemon token. MCP exposes no approval operation.
- The canary test in `test/canary.test.ts` fails the build if a planted
  secret appears in any transcript, log, audit entry, or model prompt.

See [`docs/SECURITY-AUDIT.md`](docs/SECURITY-AUDIT.md) for the full OWASP LLM Top 10
compliance matrix and Post-Quantum Cryptography threat model.

## Supported versions

Pre-1.0. Only the latest `main` is supported.
