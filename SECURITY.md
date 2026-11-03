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

MetaVault OSS implements multi-tiered, defense-in-depth protections to prevent agent identity spoofing, approval phishing, and token hijacking:

1. **Authoritative Cryptographic Enrollment Tokens**:
   - Registered agents (Cursor, Claude Code, VS Code, Codex) receive persistent bearer tokens (`ov_agent_<id>_<hex32>`).
   - The daemon (`vaultd`) resolves the agent identity **authoritatively from the token** (`x-metavault-agent-token` header or Authorization bearer token). Any `agentId` self-reported in untrusted JSON bodies is overwritten by the registered identity.
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

- Secrets are stored only as AES-256-GCM ciphertext. By default the
  master key is wrapped with a passphrase-derived key (scrypt, or
  Argon2id on request) in `metavault.key.json` and is held in daemon
  memory only while the vault is unlocked (auto-lock after 15 minutes
  idle). Plaintext secrets exist only inside `vaultd` during a single
  connector execution. See [Master key protection](#master-key-protection).
- Payment cards are a separate credential type. The number is Luhn-checked
  and the number, name, expiry and CVV are stored encrypted together.
  Agents and the app only ever see the brand, last 4 and a masked number.
  Every card use is a financial high-risk write: a human must approve each
  one, it can never be auto-approved or "always allowed", and no payment
  connector exists yet, so the daemon refuses to execute card grants.
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

## Master key protection

### What the code does

| Mode | How the daemon gets the key | Auto-lock | Default? |
| --- | --- | --- | --- |
| Passphrase (`metavault.key.json`) | `metavault unlock` sends your passphrase to `POST /unlock` (the app's preload exposes the same call, but the app has no passphrase screen yet); the daemon derives a key-encryption key (KEK) and unwraps the master key with AES-256-GCM | Yes, 15 min idle (`METAVAULT_AUTO_LOCK_MINUTES`, 1 to 1440); `metavault lock` locks now | Yes (`metavault init`) |
| Legacy OS keychain | Read from the OS keychain at start | No | Only with `init --legacy-keychain`, or an existing vault that has not been migrated (the daemon warns) |
| Environment variable | `METAVAULT_MASTER_KEY` | No | No. Ignored unless `METAVAULT_ALLOW_ENV_MASTER_KEY=1` |
| Dev plaintext file | `./metavault.key` (mode 0600) written by `scripts/run-daemon.mjs` | No | No. Only with `METAVAULT_DEV_PLAINTEXT_KEY=1` |

KDF parameters (stored in the key file and bound into the AES-GCM
additional data, so they can't be swapped without failing the unwrap):

- scrypt, the default: N = 2^17, r = 8, p = 1.
- Argon2id (`--kdf argon2id`): 19456 KiB memory, 2 iterations, 1 lane.

Both are the OWASP Password Storage Cheat Sheet minimums: "Use Argon2id
with a minimum configuration of 19 MiB of memory, an iteration count of 2,
and 1 degree of parallelism. If Argon2id is not available, use scrypt with
a minimum CPU/memory cost parameter of (2^17), a minimum block size of 8
(1024 bytes), and a parallelization parameter of 1."
(<https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>).
scrypt is the default because it ships with Node's `crypto` module.
Measured once on the development box (Linux): one Argon2id derivation took
43 ms and one scrypt derivation took 388 ms.

Other details:

- Passphrases must be at least 12 characters.
- After 5 wrong passphrases, `/unlock` returns 429 with a backoff that
  starts at 30 s and doubles to a 15 minute cap.
- While locked, every route that needs the key returns 423 `VaultLocked`.
- On lock the in-memory key Buffer is zero-filled. The KEK and temporary
  buffers are zero-filled after each unwrap.
- Oversized KDF parameters in a tampered key file are rejected before any
  derivation runs.

### Migrating an existing vault

1. Stop the daemon.
2. Run `metavault key status` to see where the key lives now.
3. Run `metavault key protect` (add `--kdf argon2id` if you want it). It
   reads the legacy key from the keychain (or from `METAVAULT_MASTER_KEY`
   if `METAVAULT_ALLOW_ENV_MASTER_KEY=1` is set),
   asks for a new passphrase twice, writes `metavault.key.json` next to the
   database with mode 0600, and deletes the keychain copy. Pass
   `--keep-keychain` to keep the keychain copy until you've confirmed the
   daemon unlocks, then run `key protect` again or delete the entry by hand.
4. Remove `METAVAULT_MASTER_KEY` and `METAVAULT_ALLOW_ENV_MASTER_KEY` from
   your shell profile and any scripts.
5. Start the daemon (it starts locked), then run `metavault unlock`.

The database and every ciphertext stay as they are. Only the way the
master key is stored changes.

### What stays exposed

These are not fixed, and the code doesn't claim to fix them:

- **Keylogging.** Malware running as you can record the passphrase as you
  type it, then unwrap `metavault.key.json` itself.
- **Memory reads while unlocked.** While the vault is unlocked the master
  key is in daemon memory, and during a brokered call the secret is too.
  Same-user malware can read another process's memory on all three desktop
  OSes. Node.js gives no `mlock`, `MADV_DONTDUMP` or `PR_SET_DUMPABLE`
  control from JavaScript, so none of those are applied. Auto-lock limits
  how long the key sits in memory; it doesn't protect it while it's there.
- **Legacy modes.** The keychain, env-var and dev-plaintext modes can't
  auto-lock. A same-user process can read the key from the keychain, the
  process environment or the file.
- **Daemon token.** Any local process that can read `metavault.token` can
  call the daemon, including `/unlock` (rate-limited), `/lock` and
  `POST /cards`. It can't read a secret or card value back, and it can't
  approve a card use without the human approval step.
- **Offline guessing.** A copied `metavault.key.json` can be attacked
  offline. The KDF slows each guess down; a weak passphrase is still weak.

### Researched, not implemented

- Windows Hello `UserConsentVerifier` ("Checks for availability of a
  verification device ... and performs a verification"):
  <https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier>.
  It returns a yes/no verification result and holds no key. The desktop
  app already uses it (`packages/app/src/windows-hello.ts`) for its own
  screen lock, which hides the app window. That lock doesn't touch the
  daemon or the master key; the daemon is unlocked only with the
  passphrase.
- macOS `LAContext` ("A mechanism for evaluating authentication policies
  and access controls"; it "interfaces to the Secure Enclave"):
  <https://developer.apple.com/documentation/localauthentication/lacontext>.
  Needs a native module and code signing.
- Linux polkit ("an authorization API intended to be used by privileged
  programs"): <https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html>.
  It's built for privileged mechanisms, and the daemon runs as you.
- Windows `CryptProtectMemory`: it "encrypts memory to prevent others from
  viewing sensitive information in your process", but Microsoft's remarks
  also say it "is not secure because the data exists as plaintext in memory
  before it is encrypted and at any time the caller decrypts it for use":
  <https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory>.
- Linux `MADV_DONTDUMP` ("Exclude from a core dump those pages"):
  <https://man7.org/linux/man-pages/man2/madvise.2.html>, and
  `PR_SET_DUMPABLE` ("Processes that are not dumpable can not be attached
  via ptrace(2) PTRACE_ATTACH"):
  <https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html>.
  Both need native code under Node.

## Supported versions

Pre-1.0. Only the latest `main` is supported.
