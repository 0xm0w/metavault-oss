# OpenVault Security Audit — Task 9 (2026-10-31)

Scope: `vaultd` daemon (`packages/daemon`), core policy/grants (`packages/core`),
marshal policy interaction (`packages/brain` via stub), MCP adapter
(`packages/mcp`), deeplink handling and renderer projections (`packages/app`).
Method: black-box probes written first as failing CI tests
(`test/security/pentest.test.ts`, 17 tests against an ephemeral real-HTTP
daemon), then fixed in the owning package with the probe kept as the
regression test. Manual equivalent: `scripts/pentest.mjs` against a running
daemon. Prior review minors were explicitly re-probed: token guard
fail-open when no token is configured, malformed JSON on settings PUT
returning 500, and connector failures audited as `executed`.

## Threat model

Assets, in priority order:

1. Credential plaintext and the vault master key. Plaintext may exist only
   inside the daemon process at connector-call time (and in the human's
   hands while typing it into the app).
2. The human-decision right: only the human (holder of `x-openvault-token`)
   may approve, deny, mutate credentials, or change warden settings.
3. Policy integrity: deterministic ceilings are law; the marshal may narrow
   or escalate, never widen.
4. Audit integrity: the audit trail is the after-the-fact evidence; a failed
   execution must never read as a successful one.

Actors:

| Actor | Capability assumed |
| --- | --- |
| Malicious or confused agent / IDE process | Can call every agent-facing daemon route and all 5 MCP tools; can craft deeplinks; cannot read the token file in the intended deployment |
| Other local process (same OS user) | Can reach `127.0.0.1:7077`; may or may not be able to read `openvault.token` (same-user processes usually can — see accepted risk A3) |
| Hostile link / web content | Can trigger `openvault://add` deeplinks with attacker-chosen parameters |
| Network attacker | Out of scope: the daemon binds `127.0.0.1` only; no TLS/auth story exists for remote use and none is claimed |
| The marshal model (Ollama / Meta API) | Untrusted advisor: may recommend any scope; deterministic policy must contain it |

Trust boundaries: agent → daemon HTTP (unauthenticated, safe-direction
routes only), renderer → daemon (token held in the Electron main process,
never in the renderer after save), daemon → connector (secret injected
in-daemon only), daemon → marshal (request metadata only, never secrets).

Global constraints verified throughout: secrets never reach agents, the
marshal prompt, the renderer after save, logs, or audit rows; settings
change who judges, never the rules; MCP/agent routes must never accept the
daemon token as an escalation path.

## Probe results (CI: `test/security/pentest.test.ts`)

| # | Probe | Result |
| --- | --- | --- |
| 1 | Approve/deny/settings/credential-mutation without token ⇒ 401; wrong token ⇒ 401 | Pass after F1 fix (guard itself was already correct when a token was configured) |
| 2 | MCP-side `x-openvault-token` injection ⇒ still agent traffic, settings denied | Pass: even the real token on `/request` only ever yields `awaiting-approval`; MCP exposes no settings/approve tool |
| 3 | Scope escalation above ceiling, marshal recommending above ceiling ⇒ denied `scope-above-ceiling` / clamped, never executed as write; connector failure audited truthfully | Escalation pass (policy held); audit stage fixed (F4) |
| 4 | Standing-approval abuse: write scope, unknown alias, delete+re-add credential | Pass (policy/service held with no code change) |
| 5 | Deeplink fuzz: `../`, `%00`, 10k alias, duplicate params ⇒ clean rejection | Fixed (F5) |
| 6 | Enrollment flood: 200 rapid creates ⇒ bounded registry, no 500s; agent B flood cannot evict agent A's pending while B has its own pendings | Fixed (F3, fair eviction) |
| 7 | Malformed percent-encoding + oversized JSON on every route ⇒ 400/413, never 500 | Fixed (F2) |
| 8 | Canary secret absent from daemon responses and audit JSON while probes run | Pass (connector received the canary in-daemon, proving the scan non-vacuous) |
| 9 | Renderer credential detail never renders a secret field | Pass (`projectCredentialsResponse` drops secret-shaped entries fail-closed) |

Manual run (`scripts/pentest.mjs` vs a live daemon on an ephemeral port,
token set): **13 PASS, 0 FAIL, 0 SKIP**.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | High | Token guard failed open when `daemonToken` was undefined: `handleVaultRequest` skipped the check entirely, and `createVaultHttpServer` forwarded no token, so a server constructed without one exposed approve/deny/settings/credential mutation to any local process. (Production `startVaultDaemon` always resolved a token, which limited real-world reachability, but the exported guard was unsafe by default.) | **Fixed** — guard is fail-closed in the handler (no configured token ⇒ 401 on protected routes); the HTTP server substitutes an ephemeral unknown token when none is configured. Regression: pentest probe 1. Legacy handler-level tests were updated to present a token. |
| F2 | Medium | Malformed JSON and oversized bodies returned 500 on every body route, including `PUT /settings/warden/key`. A 500 on attacker-controlled input hides errors, pollutes alerting, and violates the 400/413 contract. | **Fixed** — body reading throws a typed `HttpBodyError`; the HTTP edge maps it to 400 (malformed) / 413 (over 64 KiB). Regression: pentest probe 7 across 8 body routes. |
| F3 | Medium | Pending enrollment registry was unbounded inside the TTL window: 200 rapid creates left 200 pending enrollments (memory + UI surface), evicted only at expiry. Plain oldest-first eviction also let one flooding agent evict another agent's pending enrollment. | **Fixed** — pending enrollments are capped at `MAX_PENDING_ENROLLMENTS = 100`; expired pendings are purged first, then the oldest pending of the *incoming* agent (`agentId`, supplied by the MCP adapter / enrollment caller) is evicted, and only if that agent has none pending is the globally oldest evicted. Regression: pentest probes 6 and 6b (200 anonymous creates bounded; agent B flood evicts B's own oldest, agent A's pending survives). Remaining tradeoff: `agentId` on this unauthenticated route is self-asserted (see A1), so a flooder rotating or spoofing agent ids can still claim the global-oldest fallback and evict others — fairness holds for honestly-identified agents, it is not an identity guarantee. Per-agent quotas or authenticated enrollment would close this and are a contract change, not a patch. |
| F4 | Low | Connector failure on the auto-approved path was audited with stage `executed` and detail `connector-failed`, so the audit page's outcome derivation reported a failed call as executed. The human-approved path wrote no terminal stage at all on connector failure. | **Fixed** — both paths now audit stage `denied` with detail `connector-failed` (response semantics unchanged: `denied`/`connector-failed` and 502 respectively). Regression: pentest probes 3 and 6b (human-approved path: request → park → approve/approve-always with failing connector ⇒ 502 `ConnectorFailed`, terminal `denied`/`connector-failed` audit, and no standing approval left after a failed approve-always). |
| F5 | Low | Deeplink parser silently took the first of duplicate `alias`/`scope` params, and accepted path-like aliases (`../evil`, `a\b`); the daemon likewise accepted `/`-containing aliases at enrollment/credential creation, producing deeplinks the app would render as opaque names. Aliases are DB keys (never filesystem paths), so impact was confusion/UI spoofing, not traversal. | **Fixed** — parser rejects duplicate known params and slash/backslash/dot aliases; daemon rejects unsafe aliases (control chars, `/`, `\`, `.`, `..`, >128 chars) with 400 on `POST /enrollments` and `POST /credentials`. Regression: pentest probe 5. |

Fixed count by severity: **1 High, 2 Medium, 2 Low.**

## Accepted risks and parked items

| ID | Severity if exploited | Item | Reasoning |
| --- | --- | --- | --- |
| A1 | Medium | Agent-facing routes (`/request`, `/aliases`, `/audit`, `/policies`, `/revoke`, enrollment creation) are unauthenticated by design for any local process. | Accepted: requesting grants nothing (human approval or deterministic policy still gates execution) and revoke only removes access. Residual impact is approval-prompt spam and metadata disclosure (alias names, audit history) to same-user local processes. The daemon is loopback-only; a future per-agent credential would change this, and is a contract change, not a patch. |
| A2 | Low | Audit-log growth is unbounded: enrollment floods and request spam keep appending audit rows even though the pending registry is now capped; capability requests are rate-limited per agent (20/h) but enrollments are not rate-limited. Enrollment eviction fairness (F3) also relies on the self-asserted `agentId`, so rotating/spoofed ids or anonymous creates can still evict other agents' pendings via the global-oldest fallback. | Accepted for alpha: local disk, single user, and the audit trail's evidentiary value argues against silent dropping. Parked: retention/pruning policy, per-agent enrollment quotas, and authenticated enrollment identity after v0.1.0-alpha.1. |
| A3 | Low | The daemon token lives in a plaintext `openvault.token` file next to the DB (mode `0600` best-effort; POSIX modes do not map to Windows ACLs, so a same-user process can typically read it). | Accepted: this is the documented local trust model (same OS user = trusted). Parked: OS-keychain/DPAPI-backed token storage, aligned with the existing master-key keychain path. |
| A4 | Info | Selecting the Meta API warden sends request metadata (agent, alias, scope, reason — never secrets) off-device. | Accepted and disclosed in the Settings page copy and `docs/SECURITY` material; provider `none`/Ollama keeps everything on-device. |

## Residual assurance notes

- Probes 4, 8, 9, and the escalation half of probe 3 passed against the
  pre-fix code: deterministic
  policy clamping, standing-approval eligibility (read-only + low risk,
  re-checked server-side, revoked on credential delete), canary absence,
  and renderer fail-closed projections needed no changes and are now
  pinned by CI tests.
- The daemon binds `127.0.0.1` only; nothing in this audit covers a
  deployment that port-forwards or proxies the daemon, which would void
  the local trust model (notably A1/A3).
- Every fix above shipped in its own commit with the pentest probe as the
  regression test; full gates (`npm run test`, `typecheck`, `lint`) were
  green at each step.
