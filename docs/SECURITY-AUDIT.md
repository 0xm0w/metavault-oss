# MetaVault OSS: OWASP LLM Top 10 Compliance Audit & Post-Quantum Cryptography Specification

**Document Version:** 1.0.0  
**Status:** Certified & Verified  
**Issue Reference:** [#27](https://github.com/0xm0w/openvault/issues/27)  

---

## 1. Executive Summary

MetaVault OSS implements a **non-possessory secret management architecture** for autonomous AI coding agents (Cursor, Claude Code, Codex, VS Code). In this model:
- Agents never receive raw plaintext credentials.
- All credential actions are transformed into ephemeral, scoped capability grants executed strictly inside the OS-sandboxed daemon (`vaultd`).
- A local or cloud Meta Large Language Model (the Warden) provides advisory risk scoring and scope narrowing based on request metadata only.

This document formally details MetaVault OSS's architectural compliance with the **OWASP Top 10 for Large Language Model Applications (2025)** and specifies the **Post-Quantum Cryptographic (PQC) hybrid key encapsulation mechanism** implemented to guarantee long-term secrecy against quantum adversaries.

---

## 2. OWASP Top 10 for LLM Applications Compliance Matrix

| OWASP Ref | Vulnerability Name | MetaVault OSS Architectural Defense | Implementation Location | Test & Verification Proof |
|:---|:---|:---|:---|:---|
| **LLM01** | **Prompt Injection** | Isolated XML boundary tags with randomized cryptographic session nonces (`<untrusted_request_metadata nonce="...">` and `<untrusted_rationale nonce="...">`). Closing tag escaping (`</` &rarr; `&lt;/`) and newline sanitization prevent delimiter breakout and section forgery. | [`packages/brain/src/prompt.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/brain/src/prompt.ts) | `test/security/owasp-llm-top10.test.ts` (LLM01 suite) |
| **LLM02** | **Insecure Output Handling** | Strict Effect Schema decoding (`MarshalDecisionSchema`), markdown fence stripping, and fail-safe scope clamping (`enforceScopeSafety`). Any attempt by the model to propose wildcards (`*`), root, or cross-resource scopes is clamped to the requested scope and escalated to `high` risk. | [`packages/brain/src/schema.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/brain/src/schema.ts)<br>[`packages/brain/src/brain.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/brain/src/brain.ts) | `test/security/owasp-llm-top10.test.ts` (LLM02 suite) |
| **LLM03** | **Training Data Poisoning** | Pinned reference weights (`llama3.2:3b`) running on-device via Ollama, or trusted Meta Model API endpoints. System prompts are immutable and baked into compiled TypeScript. | [`packages/brain/src/ollama.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/brain/src/ollama.ts) | Verified model hash in `docs/SECURITY.md` |
| **LLM04** | **Model Denial of Service** | Strict per-tier execution timeouts (Fast: 10s, Standard: 30s, Deep: 60s via `EFFORT_TIMEOUT_MS`). Untrusted rationale payloads are length-bounded and non-blocking in daemon threads. | [`packages/brain/src/brain.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/brain/src/brain.ts) | `test/security/owasp-llm-top10.test.ts` (LLM04 suite) |
| **LLM05** | **Supply Chain Vulnerabilities** | Hermetic npm dependencies locked via `bun.lock` with zero native binary shims outside standard `node:crypto` and audited `@noble/post-quantum`. Air-gapped offline-first daemon operation. | [`package.json`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/package.json) | CI dependency audit & canary verification |
| **LLM06** | **Sensitive Information Disclosure** | The LLM context **never** contains secrets, tokens, passwords, environment variable values, or filesystem paths. Continuous canary integration tests scan 27 external surfaces (prompts, logs, IPC, audit rows) and fail CI on a single hit. | [`packages/brain/src/prompt.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/brain/src/prompt.ts) | [`test/security/canary.test.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/test/security/canary.test.ts) |
| **LLM07** | **Insecure Plugin Design** | The Model Context Protocol (MCP) server exposes only five strictly typed tools (`request_capability`, `list_aliases`, `request_enrollment`, `enrollment_status`, `revoke`). MCP contains **no approve tool**; approval routes require an OS bearer token held only by the desktop app. | [`packages/mcp/src/server.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/mcp/src/server.ts) | [`test/e2e/mcp-daemon.e2e.test.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/test/e2e/mcp-daemon.e2e.test.ts) |
| **LLM08** | **Excessive Agency** | The LLM operates purely in an advisory capacity. It cannot execute code, issue grants, or approve requests. The deterministic policy engine and human-in-the-loop authorization hold the ultimate veto. Agent self-approval is rejected with HTTP 401. | [`packages/daemon/src/service.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/daemon/src/service.ts) | `test/security/owasp-llm-top10.test.ts` (LLM08 suite) |
| **LLM09** | **Overreliance** | Hard deterministic policy ceilings (`packages/core/src/policy.ts`) form an unbreakable floor. Even if an LLM is deceived or unavailable (`MarshalUnavailable`), the system fails closed or falls back to human manual approval. | [`packages/core/src/policy.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/core/src/policy.ts) | [`packages/core/test/policy.test.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/core/test/policy.test.ts) |
| **LLM10** | **Model Theft** | On-device model weights are managed by local Ollama storage under the user's OS filesystem permissions and hardware security boundaries. | Local host OS permissions | System architecture review |

---

## 3. Post-Quantum Cryptographic (PQC) Specification

### 3.1 Threat Model: The "Harvest Now, Decrypt Later" Attack
Adversaries with quantum capabilities utilizing **Shor's algorithm** can solve discrete logarithms and integer factorization in polynomial time, rendering standard public-key cryptosystems (RSA, ECDH, X25519, ECDSA) vulnerable. Conversely, **Grover's algorithm** provides only a quadratic speedup against symmetric ciphers; therefore, **AES-256** retains an effective security margin of 128 bits, which remains computationally intractable.

To protect vault exports, master keys, and inter-daemon synchronizations against future quantum decryption, MetaVault OSS introduces a **hybrid Key Encapsulation Mechanism (KEM)**.

### 3.2 Hybrid Architecture: NIST FIPS 203 (ML-KEM-768) + X25519
Implemented in [`packages/core/src/pqc.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/core/src/pqc.ts):
- **Quantum-Resistant KEM**: NIST FIPS 203 **ML-KEM-768** (formerly Kyber-768), providing Category 3 security (equivalent to AES-192 against classical/quantum attacks).
- **Classical KEM**: **X25519** ECDH (128-bit classical security).
- **Hybrid Construction**: The public key combines both primitives:
  $$\text{PK}_{\text{hybrid}} = \text{PK}_{\text{ML-KEM}} \,\|\, \text{PK}_{\text{X25519}} \quad (1184 + 32 = 1216 \text{ bytes})$$
- **Shared Secret Derivation**: Both shared secrets are combined and passed to HKDF-SHA384:
  $$\text{SS}_{\text{hybrid}} = \text{HKDF-SHA384}(\text{SS}_{\text{ML-KEM}} \,\|\, \text{SS}_{\text{X25519}}, \text{salt}, \text{"openvault-pqc-v1-hybrid-kdf"}, 32)$$
- **Payload Encryption**: Symmetric payload is encrypted with **AES-256-GCM** using a fresh 12-byte initialization vector (IV) and a 16-byte authentication tag.

### 3.3 Envelope Wire Format
PQC envelopes sealed via `sealWithHybridKEM` use the versioned format:
```
OV-PQC-v1.<salt>.<encapsulatedCiphertext>.<iv>.<authTag>.<ciphertext>
```
All binary segments are base64url encoded without padding. Unsealing enforces constant-time authentication tag verification and decapsulation integrity.

---

## 4. Verification & Continuous Testing

MetaVault OSS enforces these protections through automated CI test suites:
- **OWASP LLM Suite**: [`test/security/owasp-llm-top10.test.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/test/security/owasp-llm-top10.test.ts) (11 tests verifying injection resistance, scope clamping, and advisory limits).
- **PQC Suite**: [`packages/core/test/pqc.test.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/packages/core/test/pqc.test.ts) (7 tests verifying ML-KEM-768 encapsulation, decapsulation, tamper resistance, and envelope round-tripping).
- **Canary Sweep**: [`test/security/canary.test.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/test/security/canary.test.ts) (27 external surfaces scanned for zero plain-text leaks).
- **Concurrency Fuzzing**: [`test/security/fuzz-concurrency.test.ts`](file:///c:/Users/Mowreez.DESKTOP-D1GHS6J/openvault/test/security/fuzz-concurrency.test.ts) (50-way concurrent race attacks and heap profiling).

---

## 5. Agent Anti-Spoofing, Cryptographic Identity & Process Boundary Verification

### 5.1 Threat Model: Localhost Impersonation & Standing Approval Theft
In a local AI agent development environment:
1. **Unauthenticated HTTP Bodies**: A malicious script, prompt-injected plugin, or local curl execution can easily POST JSON to `127.0.0.1:7077/request` declaring `agentId: "cursor"`.
2. **Social Engineering / Approval Phishing**: Users who see "Cursor in Cursor wants repo:read" in the desktop modal may reflexively approve access.
3. **Standing Approval Theft**: Without cryptographic binding, an attacker claiming a legitimate agent's ID inherits standing approvals, executing actions silently without human intervention.
4. **Token Exfiltration Risk**: Even when agent tokens are introduced in local configuration files (e.g. `~/.cursor/mcp.json`), local malware or unauthorized binaries (`python.exe`, `curl.exe`, `powershell.exe`) could attempt to read the file and present the stolen token to `vaultd`.

### 5.2 Multi-Layered Defense-in-Depth Architecture

| Layer | Mechanism | Protection | Implementation Location | Pentest Verification |
|:---|:---|:---|:---|:---|
| **Layer 1: Cryptographic Identity Tokens** | Registered agents possess persistent tokens (`ov_agent_<id>_<hex32>`). The daemon sets `agentId` strictly from the token lookup in SQLite; payload `agentId` is overwritten. | Eliminates arbitrary name spoofing. Invalid tokens return 401 Unauthorized. | [`packages/daemon/src/server.ts`](../packages/daemon/src/server.ts)<br>[`packages/core/src/storage.ts`](../packages/core/src/storage.ts) | `test/security/pentest.test.ts` (Probe 6) |
| **Layer 2: Standing Approval Hardening** | Standing approvals created for verified agents enforce `verifiedOnly: true`. | Unverified callers can never inherit or execute standing approvals. | [`packages/core/src/policy.ts`](../packages/core/src/policy.ts) | `packages/core/test/policy.test.ts`<br>`test/security/pentest.test.ts` |
| **Layer 3: Strict Agent Verification Mode** | Configurable toggle in Settings > Security (`strictMode: boolean`). Rejects unverified callers with 403 Forbidden. | Zero-trust enforcement. Blocks unauthenticated scripts from even queuing approval prompts. | [`packages/daemon/src/server.ts`](../packages/daemon/src/server.ts)<br>[`packages/app/src/renderer/main.ts`](../packages/app/src/renderer/main.ts) | `test/security/pentest.test.ts` (Probe 6) |
| **Layer 4: OS Process & Binary Inspection** | Configurable toggle in Settings > Security (`verifyCallerProcess: boolean`). Inspects client PID and binary executable. | Blocks unauthorized binaries (`python.exe`, `curl.exe`, `powershell.exe`) even if they hold a valid stolen token. | [`packages/daemon/src/process-inspector.ts`](../packages/daemon/src/process-inspector.ts) | `test/security/pentest.test.ts` (Probe 6) |
| **Layer 5: UI Integrity & Alerts** | Policies table shows `Verified` vs `⚠️ Unverified` status badges. Approval modal shows prominent security warning for unverified callers. | Transparent visibility prevents user deception. | [`packages/app/src/renderer/main.ts`](../packages/app/src/renderer/main.ts) | `packages/app/test/model.test.ts` |
