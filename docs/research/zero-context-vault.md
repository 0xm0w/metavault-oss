# Zero-Context Agentic Vault

Implementation review: 2026-11-03 PHT. Baseline: `7b6f28b692a5de4476b4b0c6aa64a9b84ef8226a`.

## Conclusion

Use "Zero-Context Agentic Vault" to describe the brokered MCP credential path: request a capability, evaluate metadata, inject the credential in the daemon, return the operation result. This is a custody design, not a cryptographic zero-knowledge property or a guarantee across every MetaVault mode. Keep the broker for the supported API operations. Proof systems can complement it at separate verification boundaries; there is no evidence here of universal superiority or a matched performance advantage.

## Four boundaries, checked against code

| Boundary | Implemented evidence | Limit |
| --- | --- | --- |
| Capability request | `packages/mcp/src/server.ts`: request schema is alias, scope, reason, optional tool/payload. Five MCP tools; no read-secret tool. | Agent-controlled reasons/payloads are not guaranteed free of secrets supplied elsewhere. Enrollment and administrator interfaces handle plaintext inputs. |
| Warden vetting | `packages/brain/src/prompt.ts`: agentId, IDE, tool, alias, scope, reason, 24-hour request/denial counts, policy digest. No stored target credential is inserted into this prompt. | `packages/core/src/settings.ts` defaults to `meta-api`, `muse-spark-1.3`. Local is BYO, with no bundled/downloaded model. BFT can combine local and cloud. The Meta API's own authentication credential is used by the transport, not placed in the model prompt. Metadata may itself be sensitive. |
| Transport injection | `packages/daemon/src/service.ts` decrypts after authorization and calls the connector. `packages/connectors/src/http.ts` inserts `Authorization: Bearer ...`. | Plaintext is a JS string. No explicit per-credential zeroization, millisecond lifetime bound or guarantee that HTTP/runtime copies disappear after the socket closes. Default connector is three preset GET requests, not arbitrary REST/OAuth or AWS SigV4. |
| Return boundary | Connector returns status/data, omits response headers, strips error response bodies and uses generic transport errors. MCP returns the daemon result verbatim. | Successful JSON/text bodies are not scanned or redacted for echoed keys or other secrets. "Only sanitized responses" and "no secret can ever reach agent memory" are not established. |

## Storage, key custody and local attackers

`packages/core/src/crypto.ts` uses AES-256-GCM, a random 12-byte IV and an authentication tag. This is authenticated encryption at rest, not proof of correct authorization or formal verification of MetaVault. New vaults use passphrase wrapping (`keywrap.ts`, scrypt by default, optional Argon2id); `key-session.ts` holds the unwrapped master key while unlocked. Passphrase mode defaults to 15-minute idle auto-lock and zero-fills the held key Buffer on lock/dispose. This does not erase all credential strings, runtime copies, swap or crash dumps. Legacy keychain/environment modes have different custody and do not auto-lock.

Same-user malware can keylog a passphrase, target an unlocked daemon or steal local authorization material. The design reduces selected exposure paths; it does not solve local infostealers or all prompt injection. Even a non-leaking credential can be abused through an authorized capability, and returned data can still be sensitive.

`packages/cli/src/cli.ts`, `runProgram`: `metavault run` decrypts non-card records into a child environment. This is an explicit exception to brokered custody. No product implementation was changed by this research update.

## ZK is not one interchangeable vault architecture

- **ZK proof:** a prover demonstrates a defined statement without revealing private witness data. Useful for selective disclosure and verifiable computation. Requires the right statement, trusted/authenticated inputs, a reviewed implementation and verification assumptions.
- **Client-side encrypted sync:** ciphertext stored by a server whose design does not give it decryption keys. Sometimes marketed as "zero knowledge", but not itself a ZK proof. X25519 key agreement and Argon2id password derivation have different jobs; listing algorithms does not establish a secure team-key lifecycle. MetaVault does not implement team sync.
- **MPC-TLS / zkTLS-style web provenance:** can authenticate selected data from a TLS exchange, without changing ordinary server authentication. TLSNotary uses MPC and a participating verifier, with an optional notary for delegated attestation. A transcript is not proof of every business fact or that settlement will remain final.

### Why keep the local broker?

Stripe's current authentication documentation supports API keys (Basic or bearer) and short-lived federation. A standalone ZK proof is not a replacement credential for this documented endpoint. Do not generalize this to every service, all future auth, or a requirement that the raw signing key itself always be transmitted: signing protocols such as SigV4 authenticate differently and need connector-specific support.

MetaVault's default presets are Stripe charges, GitHub user repositories and Cloudflare token verification. No 100% compatibility claim is warranted. No matched AES/injection versus proof benchmark was run. Existing held-out model latency measures warden assessment, not credential decryption or end-to-end API execution. Universal sub-millisecond and 500 ms-to-dozens-of-seconds comparisons are omitted. Circuit complexity, hardware, network, proof type and verification work change the tradeoff.

### Useful research directions, not shipped guarantees

1. BBS-style selective disclosure for issuer-signed claims. A fresh account/spend-limit proof needs issuer support or authenticated source data, not merely possession of an API key.
2. zkVM policy receipts bound to a reviewed program/image ID and authenticated inputs. A receipt proves the specified computation; binding it to the actual outbound request and remote outcome is additional work.
3. Client-side encrypted team sync with device enrollment, recovery, revocation and key rotation designed explicitly.
4. TLS-authenticated response provenance with stated disclosure, verifier/notary and protocol assumptions.

Near-term validation: successful-response secret-echo tests and hardening; review the CLI export exposure; memory/copy threat analysis; matched workflow benchmarks. None of these future items is claimed complete.

## Sources and scope

Primary implementation files above were read at the baseline commit. These establish current behavior, not independent security certification. Public references were fetched during this review; protocol documentation can evolve. No paid/cloud/local model calls or proof benchmarks were made.

| Source | Claims used | Confidence / limitation |
| --- | --- | --- |
| [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), 2007 | GCM is authenticated encryption with associated data. | Primary standard; does not certify this implementation. |
| [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | Minimize plaintext lifetime; memory protection is harder in garbage-collected languages; compromised process access matters. | Specialist security guidance, not a MetaVault audit. |
| [Stripe authentication](https://docs.stripe.com/api/authentication) | Key-based authentication, Basic/bearer, HTTPS, restricted keys and workload federation. | Current vendor API documentation; applies to this service. |
| [W3C BBS explainer](https://github.com/w3c/vc-di-bbs/blob/main/EXPLAINER.md) | Selective disclosure and unlinkable proofs of signed credentials. | Standards project explainer; not an integration guarantee. |
| [W3C December 2023 BBS working draft](https://www.w3.org/TR/2023/WD-vc-di-bbs-20231214/) | Issuer/holder/verifier roles and proof-of-signature model. | Historical working draft, explicitly experimental; not used as current production endorsement. |
| [RISC Zero Receipts 101](https://dev.risczero.com/api/zkvm/receipts) | Receipt journal/seal and verification against an expected image ID. | Primary implementation documentation; not proof of external-world truth. |
| [TLSNotary MPC-TLS](https://tlsnotary.org/docs/protocol/mpc-tls/) | Participating verifier, authenticated exchanged data, encrypted application data. | Primary protocol documentation; not proof of arbitrary state transitions. |
| [TLSNotary FAQ](https://tlsnotary.github.io/docs-mdbook/faq.html) | MPC, optional delegated notary, selective disclosure, oracle limitations. | Older documentation includes dated overhead estimates; no numerical performance claims adopted. |
