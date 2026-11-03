# Research thesis: skeptic review

Scope: the claims on `site/research/index.html` (branch `feat/research-thesis`).
Every number below comes from a file in this repo or from a cited public source.
Anything not yet measured is marked **pending**.

## The thesis

> The vault is deliberately dumb and safe without any model. A Meta warden
> model catches high-risk agent requests that a strong rules-only engine
> misses, without sending every request to a human.

On the held-out head-to-head the warden was **Muse Spark 1.3 via the Meta API**:
rules alone caught 12/28 high-risk reads, rules + Muse Spark caught 28/28
(27/28 counting only real model decisions; one call per run hit the output cap
and fell back to a human). The only local Muse Glimmer evidence is the
17-scenario quant eval; Glimmer was not run on this held-out set.

The thesis has two halves:

- **The floor half** (the vault is safe without a model): measured, and it holds.
- **The uplift half** (the warden adds recall): measured with Muse Spark 1.3 via the Meta API (two runs, identical counts). Rules + Muse Spark: 28/28 recall at 9/28 FPR, the same FPR as rules alone. The local Muse Glimmer head-to-head is still **pending**.

## Claims, evidence, confidence

| # | Claim | Evidence | Confidence |
|---|-------|----------|------------|
| 1 | The policy floor (writes ask, hard ceilings, no cross-resource, null decision goes to a human) catches all four held-out floor cases with no model at all. | `docs/verification/thesis-rules-only-heldout-*.txt`: policy-floor 4/4 for every arm. Code: `packages/core/src/policy.ts`. | High. This is deterministic code and the cases are simple by design. |
| 2 | A strong rules engine, frozen before the test set was written, catches only 12/28 (42.9%) held-out high-risk reads. | Same file. Rules committed in `793371d` (2026-11-03 14:37 PHT); held-out set committed later in `702bb2b`. Pinned by `packages/brain/test/thesis.test.ts`. | Medium. The number is real, but see weak spots 1–3. |
| 3 | Rules are brittle to wording: 10/10 recall and 0/10 FPR on the dev set, 12/28 on held-out, and 6/22 on the paraphrased subset. | `thesis-rules-only-dev-*.txt` and `thesis-rules-only-heldout-*.txt`. | Medium. The gap is in the expected direction, but I wrote both sets. |
| 4 | Rules flag 9/20 (45%) of benign requests that use alarming words, and 0/8 plain benign requests. | Same files. | Medium. The hard-benign set was built to contain trigger words, so this FPR is an upper-end estimate. |
| 5 | "Ask every time" catches 28/28 but prompts on 28/28 benign requests. Warning fatigue is real: over 25 million warning impressions, and 70.2% click-through on Chrome SSL warnings. | Harness output. Akhawe & Felt, USENIX Security 2013. | High for the measurement. The 2013 browser-warning setting differs from approval prompts, so the analogy is moderate. |
| 6 | Rules + warden raises recall over rules alone at an acceptable FPR. | Muse Spark 1.3 via the Meta API, two runs (`docs/verification/thesis-muse-spark-1.3-heldout-2026-11-03T08-*`): rules + Muse Spark 28/28 recall (27/28 counting only real model decisions), FPR 9/28, same as rules alone. Muse Spark alone: 26/28, FPR 0/28. Local Muse Glimmer on this set: **pending** (`scripts/thesis-windows.ps1`). | Medium for Muse Spark (small n, same author). Unknown for local Glimmer. |
| 7 | The warden decides before the request reaches a human. | Architecture: the warden runs before approval. Rules take a median 6.8 µs (p95 21.3 µs) on the box. Muse Spark 1.3 via the Meta API takes a median 8.2–8.9 s (p95 14.8–17.3 s) across the two runs. Local Glimmer latency on this set is **pending**. | We do **not** claim "faster than a human". Human approval latency wasn't measured. |
| 8 | Infostealers target browser autofill and saved cards. | Microsoft on Lumma (394,000+ PCs, Mar 16 – May 16 2025). DOJ RedLine complaint ("autofill fields", "credit card numbers"). Google Security Blog on DPAPI. | High. These are primary sources. |
| 9 | Plaintext copies of card data or credentials enabled real losses. | British Airways 2018: Bird & Bird summary of the ICO penalty ("stored in plaintext"); CNBC (244,000 card number + CVV); Snowflake / UNC5537 (Mandiant, infostealer credentials since 2020, no MFA). | High. |
| 10 | Agents have already been turned against their users' secrets and data. | Nx s1ngularity postmortem and Wiz; AWS-2025-015 (Amazon Q); The Register (Replit); Invariant Labs (GitHub MCP). | High for the facts. The mapping to MetaVault layers is my analysis. |

## Weak spots a skeptic should press on

1. **Author bias.** The same author wrote the rules, the dev set and the held-out set. Freezing the rules first and committing them before the held-out set limits tuning, but the author still knew roughly which phrasings rules catch. Independent cases would be better, for example a second bot or person writing the held-out set blind, or sampling cases from AgentDojo/InjecAgent tasks.
2. **Surface mix.** 22 of 28 held-out high-risk cases are paraphrased on purpose. That is the population the thesis is about, but it makes the 42.9% rules recall lower than a lexical-heavy mix would give. The per-surface numbers are published so this is visible.
3. **Rules can be strengthened.** A determined rules author could add patterns for "near-factory", "saved logins" and so on. The counter-argument is the dev/held-out gap: each new phrasing needs a new rule. That is an argument, not a measurement.
4. **Small n.** 28 / 4 / 20 / 8 cases. One case moves a rate by 3.6 points. Results should be read as directional.
5. **Nondeterminism.** Ollama is called without a fixed temperature, so live runs vary. The Windows script supports `-Repeats N`, and repeats should be reported.
6. **LLM judges are fallible.** In R-Judge (arXiv:2401.10019), most prompted models were near random at agent-safety judgement. "The Attacker Moves Second" (arXiv:2510.09023) shows adaptive attacks break most published defenses. The warden is therefore a second layer behind a deterministic floor, and should not be read as a guarantee.
7. **Failure crediting.** A warden error makes the human decide, which counts as "caught" for safety. The report also prints recall counting only real model decisions, so a crashing model can't look good.
8. **Licensing.** InjecAgent has no license file, so none of its text was copied; only attack categories inspired cases. AgentDojo is MIT.

## Product claims that do not match the code (fixed in copy)

- **Encryption claims.** Earlier copy described the vault with a privacy-proof label the code doesn't support; it has been removed. What the code does: AES-256-GCM at rest (`packages/core/src/crypto.ts`), a master key wrapped by a passphrase-derived key (`packages/core/src/keywrap.ts`, scrypt by default, Argon2id opt-in), auto-lock (`packages/core/src/key-session.ts`), the policy gate, and a brokered call that never hands the agent the value. The daemon holds the key while unlocked and decrypts secrets itself.
- **Card storage.** A payment-card credential type now exists (`packages/core/src/card.ts`): Luhn-checked number, name, expiry and CVV, sealed as one AES-256-GCM ciphertext. Agents and the app see only the brand, last 4 and a masked number. Every card use needs a human approval, can't be standing-approved, and the daemon refuses to execute a card grant because no payment connector exists. There's still no browser autofill or checkout.
- **Same-user malware.** New vaults keep the master key in `metavault.key.json`, wrapped with the user's passphrase, and the daemon starts locked and auto-locks after 15 idle minutes. Legacy vaults keep it unwrapped in the OS keychain (macOS `security`, Linux `secret-tool`, Windows PasswordVault) until `metavault key protect` runs; `METAVAULT_MASTER_KEY` is ignored unless `METAVAULT_ALLOW_ENV_MASTER_KEY=1`. An infostealer running as the user can still keylog the passphrase or read daemon memory while it's unlocked. MetaVault removes plaintext copies (agent context, `.env`, logs) and shortens how long the key is exposed. It does not defeat same-user malware. See `SECURITY.md#master-key-protection`.
- **Magecart.** A human typing a card into a compromised page (the British Airways skimming vector) is out of scope.
- **Post-quantum.** `packages/core/src/pqc.ts` (ML-KEM-768 + X25519) is implemented and tested, but no non-test source imports it, so credential storage doesn't use it.

## Reproduce

```
npx tsc -p tsconfig.json --outDir dist
node dist/packages/brain/eval/run-thesis.js --rules-only --set heldout --out docs/verification
node dist/packages/brain/eval/run-thesis.js --oracle     --set heldout --out docs/verification   # harness check only
powershell -ExecutionPolicy Bypass -File scripts\thesis-windows.ps1 -Repeats 3                  # live, Windows + Ollama
```
