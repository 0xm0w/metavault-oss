# #70 model verification notes (Muse Glimmer Q4_K_M), checked 2026-11-03

> **Superseded 2026-11-03 (v0.1.0-alpha):** MetaVault no longer ships, bundles or downloads a
> local model, and there is no built-in engine or Settings download. The default warden is Muse
> Spark via the Meta API. Muse Glimmer stays the recommended model for a user's own local
> endpoint (Ollama or OpenAI-compatible, set in Settings). The model facts below are kept as
> the record behind that recommendation; the implementation notes describe the removed engine.

Status: implemented in #70 (see "Implementation status" below). Live Muse Glimmer eval: **no committed result** (Windows desktop run, `scripts/eval-windows.ps1`; see `eval-live-muse-glimmer-quants.md`).

## Model checks
- Exists, official Meta open weights, Apache 2.0: https://huggingface.co/meta-models/Muse-Glimmer-30B ,
  https://research.meta.ai/blog/introducing-muse-glimmer-open-agentic-model (Aug 10 2026),
  https://dev.meta.ai/docs/muse-glimmer
- Official Q4_K_M GGUF: https://huggingface.co/meta-models/Muse-Glimmer-30B-GGUF
  - Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf, 16,756,683,904 bytes,
    sha256 4cc57c0f51040a226e5a72cc47b7613f7772950e460a665f7083de89f183f60e
  - Others: KQuant-Dynamic-Q4_K_XL (19.7 GB), mmproj Q4_K_M (1.4 GB, image input), dflash Q4_K_M (1.6 GB, optional drafter)
  - No official IQ2_XXS build exists.
- Smaller third-party GGUF quants of the same weights (checked 2026-11-03 via the HF API,
  https://huggingface.co/unsloth/Muse-Glimmer-30B-GGUF , apache-2.0, base_model meta-models/Muse-Glimmer-30B):
  UD-Q3_K_XL 13,360,983,072 bytes; UD-IQ3_XXS 13,130,658,848; UD-Q2_K_XL 12,444,212,256;
  UD-IQ2_M 12,255,421,472; UD-IQ2_XS 11,513,104,416; UD-IQ2_XXS 10,746,373,152.
  Not adopted: IQ2_XXS is only allowed if a measured eval shows minimal loss, and no such eval result is committed.
  `scripts/eval-windows.ps1 -Compare` measures UD-Q3_K_XL and UD-IQ2_XXS against Q4_K_M.
- Ollama library tags (https://ollama.com/library/muse-glimmer/tags, 2026-11-03): 30b, 30b-q4_K_M, 30b-q8_0,
  30b-bf16, 30b-mxfp8, 30b-nvfp4, 30b-mlx(-bf16) and -dflash variants. No smaller-than-Q4 GGUF tag.
- Ollama tag: muse-glimmer:30b (= latest, 18 GB), muse-glimmer:30b-mlx. Needs Ollama >= 0.32.7.
  https://ollama.com/library/muse-glimmer , https://dev.meta.ai/docs/muse-glimmer/deploy
- Hackathon: https://dev.meta.ai/events/global-hackathon says "run Meta open weights models";
  Meta model list https://dev.meta.ai/docs/models names Muse Glimmer as the open-weight line.
  Official Rules are participant-only (not public), so qualification rests on that page plus issue #70.
- Smallest qualifying Meta LLM: Muse Glimmer 30B is the only small Muse open-weight model
  (Muse Spark Open is 816B-A42B). SAM / V-JEPA 2 are not text LLMs.

## Findings (from the handoff) and how they were resolved
- Hardware: no longer MetaVault's concern. The model runs on the user's own server, so its
  hardware needs are that server's (see the Ollama library page above).
- Glimmer always reasons (cannot be turned off): requests now carry the system prompt
  "Reasoning strength: low. Think briefly, then reply with the strict JSON object only." and the
  Ollama timeout is 120 s (local effort timeouts 60 / 120 / 240 s; cloud stays 10 / 30 / 60 s).
- The built-in engine and its Settings download were removed on 2026-11-03. Mocked-HTTP tests
  now prove a user's local endpoint (Ollama `/api/chat` or OpenAI-compatible `/chat/completions`)
  scores a request through `BrainFromSettings`, and that no reachable warden fails closed.
- Live eval cannot run on the agent box (15 GB RAM, no GPU): moved to `scripts/eval-windows.ps1`.
- Cloud path: default moved to the Meta Model API (`https://api.meta.ai/v1`, `muse-spark-1.3`,
  per https://dev.meta.ai/docs/models). `response_format: {type: "json_object"}` is accepted: both
  2026-11-03 held-out runs sent it (`json_mode=true` in the thesis-muse-spark-1.3-*.json headers) and
  got HTTP 200 on every call. 1 of 60 calls per run still hit the 2,048-token cap with no valid JSON.
- The name check is a case-insensitive PCRE search for the retired model-family name ("ollama" minus its leading "o"), with a `(?<!o)` lookbehind so "ollama" itself does not match. Expected result: zero matches repo-wide.
- CI runs Node 22. Measured 2026-11-03: Node 22.23.4 gives 521 passed / 3 skipped (CI run 41659945365), Node 24.22.1 gives 522 passed / 2 skipped. The difference is the argon2id keywrap test, which needs Node 24's `crypto.argon2`.
