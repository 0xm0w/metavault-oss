# #70 model verification notes (Muse Glimmer Q4_K_M), checked 2026-11-03

Status: handed off mid-task. No app code changed yet on this branch.

## Model checks
- Exists, official Meta open weights, Apache 2.0: https://huggingface.co/meta-models/Muse-Glimmer-30B ,
  https://research.meta.ai/blog/introducing-muse-glimmer-open-agentic-model (Aug 10 2026),
  https://dev.meta.ai/docs/muse-glimmer
- Official Q4_K_M GGUF: https://huggingface.co/meta-models/Muse-Glimmer-30B-GGUF
  - Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf, 16,756,683,904 bytes,
    sha256 4cc57c0f51040a226e5a72cc47b7613f7772950e460a665f7083de89f183f60e
  - Others: KQuant-Dynamic-Q4_K_XL (19.7 GB), mmproj Q4_K_M (1.4 GB, image input), dflash Q4_K_M (1.6 GB, optional drafter)
  - No official IQ2_XXS build exists.
- Ollama tag: muse-glimmer:30b (= latest, 18 GB), muse-glimmer:30b-mlx. Needs Ollama >= 0.32.7.
  https://ollama.com/library/muse-glimmer , https://dev.meta.ai/docs/muse-glimmer/deploy
- Hackathon: https://dev.meta.ai/events/global-hackathon says "run Meta open weights models";
  Meta model list https://dev.meta.ai/docs/models names Muse Glimmer as the open-weight line.
  Official Rules are participant-only (not public), so qualification rests on that page plus issue #70.
- Smallest qualifying Meta LLM: Muse Glimmer 30B is the only small Muse open-weight model
  (Muse Spark Open is 816B-A42B). SAM / V-JEPA 2 are not text LLMs.

## Findings for the implementer
- Hardware: Q4_K_M needs ~17 GB (24 GB VRAM target) vs ~0.7-2 GB for the old Llama builds.
- Glimmer always reasons (cannot be turned off); use "Reasoning strength: low" and raise the 10 s Ollama timeout.
- packages/app built-in engine expects ONNX/WebGPU; no ONNX Glimmer build exists. Downloader writes stub files,
  and setBuiltinInferenceHandler is never called in app code (built-in engine is not wired).
- Live eval cannot run on the agent box (15 GB RAM, no GPU). Needs a >= 24 GB VRAM or >= 32 GB RAM machine.
- Cloud path (Meta API) still defaults to Llama (api.llama.com, llama-3.3-70b-instruct, Llama 4 Maverick in tests). Outside the fallback path but the same eligibility risk.
- `rg -i llama` also matches "ollama"; define the check as `rg -iP '(?<!o)llama'`.
- Local CI note: better-sqlite3 has no Node 24 prebuild here; use Node 22 (as CI does).
