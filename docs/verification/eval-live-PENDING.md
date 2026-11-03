# Live warden eval: pending

The previous `eval-live.txt` (recorded 2026-10-31 against the earlier local
model, under the old OpenVault name) was removed in #70; its numbers no
longer describe the shipped warden.

The live eval for **Muse Glimmer 30B Q4_K_M** (`muse-glimmer:30b`) has not
been run yet. It needs a machine with >= 32 GB RAM or a large GPU; the
agent box cannot run it. Run on Windows from the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\eval-windows.ps1 -Compare
```

`-Compare` runs Q4_K_M, UD-IQ3_XXS, UD-Q3_K_XL and UD-IQ2_XXS in turn. Use
`-Quant UD-IQ3_XXS` for one quant. UD-IQ3_XXS is
<https://huggingface.co/unsloth/Muse-Glimmer-30B-GGUF/blob/main/Muse-Glimmer-30B-UD-IQ3_XXS.gguf>
(tag `hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-IQ3_XXS`, 13,130,658,848 bytes).
The research run is `scripts\thesis-windows.ps1 -Compare` (or `-Quant ...`).

The script writes `docs/verification/eval-live-muse-glimmer-<yyyyMMdd-HHmm>.txt`
(accuracy, safety gate, wall time, model digest) and a memory report from
`scripts/ollama-mem.ps1`: peak working set of the whole Ollama process tree
(server plus child runner processes), peak `/api/ps` `size` and `size_vram`,
the `ollama ps` SIZE and PROCESSOR columns (GPU/CPU split), the system
memory delta, and peak NVIDIA memory use. The earlier report summed only
processes named `ollama*`, which missed the runner and gave an implausibly
low RAM figure.
Delete this file when that output is committed.
