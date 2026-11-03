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

The script writes `docs/verification/eval-live-muse-glimmer-<yyyyMMdd-HHmm>.txt`
(accuracy, safety gate, wall time, Ollama peak RAM, model digest, GPU split).
Delete this file when that output is committed.
