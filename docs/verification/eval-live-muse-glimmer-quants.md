# Live warden eval: Muse Glimmer 30B quants (Windows desktop)

Status: **no committed result.**

The 17-scenario live eval (`scripts\eval-windows.ps1 -Compare`) is meant to run on the Windows
desktop for Q4_K_M (`muse-glimmer:30b`, shipped default), UD-IQ3_XXS, UD-Q3_K_XL and UD-IQ2_XXS.
Earlier copy quoted figures from a desktop run, but that run's raw output
(`eval-live-muse-glimmer-<stamp>.txt`) and its memory report were never committed, so those
figures were removed. Numbers are published here only once their raw output is in this directory.

| quant | risk accuracy | approval accuracy | safety | peak RAM |
|---|---|---|---|---|
| Q4_K_M (`muse-glimmer:30b`, shipped default) | not committed | not committed | not committed | not committed |
| UD-IQ3_XXS | not committed | not committed | not committed | not committed |
| UD-Q3_K_XL | not committed | not committed | not committed | not committed |
| UD-IQ2_XXS | not committed | not committed | not committed | not committed |

Also not run: the local 60-case held-out thesis head-to-head (`scripts\thesis-windows.ps1`).
The held-out warden numbers in `../VERIFICATION.md` come from Muse Spark 1.3 via the Meta API.
