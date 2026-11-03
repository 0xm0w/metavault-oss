# Live warden eval: Muse Glimmer 30B quants (Windows desktop)

17-scenario live eval (`scripts\eval-windows.ps1 -Compare`), run by the owner on the
Windows desktop: Ryzen 7 5700G, RX 7600 XT, Ollama 0.34.4. Local testing is now stopped
and these are the final local numbers.

| quant | risk accuracy | approval accuracy | safety |
|---|---|---|---|
| Q4_K_M (`muse-glimmer:30b`, shipped default) | 58.8% | 82.4% | 100% |
| UD-Q3_K_XL | 11.8% | 88.2% | 100% |
| UD-IQ2_XXS | 11.8% | 88.2% | 100% |
| UD-IQ3_XXS | not run | not run | not run |

Reading: every quant kept the safety gate at 100%, so local AI works. Lower-capacity
quants lose risk accuracy (58.8% to 11.8%). The per-run text output (`eval-live-muse-glimmer-<stamp>.txt`)
and memory reports stayed on the desktop and are not committed here.

Not run: UD-IQ3_XXS, and the local 60-case held-out thesis head-to-head
(`scripts\thesis-windows.ps1`). The held-out warden numbers in `../VERIFICATION.md`
come from Muse Spark 1.3 via the Meta API.
