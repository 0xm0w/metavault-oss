<#
.SYNOPSIS
  Live research benchmark: rules-only vault vs rules + Meta Muse Glimmer warden.

.DESCRIPTION
  Sibling of scripts\eval-windows.ps1. Checks Ollama (>= 0.32.7), starts
  `ollama serve` if needed, pulls the model, builds the repo, warms the model,
  then runs

    node dist\packages\brain\eval\run-thesis.js --live --set heldout ...

  which scores four arms on the same vault policy (always-ask, rules,
  warden, rules+warden) for high-risk recall, false-positive rate and
  decision latency. The benchmark writes
    docs\verification\thesis-live-heldout-<model>-<utc-stamp>.txt / .json
  and this script writes the machine context (Ollama version, model digest,
  `ollama ps` CPU/GPU split, hardware) to
    docs\verification\thesis-live-context-<yyyyMMdd-HHmm>.txt

  No secrets are read or printed. Nothing is uploaded.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\thesis-windows.ps1
  powershell -ExecutionPolicy Bypass -File scripts\thesis-windows.ps1 -Repeats 3
  powershell -ExecutionPolicy Bypass -File scripts\thesis-windows.ps1 -Model hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-Q3_K_XL
#>
[CmdletBinding()]
param(
  [string]$Model = "muse-glimmer:30b",
  [ValidateSet("fast", "standard", "deep")][string]$Effort = "standard",
  [ValidateSet("heldout", "dev")][string]$Set = "heldout",
  [int]$Repeats = 1,
  [switch]$SkipBuild,
  [string]$OllamaUrl = "http://127.0.0.1:11434"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
$Stamp = Get-Date -Format "yyyyMMdd-HHmm"
$OutDir = Join-Path $RepoRoot "docs\verification"
$CtxFile = Join-Path $OutDir "thesis-live-context-$Stamp.txt"
$MinOllama = [version]"0.32.7"

$Log = New-Object System.Collections.Generic.List[string]
function Say([string]$line) { Write-Host $line; $Log.Add($line) | Out-Null }
function Save {
  if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($CtxFile, (($Log -join "`n") + "`n"), $enc)
}
function Fail([string]$msg) { Say "FATAL: $msg"; Save; exit 1 }
function Fmt-GB([double]$bytes) { "{0:N2} GiB" -f ($bytes / 1GB) }
function Test-OllamaApi { try { Invoke-RestMethod -Uri "$OllamaUrl/api/version" -TimeoutSec 3 } catch { $null } }

Say "MetaVault OSS thesis benchmark (live)"
Say ("started:  {0} (local time, {1})" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), [System.TimeZoneInfo]::Local.Id)
try {
  $branch = (& git rev-parse --abbrev-ref HEAD) 2>$null
  $commit = (& git rev-parse --short HEAD) 2>$null
  $dirty = (& git status --porcelain --untracked-files=no) 2>$null
  Say ("git:      {0} @ {1}{2}" -f $branch, $commit, $(if ($dirty) { " (worktree has local changes)" } else { "" }))
} catch { Say "git:      unavailable" }
try {
  $cs = Get-CimInstance Win32_ComputerSystem
  $os = Get-CimInstance Win32_OperatingSystem
  $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
  Say ("os:       {0} {1}" -f $os.Caption, $os.Version)
  Say ("cpu:      {0}" -f $cpu.Name.Trim())
  Say ("ram:      {0} total physical" -f (Fmt-GB $cs.TotalPhysicalMemory))
  foreach ($g in Get-CimInstance Win32_VideoController) { Say ("gpu:      {0} (driver {1})" -f $g.Name, $g.DriverVersion) }
} catch { Say "hardware: CIM query unavailable" }
Say ("node:     {0}" -f (& node --version))

if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) { Fail "ollama is not on PATH. Install from https://ollama.com/download" }
# ollama --version may print a "could not connect" warning on stderr; do not let
# PowerShell 5.1 turn that into a terminating NativeCommandError.
$ErrorActionPreference = "Continue"
$verText = (& ollama --version 2>&1 | Out-String)
$ErrorActionPreference = "Stop"
$m = [regex]::Match($verText, "(\d+\.\d+\.\d+)")
if (-not $m.Success) { Fail "could not parse ollama version" }
$ollamaVer = [version]$m.Groups[1].Value
Say ("ollama:   {0}" -f $ollamaVer)
if ($ollamaVer -lt $MinOllama) { Fail "Muse Glimmer needs Ollama >= $MinOllama; found $ollamaVer" }
$api = Test-OllamaApi
if (-not $api) {
  Say "ollama API not reachable at $OllamaUrl - starting 'ollama serve'"
  $null = Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden -PassThru
  for ($i = 0; $i -lt 60 -and -not $api; $i++) { Start-Sleep -Milliseconds 500; $api = Test-OllamaApi }
  if (-not $api) { Fail "ollama serve did not come up within 30 s" }
}
$env:METAVAULT_OLLAMA_URL = $OllamaUrl

Say "pull:     ollama pull $Model"
& ollama pull $Model
if ($LASTEXITCODE -ne 0) { Fail "ollama pull $Model failed" }
try {
  foreach ($t in (Invoke-RestMethod -Uri "$OllamaUrl/api/tags" -TimeoutSec 10).models) {
    if ($t.name -eq $Model -or $t.model -eq $Model) {
      Say ("model:    {0} digest {1}, {2}, quant {3}, params {4}" -f $Model, $t.digest, (Fmt-GB $t.size), $t.details.quantization_level, $t.details.parameter_size)
    }
  }
} catch { Say "model:    /api/tags unavailable" }

if (-not $SkipBuild) {
  if (-not (Test-Path (Join-Path $RepoRoot "node_modules"))) {
    Say "node_modules missing - running npm ci"
    & cmd.exe /c "npm ci"
    if ($LASTEXITCODE -ne 0) { Fail "npm ci failed" }
  }
  Say "build:    npx tsc -p tsconfig.json --outDir dist"
  & cmd.exe /c "npx tsc -p tsconfig.json --outDir dist"
  if ($LASTEXITCODE -ne 0) { Fail "tsc build failed" }
}
$js = Join-Path $RepoRoot "dist\packages\brain\eval\run-thesis.js"
if (-not (Test-Path $js)) { Fail "missing $js (build first)" }

# Warm-up so the first scenario is not charged with the cold model load.
Say "warm-up:  loading $Model"
$t0 = Get-Date
try {
  $body = @{ model = $Model; keep_alive = "60m" } | ConvertTo-Json -Compress
  $null = Invoke-RestMethod -Uri "$OllamaUrl/api/generate" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 900
} catch { Fail "model failed to load: $($_.Exception.Message)" }
Say ("warm-up:  loaded in {0:N1} s (not counted in benchmark latency)" -f ((Get-Date) - $t0).TotalSeconds)
Say "ollama ps:"
foreach ($l in ((& ollama ps) -split "`r?`n")) { Say "  $l" }
Save

$argList = @($js, "--live", "--model", $Model, "--effort", $Effort, "--set", $Set, "--repeats", "$Repeats", "--out", $OutDir)
Say ("run:      node dist\packages\brain\eval\run-thesis.js --live --model {0} --effort {1} --set {2} --repeats {3} --out docs\verification" -f $Model, $Effort, $Set, $Repeats)
$t1 = Get-Date
& node @argList
$code = $LASTEXITCODE
Say ("benchmark exit code: {0}, wall time {1:N0} s" -f $code, ((Get-Date) - $t1).TotalSeconds)
Say "ollama ps (after run):"
foreach ($l in ((& ollama ps) -split "`r?`n")) { Say "  $l" }
Say ("finished: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Save
Write-Host ""
Write-Host "Context: $CtxFile"
Write-Host "Results: docs\verification\thesis-live-$Set-*.txt and .json"
exit $code
