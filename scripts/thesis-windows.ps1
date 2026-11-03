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

  Memory is measured with scripts\ollama-mem.ps1 (whole ollama process tree
  including child runners, system-wide used RAM, /api/ps size and size_vram,
  nvidia-smi when present, and the `ollama ps` SIZE and PROCESSOR columns).

  -Quant selects a quant by name (overrides -Model). -Compare runs the
  benchmark once per quant (Q4_K_M, UD-IQ3_XXS, UD-Q3_K_XL, UD-IQ2_XXS),
  each in its own child PowerShell so every run gets its own context file.
  UD-IQ3_XXS: hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-IQ3_XXS, 13,130,658,848
  bytes per the Hugging Face tree API (checked 2026-11-03),
  https://huggingface.co/unsloth/Muse-Glimmer-30B-GGUF/blob/main/Muse-Glimmer-30B-UD-IQ3_XXS.gguf

  No secrets are read or printed. Nothing is uploaded.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\thesis-windows.ps1
  powershell -ExecutionPolicy Bypass -File scripts\thesis-windows.ps1 -Repeats 3
  powershell -ExecutionPolicy Bypass -File scripts\thesis-windows.ps1 -Model hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-Q3_K_XL
  powershell -ExecutionPolicy Bypass -File scripts\thesis-windows.ps1 -Quant UD-IQ3_XXS
  powershell -ExecutionPolicy Bypass -File scripts\thesis-windows.ps1 -Compare
#>
[CmdletBinding()]
param(
  [string]$Model = "muse-glimmer:30b",
  [ValidateSet("", "Q4_K_M", "UD-IQ3_XXS", "UD-Q3_K_XL", "UD-IQ2_XXS")][string]$Quant = "",
  [switch]$Compare,
  [int]$SampleMs = 500,
  [ValidateSet("fast", "standard", "deep")][string]$Effort = "standard",
  [ValidateSet("heldout", "dev")][string]$Set = "heldout",
  [int]$Repeats = 1,
  [switch]$SkipBuild,
  [string]$OllamaUrl = "http://127.0.0.1:11434"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$QuantTags = [ordered]@{
  "Q4_K_M"     = "muse-glimmer:30b"
  "UD-IQ3_XXS" = "hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-IQ3_XXS"
  "UD-Q3_K_XL" = "hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-Q3_K_XL"
  "UD-IQ2_XXS" = "hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-IQ2_XXS"
}
if ($Quant -ne "") { $Model = $QuantTags[$Quant] }

if ($Compare) {
  $worst = 0; $first = $true
  foreach ($q in $QuantTags.Keys) {
    $childArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath,
      "-Quant", $q, "-Effort", $Effort, "-Set", $Set, "-Repeats", "$Repeats", "-OllamaUrl", $OllamaUrl, "-SampleMs", "$SampleMs")
    if ($SkipBuild -or -not $first) { $childArgs += "-SkipBuild" }
    Write-Host ("==== -Compare: {0} ({1}) ====" -f $q, $QuantTags[$q])
    & powershell @childArgs
    if ($LASTEXITCODE -ne 0) { Write-Host ("{0} exited {1}" -f $q, $LASTEXITCODE); $worst = [math]::Max($worst, [int]$LASTEXITCODE) }
    # Free the model before the next quant so memory is measured on its own.
    try { $ErrorActionPreference = "Continue"; & ollama stop $QuantTags[$q] 2>$null | Out-Null } catch { }
    $first = $false
  }
  exit $worst
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "ollama-mem.ps1")
Set-Location $RepoRoot
$Stamp = Get-Date -Format "yyyyMMdd-HHmm"
$OutDir = Join-Path $RepoRoot "docs\verification"
$ModelSlug = ($Model -replace "[^A-Za-z0-9._-]+", "-")
$CtxFile = Join-Path $OutDir "thesis-live-context-$ModelSlug-$Stamp.txt"
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
$Mem = New-MemTracker $OllamaUrl
Update-MemTracker $Mem
Say ("before load: ollama tree {0} working set over {1} process(es); system used RAM {2}" -f (Fmt-GB $Mem.PeakWs), $Mem.Tree.Count, (Fmt-GB $Mem.SysBaseline))
Say "warm-up:  loading $Model"
$t0 = Get-Date
Add-Type -AssemblyName System.Net.Http
$client = New-Object System.Net.Http.HttpClient
$client.Timeout = [TimeSpan]::FromMinutes(15)
$body = @{ model = $Model; keep_alive = "60m" } | ConvertTo-Json -Compress
$content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
$task = $client.PostAsync("$OllamaUrl/api/generate", $content)
while (-not $task.IsCompleted) { Update-MemTracker $Mem; Start-Sleep -Milliseconds $SampleMs }
if ($task.IsFaulted -or -not $task.Result.IsSuccessStatusCode) {
  $why = if ($task.IsFaulted) { $task.Exception.InnerException.Message } else { "HTTP " + [int]$task.Result.StatusCode }
  Fail "model failed to load: $why"
}
Say ("warm-up:  loaded in {0:N1} s (not counted in benchmark latency)" -f ((Get-Date) - $t0).TotalSeconds)
$psLoaded = (& ollama ps | Out-String)
Say "ollama ps:"
foreach ($l in ($psLoaded -split "`r?`n")) { Say "  $l" }
foreach ($l in (Get-OllamaApiPs $OllamaUrl).Lines) { Say "api/ps:   $l" }
Save

$argList = @($js, "--live", "--model", $Model, "--effort", $Effort, "--set", $Set, "--repeats", "$Repeats", "--out", $OutDir)
Say ("run:      node dist\packages\brain\eval\run-thesis.js --live --model {0} --effort {1} --set {2} --repeats {3} --out docs\verification" -f $Model, $Effort, $Set, $Repeats)
$t1 = Get-Date
$quoted = @($argList | ForEach-Object { if ("$_" -match '\s') { '"' + $_ + '"' } else { "$_" } })
$proc = Start-Process -FilePath "node" -ArgumentList $quoted -NoNewWindow -PassThru
$null = $proc.Handle
while (-not $proc.HasExited) { Update-MemTracker $Mem; Start-Sleep -Milliseconds $SampleMs }
$proc.WaitForExit()
$code = $proc.ExitCode
Say ("benchmark exit code: {0}, wall time {1:N0} s" -f $code, ((Get-Date) - $t1).TotalSeconds)
$psAfter = (& ollama ps | Out-String)
Say "ollama ps (after run):"
foreach ($l in ($psAfter -split "`r?`n")) { Say "  $l" }
Write-MemReport $Mem $psLoaded $SampleMs ${function:Say}
Say ("finished: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Save
Write-Host ""
Write-Host "Context: $CtxFile"
Write-Host "Results: docs\verification\thesis-live-$Set-*.txt and .json"
exit $code
