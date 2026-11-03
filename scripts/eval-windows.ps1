<#
.SYNOPSIS
  Live brain eval for the on-device Meta Muse Glimmer 30B warden (issue #70).

.DESCRIPTION
  Self-contained: checks Ollama (>= 0.32.7, required by Muse Glimmer), starts
  `ollama serve` if the API is down, pulls the model, builds the repo, runs
  `run-eval.js --live` for each model while sampling the RAM of every ollama
  process, records the model digest, `ollama ps` (CPU/GPU split) and GPU info,
  then writes everything (UTF-8, no BOM) to
  docs/verification/eval-live-muse-glimmer-<yyyyMMdd-HHmm>.txt

  Default model: muse-glimmer:30b  (Ollama library tag = official Q4_K_M,
  https://ollama.com/library/muse-glimmer ; GGUF source
  https://huggingface.co/meta-models/Muse-Glimmer-30B-GGUF).

  -Compare adds smaller quants that were verified to exist on 2026-11-03 in
  https://huggingface.co/unsloth/Muse-Glimmer-30B-GGUF (apache-2.0, base_model
  meta-models/Muse-Glimmer-30B):
    UD-Q3_K_XL  (13,360,983,072 bytes)
    UD-IQ2_XXS  (10,746,373,152 bytes)
  pulled through Ollama's documented hf.co/{user}/{repo}:{quant} syntax.

  No secrets are read or printed. Nothing is uploaded.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\eval-windows.ps1
  powershell -ExecutionPolicy Bypass -File scripts\eval-windows.ps1 -Compare
#>
[CmdletBinding()]
param(
  [switch]$Compare,
  [string[]]$ExtraModels = @(),
  [switch]$SkipBuild,
  [switch]$SkipLiveTest,
  [string]$OllamaUrl = "http://127.0.0.1:11434",
  [int]$SampleMs = 250
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
$Stamp = Get-Date -Format "yyyyMMdd-HHmm"
$OutDir = Join-Path $RepoRoot "docs\verification"
$OutFile = Join-Path $OutDir "eval-live-muse-glimmer-$Stamp.txt"
$MinOllama = [version]"0.32.7"
$PrimaryModel = "muse-glimmer:30b"
$CompareModels = @(
  "hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-Q3_K_XL",
  "hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-IQ2_XXS"
)

$Log = New-Object System.Collections.Generic.List[string]
function Say([string]$line) { Write-Host $line; $Log.Add($line) | Out-Null }
function Save {
  if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($OutFile, (($Log -join "`n") + "`n"), $enc)
}
function Fail([string]$msg) { Say "FATAL: $msg"; Save; Write-Host "Partial output: $OutFile"; exit 1 }
function Fmt-GB([double]$bytes) { "{0:N2} GiB" -f ($bytes / 1GB) }

function Invoke-Native([string]$exe, [string[]]$argv, [string]$label) {
  # Runs a native command, captures stdout+stderr as UTF-8 text, returns @{Code; Text}
  $out = [System.IO.Path]::GetTempFileName()
  $err = [System.IO.Path]::GetTempFileName()
  $p = Start-Process -FilePath $exe -ArgumentList $argv -NoNewWindow -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
  $null = $p.Handle
  $p.WaitForExit()
  $text = ([System.IO.File]::ReadAllText($out, [System.Text.Encoding]::UTF8) +
           [System.IO.File]::ReadAllText($err, [System.Text.Encoding]::UTF8))
  Remove-Item $out, $err -ErrorAction SilentlyContinue
  return @{ Code = $p.ExitCode; Text = $text.TrimEnd() }
}

function Test-OllamaApi {
  try { return Invoke-RestMethod -Uri "$OllamaUrl/api/version" -TimeoutSec 3 } catch { return $null }
}

function Get-OllamaProcs { @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "ollama*" }) }

Say "MetaVault OSS live warden eval (issue #70)"
Say ("started:  {0} (local time, {1})" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), [System.TimeZoneInfo]::Local.Id)
Say ("repo:     {0}" -f $RepoRoot)
try {
  $branch = (& git rev-parse --abbrev-ref HEAD) 2>$null
  $commit = (& git rev-parse --short HEAD) 2>$null
  $dirty = (& git status --porcelain) 2>$null
  Say ("git:      {0} @ {1}{2}" -f $branch, $commit, $(if ($dirty) { " (worktree has local changes)" } else { "" }))
} catch { Say "git:      unavailable" }

# ---- Hardware ----------------------------------------------------------------
try {
  $cs = Get-CimInstance Win32_ComputerSystem
  $os = Get-CimInstance Win32_OperatingSystem
  $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
  Say ("os:       {0} {1}" -f $os.Caption, $os.Version)
  Say ("cpu:      {0}" -f $cpu.Name.Trim())
  Say ("ram:      {0} total physical" -f (Fmt-GB $cs.TotalPhysicalMemory))
  foreach ($g in Get-CimInstance Win32_VideoController) {
    Say ("gpu:      {0} (driver {1})" -f $g.Name, $g.DriverVersion)
  }
} catch { Say "hardware: CIM query unavailable ($($_.Exception.Message))" }
$nodeV = Invoke-Native "node" @("--version") "node"
Say ("node:     {0}" -f $nodeV.Text)

# ---- Ollama --------------------------------------------------------------------
$ollamaCmd = Get-Command ollama -ErrorAction SilentlyContinue
if (-not $ollamaCmd) { Fail "ollama is not on PATH. Install from https://ollama.com/download" }
$verText = (Invoke-Native "ollama" @("--version") "ollama").Text
$m = [regex]::Match($verText, "(\d+\.\d+\.\d+)")
if (-not $m.Success) { Fail "could not parse ollama version from: $verText" }
$ollamaVer = [version]$m.Groups[1].Value
Say ("ollama:   {0} (cli)" -f $ollamaVer)
if ($ollamaVer -lt $MinOllama) { Fail "Muse Glimmer needs Ollama >= $MinOllama (https://dev.meta.ai/docs/muse-glimmer/deploy); found $ollamaVer" }

$api = Test-OllamaApi
$startedServe = $null
if (-not $api) {
  Say "ollama API not reachable at $OllamaUrl - starting 'ollama serve'"
  $startedServe = Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden -PassThru
  for ($i = 0; $i -lt 60 -and -not $api; $i++) { Start-Sleep -Milliseconds 500; $api = Test-OllamaApi }
  if (-not $api) { Fail "ollama serve did not come up within 30 s" }
}
Say ("ollama:   {0} (server at {1})" -f $api.version, $OllamaUrl)
$env:METAVAULT_OLLAMA_URL = $OllamaUrl

# ---- Build ---------------------------------------------------------------------
if (-not $SkipBuild) {
  if (-not (Test-Path (Join-Path $RepoRoot "node_modules"))) {
    Say "node_modules missing - running npm ci"
    $r = Invoke-Native "cmd.exe" @("/c", "npm ci") "npm"
    if ($r.Code -ne 0) { Say $r.Text; Fail "npm ci failed" }
  }
  Say "building: npx tsc -p tsconfig.json --outDir dist"
  $r = Invoke-Native "cmd.exe" @("/c", "npx tsc -p tsconfig.json --outDir dist") "tsc"
  if ($r.Code -ne 0) { Say $r.Text; Fail "tsc build failed" }
}
$evalJs = Join-Path $RepoRoot "dist\packages\brain\eval\run-eval.js"
if (-not (Test-Path $evalJs)) { Fail "missing $evalJs (build first)" }
$scenarioFile = Join-Path $RepoRoot "packages\brain\eval\scenarios.json"
$ScenarioCount = @((Get-Content -Raw -Encoding UTF8 $scenarioFile | ConvertFrom-Json)).Count
Say ("scenarios: {0} ({1})" -f $ScenarioCount, "packages\brain\eval\scenarios.json")

# ---- Per-model run -------------------------------------------------------------
function Get-ModelInfo([string]$model) {
  try {
    $tags = Invoke-RestMethod -Uri "$OllamaUrl/api/tags" -TimeoutSec 10
    foreach ($t in $tags.models) {
      if ($t.name -eq $model -or $t.model -eq $model) {
        return ("digest {0}, size {1} ({2} bytes), quant {3}, params {4}" -f `
          $t.digest, (Fmt-GB $t.size), $t.size, $t.details.quantization_level, $t.details.parameter_size)
      }
    }
  } catch { }
  return "not found in /api/tags"
}

$script:PeakSum = 0.0; $script:PeakPrivate = 0.0; $script:Samples = 0; $script:PeakByPid = @{}
function Sample-Once {
  $sum = 0.0; $priv = 0.0
  foreach ($p in Get-OllamaProcs) {
    try {
      $p.Refresh()
      $sum += $p.WorkingSet64; $priv += $p.PrivateMemorySize64
      $key = "{0} (pid {1})" -f $p.ProcessName, $p.Id
      if (-not $script:PeakByPid.ContainsKey($key) -or $p.PeakWorkingSet64 -gt $script:PeakByPid[$key]) { $script:PeakByPid[$key] = $p.PeakWorkingSet64 }
    } catch { }
  }
  if ($sum -gt $script:PeakSum) { $script:PeakSum = $sum }
  if ($priv -gt $script:PeakPrivate) { $script:PeakPrivate = $priv }
  $script:Samples++
}

function Warm-Model([string]$model) {
  # Loads the model (Ollama: /api/generate with no prompt loads it into memory)
  # while sampling RAM, so the eval's 120 s per-request timeout is not spent on
  # the cold load. Returns load seconds, or -1 on failure.
  Add-Type -AssemblyName System.Net.Http
  $client = New-Object System.Net.Http.HttpClient
  $client.Timeout = [TimeSpan]::FromMinutes(15)
  $json = '{"model":"' + $model + '","keep_alive":"30m"}'
  $content = New-Object System.Net.Http.StringContent($json, [System.Text.Encoding]::UTF8, "application/json")
  $t0 = Get-Date
  $task = $client.PostAsync("$OllamaUrl/api/generate", $content)
  while (-not $task.IsCompleted) { Sample-Once; Start-Sleep -Milliseconds $SampleMs }
  $secs = ((Get-Date) - $t0).TotalSeconds
  if ($task.IsFaulted -or -not $task.Result.IsSuccessStatusCode) {
    $why = if ($task.IsFaulted) { $task.Exception.InnerException.Message } else { "HTTP " + [int]$task.Result.StatusCode + " " + $task.Result.Content.ReadAsStringAsync().Result }
    Say "warm-up FAILED: $why"
    return -1
  }
  return $secs
}

function Run-Model([string]$model) {
  Say ""
  Say ("=" * 78)
  Say "model: $model"
  Say ("=" * 78)
  Say "pull:  ollama pull $model"
  $pullStart = Get-Date
  $r = Invoke-Native "ollama" @("pull", $model) "pull"
  if ($r.Code -ne 0) {
    $tail = ($r.Text -split "`r?`n" | Select-Object -Last 5) -join " | "
    Say "pull FAILED (exit $($r.Code)): $tail"
    Say "result: NOT RUN"
    return
  }
  Say ("pull ok in {0:N0} s" -f ((Get-Date) - $pullStart).TotalSeconds)
  Say ("info:  {0}" -f (Get-ModelInfo $model))

  # Unload everything so this model's RAM is measured on its own.
  foreach ($loaded in @((Invoke-RestMethod -Uri "$OllamaUrl/api/ps" -TimeoutSec 10).models)) {
    if ($loaded) { $null = Invoke-Native "ollama" @("stop", $loaded.name) "stop" }
  }
  Start-Sleep -Seconds 2
  $baseline = 0.0
  foreach ($p in Get-OllamaProcs) { $baseline += $p.WorkingSet64 }
  Say ("ollama RAM before load (working set, all ollama processes): {0}" -f (Fmt-GB $baseline))

  $script:PeakSum = 0.0; $script:PeakPrivate = 0.0; $script:Samples = 0; $script:PeakByPid = @{}
  $load = Warm-Model $model
  if ($load -lt 0) { Say "result: NOT RUN (model failed to load)"; return }
  Say ("load:  model loaded in {0:N1} s (warm-up, not counted in eval wall time)" -f $load)

  $out = [System.IO.Path]::GetTempFileName()
  $err = [System.IO.Path]::GetTempFileName()
  $evalArgs = @("`"$evalJs`"", "--live", "--model", $model)
  Say ("run:   node dist\packages\brain\eval\run-eval.js --live --model {0}" -f $model)
  $t0 = Get-Date
  $proc = Start-Process -FilePath "node" -ArgumentList $evalArgs -NoNewWindow -PassThru `
            -RedirectStandardOutput $out -RedirectStandardError $err
  $null = $proc.Handle
  $psSnapshot = ""
  while (-not $proc.HasExited) {
    Sample-Once
    if ($psSnapshot -eq "" -and ((Get-Date) - $t0).TotalSeconds -gt 5) {
      $psSnapshot = (Invoke-Native "ollama" @("ps") "ps").Text
    }
    Start-Sleep -Milliseconds $SampleMs
  }
  $proc.WaitForExit()
  $wall = ((Get-Date) - $t0).TotalSeconds
  if ($psSnapshot -eq "") { $psSnapshot = (Invoke-Native "ollama" @("ps") "ps").Text }
  $evalText = [System.IO.File]::ReadAllText($out, [System.Text.Encoding]::UTF8).TrimEnd()
  $evalErr = [System.IO.File]::ReadAllText($err, [System.Text.Encoding]::UTF8).TrimEnd()
  Remove-Item $out, $err -ErrorAction SilentlyContinue

  Say ""
  Say $evalText
  if ($evalErr) { Say "stderr: $evalErr" }
  Say ""
  Say ("eval exit code:   {0}" -f $proc.ExitCode)
  Say ("wall time:        {0:N1} s for the scenario set, model already loaded (mean {1:N1} s per scenario)" -f $wall, ($wall / [math]::Max(1, $ScenarioCount)))
  Say ("peak ollama RAM:  {0} working set (sum of all ollama processes over load + eval, sampled every {1} ms, {2} samples)" -f (Fmt-GB $script:PeakSum), $SampleMs, $script:Samples)
  Say ("peak ollama RAM:  {0} private bytes (sum, sampled)" -f (Fmt-GB $script:PeakPrivate))
  foreach ($k in ($script:PeakByPid.Keys | Sort-Object)) {
    Say ("  OS-reported PeakWorkingSet64 {0}: {1}" -f $k, (Fmt-GB $script:PeakByPid[$k]))
  }
  Say "note: VRAM used by GPU-offloaded layers is not part of process RAM; see 'ollama ps' below."
  Say "ollama ps (during run):"
  foreach ($l in ($psSnapshot -split "`r?`n")) { Say "  $l" }
  $null = Invoke-Native "ollama" @("stop", $model) "stop"
}

$models = @($PrimaryModel)
if ($Compare) { $models += $CompareModels }
$models += $ExtraModels
foreach ($mdl in $models) { Run-Model $mdl; Save }

# ---- Optional gated live unit test -------------------------------------------
if (-not $SkipLiveTest) {
  Say ""
  Say ("=" * 78)
  Say "live unit test: METAVAULT_LIVE_OLLAMA=1 npx vitest run packages/brain/test/live-ollama.test.ts"
  $env:METAVAULT_LIVE_OLLAMA = "1"
  $r = Invoke-Native "cmd.exe" @("/c", "npx vitest run packages/brain/test/live-ollama.test.ts") "vitest"
  Remove-Item Env:METAVAULT_LIVE_OLLAMA -ErrorAction SilentlyContinue
  $keep = $r.Text -split "`r?`n" | Where-Object { $_ -match "(Test Files|Tests |Duration|FAIL|Error|passed|failed|skipped)" }
  foreach ($l in $keep) { Say "  $($l.Trim())" }
  Say ("live unit test exit code: {0}" -f $r.Code)
}

if ($startedServe) { Say ""; Say "leaving 'ollama serve' (pid $($startedServe.Id)) running; stop it with: Stop-Process -Id $($startedServe.Id)" }
Say ""
Say ("finished: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Save
Write-Host ""
Write-Host "Saved: $OutFile"
