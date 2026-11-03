# Clean-install smoke test for the MetaVault OSS Windows installer.
# Runs in CI on windows-latest (see .github/workflows/windows-installer.yml).
# Silent install to a temp folder, check files/shortcuts/registry/PATH,
# launch the app, poll the bundled daemon's /health, check first-run state,
# silent uninstall, then check everything the installer added is gone.
# No API keys are set, so nothing here calls the Meta API.
param(
  [Parameter(Mandatory = $true)][string]$InstallerDir,
  [Parameter(Mandatory = $true)][string]$LogPath,
  [int]$Port = 7077,
  [int]$HealthTimeoutSec = 90
)

$ErrorActionPreference = "Stop"
$script:failures = 0
New-Item -ItemType File -Force -Path $LogPath | Out-Null

function Log([string]$msg) {
  $line = "[$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))] $msg"
  Write-Host $line
  Add-Content -Path $LogPath -Value $line
}
function Check([bool]$ok, [string]$what) {
  if ($ok) { Log "PASS  $what" } else { Log "FAIL  $what"; $script:failures++ }
}
function UninstallEntry {
  Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty $_.PSPath } |
    Where-Object { $_.DisplayName -like "MetaVault OSS*" }
}
function UserPath {
  [string](Get-Item "HKCU:\Environment").GetValue("Path", "", "DoNotExpandEnvironmentNames")
}

foreach ($k in @("META_API_KEY", "METAVAULT_META_API_KEY", "OPENCODE_API_KEY")) {
  Remove-Item "Env:$k" -ErrorAction SilentlyContinue
}

$installer = Get-ChildItem $InstallerDir -Filter "*.exe" -File | Select-Object -First 1
if (-not $installer) { throw "No installer found in $InstallerDir" }
$installDir = Join-Path $env:RUNNER_TEMP "MVInstall"
$dataDir = Join-Path $env:APPDATA "MetaVault OSS"
$desktopLnk = Join-Path ([Environment]::GetFolderPath("Desktop")) "MetaVault OSS.lnk"
$startLnk = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\MetaVault OSS.lnk"
$binDir = Join-Path $installDir "bin"
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

Log "Windows: $([Environment]::OSVersion.VersionString)"
Log "Installer: $($installer.Name) ($($installer.Length) bytes)"
Log "SHA256: $((Get-FileHash $installer.FullName -Algorithm SHA256).Hash.ToLowerInvariant())"
Check (-not (Test-Path $installDir)) "install folder does not exist before install"
Check (-not (Test-Path $dataDir)) "no vault data before install (clean machine)"

# --- install -----------------------------------------------------------
Log "Installing: $($installer.Name) /S /D=$installDir"
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $installer.FullName -ArgumentList "/S", "/D=$installDir" -Wait -PassThru
Log "Installer exit code $($p.ExitCode) after $([int]$sw.Elapsed.TotalSeconds) s"
Check ($p.ExitCode -eq 0) "installer exit code is 0"

$exe = Join-Path $installDir "MetaVault OSS.exe"
$uninstaller = Join-Path $installDir "Uninstall MetaVault OSS.exe"
foreach ($f in @(
    $exe,
    $uninstaller,
    (Join-Path $installDir "resources\app.asar"),
    (Join-Path $installDir "resources\vaultd\vaultd.cjs"),
    (Join-Path $installDir "resources\vaultd\metavault.cjs"),
    (Join-Path $installDir "resources\vaultd\mcp.cjs"),
    (Join-Path $installDir "resources\vaultd\native\better-sqlite3\prebuilds\win32-x64.node"),
    (Join-Path $binDir "metavault.cmd"),
    (Join-Path $binDir "vaultd.cmd"),
    (Join-Path $binDir "metavault.ps1"))) {
  Check (Test-Path $f) "installed: $($f.Substring($installDir.Length + 1))"
}
$models = Get-ChildItem $installDir -Recurse -File -Include "*.gguf", "*.safetensors", "*.onnx", "*.ggml" -ErrorAction SilentlyContinue
Check (-not $models) "no model files in the install folder"
$sizeMb = [math]::Round(((Get-ChildItem $installDir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB), 1)
Log "Install folder size: $sizeMb MB"
Check (Test-Path $desktopLnk) "desktop shortcut exists"
Check (Test-Path $startLnk) "Start menu shortcut exists"
$entry = UninstallEntry
Check ($null -ne $entry) "Apps & features (Uninstall) registry entry exists"
if ($entry) { Log "Registry: DisplayName='$($entry.DisplayName)' DisplayVersion='$($entry.DisplayVersion)'" }
Check ((UserPath) -split ";" -contains $binDir) "user PATH contains $binDir"
Check ($null -ne (Get-ItemProperty $runKey -Name "MetaVault OSS" -ErrorAction SilentlyContinue)) "start-at-login Run entry exists"

# --- launch + health ---------------------------------------------------
Log "Launching: $exe"
$app = Start-Process -FilePath $exe -PassThru
$health = $null
$deadline = (Get-Date).AddSeconds($HealthTimeoutSec)
$sw.Restart()
while ((Get-Date) -lt $deadline) {
  try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 2
    if ($health.service -eq "vaultd") { break }
  } catch { }
  Start-Sleep -Milliseconds 500
}
Log "GET /health -> $($health | ConvertTo-Json -Compress) after $([int]$sw.Elapsed.TotalSeconds) s"
Check ($health.status -eq "ok" -and $health.service -eq "vaultd") "bundled daemon answers /health"

$tokenFile = Join-Path $dataDir "metavault.token"
Check (Test-Path (Join-Path $dataDir "metavault.db")) "vault DB created in %APPDATA%\MetaVault OSS"
Check (Test-Path $tokenFile) "daemon token file created"
if (Test-Path $tokenFile) {
  $token = (Get-Content $tokenFile -Raw).Trim()
  try {
    $status = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/key/status" -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 5
    Log "GET /key/status -> $($status | ConvertTo-Json -Compress)"
    Check ($status.mode -eq "uninitialized") "fresh install waits for first-run passphrase setup"
  } catch {
    Log "GET /key/status failed: $($_.Exception.Message)"
    Check $false "GET /key/status"
  }
  $token = $null
}
$procs = Get-Process -Name "MetaVault OSS" -ErrorAction SilentlyContinue
Log "MetaVault OSS processes running: $(@($procs).Count)"
Check (@($procs).Count -ge 2) "app UI and bundled daemon processes are running"
$vaultdLog = Join-Path $dataDir "vaultd.log"
if (Test-Path $vaultdLog) { Log "vaultd.log: $((Get-Content $vaultdLog -Raw) -replace '\s+', ' ')" }

# --- stop + uninstall --------------------------------------------------
Log "Stopping app"
Get-Process -Name "MetaVault OSS" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
Check (-not (Get-Process -Name "MetaVault OSS" -ErrorAction SilentlyContinue)) "app processes stopped"

Log "Uninstalling: `"$uninstaller`" /S"
$sw.Restart()
$u = Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -PassThru
Log "Uninstaller exit code $($u.ExitCode)"
Check ($u.ExitCode -eq 0) "uninstaller exit code is 0"
# The NSIS uninstaller re-launches itself from %TEMP%; wait for the folder.
$deadline = (Get-Date).AddSeconds(60)
while ((Test-Path $installDir) -and ((Get-Date) -lt $deadline)) { Start-Sleep -Milliseconds 500 }
Log "Uninstall finished after $([int]$sw.Elapsed.TotalSeconds) s"
if (Test-Path $installDir) {
  Log "Left behind: $((Get-ChildItem $installDir -Recurse | ForEach-Object FullName) -join '; ')"
}
Check (-not (Test-Path $installDir)) "install folder removed"
Check (-not (Test-Path $desktopLnk)) "desktop shortcut removed"
Check (-not (Test-Path $startLnk)) "Start menu shortcut removed"
Check ($null -eq (UninstallEntry)) "Uninstall registry entry removed"
Check (-not ((UserPath) -split ";" -contains $binDir)) "user PATH entry removed"
Check ($null -eq (Get-ItemProperty $runKey -Name "MetaVault OSS" -ErrorAction SilentlyContinue)) "Run entry removed"
# Silent uninstall answers "No" to "delete vault data", by design.
Check (Test-Path (Join-Path $dataDir "metavault.db")) "vault data kept on silent uninstall (by design)"
Remove-Item $dataDir -Recurse -Force -ErrorAction SilentlyContinue

Log "Result: $(if ($script:failures -eq 0) { 'PASS' } else { "FAIL ($script:failures checks failed)" })"
if ($script:failures -ne 0) { exit 1 }
