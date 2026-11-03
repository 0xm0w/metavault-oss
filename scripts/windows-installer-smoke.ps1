# Clean-install smoke test for the MetaVault OSS Windows installer.
# Runs in CI on windows-latest (see .github/workflows/windows-installer.yml).
#
# Covers the full data-preservation contract with a REAL encrypted vault:
#   1. silent install, files/shortcuts/registry/PATH, launch, /health
#   2. first-run passphrase setup + a stored credential (real encrypted DB)
#   3. silent uninstall -> vault data (db, key file, token) must survive
#   4. reinstall -> vault must come back locked, wrong passphrase rejected,
#      right passphrase unlocks and the credential is still there
#   5. install-over-install (the update path, NSIS --updated flag) must
#      never touch vault data
#   6. final silent uninstall -> everything the installer added is gone,
#      vault data still kept
# No API keys are set, so nothing here calls the Meta API. The vault
# created here is synthetic CI data and is deleted at the end.
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
$exe = Join-Path $installDir "MetaVault OSS.exe"
$uninstaller = Join-Path $installDir "Uninstall MetaVault OSS.exe"
$dbFile = Join-Path $dataDir "metavault.db"
$keyFile = Join-Path $dataDir "metavault.key.json"
$tokenFile = Join-Path $dataDir "metavault.token"

$smokePassphrase = "smoke-ci-passphrase-7f3a"
$smokeAlias = "smoke-ci-credential"
$smokeSecret = "smoke-secret-value-9c81"

Log "Windows: $([Environment]::OSVersion.VersionString)"
Log "Installer: $($installer.Name) ($($installer.Length) bytes)"
Log "SHA256: $((Get-FileHash $installer.FullName -Algorithm SHA256).Hash.ToLowerInvariant())"
Check (-not (Test-Path $installDir)) "install folder does not exist before install"
Check (-not (Test-Path $dataDir)) "no vault data before install (clean machine)"

function Install-App([string]$what) {
  Log "Installing ($what): $($installer.Name) /S /D=$installDir"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = Start-Process -FilePath $installer.FullName -ArgumentList "/S", "/D=$installDir" -Wait -PassThru
  Log "Installer exit code $($p.ExitCode) after $([int]$sw.Elapsed.TotalSeconds) s"
  Check ($p.ExitCode -eq 0) "installer exit code is 0 ($what)"
  # The NSIS uninstaller re-launches itself from %TEMP% on upgrades; wait
  # for the install folder to settle.
  Start-Sleep -Seconds 3
}

function Stop-App {
  Log "Stopping app"
  Get-Process -Name "MetaVault OSS" -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Seconds 2
  Check (-not (Get-Process -Name "MetaVault OSS" -ErrorAction SilentlyContinue)) "app processes stopped"
}

function Launch-App-Wait-Health([string]$what) {
  Log "Launching ($what): $exe"
  Start-Process -FilePath $exe | Out-Null
  $health = $null
  $deadline = (Get-Date).AddSeconds($HealthTimeoutSec)
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ((Get-Date) -lt $deadline) {
    try {
      $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 2
      if ($health.service -eq "vaultd") { break }
    } catch { }
    Start-Sleep -Milliseconds 500
  }
  Log "GET /health -> $($health | ConvertTo-Json -Compress) after $([int]$sw.Elapsed.TotalSeconds) s"
  Check ($health.status -eq "ok" -and $health.service -eq "vaultd") "bundled daemon answers /health ($what)"
}

function Read-DaemonToken {
  Check (Test-Path $tokenFile) "daemon token file exists"
  if (-not (Test-Path $tokenFile)) { return $null }
  return (Get-Content $tokenFile -Raw).Trim()
}

function Invoke-Daemon([string]$method, [string]$path, $body = $null) {
  $token = Read-DaemonToken
  if ($null -eq $token) { return $null }
  $headers = @{ Authorization = "Bearer $token" }
  try {
    if ($null -ne $body) {
      $json = $body | ConvertTo-Json -Compress
      return Invoke-RestMethod -Uri "http://127.0.0.1:$Port$path" -Method $method -Headers $headers -ContentType "application/json" -Body $json -TimeoutSec 10
    }
    return Invoke-RestMethod -Uri "http://127.0.0.1:$Port$path" -Method $method -Headers $headers -TimeoutSec 10
  } catch {
    $resp = $_.Exception.Response
    if ($null -ne $resp) { return @{ __httpStatus = [int]$resp.StatusCode } }
    Log "daemon $method $path failed: $($_.Exception.Message)"
    return $null
  } finally {
    $token = $null
  }
}

function Check-Installed-Layout {
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
  Check (Test-Path $desktopLnk) "desktop shortcut exists"
  Check (Test-Path $startLnk) "Start menu shortcut exists"
  $entry = UninstallEntry
  Check ($null -ne $entry) "Apps & features (Uninstall) registry entry exists"
  if ($entry) { Log "Registry: DisplayName='$($entry.DisplayName)' DisplayVersion='$($entry.DisplayVersion)'" }
  Check ((UserPath) -split ";" -contains $binDir) "user PATH contains $binDir"
  Check ($null -ne (Get-ItemProperty $runKey -Name "MetaVault OSS" -ErrorAction SilentlyContinue)) "start-at-login Run entry exists"
}

function Check-VaultDataKept([string]$what) {
  Check (Test-Path $dbFile) "vault DB kept ($what)"
  Check (Test-Path $keyFile) "vault key file kept ($what)"
  Check (Test-Path $tokenFile) "daemon token file kept ($what)"
}

function Uninstall-App([string]$what) {
  Log "Uninstalling ($what): `"$uninstaller`" /S"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $u = Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -PassThru
  Log "Uninstaller exit code $($u.ExitCode)"
  Check ($u.ExitCode -eq 0) "uninstaller exit code is 0 ($what)"
  # The NSIS uninstaller re-launches itself from %TEMP%; wait for the folder.
  $deadline = (Get-Date).AddSeconds(60)
  while ((Test-Path $installDir) -and ((Get-Date) -lt $deadline)) { Start-Sleep -Milliseconds 500 }
  Log "Uninstall finished after $([int]$sw.Elapsed.TotalSeconds) s"
}

function Check-Cleanup {
  if (Test-Path $installDir) {
    Log "Left behind: $((Get-ChildItem $installDir -Recurse | ForEach-Object FullName) -join '; ')"
  }
  Check (-not (Test-Path $installDir)) "install folder removed"
  Check (-not (Test-Path $desktopLnk)) "desktop shortcut removed"
  Check (-not (Test-Path $startLnk)) "Start menu shortcut removed"
  Check ($null -eq (UninstallEntry)) "Uninstall registry entry removed"
  Check (-not ((UserPath) -split ";" -contains $binDir)) "user PATH entry removed"
  Check ($null -eq (Get-ItemProperty $runKey -Name "MetaVault OSS" -ErrorAction SilentlyContinue)) "Run entry removed"
}

# === 1. clean install + first-run state ================================
Install-App "clean install"
Check-Installed-Layout
$sizeMb = [math]::Round(((Get-ChildItem $installDir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB), 1)
Log "Install folder size: $sizeMb MB"
Launch-App-Wait-Health "clean install"

$status = Invoke-Daemon "GET" "/key/status"
Log "GET /key/status -> $($status | ConvertTo-Json -Compress)"
Check ($null -ne $status -and $status.mode -eq "uninitialized") "fresh install waits for first-run setup"
$procs = Get-Process -Name "MetaVault OSS" -ErrorAction SilentlyContinue
Check (@($procs).Count -ge 2) "app UI and bundled daemon processes are running"
Check (Test-Path $dbFile) "vault DB created in %APPDATA%\MetaVault OSS"

# === 2. real encrypted vault: passphrase setup + credential ============
$setup = Invoke-Daemon "POST" "/setup" @{ passphrase = $smokePassphrase }
Log "POST /setup -> $($setup | ConvertTo-Json -Compress)"
Check ($null -ne $setup -and $setup.status -eq "initialized") "passphrase setup initializes the vault key"
Check (Test-Path $keyFile) "passphrase-wrapped key file created"

$add = Invoke-Daemon "POST" "/credentials" @{ alias = $smokeAlias; scope = "smoke"; secret = $smokeSecret }
Check ($null -ne $add -and $null -eq $add.__httpStatus) "credential stored"
$aliases = Invoke-Daemon "GET" "/aliases"
Log "GET /aliases -> $($aliases | ConvertTo-Json -Compress)"
Check ($null -ne $aliases -and @($aliases).Contains($smokeAlias)) "credential alias listed"
$setup = $null; $add = $null

# === 3. silent uninstall keeps the vault ===============================
Stop-App
Uninstall-App "after first install"
Check-Cleanup
Check-VaultDataKept "silent uninstall answers No to deleting vault data, by design"

# === 4. reinstall: vault must return locked and decrypt ================
Install-App "reinstall over kept vault data"
Launch-App-Wait-Health "reinstall"
$status = Invoke-Daemon "GET" "/key/status"
Log "GET /key/status (reinstall) -> $($status | ConvertTo-Json -Compress)"
Check ($null -ne $status -and $status.mode -eq "passphrase") "reinstall finds the existing passphrase-protected vault (no first-run reset)"
Check ($null -ne $status -and $status.locked -eq $true) "reinstalled vault starts locked"

$bad = Invoke-Daemon "POST" "/unlock" @{ passphrase = "definitely-wrong-passphrase" }
Check ($null -ne $bad -and $bad.__httpStatus -eq 401) "wrong passphrase rejected with 401"
$bad = $null
$unlock = Invoke-Daemon "POST" "/unlock" @{ passphrase = $smokePassphrase }
Log "POST /unlock (reinstall) -> $($unlock | ConvertTo-Json -Compress)"
Check ($null -ne $unlock -and ($unlock.status -eq "unlocked" -or $unlock.status -eq "already-unlocked")) "correct passphrase unlocks after reinstall"
$unlock = $null
$aliases = Invoke-Daemon "GET" "/aliases"
Log "GET /aliases (reinstall) -> $($aliases | ConvertTo-Json -Compress)"
Check ($null -ne $aliases -and @($aliases).Contains($smokeAlias)) "stored credential survives uninstall + reinstall (encrypted round-trip)"

# === 5. install-over-install (update path) keeps the vault =============
Stop-App
Install-App "install-over-install (update path)"
Launch-App-Wait-Health "update path"
$status = Invoke-Daemon "GET" "/key/status"
Log "GET /key/status (update) -> $($status | ConvertTo-Json -Compress)"
Check ($null -ne $status -and $status.mode -eq "passphrase") "update path keeps the vault (NSIS --updated guard)"
$unlock = Invoke-Daemon "POST" "/unlock" @{ passphrase = $smokePassphrase }
Check ($null -ne $unlock -and ($unlock.status -eq "unlocked" -or $unlock.status -eq "already-unlocked")) "vault unlocks after update-path install"
$unlock = $null
$aliases = Invoke-Daemon "GET" "/aliases"
Check ($null -ne $aliases -and @($aliases).Contains($smokeAlias)) "stored credential survives install-over-install"

# === 6. final silent uninstall: cleanup + data kept ====================
Stop-App
Uninstall-App "final uninstall"
Check-Cleanup
Check-VaultDataKept "final silent uninstall"
Remove-Item $dataDir -Recurse -Force -ErrorAction SilentlyContinue

Log "Result: $(if ($script:failures -eq 0) { 'PASS' } else { "FAIL ($script:failures checks failed)" })"
if ($script:failures -ne 0) { exit 1 }
