# Clean-install smoke test for the MetaVault OSS Windows installer.
# Runs in CI on windows-latest (see .github/workflows/windows-installer.yml).
#
# Covers the full data-preservation contract with a REAL encrypted vault:
#   1. silent install, files/shortcuts/registry/PATH, launch, /health
#   2. first-run passphrase setup + a stored credential (real encrypted DB)
#   3. deliberate silent uninstall -> fixed app profile must be removed
#   4. reinstall -> fresh password setup, old credentials/token absent
#   5. install-over-install (the update path, NSIS --updated flag) must
#      never touch vault data
#   6. final silent uninstall -> everything the installer added is gone,
#      vault data removed
# No API keys are set, so nothing here calls the Meta API. The vault
# created here is synthetic CI data and is deleted at the end.
param(
  [Parameter(Mandatory = $true)][string]$InstallerDir,
  [Parameter(Mandatory = $true)][string]$LogPath,
  [string]$PreviousInstallerDir = "",
  [int]$Port = 7077,
  [int]$HealthTimeoutSec = 90
)

# WinRT PasswordVault requires Windows PowerShell/.NET Framework, not pwsh7.
# Match the runtime used by installed cleanup and the app's legacy keychain.
if ($PSVersionTable.PSEdition -eq 'Core') {
  & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath -InstallerDir $InstallerDir -LogPath $LogPath -Port $Port -HealthTimeoutSec $HealthTimeoutSec -PreviousInstallerDir $PreviousInstallerDir
  exit $LASTEXITCODE
}

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

function Test-PackagedMcp {
  # Keep known-good Core stdio runtime separate from Framework-only WinRT tests.
  & pwsh.exe -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'windows-mcp-smoke.ps1') -InstallDir $installDir -LogPath $LogPath
  if ($LASTEXITCODE -ne 0) { throw 'Installed MCP subprocess check failed' }
}

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
      (Join-Path $installDir "resources\cleanup-profile.ps1"),
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

# Optional genuine previous-published-installer upgrade. Caller must fetch and
# hash-verify the private release asset; absence is skipped, never a fake pass.
if ($PreviousInstallerDir -ne "") {
  $candidateInstaller = $installer
  $previous = Get-ChildItem $PreviousInstallerDir -Filter '*.exe' -File | Select-Object -First 1
  if ($null -eq $previous) { throw 'Previous release installer missing' }
  $sums = Get-Content (Join-Path $PreviousInstallerDir 'SHA256SUMS') -Raw
  $hash = (Get-FileHash $previous.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($sums -notmatch [Regex]::Escape($hash)) { throw 'Previous published installer SHA256 mismatch' }
  Log ("Previous published artifact: " + $previous.Name + " SHA256=" + $hash)
  $installer = $previous
  Install-App 'published previous release'
  Launch-App-Wait-Health 'published previous release'
  $status = Invoke-Daemon 'GET' '/key/status'
  Check ($status.mode -eq 'uninitialized') 'previous release starts synthetic empty vault'
  $result = Invoke-Daemon 'POST' '/setup' @{passphrase=$smokePassphrase}
  Check ($result.status -eq 'initialized') 'previous published release creates password vault'
  $result = Invoke-Daemon 'POST' '/credentials' @{alias='previous-release-dummy';scope='smoke';secret=$smokeSecret}
  Check ($null -ne $result -and $null -eq $result.__httpStatus) 'previous release stores synthetic encrypted credential'
  $keyBeforeUpgrade = (Get-FileHash $keyFile -Algorithm SHA256).Hash
  Stop-App
  $installer = $candidateInstaller
  Install-App 'candidate in-place upgrade over published release'
  Launch-App-Wait-Health 'candidate over published release'
  $status = Invoke-Daemon 'GET' '/key/status'
  Check ($status.mode -eq 'passphrase' -and $status.locked) 'published-to-candidate upgrade preserves locked password vault'
  Check ((Get-FileHash $keyFile -Algorithm SHA256).Hash -eq $keyBeforeUpgrade) 'published upgrade retains exact wrapped key file'
  $result = Invoke-Daemon 'POST' '/unlock' @{passphrase=$smokePassphrase}
  Check ($result.status -eq 'unlocked') 'published vault password unlocks candidate'
  $aliases = Invoke-Daemon 'GET' '/aliases'
  Check (@($aliases.aliases).Contains('previous-release-dummy')) 'published credential alias remains in candidate'
  Stop-App
  $env:MV_UPGRADE_DB = $dbFile; $env:MV_UPGRADE_KEY = $keyFile
  $env:MV_UPGRADE_PASSWORD = $smokePassphrase; $env:MV_UPGRADE_EXPECTED = $smokeSecret
  $verifyScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'verify-upgrade-fixture.cjs'
  & (Join-Path (Split-Path $PSScriptRoot -Parent) 'node_modules\.bin\esbuild.cmd') (Join-Path $PSScriptRoot 'verify-upgrade-credential.ts') --bundle --platform=node --format=cjs --external:better-sqlite3 --outfile=$verifyScript
  if ($LASTEXITCODE -ne 0) { throw 'Synthetic upgrade verifier build failed' }
  & node $verifyScript
  if ($LASTEXITCODE -ne 0) { throw 'Synthetic published credential decrypt verification failed' }
  Remove-Item $verifyScript -Force
  Remove-Item Env:MV_UPGRADE_DB,Env:MV_UPGRADE_KEY,Env:MV_UPGRADE_PASSWORD,Env:MV_UPGRADE_EXPECTED
  Uninstall-App 'remove synthetic upgraded fixture using candidate policy'
  Check-Cleanup
  Check (-not (Test-Path $dataDir)) 'synthetic published-upgrade fixture removed before clean tests'
} else {
  Log 'NOT RUN: genuine previous-published-release upgrade (no verified previous artifact supplied)'
}

# === 1. clean install + first-run state ================================
Install-App "clean install"
Test-PackagedMcp
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
Check ($null -ne $aliases -and @($aliases.aliases).Contains($smokeAlias)) "credential alias listed"
$setup = $null; $add = $null

# Actual identified IDE host proof, no model account or external connector call.
$hostAgent = Invoke-Daemon "POST" "/agents" @{id='vscode';name='VS Code'}
if ($null -eq $hostAgent.token) { throw 'Unable to mint synthetic host agent' }
& (Join-Path $PSScriptRoot 'windows-vscode-smoke.ps1') -InstallDir $installDir -AgentToken $hostAgent.token -LogPath $LogPath
$hostAgent = $null
$hostPending = Invoke-Daemon "GET" "/pending"
Check (@($hostPending.approvals | Where-Object { $_.agentId -eq 'vscode' -and $_.verified -eq $true }).Count -gt 0) "VS Code capability reached daemon as verified synthetic agent"
Invoke-Daemon "POST" "/agents/revoke" @{id='vscode'} | Out-Null

# === 3. deliberate uninstall wipes only the fixed app-owned profile ====
Stop-App
$outside = Join-Path $env:RUNNER_TEMP "unrelated-vault-sentinel.txt"
Set-Content $outside "must survive MetaVault uninstall"
Set-Content (Join-Path $dataDir "settings-test-sentinel.json") '{"dummy":true}'
$backupDir = Join-Path $dataDir "metavault.db.before-agent-hash-smoke"
New-Item $backupDir -ItemType Directory | Out-Null
Set-Content (Join-Path $backupDir "vault.db.bak") "synthetic backup"
# Link refusal: cleanup must stop before touching an outside target or DB.
$outsideDir = Join-Path $env:RUNNER_TEMP "unrelated-vault-directory"
New-Item $outsideDir -ItemType Directory | Out-Null
Set-Content (Join-Path $outsideDir "keep.txt") "outside data"
$link = Join-Path $dataDir "do-not-follow"
New-Item -Path $link -ItemType Junction -Target $outsideDir | Out-Null
$blockedCleanup = Start-Process powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"' + (Join-Path $installDir 'resources\cleanup-profile.ps1') + '"') -Wait -PassThru
Check ($blockedCleanup.ExitCode -ne 0) "cleanup rejects junction before recursive deletion"
Check ((Test-Path $dbFile) -and (Test-Path (Join-Path $outsideDir 'keep.txt'))) "link rejection preserves vault and outside file"
[IO.Directory]::Delete($link)
$null = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$testKeychain = New-Object Windows.Security.Credentials.PasswordVault
# A real external encrypted fixture depends on the shared legacy key.
$sharedKey = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($sharedKey)
$aes = [Security.Cryptography.Aes]::Create(); $aes.Key = $sharedKey; $aes.GenerateIV()
$clear = [Text.Encoding]::UTF8.GetBytes('external-legacy-vault-dummy')
$encrypted = $aes.CreateEncryptor().TransformFinalBlock($clear,0,$clear.Length)
$externalEncryptedFile = Join-Path $outsideDir 'legacy-fixture.encrypted'
[IO.File]::WriteAllBytes($externalEncryptedFile,$encrypted)
$testKeychain.Add((New-Object Windows.Security.Credentials.PasswordCredential('metavault','master-key',[Convert]::ToBase64String($sharedKey))))
$blockedShared = Start-Process powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"' + (Join-Path $installDir 'resources\cleanup-profile.ps1') + '"') -Wait -PassThru
Check ($blockedShared.ExitCode -ne 0) "cleanup refuses shared legacy key before any deletion"
Check (Test-Path $dbFile) "shared-key refusal preserves app vault"
$sharedCredential = $testKeychain.Retrieve('metavault','master-key'); $sharedCredential.RetrievePassword()
$aes.Key = [Convert]::FromBase64String($sharedCredential.Password)
$recovered = $aes.CreateDecryptor().TransformFinalBlock([IO.File]::ReadAllBytes($externalEncryptedFile),0,$encrypted.Length)
Check ([Text.Encoding]::UTF8.GetString($recovered) -eq 'external-legacy-vault-dummy') "preserved external fixture remains decryptable with shared key"
# Fixture-only removal after validation, never a production cleanup action.
$testKeychain.Remove($sharedCredential)
$sharedKey = $null; $sharedCredential = $null; $aes.Dispose()

$testKeychain.Add((New-Object Windows.Security.Credentials.PasswordCredential('metavault-unrelated-ci','test-account','synthetic-unrelated')))
$oldToken = Get-Content $tokenFile -Raw
# Interactive destructive warning must precede any change; Cancel preserves all.
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Start-Process -FilePath $uninstaller | Out-Null
$warning = $null
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
  $desktop = [Windows.Automation.AutomationElement]::RootElement
  $texts = $desktop.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)
  foreach ($text in $texts) { if (($text.Current.Name -replace "\s+", " ") -like "*Uninstall MetaVault OSS and permanently delete*") { $warning = $text; break } }
  if ($null -ne $warning) { break }
  Start-Sleep -Milliseconds 500
}
Check ($null -ne $warning) "interactive uninstall displays destructive warning before removal"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$bounds = [Windows.Forms.SystemInformation]::VirtualScreen
$bitmap = New-Object Drawing.Bitmap $bounds.Width,$bounds.Height
$graphics = [Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($bounds.Left,$bounds.Top,0,0,$bitmap.Size)
$stream = New-Object IO.MemoryStream
$bitmap.Save($stream,[Drawing.Imaging.ImageFormat]::Png)
Log ("WARNING_SCREENSHOT_BASE64=" + [Convert]::ToBase64String($stream.ToArray()))
$graphics.Dispose(); $bitmap.Dispose(); $stream.Dispose()
Get-Process | Where-Object { $_.MainWindowTitle -ne '' -or $_.ProcessName -like '*Uninstall*' } | ForEach-Object { Log ("WINDOW pid=" + $_.Id + " process=" + $_.ProcessName + " title=" + $_.MainWindowTitle + " session=" + $_.SessionId) }
$topWindows = [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,[Windows.Automation.Condition]::TrueCondition)
foreach ($window in $topWindows) { Log ("UIA_WINDOW name=" + $window.Current.Name + " type=" + $window.Current.ControlType.ProgrammaticName) }
if ($null -eq $warning) { throw "No interactive warning; stopping before data wipe" }

# Native MessageBox has visible Cancel (IDCANCEL=2); hosted-runner UIA does
# not expose its button subtree consistently. Send the same native command to
# the exact observed uninstaller window, never a screen-coordinate guess.
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class UninstallDialog {
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string className, string windowName);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr parent, int id);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
}
'@
$dialog = [UninstallDialog]::FindWindow('#32770','MetaVault OSS Uninstall')
if ($dialog -eq [IntPtr]::Zero) { throw 'Exact warning dialog not found' }
$cancelHandle = [UninstallDialog]::GetDlgItem($dialog,2)
if ($cancelHandle -eq [IntPtr]::Zero) { throw 'Warning has no native IDCANCEL control' }
[void][UninstallDialog]::SendMessage($dialog,0x0111,[IntPtr]2,$cancelHandle)
Start-Sleep -Seconds 3
Check (Test-Path $exe) "Cancel retains installed program"
Check-VaultDataKept "interactive Cancel"
Check ((Get-Content $tokenFile -Raw) -eq $oldToken) "Cancel preserves existing token"
Uninstall-App "deliberate wipe"
Check-Cleanup
Check (-not (Test-Path $dataDir)) "deliberate uninstall removes vault, key, token, settings and backups"
Check ((Get-Content $outside -Raw).Trim() -eq "must survive MetaVault uninstall") "unrelated external data survives"
$other = $testKeychain.Retrieve('metavault-unrelated-ci','test-account')
Check ($null -ne $other) "unrelated keychain entry retained"
$testKeychain.Remove($other)


# === 4. reinstall is fresh, old password/credential/token not retained ==
Install-App "fresh reinstall after wipe"
Launch-App-Wait-Health "fresh reinstall"
$status = Invoke-Daemon "GET" "/key/status"
Check ($null -ne $status -and $status.mode -eq "uninitialized") "reinstall starts first-run setup, not previous password gate"
Check ((Get-Content $tokenFile -Raw) -ne $oldToken) "reinstall generates a different daemon token"
$oldToken = $null
$smokePassphrase = "new-fresh-smoke-passphrase-84c2"
$setup = Invoke-Daemon "POST" "/setup" @{ passphrase = $smokePassphrase }
Check ($null -ne $setup -and $setup.status -eq "initialized") "fresh password setup succeeds"
$aliases = Invoke-Daemon "GET" "/aliases"
Check ($null -ne $aliases -and -not @($aliases.aliases).Contains($smokeAlias)) "old credential alias is absent after wipe"
$add = Invoke-Daemon "POST" "/credentials" @{ alias = $smokeAlias; scope = "smoke"; secret = $smokeSecret }
Check ($null -ne $add -and $null -eq $add.__httpStatus) "fresh vault stores a new dummy credential"

# === 5. install-over-install (update path) keeps the vault =============
Stop-App
Install-App "install-over-install (update path)"
Launch-App-Wait-Health "update path"
$status = Invoke-Daemon "GET" "/key/status"
Log "GET /key/status (update) -> $($status | ConvertTo-Json -Compress)"
Check ($null -ne $status -and $status.mode -eq "passphrase") "update path keeps the vault (NSIS --updated guard)"
Check ($status.locked -eq $true) "updated vault starts locked"
$bad = Invoke-Daemon "POST" "/unlock" @{ passphrase = "old-or-wrong-passphrase" }
Check ($bad.__httpStatus -eq 401) "update path rejects wrong password"
$unlock = Invoke-Daemon "POST" "/unlock" @{ passphrase = $smokePassphrase }
Check ($null -ne $unlock -and ($unlock.status -eq "unlocked" -or $unlock.status -eq "already-unlocked")) "vault unlocks after update-path install"
$unlock = $null
$aliases = Invoke-Daemon "GET" "/aliases"
Check ($null -ne $aliases -and @($aliases.aliases).Contains($smokeAlias)) "stored credential survives install-over-install"

# === 6. final deliberate uninstall wipes the fresh vault ==============
Stop-App
Uninstall-App "final uninstall"
Check-Cleanup
Check (-not (Test-Path $dataDir)) "final deliberate uninstall wipes app data"
Check (Test-Path $outside) "unrelated sentinel still exists"
Remove-Item $outside -Force
Remove-Item $outsideDir -Recurse -Force

Log "Result: $(if ($script:failures -eq 0) { 'PASS' } else { "FAIL ($script:failures checks failed)" })"
if ($script:failures -ne 0) { exit 1 }
