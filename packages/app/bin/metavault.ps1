# MetaVault OSS PowerShell CLI wrapper. The installed app runs the bundled
# CLI with its own Electron binary in Node mode (no separate Node needed).
$AppExe = Join-Path $PSScriptRoot "..\MetaVault OSS.exe"
$Cli = Join-Path $PSScriptRoot "..\resources\vaultd\metavault.cjs"
if (-not $env:METAVAULT_DB_PATH) { $env:METAVAULT_DB_PATH = Join-Path $env:APPDATA "MetaVault OSS\metavault.db" }
if ((Test-Path $AppExe) -and (Test-Path $Cli)) {
  $env:ELECTRON_RUN_AS_NODE = "1"
  & $AppExe $Cli @args
  Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue
} else {
  & node (Join-Path $PSScriptRoot "..\..\cli\dist\cli.js") @args
}
