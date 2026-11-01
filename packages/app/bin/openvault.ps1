# MetaVault OSS PowerShell CLI Wrapper
$AppExe = Join-Path $PSScriptRoot "..\MetaVault OSS.exe"
if (Test-Path $AppExe) {
  & $AppExe --cli @args
} else {
  & node (Join-Path $PSScriptRoot "..\..\cli\dist\cli.js") @args
}
