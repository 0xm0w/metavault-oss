param([string]$InstallDir, [string]$AgentToken, [string]$LogPath)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:RUNNER_TEMP 'metavault-vscode-host-smoke'
New-Item $root -ItemType Directory -Force | Out-Null
$metadata = Invoke-RestMethod 'https://update.code.visualstudio.com/api/update/win32-x64-archive/stable/latest'
$zip = Join-Path $root 'vscode.zip'
Invoke-WebRequest $metadata.url -OutFile $zip -UseBasicParsing
if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.sha256hash) { throw 'VS Code archive hash mismatch' }
Add-Content $LogPath ("VS Code official archive version=" + $metadata.productVersion + " sha256=" + $metadata.sha256hash + " url=" + $metadata.url)
Expand-Archive $zip -DestinationPath (Join-Path $root 'editor')
$workspace = Join-Path $root 'workspace'
New-Item (Join-Path $workspace '.vscode') -ItemType Directory -Force | Out-Null
# Exact installed app VS Code schema, paths and environment. Synthetic token only.
$config = @{servers=@{metavault=@{type='stdio';command=(Join-Path $InstallDir 'MetaVault OSS.exe');args=@((Join-Path $InstallDir 'resources\vaultd\mcp.cjs'));env=@{ELECTRON_RUN_AS_NODE='1';METAVAULT_DAEMON_URL='http://127.0.0.1:7077';METAVAULT_AGENT_ID='vscode';METAVAULT_AGENT_TOKEN=$AgentToken;METAVAULT_IDE='VS Code'}}}}
$config | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $workspace '.vscode\mcp.json') -Encoding UTF8
$userData = Join-Path $root 'user-data'
New-Item (Join-Path $userData 'User') -ItemType Directory -Force | Out-Null
# We own this synthetic workspace; no external project/host settings are trusted.
@{'security.workspace.trust.enabled'=$false;'chat.mcp.access'='all';'telemetry.telemetryLevel'='off';'update.mode'='none'} | ConvertTo-Json | Set-Content (Join-Path $userData 'User\settings.json') -Encoding UTF8
$env:MV_HOST_LOG = $LogPath
$extension = Join-Path $PSScriptRoot 'vscode-smoke'
$code = Join-Path $root 'editor\Code.exe'
$p = Start-Process $code -ArgumentList @('--user-data-dir',('"'+$userData+'"'),'--extensions-dir',('"'+(Join-Path $root 'extensions')+'"'),'--disable-extensions','--skip-welcome','--skip-release-notes',('--extensionDevelopmentPath="'+$extension+'"'),('--extensionTestsPath="'+(Join-Path $extension 'test.cjs')+'"'),('"'+$workspace+'"')) -PassThru
if (-not $p.WaitForExit(120000)) { $p.Kill(); throw 'VS Code host proof timed out' }
if ($p.ExitCode -ne 0) { throw ('VS Code host proof exit ' + $p.ExitCode) }
Remove-Item Env:MV_HOST_LOG
# No real profile, settings sync, model account or credentials ever loaded.
Remove-Item $root -Recurse -Force
