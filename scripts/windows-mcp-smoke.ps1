# Known-good .NET Core MCP transport check, separate from WinRT fixtures.
param([string]$InstallDir, [string]$LogPath)
$ErrorActionPreference = 'Stop'
$installDir = $InstallDir
$binDir = Join-Path $installDir 'bin'
$exe = Join-Path $installDir 'MetaVault OSS.exe'
function Log([string]$msg) { Write-Host $msg; Add-Content -Path $LogPath -Value $msg }
function Check([bool]$ok, [string]$what) { if (-not $ok) { throw $what }; Log ("PASS  " + $what) }
function Test-PackagedMcp {
  Check (Test-Path (Join-Path $binDir "metavault-mcp.cmd")) "MCP cmd launcher installed"
  Check (Test-Path (Join-Path $binDir "metavault-mcp.ps1")) "MCP PowerShell launcher installed"
  $info = New-Object Diagnostics.ProcessStartInfo
  $info.FileName = $exe
  $info.Arguments = '"' + (Join-Path $installDir "resources\vaultd\mcp.cjs") + '"'
  $info.UseShellExecute = $false
  $info.RedirectStandardInput = $true
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $info.CreateNoWindow = $true
  $info.EnvironmentVariables["ELECTRON_RUN_AS_NODE"] = "1"
  $p = New-Object Diagnostics.Process
  $p.StartInfo = $info
  try {
    [void]$p.Start()
    $p.StandardInput.WriteLine('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"installed-smoke","version":"1"}}}')
    $read = $p.StandardOutput.ReadLineAsync()
    if (-not $read.Wait(15000)) { throw "Installed MCP initialize timed out" }
    $reply = $read.Result | ConvertFrom-Json
    Check ($reply.id -eq 1 -and $null -ne $reply.result.serverInfo) "installed runtime completes MCP initialize without source checkout or Node"
    $p.StandardInput.WriteLine('{"jsonrpc":"2.0","method":"notifications/initialized"}')
    $p.StandardInput.WriteLine('{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
    $read = $p.StandardOutput.ReadLineAsync()
    if (-not $read.Wait(15000)) { throw "Installed MCP tools/list timed out" }
    $reply = $read.Result | ConvertFrom-Json
    Check ($reply.id -eq 2 -and @($reply.result.tools).Count -eq 5) "installed MCP exposes exactly five secret-blind tools"
    Check (@($reply.result.tools.name) -contains "request_capability") "installed MCP includes request_capability"
  } finally {
    if ($p.Id -and -not $p.HasExited) { $p.Kill() }
    $p.Dispose()
  }
}


Test-PackagedMcp
