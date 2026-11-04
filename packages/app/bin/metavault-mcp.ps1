# Uses the installed runtime and bundled MCP server. No separate Node needed.
$previous = $env:ELECTRON_RUN_AS_NODE
try {
  $env:ELECTRON_RUN_AS_NODE = "1"
  & (Join-Path $PSScriptRoot "..\MetaVault OSS.exe") (Join-Path $PSScriptRoot "..\resources\vaultd\mcp.cjs") @args
  $result = $LASTEXITCODE
} finally {
  if ($null -eq $previous) { Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue }
  else { $env:ELECTRON_RUN_AS_NODE = $previous }
}
exit $result
