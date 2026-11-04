# One-time registration for the MetaVault CI runner. Run from ops\ci-runner:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\register.ps1
# The token is entered masked, written to runner-token.txt only for the
# register step, and the file is removed afterwards even if a step fails.
# The runner is started only if build and register both succeeded.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

docker compose build
if ($LASTEXITCODE -ne 0) { throw "docker compose build failed (exit $LASTEXITCODE). Nothing registered." }

$secure = Read-Host "Paste the registration token (input is hidden)" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
  $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  [IO.File]::WriteAllText((Join-Path $PWD 'runner-token.txt'), $plain, [Text.Encoding]::ASCII)
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  Remove-Variable plain, secure -ErrorAction SilentlyContinue
}

try {
  docker compose -f compose.yml -f compose.register.yml run --rm register
  if ($LASTEXITCODE -ne 0) { throw "register failed (exit $LASTEXITCODE). The runner was not started." }
} finally {
  Remove-Item -Force runner-token.txt -ErrorAction SilentlyContinue
}

docker compose up -d
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed (exit $LASTEXITCODE)." }
docker compose logs --tail 20 runner
Write-Host "Done. Check the repo's Runners page for metavault-ci-1 Idle."
