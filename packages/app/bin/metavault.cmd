@echo off
setlocal
if not defined METAVAULT_DB_PATH set "METAVAULT_DB_PATH=%APPDATA%\MetaVault OSS\metavault.db"
if exist "%~dp0..\resources\vaultd\metavault.cjs" (
  set ELECTRON_RUN_AS_NODE=1
  "%~dp0..\MetaVault OSS.exe" "%~dp0..\resources\vaultd\metavault.cjs" %*
) else (
  node "%~dp0..\..\cli\dist\cli.js" %*
)
