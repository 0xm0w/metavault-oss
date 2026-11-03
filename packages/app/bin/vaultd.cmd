@echo off
setlocal
if not defined METAVAULT_DB_PATH set "METAVAULT_DB_PATH=%APPDATA%\MetaVault OSS\metavault.db"
if not defined METAVAULT_FIRST_RUN_SETUP set METAVAULT_FIRST_RUN_SETUP=1
if exist "%~dp0..\resources\vaultd\vaultd.cjs" (
  set ELECTRON_RUN_AS_NODE=1
  "%~dp0..\MetaVault OSS.exe" "%~dp0..\resources\vaultd\vaultd.cjs" %*
) else (
  node "%~dp0..\..\daemon\dist\server.js" %*
)
