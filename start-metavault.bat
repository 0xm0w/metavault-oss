@echo off
rem Run from the repo root (the folder this file is in).
cd /d "%~dp0"
set METAVAULT_DAEMON_URL=http://127.0.0.1:7077
rem The daemon token is delivered via the environment only; the app mints a
rem session token and shares it with the bundled daemon it spawns. To use a
rem daemon started some other way, set METAVAULT_DAEMON_TOKEN yourself.
if exist "packages\app\release\win-unpacked\MetaVault OSS.exe" (
  start "" "packages\app\release\win-unpacked\MetaVault OSS.exe"
) else (
  rem No packaged build yet: build from source and run it with Electron.
  if not exist "packages\app\dist\main.js" call npm run build
  call npx electron packages\app\dist\main.js
)
