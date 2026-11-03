@echo off
rem Run from the repo root (the folder this file is in).
cd /d "%~dp0"
set METAVAULT_DAEMON_URL=http://127.0.0.1:7077
set /p METAVAULT_DAEMON_TOKEN=<metavault.token
if exist "packages\app\release\win-unpacked\MetaVault OSS.exe" (
  start "" "packages\app\release\win-unpacked\MetaVault OSS.exe"
) else (
  start "" "packages\app\release\win-unpacked\MetaVault OSS.exe"
)
