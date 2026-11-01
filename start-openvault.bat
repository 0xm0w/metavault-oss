@echo off
cd /d "C:\Users\Mowreez.DESKTOP-D1GHS6J\openvault"
set OPENVAULT_DAEMON_URL=http://127.0.0.1:7078
set /p OPENVAULT_DAEMON_TOKEN=<openvault.token
if exist "packages\app\release\win-unpacked\MetaVault OSS.exe" (
  start "" "packages\app\release\win-unpacked\MetaVault OSS.exe"
) else (
  start "" "packages\app\release\win-unpacked\OpenVault.exe"
)
