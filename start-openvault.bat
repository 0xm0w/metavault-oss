@echo off
cd /d "C:\Users\Mowreez.DESKTOP-D1GHS6J\openvault"
set OPENVAULT_DAEMON_URL=http://127.0.0.1:7078
set /p OPENVAULT_DAEMON_TOKEN=<openvault.token
start "" "C:\Users\Mowreez.DESKTOP-D1GHS6J\openvault\packages\app\release\win-unpacked\OpenVault.exe"
