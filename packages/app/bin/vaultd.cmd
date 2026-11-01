@echo off
setlocal
if exist "%~dp0..\MetaVault OSS.exe" (
  "%~dp0..\MetaVault OSS.exe" --daemon %*
) else (
  node "%~dp0..\..\daemon\dist\server.js" %*
)
