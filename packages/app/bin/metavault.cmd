@echo off
setlocal
if exist "%~dp0..\MetaVault OSS.exe" (
  "%~dp0..\MetaVault OSS.exe" --cli %*
) else (
  node "%~dp0..\..\cli\dist\cli.js" %*
)
