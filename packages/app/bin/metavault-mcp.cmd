@echo off
setlocal
set ELECTRON_RUN_AS_NODE=1
"%~dp0..\MetaVault OSS.exe" "%~dp0..\resources\vaultd\mcp.cjs" %*
