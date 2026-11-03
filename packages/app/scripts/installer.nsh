; MetaVault OSS NSIS hooks (electron-builder `nsis.include`).
; electron-builder itself creates the desktop and Start menu shortcuts
; (createDesktopShortcut / createStartMenuShortcut) and removes them on
; uninstall, so this file only adds what it does not do: the CLI folder on
; the user PATH, start-at-login, and the vault-data question on uninstall.
; No model is downloaded or installed.

!macro customInstall
  DetailPrint "Adding $INSTDIR\bin to your user PATH..."
  ; Idempotent: add the folder only if it is not already on the user PATH.
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = '$INSTDIR\bin'; $$k = Get-Item 'HKCU:\Environment'; $$p = [string]$$k.GetValue('Path', '', 'DoNotExpandEnvironmentNames'); $$parts = @($$p -split ';' | Where-Object { $$_ -ne '' }); if ($$parts -notcontains $$d) { Set-ItemProperty -Path 'HKCU:\Environment' -Name Path -Type ExpandString -Value (($$parts + $$d) -join ';') }"`
  Pop $0
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=3000
  ; Start minimised in the tray at login so approval prompts can surface.
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "MetaVault OSS" '"$INSTDIR\MetaVault OSS.exe" --minimized'
!macroend

!macro customUnInit
  ; Warn before removing program files, registry entries or vault bytes.
  ; /S deliberately skips UI but has the same wipe semantics. Updates preserve.
  ${ifNot} ${isUpdated}
    IfSilent wipe_notice_done
    MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION "Uninstall MetaVault OSS and permanently delete its vault, saved credentials, password key, settings and migration backups in this Windows profile? Reinstall will start fresh.$\n$\nThis cannot be undone. Custom external vault paths are not deleted. Cancel to keep everything. In-place updates preserve data." IDOK wipe_notice_done
    Abort
    wipe_notice_done:
  ${endIf}
!macroend

!macro customUnInstall
  ; Never wipe data when electron-builder invokes the uninstaller for an update.
  ${ifNot} ${isUpdated}
    ; Fixed current-user path only. Reject junctions/symlinks instead of following
    ; them into unrelated data. No environment-selected DB path is ever deleted.
    nsExec::ExecToStack `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\cleanup-profile.ps1"`
    Pop $0
    Pop $1
    ${if} $0 != 0
      IfSilent cleanup_failed_silent
      MessageBox MB_OK|MB_ICONSTOP "MetaVault data cleanup failed. Uninstall stopped. No complete wipe was performed. A shared legacy encryption key, linked folder or locked file can block cleanup. Back up/migrate dependent vaults and close MetaVault before retrying. External vault paths are not deleted."
      cleanup_failed_silent:
      SetErrorLevel 1
      Abort
    ${endIf}
  ${endIf}
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "MetaVault OSS"
  DetailPrint "Removing $INSTDIR\bin from your user PATH..."
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = '$INSTDIR\bin'; $$k = Get-Item 'HKCU:\Environment'; $$p = [string]$$k.GetValue('Path', '', 'DoNotExpandEnvironmentNames'); $$parts = @($$p -split ';' | Where-Object { $$_ -ne '' }); if ($$parts -contains $$d) { Set-ItemProperty -Path 'HKCU:\Environment' -Name Path -Type ExpandString -Value ((@($$parts | Where-Object { $$_ -ne $$d })) -join ';') }"`
  Pop $0
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=3000
!macroend
