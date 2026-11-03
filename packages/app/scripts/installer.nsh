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

!macro customUnInstall
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "MetaVault OSS"
  DetailPrint "Removing $INSTDIR\bin from your user PATH..."
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = '$INSTDIR\bin'; $$k = Get-Item 'HKCU:\Environment'; $$p = [string]$$k.GetValue('Path', '', 'DoNotExpandEnvironmentNames'); $$parts = @($$p -split ';' | Where-Object { $$_ -ne '' }); if ($$parts -contains $$d) { Set-ItemProperty -Path 'HKCU:\Environment' -Name Path -Type ExpandString -Value ((@($$parts | Where-Object { $$_ -ne $$d })) -join ';') }"`
  Pop $0
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=3000

  ; Updates run the uninstaller too; never ask about data then.
  ${ifNot} ${isUpdated}
    ; Silent uninstall (/S) answers No, so vault data is kept.
    MessageBox MB_YESNO|MB_ICONQUESTION "Also delete your encrypted vault data (metavault.db, key file and token)?$\n$\nYes: delete it from this computer. This cannot be undone.$\nNo: keep it for a later install." /SD IDNO IDNO skip_purge
      RMDir /r "$APPDATA\MetaVault OSS"
      DetailPrint "Deleted vault data in $APPDATA\MetaVault OSS."
    skip_purge:
  ${endIf}
!macroend
