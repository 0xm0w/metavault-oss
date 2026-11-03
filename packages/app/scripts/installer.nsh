; MetaVault OSS Custom NSIS Installer & Uninstaller Script
; Manages User PATH registration, desktop shortcuts, background auto-start, and data wipe prompts.

!macro customInstall
  DetailPrint "Configuring MetaVault OSS Environment and CLI Path..."

  ; Register $INSTDIR\bin in User PATH
  ReadRegStr $0 HKCU "Environment" "Path"
  ${If} $0 == ""
    WriteRegExpandStr HKCU "Environment" "Path" "$INSTDIR\bin"
  ${Else}
    ; Direct append if not already present
    WriteRegExpandStr HKCU "Environment" "Path" "$0;$INSTDIR\bin"
  ${EndIf}

  ; Broadcast environment variable change to running shells and explorer
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=3000

  ; Create Start Menu and Desktop shortcuts
  CreateDirectory "$SMPROGRAMS\MetaVault OSS"
  CreateShortcut "$SMPROGRAMS\MetaVault OSS\MetaVault OSS.lnk" "$INSTDIR\MetaVault OSS.exe" "" "$INSTDIR\MetaVault OSS.exe" 0
  CreateShortcut "$DESKTOP\MetaVault OSS.lnk" "$INSTDIR\MetaVault OSS.exe" "" "$INSTDIR\MetaVault OSS.exe" 0

  ; Configure background auto-start on user login (minimized to system tray)
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "MetaVault OSS" '"$INSTDIR\MetaVault OSS.exe" --minimized'

  DetailPrint "MetaVault OSS environment and background startup configured successfully."
!macroend

!macro customUnInstall
  DetailPrint "Cleaning up MetaVault OSS Shortcuts and Environment..."

  ; Remove auto-start Run key
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "MetaVault OSS"

  ; Clean uninstaller data prompt: ask user whether to wipe local encrypted vault data
  MessageBox MB_YESNO|MB_ICONQUESTION "Do you want to completely erase your encrypted vault data (metavault.db) and credentials?$\n$\nSelect 'Yes' to purge local vault databases.$\nSelect 'No' to preserve your encrypted vault for future use." IDNO skip_purge
    RMDir /r "$APPDATA\MetaVault OSS"
    RMDir /r "$LOCALAPPDATA\metavault"
    RMDir /r "$PROFILE\.metavault"
    DetailPrint "Purged encrypted vault databases."
  skip_purge:

  ; Broadcast environment update
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=3000

  DetailPrint "MetaVault OSS uninstalled."
!macroend
