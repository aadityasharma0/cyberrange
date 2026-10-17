; ---------------------------------------------------------------
;  CyberRange - per-user Windows installer
;  No admin rights needed: installs into %LOCALAPPDATA%\CyberRange,
;  creates Start Menu / Desktop shortcuts, adds an Uninstall entry,
;  and launches the app right after install (it opens the website).
; ---------------------------------------------------------------
!define PRODUCT_NAME     "CyberRange"
!define PRODUCT_VERSION  "1.0"
!define PRODUCT_PUBLISHER "CyberRange training range"
!define EXE_NAME         "CyberRange.exe"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "..\..\dist\CyberRange-Setup.exe"
InstallDir "$LOCALAPPDATA\${PRODUCT_NAME}"
InstallDirRegKey HKCU "Software\${PRODUCT_NAME}" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
Unicode True

Page directory
Page instfiles

Section "Install"
  SetOutPath "$INSTDIR"
  File "..\..\dist\CyberRange.exe"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Start Menu + Desktop shortcuts
  CreateShortCut "$SMPROGRAMS\CyberRange.lnk" "$INSTDIR\${EXE_NAME}"
  CreateShortCut "$DESKTOP\CyberRange.lnk" "$INSTDIR\${EXE_NAME}"

  ; Per-user Add/Remove Programs entry
  WriteRegStr HKCU "Software\${PRODUCT_NAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayIcon" "$INSTDIR\${EXE_NAME}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "NoRepair" 1

  ; Launch the app now - it opens the website in the browser itself
  Exec "$INSTDIR\${EXE_NAME}"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\${EXE_NAME}"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"          ; only removes it if empty (user logs are kept)
  Delete "$SMPROGRAMS\CyberRange.lnk"
  Delete "$DESKTOP\CyberRange.lnk"
  DeleteRegKey HKCU "Software\${PRODUCT_NAME}"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
SectionEnd
