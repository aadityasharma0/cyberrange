#!/bin/bash
# ---------------------------------------------------------------
#  CyberRange - macOS uninstaller
#  Removes ~/Applications/CyberRange and ~/Applications/CyberRange.app
# ---------------------------------------------------------------
cd "$(dirname "$0")"

echo "=============================================================="
echo "  CYBERRANGE UNINSTALLER"
echo "=============================================================="

read -r -p "Also delete the session audit logs? [y/N] " ans
if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
  rm -rf "$HOME/Applications/CyberRange"
  echo "Application and logs removed."
else
  mkdir -p "$HOME/CyberRange"
  [ -d "$HOME/Applications/CyberRange/logs" ] && \
    cp -R "$HOME/Applications/CyberRange/logs" "$HOME/CyberRange/logs"
  rm -rf "$HOME/Applications/CyberRange"
  echo "Application removed; logs kept in $HOME/CyberRange/logs"
fi

rm -rf "$HOME/Applications/CyberRange.app"
echo "CyberRange.app removed. Goodbye!"
read -r -p "Press Enter to close... "
