#!/bin/bash
# ---------------------------------------------------------------
#  CyberRange - macOS installer
#
#  Double-click this file. It:
#    1. checks for Python 3 (offers the official download if missing)
#    2. copies the app into ~/Applications/CyberRange
#    3. creates a virtual environment and downloads the dependencies
#    4. builds CyberRange.app and launches the website in your browser
#
#  If macOS blocks this file as "unidentified developer":
#    right-click this file -> Open -> Open,  or run:
#    xattr -dr com.apple.quarantine "<folder with this file>"
# ---------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

APP_HOME="$HOME/Applications/CyberRange"
APP_BUNDLE="$HOME/Applications/CyberRange.app"

echo "=============================================================="
echo "  CYBERRANGE INSTALLER"
echo "=============================================================="

# 1. Python 3 ------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required and was not found on this Mac."
  echo "Opening the official Python download page - install Python 3,"
  echo "then double-click this installer again."
  open "https://www.python.org/downloads/"
  read -r -p "Press Enter once Python is installed (or type q + Enter to quit)... " ans
  [ "$ans" = "q" ] && exit 1
  command -v python3 >/dev/null 2>&1 || { echo "python3 is still not found - aborting."; exit 1; }
fi
echo "[1/4] Python found: $(python3 --version)"

# 2. Copy the app files --------------------------------------------
mkdir -p "$APP_HOME"
rm -rf "$APP_HOME/backend" "$APP_HOME/frontend"
cp -R app/backend app/frontend "$APP_HOME/"
echo "[2/4] Application files copied to $APP_HOME"

# 3. Virtual environment + dependencies (downloaded now) ------------
if [ ! -x "$APP_HOME/venv/bin/python" ]; then
  python3 -m venv "$APP_HOME/venv"
fi
"$APP_HOME/venv/bin/pip" install --quiet --upgrade pip
"$APP_HOME/venv/bin/pip" install --quiet -r "$APP_HOME/backend/requirements.txt"
echo "[3/4] Dependencies installed into $APP_HOME/venv"

# 4. Build CyberRange.app -------------------------------------------
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"

cat > "$APP_BUNDLE/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>                <string>CyberRange</string>
  <key>CFBundleDisplayName</key>         <string>CyberRange</string>
  <key>CFBundleIdentifier</key>          <string>local.cyberrange.app</string>
  <key>CFBundleVersion</key>             <string>1.0</string>
  <key>CFBundleShortVersionString</key>  <string>1.0</string>
  <key>CFBundlePackageType</key>         <string>APPL</string>
  <key>CFBundleExecutable</key>          <string>CyberRange</string>
</dict>
</plist>
PLIST

cat > "$APP_BUNDLE/Contents/MacOS/CyberRange" <<'RUN'
#!/bin/bash
# CyberRange launcher: start the local server, then open the website.
APP_HOME="$HOME/Applications/CyberRange"
export CYBERRANGE_LOGDIR="$APP_HOME/logs"

PORT="${CYBERRANGE_PORT:-8000}"
for p in $(seq "$PORT" $((PORT + 9))); do
  if ! nc -z 127.0.0.1 "$p" 2>/dev/null; then PORT="$p"; break; fi
done
URL="http://127.0.0.1:$PORT"

cd "$APP_HOME"
"$APP_HOME/venv/bin/python" -m uvicorn main:app --app-dir backend \
    --host 127.0.0.1 --port "$PORT" --log-level warning &
SERVER_PID=$!

for _ in $(seq 1 60); do
  curl -fsS -o /dev/null "$URL" 2>/dev/null && break
  sleep 0.5
done

echo "CyberRange is running at $URL"
echo "Audit logs: $APP_HOME/logs   (close this window or Ctrl+C to stop)"
open "$URL"
wait "$SERVER_PID"
RUN

chmod +x "$APP_BUNDLE/Contents/MacOS/CyberRange"
xattr -dr com.apple.quarantine "$APP_BUNDLE" 2>/dev/null || true
echo "[4/4] Created $APP_BUNDLE"

echo "=============================================================="
echo "  DONE - launching CyberRange in your browser..."
echo "  Tip: if macOS warns about an unidentified developer,",
echo "  right-click CyberRange.app -> Open -> Open."
echo "=============================================================="
open "$APP_BUNDLE"
