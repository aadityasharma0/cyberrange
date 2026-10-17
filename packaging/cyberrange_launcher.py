#!/usr/bin/env python3
"""CyberRange launcher (packaged build).

Starts the bundled FastAPI backend, waits until it answers, then opens the
site in the default browser. Everything the app needs (Python, FastAPI,
uvicorn, the 3D web UI) is bundled inside the executable, so there is
nothing extra for the user to install.

Environment overrides (mainly for tests and packagers):
  CYBERRANGE_PORT       preferred port (default 8000, falls back to 8001..8009)
  CYBERRANGE_HOST       bind address (default 127.0.0.1)
  CYBERRANGE_LOGDIR     where siem_events.log / blocked_traffic.csv are written
  CYBERRANGE_NO_BROWSER  set to 1 to skip auto-opening the browser
"""
import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path
from urllib.request import urlopen


def bundle_root():
    """Folder holding backend/ and frontend/ (temp dir when frozen)."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


def pick_port(preferred):
    """First free port in preferred..preferred+9."""
    for port in range(preferred, preferred + 10):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise SystemExit("No free port between %d and %d - is another copy running?" % (preferred, preferred + 9))


def wait_ready(url, timeout=30.0):
    """Poll the site until it answers 200 (or give up)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)   # keep console output in order

    root = bundle_root()
    sys.path.insert(0, str(root / "backend"))

    # The bundled app lives in a read-only temp folder when frozen, so put
    # the audit logs somewhere writable and persistent instead.
    os.environ.setdefault("CYBERRANGE_LOGDIR", str(Path.home() / "CyberRange" / "logs"))

    host = os.environ.get("CYBERRANGE_HOST", "127.0.0.1")
    port = pick_port(int(os.environ.get("CYBERRANGE_PORT", "8000")))
    url = "http://%s:%d" % (host, port)

    import uvicorn
    from main import app  # backend/main.py, now on sys.path

    print("=" * 62)
    print("  CYBERRANGE - simulated cyber-security training range")
    print("=" * 62)
    print("  Starting the local server on %s ..." % url)

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()

    if not wait_ready(url):
        raise SystemExit("The server did not start in time. Check that port %d is free." % port)

    print("  Open in your browser : %s" % url)
    print("  Session audit logs  : %s" % os.environ["CYBERRANGE_LOGDIR"])
    print("  Press Ctrl+C here to stop the server.")
    print("=" * 62)

    if os.environ.get("CYBERRANGE_NO_BROWSER") != "1":
        webbrowser.open(url)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping CyberRange...")
        server.should_exit = True
        time.sleep(1)


if __name__ == "__main__":
    main()
