================================================================
  CYBERRANGE - simulated cyber-security training range
  Install guide for Windows and macOS
================================================================

Nothing real is attacked: every packet, alert and breach in this
app is simulated in your own browser.

----------------------------------------------------------------
  WINDOWS  (folder: Windows)
----------------------------------------------------------------
1. Double-click  CyberRange-Setup.exe
   -> it installs for YOUR user only (no admin rights needed),
      creates Start Menu + Desktop shortcuts, then starts the app
      and opens the website in your browser automatically.

2. Everything (Python, FastAPI, the web UI) is already inside the
   installer - nothing is downloaded and no internet is needed.

Windows SmartScreen may say "Windows protected your PC" because the
app is not signed: click  More info  ->  Run anyway.

Uninstall: Settings -> Apps -> CyberRange -> Uninstall,
or run  %LOCALAPPDATA%\CyberRange\Uninstall.exe

----------------------------------------------------------------
  macOS  (folder: macOS)
----------------------------------------------------------------
1. Double-click  Install CyberRange.command
   -> it checks for Python 3 (opens the official download page if
      missing), copies the app to ~/Applications/CyberRange,
      DOWNLOADS the Python dependencies into a private virtual
      environment, creates CyberRange.app, and opens the website.

2. If macOS says the file is from an "unidentified developer":
   right-click the file -> Open -> Open.
   (Or run:  xattr -dr com.apple.quarantine macOS )

Launch later: double-click  CyberRange.app  in ~/Applications.
Uninstall: double-click  Uninstall CyberRange.command

----------------------------------------------------------------
  AFTER INSTALLING (both systems)
----------------------------------------------------------------
* The site opens at http://127.0.0.1:8000 (if 8000 is busy it
  automatically tries 8001-8009 and opens whichever is free).
* The console window that opens is the server - keep it open
  while you use the site; close it (or press Ctrl+C) to stop.
* Session audit logs are written to:
    Windows: %USERPROFILE%\CyberRange\logs
    macOS:   ~/Applications/CyberRange/logs
  (siem_events.log and blocked_traffic.csv; plus an in-app
  "Export session log" button.)

----------------------------------------------------------------
  WHAT'S INSIDE THE APP
----------------------------------------------------------------
* Email training: Genuine / Phishing / Spam (9-email quiz)
* 5 attack simulations: DDoS, brute force, SQL injection,
  ransomware, man-in-the-middle - each with defensive actions,
  live traffic graph, SIEM event log and an end-of-run report
* Pause freezes the clock AND every packet mid-flight so you can
  orbit the 3D range and inspect each device's situation
* Trainer view: inject surges, skip phases, add bonus time,
  grade & finish early

This is a training simulator. Use it only on your own machine.
