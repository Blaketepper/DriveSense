# DriveSense

DriveSense — Windows disk & system cleanup tool (cautious, configurable)

Version: 1.0-real · Author: Blake Tepper

<p align="center"> <!-- Replace badge URLs as desired --> <img src="https://img.shields.io/badge/status-alpha-orange" alt="status"> <img src="https://img.shields.io/badge/platform-windows-blue" alt="platform"> <img src="https://img.shields.io/badge/language-python-3.8+-brightgreen" alt="python"> </p>
🔥 Quick summary

DriveSense is a Windows-focused cleanup utility written in Python. It started as a simulation UI and can run in a real mode that performs careful cleanup actions (temp cleanup, empty Recycle Bin, uninstall programs).
Dry-run is ON by default and the app includes multiple confirmations, a quarantine folder, and other safeguards.

📚 Table of contents

Features

Important safety note

Requirements

Quick start

How it works

UI & modes

Packaging & .cpl stub

Development / Testing

Roadmap / TODO

Contributing

License

Acknowledgements & references

✨ Features

Scan installed programs (reads standard Uninstall registry keys).

Heuristic "last used" via executable access times and fallback to InstallDate.

Analyze common Temp folders and estimate removable size.

Empty Recycle Bin via Windows API (SHEmptyRecycleBinW).

Uninstall programs via registry UninstallString / msiexec.

Quarantine: moved files are stored at %LOCALAPPDATA%\DriveSense\quarantine.

Dry-run support — preview actions without changing anything (default).

UI built with tkinter and organized with tabs (Dashboard / Scan & Clean / Activity Log).

Export activity log and textual .cpl stub (note: stub is not a real Control Panel DLL).

⚠️ Important safety note

THIS TOOL CAN DELETE FILES AND UNINSTALL SOFTWARE. USE WITH CAUTION.

Dry-run is ON by default — use it to preview everything before running real operations.

To perform destructive operations you must explicitly toggle Perform REAL actions in the UI and confirm multiple prompts.

Run as Administrator for most real actions. DriveSense can prompt to re-run elevated.

Always back up or create a system restore point before bulk removals. DriveSense uses a quarantine folder, but that is not a full system backup.

The author is not responsible for data loss or system changes resulting from use.

🧰 Requirements

Windows 10 / 11 (real mode uses Windows APIs & registry)

Python 3.8+

Uses standard libraries: tkinter, ctypes, winreg, subprocess, shutil, os, pathlib, threading, tempfile, datetime

Optional: psutil (for better RAM heuristics)

Install optional dependency (if desired):

pip install psutil

🚀 Quick start
git clone https://github.com/<your-username>/drivesense.git
cd drivesense

# (optional) virtualenv
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Run (dry-run by default)
python drivesense_real.py


To perform real actions:

Toggle Perform REAL actions in the UI.

Uncheck Dry-run and confirm all prompts.

Make sure you are running as Administrator if prompted.

🧠 How it works

Installed programs enumeration

DriveSense reads the standard Uninstall registry keys:

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall

HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

It extracts DisplayName, InstallLocation, UninstallString, InstallDate, etc.

Last-used heuristic

Scans InstallLocation for .exe/.dll and derives the most recent access/mod time as a best-effort estimate of last use.

If InstallDate exists, uses it as fallback.

Uninstalling

Uses the UninstallString found in registry or msiexec /x <GUID> for MSI-based products.

Drives conservative behavior: interactive uninstall shown by default; no forced silent uninstalls unless explicitly requested.

Temp cleanup

Analyzes %TEMP%, %TMP%, and C:\Windows\Temp.

Moves files older than the configured threshold to quarantine by default.

Recycle Bin

Uses the Windows API (SHEmptyRecycleBinW) to empty the Recycle Bin when confirmed.

🖼 UI & modes

Tabs: Dashboard, Scan & Clean, Activity Log

Advanced settings: Dry-run toggle, Temp age threshold, Worker threads, Memory throttle (heuristic)

Visual: entries likely to be bloatware are highlighted

📦 Packaging & Control Panel stub (.cpl)

DriveSense can export a textual .cpl stub — this is a document saved with .cpl extension for packaging/testing only.

Real .cpl files are native DLLs and cannot be produced by pure Python. To add DriveSense to Control Panel in production:

Package the Python app into an EXE (PyInstaller / Briefcase / cx_Freeze).

Create an installer that registers a Control Panel item (or author a small native wrapper DLL exporting CPlApplet).

🧪 Development / Testing

Recommended workflow:

Run the app in dry-run and inspect the log.

Test temp cleanup on a disposable VM or sample folder.

Check quarantine contents and test restore by moving files back.

Only then, toggle real operations with Admin privileges.

📌 Roadmap / TODO

Add system restore creation before bulk operations.

Improve last-used detection using UserAssist / ShellMRU parsing.

Add optional silent uninstall and allow-list management.

Create an installer (signed) and provide packaging scripts.

Add unit tests and opt-in telemetry for crash reporting.

🤝 Contributing

Contributions welcome! Please:

Fork the repo and open a PR.

Keep safety first — do not add code that auto-deletes without explicit UI confirmation and quarantine.

Include tests for registry/file parsing logic.

If adding native DLLs or installers, include build scripts and security notes.

📝 License

Suggested: MIT License (add LICENSE file). Example header:

MIT License
Copyright (c) 2025 Blake Tepper
...


Replace with your preferred license in the repo.

🙏 Acknowledgements & references

Uses Windows API (SHEmptyRecycleBinW) via ctypes.

Installed-program enumeration uses standard Uninstall registry keys.

Avoids Win32_Product due to side effects — uses registry and msiexec heuristics.

✅ Copy-ready snippets

Badge header (paste at top):

<p align="center">
  <img src="https://img.shields.io/badge/status-alpha-orange" alt="status">
  <img src="https://img.shields.io/badge/platform-windows-blue" alt="platform">
  <img src="https://img.shields.io/badge/language-python-3.8+-brightgreen" alt="python">
</p>


Run command (paste into docs or GitHub Actions):

python drivesense_real.py
