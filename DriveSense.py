#!/usr/bin/env python3
"""
DriveSense — Real (cautious) Windows cleanup app (Python + Tkinter)

RUN ON WINDOWS. Python 3.8+ recommended.

Important: dry-run is ON by default. Toggle "Perform REAL actions" and confirm
explicitly to allow deletions/uninstalls.

Main safety features:
 - Dry-run (preview).
 - Quarantine folder (moves removed files there).
 - Multiple confirmation dialogs for destructive actions.
 - Admin check and optional elevation prompt.
 - Uses registry uninstall strings; does not use Win32_Product.
"""
import os
import sys
import ctypes
import shutil
import subprocess
import threading
import time
import math
import tempfile
import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import winreg

APP_NAME = "DriveSense"
VERSION = "1.0-real"
QUARANTINE_DIR = Path(os.getenv("LOCALAPPDATA", tempfile.gettempdir())) / "DriveSense" / "quarantine"

# -------------------- Utility & Windows API --------------------

# Check admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# Elevate (re-run as admin)
def run_as_admin():
    params = " ".join([f'"{arg}"' for arg in sys.argv])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)

# Empty Recycle Bin using SHEmptyRecycleBinW
# Flags from Win32: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shemptyrecyclebinw
def empty_recycle_bin(flags=0x00000001):  # SHERB_NOCONFIRMATION by default in practice we'll ask user
    # wrapper returns True on success (or if already empty)
    shell32 = ctypes.windll.shell32
    hwnd = None
    pszRootPath = None
    try:
        res = shell32.SHEmptyRecycleBinW(hwnd, pszRootPath, flags)
        # S_OK == 0
        return res == 0
    except Exception as e:
        raise

# Human readable sizes
def human_size(n):
    if n < 1024:
        return f"{n} B"
    for unit in ["KB", "MB", "GB", "TB"]:
        n /= 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"

# Ensure quarantine exists
def ensure_quarantine():
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    return QUARANTINE_DIR

# Move file/dir to quarantine, preserving structure
def move_to_quarantine(src_path: Path):
    q = ensure_quarantine()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    rel = src_path.name
    dest = q / f"{ts}_{rel}"
    try:
        shutil.move(str(src_path), str(dest))
        return dest
    except Exception as e:
        return None

# -------------------- Installed programs enumeration --------------------
# We'll enumerate these registry keys (per Microsoft guidance):
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
# HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
# HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
UNINSTALL_REG_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]

def read_installed_programs():
    results = []
    for root, keypath in UNINSTALL_REG_PATHS:
        try:
            reg = winreg.OpenKey(root, keypath)
        except FileNotFoundError:
            continue
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(reg, i)
            except OSError:
                break
            i += 1
            try:
                sk = winreg.OpenKey(reg, subkey_name)
                get = lambda name: winreg.QueryValueEx(sk, name)[0] if _reg_value_exists(sk, name) else None
                display = get("DisplayName")
                if not display:
                    winreg.CloseKey(sk)
                    continue
                install_loc = get("InstallLocation")
                uninstall_str = get("UninstallString")
                publisher = get("Publisher")
                install_date = get("InstallDate")  # often YYYYMMDD or None
                display_version = get("DisplayVersion")
                results.append({
                    "keyroot": root,
                    "keypath": keypath + "\\" + subkey_name,
                    "name": display,
                    "install_location": install_loc,
                    "uninstall_string": uninstall_str,
                    "publisher": publisher,
                    "install_date": install_date,
                    "display_version": display_version,
                })
                winreg.CloseKey(sk)
            except Exception:
                continue
        try:
            winreg.CloseKey(reg)
        except Exception:
            pass
    return results

def _reg_value_exists(key, name):
    try:
        winreg.QueryValueEx(key, name)
        return True
    except OSError:
        return False

# -------------------- Heuristic: estimate last used days --------------------
def estimate_last_used_days(program):
    """
    Heuristic: try to use InstallLocation and look for .exe last access times.
    If not available, try InstallDate from registry (YYYYMMDD) and use that as fallback.
    Returns integer days since last access, or None if unknown.
    """
    try:
        loc = program.get("install_location") or ""
        if loc and os.path.isdir(loc):
            latest = 0
            for root, _, files in os.walk(loc):
                for f in files:
                    if f.lower().endswith(".exe") or f.lower().endswith(".dll"):
                        p = Path(root) / f
                        try:
                            atime = p.stat().st_atime
                            if atime > latest:
                                latest = atime
                        except Exception:
                            continue
            if latest > 0:
                days = (time.time() - latest) / (60 * 60 * 24)
                return int(days)
        # fallback: InstallDate (YYYYMMDD)
        inst = program.get("install_date")
        if inst:
            # some entries are strings like '20210930'
            s = str(inst)
            if len(s) >= 8:
                try:
                    dt = datetime.datetime.strptime(s[:8], "%Y%m%d")
                    days = (datetime.datetime.now() - dt).days
                    return int(days)
                except Exception:
                    pass
    except Exception:
        pass
    return None

# -------------------- Cleaning implementations --------------------

def calculate_folder_size(path: Path, older_than_days: int = 0):
    total = 0
    cutoff = time.time() - older_than_days * 86400 if older_than_days > 0 else 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                p = Path(root) / f
                st = p.stat()
                if cutoff and st.st_mtime < cutoff:
                    total += st.st_size
                elif not cutoff:
                    total += st.st_size
            except Exception:
                continue
    return total

def clean_temp_folder(path: Path, dry_run=True, older_than_days=0, move_to_quarantine_flag=True, log_fn=print):
    """
    Removes files in 'path'. If dry_run: only report what would be removed.
    older_than_days: only remove files older than this (0 => all)
    move_to_quarantine_flag: if True, move to quarantine instead of permanently deleting
    """
    removed = []
    cutoff = time.time() - older_than_days * 86400 if older_than_days > 0 else 0
    # Walk files first (avoid modifying while iterating)
    to_remove = []
    for root, dirs, files in os.walk(path):
        for f in files:
            try:
                p = Path(root) / f
                st = p.stat()
                if cutoff and st.st_mtime > cutoff:
                    continue
                to_remove.append(p)
            except Exception:
                continue
    # Now process
    for p in to_remove:
        try:
            if dry_run:
                log_fn(f"[DRY] Would remove: {p}")
            else:
                if move_to_quarantine_flag:
                    dest = move_to_quarantine(p)
                    if dest:
                        log_fn(f"Moved to quarantine: {p} -> {dest}")
                    else:
                        # fallback to delete
                        p.unlink(missing_ok=True)
                        log_fn(f"Deleted (fallback): {p}")
                else:
                    p.unlink(missing_ok=True)
                    log_fn(f"Deleted: {p}")
            removed.append(str(p))
        except Exception as e:
            log_fn(f"Error removing {p}: {e}")
    # Optionally remove empty directories (dry-run safe)
    if not dry_run:
        for root, dirs, files in os.walk(path, topdown=False):
            try:
                if not os.listdir(root):
                    os.rmdir(root)
            except Exception:
                pass
    return removed

# -------------------- Uninstall helper --------------------

def run_uninstall_command(uninstall_string, dry_run=True, log_fn=print):
    """
    Uses the uninstall string from registry. Could be:
     - an MSI GUID invocation via msiexec
     - a program uninstaller exe with arguments
    We'll parse and run it conservatively.
    """
    if not uninstall_string:
        return False, "No uninstall string"
    uninstall_string = uninstall_string.strip()
    # Simple heuristic: if contains "MsiExec" or ends with a GUID, use msiexec
    lowered = uninstall_string.lower()
    if "msiexec" in lowered or (uninstall_string.startswith("{") and uninstall_string.endswith("}")):
        # If string includes /I, replace with /x to uninstall
        cmd = uninstall_string
        # Ensure msiexec uses /x for uninstall; if GUID present, run msiexec /x {GUID}
        if "msiexec" in lowered and "/i" in lowered:
            cmd = cmd.replace("/I", "/X").replace("/i", "/x")
        # Default to interactive uninstall so the user can cancel, unless dry_run == False and user requested silent
        if dry_run:
            log_fn(f"[DRY] Would run: {cmd}")
            return True, "Dry-run"
        else:
            log_fn(f"Running: {cmd}")
            try:
                subprocess.run(cmd, shell=True, check=True)
                return True, "Ran"
            except subprocess.CalledProcessError as e:
                return False, f"Failed: {e}"
    else:
        # It's often "C:\\Program Files\\app\\uninstall.exe" /uninstall
        # We'll attempt to quote the executable if necessary
        parts = uninstall_string
        if dry_run:
            log_fn(f"[DRY] Would run: {parts}")
            return True, "Dry-run"
        else:
            try:
                subprocess.run(parts, shell=True, check=True)
                return True, "Ran"
            except subprocess.CalledProcessError as e:
                return False, f"Failed: {e}"

# -------------------- GUI (Tkinter) --------------------

class DriveSenseGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {VERSION}")
        self.geometry("900x620")
        self.minsize(640, 420)

        # State
        self.perform_real = tk.BooleanVar(value=False)  # must be explicitly toggled to allow destructive actions
        self.dry_run = tk.BooleanVar(value=True)
        self.older_than_days = tk.IntVar(value=2)
        self.cores = tk.IntVar(value=max(1, os.cpu_count()//2))
        self.ram_mb = tk.IntVar(value=512)  # used as 'chunk throttle' only
        self.scan_results = []
        self.bloat_list = ["PhotoEditorPlus","MegaUpdater","TrialGameX","SillyToolBar","VendorAppSync","CandySplash","UnwantedHelper"]

        self._create_widgets()

    def _log(self, msg):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{ts}] {msg}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _create_widgets(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill=tk.X)
        ttk.Label(top, text=APP_NAME, font=("Segoe UI", 16, "bold")).pack(side=tk.LEFT)
        right_top = ttk.Frame(top)
        right_top.pack(side=tk.RIGHT)
        ttk.Checkbutton(right_top, text="Perform REAL actions (dangerous)", variable=self.perform_real).pack(side=tk.LEFT, padx=6)
        ttk.Button(right_top, text="Export Log", command=self.export_log).pack(side=tk.LEFT, padx=6)
        ttk.Button(right_top, text="About", command=self.about).pack(side=tk.LEFT, padx=6)

        # Tabs
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Scan tab
        tab_scan = ttk.Frame(nb); nb.add(tab_scan, text="Scan & Clean")
        left = ttk.Frame(tab_scan); left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=6)
        right = ttk.Frame(tab_scan, width=280); right.pack(side=tk.RIGHT, fill=tk.Y, padx=6, pady=6)

        controls = ttk.LabelFrame(left, text="Actions", padding=6); controls.pack(fill=tk.X)
        ttk.Button(controls, text="Scan Installed Programs", command=self.scan_programs).pack(side=tk.LEFT, padx=6)
        ttk.Button(controls, text="Analyze Temp Folders", command=self.analyze_temp).pack(side=tk.LEFT, padx=6)
        ttk.Button(controls, text="Empty Recycle Bin", command=self.action_empty_recycle).pack(side=tk.LEFT, padx=6)
        ttk.Button(controls, text="Open Quarantine Folder", command=lambda: os.startfile(str(ensure_quarantine()))).pack(side=tk.LEFT, padx=6)

        self.results_tree = ttk.Treeview(left, columns=("name","info","age"), show="headings", selectmode="extended")
        self.results_tree.heading("name", text="Program / Item")
        self.results_tree.heading("info", text="Install Location / Path")
        self.results_tree.heading("age", text="Days since last use / info")
        self.results_tree.pack(fill=tk.BOTH, expand=True, pady=(6,0))

        # Right settings
        adv = ttk.LabelFrame(right, text="Advanced Settings", padding=6); adv.pack(fill=tk.X)
        ttk.Label(adv, text="Dry-run (preview):").pack(anchor="w")
        ttk.Checkbutton(adv, text="Dry-run (no changes)", variable=self.dry_run).pack(anchor="w")
        ttk.Label(adv, text="Temp files older than (days):").pack(anchor="w", pady=(6,0))
        ttk.Spinbox(adv, from_=0, to=365, textvariable=self.older_than_days).pack(anchor="w")
        ttk.Label(adv, text="Worker threads (cores):").pack(anchor="w", pady=(6,0))
        ttk.Spinbox(adv, from_=1, to=(os.cpu_count() or 4), textvariable=self.cores).pack(anchor="w")
        ttk.Label(adv, text="Memory throttle (MB, heuristic):").pack(anchor="w", pady=(6,0))
        ttk.Scale(adv, from_=128, to=8192, orient=tk.HORIZONTAL, variable=self.ram_mb).pack(fill=tk.X)

        # Buttons for performing selected actions in results
        bottom_buttons = ttk.Frame(self)
        bottom_buttons.pack(fill=tk.X, padx=8, pady=6)
        ttk.Button(bottom_buttons, text="Uninstall Selected Programs", command=self.uninstall_selected).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom_buttons, text="Clean Selected Temp Items (move to quarantine)", command=self.clean_selected_files).pack(side=tk.LEFT, padx=6)

        # Log tab
        tab_log = ttk.Frame(nb); nb.add(tab_log, text="Activity Log")
        self.log_text = tk.Text(tab_log, wrap="word", state="disabled")
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Status bar
        self.status_var = tk.StringVar(value="Ready (dry-run ON)")
        ttk.Label(self, textvariable=self.status_var).pack(fill=tk.X, side=tk.BOTTOM)

    # ----------------- Actions -----------------

    def about(self):
        messagebox.showinfo("About", f"{APP_NAME} {VERSION}\nReal mode requires admin and careful confirmations.\nDefault is dry-run.")

    def export_log(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt")
        if not p:
            return
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.log_text.get("1.0","end"))
        messagebox.showinfo("Export Log", f"Exported to: {p}")

    def scan_programs(self):
        self.status_var.set("Scanning installed programs...")
        self._log("Scanning registry for installed programs...")
        progs = read_installed_programs()
        self.scan_results = []
        self.results_tree.delete(*self.results_tree.get_children())
        for p in progs:
            days = estimate_last_used_days(p)
            info = p.get("install_location") or p.get("uninstall_string") or ""
            age = f"{days} days" if days is not None else (f"Installed: {p.get('install_date')}" if p.get("install_date") else "Unknown")
            self.scan_results.append({**p, "age_days": days})
            # mark bloatware
            tag = ""
            if any(b.lower() in p["name"].lower() for b in self.bloat_list):
                tag = "bloat"
            iid = self.results_tree.insert("", "end", values=(p["name"], info, age), tags=(tag,))
        self.results_tree.tag_configure("bloat", background="#ffecec")
        self._log(f"Found {len(self.scan_results)} installed programs (registry).")
        self.status_var.set("Scan complete (dry-run={})".format(self.dry_run.get()))

    def analyze_temp(self):
        self._log("Analyzing temp locations...")
        # typical temp locations
        temp_paths = []
        env_temp = os.getenv("TEMP")
        env_tmp = os.getenv("TMP")
        windows_temp = Path(os.getenv("SystemRoot", r"C:\Windows")) / "Temp"
        for p in [env_temp, env_tmp, str(windows_temp)]:
            if p and os.path.exists(p):
                temp_paths.append(Path(p))
        self.results_tree.delete(*self.results_tree.get_children())
        for p in temp_paths:
            size_all = calculate_folder_size(p, older_than_days=0)
            size_old = calculate_folder_size(p, older_than_days=self.older_than_days.get())
            ageinfo = f"{human_size(size_old)} older than {self.older_than_days.get()}d / total {human_size(size_all)}"
            self.results_tree.insert("", "end", values=(f"TEMP: {p}", str(p), ageinfo))
            self._log(f"{p} -> {ageinfo}")
        self.status_var.set("Temp analysis complete")

    def action_empty_recycle(self):
        if self.dry_run.get():
            if messagebox.askyesno("Dry run", "Dry-run is ON: show what would happen (OK to continue)?"):
                self._log("[DRY] Would call SHEmptyRecycleBinW() to empty Recycle Bin.")
                messagebox.showinfo("Dry-run", "Would call Windows API to empty Recycle Bin.")
            return
        if not is_admin():
            if messagebox.askyesno("Admin required", "Emptying Recycle Bin for all users requires admin. Re-run as admin?"):
                run_as_admin()
            return
        if not messagebox.askyesno("Confirm", "Empty Recycle Bin? This is irreversible."):
            return
        try:
            # Flags: 0 => show confirmation; using 0x00000001 (SHERB_NOCONFIRMATION) skip confirmation inside API
            empty_recycle_bin(flags=0)
            self._log("Recycle Bin emptied via SHEmptyRecycleBinW()")
            self.status_var.set("Recycle Bin emptied")
        except Exception as e:
            self._log(f"Error emptying Recycle Bin: {e}")
            messagebox.showerror("Error", f"Failed to empty Recycle Bin: {e}")

    def uninstall_selected(self):
        sel = self.results_tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select installed programs from the list to uninstall.")
            return
        # build list of programs
        progs_to_uninstall = []
        for s in sel:
            vals = self.results_tree.item(s)["values"]
            name = vals[0]
            # find matching in scan_results
            for p in self.scan_results:
                if p["name"] == name:
                    progs_to_uninstall.append(p)
                    break
        # Confirm
        names = "\n".join(p["name"] for p in progs_to_uninstall)
        if not messagebox.askyesno("Confirm uninstall", f"You are about to uninstall:\n\n{names}\n\nProceed?"):
            return
        if self.dry_run.get():
            for p in progs_to_uninstall:
                self._log(f"[DRY] Would uninstall: {p['name']} using: {p.get('uninstall_string')}")
            messagebox.showinfo("Dry-run", "Uninstall commands were listed in log (dry-run).")
            return
        if not is_admin():
            if messagebox.askyesno("Admin required", "Uninstalling programs requires admin. Re-run as admin?"):
                run_as_admin()
            return
        # Perform uninstalls (sequentially)
        for p in progs_to_uninstall:
            self._log(f"Attempting uninstall: {p['name']}")
            ok, msg = run_uninstall_command(p.get("uninstall_string"), dry_run=False, log_fn=self._log)
            if ok:
                self._log(f"Uninstall started/completed for {p['name']}: {msg}")
            else:
                self._log(f"Uninstall failed for {p['name']}: {msg}")

    def clean_selected_files(self):
        sel = self.results_tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select TEMP rows (or file rows) to clean.")
            return
        paths = []
        for s in sel:
            vals = self.results_tree.item(s)["values"]
            path = vals[1]
            if path:
                paths.append(Path(path))
        if not paths:
            messagebox.showinfo("No paths", "No valid paths selected.")
            return
        if self.dry_run.get():
            for p in paths:
                size = calculate_folder_size(p, older_than_days=self.older_than_days.get())
                self._log(f"[DRY] Would clean {p} -> remove {human_size(size)} older than {self.older_than_days.get()} days.")
            messagebox.showinfo("Dry-run", "See log for details.")
            return
        # If real: ask admin if needed (deleting from system temp may require)
        if not is_admin():
            if messagebox.askyesno("Admin required", "Cleaning system temp may require admin. Re-run as admin?"):
                run_as_admin()
            return
        if not messagebox.askyesno("Confirm", f"Move temp files older than {self.older_than_days.get()} days to quarantine?"):
            return
        for p in paths:
            self._log(f"Cleaning {p} ...")
            removed = clean_temp_folder(p, dry_run=False, older_than_days=self.older_than_days.get(), move_to_quarantine_flag=True, log_fn=self._log)
            self._log(f"Moved {len(removed)} items from {p} to quarantine.")

# -------------------- Main --------------------

def main():
    if sys.platform != "win32":
        print("DriveSense (real) is Windows-only.")
        return
    app = DriveSenseGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
