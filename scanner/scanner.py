"""
DataSentry Scanner Agent
Cross-platform data discovery tool for Windows and macOS.
Detects storage locations, scans file content for PII,
and reports to the DataSentry cloud dashboard.

Usage:
    python scanner.py --api-url https://your-backend.com --api-key YOUR_KEY
    python scanner.py --output local   # write results to JSON file instead

Packaging:
    pyinstaller --onefile --windowed scanner.py
"""

import os
import sys
import re
import json
import platform
import socket
import hashlib
import getpass
import argparse
import logging
import struct
import math
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Optional dependencies (graceful fallback if not installed) ─────────────────
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import docx  # python-docx
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False

try:
    import openpyxl
    HAS_XLSX = True
except ImportError:
    HAS_XLSX = False

try:
    import pdfminer.high_level as pdfminer
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    HAS_TK = True
except ImportError:
    HAS_TK = False

# ─────────────────────────────────────────────────────────────────────────────
# PII PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

PII_PATTERNS = {
    "email": re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    ),
    "uk_phone": re.compile(
        r'\b(?:(?:\+44|0044|0)[\s\-]?(?:\d[\s\-]?){9,10})\b'
    ),
    "us_phone": re.compile(
        r'\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b'
    ),
    "credit_card": re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?'      # Visa
        r'|5[1-5][0-9]{14}'                   # Mastercard
        r'|3[47][0-9]{13}'                    # Amex
        r'|6(?:011|5[0-9]{2})[0-9]{12})\b'   # Discover
    ),
    "uk_nino": re.compile(
        r'\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[ABCD]\b',
        re.IGNORECASE
    ),
    "uk_nhs": re.compile(
        r'\b\d{3}\s?\d{3}\s?\d{4}\b'
    ),
    "passport": re.compile(
        r'\b[A-Z]{2}\d{6,7}\b'
    ),
    "sort_code": re.compile(
        r'\b\d{2}[-\s]?\d{2}[-\s]?\d{2}\b'
    ),
    "uk_bank_account": re.compile(
        r'\b\d{8}\b'
    ),
    "iban": re.compile(
        r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b'
    ),
    "ip_address": re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ),
    "date_of_birth": re.compile(
        r'\b(?:0?[1-9]|[12]\d|3[01])[\s/\-.](?:0?[1-9]|1[0-2])[\s/\-.](?:19|20)\d{2}\b'
    ),
    "postcode": re.compile(
        r'\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b',
        re.IGNORECASE
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# STORAGE LOCATION DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def get_windows_locations() -> list[dict]:
    """Discover all relevant storage locations on Windows."""
    locations = []
    home = Path.home()

    # Standard local folders
    local_dirs = [
        ("My Documents", home / "Documents"),
        ("Desktop",      home / "Desktop"),
        ("Downloads",    home / "Downloads"),
        ("Pictures",     home / "Pictures"),
        ("Videos",       home / "Videos"),
    ]
    for label, path in local_dirs:
        if path.exists():
            locations.append({"label": label, "path": str(path), "type": "local"})

    # OneDrive personal
    onedrive_personal = home / "OneDrive"
    if onedrive_personal.exists():
        locations.append({"label": "OneDrive Personal", "path": str(onedrive_personal), "type": "onedrive"})

    # OneDrive for Business / SharePoint (multiple tenants)
    for p in home.glob("OneDrive - *"):
        if p.is_dir():
            tenant = p.name.replace("OneDrive - ", "")
            locations.append({
                "label": f"OneDrive for Business ({tenant})",
                "path": str(p),
                "type": "onedrive_business"
            })

    # Dropbox — read config file for actual path
    dropbox_info = Path(os.environ.get("APPDATA", "")) / "Dropbox" / "info.json"
    if dropbox_info.exists():
        try:
            with open(dropbox_info) as f:
                db_config = json.load(f)
            for account_type in ("personal", "business"):
                if account_type in db_config:
                    db_path = Path(db_config[account_type]["path"])
                    if db_path.exists():
                        locations.append({
                            "label": f"Dropbox ({account_type.capitalize()})",
                            "path": str(db_path),
                            "type": "dropbox"
                        })
        except Exception:
            pass
    else:
        # Fallback: common Dropbox paths
        for fallback in [home / "Dropbox", home / "Dropbox (Personal)", home / "Dropbox (Business)"]:
            if fallback.exists():
                locations.append({"label": f"Dropbox ({fallback.name})", "path": str(fallback), "type": "dropbox"})

    # Google Drive — registry or common path
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Google\DriveFS")
        gdrive_path = winreg.QueryValueEx(key, "DefaultMountPoint")[0]
        if Path(gdrive_path).exists():
            locations.append({"label": "Google Drive", "path": gdrive_path, "type": "google_drive"})
        winreg.CloseKey(key)
    except Exception:
        for fallback in [home / "Google Drive", home / "My Drive"]:
            if fallback.exists():
                locations.append({"label": "Google Drive", "path": str(fallback), "type": "google_drive"})

    # Box Drive
    box_path = home / "Box"
    if box_path.exists():
        locations.append({"label": "Box Drive", "path": str(box_path), "type": "box"})

    # Mapped network drives (Windows only)
    if sys.platform == "win32":
        try:
            import subprocess
            result = subprocess.run(["net", "use"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.splitlines():
                # Parse "OK   X:   \\server\share"
                parts = line.split()
                if len(parts) >= 3 and ":" in parts[1] and parts[2].startswith("\\\\"):
                    drive_letter = parts[1]
                    unc_path = parts[2]
                    locations.append({
                        "label": f"Network Drive {drive_letter} ({unc_path})",
                        "path": drive_letter + "\\",
                        "type": "network_drive",
                        "unc_path": unc_path
                    })
        except Exception:
            pass

    return locations


def get_macos_locations() -> list[dict]:
    """Discover all relevant storage locations on macOS."""
    locations = []
    home = Path.home()

    local_dirs = [
        ("Documents", home / "Documents"),
        ("Desktop",   home / "Desktop"),
        ("Downloads", home / "Downloads"),
        ("Pictures",  home / "Pictures"),
        ("Movies",    home / "Movies"),
    ]
    for label, path in local_dirs:
        if path.exists():
            locations.append({"label": label, "path": str(path), "type": "local"})

    # iCloud Drive
    icloud = home / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
    if icloud.exists():
        locations.append({"label": "iCloud Drive", "path": str(icloud), "type": "icloud"})

    # CloudStorage (modern macOS mounts: OneDrive, Google Drive, Dropbox)
    cloud_storage = home / "Library" / "CloudStorage"
    if cloud_storage.exists():
        for p in cloud_storage.iterdir():
            if p.is_dir():
                name = p.name
                if "OneDrive" in name:
                    svc = "onedrive_business" if "-" in name else "onedrive"
                    label = name.replace("OneDrive-", "OneDrive for Business (").rstrip() + (")" if "-" in name else "")
                elif "GoogleDrive" in name:
                    svc = "google_drive"
                    label = "Google Drive"
                elif "Dropbox" in name:
                    svc = "dropbox"
                    label = "Dropbox"
                elif "Box" in name:
                    svc = "box"
                    label = "Box Drive"
                else:
                    svc = "cloud_sync"
                    label = name
                locations.append({"label": label, "path": str(p), "type": svc})

    # Dropbox legacy path
    dropbox_info = home / ".dropbox" / "info.json"
    if dropbox_info.exists():
        try:
            with open(dropbox_info) as f:
                db_config = json.load(f)
            for acct_type in ("personal", "business"):
                if acct_type in db_config:
                    db_path = Path(db_config[acct_type]["path"])
                    if db_path.exists():
                        label = f"Dropbox ({acct_type.capitalize()})"
                        if not any(l["path"] == str(db_path) for l in locations):
                            locations.append({"label": label, "path": str(db_path), "type": "dropbox"})
        except Exception:
            pass

    # Network mounts
    volumes = Path("/Volumes")
    if volumes.exists():
        for vol in volumes.iterdir():
            if vol.is_dir() and vol.name not in ("Macintosh HD", "Data"):
                locations.append({
                    "label": f"Network/External: {vol.name}",
                    "path": str(vol),
                    "type": "network_drive"
                })

    return locations


def discover_storage_locations() -> list[dict]:
    """Return all discovered storage locations for the current OS."""
    if sys.platform == "win32":
        return get_windows_locations()
    elif sys.platform == "darwin":
        return get_macos_locations()
    else:
        # Linux fallback
        home = Path.home()
        locs = []
        for label, subdir in [("Home", home), ("Documents", home / "Documents"),
                               ("Desktop", home / "Desktop"), ("Downloads", home / "Downloads")]:
            if subdir.exists():
                locs.append({"label": label, "path": str(subdir), "type": "local"})
        return locs

# ─────────────────────────────────────────────────────────────────────────────
# FILE CONTENT EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

MAX_FILE_SIZE_MB = 50  # skip files larger than this
SCAN_EXTENSIONS = {
    ".txt", ".csv", ".tsv", ".log", ".xml", ".json", ".html", ".htm",
    ".md", ".rtf", ".msg",
    ".docx", ".xlsx", ".pptx",
    ".pdf",
    ".eml",
}

def extract_text(file_path: Path) -> str:
    """Extract plain text from supported file types."""
    ext = file_path.suffix.lower()
    try:
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        if file_size_mb > MAX_FILE_SIZE_MB:
            return ""

        if ext in (".txt", ".csv", ".tsv", ".log", ".md", ".rtf", ".xml", ".json", ".eml"):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()

        elif ext in (".html", ".htm"):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
            # Strip HTML tags
            return re.sub(r"<[^>]+>", " ", raw)

        elif ext == ".docx" and HAS_DOCX:
            doc = docx.Document(str(file_path))
            return "\n".join(p.text for p in doc.paragraphs)

        elif ext == ".xlsx" and HAS_XLSX:
            wb = openpyxl.load_workbook(str(file_path), read_only=True, data_only=True)
            texts = []
            for ws in wb.worksheets:
                for row in ws.iter_rows(values_only=True):
                    texts.append(" ".join(str(c) for c in row if c is not None))
            return "\n".join(texts)

        elif ext == ".pdf" and HAS_PDF:
            return pdfminer.extract_text(str(file_path)) or ""

        elif ext == ".msg":
            # Simplified: treat as binary and look for text
            with open(file_path, "rb") as f:
                raw = f.read()
            return raw.decode("utf-8", errors="ignore")

    except Exception:
        pass
    return ""


def scan_for_pii(text: str) -> dict[str, int]:
    """Return counts of each PII type found in text."""
    findings = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            findings[pii_type] = len(matches)
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# LOCATION SCANNER
# ─────────────────────────────────────────────────────────────────────────────

IGNORE_DIRS = {
    ".git", "__pycache__", "node_modules", ".vs", ".idea",
    "AppData", "Application Data", "Library", "System Volume Information",
    "$Recycle.Bin", "Windows",
}

def human_size(size_bytes: int) -> str:
    if size_bytes == 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    i = min(i, len(units) - 1)
    p = math.pow(1024, i)
    return f"{size_bytes / p:.1f} {units[i]}"


def scan_location(location: dict, progress_cb=None) -> dict:
    """Walk a directory and collect file metadata + PII findings."""
    root = Path(location["path"])
    file_type_counts: dict[str, int] = {}
    file_type_sizes: dict[str, int] = {}
    total_files = 0
    total_size = 0
    pii_findings: dict[str, int] = {}
    pii_files: list[dict] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune ignored directories
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]

        for fname in filenames:
            fp = Path(dirpath) / fname
            try:
                stat = fp.stat()
                size = stat.st_size
                ext = fp.suffix.lower() or "(no ext)"

                total_files += 1
                total_size += size
                file_type_counts[ext] = file_type_counts.get(ext, 0) + 1
                file_type_sizes[ext] = file_type_sizes.get(ext, 0) + size

                if progress_cb:
                    progress_cb(f"Scanning: {fp.name[:60]}")

                # Full content scan
                if ext in SCAN_EXTENSIONS:
                    text = extract_text(fp)
                    if text:
                        file_pii = scan_for_pii(text)
                        if file_pii:
                            # Accumulate totals
                            for pii_type, count in file_pii.items():
                                pii_findings[pii_type] = pii_findings.get(pii_type, 0) + count
                            pii_files.append({
                                "path": str(fp.relative_to(root)),
                                "size_bytes": size,
                                "pii_types": file_pii,
                                "total_pii_count": sum(file_pii.values()),
                            })

            except (PermissionError, OSError):
                continue

    # Top file types by count
    top_extensions = sorted(
        [{"ext": k, "count": v, "size_bytes": file_type_sizes[k]}
         for k, v in file_type_counts.items()],
        key=lambda x: x["count"], reverse=True
    )[:25]

    # Top PII files
    top_pii_files = sorted(pii_files, key=lambda x: x["total_pii_count"], reverse=True)[:50]

    return {
        "label": location["label"],
        "type": location["type"],
        "path": location["path"],
        "unc_path": location.get("unc_path"),
        "total_files": total_files,
        "total_size_bytes": total_size,
        "total_size_human": human_size(total_size),
        "top_extensions": top_extensions,
        "pii_summary": pii_findings,
        "pii_file_count": len(pii_files),
        "top_pii_files": top_pii_files,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
    }


# ─────────────────────────────────────────────────────────────────────────────
# MACHINE INFO
# ─────────────────────────────────────────────────────────────────────────────

def get_machine_info() -> dict:
    """Collect identifying info about this machine."""
    hostname = socket.gethostname()
    username = getpass.getuser()
    # Stable machine ID from hostname+username hash
    machine_id = hashlib.sha256(f"{hostname}:{username}".encode()).hexdigest()[:16]
    return {
        "machine_id": machine_id,
        "hostname": hostname,
        "username": username,
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# REPORT SUBMISSION
# ─────────────────────────────────────────────────────────────────────────────

def submit_report(report: dict, api_url: str, api_key: str) -> bool:
    """POST the scan report to the DataSentry backend."""
    if not HAS_REQUESTS:
        print("ERROR: 'requests' library not installed — cannot submit to API.")
        return False
    try:
        resp = requests.post(
            f"{api_url.rstrip('/')}/api/scans",
            json=report,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            timeout=60,
        )
        resp.raise_for_status()
        return True
    except Exception as e:
        print(f"ERROR submitting report: {e}")
        return False


def save_local_report(report: dict, output_path: str):
    """Write report to a local JSON file."""
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Report saved to: {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(api_url: Optional[str] = None, api_key: Optional[str] = None,
             output: Optional[str] = None, progress_cb=None,
             customer_id: Optional[str] = None, customer_name: Optional[str] = None):
    """Main scan routine. Returns the completed report dict."""
    machine = get_machine_info()
    locations = discover_storage_locations()

    if progress_cb:
        progress_cb(f"Found {len(locations)} storage location(s) to scan")

    location_results = []
    for i, loc in enumerate(locations):
        if progress_cb:
            progress_cb(f"[{i+1}/{len(locations)}] Scanning {loc['label']} ...")
        result = scan_location(loc, progress_cb=progress_cb)
        location_results.append(result)

    report = {
        "machine": machine,
        "customer": {
            "id":   customer_id   or os.environ.get("DATASENTRY_CUSTOMER_ID", ""),
            "name": customer_name or os.environ.get("DATASENTRY_CUSTOMER_NAME", ""),
        },
        "scan_started_at": datetime.utcnow().isoformat() + "Z",
        "locations": location_results,
        "summary": {
            "total_locations": len(location_results),
            "total_files": sum(r["total_files"] for r in location_results),
            "total_size_bytes": sum(r["total_size_bytes"] for r in location_results),
            "total_pii_files": sum(r["pii_file_count"] for r in location_results),
            "capabilities": {
                "docx": HAS_DOCX,
                "xlsx": HAS_XLSX,
                "pdf": HAS_PDF,
            }
        }
    }

    # Submission
    if api_url and api_key:
        if progress_cb:
            progress_cb("Submitting report to DataSentry cloud...")
        ok = submit_report(report, api_url, api_key)
        report["submitted"] = ok
    elif output:
        save_local_report(report, output)
    else:
        # Default: local file next to script
        default_out = f"datasentry_report_{machine['hostname']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_local_report(report, default_out)

    return report


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG FILE  (read datasentry.cfg alongside EXE, or from AppData/home)
# ─────────────────────────────────────────────────────────────────────────────

import configparser

def _config_dir() -> Path:
    """Return the platform-appropriate config directory."""
    if platform.system() == "Windows":
        return Path(os.environ.get("APPDATA", Path.home())) / "DataSentry"
    elif platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "DataSentry"
    else:
        return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "datasentry"


def _exe_dir() -> Path:
    """Return the directory containing the running EXE (or script)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def load_config() -> dict:
    """
    Load configuration from (in priority order):
      1. datasentry.cfg alongside the EXE  (portal-generated pre-configured install)
      2. Platform config dir  (saved by the wizard on a previous run)
      3. Environment variables
    Returns a dict with keys: api_url, api_key, customer_id, customer_name.
    Missing keys will be empty strings (caller must prompt for them).
    """
    cfg = configparser.ConfigParser()

    # Search locations
    search = [
        _exe_dir() / "datasentry.cfg",
        _config_dir() / "config.ini",
    ]
    cfg.read([str(p) for p in search if p.exists()])

    section = "datasentry" if cfg.has_section("datasentry") else "DEFAULT"

    def g(key):
        return cfg.get(section, key, fallback="").strip()

    return {
        "api_url":       g("api_url")       or os.environ.get("DATASENTRY_API_URL",       ""),
        "api_key":       g("api_key")        or os.environ.get("DATASENTRY_API_KEY",       ""),
        "customer_id":   g("customer_id")   or os.environ.get("DATASENTRY_CUSTOMER_ID",   ""),
        "customer_name": g("customer_name") or os.environ.get("DATASENTRY_CUSTOMER_NAME", ""),
    }


def save_config(api_url: str, api_key: str, customer_id: str, customer_name: str):
    """Persist config to the platform config directory."""
    config_path = _config_dir() / "config.ini"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    cfg = configparser.ConfigParser()
    cfg["datasentry"] = {
        "api_url":       api_url,
        "api_key":       api_key,
        "customer_id":   customer_id,
        "customer_name": customer_name,
    }
    with open(config_path, "w") as f:
        cfg.write(f)


def _slug(name: str) -> str:
    """Convert a display name to a URL-safe customer ID slug."""
    import re as _re
    return _re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "customer"


# ─────────────────────────────────────────────────────────────────────────────
# SETUP WIZARD  (Tkinter multi-step)
# ─────────────────────────────────────────────────────────────────────────────

NAV  = "#0D1E30"   # dark navy — sidebar colour
TEAL = "#00C49A"   # accent
WHITE = "#FFFFFF"
GREY  = "#EEF3F8"
TEXT  = "#0A1B2A"
TEXT2 = "#4A6A82"


def run_wizard(prefill: dict) -> Optional[dict]:
    """
    Multi-step setup wizard.  Returns a dict with api_url, api_key,
    customer_id, customer_name — or None if the user cancelled.
    """
    if not HAS_TK:
        return None

    result = {}

    root = tk.Tk()
    root.title("DataSentry Setup")
    root.geometry("520x420")
    root.resizable(False, False)
    root.configure(bg=WHITE)

    # ── Shared layout helpers ─────────────────────────────────────────────────
    current_frame = [None]

    def clear():
        if current_frame[0]:
            current_frame[0].destroy()

    def show(frame):
        clear()
        current_frame[0] = frame
        frame.pack(fill="both", expand=True)

    def header_band(title: str, subtitle: str = ""):
        band = tk.Frame(root, bg=NAV, height=82)
        band.pack(fill="x")
        band.pack_propagate(False)
        tk.Label(band, text="DataSentry", font=("Helvetica", 11, "bold"),
                 bg=NAV, fg=TEAL).pack(anchor="w", padx=24, pady=(16, 0))
        tk.Label(band, text=title, font=("Helvetica", 17, "bold"),
                 bg=NAV, fg=WHITE).pack(anchor="w", padx=24)
        if subtitle:
            tk.Label(band, text=subtitle, font=("Helvetica", 10),
                     bg=NAV, fg="#8AAABB").pack(anchor="w", padx=24)
        return band

    def field(parent, label: str, placeholder: str = "", show_char: str = "",
              initial: str = "") -> tk.StringVar:
        tk.Label(parent, text=label, font=("Helvetica", 10, "bold"),
                 bg=WHITE, fg=TEXT, anchor="w").pack(fill="x", padx=28, pady=(14, 2))
        var = tk.StringVar(value=initial)
        e = tk.Entry(parent, textvariable=var, font=("Helvetica", 11),
                     relief="flat", bg=GREY, fg=TEXT, show=show_char,
                     insertbackground=TEXT)
        e.pack(fill="x", padx=28, ipady=8)
        e.configure(highlightthickness=1, highlightbackground="#C8D8E8",
                    highlightcolor=TEAL)
        if placeholder and not initial:
            e.insert(0, placeholder)
            e.configure(fg=TEXT2)
            def _focus_in(ev, entry=e, v=var, ph=placeholder):
                if v.get() == ph:
                    entry.delete(0, "end")
                    entry.configure(fg=TEXT)
            def _focus_out(ev, entry=e, v=var, ph=placeholder):
                if not v.get():
                    entry.insert(0, ph)
                    entry.configure(fg=TEXT2)
            e.bind("<FocusIn>",  _focus_in)
            e.bind("<FocusOut>", _focus_out)
        return var

    def note(parent, text: str):
        tk.Label(parent, text=text, font=("Helvetica", 9), bg=WHITE, fg=TEXT2,
                 wraplength=460, justify="left", anchor="w").pack(fill="x", padx=28, pady=(4, 0))

    def btn_row(parent, primary_text: str, primary_cmd, secondary_text: str = "",
                secondary_cmd=None):
        row = tk.Frame(parent, bg=WHITE)
        row.pack(fill="x", padx=28, pady=18)
        if secondary_text and secondary_cmd:
            tk.Button(row, text=secondary_text, command=secondary_cmd,
                      bg=WHITE, fg=TEXT2, relief="flat", font=("Helvetica", 10),
                      cursor="hand2").pack(side="left")
        tk.Button(row, text=primary_text, command=primary_cmd,
                  bg=TEAL, fg=NAV, relief="flat", font=("Helvetica", 11, "bold"),
                  padx=24, pady=8, cursor="hand2",
                  activebackground="#00A87E", activeforeground=NAV).pack(side="right")

    # ── Step 1: Server URL ────────────────────────────────────────────────────
    def step1():
        f = tk.Frame(root, bg=WHITE)
        header_band("Connect to DataSentry", "Where is your DataSentry server hosted?")
        url_var = field(f, "Server URL",
                        placeholder="https://datasentry.up.railway.app",
                        initial=prefill.get("api_url", ""))
        note(f, "This is the address of your DataSentry backend. "
                "Your IT administrator or the person who set up DataSentry "
                "will have given this to you.")
        err_var = tk.StringVar()
        tk.Label(f, textvariable=err_var, font=("Helvetica", 9),
                 bg=WHITE, fg="#C0392B", anchor="w").pack(fill="x", padx=28)

        def next_step():
            url = url_var.get().strip()
            if not url or url == "https://datasentry.up.railway.app":
                err_var.set("Please enter your server URL.")
                return
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            result["api_url"] = url.rstrip("/")
            step2()

        btn_row(f, "Next →", next_step, "Cancel", root.destroy)
        show(f)

    # ── Step 2: Company details ───────────────────────────────────────────────
    def step2():
        f = tk.Frame(root, bg=WHITE)
        header_band("Your Organisation", "Tell us who this machine belongs to.")
        name_var = field(f, "Company name",
                         placeholder="Acme Corporation Ltd",
                         initial=prefill.get("customer_name", ""))
        note(f, "This is used to group this machine with others in your "
                "organisation on the DataSentry dashboard.")

        id_label_var = tk.StringVar()
        id_frame = tk.Frame(f, bg=WHITE)
        id_frame.pack(fill="x", padx=28, pady=(10, 0))
        tk.Label(id_frame, text="Customer ID (auto-generated):",
                 font=("Helvetica", 9), bg=WHITE, fg=TEXT2).pack(side="left")
        tk.Label(id_frame, textvariable=id_label_var, font=("Helvetica", 9, "bold"),
                 bg=WHITE, fg=TEAL).pack(side="left", padx=6)

        def _update_id(*_):
            n = name_var.get().strip()
            if n and n != "Acme Corporation Ltd":
                id_label_var.set(_slug(n))
            else:
                id_label_var.set("")
        name_var.trace_add("write", _update_id)
        if prefill.get("customer_id"):
            id_label_var.set(prefill["customer_id"])

        err_var = tk.StringVar()
        tk.Label(f, textvariable=err_var, font=("Helvetica", 9),
                 bg=WHITE, fg="#C0392B", anchor="w").pack(fill="x", padx=28)

        def next_step():
            name = name_var.get().strip()
            if not name or name == "Acme Corporation Ltd":
                err_var.set("Please enter your company name.")
                return
            result["customer_name"] = name
            result["customer_id"]   = prefill.get("customer_id") or _slug(name)
            step3()

        btn_row(f, "Next →", next_step, "← Back", step1)
        show(f)

    # ── Step 3: API key ───────────────────────────────────────────────────────
    def step3():
        f = tk.Frame(root, bg=WHITE)
        header_band("API Key", "Authenticate with your DataSentry server.")
        key_var = field(f, "API Key",
                        placeholder="dsk_xxxxxxxxxxxxxxxxxxxxxx",
                        initial=prefill.get("api_key", ""))
        note(f, "Your administrator generated this key when they created "
                "your account. Find it in the DataSentry portal under "
                "Settings → Agent Keys, or ask the person who set up DataSentry.")

        err_var = tk.StringVar()
        tk.Label(f, textvariable=err_var, font=("Helvetica", 9),
                 bg=WHITE, fg="#C0392B", anchor="w").pack(fill="x", padx=28)

        def start():
            key = key_var.get().strip()
            if not key or key == "dsk_xxxxxxxxxxxxxxxxxxxxxx":
                err_var.set("Please enter your API key.")
                return
            if not key.startswith("dsk_"):
                err_var.set("API keys start with  dsk_  — please check and try again.")
                return
            result["api_key"] = key
            save_config(result["api_url"], result["api_key"],
                        result["customer_id"], result["customer_name"])
            step_scan()

        btn_row(f, "Start Scan", start, "← Back", step2)
        show(f)

    # ── Step 4: Scanning ──────────────────────────────────────────────────────
    def step_scan():
        f = tk.Frame(root, bg=WHITE)
        header_band("Scanning…", "Discovering and analysing your data locations.")

        status_var = tk.StringVar(value="Starting…")
        tk.Label(f, textvariable=status_var, font=("Helvetica", 10),
                 bg=WHITE, fg=TEXT2, wraplength=460, anchor="w").pack(fill="x", padx=28, pady=(16, 4))

        bar = ttk.Progressbar(f, mode="indeterminate", length=464)
        bar.pack(padx=28, pady=4)
        bar.start(12)

        log_frame = tk.Frame(f, bg=GREY)
        log_frame.pack(fill="both", expand=True, padx=28, pady=10)
        sb = tk.Scrollbar(log_frame)
        sb.pack(side="right", fill="y")
        log_box = tk.Text(log_frame, height=9, yscrollcommand=sb.set,
                          state="disabled", bg=GREY, fg=TEXT2,
                          font=("Courier", 8), relief="flat", padx=8, pady=6)
        log_box.pack(fill="both", expand=True)
        sb.config(command=log_box.yview)

        def append(msg: str):
            log_box.config(state="normal")
            log_box.insert("end", msg + "\n")
            log_box.see("end")
            log_box.config(state="disabled")
            status_var.set(msg[:80] + ("…" if len(msg) > 80 else ""))
            root.update_idletasks()

        def worker():
            import threading
            rep = run_scan(
                api_url=result.get("api_url"),
                api_key=result.get("api_key"),
                customer_id=result.get("customer_id"),
                customer_name=result.get("customer_name"),
                progress_cb=append,
            )
            root.after(0, lambda: step_done(rep))

        show(f)
        import threading
        threading.Thread(target=worker, daemon=True).start()

    # ── Step 5: Done ──────────────────────────────────────────────────────────
    def step_done(report: dict):
        f = tk.Frame(root, bg=WHITE)
        band = tk.Frame(root, bg="#00A87E", height=82)
        band.pack(fill="x")
        band.pack_propagate(False)
        tk.Label(band, text="✓  Scan complete", font=("Helvetica", 17, "bold"),
                 bg="#00A87E", fg=WHITE).pack(anchor="w", padx=24, pady=24)

        summary = report.get("summary", {})
        stats = [
            ("Files scanned",      f"{summary.get('total_files', 0):,}"),
            ("Storage locations",  str(summary.get("total_locations", 0))),
            ("Files containing PII", f"{summary.get('total_pii_files', 0):,}"),
        ]
        for label, value in stats:
            row = tk.Frame(f, bg=WHITE)
            row.pack(fill="x", padx=28, pady=3)
            tk.Label(row, text=label + ":", font=("Helvetica", 10),
                     bg=WHITE, fg=TEXT2).pack(side="left")
            tk.Label(row, text=value, font=("Helvetica", 10, "bold"),
                     bg=WHITE, fg=TEXT).pack(side="left", padx=8)

        submitted = report.get("submitted", False)
        msg = ("Results sent to your DataSentry dashboard. ✓"
               if submitted else "Results saved locally.")
        tk.Label(f, text=msg, font=("Helvetica", 10), bg=WHITE, fg=TEXT2,
                 wraplength=460, anchor="w").pack(fill="x", padx=28, pady=(16, 0))

        btn_row(f, "Close", root.destroy,
                "Scan Again", lambda: (clear(), step_scan()))
        show(f)

    # ── Start ─────────────────────────────────────────────────────────────────
    step1()
    root.mainloop()
    return result if "api_url" in result else None


# ─────────────────────────────────────────────────────────────────────────────
# QUICK PROGRESS WINDOW  (for pre-configured silent runs — no wizard)
# ─────────────────────────────────────────────────────────────────────────────

def run_gui(api_url: str, api_key: str, customer_id: str = "", customer_name: str = ""):
    """Progress window shown when config is already known — no setup steps."""
    if not HAS_TK:
        run_scan(api_url=api_url, api_key=api_key,
                 customer_id=customer_id, customer_name=customer_name,
                 progress_cb=print)
        return

    root = tk.Tk()
    root.title("DataSentry — Scanning")
    root.geometry("520x360")
    root.resizable(False, False)
    root.configure(bg=WHITE)

    band = tk.Frame(root, bg=NAV, height=72)
    band.pack(fill="x")
    band.pack_propagate(False)
    tk.Label(band, text="DataSentry", font=("Helvetica", 11, "bold"),
             bg=NAV, fg=TEAL).pack(anchor="w", padx=24, pady=(14, 0))
    tk.Label(band, text="Data Discovery Scan", font=("Helvetica", 16, "bold"),
             bg=NAV, fg=WHITE).pack(anchor="w", padx=24)

    if customer_name:
        tk.Label(root, text=f"Organisation: {customer_name}", font=("Helvetica", 10),
                 bg=WHITE, fg=TEXT2, anchor="w").pack(fill="x", padx=24, pady=(10, 0))

    status_var = tk.StringVar(value="Preparing scan…")
    tk.Label(root, textvariable=status_var, font=("Helvetica", 10),
             bg=WHITE, fg=TEXT2, anchor="w", wraplength=470).pack(fill="x", padx=24, pady=4)

    bar = ttk.Progressbar(root, mode="indeterminate", length=470)
    bar.pack(padx=24, pady=4)
    bar.start(12)

    log_frame = tk.Frame(root, bg=GREY)
    log_frame.pack(fill="both", expand=True, padx=24, pady=8)
    sb = tk.Scrollbar(log_frame)
    sb.pack(side="right", fill="y")
    log = tk.Text(log_frame, height=9, yscrollcommand=sb.set,
                  state="disabled", bg=GREY, fg=TEXT2,
                  font=("Courier", 8), relief="flat", padx=6, pady=4)
    log.pack(fill="both", expand=True)
    sb.config(command=log.yview)

    def append(msg: str):
        log.config(state="normal")
        log.insert("end", msg + "\n")
        log.see("end")
        log.config(state="disabled")
        status_var.set(msg[:80])
        root.update_idletasks()

    def worker():
        import threading
        rep = run_scan(api_url=api_url, api_key=api_key,
                       customer_id=customer_id, customer_name=customer_name,
                       progress_cb=append)
        root.after(0, lambda: done(rep))

    def done(rep):
        bar.stop()
        s = rep.get("summary", {})
        append(f"\n✓ Scan complete — {s.get('total_files',0):,} files, "
               f"{s.get('total_pii_files',0):,} with PII")
        if rep.get("submitted"):
            append("  Report submitted to DataSentry ✓")
        status_var.set("Done. You may close this window.")
        close_btn.config(state="normal")

    close_btn = tk.Button(root, text="Close", state="disabled",
                          command=root.destroy,
                          bg=TEAL, fg=NAV, relief="flat",
                          font=("Helvetica", 10, "bold"),
                          padx=20, pady=6, cursor="hand2")
    close_btn.pack(pady=6)

    import threading
    threading.Thread(target=worker, daemon=True).start()
    root.mainloop()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="DataSentry — Data Discovery Scanner")
    parser.add_argument("--api-url",       help="DataSentry backend URL")
    parser.add_argument("--api-key",       help="API key for authentication")
    parser.add_argument("--customer-id",   help="Customer identifier (e.g. acme-corp)")
    parser.add_argument("--customer-name", help="Customer display name (e.g. 'Acme Corp Ltd')")
    parser.add_argument("--output",        help="Write report to this local JSON file instead")
    parser.add_argument("--cli",           action="store_true",
                        help="Force CLI mode (no GUI)")
    parser.add_argument("--verbose",       action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    # Load saved / pre-baked config, then overlay CLI args
    cfg = load_config()
    if args.api_url:       cfg["api_url"]       = args.api_url
    if args.api_key:       cfg["api_key"]        = args.api_key
    if args.customer_id:   cfg["customer_id"]   = args.customer_id
    if args.customer_name: cfg["customer_name"] = args.customer_name

    force_cli = args.cli or not HAS_TK

    # ── CLI mode ───────────────────────────────────────────────────────────────
    if force_cli:
        if not cfg["api_url"] or not cfg["api_key"]:
            print("ERROR: --api-url and --api-key are required in CLI mode "
                  "unless a datasentry.cfg is present.")
            sys.exit(1)
        run_scan(progress_cb=print, output=args.output, **cfg)
        return

    # ── GUI mode ───────────────────────────────────────────────────────────────
    config_is_complete = bool(cfg["api_url"] and cfg["api_key"] and cfg["customer_name"])

    if config_is_complete:
        # Pre-configured (portal download or already set up) — skip wizard
        run_gui(**cfg)
    else:
        # First run — show the setup wizard
        completed = run_wizard(prefill=cfg)
        if not completed:
            sys.exit(0)  # user cancelled


if __name__ == "__main__":
    main()
