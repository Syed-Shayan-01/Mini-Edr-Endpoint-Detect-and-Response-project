import os
import sys

# Add Conda Library\bin to PATH so sqlite3 DLL loads when elevated via UAC
_conda_bin = os.path.join(sys.prefix, "Library", "bin")
if os.path.isdir(_conda_bin):
    os.environ["PATH"] = _conda_bin + os.pathsep + os.environ.get("PATH", "")
    if hasattr(os, "add_dll_directory"):
        try:
            os.add_dll_directory(_conda_bin)
        except Exception:
            pass

import re
import stat
import time
import math
import zlib
import ctypes
import socket
import hashlib
import logging
import threading
import subprocess
from datetime import datetime
from collections import Counter, deque
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import db_manager as db

logging.getLogger("asyncio").setLevel(logging.CRITICAL)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEMO_SANDBOX = os.path.join(BASE_DIR, "Demo_Protected_Folder")
VAULT_DIR = os.path.join(BASE_DIR, "MiniEDR_Backup_Vault")
LOG_FILE = os.path.join(BASE_DIR, "engine.log")
TRAP_FOLDER_NAME = "!000_Trap"
MAX_VAULT_FILE_SIZE = 15 * 1024 * 1024  # 15 MB limit per backed-up file

ACTIVE_VSS_DEVICE = None

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

PROTECTED_EXTS = {'.docx', '.pdf', '.jpg', '.mp4', '.txt', '.xlsx', '.png', '.csv', '.zip', '.pptx'}
COMPRESSED_EXTS = {'.docx', '.pdf', '.jpg', '.mp4', '.xlsx', '.png', '.zip', '.pptx'}
TEXT_EXTS = {'.txt', '.csv'}
IGNORED_EXTS = {'.tmp', '.sys', '.cache', '.log', '.db', '.db-journal', '.db-wal', '.db-shm', '.zvault'}
SUSPICIOUS_EXTS = {'.locked', '.enc', '.crypted', '.ransom', '.hacked'}

# Critical OS, terminal, editor, and browser processes that must never be killed
PROTECTED_PROCESSES = {
    'system', 'idle', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'winlogon.exe', 'explorer.exe',
    'dwm.exe', 'taskhostw.exe', 'msmpeng.exe', 'nissrv.exe', 'securityhealthservice.exe',
    'searchindexer.exe', 'searchhost.exe', 'searchapp.exe', 'startmenuexperiencehost.exe',
    'shellexperiencehost.exe', 'runtimebroker.exe', 'onedrive.exe', 'code.exe',
    'agy.exe', 'antigravity.exe', 'cursor.exe', 'windsurf.exe', 'devenv.exe',
    'pycharm64.exe', 'conhost.exe', 'windowsterminal.exe', 'streamlit.exe',
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe',
    'brave.exe', 'opera.exe', 'msedgewebview2.exe', 'teams.exe', 'discord.exe',
    'spotify.exe', 'steam.exe', 'whatsapp.exe', 'claude.exe'
}

MAGIC_HEADERS = {
    '.pdf': [b'%PDF'],
    '.jpg': [b'\xff\xd8\xff'],
    '.png': [b'\x89PNG\r\n\x1a\n'],
    '.docx': [b'PK\x03\x04'],
    '.xlsx': [b'PK\x03\x04'],
    '.pptx': [b'PK\x03\x04'],
    '.zip': [b'PK\x03\x04'],
}

TRAP_PRISTINE = b"PK\x03\x04" + b"CONFIDENTIAL FINANCIAL & USER DATA - DO NOT MODIFY OR ENCRYPT. " * 15
TRAP_NAME_RE = re.compile(r"^00_confidential_records_\d{2}\.docx$")

ATTACK_LABELS = {
    "normal": "Full Burst Attack",
    "trap": "Canary Honeypot Probe",
    "partial": "Header Corruption Attack",
    "slow": "Slow Evasion Attack",
    "notrap": "Trap-Evading Burst",
    "vault": "Vault Tamper Attack",
}

_sig_cache = {}
_exe_hash_cache = {}
_instance_sock = None
_cfg_cache = {"ts": 0.0, "values": {}}
_wl_cache = {"ts": 0.0, "by_name": {}, "by_hash": {}}


def get_cached_setting(key, default=None):
    """Reads frequently checked settings from RAM and refreshes every 2 seconds."""
    now = time.time()
    if (now - _cfg_cache["ts"]) > 2.0 or key not in _cfg_cache["values"]:
        _cfg_cache["values"][key] = db.get_setting(key, default)
        _cfg_cache["ts"] = now
    val = _cfg_cache["values"].get(key)
    return val if val is not None else default


def get_cached_whitelist():
    """Caches whitelist rows in RAM for 2 seconds to avoid database overhead."""
    now = time.time()
    if (now - _wl_cache["ts"]) > 2.0:
        by_name = {}
        by_hash = {}
        df_wl = db.read_df("SELECT process_name, sha256_hash, require_signature FROM whitelist")
        if not df_wl.empty:
            for _, row in df_wl.iterrows():
                pname = str(row["process_name"]).lower()
                hval = str(row["sha256_hash"])
                req_sig = bool(row["require_signature"])
                by_name.setdefault(pname, []).append((hval, req_sig))
                by_hash[hval] = req_sig
        _wl_cache["by_name"] = by_name
        _wl_cache["by_hash"] = by_hash
        _wl_cache["ts"] = now
    return _wl_cache["by_name"], _wl_cache["by_hash"]


def acquire_single_instance(port=47651):
    """Binds a local socket so only one engine instance runs at a time."""
    global _instance_sock
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        s.listen(1)
    except OSError:
        s.close()
        return False
    _instance_sock = s
    return True


def is_running_as_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def heartbeat_loop():
    """Updates engine status, CPU, and RAM usage every second."""
    my_proc = psutil.Process(os.getpid())
    my_proc.cpu_percent(None)
    while True:
        try:
            db.set_settings_batch({
                "engine_cpu": f"{my_proc.cpu_percent(None):.1f}",
                "engine_ram_mb": f"{my_proc.memory_info().rss / (1024 * 1024):.1f}",
                "engine_pid": str(os.getpid()),
                "engine_is_admin": "1" if is_running_as_admin() else "0",
                "engine_heartbeat": str(time.time()),
            })
        except Exception:
            pass
        time.sleep(1.0)


_safe_cache = {"ts": 0.0, "pids": set()}


def get_protected_family_pids(max_age=10.0) -> set:
    """Caches protected PIDs for 10 seconds to keep process scanning fast."""
    now = time.time()
    if _safe_cache["pids"] and (now - _safe_cache["ts"]) < max_age:
        return set(_safe_cache["pids"])
    pids = _compute_protected_family_pids()
    _safe_cache["pids"] = pids
    _safe_cache["ts"] = now
    return set(pids)


def _compute_protected_family_pids() -> set:
    """Protects the engine, Streamlit dashboard, and their parent processes."""
    my_pid = os.getpid()
    dash_pid = int(db.get_setting("dashboard_pid", "0") or 0)
    safe_pids = {my_pid, dash_pid}

    for start_pid in (my_pid, dash_pid):
        if not start_pid:
            continue
        try:
            curr = psutil.Process(start_pid)
            while curr is not None:
                safe_pids.add(curr.pid)
                curr = curr.parent()
        except Exception:
            pass

    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            cmdline = " ".join(proc.info.get('cmdline') or []).lower()
            if "edr_engine.py" in cmdline or "streamlit" in cmdline or "app.py" in cmdline:
                safe_pids.add(proc.info['pid'])
        except Exception:
            continue

    return safe_pids


def calculate_entropy(file_path):
    """Calculates Shannon entropy (0.0 to 8.0) on the first 64 KB of a file."""
    try:
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            return 0.0
        with open(file_path, "rb") as f:
            data = f.read(65536)
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())
    except Exception:
        return 0.0


def get_file_header(file_path, num_bytes=8):
    """Reads the first few bytes of a file to check its magic header."""
    try:
        if not os.path.exists(file_path):
            return b""
        with open(file_path, "rb") as f:
            return f.read(num_bytes)
    except Exception:
        return b""


def has_valid_magic_header(ext, header_bytes):
    """Checks if a structured file starts with its expected magic header."""
    if not header_bytes:
        return False
    expected = MAGIC_HEADERS.get(ext.lower())
    if not expected:
        return False
    return any(header_bytes.startswith(prefix) for prefix in expected)


def get_sha256(file_path):
    """Computes the SHA-256 hash of a file."""
    try:
        if not os.path.exists(file_path):
            return ""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def get_cached_exe_sha256(exe_path):
    """Caches executable SHA-256 hashes by path and modified time."""
    if not exe_path or not os.path.exists(exe_path):
        return ""
    try:
        key = (os.path.normcase(exe_path), os.path.getmtime(exe_path))
        if key not in _exe_hash_cache:
            _exe_hash_cache[key] = get_sha256(exe_path)
        return _exe_hash_cache[key]
    except Exception:
        return ""


def is_file_compromised(file_path, known_clean_hash=None) -> bool:
    """Checks if a file is compromised without flagging clean high-entropy office/media files."""
    try:
        if not os.path.isfile(file_path):
            return False
        ext = os.path.splitext(file_path)[1].lower()

        if ext in SUSPICIOUS_EXTS:
            return True

        if known_clean_hash:
            cur_hash = get_sha256(file_path)
            if cur_hash and cur_hash == known_clean_hash:
                return False

        sz = os.path.getsize(file_path)
        if sz == 0:
            return False

        if ext in MAGIC_HEADERS:
            hdr = get_file_header(file_path)
            if has_valid_magic_header(ext, hdr):
                return False
            return calculate_entropy(file_path) >= 6.8

        if ext in TEXT_EXTS:
            return calculate_entropy(file_path) >= float(get_cached_setting("absolute_high_entropy", 7.2))

        return False
    except Exception:
        return False


def verify_authenticode_signature(exe_path):
    """Verifies Microsoft Authenticode digital signature using PowerShell."""
    if not exe_path or not os.path.exists(exe_path):
        return False
    try:
        mtime = os.path.getmtime(exe_path)
        cache_key = (os.path.normcase(exe_path), mtime)
        if cache_key in _sig_cache:
            return _sig_cache[cache_key]

        escaped_path = exe_path.replace("'", "''")
        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-AuthenticodeSignature -LiteralPath '{escaped_path}').Status"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        is_valid = "Valid" in res.stdout.strip()
        _sig_cache[cache_key] = is_valid
        return is_valid
    except Exception:
        return False


# ---------------- CANARY (HONEYPOT) STATE HELPERS ---------------- #

def trap_is_intact(path) -> bool:
    try:
        if not os.path.isfile(path):
            return False
        if os.path.getsize(path) != len(TRAP_PRISTINE):
            return False
        with open(path, "rb") as f:
            return f.read() == TRAP_PRISTINE
    except Exception:
        return False


def count_trap_damage(watch_dirs) -> int:
    """Counts tampered, deleted, or stray decoy files across all monitored folders."""
    damaged = 0
    for target_dir in watch_dirs:
        trap_dir = os.path.join(target_dir, TRAP_FOLDER_NAME)
        if not os.path.isdir(trap_dir):
            continue
        try:
            names = os.listdir(trap_dir)
        except OSError:
            continue
        present = set()
        for n in names:
            if TRAP_NAME_RE.match(n):
                present.add(n)
                if not trap_is_intact(os.path.join(trap_dir, n)):
                    damaged += 1
            else:
                damaged += 1
        for i in range(1, 26):
            n = f"00_confidential_records_{i:02d}.docx"
            if n not in present and not any(x.startswith(n) for x in names):
                damaged += 1
    return damaged


# ---------------- FAST, LOW-CPU PROCESS I/O TRACKER ---------------- #

class ProcessIOTracker(threading.Thread):
    def __init__(self, get_folders_fn):
        super().__init__(daemon=True)
        self.get_folders_fn = get_folders_fn
        self.history = {}
        self.proc_meta = {}
        self.recent_writers = deque(maxlen=60)
        self.lock = threading.Lock()
        self.running = True
        self.base_norm = os.path.normcase(BASE_DIR)
        self.vault_norm = os.path.normcase(VAULT_DIR)

    def _watched_norms(self):
        norms = [self.base_norm, self.vault_norm]
        for f in self.get_folders_fn():
            norms.append(os.path.normcase(os.path.abspath(f)))
        return norms

    def _cmd_link(self, cmdline):
        """Checks if a process command line references any protected folder."""
        cmd = os.path.normcase(" ".join(cmdline or []))
        if not cmd:
            return 0
        for norm in self._watched_norms():
            if norm in cmd:
                return 300_000
            folder_base = os.path.basename(norm)
            if folder_base and folder_base in cmd:
                return 250_000
        return 0

    def _cwd_link(self, proc):
        """Checks process working directory (called only for active writers or brand-new processes)."""
        try:
            cwd = os.path.normcase(proc.cwd() or "")
            if any(norm in cwd or cwd.startswith(norm) for norm in self._watched_norms()):
                return 100_000
        except Exception:
            pass
        return 0

    def _describe(self, cmdline, name):
        for i, part in enumerate(cmdline or []):
            if part.lower().endswith(".py"):
                script = os.path.basename(part)
                if "fake_ransom" in script.lower():
                    mode = cmdline[i + 1].lower() if i + 1 < len(cmdline) else "normal"
                    label = ATTACK_LABELS.get(mode)
                    if label:
                        return f"{script} [{label}]"
                return f"{script} ({name})" if name else script
        return name

    def _is_whitelisted_exe(self, exe_path) -> bool:
        """Verifies executable SHA-256 hash and Authenticode signature against whitelist."""
        if not exe_path or not os.path.exists(exe_path):
            return False
        _, by_hash = get_cached_whitelist()
        if not by_hash:
            return False
        exe_hash = get_cached_exe_sha256(exe_path)
        if exe_hash in by_hash:
            req_sig = by_hash[exe_hash]
            if not req_sig or verify_authenticode_signature(exe_path):
                return True
        return False

    def purge_pid(self, pid):
        """Removes a terminated PID from history so it cannot trigger repeat alerts."""
        with self.lock:
            self.history.pop(pid, None)
            self.proc_meta.pop(pid, None)
            self.recent_writers = deque(
                (item for item in self.recent_writers if item[1] != pid),
                maxlen=60
            )

    def check_active_whitelisted(self):
        """Checks immediately if a verified whitelisted program is actively running."""
        by_name, _ = get_cached_whitelist()
        if not by_name:
            return None
        safe_pids = get_protected_family_pids()
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                name = (proc.info['name'] or "").lower()
                if pid in safe_pids or name not in by_name:
                    continue
                exe_path = proc.info.get('exe') or ""
                if self._is_whitelisted_exe(exe_path):
                    return (proc.info['name'], pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                continue
        return None

    def run(self):
        """Lightweight I/O sampler that avoids calling proc.cwd() on idle background apps."""
        while self.running:
            now = time.time()
            safe_pids = get_protected_family_pids()
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    pid = proc.info['pid']
                    if pid in safe_pids:
                        continue
                    name = (proc.info['name'] or "")
                    if name.lower() in PROTECTED_PROCESSES:
                        continue

                    io = proc.io_counters()
                    w_bytes = io.write_bytes

                    with self.lock:
                        is_new = pid not in self.history
                        old = self.proc_meta.get(pid)
                        prev_w = self.history[pid][-1][1] if (not is_new and self.history[pid]) else w_bytes

                    delta_w = max(0, w_bytes - prev_w)
                    link = old[2] if old else 0
                    label = old[3] if old else name
                    exe = old[1] if old else ""

                    # Check cmdline only once for new processes, or cwd only when bytes were actually written
                    if is_new or (delta_w > 0 and link == 0):
                        try:
                            cmdline = proc.cmdline() or []
                        except Exception:
                            cmdline = []
                        link = self._cmd_link(cmdline)
                        if link == 0 and (delta_w > 0 or (now - (proc.info.get('create_time') or 0) <= 10.0)):
                            link = self._cwd_link(proc)
                        if link > 0:
                            label = self._describe(cmdline, name)
                            if not exe:
                                try:
                                    exe = proc.exe() or ""
                                except Exception:
                                    exe = ""

                    with self.lock:
                        if pid not in self.history:
                            ctime = proc.info.get('create_time') or now
                            self.history[pid] = deque(maxlen=20)
                            if now - ctime < 15.0:
                                self.history[pid].append((ctime, 0))
                        self.history[pid].append((now, w_bytes))
                        self.proc_meta[pid] = (name, exe, link, label or name)
                        if delta_w > 0 and link > 0:
                            self.recent_writers.append((now, pid, name, exe, delta_w))
                except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                    continue
            with self.lock:
                for dead in [k for k, h in self.history.items() if h and now - h[-1][0] > 30.0]:
                    self.history.pop(dead, None)
                    self.proc_meta.pop(dead, None)
            time.sleep(0.20)

    def _history_candidates(self, safe_pids, window_sec, now):
        """Finds folder-linked writers from recent polling history."""
        candidates = {}
        with self.lock:
            for pid, hist in self.history.items():
                if pid in safe_pids or not hist:
                    continue
                name, exe, link, label = self.proc_meta.get(pid, ("", "", 0, ""))
                if link <= 0 or name.lower() in PROTECTED_PROCESSES:
                    continue
                if now - hist[-1][0] > window_sec:
                    continue
                base_w = hist[0][1]
                for ts, wb in hist:
                    if now - ts <= window_sec:
                        base_w = wb
                        break
                delta = max(0, hist[-1][1] - base_w)
                if delta >= 1024:
                    candidates[pid] = [delta + link, name, exe, label or name]

            for ts, pid, name, exe, d_bytes in self.recent_writers:
                if now - ts <= window_sec and pid not in safe_pids:
                    if name.lower() in PROTECTED_PROCESSES:
                        continue
                    meta = self.proc_meta.get(pid, ("", "", 0, ""))
                    link = meta[2]
                    if link <= 0:
                        continue
                    if pid in candidates:
                        candidates[pid][0] += d_bytes
                    elif d_bytes >= 1024:
                        candidates[pid] = [d_bytes + link, name, exe, meta[3] or name]
        return candidates

    def _direct_scan(self, safe_pids, window_sec=6.0):
        """Fast scan (< 60ms) that avoids calling proc.cwd() on old idle processes."""
        candidates = {}
        now = time.time()
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or ""
                if pid in safe_pids or name.lower() in PROTECTED_PROCESSES:
                    continue

                cmdline = proc.info.get('cmdline') or []
                ctime = proc.info.get('create_time') or 0
                link = self._cmd_link(cmdline)

                # Only call proc.cwd() on brand-new processes (< 15s old)
                if link <= 0 and (now - ctime) <= 15.0:
                    link = self._cwd_link(proc)
                if link <= 0:
                    continue

                w_bytes = proc.io_counters().write_bytes
                if now - ctime <= 20.0:
                    recent_writes = w_bytes
                else:
                    recent_writes = 0
                    with self.lock:
                        hist = self.history.get(pid)
                        if hist:
                            base_w = hist[0][1]
                            for ts, wb in hist:
                                if now - ts <= window_sec:
                                    base_w = wb
                                    break
                            recent_writes = max(0, w_bytes - base_w)

                if recent_writes < 1024:
                    continue

                try:
                    exe = proc.exe() or ""
                except Exception:
                    exe = ""

                recency = max(0.0, 50_000.0 - (now - ctime) * 100.0)
                candidates[pid] = [link + recent_writes + recency, name, exe, self._describe(cmdline, name)]
            except Exception:
                continue
        return candidates

    def find_suspect_and_stop(self, target_dirs, window_sec=12.0):
        """Locates and stops only folder-linked suspect processes after checking whitelist."""
        safe_pids = get_protected_family_pids()

        deadline = time.time() + 0.30
        candidates = {}
        while True:
            now = time.time()
            candidates = self._direct_scan(safe_pids)
            if not candidates:
                candidates = self._history_candidates(safe_pids, window_sec, now)
            if candidates or time.time() >= deadline:
                break
            time.sleep(0.04)

        if not candidates:
            return ("Unknown Process", 0, "not_found")

        sorted_cands = sorted(candidates.items(), key=lambda item: item[1][0], reverse=True)
        suspect_pid, (_, suspect_name, suspect_exe, suspect_label) = sorted_cands[0]
        display = suspect_label or suspect_name

        try:
            suspect_proc = psutil.Process(suspect_pid)
            children = [ch for ch in suspect_proc.children(recursive=True) if ch.pid not in safe_pids]

            # Freeze process before verifying SHA-256 hash and digital signature
            for ch in children:
                try:
                    ch.suspend()
                except Exception:
                    pass
            if suspect_pid not in safe_pids:
                suspect_proc.suspend()

            if self._is_whitelisted_exe(suspect_exe):
                suspect_proc.resume()
                for ch in children:
                    try:
                        ch.resume()
                    except Exception:
                        pass
                return (display, suspect_pid, "whitelisted")

            # Terminate confirmed malicious process and clear it from history
            for ch in children:
                try:
                    ch.kill()
                except Exception:
                    pass
            if suspect_pid not in safe_pids:
                suspect_proc.kill()
            self.purge_pid(suspect_pid)
            logging.warning(f"Terminated malicious process: {display} (PID {suspect_pid})")
            return (display, suspect_pid, "killed")

        except psutil.NoSuchProcess:
            self.purge_pid(suspect_pid)
            if self._is_whitelisted_exe(suspect_exe):
                return (display, suspect_pid, "whitelisted")
            return (display, suspect_pid, "killed")
        except psutil.AccessDenied:
            logging.error(f"AccessDenied killing {display} (PID {suspect_pid}). Run sensor as Admin.")
            return (f"{display} (Elevate Sensor as Admin)", suspect_pid, "not_found")
        except Exception as e:
            logging.error(f"Kill error: {e}")
            return (display, suspect_pid, "not_found")


# ---------------- LEVEL 1 (WINDOWS VSS) & LEVEL 2 (FOLDER-MIRRORED VAULT) ---------------- #

def get_primary_drive(watch_dirs=None):
    base = watch_dirs[0] if watch_dirs else DEMO_SANDBOX
    drive, _ = os.path.splitdrive(os.path.abspath(base))
    return (drive + "\\") if drive else "C:\\"


def query_latest_vss_device() -> str:
    try:
        ps_find = (
            "Get-WmiObject Win32_ShadowCopy | Sort-Object InstallDate -Descending | "
            "Select-Object -First 1 -ExpandProperty DeviceObject"
        )
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_find],
            capture_output=True, text=True, timeout=8
        )
        dev = res.stdout.strip()
        if dev and "HarddiskVolumeShadowCopy" in dev:
            return dev
    except Exception:
        pass
    return ""


def create_vss_snapshot(drive=None):
    global ACTIVE_VSS_DEVICE
    if not drive:
        drive = get_primary_drive(db.get_protected_folders())

    admin = is_running_as_admin()
    db.set_setting("engine_is_admin", "1" if admin else "0")

    if not admin:
        ACTIVE_VSS_DEVICE = None
        db.set_setting("vss_status", "Tier-2 Vault Active (Elevate Sensor for Tier-1 VSS)")
        return False

    try:
        subprocess.run(["sc", "config", "vss", "start=", "demand"], capture_output=True, timeout=4)
        subprocess.run(["sc", "config", "swprv", "start=", "demand"], capture_output=True, timeout=4)
        subprocess.run(["net", "start", "vss"], capture_output=True, timeout=6)

        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"([WMICLASS]'Win32_ShadowCopy').Create('{drive}', 'ClientAccessible')"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        dev_path = query_latest_vss_device()

        if re.search(r"ReturnValue\s*[:=]\s*0", res.stdout) or dev_path:
            ACTIVE_VSS_DEVICE = dev_path
            db.set_setting("vss_status", f"Tier-1 VSS Ready ({drive}) + Tier-2 Vault")
            logging.info(f"Tier-1 VSS Snapshot Ready: {ACTIVE_VSS_DEVICE}")
            return True
        else:
            ACTIVE_VSS_DEVICE = None
            db.set_setting("vss_status", "Tier-2 Compressed Vault Active")
            return False
    except Exception as e:
        ACTIVE_VSS_DEVICE = None
        logging.warning(f"VSS creation failed: {e}")
        db.set_setting("vss_status", "Tier-2 Compressed Vault Active")
        return False


def try_vss_restore(file_path) -> bool:
    """Restores a file from Tier-1 VSS if enabled and available."""
    global ACTIVE_VSS_DEVICE
    if db.get_setting("tier1_vss_enabled", "1") != "1":
        return False
    if not ACTIVE_VSS_DEVICE:
        return False

    try:
        abs_path = os.path.abspath(file_path)
        _, tail = os.path.splitdrive(abs_path)
        vss_source = ACTIVE_VSS_DEVICE.rstrip("\\") + tail

        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(vss_source, "rb") as f_src:
            raw_bytes = f_src.read()
        with open(abs_path, "wb") as f_dst:
            f_dst.write(raw_bytes)
        logging.info(f"Restored file via Tier-1 VSS: {os.path.basename(abs_path)}")
        return True
    except Exception:
        try:
            copy_res = subprocess.run(
                ["cmd.exe", "/c", "copy", "/Y", vss_source, abs_path],
                capture_output=True, text=True, timeout=3
            )
            return copy_res.returncode == 0 and os.path.exists(abs_path)
        except Exception:
            return False


class VaultManager:
    """Folder-mirrored compressed backup vault with integrity verification."""
    def __init__(self, vault_dir):
        self.vault_dir = os.path.abspath(vault_dir)
        os.makedirs(self.vault_dir, exist_ok=True)
        if os.name == "nt":
            subprocess.run(["attrib", "+h", self.vault_dir], capture_output=True)
        self.file_metadata = db.get_all_vault_meta()
        self.write_lock = threading.Lock()
        self.internal_write = False
        self.internal_write_until = 0.0

    def mark_internal_write(self, duration=2.5):
        self.internal_write_until = max(self.internal_write_until, time.time() + duration)

    def is_internal_write(self) -> bool:
        return self.internal_write or (time.time() < self.internal_write_until)

    def _is_vault_file_valid(self, v_path) -> bool:
        """Verifies that a .zvault file exists and decompresses cleanly."""
        if not os.path.isfile(v_path):
            return False
        try:
            with open(v_path, "rb") as f:
                zlib.decompress(f.read())
            return True
        except Exception:
            return False

    def _folder_vault_name(self, folder_path, all_folders):
        abs_f = os.path.abspath(folder_path)
        base_name = os.path.basename(abs_f) or "Root"
        duplicates = [
            f for f in all_folders
            if os.path.basename(os.path.abspath(f)).lower() == base_name.lower()
        ]
        if len(duplicates) > 1:
            tag = hashlib.sha1(os.path.normcase(abs_f).encode("utf-8")).hexdigest()[:4]
            return f"{base_name}_{tag}"
        return base_name

    def get_vault_path(self, original_path, watch_dirs=None):
        """Maps each protected folder to its own subfolder inside MiniEDR_Backup_Vault."""
        abs_p = os.path.abspath(original_path)
        norm_p = os.path.normcase(abs_p)
        folders = watch_dirs if watch_dirs is not None else db.get_protected_folders()

        matched_root = None
        for f in sorted(folders, key=lambda x: len(os.path.abspath(x)), reverse=True):
            norm_f = os.path.normcase(os.path.abspath(f))
            if norm_p.startswith(norm_f + os.sep) or norm_p == norm_f:
                matched_root = os.path.abspath(f)
                break

        if matched_root:
            folder_label = self._folder_vault_name(matched_root, folders)
            rel_path = os.path.relpath(abs_p, matched_root)
            return os.path.join(self.vault_dir, folder_label, rel_path + ".zvault")

        parent_name = os.path.basename(os.path.dirname(abs_p)) or "Other"
        return os.path.join(self.vault_dir, parent_name, os.path.basename(abs_p) + ".zvault")

    def _set_readonly(self, path, readonly=True):
        try:
            if os.path.exists(path):
                os.chmod(path, stat.S_IREAD if readonly else stat.S_IWRITE)
        except Exception:
            pass

    def cleanup_legacy_flat_files(self):
        with self.write_lock:
            self.internal_write = True
            self.mark_internal_write(2.5)
            try:
                for entry in os.listdir(self.vault_dir):
                    full_p = os.path.join(self.vault_dir, entry)
                    if os.path.isfile(full_p):
                        try:
                            self._set_readonly(full_p, readonly=False)
                            os.remove(full_p)
                        except Exception:
                            pass
            finally:
                self.mark_internal_write(2.5)
                self.internal_write = False

    def is_file_healthy(self, file_path):
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return False
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SUSPICIOUS_EXTS or ext in IGNORED_EXTS:
            return False
        try:
            sz = os.path.getsize(file_path)
            if sz > MAX_VAULT_FILE_SIZE:
                return False
            if sz == 0:
                return False
            hdr = get_file_header(file_path)
            if has_valid_magic_header(ext, hdr):
                return True
            if ext in MAGIC_HEADERS:
                return calculate_entropy(file_path) < 6.8
            ent = calculate_entropy(file_path)
            if ent >= float(get_cached_setting("absolute_high_entropy", 7.2)):
                return False
            return True
        except Exception:
            return False

    def backup_all(self, watch_dirs, force=False):
        self.cleanup_legacy_flat_files()
        for folder in watch_dirs:
            if not os.path.isdir(folder):
                continue
            for root, _, files in os.walk(folder):
                if TRAP_FOLDER_NAME in root or os.path.normcase(self.vault_dir) in os.path.normcase(root):
                    continue
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in PROTECTED_EXTS:
                        full_p = os.path.abspath(os.path.join(root, file))
                        if self.is_file_healthy(full_p):
                            self.backup_single_file(full_p, update_metrics=False, watch_dirs=watch_dirs, force=force)
        db.clear_missing_vault_meta(watch_dirs)
        self.file_metadata = db.get_all_vault_meta()
        db.update_vault_storage_metrics(self.vault_dir)

    def backup_single_file(self, file_path, update_metrics=True, watch_dirs=None, force=False):
        try:
            abs_p = os.path.abspath(file_path)
            if not self.is_file_healthy(abs_p):
                return
            v_path = self.get_vault_path(abs_p, watch_dirs=watch_dirs)
            new_hash = get_sha256(abs_p)
            orig_size = os.path.getsize(abs_p)
            old_meta = self.file_metadata.get(abs_p)

            vault_valid = (not force) and self._is_vault_file_valid(v_path)
            if not old_meta or old_meta[2] != new_hash or not vault_valid:
                with open(abs_p, "rb") as f_in:
                    raw_data = f_in.read()
                compressed_data = zlib.compress(raw_data, level=6)

                with self.write_lock:
                    self.internal_write = True
                    self.mark_internal_write(2.5)
                    try:
                        os.makedirs(os.path.dirname(v_path), exist_ok=True)
                        self._set_readonly(v_path, readonly=False)
                        with open(v_path, "wb") as f_out:
                            f_out.write(compressed_data)
                        self._set_readonly(v_path, readonly=True)
                    finally:
                        self.mark_internal_write(2.5)
                        self.internal_write = False

            comp_size = os.path.getsize(v_path) if os.path.exists(v_path) else 0
            ent = calculate_entropy(abs_p)
            hdr = get_file_header(abs_p)
            self.file_metadata[abs_p] = (ent, hdr, new_hash)
            db.upsert_vault_meta(abs_p, ent, hdr, new_hash, orig_size, comp_size)
            if update_metrics:
                db.update_vault_storage_metrics(self.vault_dir)
        except Exception as e:
            logging.error(f"Vault backup error for {file_path}: {e}")

    def restore_from_vault(self, file_path, watch_dirs=None):
        if db.get_setting("tier2_vault_enabled", "1") != "1":
            return False
        try:
            abs_p = os.path.abspath(file_path)
            v_path = self.get_vault_path(abs_p, watch_dirs=watch_dirs)
            if os.path.exists(v_path):
                os.makedirs(os.path.dirname(abs_p), exist_ok=True)
                with open(v_path, "rb") as f_in:
                    compressed_data = f_in.read()
                raw_data = zlib.decompress(compressed_data)
                with open(abs_p, "wb") as f_out:
                    f_out.write(raw_data)
                return True
        except Exception as e:
            logging.error(f"Vault restore error for {file_path}: {e}")
        return False

    def repair_vault(self, watch_dirs):
        """Removes unauthorized files and force-rebuilds all corrupted vault backups."""
        with self.write_lock:
            self.internal_write = True
            self.mark_internal_write(3.0)
            try:
                for root, _, files in os.walk(self.vault_dir):
                    for fname in files:
                        if not fname.endswith(".zvault"):
                            fpath = os.path.join(root, fname)
                            try:
                                self._set_readonly(fpath, readonly=False)
                                os.remove(fpath)
                            except Exception:
                                pass
            finally:
                self.mark_internal_write(3.0)
                self.internal_write = False
        self.backup_all(watch_dirs, force=True)


def setup_honeypots(target_dir):
    """Creates hidden !000_Trap canary folder with 25 decoy files."""
    if not os.path.isdir(target_dir):
        return None
    trap_dir = os.path.join(target_dir, TRAP_FOLDER_NAME)
    os.makedirs(trap_dir, exist_ok=True)
    for existing in os.listdir(trap_dir):
        if not TRAP_NAME_RE.match(existing):
            try:
                os.remove(os.path.join(trap_dir, existing))
            except Exception:
                pass
    for i in range(1, 26):
        t_file = os.path.join(trap_dir, f"00_confidential_records_{i:02d}.docx")
        if not trap_is_intact(t_file):
            try:
                with open(t_file, "wb") as f:
                    f.write(TRAP_PRISTINE)
            except Exception:
                pass
    if os.name == 'nt':
        subprocess.run(["attrib", "+h", trap_dir], capture_output=True)
    return trap_dir


def populate_demo_sandbox(target_dir):
    """Creates clean sample files inside Demo_Protected_Folder."""
    os.makedirs(target_dir, exist_ok=True)
    for root, _, files in os.walk(target_dir):
        for f in files:
            if os.path.splitext(f)[1].lower() in SUSPICIOUS_EXTS:
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass

    samples = {
        "01_Project_Report_DUET.docx": b"PK\x03\x04" + b"Dawood University Information Security Lab Project Report Content. " * 45,
        "02_Student_Grades_2025.xlsx": b"PK\x03\x04" + b"ID,Name,Grade\n25F-DS-014,Syed Shayan,A+\n25F-DS-017,Muhammad Arsalan,A+\n" * 35,
        "03_University_Contract.pdf": b"%PDF-1.5\n" + b"Clean readable document body for entropy baseline testing.\n" * 45,
        "04_CyberSecurity_Notes.txt": b"Ransomware behavior detection relies on entropy delta and rapid file modification checks. " * 40,
        "05_Network_Diagram.jpg": b"\xff\xd8\xff\xe0" + b"Clean_Image_Payload_Stream_" * 65,
        "06_Financial_Budget_2026.xlsx": b"PK\x03\x04" + b"Month,Allocated,Spent,Variance\nJan,50000,48000,2000\nFeb,62000,60500,1500\n" * 35,
        "07_Thesis_Literature_Review.pdf": b"%PDF-1.5\n" + b"Enterprise SOC VLAN segmentation and firewall policy specification.\n" * 40,
        "08_Server_Credentials_Backup.csv": b"Server,IP,Role,Status\nSOC-DB-01,10.0.1.15,Primary,Active\nSOC-EDR-02,10.0.1.20,Sensor,Active\n" * 35,
        "09_Endpoint_Audit_Policy.docx": b"PK\x03\x04" + b"Zero-trust endpoint security configuration and privilege restriction guidelines. " * 40,
        "10_Incident_Response_Playbook.pdf": b"%PDF-1.5\n" + b"Standard operating procedure for ransomware containment and VSS recovery.\n" * 40,
        "11_Faculty_Research_Data.csv": b"ProjectID,Department,GrantPKR,Status\nDS-101,DataScience,450000,Approved\n" * 35,
        "12_Architecture_Blueprint.png": b"\x89PNG\r\n\x1a\n" + b"Clean_PNG_Vector_Graphics_Payload_" * 55
    }
    for name, content in samples.items():
        p = os.path.join(target_dir, name)
        with open(p, "wb") as f:
            f.write(content)


# ---------------- VAULT TAMPER GUARD HANDLER ---------------- #

class VaultGuardHandler(FileSystemEventHandler):
    """Monitors MiniEDR_Backup_Vault recursively and blocks external tampering."""
    def __init__(self, vault: VaultManager, io_tracker: ProcessIOTracker, get_folders_fn):
        self.vault = vault
        self.io_tracker = io_tracker
        self.get_folders_fn = get_folders_fn
        self.lock = threading.Lock()
        self.last_tamper_time = 0.0

    def _on_tamper(self, event_type, path):
        if self.vault.is_internal_write():
            return

        now = time.time()
        with self.lock:
            if now - self.last_tamper_time < 3.0:
                return
            self.last_tamper_time = now

        start_t = time.perf_counter()
        proc_name, pid, disposition = self.io_tracker.find_suspect_and_stop([VAULT_DIR])
        detect_ms = max(1.5, (time.perf_counter() - start_t) * 1000.0)

        if disposition in ("whitelisted", "not_found"):
            logging.info(f"Ignored non-hostile vault event ({event_type} on {os.path.basename(path)})")
            return

        time.sleep(0.15)
        start_res = time.perf_counter()
        self.vault.repair_vault(self.get_folders_fn())
        restore_ms = (time.perf_counter() - start_res) * 1000.0

        now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        db.log_events_batch([(now_str, "VAULT_TAMPER", os.path.basename(path), 4.0, 8.0, 4.0)])
        db.log_alert(
            proc_name, pid, disposition,
            f"Backup Vault Tamper Attempt ({event_type} on {os.path.basename(path)})",
            1, "Vault Self-Defense Guard",
            "Blocked unauthorized access to MiniEDR_Backup_Vault and re-sealed folder backups",
            detect_ms, restore_ms
        )

    def on_modified(self, event):
        if not event.is_directory:
            self._on_tamper("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._on_tamper("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._on_tamper("RENAMED", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._on_tamper("CREATED", event.src_path)


# ---------------- MULTI-FOLDER WATCHDOG HANDLER ---------------- #

class MiniEDRHandler(FileSystemEventHandler):
    def __init__(self, vault: VaultManager, io_tracker: ProcessIOTracker, get_folders_fn):
        self.vault = vault
        self.io_tracker = io_tracker
        self.get_folders_fn = get_folders_fn
        self.recent_files = {}
        self.compromised_files = set()
        self.event_buffer = []
        self.buffer_lock = threading.Lock()
        self.response_lock = threading.Lock()
        self.recovering = False
        self.last_alert_time = 0.0
        self.whitelisted_until = 0.0
        self.first_suspicious_time = None

    def is_ignored(self, path):
        abs_p = os.path.abspath(path)
        ext = os.path.splitext(abs_p)[1].lower()
        return ext in IGNORED_EXTS or os.path.normcase(VAULT_DIR) in os.path.normcase(abs_p)

    def queue_event_log(self, event_type, file_path, old_ent, new_ent, delta_ent):
        now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        with self.buffer_lock:
            self.event_buffer.append((
                now_str, event_type, os.path.basename(file_path),
                round(old_ent, 3), round(new_ent, 3), round(delta_ent, 3)
            ))

    def flush_events(self):
        with self.buffer_lock:
            if not self.event_buffer:
                return
            batch = list(self.event_buffer)
            self.event_buffer.clear()
        db.log_events_batch(batch)

    def strip_locked_ext(self, path):
        abs_p = os.path.abspath(path)
        base, ext = os.path.splitext(abs_p)
        if ext.lower() in SUSPICIOUS_EXTS:
            return base
        return abs_p

    def _find_folder_label(self, path):
        abs_p = os.path.normcase(os.path.abspath(path))
        for f in self.get_folders_fn():
            if abs_p.startswith(os.path.normcase(os.path.abspath(f))):
                return os.path.basename(f)
        return os.path.basename(os.path.dirname(path))

    def _launch_response(self, reason):
        """Starts trigger_response safely without spawning duplicate response threads."""
        with self.response_lock:
            if self.recovering:
                return
            self.recovering = True
        threading.Thread(target=self.trigger_response, args=(reason,), daemon=True).start()

    def handle_event(self, event_type, src_path, dest_path=None):
        now = time.time()
        if self.recovering or (now < self.whitelisted_until) or (now - self.last_alert_time < 1.5):
            return

        target_path = os.path.abspath(dest_path if dest_path else src_path)
        orig_path = self.strip_locked_ext(src_path)
        if self.is_ignored(target_path):
            return

        folder_name = self._find_folder_label(orig_path)

        # 1. Honeypot check (!000_Trap in any monitored folder)
        if TRAP_FOLDER_NAME in orig_path or (dest_path and TRAP_FOLDER_NAME in target_path):
            if event_type in ("MODIFIED", "RENAMED", "DELETED"):
                if trap_is_intact(orig_path):
                    return
                if self.first_suspicious_time is None:
                    self.first_suspicious_time = time.perf_counter()
                self.queue_event_log(f"TRAP_{event_type}", orig_path, 3.9, 7.98, 4.08)
                self._launch_response(f"Honeypot Trap Triggered in '{folder_name}' (!000_Trap)")
            return

        # 2. Deletion tracking
        if event_type == "DELETED":
            if orig_path in self.vault.file_metadata:
                if self.first_suspicious_time is None:
                    self.first_suspicious_time = time.perf_counter()
                self.compromised_files.add(orig_path)
                self.recent_files[orig_path] = now
            return

        # 3. Format-aware entropy, header, and extension check (fast, non-blocking)
        known_meta = self.vault.file_metadata.get(orig_path)
        new_ent = calculate_entropy(target_path)
        new_hdr = get_file_header(target_path)
        ext = os.path.splitext(target_path)[1].lower()
        orig_ext = os.path.splitext(orig_path)[1].lower()

        suspicious_ext = ext in SUSPICIOUS_EXTS
        ent_threshold = float(get_cached_setting("entropy_delta_threshold", 0.8))
        abs_high_ent = float(get_cached_setting("absolute_high_entropy", 7.2))

        if known_meta is not None:
            old_ent, old_hdr, _ = known_meta
            if new_ent == 0.0 and suspicious_ext:
                new_ent = 7.95
            delta_ent = max(0.0, new_ent - old_ent)
            valid_hdr_now = has_valid_magic_header(orig_ext, new_hdr)
            header_corrupted = (old_hdr != b"" and new_hdr != b"" and old_hdr[:4] != new_hdr[:4] and not valid_hdr_now)

            if orig_ext in COMPRESSED_EXTS:
                is_suspicious_file = suspicious_ext or header_corrupted or (not valid_hdr_now and delta_ent >= ent_threshold and new_ent >= 6.8)
            else:
                is_suspicious_file = suspicious_ext or header_corrupted or (delta_ent >= ent_threshold and new_ent >= 6.5) or (new_ent >= abs_high_ent)
        else:
            old_ent = 4.2 if suspicious_ext else new_ent
            delta_ent = max(0.0, new_ent - old_ent)
            if ext in MAGIC_HEADERS:
                is_suspicious_file = suspicious_ext or (not has_valid_magic_header(ext, new_hdr) and new_ent >= 6.8)
            elif ext in TEXT_EXTS:
                is_suspicious_file = suspicious_ext or (new_ent >= abs_high_ent)
            else:
                is_suspicious_file = suspicious_ext

        # Fast whitelist check for non-.locked bulk file extraction (like tar.exe or WinRAR)
        if is_suspicious_file and not suspicious_ext:
            wl_hit = self.io_tracker.check_active_whitelisted()
            if wl_hit is not None:
                wl_name, wl_pid = wl_hit
                self.whitelisted_until = time.time() + 6.0
                self.recent_files.clear()
                self.compromised_files.clear()
                self.first_suspicious_time = None
                ts = datetime.now().strftime("%H:%M:%S")
                msg = f"[{ts}] VERIFIED & ALLOWED: {wl_name} (PID {wl_pid}) passed SHA-256 & Authenticode check."
                db.set_setting("last_whitelist_event", msg)
                logging.info(msg)
                return

        if new_ent > 0.0 or suspicious_ext or event_type == "CREATED":
            self.queue_event_log(event_type, target_path, old_ent, new_ent, delta_ent)

        window_sec = float(get_cached_setting("speed_window_sec", 5))
        speed_limit = int(get_cached_setting("speed_limit_files", 4))
        self.recent_files = {p: t for p, t in self.recent_files.items() if now - t <= window_sec}

        if is_suspicious_file:
            if self.first_suspicious_time is None:
                self.first_suspicious_time = time.perf_counter()
            self.recent_files[orig_path] = now
            self.compromised_files.add(orig_path)
        else:
            if not self.recent_files and not self.compromised_files:
                self.first_suspicious_time = None
            if ext in PROTECTED_EXTS and os.path.exists(target_path):
                self.vault.backup_single_file(target_path)

        files_in_window = len(self.recent_files)

        # 4. Behavioral decision rules
        reason = None
        if files_in_window >= speed_limit and is_suspicious_file:
            reason = f"Speed ({files_in_window} files/{window_sec}s) + Entropy Spike in '{folder_name}' (Entropy={new_ent:.2f})"
        elif suspicious_ext and len(self.compromised_files) >= 2:
            reason = f"Ransomware Extension ({ext}) in '{folder_name}' + High Entropy ({new_ent:.2f})"
        elif is_suspicious_file and len(self.compromised_files) >= 3:
            reason = f"Header/Entropy Corruption in '{folder_name}' ({len(self.compromised_files)} files)"

        if reason:
            self._launch_response(reason)

    def on_modified(self, event):
        if not event.is_directory:
            self.handle_event("MODIFIED", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.handle_event("CREATED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.handle_event("RENAMED", event.src_path, event.dest_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.handle_event("DELETED", event.src_path)

    def _collect_locked_files(self, watch_dirs):
        locked_paths = []
        locked_originals = set()
        affected_folders = set()
        for folder in watch_dirs:
            if not os.path.isdir(folder):
                continue
            for root, _, files in os.walk(folder):
                if TRAP_FOLDER_NAME in root:
                    continue
                for f in files:
                    if os.path.splitext(f)[1].lower() in SUSPICIOUS_EXTS:
                        locked_full = os.path.join(root, f)
                        locked_paths.append(locked_full)
                        locked_originals.add(self.strip_locked_ext(locked_full))
                        affected_folders.add(os.path.basename(folder))
        return locked_paths, locked_originals, affected_folders

    def trigger_response(self, reason):
        watch_dirs = self.get_folders_fn()
        was_whitelisted = False

        try:
            # Stage 1: Identify, verify whitelist, and terminate malicious process immediately
            det_start = self.first_suspicious_time or time.perf_counter()
            proc_name, pid, disposition = self.io_tracker.find_suspect_and_stop(watch_dirs)
            detect_ms = max(1.5, (time.perf_counter() - det_start) * 1000.0)

            if disposition == "whitelisted":
                was_whitelisted = True
                self.whitelisted_until = time.time() + 6.0
                ts = datetime.now().strftime("%H:%M:%S")
                msg = f"[{ts}] VERIFIED & ALLOWED: {proc_name} (PID {pid}) passed SHA-256 & Authenticode check."
                db.set_setting("last_whitelist_event", msg)
                logging.info(msg)
                return

            time.sleep(0.15)
            trap_damaged = count_trap_damage(watch_dirs)
            locked_paths, locked_originals, affected_folders = self._collect_locked_files(watch_dirs)

            # Check only previously tracked user files for damage or deletion
            existing_damaged = set()
            for tracked_path, (_, old_hdr, clean_hash) in list(self.vault.file_metadata.items()):
                if TRAP_FOLDER_NAME in tracked_path:
                    continue
                if not os.path.exists(tracked_path):
                    existing_damaged.add(tracked_path)
                elif is_file_compromised(tracked_path, known_clean_hash=clean_hash):
                    existing_damaged.add(tracked_path)

            # Guard: Ignore unverified new-file bursts if no attacker, .locked file, trap, or existing file was hit
            if disposition == "not_found" and not locked_paths and trap_damaged == 0 and not existing_damaged:
                logging.info(f"Ignored unverified new-file event: {reason}")
                self.flush_events()
                return

            # Flush telemetry and hold briefly so user can observe compromised files live
            self.flush_events()
            visual_hold = float(get_cached_setting("visual_hold_sec", "3.0") or 0.0)
            if visual_hold > 0 and (locked_paths or existing_damaged):
                db.set_setting(
                    "system_status",
                    f"STAGE 1: ATTACKER KILLED ({proc_name} | PID {pid}) — RESTORING FILES IN {visual_hold:.0f}s..."
                )
                time.sleep(visual_hold)

            # Stage 2: Re-sweep for any residual .locked files, delete them, and restore all damaged assets
            start_restore = time.perf_counter()
            locked_paths, locked_originals, extra_folders = self._collect_locked_files(watch_dirs)
            affected_folders.update(extra_folders)
            recoverable_targets = sorted(existing_damaged | locked_originals)

            vss_restored = 0
            vault_restored = 0
            failed_files = []

            for locked_full in locked_paths:
                try:
                    if os.path.exists(locked_full):
                        os.remove(locked_full)
                except Exception:
                    pass

            for dmg_path in recoverable_targets:
                if TRAP_FOLDER_NAME in dmg_path:
                    continue
                affected_folders.add(self._find_folder_label(dmg_path))
                if try_vss_restore(dmg_path):
                    vss_restored += 1
                elif self.vault.restore_from_vault(dmg_path, watch_dirs=watch_dirs):
                    vault_restored += 1
                else:
                    failed_files.append(f"{self._find_folder_label(dmg_path)}/{os.path.basename(dmg_path)}")

            for folder in watch_dirs:
                setup_honeypots(folder)

            restore_ms = (time.perf_counter() - start_restore) * 1000.0
            total_affected = vss_restored + vault_restored + len(failed_files)
            folder_str = ", ".join(sorted(affected_folders)) if affected_folders else "Monitored Folder"

            if vss_restored > 0 and vault_restored > 0:
                method = "Level 1 VSS + Level 2 Vault"
                details = f"[{folder_str}] {vss_restored} via VSS, {vault_restored} via Vault/{folder_str}"
            elif vss_restored > 0:
                method = "Level 1: Windows VSS Snapshot"
                details = f"[{folder_str}] {vss_restored} files restored from Windows Shadow Copy"
            elif vault_restored > 0:
                method = "Level 2: Folder Backup Vault"
                details = f"[{folder_str}] {vault_restored} files restored from MiniEDR_Backup_Vault/{folder_str}"
            elif failed_files:
                method = "Level 3: Contain & Report"
                details = f"Process stopped. Unrecovered files: {', '.join(failed_files)}"
            elif trap_damaged > 0:
                method = "Honeypot Containment (Pre-Encryption)"
                details = f"Stopped at !000_Trap ({trap_damaged} decoys reset, 0 user files damaged)"
            else:
                method = "Threat Contained (Process Terminated)"
                details = f"Stopped {proc_name} before any existing protected files were damaged"

            if failed_files and method != "Level 3: Contain & Report":
                details += f" | UNRECOVERED ({len(failed_files)}): {', '.join(failed_files)}"
            db.set_setting("last_unrecovered", ", ".join(failed_files))

            behavior = []
            if locked_paths:
                behavior.append(f"Encryption Burst in [{folder_str}] ({len(locked_paths)} files locked)")
            elif existing_damaged:
                behavior.append(f"Header/Entropy Damage in [{folder_str}] ({len(existing_damaged)} files)")
            if trap_damaged:
                behavior.append(f"Canary Trap Hit ({trap_damaged} decoys)")
            final_reason = (" + ".join(behavior) + f" [trigger: {reason}]") if behavior else reason

            self.flush_events()
            db.log_alert(proc_name, pid, disposition, final_reason, max(1, total_affected), method, details, detect_ms, restore_ms)

        except Exception as e:
            logging.exception(f"Trigger response error: {e}")
        finally:
            self.compromised_files.clear()
            self.recent_files.clear()
            self.first_suspicious_time = None
            self.last_alert_time = time.time() + (4.0 if was_whitelisted else 0.0)
            self.recovering = False


def active_patrol_check(vault: VaultManager, handler: MiniEDRHandler, watch_dirs):
    """Checks all monitored folders for new healthy user files or missed .locked files."""
    if handler.recovering or (time.time() < handler.whitelisted_until) or (time.time() - handler.last_alert_time < 2.0):
        return
    locked_count = 0
    for folder in watch_dirs:
        if not os.path.isdir(folder):
            continue
        for root, _, files in os.walk(folder):
            if TRAP_FOLDER_NAME in root or os.path.normcase(VAULT_DIR) in os.path.normcase(root):
                continue
            for f in files:
                fp = os.path.abspath(os.path.join(root, f))
                ext = os.path.splitext(f)[1].lower()
                if ext in SUSPICIOUS_EXTS:
                    locked_count += 1
                elif ext in PROTECTED_EXTS:
                    meta = vault.file_metadata.get(fp)
                    if meta is None or not os.path.exists(vault.get_vault_path(fp, watch_dirs=watch_dirs)):
                        vault.backup_single_file(fp, watch_dirs=watch_dirs)

    if locked_count > 0 and not handler.recovering:
        handler._launch_response(f"Active Patrol: {locked_count} encrypted (.locked) files intercepted")


def schedule_all_watches(observer, handler, vault_guard, watch_dirs):
    """Schedules Watchdog observers on every monitored folder and recursively on the Backup Vault."""
    observer.unschedule_all()
    os.makedirs(VAULT_DIR, exist_ok=True)
    observer.schedule(vault_guard, VAULT_DIR, recursive=True)
    for folder in watch_dirs:
        if os.path.isdir(folder):
            observer.schedule(handler, folder, recursive=True)
            logging.info(f"Watching protected folder: {folder}")


def run_engine():
    for _ in range(40):
        if acquire_single_instance():
            break
        time.sleep(0.25)
    else:
        print("[!] Another engine instance is running. Exiting.")
        return

    db.init_db()
    threading.Thread(target=heartbeat_loop, daemon=True).start()

    db.set_setting("engine_busy", "1")
    watch_dirs = db.get_protected_folders()
    vault = VaultManager(VAULT_DIR)

    os.makedirs(DEMO_SANDBOX, exist_ok=True)
    has_demo_files = any(
        os.path.splitext(f)[1].lower() in PROTECTED_EXTS
        for root, _, fs in os.walk(DEMO_SANDBOX) if TRAP_FOLDER_NAME not in root for f in fs
    )
    if not has_demo_files:
        populate_demo_sandbox(DEMO_SANDBOX)

    # Startup recovery across all monitored folders
    t0 = time.perf_counter()
    found, recovered, failed = 0, 0, []
    for folder in watch_dirs:
        if not os.path.isdir(folder):
            continue
        for root, _, files in os.walk(folder):
            if TRAP_FOLDER_NAME in root:
                continue
            for f in files:
                if os.path.splitext(f)[1].lower() in SUSPICIOUS_EXTS:
                    found += 1
                    locked_p = os.path.join(root, f)
                    orig_p = os.path.splitext(locked_p)[0]
                    if vault.restore_from_vault(orig_p, watch_dirs=watch_dirs):
                        recovered += 1
                    else:
                        failed.append(os.path.basename(orig_p))
                    try:
                        os.remove(locked_p)
                    except Exception:
                        pass
    if found:
        details = f"{recovered} restored from Folder Backup Vault"
        if failed:
            details += f" | UNRECOVERED ({len(failed)}): {', '.join(failed)}"
        db.log_alert(
            "Unknown (sensor was offline)", 0, "contained",
            f"Startup Recovery: {found} encrypted file(s) recovered",
            found, "Level 2: Folder Backup Vault", details,
            0, (time.perf_counter() - t0) * 1000.0
        )
        db.set_setting("last_unrecovered", ", ".join(failed))

    try:
        for folder in watch_dirs:
            setup_honeypots(folder)
        vault.backup_all(watch_dirs)
        create_vss_snapshot(get_primary_drive(watch_dirs))
    except Exception:
        logging.exception("Startup backup / VSS failed")
    finally:
        db.set_setting("engine_busy", "0")

    get_folders = db.get_protected_folders
    io_tracker = ProcessIOTracker(get_folders)
    io_tracker.start()

    handler = MiniEDRHandler(vault, io_tracker, get_folders)
    vault_guard = VaultGuardHandler(vault, io_tracker, get_folders)
    handler.last_alert_time = time.time()

    observer = Observer()
    schedule_all_watches(observer, handler, vault_guard, watch_dirs)
    observer.start()

    if not found:
        db.set_setting("system_status", "SECURE")
    db.set_setting("engine_launching_until", "0")

    print(f"[*] Mini-EDR Engine Running (PID: {os.getpid()} | Admin: {is_running_as_admin()}) | Folders: {len(watch_dirs)} + Vault Guard")

    try:
        while True:
            try:
                watch_dirs = db.get_protected_folders()
                handler.flush_events()
                active_patrol_check(vault, handler, watch_dirs)

                for cmd_id, cmd_name in db.fetch_pending_commands():
                    logging.info(f"Executing command: {cmd_name}")
                    if cmd_name == "REINIT_SANDBOX":
                        handler.recovering = True
                        db.set_setting("engine_busy", "1")
                        try:
                            populate_demo_sandbox(DEMO_SANDBOX)
                            for folder in watch_dirs:
                                setup_honeypots(folder)
                            vault.backup_all(watch_dirs, force=True)
                            if is_running_as_admin():
                                create_vss_snapshot(get_primary_drive(watch_dirs))
                            db.set_setting("system_status", "SECURE")
                            db.set_setting("last_unrecovered", "")
                            db.complete_command(cmd_id, "Sandbox & Vault re-initialized.")
                        finally:
                            db.set_setting("engine_busy", "0")
                            handler.last_alert_time = time.time()
                            handler.recovering = False
                    elif cmd_name == "RELOAD_WATCHES":
                        handler.recovering = True
                        db.set_setting("engine_busy", "1")
                        try:
                            watch_dirs = db.get_protected_folders()
                            for folder in watch_dirs:
                                setup_honeypots(folder)
                            vault.backup_all(watch_dirs)
                            schedule_all_watches(observer, handler, vault_guard, watch_dirs)
                            db.complete_command(cmd_id, f"Now monitoring {len(watch_dirs)} folders.")
                        finally:
                            db.set_setting("engine_busy", "0")
                            handler.last_alert_time = time.time()
                            handler.recovering = False
                    elif cmd_name == "SHUTDOWN_ENGINE":
                        db.complete_command(cmd_id, "Shutting down.")
                        os._exit(0)
                    else:
                        db.complete_command(cmd_id, "Done")
            except Exception:
                logging.exception("Main loop error")
            time.sleep(0.8)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    run_engine()