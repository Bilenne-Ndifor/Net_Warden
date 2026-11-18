"""Updates from GitHub.

How it works
- The version lives in one place: ``__version__`` in netwarden/__init__.py.
- NetWarden reads that line from the repository's main branch (raw.githubusercontent.com)
  at start-up and every 12 hours. A higher number means an update is available.
- "Install update" downloads the branch as a zip, unpacks it into the admin-only data folder and
  runs that version's installer (install.ps1 -Update) in a separate process. The installer stops
  NetWarden, copies the new files, keeps your rules/settings, and starts it again.
- Only the installed copy (C:\\Program Files\\NetWarden) can update itself. A copy run from a git
  clone is updated with ``git pull``.
- In block-all mode NetWarden's own Python is blocked like any other program. For the duration of a
  check/download it adds one temporary allow rule limited to GitHub's addresses, then removes it.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile

from . import __version__
from .util import BASE_DIR

log = logging.getLogger("netwarden")

REPO = "Bilenne-Ndifor/Net_Warden"
BRANCH = "main"
VERSION_URL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/netwarden/__init__.py"
ZIP_URL = f"https://codeload.github.com/{REPO}/zip/refs/heads/{BRANCH}"
PAGE_URL = f"https://github.com/{REPO}"
HOSTS = ("raw.githubusercontent.com", "codeload.github.com")
CHECK_EVERY = 12 * 3600
TEMP_RULE = "NetWardenUpdate_tmp"   # deliberately outside the NetWarden_* prefix the engine reconciles
UA = "NetWarden-updater"
CREATE_NO_WINDOW = 0x08000000


def parse_version(text: str) -> tuple[int, ...] | None:
    m = re.search(r"""__version__\s*=\s*["']([0-9]+(?:\.[0-9]+)*)["']""", text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def vstr(v) -> str:
    return ".".join(map(str, v)) if v else "?"


def is_installed() -> bool:
    """True for the copy in Program Files (the installer puts uninstall.ps1 next to it)."""
    return (BASE_DIR / "uninstall.ps1").is_file() and (BASE_DIR / ".venv").is_dir()


class Updater:
    def __init__(self, engine):
        self.engine = engine
        self.current = parse_version(f'__version__ = "{__version__}"')
        self.lock = threading.Lock()
        self.state = {
            "current": __version__, "latest": None, "available": False, "checked_at": None,
            "error": None, "busy": None, "installed": is_installed(), "page": PAGE_URL,
            "can_install": False,
        }
        self._stop = threading.Event()

    # ------------------------------------------------------------------ public
    def info(self) -> dict:
        s = dict(self.state)
        s["can_install"] = bool(s["available"] and s["installed"] and self.engine.admin and not self.engine.sim)
        s["auto"] = bool(self.engine.settings.get("auto_update_check", True))
        return s

    def start(self):
        if self.engine.sim:
            return
        self._cleanup_leftovers()
        threading.Thread(target=self._loop, daemon=True, name="updater").start()

    def stop(self):
        self._stop.set()

    def check_async(self):
        threading.Thread(target=self.check, daemon=True, name="update-check").start()

    def install_async(self):
        info = self.info()
        if not info["installed"]:
            raise ValueError("This copy isn't installed. Update it with 'git pull', or run 'Install NetWarden.bat'.")
        if not self.engine.admin:
            raise ValueError("NetWarden needs administrator rights to update itself.")
        if not info["available"]:
            raise ValueError("No update available.")
        if self.state["busy"]:
            raise ValueError("Already busy: " + self.state["busy"])
        self.state["busy"] = "downloading"
        threading.Thread(target=self._install, daemon=True, name="update-install").start()
        return {"ok": True}

    # ------------------------------------------------------------------ checking
    def _loop(self):
        if self._stop.wait(25):          # let start-up (firewall reconcile) settle first
            return
        while True:
            if self.engine.settings.get("auto_update_check", True):
                self.check()
            if self._stop.wait(CHECK_EVERY):
                return

    def check(self):
        if self.engine.sim:
            return self.info()
        with self.lock:
            if self.state["busy"] and self.state["busy"] != "checking":
                return self.info()
            self.state["busy"] = "checking"
            try:
                with self._network():
                    text = self._get(VERSION_URL, 15).decode("utf-8", "replace")
                latest = parse_version(text)
                if not latest:
                    raise ValueError("couldn't read the version number on GitHub")
                self.state.update(latest=vstr(latest), available=latest > self.current, error=None)
                if self.state["available"]:
                    log.info("Update available: %s -> %s", __version__, vstr(latest))
            except Exception as e:  # noqa: BLE001
                self.state["error"] = _friendly(e)
                log.info("Update check failed: %s", e)
            finally:
                self.state["checked_at"] = time.time()
                self.state["busy"] = None
        return self.info()

    # ------------------------------------------------------------------ installing
    def _install(self):
        work = self.engine.data_dir / "update"
        try:
            shutil.rmtree(work, ignore_errors=True)
            work.mkdir(parents=True, exist_ok=True)
            zpath = work / "netwarden.zip"
            with self._network():
                zpath.write_bytes(self._get(ZIP_URL, 120))
            self.state["busy"] = "unpacking"
            with zipfile.ZipFile(zpath) as z:
                for n in z.namelist():   # refuse odd paths
                    if n.startswith("/") or ".." in n.replace("\\", "/").split("/"):
                        raise ValueError("unexpected file in the download")
                z.extractall(work / "src")
            roots = [p for p in (work / "src").iterdir() if (p / "installer" / "install.ps1").is_file()]
            if not roots:
                raise ValueError("the download doesn't contain the installer")
            root = roots[0]
            got = parse_version((root / "netwarden" / "__init__.py").read_text(encoding="utf-8", errors="replace"))
            if not got or got <= self.current:
                raise ValueError(f"the download is version {vstr(got)}, not newer than {__version__}")
            self.state["busy"] = "installing"
            log.info("Installing update %s from %s", vstr(got), root)
            self.engine.log("info", f"Updating NetWarden to {vstr(got)} — it restarts in a moment.")
            _launch_detached(root / "installer" / "install.ps1", work / "update.log")
        except Exception as e:  # noqa: BLE001
            log.warning("Update failed: %s", e)
            self.state["error"] = "Update failed: " + _friendly(e)
            self.state["busy"] = None

    def _cleanup_leftovers(self):
        work = self.engine.data_dir / "update"
        if (work / "src").exists():
            shutil.rmtree(work / "src", ignore_errors=True)
            try:
                (work / "netwarden.zip").unlink()
            except OSError:
                pass

    # ------------------------------------------------------------------ network helpers
    def _get(self, url, timeout):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()

    def _network(self):
        return _TempAllow(self.engine)


class _TempAllow:
    """While block-all is on, let only NetWarden's Python reach GitHub, for one request."""

    def __init__(self, engine):
        self.engine = engine
        self.added = False

    def __enter__(self):
        e = self.engine
        try:
            on = e.lockdown.mode != "off" and e.admin and not e.sim
        except Exception:
            on = False
        if not on:
            return self
        ips = set()
        for h in HOSTS:
            try:
                for fam, *_r, sa in socket.getaddrinfo(h, 443, proto=socket.IPPROTO_TCP):
                    ips.add(sa[0].split("%")[0])
            except OSError:
                pass
        if ips:
            ok, out = e.fw.add(TEMP_RULE, {"dir": "out", "action": "allow", "program": sys.executable,
                                            "remoteip": ",".join(sorted(ips)), "protocol": "tcp",
                                            "remoteport": "443"})
            self.added = ok
            if not ok:
                log.info("Could not add the temporary update rule: %s", out)
            time.sleep(0.5)
        return self

    def __exit__(self, *exc):
        if self.added:
            self.engine.fw.remove(TEMP_RULE)
        return False


def _launch_detached(script, logfile):
    """Run the new installer outside NetWarden's process tree: it stops NetWarden (and the task that
    started it), so it must not be a child of it. WMI's Win32_Process.Create gives it a new parent."""
    cmd = (f'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden '
           f'-File "{script}" -Update -LogFile "{logfile}"')
    ps = ("$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="
          + "'" + cmd.replace("'", "''") + "'}; $r.ReturnValue")
    p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
                       capture_output=True, text=True, timeout=60, creationflags=CREATE_NO_WINDOW)
    if p.returncode != 0 or p.stdout.strip() != "0":
        # fallback: a detached process that breaks away from the task's job object
        flags = 0x00000008 | 0x00000200 | 0x01000000 | CREATE_NO_WINDOW  # DETACHED | NEW_GROUP | BREAKAWAY
        subprocess.Popen(cmd, creationflags=flags, close_fds=True)


def _friendly(e) -> str:
    s = str(e)
    if isinstance(e, urllib.error.HTTPError):
        return f"GitHub answered {e.code}"
    if isinstance(e, (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError)):
        return "couldn't reach GitHub (offline, or blocked?)"
    return s[:200]

