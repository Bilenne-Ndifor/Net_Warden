"""NetWarden entry point.

  python -m netwarden                 run with a console + tray + pop-ups, open the window
  python -m netwarden --background    run silently (tray + pop-ups), used by the installed autostart task
  python -m netwarden --open          launcher for shortcuts: show the running instance or start it
  python -m netwarden --sim           demo mode with simulated traffic (no system changes)
  python -m netwarden --cleanup       remove every NetWarden firewall/QoS rule and exit
"""
from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser

from .util import DATA_DIR, IS_WINDOWS

SESSION = DATA_DIR / "session.json"
TASK_NAME = "NetWarden"
LIVE_PORT, DEMO_PORT = 47800, 47900
log = logging.getLogger("netwarden")


def session_path(sim: bool):
    return (DATA_DIR / "demo" / "session.json") if sim else SESSION


def setup_logging(sim: bool, background: bool):
    d = DATA_DIR / "demo" if sim else DATA_DIR
    d.mkdir(parents=True, exist_ok=True)
    h = logging.handlers.RotatingFileHandler(d / "netwarden.log", maxBytes=1_000_000, backupCount=2, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(h)
    if not background:
        root.addHandler(logging.StreamHandler())

    def hook(args):
        log.error("Unhandled error in thread %s", args.thread.name if args.thread else "?",
                  exc_info=(args.exc_type, args.exc_value, args.exc_traceback))
    threading.excepthook = hook


def open_window(url: str):
    """Open the UI in a chromeless Edge/Chrome app window, falling back to the default browser."""
    if IS_WINDOWS:
        cands = [
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        ]
        profile = DATA_DIR / "ui-profile"
        for exe in cands:
            if os.path.isfile(exe):
                try:
                    subprocess.Popen([exe, f"--app={url}", "--window-size=1360,880", f"--user-data-dir={profile}",
                                      "--no-first-run", "--no-default-browser-check", "--disable-sync",
                                      "--disable-background-networking", "--disable-component-update"])
                    return
                except Exception:
                    pass
    webbrowser.open(url)


def existing_instance(path):
    try:
        s = json.loads(path.read_text())
        req = urllib.request.Request(f"http://127.0.0.1:{s['port']}/api/state", headers={"X-Token": s["token"]})
        with urllib.request.urlopen(req, timeout=1.5) as r:
            if r.status == 200:
                return s
    except Exception:
        return None
    return None


def find_running(base: int) -> int | None:
    """Port of a running NetWarden (works without admin rights: /api/hello needs no token)."""
    for port in range(base, base + 20):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/hello", timeout=0.6) as r:
                if json.loads(r.read().decode()).get("app") == "NetWarden":
                    return port
        except Exception:
            continue
    return None


def ask_open(port: int) -> bool:
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/open", data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=2).read()
        return True
    except Exception:
        return False


def launcher(sim: bool):
    """Start-menu / desktop shortcut: never runs the engine itself without admin rights."""
    base = DEMO_PORT if sim else LIVE_PORT
    port = find_running(base)
    if port:
        ask_open(port)
        return
    if not sim and IS_WINDOWS:
        # 1) the autostart task (already approved for admin rights at install time, no UAC prompt)
        r = subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], capture_output=True, creationflags=0x08000000)
        if r.returncode != 0:
            # 2) not installed as a task: ask for admin rights directly
            import ctypes
            exe = sys.executable
            ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, "-m netwarden --background",
                                                os.getcwd(), 0)
        for _ in range(60):
            time.sleep(0.5)
            port = find_running(base)
            if port and ask_open(port):
                return
        return
    # demo / non-Windows: just start it normally
    subprocess.Popen([sys.executable, "-m", "netwarden", "--sim"])


def main():
    ap = argparse.ArgumentParser(prog="netwarden")
    ap.add_argument("--sim", action="store_true", help="demo mode with simulated traffic (no system changes)")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--no-window", action="store_true", help="don't open the UI window at start")
    ap.add_argument("--background", action="store_true", help="run silently with tray icon (autostart)")
    ap.add_argument("--open", action="store_true", help="open the running NetWarden, starting it if needed")
    ap.add_argument("--show", action="store_true", help="open the window even in --background mode")
    ap.add_argument("--no-agent", action="store_true", help="no tray icon / pop-ups")
    ap.add_argument("--cleanup", action="store_true", help="remove every NetWarden firewall/QoS rule and exit")
    args = ap.parse_args()
    sim = args.sim or not IS_WINDOWS

    if args.open:
        launcher(sim)
        return

    if args.cleanup:
        from .winapi import WindowsFirewall, WindowsQos
        print("Removing NetWarden firewall rules…", WindowsFirewall().cleanup())
        print("Removing NetWarden QoS policies…", WindowsQos().cleanup())
        return

    session = session_path(sim)
    inst = existing_instance(session)
    if inst:
        if not args.background or args.show:
            print("NetWarden is already running — opening its window.")
            open_window(f"http://127.0.0.1:{inst['port']}/?t={inst['token']}")
        return
    # Another copy (e.g. the installed one vs. this folder) must never run a second engine:
    # two engines would fight over the same firewall rules.
    other = find_running(DEMO_PORT if sim else LIVE_PORT)
    if other:
        print("NetWarden is already running (another copy) — opening its window.")
        if not args.background or args.show:
            ask_open(other)
        return

    setup_logging(sim, args.background)
    from .engine import Engine
    from .server import make_server

    engine = Engine(sim=sim)
    token = secrets.token_urlsafe(18)
    stopped = threading.Event()
    srv = None
    url_box = {}

    def show():
        open_window(url_box["url"])

    def stop(*_):
        if stopped.is_set():
            return
        stopped.set()
        log.info("Stopping NetWarden")
        engine.shutdown()
        try:
            session.unlink()
        except Exception:
            pass
        if srv is not None:
            threading.Thread(target=srv.shutdown, daemon=True).start()

    base_port = args.port or (DEMO_PORT if sim else LIVE_PORT)
    for port in range(base_port, base_port + 20):
        try:
            srv = make_server(engine, port, token, on_quit=stop, on_open=show)
            break
        except OSError:
            continue
    if srv is None:
        log.error("No free port found.")
        sys.exit(1)
    port = srv.server_address[1]
    url_box["url"] = f"http://127.0.0.1:{port}/?t={token}"
    session.parent.mkdir(parents=True, exist_ok=True)
    session.write_text(json.dumps({"port": port, "token": token, "pid": os.getpid()}))

    # Closing the console / logging off must still run shutdown.
    if IS_WINDOWS:
        import ctypes
        HANDLER = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_ulong)

        def _ctrl(evt):
            stop()
            time.sleep(1.5)
            return 1
        _ctrl_ref = HANDLER(_ctrl)
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_ctrl_ref, True)
        main._keep = _ctrl_ref
    else:
        signal.signal(signal.SIGTERM, stop)

    engine.start()
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True, name="http").start()
    mode = "SIMULATION (demo data)" if engine.sim else ("LIVE" + ("" if engine.admin else " — NOT ADMIN, monitor only"))
    banner = (f"NetWarden is running [{mode}] on {url_box['url']}")
    log.info(banner)
    if not args.background:
        print("=" * 64)
        print(f"  NetWarden is running  [{mode}]")
        print(f"  UI: {url_box['url']}")
        print("  Use the tray icon (near the clock) or this window. Closing this")
        print("  window stops NetWarden. Install it to run in the background.")
        print("=" * 64)
    if (not args.background and not args.no_window) or args.show:
        threading.Timer(0.6, show).start()

    try:
        if args.no_agent:
            while not stopped.wait(0.5):
                pass
        else:
            from .agent import Agent
            Agent(engine, open_ui=show, quit_app=stop).run(stopped)
    except KeyboardInterrupt:
        pass
    finally:
        stop()


if __name__ == "__main__":
    main()
