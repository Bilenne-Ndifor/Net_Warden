"""Desktop agent: tray icon + always-on-top permission pop-ups.

Runs on the main thread (Tk requires it). The tray icon (pystray) runs on its own thread and
hands work to the Tk thread through a queue. Both are optional: without Tk there are no pop-ups
(requests still appear in the NetWarden window and as tray notifications); without pystray there
is no tray icon.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque

log = logging.getLogger("netwarden")

BG, PANEL, LINE, TEXT, MUTED = "#111821", "#16202b", "#2a3949", "#e6edf3", "#8a99ab"
DOWN, UP, OK, BAD = "#38bdf8", "#f5a524", "#34d399", "#f87171"
AV_COLORS = ["#38bdf8", "#f5a524", "#34d399", "#a78bfa", "#f472b6", "#60a5fa", "#fb923c", "#4ade80"]
MODE_NAMES = {"off": "Normal", "ask": "Ask before connecting", "allowlist": "Only allowed apps"}


def _initials(name):
    w = [x for x in name.replace(".exe", "").replace("-", " ").replace("_", " ").split() if x]
    return ((w[0][0] if w else "?") + (w[1][0] if len(w) > 1 else "")).upper()


def _work_area():
    """Desktop rectangle without the taskbar (Windows); falls back to the screen size."""
    try:
        import ctypes
        from ctypes import wintypes
        r = wintypes.RECT()
        if ctypes.windll.user32.SystemParametersInfoW(0x30, 0, ctypes.byref(r), 0):
            return r.left, r.top, r.right, r.bottom
    except Exception:
        pass
    return None


class Agent:
    def __init__(self, engine, open_ui, quit_app):
        self.engine = engine
        self.open_ui = open_ui
        self.quit_app = quit_app
        self.calls = deque()          # work for the Tk thread
        self.root = None
        self.tk = None
        self.popup = None
        self.popup_ids: list[str] = []
        self.icon = None
        self.icon_state = None
        self.notified: set[str] = set()
        self.tray_error = None
        self.tk_error = None

    # ------------------------------------------------------------------ main loop
    def run(self, stopped: threading.Event):
        self._start_tray()
        try:
            try:
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
            import tkinter as tk
            self.tk = tk
            self.root = tk.Tk()
            self.root.withdraw()
            self.root.title("NetWarden")
        except Exception as e:  # noqa: BLE001
            self.tk_error = str(e)
            log.warning("No pop-ups (tkinter unavailable): %s", e)
            self.root = None
        if self.root is not None:
            def loop():
                if stopped.is_set():
                    self.root.quit()
                    return
                self._tick()
                self.root.after(600, loop)
            self.root.after(300, loop)
            self.root.mainloop()
            try:
                self.root.destroy()
            except Exception:
                pass
        else:
            while not stopped.wait(0.8):
                self._tick()
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass

    def _tick(self):
        while self.calls:
            try:
                self.calls.popleft()()
            except Exception:
                log.exception("agent call failed")
        try:
            self._update_tray()
            self._prompts()
        except Exception:
            log.exception("agent tick failed")

    # ------------------------------------------------------------------ prompts
    def _prompts(self):
        ld = self.engine.lockdown
        pending = ld.pending_list() if ld.mode == "ask" else []
        ids = {p["id"] for p in pending}
        if self.popup is not None and not (set(self.popup_ids) & ids):
            self._close_popup()  # answered elsewhere (e.g. in the main window)
        if not pending:
            return
        if self.root is None:
            for p in pending:
                if p["id"] not in self.notified and self.icon:
                    self.notified.add(p["id"])
                    try:
                        self.icon.notify(f"{p['app_name']} wants to connect to {p.get('host') or p['ip']}. "
                                         f"Open NetWarden to allow or block it.", "NetWarden: permission needed")
                    except Exception:
                        pass
            return
        if self.popup is None:
            first = pending[0]
            group = [p for p in pending if p["app"].lower() == first["app"].lower()]
            self._show_popup(group, len({p["app"].lower() for p in pending}))

    def _close_popup(self):
        if self.popup is not None:
            try:
                self.popup.destroy()
            except Exception:
                pass
        self.popup = None
        self.popup_ids = []

    def _show_popup(self, group, apps_waiting):
        tk = self.tk
        p = group[0]
        pro = p["granularity"] == "address"
        w = tk.Toplevel(self.root)
        self.popup, self.popup_ids = w, [x["id"] for x in group]
        w.overrideredirect(True)
        w.attributes("-topmost", True)
        w.configure(bg=LINE)
        body = tk.Frame(w, bg=BG, padx=16, pady=12)
        body.pack(fill="both", expand=True, padx=1, pady=1)
        f_small = ("Segoe UI", 9)
        f_norm = ("Segoe UI", 10)
        f_bold = ("Segoe UI Semibold", 12)

        top = tk.Frame(body, bg=BG)
        top.pack(fill="x")
        tk.Label(top, text="●", fg=UP, bg=BG, font=f_small).pack(side="left")
        tk.Label(top, text=" NetWarden · permission needed", fg=MUTED, bg=BG, font=f_small).pack(side="left")
        x = tk.Label(top, text="✕", fg=MUTED, bg=BG, font=f_norm, cursor="hand2")
        x.pack(side="right")
        x.bind("<Button-1>", lambda e: self._later(group))
        if apps_waiting > 1:
            tk.Label(top, text=f"{apps_waiting} apps waiting  ", fg=MUTED, bg=BG, font=f_small).pack(side="right")

        row = tk.Frame(body, bg=BG, pady=10)
        row.pack(fill="x")
        av = tk.Canvas(row, width=40, height=40, bg=BG, highlightthickness=0)
        col = AV_COLORS[sum(map(ord, p["app_name"])) % len(AV_COLORS)]
        av.create_rectangle(0, 0, 40, 40, fill=col, outline=col)
        av.create_text(20, 20, text=_initials(p["app_name"]), fill=BG, font=("Segoe UI Semibold", 13))
        av.pack(side="left", padx=(0, 12))
        info = tk.Frame(row, bg=BG)
        info.pack(side="left", fill="x", expand=True)
        tk.Label(info, text=p["app_name"], fg=TEXT, bg=BG, font=f_bold, anchor="w").pack(fill="x")
        path = p["app"] if len(p["app"]) < 58 else "…" + p["app"][-56:]
        tk.Label(info, text=path, fg=MUTED, bg=BG, font=("Segoe UI", 8), anchor="w").pack(fill="x")

        if pro:
            tk.Label(body, text="wants to connect to", fg=MUTED, bg=BG, font=f_norm, anchor="w").pack(fill="x")
            dest = f"{p.get('host') or p['ip']}"
            tk.Label(body, text=dest, fg=DOWN, bg=BG, font=("Segoe UI Semibold", 11), anchor="w").pack(fill="x")
            tk.Label(body, text=f"{p['ip']} · port {p['port']} · {p['proto'].upper()} · {p['count']} attempt(s)",
                     fg=MUTED, bg=BG, font=f_small, anchor="w").pack(fill="x")
            if len(group) > 1:
                tk.Label(body, text=f"+ {len(group) - 1} more address(es) from this app are waiting",
                         fg=UP, bg=BG, font=f_small, anchor="w").pack(fill="x")
        else:
            tk.Label(body, text="wants to connect to the internet.", fg=TEXT, bg=BG, font=f_norm,
                     anchor="w").pack(fill="x")
            tk.Label(body, text="First tried: " + ", ".join(p["dests"][:2]), fg=MUTED, bg=BG, font=f_small,
                     anchor="w").pack(fill="x")

        scope = tk.StringVar(value="address" if pro else "app")
        if pro:
            sf = tk.Frame(body, bg=BG, pady=6)
            sf.pack(fill="x")
            tk.Label(sf, text="Apply to:", fg=MUTED, bg=BG, font=f_small).pack(side="left")
            opts = [("this address", "address"), ("this domain", "domain"), ("whole app", "app")]
            for label, val in opts:
                rb = tk.Radiobutton(sf, text=label, value=val, variable=scope, fg=TEXT, bg=BG, selectcolor=PANEL,
                                    activebackground=BG, activeforeground=TEXT, font=f_small, highlightthickness=0)
                if val == "domain" and not p.get("host"):
                    rb.configure(state="disabled")
                rb.pack(side="left", padx=(6, 0))
        hour = tk.BooleanVar(value=False)
        tk.Checkbutton(body, text="Only for 1 hour", variable=hour, fg=MUTED, bg=BG, selectcolor=PANEL,
                       activebackground=BG, activeforeground=TEXT, font=f_small, highlightthickness=0,
                       anchor="w").pack(fill="x", pady=(2, 8))

        btns = tk.Frame(body, bg=BG)
        btns.pack(fill="x")

        def mk(text, bg, fg, cmd):
            b = tk.Button(btns, text=text, bg=bg, fg=fg, activebackground=bg, activeforeground=fg, relief="flat",
                          bd=0, highlightthickness=0, padx=16, pady=6, font=("Segoe UI Semibold", 10), cursor="hand2", command=cmd)
            return b
        mk("Block", "#3a1416", "#ffd4d4", lambda: self._answer(group, "deny", scope.get(), hour.get())).pack(side="left")
        mk("Later", PANEL, MUTED, lambda: self._later(group)).pack(side="left", padx=8)
        mk("Allow", "#0e3a52", "#d5f0ff", lambda: self._answer(group, "allow", scope.get(), hour.get())).pack(side="right")
        link = tk.Label(body, text="Open NetWarden", fg=DOWN, bg=BG, font=("Segoe UI", 8, "underline"), cursor="hand2")
        link.pack(anchor="w", pady=(8, 0))
        link.bind("<Button-1>", lambda e: self.open_ui())

        w.update_idletasks()
        width = max(400, w.winfo_reqwidth())
        height = w.winfo_reqheight()
        area = _work_area()
        if area:
            x0 = area[2] - width - 16
            y0 = area[3] - height - 16
        else:
            x0 = w.winfo_screenwidth() - width - 24
            y0 = w.winfo_screenheight() - height - 72
        w.geometry(f"{width}x{height}+{x0}+{y0}")
        try:
            import winsound
            winsound.MessageBeep(0x40)
        except Exception:
            pass

    def _answer(self, group, action, scope, one_hour):
        ld = self.engine.lockdown
        minutes = 60 if (one_hour and action == "allow") else None
        p = group[0]
        try:
            if scope == "app" or p["granularity"] == "app":
                ld.add_decision(p["app"], p["app_name"], "app", None, action, minutes)
            else:
                ld.answer(p["id"], action, scope, minutes)
        except Exception as e:  # noqa: BLE001
            log.warning("answer failed: %s", e)
        self.engine._enforce_soon()
        self._close_popup()

    def _later(self, group):
        for p in group:
            self.engine.lockdown.snooze(p["id"])
        self._close_popup()

    # ------------------------------------------------------------------ tray
    def _icon_image(self, color):
        from PIL import Image, ImageDraw
        im = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(im)
        d.polygon([(32, 3), (7, 12), (7, 32), (14, 47), (32, 61), (50, 47), (57, 32), (57, 12)], fill=color)
        d.line([(17, 35), (25, 35), (29, 23), (36, 45), (40, 33), (47, 33)], fill=(11, 15, 20), width=5, joint="curve")
        return im

    def _state(self):
        e = self.engine
        paused = any(r.get("pause_all") for r in e.rules)
        mode = e.lockdown.mode
        waiting = len(e.lockdown.pending) if mode == "ask" else 0
        return mode, paused, waiting

    def _start_tray(self):
        try:
            import pystray
        except Exception as e:  # noqa: BLE001
            self.tray_error = str(e)
            log.warning("No tray icon (pystray unavailable): %s", e)
            return
        e = self.engine
        ld = e.lockdown

        def set_mode(m):
            def f(icon, item):
                try:
                    e.set_lockdown_mode(m)
                except Exception as ex:  # noqa: BLE001
                    log.warning("mode change failed: %s", ex)
            return f

        def quit_(icon, item):
            self.calls.append(self._confirm_quit)

        menu = pystray.Menu(
            pystray.MenuItem("Open NetWarden", lambda icon, item: self.open_ui(), default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Normal — apps connect freely", set_mode("off"),
                             checked=lambda item: ld.mode == "off", radio=True),
            pystray.MenuItem("Block all — ask me for each app", set_mode("ask"),
                             checked=lambda item: ld.mode == "ask", radio=True),
            pystray.MenuItem("Block all except allowed apps", set_mode("allowlist"),
                             checked=lambda item: ld.mode == "allowlist", radio=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Pause internet for 15 min", lambda icon, item: e.pause_all(15)),
            pystray.MenuItem("Resume internet", lambda icon, item: e.resume_all(),
                             enabled=lambda item: any(r.get("pause_all") for r in e.rules)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit NetWarden", quit_),
        )
        try:
            self.icon = pystray.Icon("NetWarden", self._icon_image((56, 189, 248)), "NetWarden", menu)
            self.icon.run_detached()
        except Exception as ex:  # noqa: BLE001
            self.tray_error = str(ex)
            self.icon = None
            log.warning("Tray icon failed: %s", ex)

    def _update_tray(self):
        if not self.icon:
            return
        st = self._state()
        if st == self.icon_state:
            return
        self.icon_state = st
        mode, paused, waiting = st
        color = (167, 139, 250) if paused else {"off": (56, 189, 248), "ask": (245, 165, 36),
                                                 "allowlist": (52, 211, 153)}[mode]
        try:
            self.icon.icon = self._icon_image(color)
            title = "NetWarden — " + ("internet paused" if paused else MODE_NAMES[mode])
            if waiting:
                title += f" — {waiting} waiting for you"
            self.icon.title = title
            self.icon.update_menu()
        except Exception:
            pass

    def _confirm_quit(self):
        mode = self.engine.lockdown.mode
        msg = "Quit NetWarden?\n\n"
        if mode != "off":
            msg += ("Block-all mode stays on while NetWarden is closed: apps you haven't allowed stay blocked "
                    "and won't be able to ask. Switch to Normal first if you want everything open again.")
        else:
            msg += "Monitoring stops and NetWarden's blocks and limits are lifted until it starts again."
        ok = True
        if self.root is not None:
            from tkinter import messagebox
            self.root.attributes("-topmost", True)
            ok = messagebox.askyesno("NetWarden", msg, parent=self.root)
        if ok:
            threading.Thread(target=self.quit_app, daemon=True).start()


def make_ico(path):
    """Write the NetWarden shield as a multi-size .ico (used for shortcuts by the installer)."""
    from PIL import Image, ImageDraw
    im = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    pts = [(32, 3), (7, 12), (7, 32), (14, 47), (32, 61), (50, 47), (57, 32), (57, 12)]
    d.polygon([(x * 4, y * 4) for x, y in pts], fill=(56, 189, 248))
    d.line([(x * 4, y * 4) for x, y in [(17, 35), (25, 35), (29, 23), (36, 45), (40, 33), (47, 33)]],
           fill=(11, 15, 20), width=20, joint="curve")
    im.save(path, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
