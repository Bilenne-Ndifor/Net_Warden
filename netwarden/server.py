"""Local HTTP server (127.0.0.1 only) serving the UI and a small JSON API protected by a token."""
from __future__ import annotations

import json
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .safety import NeedsConfirm
from .util import WEB_DIR


def make_server(engine, port: int, token: str, on_quit, on_open=None):
    last_open = [0.0]

    class Handler(BaseHTTPRequestHandler):
        server_version = "NetWarden"

        def log_message(self, *a):  # keep the console quiet
            pass

        # ---------------------------------------------------------------- helpers
        def _host_ok(self):
            host = (self.headers.get("Host") or "").split(":")[0]
            return host in ("127.0.0.1", "localhost")

        def _auth(self):
            return self.headers.get("X-Token") == token

        def _json(self, obj, code=200):
            body = json.dumps(obj, default=_default).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if not n:
                return {}
            return json.loads(self.rfile.read(n).decode() or "{}")

        def _guard(self):
            if not self._host_ok():
                self.send_error(403)
                return False
            if not self._auth():
                self._json({"error": "bad token — reopen NetWarden from run.bat"}, 401)
                return False
            return True

        # ---------------------------------------------------------------- GET
        def do_GET(self):
            if not self._host_ok():
                return self.send_error(403)
            u = urlparse(self.path)
            if u.path == "/api/hello":  # unauthenticated: lets the Start-menu launcher find us
                return self._json({"app": "NetWarden"})
            if u.path.startswith("/api/"):
                if not self._auth():
                    return self._json({"error": "bad token"}, 401)
                q = parse_qs(u.query)
                if u.path == "/api/state":
                    return self._json(engine.state(full=q.get("full", ["0"])[0] == "1"))
                if u.path == "/api/app":
                    d = engine.monitor.app_detail(q.get("key", [""])[0])
                    return self._json(d or {"error": "not found"}, 200 if d else 404)
                return self._json({"error": "not found"}, 404)
            path = "index.html" if u.path in ("/", "") else u.path.lstrip("/")
            f = (WEB_DIR / path).resolve()
            if WEB_DIR.resolve() not in f.parents or not f.is_file():
                return self.send_error(404)
            data = f.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", (mimetypes.guess_type(str(f))[0] or "application/octet-stream")
                             + ("; charset=utf-8" if f.suffix in (".html", ".js", ".css") else ""))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        # ---------------------------------------------------------------- POST / PATCH / DELETE
        def do_POST(self):
            p = urlparse(self.path).path
            if p == "/api/open" and self._host_ok():  # unauthenticated, only opens our own window
                import time as _t
                if on_open and _t.time() - last_open[0] > 1.5:
                    last_open[0] = _t.time()
                    threading.Thread(target=on_open, daemon=True).start()
                return self._json({"ok": True})
            if not self._guard():
                return
            try:
                b = self._body()
                if p == "/api/rules":
                    return self._json(engine.add_rule(b))
                if p == "/api/pause":
                    return self._json(engine.pause_all(b.get("minutes"), bool(b.get("force"))))
                if p == "/api/resume":
                    engine.resume_all()
                    return self._json({"ok": True})
                if p == "/api/allow_app":
                    return self._json({"removed": engine.allow_app(b.get("app"))})
                if p == "/api/kill":
                    return self._json({"ok": engine.kill(b["lip"], b["lport"], b["rip"], b["rport"])})
                if p == "/api/settings":
                    engine.set_settings(b)
                    return self._json(engine.settings)
                if p == "/api/cleanup":
                    engine.cleanup_all()
                    return self._json({"ok": True})
                if p == "/api/usage/reset":
                    engine.usage.reset(b.get("key"))
                    return self._json({"ok": True})
                ld = engine.lockdown
                if p.startswith("/api/lockdown/"):
                    r = self._lockdown_post(p[len("/api/lockdown/"):], b, ld)
                    engine._enforce_soon()
                    return self._json(r)
                if p == "/api/quit":
                    self._json({"ok": True})
                    threading.Thread(target=on_quit, daemon=True).start()
                    return
                return self._json({"error": "not found"}, 404)
            except NeedsConfirm as e:
                return self._json({"error": "needs confirmation", "confirm": e.reasons}, 409)
            except (ValueError, KeyError) as e:
                return self._json({"error": str(e).strip("'")}, 400)

        def _lockdown_post(self, what, b, ld):
            if what == "mode":
                engine.set_lockdown_mode(b.get("mode"), bool(b.get("force")))
                return {"mode": ld.mode}
            if what == "answer":
                return ld.answer(b["id"], b["action"], b.get("scope", "app"), b.get("minutes"), bool(b.get("force")))
            if what == "answer_app":  # answer every pending request of one app at once
                return ld.add_decision(b["app"], b.get("app_name") or b["app"], "app", None,
                                       b["action"], b.get("minutes"), bool(b.get("force")))
            if what == "snooze":
                return {"ok": ld.snooze(b["id"])}
            if what == "decision":
                return ld.add_decision(b["app"], b.get("app_name") or b["app"].split("\\")[-1],
                                       b.get("scope", "app"), b.get("remote"), b.get("action", "allow"),
                                       b.get("minutes"), bool(b.get("force")))
            if what == "group":
                return ld.add_group(b.get("name"))
            if what == "firewall_on":
                engine.turn_on_firewall()
                return {"ok": True}
            raise KeyError("unknown lockdown action")

        def do_PATCH(self):
            if not self._guard():
                return
            p = urlparse(self.path).path
            if p.startswith("/api/lockdown/group/"):
                try:
                    g = engine.lockdown.update_group(p.rsplit("/", 1)[1], self._body())
                    engine._enforce_soon()
                    return self._json(g)
                except NeedsConfirm as e:
                    return self._json({"error": "needs confirmation", "confirm": e.reasons}, 409)
                except (KeyError, ValueError) as e:
                    return self._json({"error": str(e).strip("'")}, 400)
            if p.startswith("/api/rules/"):
                try:
                    return self._json(engine.update_rule(p.rsplit("/", 1)[1], self._body()))
                except NeedsConfirm as e:
                    return self._json({"error": "needs confirmation", "confirm": e.reasons}, 409)
                except KeyError:
                    return self._json({"error": "rule not found"}, 404)
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
            return self._json({"error": "not found"}, 404)

        def do_DELETE(self):
            if not self._guard():
                return
            p = urlparse(self.path).path
            if p.startswith("/api/rules/"):
                return self._json({"ok": engine.delete_rule(p.rsplit("/", 1)[1])})
            if p.startswith("/api/lockdown/decision/"):
                ok = engine.lockdown.delete_decision(p.rsplit("/", 1)[1])
                engine._enforce_soon()
                return self._json({"ok": ok})
            if p.startswith("/api/lockdown/group/"):
                try:
                    engine.lockdown.delete_group(p.rsplit("/", 1)[1])
                    engine._enforce_soon()
                    return self._json({"ok": True})
                except (KeyError, ValueError) as e:
                    return self._json({"error": str(e).strip("'")}, 400)
            return self._json({"error": "not found"}, 404)

    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    return srv


def _default(o):
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    return str(o)
