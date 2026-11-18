"""Turns raw connections + packet byte counts into per-app, per-connection and per-endpoint stats."""
from __future__ import annotations

import socket
import threading
import time
from collections import deque

from .util import is_loopback

EMA = 0.45  # smoothing for rates


def app_key(info: dict) -> str:
    return (info.get("exe") or info.get("name") or "unknown").lower()


class AppStat:
    __slots__ = ("key", "name", "exe", "friendly", "pids", "up", "down", "rate_up", "rate_down",
                 "conns", "endpoints", "first_seen", "last_active", "hist", "services", "user")

    def __init__(self, key, info):
        self.key = key
        self.name = info.get("name")
        self.exe = info.get("exe")
        self.friendly = info.get("friendly") or self.name
        self.user = info.get("user")
        self.services = set()
        self.pids = set()
        self.up = self.down = 0
        self.rate_up = self.rate_down = 0.0
        self.conns = 0
        self.endpoints: dict[str, float] = {}
        self.first_seen = time.time()
        self.last_active = 0.0
        self.hist = deque(maxlen=60)


class Monitor:
    def __init__(self, source, on_event=None):
        self.src = source
        self.on_event = on_event or (lambda kind, msg: None)
        self.lock = threading.RLock()
        self.apps: dict[str, AppStat] = {}
        self.flows: dict[tuple, dict] = {}
        self.endpoints: dict[str, dict] = {}
        self.tcp_live: list[dict] = []
        self.history = deque(maxlen=300)
        self.portmap: dict[tuple, int] = {}
        self.total = {"up": 0, "down": 0, "rate_up": 0.0, "rate_down": 0.0}
        self.unattributed = {"up": 0, "down": 0}
        self._io_last = None
        self._t_last = time.time()
        self.ticks = 0

    # ------------------------------------------------------------------ tick
    def tick(self) -> tuple[dict, tuple[int, int]]:
        """Collect one sample. Returns ({app_key: [up, down]} deltas, (sys_up, sys_down) deltas)."""
        t = time.time()
        dt = max(0.2, t - self._t_last)
        self._t_last = t
        conns = self.src.connections()
        deltas = self.src.drain()
        io = self.src.net_io()
        app_deltas: dict[str, list[int]] = {}

        with self.lock:
            self.ticks += 1
            portmap = {}
            tcp_live = []
            conn_count: dict[str, int] = {}
            seen_pids: dict[str, set] = {}
            for c in conns:
                pid = c.pid
                if not pid:
                    continue
                proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                if c.laddr:
                    portmap[(proto, c.laddr.port)] = pid
                info = self.src.proc_info(pid)
                key = app_key(info)
                app = self._app(key, info)
                app.pids.add(pid)
                app.services.update(info.get("services") or [])
                seen_pids.setdefault(key, set()).add(pid)
                if proto == "tcp" and c.raddr and c.raddr.ip and not is_loopback(c.raddr.ip):
                    if c.status in ("LISTEN",):
                        continue
                    tcp_live.append({"pid": pid, "app": key, "proto": "tcp", "lip": c.laddr.ip,
                                     "lport": c.laddr.port, "rip": c.raddr.ip, "rport": c.raddr.port,
                                     "status": c.status, "v6": c.family == socket.AF_INET6})
                    if c.status == "ESTABLISHED":
                        conn_count[key] = conn_count.get(key, 0) + 1
            old_map = self.portmap
            self.portmap = portmap

            # attribute packet bytes
            for (proto, lport, rip, rport), (up, down) in deltas.items():
                pid = portmap.get((proto, lport)) or old_map.get((proto, lport))
                key = None
                if pid:
                    info = self.src.proc_info(pid)
                    key = app_key(info)
                    app = self._app(key, info)
                    app.up += up
                    app.down += down
                    app.last_active = t
                    app.endpoints[rip] = t
                    d = app_deltas.setdefault(key, [0, 0])
                    d[0] += up
                    d[1] += down
                else:
                    self.unattributed["up"] += up
                    self.unattributed["down"] += down
                fk = (proto, lport, rip, rport)
                f = self.flows.get(fk)
                if f is None:
                    f = self.flows[fk] = {"proto": proto, "lport": lport, "rip": rip, "rport": rport,
                                          "up": 0, "down": 0, "rate_up": 0.0, "rate_down": 0.0,
                                          "first": t, "pid": pid, "app": key}
                f["up"] += up
                f["down"] += down
                f["last"] = t
                f["_du"] = f.get("_du", 0) + up
                f["_dd"] = f.get("_dd", 0) + down
                if pid:
                    f["pid"], f["app"] = pid, key
                ep = self.endpoints.get(rip)
                if ep is None:
                    ep = self.endpoints[rip] = {"ip": rip, "up": 0, "down": 0, "apps": set(), "ports": set(),
                                                "protos": set(), "first": t, "rate_up": 0.0, "rate_down": 0.0,
                                                "_du": 0, "_dd": 0}
                ep["up"] += up
                ep["down"] += down
                ep["_du"] += up
                ep["_dd"] += down
                ep["last"] = t
                ep["ports"].add(rport)
                ep["protos"].add(proto)
                if key:
                    ep["apps"].add(key)

            # TCP connections the sniffer hasn't seen bytes for yet still define endpoints
            for c in tcp_live:
                ep = self.endpoints.get(c["rip"])
                if ep is None:
                    ep = self.endpoints[c["rip"]] = {"ip": c["rip"], "up": 0, "down": 0, "apps": set(),
                                                     "ports": set(), "protos": set(), "first": t,
                                                     "rate_up": 0.0, "rate_down": 0.0, "_du": 0, "_dd": 0}
                ep["last"] = t
                ep["apps"].add(c["app"])
                ep["ports"].add(c["rport"])
                ep["protos"].add("tcp")
                self.apps[c["app"]].endpoints[c["rip"]] = t

            # rates
            for key, app in self.apps.items():
                du, dd = app_deltas.get(key, (0, 0))
                app.rate_up = app.rate_up * (1 - EMA) + (du / dt) * EMA
                app.rate_down = app.rate_down * (1 - EMA) + (dd / dt) * EMA
                if app.rate_up < 1 and app.rate_down < 1:
                    app.rate_up = app.rate_down = 0.0
                app.conns = conn_count.get(key, 0)
                if key in seen_pids:
                    app.pids = seen_pids[key]
                app.hist.append((round(app.rate_down), round(app.rate_up)))
                if len(app.endpoints) > 400:
                    for ip, _ in sorted(app.endpoints.items(), key=lambda kv: kv[1])[:100]:
                        app.endpoints.pop(ip, None)
            for coll in (self.flows, self.endpoints):
                for v in coll.values():
                    du, dd = v.pop("_du", 0), v.pop("_dd", 0)
                    v["rate_up"] = v["rate_up"] * (1 - EMA) + (du / dt) * EMA
                    v["rate_down"] = v["rate_down"] * (1 - EMA) + (dd / dt) * EMA
                    if v["rate_up"] < 1 and v["rate_down"] < 1:
                        v["rate_up"] = v["rate_down"] = 0.0
                    v["_du"] = v["_dd"] = 0
            # prune
            for fk in [k for k, f in self.flows.items() if t - f.get("last", t) > 120]:
                del self.flows[fk]
            if len(self.endpoints) > 3000:
                for ip, _ in sorted(self.endpoints.items(), key=lambda kv: kv[1].get("last", 0))[:500]:
                    del self.endpoints[ip]
            self.tcp_live = tcp_live

            # adapter totals (exact, independent of the sniffer)
            sys_delta = (0, 0)
            if self._io_last is not None:
                sys_delta = (max(0, io[0] - self._io_last[0]), max(0, io[1] - self._io_last[1]))
            self._io_last = io
            self.total["up"] += sys_delta[0]
            self.total["down"] += sys_delta[1]
            self.total["rate_up"] = self.total["rate_up"] * (1 - EMA) + (sys_delta[0] / dt) * EMA
            self.total["rate_down"] = self.total["rate_down"] * (1 - EMA) + (sys_delta[1] / dt) * EMA
            self.history.append((round(t), round(self.total["rate_down"]), round(self.total["rate_up"])))
        return app_deltas, sys_delta

    def _app(self, key, info) -> AppStat:
        app = self.apps.get(key)
        if app is None:
            app = self.apps[key] = AppStat(key, info)
            if self.ticks > 2:
                self.on_event("new_app", f"{app.friendly} ({app.name}) started using the network")
        return app

    # ------------------------------------------------------------------ views
    def host(self, ip):
        return self.src.dns.host_for(ip)

    def live_tcp(self):
        with self.lock:
            return list(self.tcp_live)

    def app_list(self, usage):
        t = time.time()
        out = []
        with self.lock:
            for a in self.apps.values():
                active_eps = sum(1 for ts in a.endpoints.values() if t - ts < 60)
                if a.conns == 0 and a.rate_up == 0 and a.rate_down == 0 and not a.up and not a.down \
                        and not usage.has(a.key):
                    continue
                today = usage.get_app(a.key)
                out.append({
                    "key": a.key, "name": a.name, "exe": a.exe, "friendly": a.friendly, "user": a.user,
                    "pids": sorted(a.pids), "services": sorted(a.services)[:12],
                    "up": a.up, "down": a.down, "rate_up": round(a.rate_up), "rate_down": round(a.rate_down),
                    "conns": a.conns, "endpoints": active_eps, "endpoints_total": len(a.endpoints),
                    "today_up": today["d"][0], "today_down": today["d"][1],
                    "month_up": today["m"][0], "month_down": today["m"][1],
                    "first_seen": a.first_seen, "last_active": a.last_active,
                    "active": a.conns > 0 or (t - a.last_active < 30),
                    "hist": list(a.hist)[-40:],
                })
        out.sort(key=lambda x: (-(x["rate_down"] + x["rate_up"]), -(x["today_down"] + x["today_up"])))
        return out

    def app_detail(self, key):
        t = time.time()
        with self.lock:
            a = self.apps.get(key)
            if not a:
                return None
            eps = []
            for ip, ts in sorted(a.endpoints.items(), key=lambda kv: -kv[1])[:80]:
                ep = self.endpoints.get(ip, {})
                eps.append({"ip": ip, "host": self.host(ip), "last": ts, "up": ep.get("up", 0),
                            "down": ep.get("down", 0), "ports": sorted(ep.get("ports", []))[:8]})
            return {"key": key, "endpoints": eps, "hist": list(a.hist),
                    "connections": [c for c in self.connection_list() if c["app"] == key][:200],
                    "t": t}

    def connection_list(self, limit=600):
        t = time.time()
        with self.lock:
            rows = {}
            for c in self.tcp_live:
                k = ("tcp", c["lport"], c["rip"], c["rport"])
                rows[k] = dict(c, up=0, down=0, rate_up=0, rate_down=0, first=None)
            for k, f in self.flows.items():
                if t - f.get("last", 0) > 15 and k not in rows:
                    continue
                r = rows.get(k)
                if r is None:
                    r = rows[k] = {"pid": f["pid"], "app": f["app"], "proto": f["proto"], "lip": "",
                                   "lport": f["lport"], "rip": f["rip"], "rport": f["rport"],
                                   "status": "ACTIVE" if f["proto"] == "udp" else "CLOSED", "v6": ":" in f["rip"]}
                r.update(up=f["up"], down=f["down"], rate_up=round(f["rate_up"]),
                         rate_down=round(f["rate_down"]), first=f["first"])
            out = []
            for r in rows.values():
                a = self.apps.get(r["app"]) if r["app"] else None
                r["friendly"] = a.friendly if a else "Unknown"
                r["exe"] = a.exe if a else None
                r["host"] = self.host(r["rip"])
                out.append(r)
        out.sort(key=lambda r: (-(r["rate_down"] + r["rate_up"]), r["friendly"], r["rip"]))
        return out[:limit]

    def endpoint_list(self, limit=400):
        t = time.time()
        with self.lock:
            out = []
            for ep in self.endpoints.values():
                out.append({"ip": ep["ip"], "host": self.host(ep["ip"]), "up": ep["up"], "down": ep["down"],
                            "rate_up": round(ep["rate_up"]), "rate_down": round(ep["rate_down"]),
                            "apps": [self.apps[k].friendly for k in ep["apps"] if k in self.apps][:6],
                            "app_keys": list(ep["apps"])[:6],
                            "ports": sorted(ep["ports"])[:10], "protos": sorted(ep["protos"]),
                            "first": ep["first"], "last": ep.get("last", ep["first"]),
                            "active": t - ep.get("last", 0) < 30})
        out.sort(key=lambda e: (-int(e["active"]), -(e["rate_down"] + e["rate_up"]), -(e["down"] + e["up"])))
        return out[:limit]
