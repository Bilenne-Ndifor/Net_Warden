"""Block-all ("lockdown") mode: default-deny outbound + permission decisions + app groups.

Modes
  off        normal: everything may connect (ordinary block/limit rules still apply)
  ask        everything is blocked until you allow it; each new app (Beginner) or each new
             address an app contacts (Pro) raises a permission request
  allowlist  everything is blocked except apps in the enabled ("allowed") groups; no questions

Enforcement: Windows Firewall default outbound action = Block, plus allow rules for what you
permitted. Detection: Windows logs every blocked connection (Security event 5157) once
"Filtering Platform Connection" failure auditing is on; we turn that on while lockdown is active.
"""
from __future__ import annotations

import ipaddress
import os
import threading
import time
import uuid
from collections import deque

from .util import JsonStore, classify_target, ip_in_targets

MODES = ("off", "ask", "allowlist")
SNOOZE_SECONDS = 600
MAX_PENDING = 300


def _sys(path: str) -> str:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return path.replace("%SystemRoot%", root)


def default_groups():
    return [
        {"id": "essentials", "name": "Windows essentials", "builtin": True, "enabled": True,
         "note": "Core Windows networking (DNS, DHCP, time, updates). Turning this off can break Windows networking.",
         "apps": [{"path": _sys(r"%SystemRoot%\System32\svchost.exe"), "name": "Windows services (svchost)"},
                  {"path": "System", "name": "Windows kernel (System)"}]},
        {"id": "allowed", "name": "My allowed apps", "builtin": True, "enabled": True,
         "note": "Apps you always allow. In 'Only allowed apps' mode these are the only apps that can connect.",
         "apps": []},
    ]


def is_noise(ip: str) -> bool:
    """Multicast / broadcast / link-local chatter is never worth a question."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_multicast or a.is_loopback or a.is_unspecified or ip == "255.255.255.255" or \
        (a.version == 4 and ip.endswith(".255")) or a.is_link_local


class Lockdown:
    def __init__(self, path, dns, resolver, log):
        self.store = JsonStore(path, {"mode": "off", "groups": default_groups(), "decisions": [],
                                      "saved_profiles": None, "audit_by_us": False})
        self.d = self.store.data
        self.dns = dns
        self.resolver = resolver
        self.log = log
        self.lock = threading.RLock()
        self.pending: dict[str, dict] = {}
        self.snoozed: dict[str, float] = {}
        self.attempts = deque(maxlen=400)
        self.policy_ok = False        # runtime: default-outbound=Block confirmed this session
        self.status = {"warnings": []}
        # make sure built-in groups exist (older data files)
        ids = {g["id"] for g in self.d["groups"]}
        for g in default_groups():
            if g["id"] not in ids:
                self.d["groups"].append(g)
        self._expire()

    @property
    def mode(self) -> str:
        return self.d.get("mode", "off")

    def save(self):
        self.store.save()

    # ------------------------------------------------------------------ matching
    def _groups_allow(self, exe: str) -> bool:
        e = (exe or "").lower()
        for g in self.d["groups"]:
            if g.get("enabled") and any(a["path"].lower() == e for a in g["apps"]):
                return True
        return False

    def _decision_targets(self, dec) -> list[str]:
        if dec["scope"] == "app":
            return []
        if dec["scope"] == "address":
            return [dec["remote"]]
        ips = self.resolver.ips(dec["remote"]) or set()
        return sorted(ips) or ["0.0.0.0/32"]  # unresolved domain matches nothing

    def classify(self, exe: str, ip: str) -> str:
        """'allowed' | 'denied' | 'unknown' for a connection attempt in the current mode."""
        e = (exe or "").lower()
        decs = [x for x in self.d["decisions"] if x["app"].lower() == e]
        for x in decs:
            if x["action"] == "deny" and (x["scope"] == "app" or ip_in_targets(ip, self._decision_targets(x))
                                          or (x["scope"] == "domain" and self._host_in(ip, x["remote"]))):
                return "denied"
        if self._groups_allow(e):
            return "allowed"
        if self.mode == "allowlist":
            return "denied"
        for x in decs:
            if x["action"] == "allow" and (x["scope"] == "app" or ip_in_targets(ip, self._decision_targets(x))
                                           or (x["scope"] == "domain" and self._host_in(ip, x["remote"]))):
                return "allowed"
        return "unknown"

    def _host_in(self, ip, domain):
        h = self.dns.ip2host.get(ip)
        if not h:
            return False
        base = domain[2:] if domain.startswith("*.") else domain
        return h == base or h.endswith("." + base)

    def app_status(self, exe: str) -> str | None:
        """Per-app badge for the UI when lockdown is on."""
        if self.mode == "off" or not exe:
            return None
        e = exe.lower()
        if any(p["app"].lower() == e for p in self.pending.values()):
            return "pending"
        decs = [x for x in self.d["decisions"] if x["app"].lower() == e]
        if any(x["action"] == "deny" and x["scope"] == "app" for x in decs):
            return "denied"
        if self._groups_allow(e):
            return "allowed"
        if self.mode == "allowlist":
            return "blocked"
        if any(x["action"] == "allow" and x["scope"] == "app" for x in decs):
            return "allowed"
        if any(x["action"] == "allow" for x in decs):
            return "partial"
        return "blocked"

    # ------------------------------------------------------------------ attempts -> requests
    def on_attempt(self, a: dict, granularity: str, app_name: str):
        """a = {t, pid, app, ip, port, proto}. Called for every blocked outbound connection."""
        if self.mode == "off" or not a.get("app"):
            return
        ip = a["ip"]
        host = self.dns.ip2host.get(ip)
        verdict = "noise" if is_noise(ip) else self.classify(a["app"], ip)
        rec = dict(a, host=host, app_name=app_name, verdict=verdict)
        with self.lock:
            last = self.attempts[0] if self.attempts else None
            if last and last["app"] == a["app"] and last["ip"] == ip and last["port"] == a["port"] \
                    and a["t"] - last["t"] < 5:
                last["count"] = last.get("count", 1) + 1
                last["t"] = a["t"]
            else:
                rec["count"] = 1
                self.attempts.appendleft(rec)
            if verdict != "unknown" or self.mode != "ask":
                return
            key = a["app"].lower() if granularity == "app" else f"{a['app'].lower()}|{ip}"
            if self.snoozed.get(key, 0) > time.time():
                return
            p = self.pending.get(key)
            if p is None:
                if len(self.pending) >= MAX_PENDING:
                    oldest = min(self.pending.values(), key=lambda x: x["first"])
                    self.pending.pop(oldest["key"], None)
                p = self.pending[key] = {"id": uuid.uuid4().hex[:10], "key": key, "app": a["app"],
                                         "app_name": app_name, "granularity": granularity, "ip": ip,
                                         "host": host, "port": a["port"], "proto": a["proto"], "pid": a["pid"],
                                         "count": 0, "first": a["t"], "dests": []}
                self.log("ask", f"{app_name} wants to connect to {host or ip}:{a['port']} — waiting for your OK")
            p["count"] += 1
            p["last"] = a["t"]
            if host and not p.get("host") and p["ip"] == ip:
                p["host"] = host
            d = f"{host or ip}:{a['port']}"
            if d not in p["dests"]:
                p["dests"] = ([d] + p["dests"])[:12]

    def pending_list(self):
        with self.lock:
            for p in self.pending.values():
                if not p.get("host"):
                    p["host"] = self.dns.ip2host.get(p["ip"])
            return sorted(self.pending.values(), key=lambda p: p["first"])

    # ------------------------------------------------------------------ answers
    def answer(self, pid: str, action: str, scope: str, minutes=None) -> dict:
        """Turn a pending request into a decision. scope: app | address | domain."""
        if action not in ("allow", "deny"):
            raise ValueError("action must be allow or deny")
        with self.lock:
            p = next((x for x in self.pending.values() if x["id"] == pid), None)
            if not p:
                raise KeyError("request not found (maybe already answered)")
            remote = None
            if scope == "address":
                remote = p["ip"]
            elif scope == "domain":
                host = p.get("host") or self.dns.ip2host.get(p["ip"])
                if not host:
                    raise ValueError("no domain name is known for this address — allow the address or the app")
                remote = host
            elif scope != "app":
                raise ValueError("scope must be app, address or domain")
            dec = self.add_decision(p["app"], p["app_name"], scope, remote, action, minutes)
            self._drop_covered()
            return dec

    def add_decision(self, app, app_name, scope, remote, action, minutes=None) -> dict:
        if scope != "app":
            kind, val = classify_target(remote)
            if scope == "address" and kind == "domain":
                scope = "domain"
            remote = val
        with self.lock:
            # replace an identical existing decision
            self.d["decisions"] = [x for x in self.d["decisions"]
                                   if not (x["app"].lower() == app.lower() and x["scope"] == scope
                                           and (x.get("remote") or "") == (remote or ""))]
            dec = {"id": uuid.uuid4().hex[:8], "app": app, "app_name": app_name, "scope": scope,
                   "remote": remote, "action": action, "created_at": time.time(),
                   "expires_at": time.time() + float(minutes) * 60 if minutes else None}
            self.d["decisions"].append(dec)
            self.save()
        what = {"app": "everywhere", "address": remote, "domain": remote}[scope]
        self.log("allow" if action == "allow" else "rule",
                 f"{'Allowed' if action == 'allow' else 'Blocked'} {app_name} → {what}"
                 + (f" for {minutes} min" if minutes else ""))
        self._drop_covered()
        return dec

    def _drop_covered(self):
        with self.lock:
            for k, p in list(self.pending.items()):
                if self.classify(p["app"], p["ip"]) != "unknown":
                    self.pending.pop(k, None)

    def snooze(self, pid):
        with self.lock:
            for k, p in list(self.pending.items()):
                if p["id"] == pid:
                    self.snoozed[k] = time.time() + SNOOZE_SECONDS
                    self.pending.pop(k)
                    return True
        return False

    def delete_decision(self, did):
        with self.lock:
            n = len(self.d["decisions"])
            self.d["decisions"] = [x for x in self.d["decisions"] if x["id"] != did]
            self.save()
            return n != len(self.d["decisions"])

    def _expire(self):
        t = time.time()
        with self.lock:
            keep = [x for x in self.d["decisions"] if not (x.get("expires_at") and x["expires_at"] <= t)]
            if len(keep) != len(self.d["decisions"]):
                for x in self.d["decisions"]:
                    if x not in keep:
                        self.log("info", f"Time is up for: {x['app_name']} → {x.get('remote') or 'everywhere'}")
                self.d["decisions"] = keep
                self.save()
            for k in [k for k, v in self.snoozed.items() if v < t]:
                del self.snoozed[k]

    # ------------------------------------------------------------------ groups
    def group(self, gid):
        g = next((g for g in self.d["groups"] if g["id"] == gid), None)
        if not g:
            raise KeyError("group not found")
        return g

    def add_group(self, name):
        name = (name or "").strip()
        if not name:
            raise ValueError("group needs a name")
        g = {"id": uuid.uuid4().hex[:8], "name": name, "enabled": True, "apps": []}
        with self.lock:
            self.d["groups"].append(g)
            self.save()
        return g

    def update_group(self, gid, data):
        with self.lock:
            g = self.group(gid)
            if "name" in data and not g.get("builtin"):
                g["name"] = str(data["name"]).strip() or g["name"]
            if "enabled" in data:
                g["enabled"] = bool(data["enabled"])
            if "add_app" in data:
                path = str(data["add_app"]).strip().strip('"')
                if not path:
                    raise ValueError("app path is empty")
                if path.lower() != "system" and not (len(path) > 3 and path[1] == ":" and path.lower().endswith(".exe")):
                    raise ValueError("use the full path of a program, e.g. C:\\Program Files\\App\\app.exe")
                if not any(a["path"].lower() == path.lower() for a in g["apps"]):
                    g["apps"].append({"path": path, "name": data.get("app_name") or path.split("\\")[-1]})
            if "remove_app" in data:
                g["apps"] = [a for a in g["apps"] if a["path"].lower() != str(data["remove_app"]).lower()]
            self.save()
        self._drop_covered()
        return g

    def delete_group(self, gid):
        with self.lock:
            g = self.group(gid)
            if g.get("builtin"):
                raise ValueError("built-in groups can't be deleted (you can turn them off)")
            self.d["groups"].remove(g)
            self.save()

    # ------------------------------------------------------------------ firewall specs
    def specs(self) -> list[dict]:
        """Firewall rules needed for the current mode (only allow/deny rules; the default
        outbound Block policy is handled separately)."""
        self._expire()
        if self.mode == "off":
            return []
        out = []
        seen_apps = set()
        for g in self.d["groups"]:
            if not g.get("enabled"):
                continue
            for a in g["apps"]:
                p = a["path"]
                if p.lower() in seen_apps:
                    continue
                seen_apps.add(p.lower())
                out.append({"dir": "out", "action": "allow", "program": p, "remoteip_list": []})
        for x in self.d["decisions"]:
            if self.mode == "allowlist" and x["action"] == "allow":
                continue
            if x["action"] == "allow" and x["scope"] == "app" and x["app"].lower() in seen_apps:
                continue
            ips = self._decision_targets(x)
            if x["scope"] == "domain" and ips == ["0.0.0.0/32"]:
                continue
            for i in range(0, max(1, len(ips)), 100):
                chunk = ips[i:i + 100]
                out.append({"dir": "out", "action": "allow" if x["action"] == "allow" else "block",
                            "program": x["app"], "remoteip": ",".join(chunk) if chunk else None,
                            "remoteip_list": chunk})
        return out
