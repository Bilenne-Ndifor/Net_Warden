"""The engine: runs the monitor, keeps rules, and reconciles them into firewall / QoS state."""
from __future__ import annotations

import hashlib
import json
import logging
import socket
import threading
import time
import traceback
from collections import deque

from . import rules as R
from .lockdown import MODES as LOCK_MODES
from .lockdown import Lockdown
from .safety import NeedsConfirm, NetInfo, in_remote_session, is_critical, rule_risks
from .monitor import Monitor
from .util import (DATA_DIR, IS_WINDOWS, RULE_PREFIX, JsonStore, classify_target, fmt_bytes,
                   parse_ports, spec_matches)

DEFAULT_SETTINGS = {
    "ui_mode": "beginner",
    "theme": "classic",             # "classic" (Windows 2000 look, default) or "modern"
    "kill_on_block": True,          # reset open TCP connections when a block starts
    "instant_pause": True,          # use WinDivert to drop packets instantly during Pause internet
    "keep_rules_on_exit": False,    # leave firewall blocks in place when NetWarden closes
    "resolve_hostnames": True,
    "notify_new_apps": True,
}
MAX_IPS_PER_RULE = 100
LOCK_PREFIX = RULE_PREFIX + "L_"


def entry_name(tag: str, kind: str, spec: dict) -> str:
    """Stable firewall/QoS entry name: content hash => unchanged rules keep their name across runs."""
    h = hashlib.sha1(json.dumps(spec, sort_keys=True, default=str).encode()).hexdigest()[:10]
    return f"{RULE_PREFIX}{tag}_{kind}_{h}"


class DomainResolver:
    """Resolves domain targets in the background (DNS lookups + IPs learned by the sniffer)."""

    def __init__(self, dns):
        self.dns = dns
        self.cache: dict[str, tuple[float, set]] = {}
        self.pending: set[str] = set()
        self.lock = threading.Lock()

    def ips(self, domain: str) -> set[str] | None:
        """Known IPs right now (None = never resolved yet). Refreshes every 2 minutes."""
        learned = self.dns.ips_for(domain)
        with self.lock:
            hit = self.cache.get(domain)
            stale = hit is None or time.time() - hit[0] > 120
            if stale and domain not in self.pending:
                self.pending.add(domain)
                threading.Thread(target=self._resolve, args=(domain,), daemon=True).start()
        if hit is None and not learned:
            return None
        return (set(hit[1]) if hit else set()) | learned

    IP_TTL = 6 * 3600  # forget addresses a domain hasn't used for 6 h (CDNs reuse them for other sites)

    def _resolve(self, domain):
        now = time.time()
        found = set()
        base = domain[2:] if domain.startswith("*.") else domain
        for host in ({base, "www." + base} if domain.startswith("*.") else {base}):
            try:
                for fam, *_rest, sa in socket.getaddrinfo(host, None):
                    if fam in (socket.AF_INET, socket.AF_INET6):
                        found.add(sa[0].split("%")[0])
            except Exception:
                pass
        with self.lock:
            seen = dict(self.cache.get(domain, (0, {}))[1])
            for ip in found:
                seen[ip] = now
            seen = {ip: ts for ip, ts in seen.items() if now - ts < self.IP_TTL}
            if len(seen) > 400:
                seen = dict(sorted(seen.items(), key=lambda kv: -kv[1])[:400])
            self.cache[domain] = (now, seen)
            self.pending.discard(domain)


class Engine:
    def __init__(self, sim: bool = False, data_dir=None):
        self.sim = sim or not IS_WINDOWS
        data = data_dir or (DATA_DIR / "demo" if self.sim else DATA_DIR)
        data.mkdir(parents=True, exist_ok=True)
        self.data_dir = data
        self.lock = threading.RLock()
        self.events = deque(maxlen=600)
        self.settings_store = JsonStore(data / "settings.json", dict(DEFAULT_SETTINGS))
        self.settings = self.settings_store.data
        self.rules_store = JsonStore(data / "rules.json", {"rules": []})
        self.usage = R.Usage(data / "usage.json")
        if self.sim:
            from .sim import SimFirewall, SimQos, SimSource
            self.src = SimSource()
            self.fw, self.qos = SimFirewall(self.src), SimQos(self.src)
            self.killer = self.src.kill
            self.admin = True
        else:
            from . import winapi
            self.admin = winapi.is_admin()
            self.src = winapi.RealSource()
            self.fw, self.qos = winapi.WindowsFirewall(), winapi.WindowsQos()
            self.killer = winapi.kill_tcp
        self.src.dns.reverse_enabled = self.settings.get("resolve_hostnames", True) and not self.sim
        self.monitor = Monitor(self.src, self._on_monitor_event)
        self.resolver = DomainResolver(self.src.dns)
        self.lockdown = Lockdown(data / "permissions.json", self.src.dns, self.resolver, self.log)
        self._profiles_checked = 0.0
        self.netinfo = NetInfo(self.src.critical_ips)
        self.failsafe: set[str] = set()   # rule ids with a Windows "end this pause" task registered
        self._ld_wait_logged = False
        self.applied: dict[str, str] = {}  # firewall/QoS entry name -> kind ('fw' | 'qos')
        self.failed: dict[str, float] = {}
        self.status: dict[str, dict] = {}
        self.cap_state: dict[str, dict] = {}
        self.dropper = None
        self.dropper_error = None
        self.running = False
        self.started_at = time.time()
        self.last_enforce_error = None
        self._enf_lock = threading.Lock()
        # drop timed rules that expired while we were closed
        t = time.time()
        before = len(self.rules_store.data["rules"])
        self.rules_store.data["rules"] = [r for r in self.rules_store.data["rules"]
                                          if not (r.get("expires_at") and r["expires_at"] <= t)]
        if len(self.rules_store.data["rules"]) != before:
            self.rules_store.save()

    @property
    def rules(self) -> list[dict]:
        return self.rules_store.data["rules"]

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        if not self.sim and not self.admin:
            self.log("warn", "Not running as Administrator: monitoring only, blocking and limits are disabled.")
        if self.admin:
            # Adopt entries left by a previous run. Names contain a hash of their content, so the
            # first reconcile keeps what is still wanted and removes the rest: no unprotected gap.
            for n in self.fw.list_names():
                self.applied[n] = "fw"
            for n in self.qos.list_names():
                self.applied[n] = "qos"
            # Leftover block-all entries while our state says "off" (e.g. permissions.json was lost):
            # make sure the firewall's outbound policy gets restored instead of staying on Block.
            if self.lockdown.mode == "off" and any(n.startswith(LOCK_PREFIX) for n in self.applied):
                self.lockdown.d["policy_set_by_us"] = True
                self.log("warn", "Found block-all leftovers from an earlier run — restoring normal access.")
            try:
                self.failsafe = set(self.fw.list_expiry())
            except Exception:
                self.failsafe = set()
        threading.Thread(target=self.netinfo.get, daemon=True).start()
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True, name="monitor").start()
        threading.Thread(target=self._enforce_loop, daemon=True, name="enforce").start()
        mode = "simulation (demo data)" if self.sim else "live"
        self.log("info", f"NetWarden started in {mode} mode.")
        if not self.sim and not self.src.per_app_bytes():
            self.log("warn", "Per-app traffic counting is off: " + (self.src.sniffer_error or "sniffer unavailable"))

    def shutdown(self):
        if not self.running:
            return
        self.running = False
        try:
            self.usage.save()
            self.rules_store.save()
        except Exception:
            pass
        if self.dropper:
            self.dropper.close()
            self.dropper = None
        if self.admin and not self.settings.get("keep_rules_on_exit"):
            # Block-all mode ('_L_' entries + default-deny policy) deliberately stays in force.
            for name, kind in list(self.applied.items()):
                if not name.startswith(LOCK_PREFIX):
                    (self.fw if kind == "fw" else self.qos).remove(name)
        self.src.stop()

    def _monitor_loop(self):
        last_save = time.time()
        while self.running:
            t0 = time.time()
            try:
                app_deltas, sys_delta = self.monitor.tick()
                self._process_attempts()
                with self.lock:
                    changed = self.usage.roll()
                    if changed:
                        self.cap_state.clear()
                        self.log("info", "New " + " & ".join(changed) + ": daily data limits reset.")
                    for key, (up, down) in app_deltas.items():
                        self.usage.add_app(key, up, down)
                    self.usage.add_system(*sys_delta)
                if time.time() - last_save > 30:
                    self.usage.save()
                    last_save = time.time()
            except Exception:
                self.log("error", "Monitor error: " + traceback.format_exc(limit=2).strip().splitlines()[-1])
            time.sleep(max(0.05, 1.0 - (time.time() - t0)))

    def _enforce_loop(self):
        while self.running:
            t0 = time.time()
            try:
                self.enforce()
            except Exception:
                self.last_enforce_error = traceback.format_exc(limit=3)
                self.log("error", "Rule engine error: " + self.last_enforce_error.strip().splitlines()[-1])
            time.sleep(max(0.1, 1.0 - (time.time() - t0)))

    # ------------------------------------------------------------------ events
    def log(self, kind, msg):
        self.events.appendleft({"t": time.time(), "kind": kind, "msg": msg})
        logging.getLogger("netwarden").info("[%s] %s", kind, msg)

    def _on_monitor_event(self, kind, msg):
        if kind == "new_app" and not self.settings.get("notify_new_apps", True):
            return
        self.log(kind, msg)

    # ------------------------------------------------------------------ rule -> specs
    def _resolve_remote(self, r) -> tuple[list[str] | None, str]:
        """Return (netsh address list, note). [] means any; None means 'not resolved yet'."""
        out, note, waiting = [], "", False
        for tok in r.get("remote") or []:
            kind, val = classify_target(tok)
            if kind == "domain":
                ips = self.resolver.ips(val)
                if ips is None:
                    waiting = True
                    continue
                out.extend(sorted(ips))
            else:
                out.append(val)
        if waiting and not out:
            return None, "Looking up domain…"
        if r.get("remote") and not out:
            return None, "Domain has no addresses yet"
        if len(out) > 600:
            out, note = out[:600], "Only the first 600 addresses are blocked"
        return out, note

    def _block_specs(self, r, app=None, direction=None, remote=None) -> list[dict]:
        app = r.get("app") if app is None else app
        direction = direction or r.get("direction", "both")
        dirs = ["out", "in"] if direction == "both" else [direction]
        ports = parse_ports(r.get("ports"))
        proto = r.get("protocol", "any")
        protos = ["tcp", "udp"] if (ports and proto == "any") else [None if proto == "any" else proto]
        chunks = [remote[i:i + MAX_IPS_PER_RULE] for i in range(0, len(remote), MAX_IPS_PER_RULE)] if remote else [None]
        specs = []
        for d in dirs:
            for p in protos:
                for ch in chunks:
                    specs.append({"dir": d, "program": app, "protocol": p,
                                  "remoteip": ",".join(ch) if ch else None, "remoteip_list": ch or [],
                                  "remoteport": r.get("ports") if p else None, "ports": ports if p else []})
        return specs

    def _qos_specs(self, r, kbps, remote) -> list[dict]:
        ports = parse_ports(r.get("ports"))[:4] or [None]
        proto = {"any": "Both", "tcp": "TCP", "udp": "UDP"}[r.get("protocol", "any")]
        dsts = [x for x in (remote or []) if "-" not in x][:24] or [None]
        specs = []
        for dst in dsts:
            for pr in ports:
                s = {"app": r.get("app"), "dst": dst, "proto": proto, "bits": int(kbps * 1000)}
                if pr:
                    s["port_start"], s["port_end"] = pr
                specs.append(s)
        return specs

    def desired_state(self, t):
        desired: dict[str, tuple[str, dict, str]] = {}
        status: dict[str, dict] = {}
        want_drop = False
        for r in list(self.rules):
            st = status[r["id"]] = {"state": "pending", "detail": "", "active": False}
            try:
                want_drop = self._rule_state(r, t, st, desired) or want_drop
            except Exception as e:  # one bad rule must never stop the others
                st.update(state="error", detail=f"{type(e).__name__}: {e}", active=False)
        try:
            for s in self.lockdown.specs():
                desired[entry_name("L", "fw", s)] = ("fw", s, "lockdown")
        except Exception as e:  # noqa: BLE001
            self.log("error", f"Block-all rules: {e}")
        return desired, status, want_drop

    def _rule_state(self, r, t, st, desired) -> bool:
        """Fill st (status) and desired (specs) for one rule. Returns True if it wants the hard pause."""
        rid = r["id"]
        want_drop = False
        state, detail = R.timing_state(r, t)
        st.update(state=state, detail=detail)
        if state != "on":
            return False
        remote, note = self._resolve_remote(r)
        if remote is None:
            st.update(state="waiting", detail=note)
            return False
        specs, kind = [], "fw"
        if r["type"] == "block":
            specs = self._block_specs(r, remote=remote)
            if r.get("pause_all") and self.settings.get("instant_pause", True):
                want_drop = True
        elif r["type"] == "throttle":
            specs, kind = self._qos_specs(r, r["rate_kbps"], remote), "qos"
        elif r["type"] == "cap":
            cap = r["cap"]
            key = r["app"].lower() if r.get("app") else None
            used = self.usage.amount(key, cap["period"], cap["metric"])
            limit = cap["mb"] * 1024 * 1024
            cs = self.cap_state.setdefault(rid, {})
            st["used"], st["limit"] = used, limit
            if used < limit:
                st.update(state="watching", detail=f"{fmt_bytes(used)} of {fmt_bytes(limit)} used "
                                                    + ("today" if cap["period"] == "day" else "this month"))
                cs.pop("tripped", None)
                if used >= 0.8 * limit and not cs.get("warned"):
                    cs["warned"] = True
                    self.log("alert", f"{r['name']}: 80% used ({fmt_bytes(used)} of {fmt_bytes(limit)}).")
                return False
            if not cs.get("tripped"):
                cs["tripped"] = True
                act = {"block": "blocked", "throttle": "slowed down", "alert": "alert only"}[cap["action"]]
                self.log("alert", f"Data limit reached: {r['name']} ({fmt_bytes(used)}) — {act}.")
            when = "tomorrow" if cap["period"] == "day" else "next month"
            st.update(state="tripped", detail=f"Limit reached ({fmt_bytes(used)}) — resets {when}")
            if cap["action"] == "block":
                specs = self._block_specs(r, direction="both", remote=remote)
            elif cap["action"] == "throttle":
                specs, kind = self._qos_specs(r, cap["throttle_kbps"], remote), "qos"
        for s in specs:
            desired[entry_name(rid, kind, s)] = (kind, s, rid)
        if specs:
            st["active"] = True
            if st["state"] == "on":
                st["state"] = "active"
            if note:
                st["detail"] = (st["detail"] + " · " if st["detail"] else "") + note
        return want_drop

    def enforce(self):
        with self._enf_lock:
            self._enforce()

    def _enforce(self):
        t = time.time()
        with self.lock:
            # remove expired timed rules ("allow later")
            expired = [r for r in self.rules if r.get("expires_at") and r["expires_at"] <= t]
            for r in expired:
                self.rules.remove(r)
                self.log("allow", f"Time is up — allowed again: {r['name']}")
            if expired:
                self.rules_store.save()
            desired, status, want_drop = self.desired_state(t)
        if not self.admin:
            for st in status.values():
                if st["state"] in ("active", "tripped"):
                    st.update(state="error", detail="Needs Administrator rights", active=False)
            self.status = status
            return

        # instant pause
        if want_drop and self.dropper is None:
            try:
                self.dropper = self.src.make_dropper()
                self.dropper_error = None
            except Exception as e:  # noqa: BLE001
                self.dropper_error = str(e)
        elif not want_drop and self.dropper is not None:
            self.dropper.close()
            self.dropper = None

        # leaving block-all: restore the normal outbound policy BEFORE removing allow rules.
        # If restoring fails, keep the allow rules: never leave the PC on Block without them.
        restore_ok = True
        if self.lockdown.mode == "off":
            restore_ok = self._lockdown_policy()
        # remove what is no longer wanted (names hash their content, so a change = new name)
        for name in list(self.applied):
            if not restore_ok and name.startswith(LOCK_PREFIX):
                continue
            if name not in desired:
                kind = self.applied[name]
                ok, out = (self.fw if kind == "fw" else self.qos).remove(name)
                self.applied.pop(name, None)
        # add new
        newly_blocked = []
        errors: dict[str, str] = {}
        for name, (kind, spec, rid) in desired.items():
            if name in self.applied:
                continue
            if name in self.failed and t - self.failed[name] < 30:
                errors[rid] = errors.get(rid) or "Retrying soon"
                continue
            ok, out = (self.fw if kind == "fw" else self.qos).add(name, spec)
            if ok:
                self.applied[name] = kind
                self.failed.pop(name, None)
                if kind == "fw" and spec.get("action", "block") == "block":
                    newly_blocked.append(spec)
            else:
                self.failed[name] = t
                errors[rid] = out.splitlines()[-1][:200] if out else "failed"
                self.log("error", f"Could not apply rule ({name}): {errors[rid]}")
        for rid, err in errors.items():
            if rid in status:
                status[rid].update(state="error", detail=err)
        self.status = status
        # entering / staying in block-all: only switch the default to Block once EVERY allow rule
        # (Windows essentials first of all) is really in place.
        if self.lockdown.mode != "off":
            missing = [n for n, (_k, sp, _r) in desired.items()
                       if n.startswith(LOCK_PREFIX) and sp.get("essential") and n not in self.applied]
            if missing:
                if not self._ld_wait_logged:
                    self._ld_wait_logged = True
                    self.log("warn", f"Block-all is waiting: {len(missing)} Windows-essentials allow rule(s) could not "
                                     f"be added yet, so nothing is blocked by default.")
            else:
                self._ld_wait_logged = False
                self._lockdown_policy()
        self._sync_failsafe(t)

        if newly_blocked and self.settings.get("kill_on_block", True):
            self._kill_matching(newly_blocked)

    def _kill_matching(self, specs):
        killed = 0
        for c in self.monitor.live_tcp():
            if c["status"] != "ESTABLISHED" or c.get("v6"):
                continue
            exe = (self.monitor.apps.get(c["app"]).exe if self.monitor.apps.get(c["app"]) else None)
            for s in specs:
                if spec_matches(s, exe, c["rip"], c["rport"], "tcp"):
                    if self.killer(c["lip"], c["lport"], c["rip"], c["rport"]):
                        killed += 1
                    break
        if killed:
            self.log("info", f"Closed {killed} open connection(s) so the block takes effect now.")

    # ------------------------------------------------------------------ block-all mode
    def _process_attempts(self):
        attempts = self.src.drain_attempts()
        if not attempts:
            return
        gran = "address" if self.settings.get("ui_mode") == "pro" else "app"
        for a in attempts:
            name = None
            if a.get("pid"):
                info = self.src.proc_info(a["pid"])
                if info.get("exe") and a.get("app") and info["exe"].lower() == a["app"].lower():
                    a["app"] = info["exe"]
                    name = info.get("friendly")
            if not name:
                key = (a.get("app") or "").lower()
                app = self.monitor.apps.get(key)
                name = app.friendly if app else (a.get("app") or "?").replace("/", "\\").split("\\")[-1]
            self.lockdown.on_attempt(a, gran, name)

    def _lockdown_policy(self):
        ld = self.lockdown
        t = time.time()
        if ld.mode == "off":
            saved = ld.d.get("saved_profiles")
            if not saved and ld.d.get("policy_set_by_us"):
                saved = {"Domain": "NotConfigured", "Private": "NotConfigured", "Public": "NotConfigured"}
            if saved:
                ok, out = self.fw.set_outbound(saved)
                if ok:
                    ld.d["saved_profiles"] = None
                    ld.d["policy_set_by_us"] = False
                    if ld.d.get("audit_by_us"):
                        self.fw.set_audit(False)
                        ld.d["audit_by_us"] = False
                    ld.save()
                    ld.policy_ok = False
                    self.log("allow", "Block-all mode is off — apps can connect normally again.")
                    return True
                self.log("error", f"Could not restore the firewall policy: {out[-200:]}")
                return False
            return True
        if ld.policy_ok and t - self._profiles_checked < 60:
            return True
        self._profiles_checked = t
        profiles = self.fw.get_profiles()
        warnings = [f"Windows Firewall is turned off for {n} networks — NetWarden can't block anything there."
                    for n, p in profiles.items() if not p["enabled"]]
        ld.status = {"warnings": warnings, "profiles": profiles}
        if ld.d.get("saved_profiles") is None and profiles:
            ld.d["saved_profiles"] = {n: p["out"] for n, p in profiles.items()}
        if not ld.d.get("audit_by_us"):
            ok, _ = self.fw.set_audit(True)
            ld.d["audit_by_us"] = bool(ok)
        ld.save()
        if profiles and all(p["out"] == "Block" for p in profiles.values()):
            ld.policy_ok = True
            return True
        ld.d["policy_set_by_us"] = True
        ld.save()
        ok, out = self.fw.set_outbound({"Domain": "Block", "Private": "Block", "Public": "Block"})
        if ok:
            if not ld.policy_ok:
                self.log("rule", "Block-all mode is on — only allowed apps can connect.")
                self._kill_unallowed()
            ld.policy_ok = True
        else:
            self.log("error", f"Could not switch the firewall to block-all: {out[-200:]}")
        return ok

    def _kill_unallowed(self):
        """Firewall rules only stop NEW connections: close open ones of apps that aren't allowed."""
        if not self.settings.get("kill_on_block", True):
            return
        n = 0
        for c in self.monitor.live_tcp():
            if c["status"] != "ESTABLISHED" or c.get("v6"):
                continue
            a = self.monitor.apps.get(c["app"])
            if a and a.exe and self.lockdown.classify(a.exe, c["rip"]) not in ("allowed",):
                n += bool(self.killer(c["lip"], c["lport"], c["rip"], c["rport"]))
        if n:
            self.log("info", f"Closed {n} open connection(s) of apps that aren't allowed.")

    def _sync_failsafe(self, t):
        """Timed blocks (pauses) get a Windows task that removes them at the end time, so a
        pause can never become permanent if NetWarden crashes or is killed."""
        want = {}
        for r in self.rules:
            if r["type"] == "block" and r.get("expires_at") and r.get("enabled", True):
                if any(n.startswith(f"{RULE_PREFIX}{r['id']}_") for n in self.applied):
                    want[r["id"]] = r["expires_at"]
        for rid, ts in want.items():
            if rid not in self.failsafe:
                ok, out = self.fw.schedule_expiry(rid, ts)
                if ok:
                    self.failsafe.add(rid)
                else:
                    self.log("warn", f"Couldn't register the safety timer for a pause: {out[-160:]}")
                    self.failsafe.add(rid)  # don't retry every second; logged once
        for rid in list(self.failsafe):
            if rid not in want:
                self.fw.cancel_expiry(rid)
                self.failsafe.discard(rid)

    def set_lockdown_mode(self, mode, force=False):
        if mode not in LOCK_MODES:
            raise ValueError("mode must be off, ask or allowlist")
        if mode != "off" and not force and in_remote_session():
            raise NeedsConfirm(["You're connected through Remote Desktop. Block-all could cut this session "
                                "off and you might not be able to reconnect."])
        if not self.admin:
            raise ValueError("Block-all mode needs Administrator rights")
        ld = self.lockdown
        prev = ld.mode
        ld.d["mode"] = mode
        ld.policy_ok = False
        if mode != "ask":
            ld.pending.clear()
        ld.save()
        if mode != prev:
            names = {"off": "Normal", "ask": "Ask before connecting", "allowlist": "Only allowed apps"}
            self.log("rule", f"Protection mode: {names[mode]}")
        self._enforce_soon()

    def turn_on_firewall(self):
        ok, out = self.fw.enable_all()
        self._profiles_checked = 0
        self.lockdown.policy_ok = False
        self._enforce_soon()
        if not ok:
            raise ValueError(out[-200:] or "failed")

    # ------------------------------------------------------------------ API actions
    def _check(self, r, force):
        risks = rule_risks(r, self.netinfo.get())
        if r.get("pause_all") and in_remote_session():
            risks.append("You're connected through Remote Desktop: pausing the internet will cut this session "
                         "and you won't be able to reconnect until the pause ends.")
        if risks and not force:
            raise NeedsConfirm(risks)

    def add_rule(self, data) -> dict:
        data = dict(data)
        force = bool(data.pop("force", False))
        with self.lock:
            r = R.normalize(data)
            self._check(r, force)
            if r.get("pause_all"):
                self.rules[:] = [x for x in self.rules if not x.get("pause_all")]
            self.rules.append(r)
            self.rules_store.save()
        self.log("rule", f"Added: {r['name']}" + (f" (until {R._when(r['expires_at'])})" if r.get("expires_at") else ""))
        self._enforce_soon()
        return r

    def update_rule(self, rid, data) -> dict:
        with self.lock:
            for i, r in enumerate(self.rules):
                if r["id"] == rid:
                    merged = dict(r)
                    if "name" not in data and r.get("name") == R.describe(r):
                        merged.pop("name", None)  # keep auto-generated names in sync
                    data = dict(data)
                    force = bool(data.pop("force", False))
                    nr = R.normalize(data, merged)
                    if nr.get("enabled", True):
                        self._check(nr, force)
                    self.rules[i] = nr
                    self.cap_state.pop(rid, None)
                    self.rules_store.save()
                    self.log("rule", f"Updated: {nr['name']}")
                    self._enforce_soon()
                    return nr
        raise KeyError(rid)

    def delete_rule(self, rid):
        with self.lock:
            for r in list(self.rules):
                if r["id"] == rid:
                    self.rules.remove(r)
                    self.rules_store.save()
                    self.log("allow", f"Removed: {r['name']}")
                    self._enforce_soon()
                    return True
        return False

    def allow_app(self, app):
        """Remove every block/throttle rule that targets exactly this app (not data limits)."""
        app = (app or "").lower()
        n = 0
        with self.lock:
            for r in list(self.rules):
                if (r.get("app") or "").lower() == app and r["type"] in ("block", "throttle"):
                    self.rules.remove(r)
                    n += 1
            if n:
                self.rules_store.save()
        if n:
            self.log("allow", f"Allowed again: {app.split(chr(92))[-1]}")
            self._enforce_soon()
        return n

    def pause_all(self, minutes, force=False):
        exp = time.time() + float(minutes) * 60 if minutes else None
        return self.add_rule({"type": "block", "pause_all": True, "direction": "both",
                              "name": "Internet paused", "expires_at": exp, "force": force})

    def resume_all(self):
        with self.lock:
            n = len(self.rules)
            self.rules[:] = [r for r in self.rules if not r.get("pause_all")]
            if len(self.rules) != n:
                self.rules_store.save()
                self.log("allow", "Internet resumed.")
        self._enforce_soon()

    def kill(self, lip, lport, rip, rport):
        ok = self.killer(lip, int(lport), rip, int(rport))
        self.log("info", f"{'Closed' if ok else 'Could not close'} connection to {rip}:{rport}")
        return ok

    def cleanup_all(self):
        with self.lock:
            self.rules[:] = []
            self.rules_store.save()
            self.applied = {n: k for n, k in self.applied.items() if n.startswith(LOCK_PREFIX)}
            self.failed.clear()
        if self.dropper:
            self.dropper.close()
            self.dropper = None
        self.fw.cleanup(keep_prefix=LOCK_PREFIX)
        self.qos.cleanup()
        self.log("allow", "Removed all NetWarden rules from Windows Firewall and QoS.")

    def set_settings(self, data):
        if "ui_mode" in data and data["ui_mode"] != self.settings.get("ui_mode"):
            self.lockdown.pending.clear()  # requests are per app (Beginner) or per address (Pro)
        if "theme" in data and data["theme"] not in ("classic", "modern"):
            raise ValueError("theme must be classic or modern")
        for k, v in data.items():
            if k in DEFAULT_SETTINGS:
                self.settings[k] = type(DEFAULT_SETTINGS[k])(v)
        self.src.dns.reverse_enabled = self.settings.get("resolve_hostnames", True) and not self.sim
        self.settings_store.save()

    def _enforce_soon(self):
        threading.Thread(target=self._safe_enforce, daemon=True).start()

    def _safe_enforce(self):
        try:
            self.enforce()
        except Exception:
            pass

    # ------------------------------------------------------------------ state for UI
    def state(self, full: bool) -> dict:
        t = time.time()
        m = self.monitor
        apps = m.app_list(self.usage)
        with self.lock:
            rules = []
            for r in self.rules:
                rr = dict(r)
                rr["status"] = self.status.get(r["id"], {"state": "pending", "detail": ""})
                rules.append(rr)
        ld = self.lockdown
        for a in apps:
            a["perm"] = ld.app_status(a["exe"])
            a["critical"] = is_critical(a["exe"] or a["name"])
        sysu = self.usage.data["system"]
        paused = next((r for r in rules if r.get("pause_all")), None)
        s = {
            "t": t, "sim": self.sim, "admin": self.admin, "uptime": t - self.started_at,
            "per_app_bytes": self.src.per_app_bytes(),
            "sniffer_error": getattr(self.src, "sniffer_error", None),
            "settings": self.settings,
            "total": {k: round(v) for k, v in m.total.items()},
            "today": {"up": sysu["d"][0], "down": sysu["d"][1]},
            "month": {"up": sysu["m"][0], "down": sysu["m"][1]},
            "history": list(m.history)[-120 if not full else -300:],
            "apps": apps,
            "rules": rules,
            "paused": paused,
            "events": list(self.events)[:60 if not full else 300],
            "lockdown": {
                "mode": ld.mode, "granularity": "address" if self.settings.get("ui_mode") == "pro" else "app",
                "pending": ld.pending_list(), "groups": ld.d["groups"], "decisions": ld.d["decisions"],
                "attempts": list(ld.attempts)[:250 if full else 30], "policy_ok": ld.policy_ok,
                "warnings": ld.status.get("warnings", []) + ([getattr(self.src, "watcher_error")]
                                                              if getattr(self.src, "watcher_error", None) else []),
            },
            "counts": {"connections": sum(a["conns"] for a in apps),
                       "endpoints": sum(1 for e in m.endpoints.values() if t - e.get("last", 0) < 30),
                       "apps_active": sum(1 for a in apps if a["active"])},
        }
        if full:
            s["connections"] = m.connection_list()
            s["endpoints"] = m.endpoint_list()
            s["dns"] = list(self.src.dns.recent)[:200]
            s["days"] = sorted(self.usage.data.get("days", {}).items())[-30:]
            s["unattributed"] = m.unattributed
            s["applied"] = len(self.applied)
            s["dropper"] = self.dropper is not None
            s["dropper_error"] = self.dropper_error
        return s
