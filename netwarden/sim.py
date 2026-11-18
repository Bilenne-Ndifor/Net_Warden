"""Simulated system for demo / UI testing (`--sim`, or automatically on non-Windows).
It fakes apps, connections and traffic, and honours the block / throttle rules it is given."""
from __future__ import annotations

import random
import socket
import time
from collections import namedtuple

from .dnsparse import DnsMap
from .util import ip_in_targets, port_in

Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "fd family type laddr raddr status pid")

APPS = [
    # name, exe, friendly, base down KB/s, base up KB/s, hosts
    ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Google Chrome", 900, 60,
     ["www.youtube.com", "rr3---sn-4g5e.googlevideo.com", "www.google.com", "github.com", "fonts.gstatic.com"]),
    ("Discord.exe", r"C:\Users\me\AppData\Local\Discord\app-1.0.9187\Discord.exe", "Discord", 40, 25,
     ["gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net"]),
    ("steam.exe", r"C:\Program Files (x86)\Steam\steam.exe", "Steam", 2200, 15,
     ["cache1-fra1.steamcontent.com", "api.steampowered.com", "store.steampowered.com"]),
    ("OneDrive.exe", r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "Microsoft OneDrive", 20, 380,
     ["api.onedrive.com", "my.microsoftpersonalcontent.com"]),
    ("Spotify.exe", r"C:\Users\me\AppData\Roaming\Spotify\Spotify.exe", "Spotify", 160, 8,
     ["audio-ak-spotify-com.akamaized.net", "spclient.wg.spotify.com"]),
    ("svchost.exe", r"C:\Windows\System32\svchost.exe", "Host Process for Windows Services", 30, 6,
     ["v10.events.data.microsoft.com", "settings-win.data.microsoft.com", "dl.delivery.mp.microsoft.com"]),
    ("Code.exe", r"C:\Users\me\AppData\Local\Programs\Microsoft VS Code\Code.exe", "Visual Studio Code", 12, 4,
     ["marketplace.visualstudio.com", "update.code.visualstudio.com"]),
    ("ollama.exe", r"C:\Users\me\AppData\Local\Programs\Ollama\ollama.exe", "Ollama", 5, 1,
     ["registry.ollama.ai"]),
]
LATE_APPS = [
    ("AdobeARM.exe", r"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe", "Adobe Reader Updater", 30, 4,
     ["armmf.adobe.com", "ardownload3.adobe.com"], 12),
    ("CompatTelRunner.exe", r"C:\Windows\System32\CompatTelRunner.exe", "Microsoft Compatibility Telemetry", 2, 20,
     ["v10.events.data.microsoft.com", "watson.telemetry.microsoft.com"], 20),
]
PORTS = {"default": [443, 443, 443, 80], "gateway.discord.gg": [443], "registry.ollama.ai": [443]}


class SimSource:
    def __init__(self):
        rnd = random.Random(7)
        self.rnd = rnd
        self.dns = DnsMap()
        self.dns.reverse_enabled = False
        self.fw_specs: dict[str, dict] = {}
        self.qos_specs: dict[str, dict] = {}
        self.paused_all = False
        self.default_out = "Allow"
        self.attempt_q = []
        self.profiles = {n: {"enabled": True, "out": "NotConfigured"} for n in ("Domain", "Private", "Public")}
        self.late = list(LATE_APPS)
        self.t0 = time.time()
        self.procs = {}
        self.flows = []  # dicts
        self.up_total = 10_000_000
        self.down_total = 80_000_000
        self.last = time.time()
        self.next_port = 52000
        pid = 3000
        for name, exe, friendly, dn, up, hosts in APPS:
            n_pids = 3 if name in ("chrome.exe", "svchost.exe") else 1
            pids = []
            for _ in range(n_pids):
                pid += rnd.randint(8, 400)
                pids.append(pid)
                self.procs[pid] = {"pid": pid, "name": name, "exe": exe, "friendly": friendly,
                                   "user": "QUANTUM\\me" if name != "svchost.exe" else "NT AUTHORITY\\SYSTEM",
                                   "services": ["Windows Update", "Delivery Optimization"] if name == "svchost.exe" else []}
            for h in hosts:
                ip = self._ip_for(h)
                self.dns.learn(h, [ip])
            self.procs_by_name = None
            for _ in range(rnd.randint(2, 4)):
                self._new_flow(pids, hosts, dn, up)

    def _ip_for(self, host):
        h = abs(hash(host)) % 2**32
        if "google" in host or "youtube" in host:
            return f"142.250.{h % 255}.{(h >> 8) % 254 + 1}"
        if "microsoft" in host or "onedrive" in host or "visualstudio" in host:
            return f"20.{(h >> 4) % 200 + 20}.{h % 255}.{(h >> 12) % 254 + 1}"
        return f"{(h % 180) + 23}.{(h >> 8) % 255}.{(h >> 16) % 255}.{(h >> 24) % 254 + 1}"

    def _new_flow(self, pids, hosts, dn, up):
        rnd = self.rnd
        host = rnd.choice(hosts)
        self.next_port += rnd.randint(1, 40)
        proto = "udp" if ("youtube" in host or "googlevideo" in host) and rnd.random() < 0.5 else "tcp"
        self.flows.append({
            "pid": rnd.choice(pids), "proto": proto, "lip": "192.168.1.42", "lport": self.next_port,
            "rip": self._ip_for(host), "rport": rnd.choice(PORTS.get(host, PORTS["default"])), "host": host,
            "dn": dn * rnd.uniform(0.2, 1.2) * 1024, "up": up * rnd.uniform(0.2, 1.2) * 1024,
            "until": time.time() + rnd.uniform(15, 120), "status": "ESTABLISHED", "pids": pids,
            "hosts": hosts, "bdn": dn, "bup": up})

    # ---- rule evaluation
    @staticmethod
    def _match(s, exe, f):
        if s.get("program") and s["program"].lower() != exe.lower():
            return False
        if s.get("protocol") and s["protocol"] != f["proto"]:
            return False
        if s.get("remoteip_list") and not ip_in_targets(f["rip"], s["remoteip_list"]):
            return False
        if s.get("ports") and not port_in(s["ports"], f["rport"]):
            return False
        return True

    def _blocked(self, f) -> bool:
        if self.paused_all:
            return True
        exe = self.procs[f["pid"]]["exe"]
        if any(s.get("action") == "block" or "action" not in s for s in self.fw_specs.values()
               if self._match(s, exe, f)):
            return True
        if self.default_out == "Block":
            return not any(s.get("action") == "allow" and s.get("dir") == "out" and self._match(s, exe, f)
                           for s in self.fw_specs.values())
        return False

    def _throttle(self, f):
        exe = self.procs[f["pid"]]["exe"]
        best = None
        for s in self.qos_specs.values():
            if s.get("app") and s["app"].lower() != exe.lower():
                continue
            if s.get("dst") and not ip_in_targets(f["rip"], [s["dst"]]):
                continue
            best = s["bits"] / 8 if best is None else min(best, s["bits"] / 8)
        return best

    # ---- Monitor interface
    def connections(self):
        t = time.time()
        alive = []
        for f in self.flows:
            if f["until"] < t:
                if f["status"] == "ESTABLISHED" and f["proto"] == "tcp":
                    f["status"] = "TIME_WAIT"
                    f["until"] = t + 8
                    alive.append(f)
                    self._new_flow(f["pids"], f["hosts"], f["bdn"], f["bup"])
                elif f["proto"] == "udp" and f["status"] == "ESTABLISHED":
                    self._new_flow(f["pids"], f["hosts"], f["bdn"], f["bup"])
                continue
            alive.append(f)
        self.flows = alive
        out = []
        for f in self.flows:
            if f["proto"] == "tcp":
                out.append(Conn(-1, socket.AF_INET, socket.SOCK_STREAM, Addr(f["lip"], f["lport"]),
                                Addr(f["rip"], f["rport"]), f["status"], f["pid"]))
            else:
                out.append(Conn(-1, socket.AF_INET, socket.SOCK_DGRAM, Addr("0.0.0.0", f["lport"]),
                                (), "NONE", f["pid"]))
        return out

    def proc_info(self, pid):
        return self.procs.get(pid, {"pid": pid, "name": f"pid {pid}", "exe": None,
                                    "friendly": f"pid {pid}", "user": None, "services": []})

    def drain(self):
        t = time.time()
        dt = max(0.1, t - self.last)
        self.last = t
        out = {}
        per_app_up = {}
        while self.late and t - self.t0 > self.late[0][6]:
            name, exe, friendly, dn, up, hosts, _ = self.late.pop(0)
            pid = 9000 + len(self.procs)
            self.procs[pid] = {"pid": pid, "name": name, "exe": exe, "friendly": friendly,
                               "user": "QUANTUM\\me", "services": []}
            for h in hosts:
                self.dns.learn(h, [self._ip_for(h)])
            for _ in range(2):
                self._new_flow([pid], hosts, dn, up)
        for f in self.flows:
            if f["status"] != "ESTABLISHED":
                continue
            if self._blocked(f):
                if t - f.get("last_attempt", 0) > 3:
                    f["last_attempt"] = t
                    self.attempt_q.append({"t": t, "pid": f["pid"], "app": self.procs[f["pid"]]["exe"],
                                           "ip": f["rip"], "port": f["rport"], "proto": f["proto"]})
                continue
            wobble = self.rnd.uniform(0.3, 1.7)
            dn = f["dn"] * dt * wobble
            up = f["up"] * dt * wobble
            out[(f["proto"], f["lport"], f["rip"], f["rport"])] = [up, dn]
            per_app_up.setdefault(f["pid"], []).append((f, up))
        # apply QoS (upload only, like Windows)
        for flist in per_app_up.values():
            for f, up in flist:
                lim = self._throttle(f)
                if lim is not None:
                    k = (f["proto"], f["lport"], f["rip"], f["rport"])
                    share = lim * dt / max(1, len(flist))
                    out[k][0] = min(out[k][0], share)
        for up, dn in out.values():
            self.up_total += up
            self.down_total += dn
        return {k: [int(v[0]), int(v[1])] for k, v in out.items()}

    def net_io(self):
        return int(self.up_total), int(self.down_total)

    def per_app_bytes(self):
        return True

    def drain_attempts(self):
        q, self.attempt_q = self.attempt_q, []
        return q

    def kill(self, laddr, lport, raddr, rport):
        for f in self.flows:
            if f["lport"] == lport and f["rip"] == raddr and f["rport"] == rport:
                f["until"] = 0
                return True
        return False

    def make_dropper(self):
        src = self

        class _D:
            def __init__(self):
                src.paused_all = True

            def close(self):
                src.paused_all = False
        return _D()

    def stop(self):
        pass


class SimFirewall:
    def __init__(self, src: SimSource):
        self.src = src

    def add(self, name, spec):
        self.src.fw_specs[name] = spec
        return True, "ok"

    def remove(self, name):
        self.src.fw_specs.pop(name, None)
        return True, "ok"

    def cleanup(self, keep_prefix=None):
        for k in list(self.src.fw_specs):
            if not (keep_prefix and k.startswith(keep_prefix)):
                del self.src.fw_specs[k]
        return True, "ok"

    def list_names(self):
        return set(self.src.fw_specs)

    def get_profiles(self):
        return {n: dict(p) for n, p in self.src.profiles.items()}

    def set_outbound(self, actions):
        for n, a in actions.items():
            self.src.profiles[n]["out"] = a
        self.src.default_out = "Block" if any(p["out"] == "Block" for p in self.src.profiles.values()) else "Allow"
        return True, "ok"

    def enable_all(self):
        for p in self.src.profiles.values():
            p["enabled"] = True
        return True, "ok"

    def set_audit(self, enable):
        return True, "ok"


class SimQos:
    def __init__(self, src: SimSource):
        self.src = src

    def add(self, name, spec):
        self.src.qos_specs[name] = spec
        return True, "ok"

    def remove(self, name):
        self.src.qos_specs.pop(name, None)
        return True, "ok"

    def cleanup(self):
        self.src.qos_specs.clear()
        return True, "ok"

    def list_names(self):
        return set(self.src.qos_specs)
