"""Windows back end: Windows Firewall rules, QoS throttling policies, WinDivert sniffing,
TCP connection reset and process metadata. Everything here needs Administrator rights."""
from __future__ import annotations

import ctypes
import os
import socket
import struct
import subprocess
import threading
import time
from collections import deque

import psutil

from .dnsparse import DnsMap, parse_dns_response
from .util import RULE_PREFIX, is_loopback

CREATE_NO_WINDOW = 0x08000000


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd, timeout=20):
    """Run a command string (Windows passes it to CreateProcess verbatim, so quoting is exact)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW, errors="replace")
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode == 0, out.strip()
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def _ps(script, timeout=30):
    return _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-Command", script], timeout=timeout)


def _psq(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


# --------------------------------------------------------------------------- firewall
class WindowsFirewall:
    """Block rules through `netsh advfirewall`. All rules are named NetWarden_<rule>_<n>."""

    def add(self, name: str, spec: dict):
        parts = ["netsh advfirewall firewall add rule", f"name={name}", f"dir={spec['dir']}",
                 f"action={spec.get('action', 'block')}", "enable=yes", "profile=any",
                 f'description="Managed by NetWarden"']
        if spec.get("program"):
            parts.append(f'program="{spec["program"]}"')
        if spec.get("remoteip"):
            parts.append(f"remoteip={spec['remoteip']}")
        if spec.get("protocol"):
            parts.append(f"protocol={spec['protocol'].upper()}")
            if spec.get("remoteport"):
                parts.append(f"remoteport={spec['remoteport']}")
        return _run(" ".join(parts))

    def remove(self, name: str):
        ok, out = _run(f"netsh advfirewall firewall delete rule name={name}")
        if not ok and "No rules match" in out:
            return True, out
        return ok, out

    def cleanup(self, keep_prefix: str | None = None):
        keep = f" | Where-Object {{ $_.DisplayName -notlike '{keep_prefix}*' }}" if keep_prefix else ""
        return _ps(f"Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue{keep} "
                   f"| Remove-NetFirewallRule -ErrorAction SilentlyContinue; 'ok'")

    def list_names(self) -> set[str]:
        ok, out = _ps(f"Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue "
                      f"| ForEach-Object {{ $_.DisplayName }}")
        return {l.strip() for l in out.splitlines() if l.strip().startswith(RULE_PREFIX)} if ok else set()

    # ---- profile policy (block-all mode)
    def get_profiles(self) -> dict:
        """{'Domain': {'enabled': True, 'out': 'NotConfigured'}, 'Private': ..., 'Public': ...}"""
        ok, out = _ps("Get-NetFirewallProfile | ForEach-Object { '{0}|{1}|{2}' -f $_.Name, $_.Enabled, $_.DefaultOutboundAction }")
        res = {}
        for line in out.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 3 and parts[0] in ("Domain", "Private", "Public"):
                res[parts[0]] = {"enabled": parts[1].strip().lower() == "true", "out": parts[2].strip()}
        return res

    def set_outbound(self, actions: dict):
        """actions: {'Domain': 'Block', 'Private': 'Block', 'Public': 'Block'} (or Allow / NotConfigured)."""
        cmds = [f"Set-NetFirewallProfile -Name {n} -DefaultOutboundAction {a}" for n, a in actions.items()
                if a in ("Block", "Allow", "NotConfigured")]
        return _ps("; ".join(cmds) + "; 'ok'") if cmds else (True, "")

    def enable_all(self):
        return _ps("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True; 'ok'")

    def set_audit(self, enable: bool):
        return set_connection_audit(enable)


    # ---- failsafe: a timed block (pause) must end even if NetWarden is killed or crashes
    def schedule_expiry(self, tag: str, ts: float):
        """Register a one-shot Windows task (as SYSTEM) that deletes NetWarden_<tag>_* rules at ts."""
        import base64
        import datetime as _dt
        task = f"Expire_{tag}"
        inner = (f"Get-NetFirewallRule -DisplayName '{RULE_PREFIX}{tag}_*' -ErrorAction SilentlyContinue | "
                 f"Remove-NetFirewallRule; Unregister-ScheduledTask -TaskName '{task}' -TaskPath '\\NetWarden\\' "
                 f"-Confirm:$false")
        enc = base64.b64encode(inner.encode("utf-16-le")).decode()
        when = _dt.datetime.fromtimestamp(ts + 5).strftime("%Y-%m-%dT%H:%M:%S")
        script = (
            "$sys = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18'))"
            ".Translate([System.Security.Principal.NTAccount]).Value; "
            f"$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive "
            f"-WindowStyle Hidden -EncodedCommand {enc}'; "
            f"$t = New-ScheduledTaskTrigger -Once -At ([datetime]::ParseExact('{when}', 'yyyy-MM-ddTHH:mm:ss', "
            "[Globalization.CultureInfo]::InvariantCulture)); "
            "$p = New-ScheduledTaskPrincipal -UserId $sys -LogonType ServiceAccount -RunLevel Highest; "
            "$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; "
            f"Register-ScheduledTask -TaskName '{task}' -TaskPath '\\NetWarden\\' -Action $a -Trigger $t "
            "-Principal $p -Settings $s -Force | Out-Null; 'ok'")
        return _ps(script)

    def cancel_expiry(self, tag: str):
        return _ps(f"Unregister-ScheduledTask -TaskName 'Expire_{tag}' -TaskPath '\\NetWarden\\' "
                   f"-Confirm:$false -ErrorAction SilentlyContinue; 'ok'")

    def list_expiry(self) -> set[str]:
        ok, out = _ps("Get-ScheduledTask -TaskPath '\\NetWarden\\' -ErrorAction SilentlyContinue | "
                      "ForEach-Object { $_.TaskName }")
        return {l.strip()[7:] for l in out.splitlines() if l.strip().startswith("Expire_")} if ok else set()


def get_critical_ips() -> list[str]:
    """Default gateways + DNS servers: blocking these cuts the whole PC off."""
    ok, out = _ps("Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object { "
                  "$_.IPv4DefaultGateway.NextHop; $_.IPv6DefaultGateway.NextHop; $_.DNSServer.ServerAddresses }")
    import ipaddress
    res = []
    for line in out.splitlines():
        v = line.strip().split("%")[0]
        try:
            a = ipaddress.ip_address(v)
            if not a.is_unspecified and not a.is_loopback:
                res.append(str(a))
        except ValueError:
            continue
    return res


AUDIT_GUID = "{0CCE9226-69AE-11D9-BED3-505054503030}"  # Filtering Platform Connection (locale-independent)


def set_connection_audit(enable: bool):
    """Turn on/off logging of blocked connections (Security event 5157)."""
    return _run(f'auditpol /set /subcategory:"{AUDIT_GUID}" /failure:{"enable" if enable else "disable"}')


class WindowsQos:
    """Outbound bandwidth throttling with Windows QoS policies (ActiveStore = not persisted)."""

    def add(self, name: str, spec: dict):
        cond = []
        if spec.get("app"):
            cond.append(f"-AppPathNameMatchCondition {_psq(spec['app'])}")
        if spec.get("dst"):
            cond.append(f"-IPDstPrefixMatchCondition {_psq(spec['dst'])}")
        if spec.get("port_start"):
            cond.append(f"-IPDstPortStartMatchCondition {spec['port_start']} "
                        f"-IPDstPortEndMatchCondition {spec['port_end']}")
        cond.append(f"-IPProtocolMatchCondition {spec.get('proto', 'Both')}")
        script = (f"New-NetQosPolicy -Name {_psq(name)} {' '.join(cond)} "
                  f"-ThrottleRateActionBitsPerSecond {int(spec['bits'])} "
                  f"-PolicyStore ActiveStore -Confirm:$false | Out-Null; 'ok'")
        return _ps(script)

    def remove(self, name: str):
        return _ps(f"Remove-NetQosPolicy -Name {_psq(name)} -PolicyStore ActiveStore "
                   f"-Confirm:$false -ErrorAction SilentlyContinue; 'ok'")

    def cleanup(self):
        return _ps(f"Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | "
                   f"Where-Object {{ $_.Name -like '{RULE_PREFIX}*' }} | "
                   f"Remove-NetQosPolicy -PolicyStore ActiveStore -Confirm:$false; 'ok'")

    def list_names(self) -> set[str]:
        ok, out = _ps(f"Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | "
                      f"Where-Object {{ $_.Name -like '{RULE_PREFIX}*' }} | ForEach-Object {{ $_.Name }}")
        return {l.strip() for l in out.splitlines() if l.strip().startswith(RULE_PREFIX)} if ok else set()


# --------------------------------------------------------------------------- tcp reset
class _MIB_TCPROW(ctypes.Structure):
    _fields_ = [("dwState", ctypes.c_ulong), ("dwLocalAddr", ctypes.c_ulong),
                ("dwLocalPort", ctypes.c_ulong), ("dwRemoteAddr", ctypes.c_ulong),
                ("dwRemotePort", ctypes.c_ulong)]


def kill_tcp(laddr: str, lport: int, raddr: str, rport: int) -> bool:
    """Reset an IPv4 TCP connection (MIB_TCP_STATE_DELETE_TCB). IPv6 is not supported by Windows."""
    if ":" in laddr or ":" in raddr:
        return False
    try:
        row = _MIB_TCPROW(12,
                          struct.unpack("<I", socket.inet_aton(laddr))[0], socket.htons(lport),
                          struct.unpack("<I", socket.inet_aton(raddr))[0], socket.htons(rport))
        return ctypes.windll.iphlpapi.SetTcpEntry(ctypes.byref(row)) == 0
    except Exception:
        return False


# --------------------------------------------------------------------------- file description
def file_description(path: str) -> str | None:
    """Read FileDescription from an exe's version resource, e.g. 'Google Chrome'."""
    try:
        from ctypes import wintypes
        ver = ctypes.windll.version
        ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        ver.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
        ver.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                       ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return None
        lp, ln = ctypes.c_void_p(), wintypes.UINT()
        pages = []
        if ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(lp), ctypes.byref(ln)) and ln.value >= 4:
            arr = ctypes.cast(lp, ctypes.POINTER(ctypes.c_ushort * 2)).contents
            pages.append((arr[0], arr[1]))
        pages += [(0x0409, 0x04B0), (0x0409, 0x04E4), (0x0000, 0x04B0)]
        for lang, cp in pages:
            sub = f"\\StringFileInfo\\{lang:04x}{cp:04x}\\FileDescription"
            if ver.VerQueryValueW(buf, sub, ctypes.byref(lp), ctypes.byref(ln)) and ln.value:
                s = ctypes.wstring_at(lp.value, ln.value).rstrip("\x00").strip()
                if s:
                    return s
    except Exception:
        return None
    return None


# --------------------------------------------------------------------------- WinDivert
class Sniffer(threading.Thread):
    """Passive copy of every TCP/UDP packet (WinDivert SNIFF mode) -> per-flow byte counters."""

    def __init__(self, dns: DnsMap):
        super().__init__(daemon=True, name="sniffer")
        import pydivert  # noqa: F401  (raises ImportError if missing)
        self.pydivert = pydivert
        self.dns = dns
        self.cur: dict = {}
        self.running = True
        self.packets = 0
        self.error = None
        self.w = pydivert.WinDivert("tcp or udp", flags=pydivert.Flag.SNIFF)
        self.w.open()
        for param, val in ((pydivert.Param.QUEUE_LEN, 8192), (pydivert.Param.QUEUE_TIME, 2048)):
            try:
                self.w.set_param(param, val)
            except Exception:
                pass

    def run(self):
        while self.running:
            try:
                p = self.w.recv()  # blocking is fastest; stop() closes the handle to unblock
            except Exception as e:  # noqa: BLE001
                if not self.running:
                    break
                self.error = str(e)
                time.sleep(0.05)
                continue
            try:
                self.packets += 1
                proto = "tcp" if p.tcp is not None else "udp"
                size = len(p.raw)
                if p.is_outbound:
                    rip, lport, rport = p.dst_addr, p.src_port, p.dst_port
                    if is_loopback(rip):
                        continue
                    k = (proto, lport, rip, rport)
                    c = self.cur.get(k)
                    if c is None:
                        self.cur[k] = [size, 0]
                    else:
                        c[0] += size
                else:
                    rip, lport, rport = p.src_addr, p.dst_port, p.src_port
                    if is_loopback(rip):
                        continue
                    k = (proto, lport, rip, rport)
                    c = self.cur.get(k)
                    if c is None:
                        self.cur[k] = [0, size]
                    else:
                        c[1] += size
                    if proto == "udp" and rport == 53:
                        r = parse_dns_response(bytes(p.payload or b""))
                        if r:
                            self.dns.learn(*r)
            except Exception:
                continue

    def drain(self) -> dict:
        d, self.cur = self.cur, {}
        return d

    def stop(self):
        self.running = False
        try:
            self.w.close()
        except Exception:
            pass


class Dropper:
    """Kernel-side drop of all non-loopback IP traffic: makes 'Pause internet' instant,
    including already-open connections and QUIC/UDP streams the firewall would let finish."""

    FILTER = ("(ip and ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1) or "
              "(ipv6 and ipv6.DstAddr != ::1 and ipv6.SrcAddr != ::1)")

    def __init__(self):
        import pydivert
        self.w = pydivert.WinDivert(self.FILTER, priority=-500, flags=pydivert.Flag.DROP)
        self.w.open()

    def close(self):
        try:
            self.w.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- blocked-connection watcher
def device_path_map() -> dict[str, str]:
    """'\\device\\harddiskvolume3' -> 'C:' for every drive letter."""
    m = {}
    buf = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        try:
            if ctypes.windll.kernel32.QueryDosDeviceW(f"{letter}:", buf, 1024):
                m[buf.value.lower()] = f"{letter}:"
        except Exception:
            continue
    return m


class AuditWatcher:
    """Subscribes to Security event 5157 (connection blocked by WFP) and queues outbound attempts."""

    QUERY_OUT = ("*[System[(EventID=5157)]] and "
                 "*[EventData[Data[@Name='Direction']='%%14593']]")
    QUERY_ANY = "*[System[(EventID=5157)]]"

    def __init__(self):
        from ctypes import wintypes
        self.queue = deque(maxlen=5000)
        self.error = None
        self.events = 0
        self.devmap = device_path_map()
        self._devmap_t = time.time()
        w = ctypes.WinDLL("wevtapi", use_last_error=True)
        self.CB = ctypes.WINFUNCTYPE(wintypes.DWORD, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
        w.EvtSubscribe.restype = ctypes.c_void_p
        w.EvtSubscribe.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                   ctypes.c_void_p, ctypes.c_void_p, self.CB, wintypes.DWORD]
        w.EvtRender.restype = wintypes.BOOL
        w.EvtRender.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
        w.EvtClose.argtypes = [ctypes.c_void_p]
        self.w = w
        self._cb = self.CB(self._callback)  # keep a reference: ctypes callbacks must stay alive
        self.handle = None
        for q in (self.QUERY_OUT, self.QUERY_ANY):
            h = w.EvtSubscribe(None, None, "Security", q, None, None, self._cb, 1)  # 1 = future events
            if h:
                self.handle = h
                break
        if not self.handle:
            raise OSError(f"EvtSubscribe failed ({ctypes.get_last_error()})")

    def _render(self, ev) -> str | None:
        from ctypes import wintypes
        used, count = wintypes.DWORD(), wintypes.DWORD()
        self.w.EvtRender(None, ev, 1, 0, None, ctypes.byref(used), ctypes.byref(count))
        if not used.value:
            return None
        buf = ctypes.create_string_buffer(used.value)
        if not self.w.EvtRender(None, ev, 1, used.value, buf, ctypes.byref(used), ctypes.byref(count)):
            return None
        return buf.raw[:used.value].decode("utf-16-le", "replace").rstrip("\x00")

    def _callback(self, action, ctx, ev):
        try:
            if action != 1:  # EvtSubscribeActionDeliver
                return 0
            xml = self._render(ev)
            if xml:
                self.events += 1
                a = self._parse(xml)
                if a:
                    self.queue.append(a)
        except Exception as e:  # noqa: BLE001
            self.error = str(e)
        return 0

    def _parse(self, xml: str):
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
        data = {}
        for el in root.iter():
            if el.tag.endswith("Data") and el.get("Name"):
                data[el.get("Name").lower()] = (el.text or "").strip()
        if data.get("direction") != "%%14593":
            return None
        app = data.get("application") or ""
        pid = int(data.get("processid") or 0)
        exe = None
        try:
            exe = psutil.Process(pid).exe() if pid > 4 else None
        except Exception:
            exe = None
        if not exe:
            exe = self.to_dos(app)
        proto = {"6": "tcp", "17": "udp"}.get(data.get("protocol", ""), data.get("protocol", ""))
        if proto not in ("tcp", "udp"):
            return None
        try:
            port = int(data.get("destport") or 0)
        except ValueError:
            port = 0
        return {"t": time.time(), "pid": pid, "app": exe, "ip": data.get("destaddress", ""),
                "port": port, "proto": proto}

    def to_dos(self, app: str) -> str | None:
        if not app or app == "-":
            return None
        if app.lower() == "system":
            return "System"
        low = app.lower()
        if time.time() - self._devmap_t > 300:
            self.devmap, self._devmap_t = device_path_map(), time.time()
        for dev, letter in self.devmap.items():
            if low.startswith(dev + "\\"):
                return letter + app[len(dev):]
        return app

    def drain(self):
        out = []
        while self.queue:
            out.append(self.queue.popleft())
        return out

    def close(self):
        if self.handle:
            try:
                self.w.EvtClose(self.handle)
            except Exception:
                pass
            self.handle = None


# --------------------------------------------------------------------------- data source
class RealSource:
    """Feeds the Monitor from the live system."""

    def __init__(self):
        self.dns = DnsMap()
        self.sniffer = None
        self.sniffer_error = None
        try:
            self.sniffer = Sniffer(self.dns)
            self.sniffer.start()
        except ImportError:
            self.sniffer_error = "pydivert is not installed (run run.bat to install dependencies)"
        except Exception as e:  # noqa: BLE001
            self.sniffer_error = f"WinDivert could not start: {e}. Run as Administrator; some antivirus tools block WinDivert."
        self.watcher = None
        self.watcher_error = None
        try:
            self.watcher = AuditWatcher()
        except Exception as e:  # noqa: BLE001
            self.watcher_error = f"Can't watch blocked connections: {e}"
        self._proc: dict[int, tuple[float, dict]] = {}
        self._desc: dict[str, str | None] = {}
        self._services: dict[int, list[str]] = {}
        self._services_t = 0.0

    # psutil-compatible connection list
    def connections(self):
        try:
            return psutil.net_connections(kind="inet")
        except Exception:
            return []

    def _refresh_services(self):
        if time.time() - self._services_t < 30:
            return
        self._services_t = time.time()
        m: dict[int, list[str]] = {}
        try:
            for s in psutil.win_service_iter():
                try:
                    pid = s.pid()
                    if pid:
                        m.setdefault(pid, []).append(s.display_name())
                except Exception:
                    continue
        except Exception:
            pass
        self._services = m

    def proc_info(self, pid: int) -> dict:
        self._refresh_services()
        cached = self._proc.get(pid)
        try:
            p = psutil.Process(pid)
            ct = p.create_time()
        except Exception:
            ct = None
            p = None
        if cached and cached[0] == ct:
            info = cached[1]
            info["services"] = self._services.get(pid, [])
            return info
        name, exe, user = f"pid {pid}", None, None
        if pid == 4:
            name, exe = "System", "System"
        elif p is not None:
            try:
                name = p.name()
            except Exception:
                pass
            try:
                exe = p.exe() or None
            except Exception:
                exe = None
            try:
                user = p.username()
            except Exception:
                user = None
        friendly = None
        if exe and exe != "System":
            if exe not in self._desc:
                self._desc[exe] = file_description(exe)
            friendly = self._desc[exe]
        info = {"pid": pid, "name": name, "exe": exe, "friendly": friendly or _pretty(name),
                "user": user, "services": self._services.get(pid, [])}
        self._proc[pid] = (ct, info)
        if len(self._proc) > 4000:
            self._proc.clear()
        return info

    def drain(self):
        return self.sniffer.drain() if self.sniffer else {}

    def net_io(self):
        up = down = 0
        try:
            for nic, c in psutil.net_io_counters(pernic=True).items():
                if "loopback" in nic.lower():
                    continue
                up += c.bytes_sent
                down += c.bytes_recv
        except Exception:
            pass
        return up, down

    def per_app_bytes(self) -> bool:
        return self.sniffer is not None

    def critical_ips(self):
        return get_critical_ips()

    def drain_attempts(self):
        return self.watcher.drain() if self.watcher else []

    def make_dropper(self):
        return Dropper()

    def stop(self):
        if self.sniffer:
            self.sniffer.stop()
        if self.watcher:
            self.watcher.close()


def _pretty(name: str) -> str:
    base = os.path.splitext(name)[0]
    return base[:1].upper() + base[1:] if base else name
