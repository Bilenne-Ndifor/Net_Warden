"""Guard rails: detect rules / decisions that could cut the PC off or break Windows networking.

Risky changes are not refused; they raise NeedsConfirm. The UI shows the reasons and only
re-sends the change with force=true after the user explicitly agrees.
"""
from __future__ import annotations

import ipaddress
import os
import time

from .util import classify_target, parse_ports

# Programs Windows needs for networking, security updates and sign-in.
CRITICAL_APPS = {
    "system", "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe", "csrss.exe",
    "smss.exe", "msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe", "mpcmdrun.exe",
    "mousocoreworker.exe", "sihclient.exe", "smartscreen.exe", "dns.exe",
}
DNS_DHCP_PORTS = {53, 67, 68}


class NeedsConfirm(Exception):
    """A change that could break networking. .reasons = list of plain-language warnings."""

    def __init__(self, reasons):
        super().__init__("; ".join(reasons))
        self.reasons = list(reasons)


def is_critical(app: str | None) -> bool:
    if not app:
        return False
    return os.path.basename(app.replace("/", "\\").split("\\")[-1]).lower() in CRITICAL_APPS


def _app_label(app):
    return app.replace("/", "\\").split("\\")[-1] if app else "All apps"


class NetInfo:
    """Default gateways and DNS servers of this PC (refreshed every 10 minutes)."""

    def __init__(self, fetch):
        self.fetch = fetch
        self.ips: set[str] = set()
        self.t = 0.0

    def get(self) -> set[str]:
        if time.time() - self.t > 600:
            self.t = time.time()
            try:
                self.ips = set(self.fetch()) or self.ips
            except Exception:
                pass
        return self.ips


def _covers(targets, ip):
    a = ipaddress.ip_address(ip)
    for t in targets:
        try:
            if "-" in t and "/" not in t:
                lo, hi = (ipaddress.ip_address(x) for x in t.split("-", 1))
                if lo.version == a.version and lo <= a <= hi:
                    return True
            else:
                n = ipaddress.ip_network(t, strict=False)
                if n.version == a.version and a in n:
                    return True
        except ValueError:
            continue
    return False


def rule_risks(r: dict, critical_ips: set[str]) -> list[str]:
    """Plain-language reasons why this rule could break the PC's networking (empty = fine)."""
    risks = []
    typ = r.get("type")
    blocks = typ == "block" or (typ == "cap" and (r.get("cap") or {}).get("action") == "block")
    throttles = typ == "throttle" or (typ == "cap" and (r.get("cap") or {}).get("action") == "throttle")
    app = r.get("app")
    if r.get("pause_all"):
        return risks
    if (blocks or throttles) and is_critical(app):
        risks.append(f"{_app_label(app)} is a core Windows component (DNS, DHCP, updates, sign-in or antivirus). "
                     f"{'Blocking' if blocks else 'Slowing'} it can break the internet for every app "
                     f"or stop security updates.")
    ips = []
    for tok in r.get("remote") or []:
        try:
            kind, val = classify_target(tok)
        except ValueError:
            continue
        if kind == "ip":
            net = ipaddress.ip_network(val, strict=False)
            if blocks and ((net.version == 4 and net.prefixlen <= 8) or (net.version == 6 and net.prefixlen <= 16)):
                risks.append(f"{val} covers {net.num_addresses:,} addresses — a large part of the internet.")
        if kind in ("ip", "range"):
            ips.append(val)
    if blocks and not app:
        hit = sorted(ip for ip in critical_ips if _covers(ips, ip)) if ips else []
        if hit:
            risks.append(f"This blocks your router / DNS server ({', '.join(hit)}). Every app would lose the "
                         f"internet, including name lookups.")
        try:
            ports = parse_ports(r.get("ports"))
        except ValueError:
            ports = []
        if ports and any(a <= p <= b for a, b in ports for p in DNS_DHCP_PORTS) and r.get("protocol") != "tcp":
            risks.append("These ports include DNS/DHCP (53, 67, 68). Blocking them for all apps stops "
                         "websites from loading and can drop your network connection.")
        if typ == "cap":
            risks.append("When this data limit is reached, the whole PC goes offline until it resets.")
    if typ == "throttle" and not app and float(r.get("rate_kbps") or 0) < 512:
        risks.append(f"This slows ALL uploads of the PC to {r.get('rate_kbps'):g} kbit/s — web pages and calls "
                     f"may stop working.")
    if typ == "cap" and not app and throttles and float((r.get("cap") or {}).get("throttle_kbps") or 0) < 512:
        risks.append("When reached, ALL uploads of the PC are slowed to a crawl.")
    return risks


def in_remote_session() -> bool:
    """True inside a Remote Desktop session (pausing / block-all could cut the session)."""
    try:
        import ctypes
        return bool(ctypes.windll.user32.GetSystemMetrics(0x1000))
    except Exception:
        return False
