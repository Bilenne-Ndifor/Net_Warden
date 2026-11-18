"""Shared helpers: paths, JSON storage, target/port parsing and rule-spec matching."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
from pathlib import Path

IS_WINDOWS = os.name == "nt"

PKG_DIR = Path(__file__).resolve().parent
BASE_DIR = PKG_DIR.parent
WEB_DIR = PKG_DIR / "web"
DATA_DIR = BASE_DIR / "data"

RULE_PREFIX = "NetWarden_"


def now() -> float:
    return time.time()


# --------------------------------------------------------------------------- storage
class JsonStore:
    """Tiny thread-safe JSON file with atomic writes."""

    def __init__(self, path: Path, default):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.data = default
        try:
            if self.path.exists():
                with open(self.path, "r", encoding="utf-8-sig") as f:  # -sig: PowerShell writes a BOM
                    loaded = json.load(f)
                if isinstance(default, dict) and isinstance(loaded, dict):
                    merged = dict(default)
                    merged.update(loaded)
                    self.data = merged
                else:
                    self.data = loaded
        except Exception:
            # Corrupt file: keep a backup and start fresh rather than crashing.
            try:
                self.path.replace(self.path.with_suffix(".corrupt.json"))
            except Exception:
                pass

    def save(self):
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            os.replace(tmp, self.path)


# --------------------------------------------------------------------------- parsing
DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}\.?$", re.I)


def parse_ports(text) -> list[tuple[int, int]]:
    """'80, 443, 1000-2000' -> [(80,80),(443,443),(1000,2000)]. Empty -> []."""
    if text is None:
        return []
    if isinstance(text, (list, tuple)):
        text = ",".join(str(x) for x in text)
    out = []
    for part in str(text).replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
        else:
            lo = hi = int(part)
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535) or lo > hi:
            raise ValueError(f"Invalid port '{part}'")
        out.append((lo, hi))
    return out


def ports_to_str(ranges) -> str:
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)


def port_in(ranges, port) -> bool:
    if not ranges:
        return True
    if port is None:
        return False
    return any(a <= port <= b for a, b in ranges)


def classify_target(tok: str):
    """Return ('ip', 'a.b.c.d/nn') | ('range', 'a-b') | ('domain', 'x.com'). Raises ValueError."""
    tok = tok.strip()
    if not tok:
        raise ValueError("empty target")
    try:
        net = ipaddress.ip_network(tok, strict=False)
        return ("ip", str(net) if "/" in tok else str(net.network_address))
    except ValueError:
        pass
    if "-" in tok:
        a, b = tok.split("-", 1)
        try:
            ia, ib = ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())
            if ia.version == ib.version and ia <= ib:
                return ("range", f"{ia}-{ib}")
        except ValueError:
            pass
    t = tok.lower().rstrip(".")
    if t.startswith("http://") or t.startswith("https://"):
        t = t.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    if DOMAIN_RE.match(t):
        return ("domain", t)
    raise ValueError(f"'{tok}' is not an IP, CIDR, IP range or domain name")


def split_targets(text) -> list[str]:
    if not text:
        return []
    if isinstance(text, (list, tuple)):
        items = [str(x) for x in text]
    else:
        items = re.split(r"[\s,;]+", str(text))
    return [i.strip() for i in items if i.strip()]


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def ip_in_targets(ip: str, targets) -> bool:
    """targets: list of netsh-style strings (ip, cidr, range). Empty list = any."""
    if not targets:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for t in targets:
        try:
            if "-" in t and "/" not in t:
                a, b = t.split("-", 1)
                ia, ib = ipaddress.ip_address(a), ipaddress.ip_address(b)
                if ia.version == addr.version and ia <= addr <= ib:
                    return True
            else:
                net = ipaddress.ip_network(t, strict=False)
                if addr.version == net.version and addr in net:
                    return True
        except ValueError:
            continue
    return False


def spec_matches(spec: dict, exe: str | None, rip: str, rport: int | None, proto: str) -> bool:
    """Does a firewall block spec apply to a connection? Used to kill live connections."""
    prog = spec.get("program")
    if prog and (not exe or prog.lower() != exe.lower()):
        return False
    p = spec.get("protocol")
    if p and p != proto:
        return False
    if spec.get("remoteip_list") and not ip_in_targets(rip, spec["remoteip_list"]):
        return False
    if spec.get("ports") and not port_in(spec["ports"], rport):
        return False
    return True


def fmt_bytes(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
