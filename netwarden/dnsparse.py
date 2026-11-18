"""Minimal DNS response parser + learned IP<->hostname map (fed by the packet sniffer)."""
from __future__ import annotations

import socket
import struct
import threading
import time
from collections import deque


def _read_name(buf: bytes, off: int, depth: int = 0):
    labels = []
    jumped_end = None
    hops = 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated")
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("truncated ptr")
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if jumped_end is None:
                jumped_end = off + 2
            off = ptr
            hops += 1
            if hops > 20:
                raise ValueError("pointer loop")
            continue
        off += 1
        labels.append(buf[off:off + ln].decode("ascii", "replace"))
        off += ln
    return ".".join(labels).lower(), (jumped_end if jumped_end is not None else off)


def parse_dns_response(payload: bytes):
    """Return (question_name, [ip, ...]) for an A/AAAA response, else None."""
    if len(payload) < 12:
        return None
    flags, qd, an = struct.unpack(">HHH", payload[2:8])
    if not flags & 0x8000 or qd < 1:
        return None
    try:
        qname, off = _read_name(payload, 12)
        off += 4
        for _ in range(qd - 1):
            _, off = _read_name(payload, off)
            off += 4
        ips = []
        for _ in range(an):
            _, off = _read_name(payload, off)
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", payload[off:off + 10])
            off += 10
            rdata = payload[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif rtype == 28 and rdlen == 16:
                ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
        return qname, ips
    except (ValueError, struct.error, OSError):
        return None


class DnsMap:
    """IP -> hostname learned from DNS answers, plus reverse-DNS fallback."""

    def __init__(self):
        self.lock = threading.Lock()
        self.ip2host: dict[str, str] = {}
        self.host2ips: dict[str, set[str]] = {}
        self.recent = deque(maxlen=300)
        self._rdns: dict[str, str | None] = {}
        self._rdns_pending: set[str] = set()
        self.reverse_enabled = True

    def learn(self, host: str, ips):
        if not host or not ips:
            return
        with self.lock:
            if len(self.ip2host) > 60000:  # long-running background process: keep memory bounded
                self.ip2host.clear()
                self.host2ips.clear()
            for ip in ips:
                self.ip2host[ip] = host
                hs = self.host2ips.setdefault(host, set())
                hs.add(ip)
                if len(hs) > 64:  # keep only a recent handful per host (CDNs rotate addresses)
                    hs.pop()
            self.recent.appendleft({"t": time.time(), "host": host, "ips": list(ips)[:8]})

    def host_for(self, ip: str) -> str | None:
        h = self.ip2host.get(ip)
        if h:
            return h
        if not self.reverse_enabled:
            return None
        if ip in self._rdns:
            return self._rdns[ip]
        if len(self._rdns) > 20000:
            self._rdns.clear()
        if ip not in self._rdns_pending and len(self._rdns_pending) < 16:
            self._rdns_pending.add(ip)
            threading.Thread(target=self._reverse, args=(ip,), daemon=True).start()
        return None

    def _reverse(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0].lower()
        except Exception:
            name = None
        self._rdns[ip] = name
        self._rdns_pending.discard(ip)

    def ips_for(self, domain: str) -> set[str]:
        """Learned IPs for domain; '*.x.com' also matches every learned subdomain."""
        wildcard = domain.startswith("*.")
        base = domain[2:] if wildcard else domain
        out = set()
        with self.lock:
            for host, ips in self.host2ips.items():
                if host == base or (wildcard and host.endswith("." + base)):
                    out |= ips
        return out
