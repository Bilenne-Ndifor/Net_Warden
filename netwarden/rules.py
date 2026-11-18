"""Rule model: validation, timing (pause / allow later / schedules) and data-usage accounting."""
from __future__ import annotations

import datetime as dt
import time
import uuid

from .util import JsonStore, classify_target, parse_ports, split_targets

TYPES = ("block", "throttle", "cap")
DIRECTIONS = ("out", "in", "both")
PROTOCOLS = ("any", "tcp", "udp")
DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def _hm(s: str) -> int:
    h, m = str(s).split(":", 1)
    h, m = int(h), int(m)
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError(f"bad time {s}")
    return h * 60 + m


def normalize(data: dict, existing: dict | None = None) -> dict:
    """Validate a rule coming from the UI. Raises ValueError with a readable message."""
    r = dict(existing or {})
    r.update({k: v for k, v in data.items() if not k.startswith("_")})
    r.setdefault("id", uuid.uuid4().hex[:8])
    r.setdefault("created_at", time.time())
    r["type"] = r.get("type") or "block"
    if r["type"] not in TYPES:
        raise ValueError("type must be block, throttle or cap")
    r["enabled"] = bool(r.get("enabled", True))
    r["app"] = (r.get("app") or "").strip() or None
    r["app_name"] = r.get("app_name") or (r["app"].replace("/", "\\").split("\\")[-1] if r["app"] else None)
    targets = split_targets(r.get("remote"))
    for tok in targets:
        classify_target(tok)
    r["remote"] = targets
    r["protocol"] = (r.get("protocol") or "any").lower()
    if r["protocol"] not in PROTOCOLS:
        raise ValueError("protocol must be any, tcp or udp")
    ports = parse_ports(r.get("ports"))
    r["ports"] = ",".join(str(a) if a == b else f"{a}-{b}" for a, b in ports)
    r["direction"] = r.get("direction") or "both"
    if r["direction"] not in DIRECTIONS:
        raise ValueError("direction must be out, in or both")
    for k in ("starts_at", "expires_at"):
        v = r.get(k)
        r[k] = float(v) if v not in (None, "", 0) else None
    if r["starts_at"] and r["expires_at"] and r["expires_at"] <= r["starts_at"]:
        raise ValueError("'allow again at' must be after 'start at'")
    sch = r.get("schedule")
    if sch:
        days = [int(d) for d in (sch.get("days") or range(7)) if 0 <= int(d) <= 6]
        _hm(sch.get("start", "00:00")), _hm(sch.get("end", "00:00"))
        if not days:
            raise ValueError("schedule needs at least one day")
        r["schedule"] = {"days": sorted(set(days)), "start": sch["start"], "end": sch["end"]}
    else:
        r["schedule"] = None
    if r["type"] == "throttle":
        kbps = float(r.get("rate_kbps") or 0)
        if kbps < 8:
            raise ValueError("throttle speed must be at least 8 kbit/s")
        r["rate_kbps"] = kbps
    if r["type"] == "cap":
        cap = dict(r.get("cap") or {})
        cap["mb"] = float(cap.get("mb") or 0)
        if cap["mb"] <= 0:
            raise ValueError("data limit must be more than 0 MB")
        cap["period"] = cap.get("period") or "day"
        if cap["period"] not in ("day", "month"):
            raise ValueError("period must be day or month")
        cap["metric"] = cap.get("metric") or "total"
        if cap["metric"] not in ("total", "up", "down"):
            raise ValueError("metric must be total, up or down")
        cap["action"] = cap.get("action") or "block"
        if cap["action"] not in ("block", "throttle", "alert"):
            raise ValueError("action must be block, throttle or alert")
        if cap["action"] == "throttle":
            cap["throttle_kbps"] = max(8.0, float(cap.get("throttle_kbps") or 256))
        r["cap"] = cap
    if r["type"] == "block" and not (r["app"] or r["remote"] or r["ports"] or r.get("pause_all")):
        raise ValueError("a block rule needs an app, a remote address/domain or ports "
                         "(use Pause internet to block everything)")
    r["name"] = (r.get("name") or "").strip() or describe(r)
    return r


def schedule_active(sch: dict, t: float) -> bool:
    lt = dt.datetime.fromtimestamp(t)
    s, e = _hm(sch["start"]), _hm(sch["end"])
    m = lt.hour * 60 + lt.minute
    days = sch["days"]
    if s == e:
        return lt.weekday() in days
    if s < e:
        return lt.weekday() in days and s <= m < e
    if m >= s:
        return lt.weekday() in days
    if m < e:
        return (lt.weekday() - 1) % 7 in days
    return False


def timing_state(r: dict, t: float):
    """('disabled'|'scheduled'|'expired'|'off-schedule'|'on', detail)."""
    if not r.get("enabled", True):
        return "disabled", "Turned off"
    if r.get("starts_at") and t < r["starts_at"]:
        return "scheduled", "Starts " + _when(r["starts_at"])
    if r.get("expires_at") and t >= r["expires_at"]:
        return "expired", "Expired"
    if r.get("schedule") and not schedule_active(r["schedule"], t):
        s = r["schedule"]
        return "off-schedule", f"Only {s['start']}–{s['end']} on " + ",".join(DAY_NAMES[d] for d in s["days"])
    return "on", ("Until " + _when(r["expires_at"])) if r.get("expires_at") else ""


def _when(ts: float) -> str:
    d = dt.datetime.fromtimestamp(ts)
    today = dt.date.today()
    if d.date() == today:
        return d.strftime("%H:%M")
    if d.date() == today + dt.timedelta(days=1):
        return "tomorrow " + d.strftime("%H:%M")
    return d.strftime("%d %b %H:%M")


def describe(r: dict) -> str:
    who = r.get("app_name") or "All apps"
    if r.get("pause_all"):
        return "Internet paused"
    where = ""
    if r.get("remote"):
        where = " → " + ", ".join(r["remote"][:3]) + ("…" if len(r["remote"]) > 3 else "")
    what = ""
    if r.get("protocol") not in (None, "any") or r.get("ports"):
        proto = (r.get('protocol') or 'any')
        bits = ([proto.upper()] if proto != 'any' else []) + (['ports ' + r['ports']] if r.get('ports') else [])
        what = f" ({' '.join(bits)})"
    if r["type"] == "block":
        return f"Block {who}{where}{what}"
    if r["type"] == "throttle":
        return f"Limit upload of {who}{where}{what} to {fmt_kbps(r.get('rate_kbps', 0))}"
    cap = r.get("cap") or {}
    return f"{cap.get('mb', 0):g} MB/{cap.get('period', 'day')} data limit for {who}"


def fmt_kbps(k: float) -> str:
    return f"{k / 1000:g} Mbit/s" if k >= 1000 else f"{k:g} kbit/s"


# --------------------------------------------------------------------------- usage
class Usage:
    """Per-app bytes for today and this month, plus 60 days of system totals. Persisted."""

    def __init__(self, path):
        self.store = JsonStore(path, {"day": "", "month": "", "apps": {}, "system": {"d": [0, 0], "m": [0, 0]},
                                      "days": {}})
        self.data = self.store.data
        self.dirty = False
        self.roll()

    def roll(self):
        today = dt.date.today()
        d, m = today.isoformat(), today.strftime("%Y-%m")
        changed = []
        if self.data.get("day") != d:
            self.data["day"] = d
            for a in self.data["apps"].values():
                a["d"] = [0, 0]
            self.data["system"]["d"] = [0, 0]
            changed.append("day")
        if self.data.get("month") != m:
            self.data["month"] = m
            for a in self.data["apps"].values():
                a["m"] = [0, 0]
            self.data["system"]["m"] = [0, 0]
            changed.append("month")
        if changed:
            self.dirty = True
            days = self.data.setdefault("days", {})
            for k in sorted(days)[:-60]:
                days.pop(k, None)
        return changed

    def add_app(self, key, up, down):
        a = self.data["apps"].setdefault(key, {"d": [0, 0], "m": [0, 0]})
        a["d"][0] += up
        a["d"][1] += down
        a["m"][0] += up
        a["m"][1] += down
        self.dirty = True

    def add_system(self, up, down):
        s = self.data["system"]
        s["d"][0] += up
        s["d"][1] += down
        s["m"][0] += up
        s["m"][1] += down
        day = self.data.setdefault("days", {}).setdefault(self.data["day"], [0, 0])
        day[0] += up
        day[1] += down
        self.dirty = True

    def has(self, key):
        a = self.data["apps"].get(key)
        return bool(a and (a["d"][0] or a["d"][1]))

    def get_app(self, key):
        return self.data["apps"].get(key) or {"d": [0, 0], "m": [0, 0]}

    def amount(self, key, period, metric) -> int:
        src = self.data["system"] if key is None else self.get_app(key)
        up, down = src["d" if period == "day" else "m"]
        return {"up": up, "down": down}.get(metric, up + down)

    def reset(self, key=None):
        if key is None:
            for a in self.data["apps"].values():
                a["d"], a["m"] = [0, 0], [0, 0]
            self.data["system"] = {"d": [0, 0], "m": [0, 0]}
        else:
            self.data["apps"].pop(key, None)
        self.dirty = True

    def save(self):
        if self.dirty:
            self.store.save()
            self.dirty = False
