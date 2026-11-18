/* NetWarden UI — vanilla JS, no build step. Beginner + Pro modes over one JSON API. */
"use strict";

// ------------------------------------------------------------------ state
const qs = new URLSearchParams(location.search);
const TOKEN = qs.get("t") || sessionStorage.getItem("nw_token") || "";
if (qs.get("t")) { sessionStorage.setItem("nw_token", TOKEN); history.replaceState(null, "", "/"); }

const S = {
  mode: null, tab: "overview", data: null, shellKey: null,
  sort: { apps: ["rate", -1], conns: ["rate", -1], eps: ["rate", -1], rules: ["created_at", -1] },
  filter: { apps: "", conns: "", eps: "", dns: "", log: "", proto: "", cstate: "" },
  freeze: false, showIdle: false, pointerDown: false, failures: 0, lastOk: 0,
};
const $ = (sel, root = document) => root.querySelector(sel);

// ------------------------------------------------------------------ api
async function api(method, path, body) {
  const r = await fetch(path, {
    method, headers: { "X-Token": TOKEN, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let j = {};
  try { j = await r.json(); } catch (_) { /* empty */ }
  if (r.status === 409 && j.confirm) {
    // risky change (could cut the PC off): ask, then resend with force
    if (await confirmRisk(j.confirm)) return api(method, path, { ...(body || {}), force: true });
    const e = new Error("Cancelled — nothing was changed"); e.cancelled = true; throw e;
  }
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}
async function act(promise, okMsg, opts) {
  try { const r = await promise; if (okMsg) toast(okMsg, opts); poll(true); return r; }
  catch (e) { toast(e.message, { err: !e.cancelled }); poll(true); throw e; }
}
function confirmRisk(reasons) {
  return new Promise((resolve) => {
    const layer = document.createElement("div");
    layer.className = "modal-bg top";
    layer.innerHTML = `<div class="modal"><header><h2>⚠ This could break your internet</h2></header><div class="body">
      <ul class="risks">${reasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
      <p class="muted" style="font-size:12.5px">If something goes wrong, open NetWarden and undo it, or run “NetWarden emergency reset” from the Start menu (cleanup.bat).</p></div>
      <footer><button class="btn" data-x="no">Cancel</button><button class="btn danger" data-x="yes">Do it anyway</button></footer></div>`;
    document.body.appendChild(layer);
    layer.addEventListener("click", (e) => {
      const b = e.target.closest("[data-x]");
      if (!b) return;
      e.stopPropagation();
      layer.remove();
      resolve(b.dataset.x === "yes");
    });
    layer.querySelector('[data-x="no"]').focus();
  });
}

// ------------------------------------------------------------------ format
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function fmtB(n) {
  n = +n || 0;
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return i === 0 ? `${Math.round(n)} B` : `${n.toFixed(n < 10 ? 2 : n < 100 ? 1 : 0)} ${u[i]}`;
}
const fmtR = (n) => fmtB(n) + "/s";
const fmtKbps = (k) => (k >= 1000 ? `${+(k / 1000).toFixed(2)} Mbit/s` : `${+k} kbit/s`);
const pad = (n) => String(n).padStart(2, "0");
function clock(ts, sec) { const d = new Date(ts * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}${sec ? ":" + pad(d.getSeconds()) : ""}`; }
function when(ts) {
  const d = new Date(ts * 1000), n = new Date();
  const tom = new Date(n); tom.setDate(n.getDate() + 1);
  if (d.toDateString() === n.toDateString()) return clock(ts);
  if (d.toDateString() === tom.toDateString()) return "tomorrow " + clock(ts);
  return d.toLocaleDateString(undefined, { day: "numeric", month: "short" }) + " " + clock(ts);
}
function left(ts) {
  let s = Math.max(0, Math.round(ts - Date.now() / 1000));
  const h = Math.floor(s / 3600); s -= h * 3600; const m = Math.floor(s / 60); s -= m * 60;
  return h ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}
function ago(ts) {
  const s = Date.now() / 1000 - ts;
  if (s < 5) return "now"; if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`; return `${Math.round(s / 3600)}h ago`;
}
const PALETTE = ["#38bdf8", "#f5a524", "#34d399", "#a78bfa", "#f472b6", "#60a5fa", "#fb923c", "#4ade80", "#e879f9", "#facc15", "#2dd4bf", "#f87171"];
function color(s) { let h = 0; for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) >>> 0; return PALETTE[h % PALETTE.length]; }
function initials(name) { const w = String(name || "?").replace(/\.exe$/i, "").split(/[\s._-]+/).filter(Boolean); return ((w[0] || "?")[0] + (w[1] ? w[1][0] : "")).toUpperCase(); }
// App logo: the program's own icon (served by /api/icon); the coloured letters stay as the fallback
// for programs without an icon, Windows services and demo mode.
// Lists re-render every second, so remember which programs have an icon: known ones are drawn
// as a logo straight away (no letter flash), known misses go straight to the letters.
const NO_ICON = new Set(), HAS_ICON = new Set();
window.nwIconFail = (img) => { NO_ICON.add(img.dataset.p); const p = img.parentElement; img.remove(); if (p) p.classList.remove("has-logo"); };
window.nwIconOk = (img) => { HAS_ICON.add(img.dataset.p); if (img.parentElement) img.parentElement.classList.add("has-logo"); };
function avatar(a, cls = "avatar") {
  const exe = a.exe || a.path || a.app || "";
  const k = lc(exe);
  const letters = `<span>${esc(initials(a.friendly || a.name))}</span>`;
  const useIcon = exe && /^[a-z]:[\\/]/i.test(exe) && !NO_ICON.has(k) && !S.data?.sim;
  const img = useIcon ? `<img alt="" draggable="false" data-p="${esc(k)}" src="/api/icon?t=${encodeURIComponent(TOKEN)}&p=${encodeURIComponent(exe)}" onload="nwIconOk(this)" onerror="nwIconFail(this)">` : "";
  return `<div class="${cls}${useIcon && HAS_ICON.has(k) ? " has-logo" : ""}" style="--av:${color(a.name || a.friendly)}">${letters}${img}</div>`;
}
const lc = (s) => String(s || "").toLowerCase();

function spark(hist, w = 90, h = 24) {
  if (!hist || hist.length < 2) return `<svg class="spark" width="${w}" height="${h}"></svg>`;
  const max = Math.max(1, ...hist.map((p) => Math.max(p[0], p[1])));
  const pts = (i) => hist.map((p, k) => `${(k / (hist.length - 1)) * w},${h - 1 - (p[i] / max) * (h - 3)}`).join(" ");
  return `<svg class="spark" width="${w}" height="${h}"><polyline fill="none" stroke="var(--down)" stroke-width="1.4" points="${pts(0)}"/><polyline fill="none" stroke="var(--up)" stroke-width="1.2" opacity=".85" points="${pts(1)}"/></svg>`;
}

// ------------------------------------------------------------------ chart
function drawChart(canvas, hist) {
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w) return;
  if (canvas.width !== w * dpr) { canvas.width = w * dpr; canvas.height = h * dpr; }
  const g = canvas.getContext("2d");
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  g.clearRect(0, 0, w, h);
  const cs = getComputedStyle(document.body);
  const cv = (n, d) => (cs.getPropertyValue(n) || "").trim() || d;
  const C = { grid: cv("--chart-grid", "#1f2b38"), text: cv("--chart-text", "#5c6b7c"), down: cv("--chart-down", "#38bdf8"),
              up: cv("--chart-up", "#f5a524"), fill: cv("--chart-fill", "rgba(56,189,248,.35)") };
  const pts = hist || [];
  const max = Math.max(1024, ...pts.map((p) => Math.max(p[1], p[2]))) * 1.15;
  const top = 16, bot = h - 4;
  g.strokeStyle = C.grid; g.lineWidth = 1;
  for (let i = 0; i <= 3; i++) { const y = top + ((bot - top) * i) / 3; g.beginPath(); g.moveTo(0, y + 0.5); g.lineTo(w, y + 0.5); g.stroke(); }
  g.fillStyle = C.text; g.font = "11px 'Lucida Console', Consolas, monospace"; g.fillText(fmtR(max / 1.15), 4, 11);
  if (pts.length < 2) return;
  const X = (i) => (i / (pts.length - 1)) * w, Y = (v) => bot - (v / max) * (bot - top);
  const grad = g.createLinearGradient(0, top, 0, bot);
  grad.addColorStop(0, C.fill); grad.addColorStop(1, "rgba(0,0,0,0)");
  g.beginPath(); g.moveTo(0, bot); pts.forEach((p, i) => g.lineTo(X(i), Y(p[1]))); g.lineTo(w, bot); g.closePath();
  g.fillStyle = grad; g.fill();
  g.beginPath(); pts.forEach((p, i) => (i ? g.lineTo(X(i), Y(p[1])) : g.moveTo(0, Y(p[1])))); g.strokeStyle = C.down; g.lineWidth = 1.8; g.stroke();
  g.beginPath(); pts.forEach((p, i) => (i ? g.lineTo(X(i), Y(p[2])) : g.moveTo(0, Y(p[2])))); g.strokeStyle = C.up; g.lineWidth = 1.5; g.stroke();
}

// ------------------------------------------------------------------ rule helpers
const isPlainAppRule = (r) => r.app && !(r.remote || []).length && !r.ports && (r.protocol || "any") === "any";
function appRules(key) {
  const out = { block: null, pause: null, throttle: null, cap: null, custom: 0 };
  for (const r of S.data?.rules || []) {
    if (lc(r.app) !== key || !r.app) continue;
    if (!isPlainAppRule(r)) { out.custom++; continue; }
    if (r.type === "block") { if (r.expires_at) out.pause = r; else out.block = r; }
    else if (r.type === "throttle") out.throttle = r;
    else if (r.type === "cap") out.cap = r;
  }
  return out;
}
function appName(r) {
  const a = (S.data?.apps || []).find((x) => lc(x.exe) === lc(r.app));
  return a ? a.friendly : r.app_name || r.app || "All apps";
}
function plainRule(r) {
  const who = r.app ? appName(r) : "All apps";
  const st = r.status || {};
  if (r.pause_all) return { icon: "pause", ic: "⏸", t: "Internet is paused", d: r.expires_at ? `Comes back at ${when(r.expires_at)}` : "Until you resume it" };
  if (r.type === "block" && isPlainAppRule(r))
    return r.expires_at ? { icon: "pause", ic: "⏸", t: `${who} is paused`, d: `Allowed again at ${when(r.expires_at)}` }
      : { icon: "block", ic: "⛔", t: `${who} is blocked`, d: r.schedule ? st.detail || "On a schedule" : "Can't use the internet" };
  if (r.type === "throttle") return { icon: "throttle", ic: "⇣", t: `${who}: upload limited to ${fmtKbps(r.rate_kbps)}`, d: st.detail || "Slows down what it sends" };
  if (r.type === "cap") {
    const c = r.cap;
    return { icon: "cap", ic: "◔", t: `${who}: ${c.mb >= 1024 ? +(c.mb / 1024).toFixed(1) + " GB" : c.mb + " MB"} per ${c.period}`, d: st.detail || "" };
  }
  return { icon: "block", ic: "⛔", t: r.name, d: st.detail || "" };
}

// ------------------------------------------------------------------ modal / toast
function modal(html, { wide, onMount } = {}) {
  const root = $("#modal-root");
  root.innerHTML = `<div class="modal-bg"><div class="modal ${wide ? "wide" : ""}">${html}</div></div>`;
  const bg = root.firstElementChild;
  bg.addEventListener("mousedown", (e) => { if (e.target === bg) closeModal(); });
  if (onMount) onMount(bg.firstElementChild);
  return bg.firstElementChild;
}
function closeModal() { $("#modal-root").innerHTML = ""; }
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
function toast(msg, { err, undo } = {}) {
  const el = document.createElement("div");
  el.className = "toast" + (err ? " err" : "");
  el.innerHTML = `${esc(msg)}${undo ? ' <button class="btn sm ghost">Undo</button>' : ""}`;
  if (undo) el.querySelector("button").onclick = () => { undo(); el.remove(); };
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), undo ? 7000 : 4200);
}

// ------------------------------------------------------------------ actions
const H = {}; // data-act handlers
document.addEventListener("pointerdown", () => (S.pointerDown = true), true);
document.addEventListener("pointerup", () => setTimeout(() => (S.pointerDown = false), 60), true);
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-act]");
  if (!el || el.tagName === "INPUT") return;
  const fn = H[el.dataset.act];
  if (fn) { e.preventDefault(); fn(el.dataset, el); }
});
const appByKey = (k) => (S.data?.apps || []).find((a) => a.key === k);

const THEMES = { classic: "Classic 2000", "classic-dark": "Classic 2000 dark", modern: "Modern dark" };
const THEME_ORDER = ["classic", "classic-dark", "modern"];
function applyTheme(t) {
  t = THEMES[t] ? t : "classic";
  S.theme = t;
  document.body.classList.toggle("theme-classic", t === "classic" || t === "classic-dark");
  document.body.classList.toggle("classic-dark", t === "classic-dark");
  document.body.classList.toggle("theme-modern", t === "modern");
  const b = $("#theme-btn"); if (b) b.textContent = "Theme: " + THEMES[t];
  try { localStorage.setItem("nw_theme", t); } catch (_) { /* ignore */ }
  const c = $("#chart"); if (c && S.data) drawChart(c, S.data.history);
}
try { applyTheme(localStorage.getItem("nw_theme") || "classic"); } catch (_) { applyTheme("classic"); }
H.theme = () => {
  const next = THEME_ORDER[(THEME_ORDER.indexOf(S.theme) + 1) % THEME_ORDER.length];
  applyTheme(next);
  S.themeLocked = Date.now();
  api("POST", "/api/settings", { theme: next }).catch(() => {});
};
H.updCheck = async () => {
  try {
    const r = await api("POST", "/api/update/check");
    toast(r.error ? "Update check: " + r.error : r.available ? `Version ${r.latest} is available` : `You have the latest version (${r.current})`, { err: !!r.error });
  } catch (e) { toast(e.message, { err: true }); }
  poll(true);
};
H.updInstall = () => { S.updDismissed = false; act(api("POST", "/api/update/install"), "Downloading the update… NetWarden restarts by itself."); };
H.updDismiss = () => { S.updDismissed = true; renderHeader(); };
H.mode = (d) => { S.mode = d.mode; api("POST", "/api/settings", { ui_mode: d.mode }).catch(() => {}); render(); };
H.tab = (d) => { S.tab = d.tab; render(); };
H.pauseAll = (d) => act(api("POST", "/api/pause", { minutes: d.min ? +d.min : null }),
  d.min ? `Internet paused for ${d.min >= 60 ? d.min / 60 + " h" : d.min + " min"}` : "Internet paused until you resume it");
H.resumeAll = () => act(api("POST", "/api/resume"), "Internet is back on");
H.pauseMenu = () => {
  modal(`<header><h2>Pause the internet</h2></header><div class="body"><p class="muted">Everything on this PC goes offline. It comes back on automatically when the time is up.</p>
    <div class="choice-grid">${[[5, "5 minutes"], [15, "15 minutes"], [30, "30 minutes"], [60, "1 hour"], [180, "3 hours"], [0, "Until I resume"]]
      .map(([m, l]) => `<button class="choice" data-act="pauseAllClose" data-min="${m}">${l}</button>`).join("")}</div></div>
    <footer><button class="btn" data-act="close">Cancel</button></footer>`);
};
H.pauseAllClose = (d) => { closeModal(); H.pauseAll(d.min === "0" ? {} : d); };
H.close = () => closeModal();

H.blockApp = async (d) => {
  const a = appByKey(d.key); if (!a) return;
  if (!a.exe) return toast("Windows doesn't expose this program's path, so it can't be blocked by app.", { err: true });
  const r = await act(api("POST", "/api/rules", { type: "block", app: a.exe, app_name: a.friendly, direction: "both", name: `Block ${a.friendly}` }));
  toast(`${a.friendly} is blocked`, { undo: () => act(api("DELETE", `/api/rules/${r.id}`), `${a.friendly} allowed again`) });
};
H.allowApp = (d) => { const a = appByKey(d.key); act(api("POST", "/api/allow_app", { app: d.exe || a?.exe }), `${a ? a.friendly : "App"} can use the internet again`); };
H.pauseApp = (d) => {
  const a = appByKey(d.key); if (!a) return;
  if (!a.exe) return toast("This program can't be paused by app (no path).", { err: true });
  const tomorrow7 = new Date(); tomorrow7.setDate(tomorrow7.getDate() + 1); tomorrow7.setHours(7, 0, 0, 0);
  const opts = [[15, "15 minutes"], [30, "30 minutes"], [60, "1 hour"], [180, "3 hours"], [-1, "Until 7:00 tomorrow"]];
  modal(`<header>${avatar(a)}<h2>Pause ${esc(a.friendly)}</h2></header><div class="body">
    <p class="muted">${esc(a.friendly)} won't be able to use the internet, then it's allowed again automatically.</p>
    <div class="choice-grid">${opts.map(([m, l]) => `<button class="choice" data-min="${m}">${l}</button>`).join("")}</div>
    <div class="field"><label>Or a custom time (minutes)</label><div style="display:flex;gap:8px"><input class="input num" id="pm-custom" type="number" min="1" placeholder="e.g. 45" style="width:120px"><button class="btn" id="pm-go">Pause</button></div></div>
    </div><footer><button class="btn" data-act="close">Cancel</button></footer>`, {
    onMount(m) {
      const go = async (min) => {
        const exp = min === -1 ? tomorrow7.getTime() / 1000 : Date.now() / 1000 + min * 60;
        closeModal();
        await act(api("POST", "/api/rules", { type: "block", app: a.exe, app_name: a.friendly, direction: "both", expires_at: exp, name: `Pause ${a.friendly}` }),
          `${a.friendly} paused until ${when(exp)}`);
      };
      m.querySelectorAll(".choice").forEach((b) => (b.onclick = () => go(+b.dataset.min)));
      m.querySelector("#pm-go").onclick = () => { const v = +m.querySelector("#pm-custom").value; if (v > 0) go(v); };
    },
  });
};
H.limitApp = (d) => {
  const a = appByKey(d.key); if (!a) return;
  if (!a.exe) return toast("This program can't be limited by app (no path).", { err: true });
  const ex = appRules(a.key);
  const speeds = [[0, "No limit"], [256, "256 kbit/s"], [1000, "1 Mbit/s"], [5000, "5 Mbit/s"], [20000, "20 Mbit/s"]];
  const caps = [[0, "No limit"], [100, "100 MB"], [500, "500 MB"], [1024, "1 GB"], [5120, "5 GB"], [20480, "20 GB"]];
  let speed = ex.throttle ? ex.throttle.rate_kbps : 0;
  let cap = ex.cap ? ex.cap.cap.mb : 0;
  let action = ex.cap ? ex.cap.cap.action : "block";
  const grid = (list, cur, name) => list.map(([v, l]) => `<button class="choice ${v === cur ? "on" : ""}" data-g="${name}" data-v="${v}">${l}</button>`).join("");
  modal(`<header>${avatar(a)}<h2>Limit ${esc(a.friendly)}</h2></header><div class="body">
    <div class="field"><label>Upload speed — how fast it can send data</label><div class="choice-grid" id="g-speed">${grid(speeds, speed, "speed")}</div>
      <div class="hint">Windows can only slow down sending (upload). To control downloads, use a daily data limit.</div></div>
    <div class="field"><label>Daily data — how much it can use per day (download + upload)</label><div class="choice-grid" id="g-cap">${grid(caps, cap, "cap")}</div>
      <div class="hint">Used today: ${fmtB(a.today_down + a.today_up)}</div></div>
    <div class="field" id="f-action"><label>When the daily limit is reached</label><div class="choice-grid">${grid([["block", "Block until tomorrow"], ["throttle", "Slow it right down"], ["alert", "Just tell me"]], action, "action")}</div></div>
    </div><footer><button class="btn" data-act="close">Cancel</button><button class="btn primary" id="lim-save">Save limits</button></footer>`, {
    onMount(m) {
      m.querySelectorAll(".choice").forEach((b) => (b.onclick = () => {
        const g = b.dataset.g;
        m.querySelectorAll(`.choice[data-g="${g}"]`).forEach((x) => x.classList.toggle("on", x === b));
        if (g === "speed") speed = +b.dataset.v; else if (g === "cap") cap = +b.dataset.v; else action = b.dataset.v;
      }));
      m.querySelector("#lim-save").onclick = async () => {
        try {
          if (ex.throttle) await api("DELETE", `/api/rules/${ex.throttle.id}`);
          if (ex.cap) await api("DELETE", `/api/rules/${ex.cap.id}`);
          if (speed) await api("POST", "/api/rules", { type: "throttle", app: a.exe, app_name: a.friendly, rate_kbps: speed });
          if (cap) await api("POST", "/api/rules", { type: "cap", app: a.exe, app_name: a.friendly, cap: { mb: cap, period: "day", metric: "total", action, throttle_kbps: 128 } });
          closeModal(); toast(speed || cap ? `Limits saved for ${a.friendly}` : `Limits removed for ${a.friendly}`); poll(true);
        } catch (e) { toast(e.message, { err: true }); }
      };
    },
  });
};
H.delRule = (d) => {
  const r = (S.data?.rules || []).find((x) => x.id === d.id);
  act(api("DELETE", `/api/rules/${d.id}`), r ? (r.pause_all ? "Internet is back on" : `Removed: ${r.name}`) : "Removed");
};
H.toggleRule = (d, el) => act(api("PATCH", `/api/rules/${d.id}`, { enabled: el.checked !== undefined ? el.checked : d.on !== "1" }));
H.showIdle = () => { S.showIdle = !S.showIdle; render(); };
H.kill = (d) => act(api("POST", "/api/kill", { lip: d.lip, lport: +d.lport, rip: d.rip, rport: +d.rport }), `Closed connection to ${d.rip}:${d.rport}`);
H.blockIp = (d) => blockTarget(d.ip, d.exe, d.name);
H.blockHost = (d) => blockTarget(d.host, d.exe, d.name);
function blockTarget(target, exe, name) {
  const isDomain = /[a-z]/i.test(target) && !target.includes(":");
  let scope = exe ? "app" : "all", dur = 60;
  modal(`<header><h2>Block ${esc(target)}</h2></header><div class="body">
    ${isDomain ? `<p class="muted" style="font-size:12.5px">A domain is blocked by its IP addresses. Big services share servers (CDNs), so blocking it for all apps can also block other sites. Blocking only for one app, or only for a while, is safer.</p>` : ""}
    <div class="field"><label>For</label><div class="choice-grid">
      ${exe ? `<button class="choice ${scope === "app" ? "on" : ""}" data-g="scope" data-v="app">Only ${esc(name || "this app")}</button>` : ""}
      <button class="choice ${scope === "all" ? "on" : ""}" data-g="scope" data-v="all">All apps</button></div></div>
    <div class="field"><label>How long</label><div class="choice-grid">
      ${[[60, "1 hour"], [1440, "1 day"], [10080, "1 week"], [0, "Always"]].map(([v, l]) => `<button class="choice ${v === dur ? "on" : ""}" data-g="dur" data-v="${v}">${l}</button>`).join("")}</div>
      <div class="hint">Timed blocks end by themselves — even if NetWarden is closed.</div></div>
    </div><footer><button class="btn" data-act="close">Cancel</button><button class="btn danger" id="bt-go">Block</button></footer>`, {
    onMount(m) {
      m.querySelectorAll(".choice").forEach((b) => (b.onclick = () => {
        m.querySelectorAll(`.choice[data-g="${b.dataset.g}"]`).forEach((x) => x.classList.toggle("on", x === b));
        if (b.dataset.g === "scope") scope = b.dataset.v; else dur = +b.dataset.v;
      }));
      m.querySelector("#bt-go").onclick = () => {
        closeModal();
        const body = { type: "block", remote: target, direction: "both", expires_at: dur ? Date.now() / 1000 + dur * 60 : null };
        if (scope === "app" && exe) { body.app = exe; body.app_name = name; }
        act(api("POST", "/api/rules", body), `Blocked ${target}${scope === "app" ? " for " + (name || "the app") : ""}${dur ? " for " + (dur >= 1440 ? dur / 1440 + " day(s)" : "1 hour") : ""}`).catch(() => {});
      };
    },
  });
}
H.newRule = (d) => ruleEditor(d.prefill ? JSON.parse(d.prefill) : {});
H.editRule = (d) => ruleEditor((S.data?.rules || []).find((x) => x.id === d.id) || {});
H.appDetail = (d) => appDetail(d.key);
H.sort = (d) => { const cur = S.sort[d.table]; S.sort[d.table] = cur[0] === d.key ? [d.key, -cur[1]] : [d.key, -1]; render(true); };
H.setting = (d, el) => act(api("POST", "/api/settings", { [d.key]: el.checked }), "Saved");
H.cleanup = () => {
  modal(`<header><h2>Remove all rules?</h2></header><div class="body"><p class="muted">Deletes every NetWarden block, pause, limit and data cap, and removes them from Windows Firewall and QoS. Everything is allowed again.</p></div>
  <footer><button class="btn" data-act="close">Cancel</button><button class="btn danger" data-act="cleanupYes">Remove everything</button></footer>`);
};
H.cleanupYes = () => { closeModal(); act(api("POST", "/api/cleanup"), "All rules removed"); };
H.resetUsage = () => act(api("POST", "/api/usage/reset", {}), "Usage counters reset");
H.quit = () => {
  modal(`<header><h2>Quit NetWarden?</h2></header><div class="body"><p class="muted">Monitoring stops${S.data?.settings?.keep_rules_on_exit ? "; your firewall blocks stay in place." : " and all NetWarden blocks and limits are lifted until you start it again."}</p></div>
  <footer><button class="btn" data-act="close">Cancel</button><button class="btn danger" data-act="quitYes">Quit</button></footer>`);
};
H.quitYes = async () => { closeModal(); try { await api("POST", "/api/quit"); } catch (_) {} document.body.innerHTML = '<div class="empty" style="margin-top:20vh"><h2>NetWarden has stopped.</h2><p>You can close this window.</p></div>'; S.stopped = true; };

// ------------------------------------------------------------------ block-all mode (lockdown)
const LD = () => S.data?.lockdown || { mode: "off", pending: [], groups: [], decisions: [], attempts: [], warnings: [] };
const LMODES = {
  off: { t: "Normal", d: "Apps connect freely. Your blocks, pauses and limits still apply." },
  ask: { t: "Block all — ask me", d: "Everything is blocked until you allow it. When an app tries to connect, NetWarden asks you." },
  allowlist: { t: "Only allowed apps", d: "Everything is blocked except the apps in your allowed groups. No questions asked." },
};
const PERM = {
  allowed: ["ok", "Allowed"], blocked: ["blocked", "Not allowed"], pending: ["paused", "Asking you"],
  denied: ["blocked", "Blocked by you"], partial: ["cap", "Some addresses allowed"],
};
function knownApps() {
  const m = new Map();
  for (const a of S.data?.apps || []) if (a.exe) m.set(lc(a.exe), { exe: a.exe, name: a.friendly });
  for (const a of LD().attempts || []) if (a.app && !m.has(lc(a.app))) m.set(lc(a.app), { exe: a.app, name: a.app_name });
  for (const p of LD().pending || []) if (!m.has(lc(p.app))) m.set(lc(p.app), { exe: p.app, name: p.app_name });
  return [...m.values()].sort((a, b) => lc(a.name).localeCompare(lc(b.name)));
}
H.lmode = (d) => {
  const m = d.mode;
  if (m === LD().mode) return;
  if (m === "off") return act(api("POST", "/api/lockdown/mode", { mode: m }), "Normal mode: apps can connect again");
  const allowed = LD().groups.filter((g) => g.enabled && g.id !== "essentials").flatMap((g) => g.apps);
  const inGroups = new Set(allowed.map((a) => lc(a.path)));
  const carry = LD().decisions.filter((x) => x.scope === "app" && x.action === "allow" && !inGroups.has(lc(x.app)));
  modal(`<header><h2>${esc(LMODES[m].t)}?</h2></header><div class="body">
    <p>${esc(LMODES[m].d)}</p>
    ${m === "ask" ? `<p class="muted">A small window pops up near the clock each time an app wants to connect${S.mode === "pro" ? " to a new address (Pro mode asks per address)" : ""}. Until you answer, the app stays offline. Apps usually retry by themselves; a browser page may need a refresh after you allow it.</p>`
      : `<p class="muted">Allowed right now: <b>${allowed.length ? esc(allowed.map((a) => a.name).join(", ")) : "no apps yet"}</b> + Windows essentials. ${allowed.length || carry.length ? "" : "Add your apps first (browser, chat…) or almost nothing will work."}</p>
         ${carry.length ? `<label style="display:flex;gap:8px;align-items:flex-start;margin:10px 0"><input type="checkbox" id="lm-carry" checked> <span>Also allow the apps you said yes to earlier: <b>${esc(carry.map((x) => x.app_name).join(", "))}</b> (adds them to “My allowed apps”)</span></label>` : ""}`}
    <p class="muted" style="font-size:12.5px">Windows' own core networking (DNS, DHCP, updates) stays allowed through the “Windows essentials” group. Block-all stays active even when NetWarden is closed; switch back to Normal to undo it.</p>
  </div><footer><button class="btn" data-act="close">Cancel</button>${m === "allowlist" ? '<button class="btn" data-act="addAllowedClose">Choose allowed apps…</button>' : ""}<button class="btn primary" data-act="lmodeYes" data-mode="${m}">Turn on</button></footer>`);
};
H.lmodeYes = async (d) => {
  const carry = $("#lm-carry")?.checked;
  closeModal();
  if (carry) {
    const have = new Set(LD().groups.filter((g) => g.enabled).flatMap((g) => g.apps.map((a) => lc(a.path))));
    for (const x of LD().decisions) if (x.scope === "app" && x.action === "allow" && !have.has(lc(x.app)))
      await api("PATCH", "/api/lockdown/group/allowed", { add_app: x.app, app_name: x.app_name }).catch(() => {});
  }
  act(api("POST", "/api/lockdown/mode", { mode: d.mode }), `${LMODES[d.mode].t} is on`);
};
H.addAllowedClose = () => { closeModal(); H.addAllowed(); };
H.reqApp = (d) => act(api("POST", "/api/lockdown/answer_app", { app: d.app, app_name: d.name, action: d.action }),
  d.action === "allow" ? `${d.name} can connect now` : `${d.name} stays blocked`);
H.reqAnswer = (d) => act(api("POST", "/api/lockdown/answer", { id: d.id, action: d.action, scope: d.scope }),
  `${d.action === "allow" ? "Allowed" : "Blocked"} (${d.scope === "app" ? "whole app" : d.scope})`);
H.reqLater = (d) => act(api("POST", "/api/lockdown/snooze", { id: d.id }), "Asked again in 10 minutes if it keeps trying");
H.allowLD = (d) => {
  if (LD().mode === "allowlist") return act(api("PATCH", "/api/lockdown/group/allowed", { add_app: d.exe, app_name: d.name }), `${d.name} added to your allowed apps`);
  return act(api("POST", "/api/lockdown/decision", { app: d.exe, app_name: d.name, scope: "app", action: "allow" }), `${d.name} can connect now`);
};
H.decDel = (d) => act(api("DELETE", `/api/lockdown/decision/${d.id}`), "Removed");
H.grpRemoveApp = (d) => act(api("PATCH", `/api/lockdown/group/${d.gid}`, { remove_app: d.exe }), "Removed from group");
H.grpAddApp = (d) => {
  const el = document.getElementById("ga-" + d.gid); const v = (el?.value || "").trim(); if (!v) return;
  const k = knownApps().find((a) => lc(a.exe) === lc(v) || lc(a.name) === lc(v));
  act(api("PATCH", `/api/lockdown/group/${d.gid}`, { add_app: k ? k.exe : v, app_name: k ? k.name : null }), "Added").then(() => { if (el) el.value = ""; });
};
H.grpNew = () => { const el = $("#g-new"); const v = (el?.value || "").trim(); if (v) act(api("POST", "/api/lockdown/group", { name: v }), `Group “${v}” created`).then(() => (el.value = "")); };
H.grpDel = (d) => act(api("DELETE", `/api/lockdown/group/${d.gid}`), "Group deleted");
H.fwOn = () => act(api("POST", "/api/lockdown/firewall_on", {}), "Windows Firewall turned on");
H.addAllowed = () => {
  const g = LD().groups.find((x) => x.id === "allowed") || { apps: [] };
  const inGroup = new Set(g.apps.map((a) => lc(a.path)));
  const apps = knownApps();
  modal(`<header><h2>Choose your allowed apps</h2></header><div class="body">
    <p class="muted">Ticked apps can always connect, in every block-all mode.</p>
    <div style="display:grid;gap:4px;max-height:50vh;overflow:auto">${apps.map((a) => `<label style="display:flex;gap:10px;align-items:center;padding:6px 8px;border-radius:8px;background:var(--panel-2)">
      <input type="checkbox" value="${esc(a.exe)}" data-name="${esc(a.name)}" ${inGroup.has(lc(a.exe)) ? "checked" : ""}>${avatar({ name: a.name, friendly: a.name, exe: a.exe }, "mini-av")}<span><b>${esc(a.name)}</b><div class="faint num" style="font-size:11px">${esc(a.exe)}</div></span></label>`).join("") || '<div class="empty">No apps seen yet.</div>'}</div>
    <div class="field" style="margin-top:12px"><label>Or add a program by its full path</label><input class="input num" id="aa-path" placeholder="C:\\Program Files\\App\\app.exe"></div>
  </div><footer><button class="btn" data-act="close">Cancel</button><button class="btn primary" id="aa-save">Save</button></footer>`, {
    onMount(m) {
      m.querySelector("#aa-save").onclick = async () => {
        try {
          for (const cb of m.querySelectorAll("input[type=checkbox]")) {
            const was = inGroup.has(lc(cb.value));
            if (cb.checked && !was) await api("PATCH", "/api/lockdown/group/allowed", { add_app: cb.value, app_name: cb.dataset.name });
            if (!cb.checked && was) await api("PATCH", "/api/lockdown/group/allowed", { remove_app: cb.value });
          }
          const pth = m.querySelector("#aa-path").value.trim();
          if (pth) await api("PATCH", "/api/lockdown/group/allowed", { add_app: pth });
          closeModal(); toast("Allowed apps saved"); poll(true);
        } catch (e) { toast(e.message, { err: true }); }
      };
    },
  });
};
function permChip(perm) { if (!perm || !PERM[perm]) return ""; const [c, t] = PERM[perm]; return `<span class="chip ${c === "ok" ? "okc" : c}">${t}</span>`; }
function modeCards(compact) {
  const cur = LD().mode;
  return `<div class="modes ${compact ? "compact" : ""}">${Object.entries(LMODES).map(([k, v]) => `<button class="modecard ${k === cur ? "on" : ""} m-${k}" data-act="lmode" data-mode="${k}">
    <div class="mc-t"><span class="radio"></span>${esc(v.t)}</div><div class="mc-d">${esc(v.d)}</div></button>`).join("")}</div>`;
}

// ------------------------------------------------------------------ rule editor (pro)
function toLocalInput(ts) { const d = new Date(ts * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`; }
function ruleEditor(r) {
  const editing = !!r.id;
  const apps = S.data?.apps || [];
  const type = r.type || "block";
  const cap = r.cap || { mb: 500, period: "day", metric: "total", action: "block", throttle_kbps: 256 };
  const sch = r.schedule || { days: [0, 1, 2, 3, 4], start: "22:00", end: "07:00" };
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  modal(`<header><h2>${editing ? "Edit rule" : "New rule"}</h2></header><div class="body">
    <div class="seg" id="re-type" style="margin-bottom:14px">${[["block", "Block"], ["throttle", "Limit upload speed"], ["cap", "Data limit"]]
      .map(([v, l]) => `<button type="button" data-v="${v}" class="${v === type ? "on" : ""}">${l}</button>`).join("")}</div>
    <div class="field"><label>Name <span class="faint">(optional)</span></label><input class="input" id="re-name" value="${esc(r.name && editing ? r.name : "")}" placeholder="Generated automatically"></div>
    <fieldset><legend>What traffic</legend>
      <div class="field"><label>Application</label><input class="input" id="re-app" list="re-apps" value="${esc(r.app || "")}" placeholder="All applications — or pick / paste a full .exe path">
        <datalist id="re-apps">${apps.filter((a) => a.exe).map((a) => `<option value="${esc(a.exe)}">${esc(a.friendly)}</option>`).join("")}</datalist></div>
      <div class="field"><label>Remote addresses / domains</label><textarea class="input" id="re-remote" placeholder="Empty = anywhere.  Examples: 1.2.3.4  10.0.0.0/8  5.6.7.1-5.6.7.9  ads.example.com  *.tracker.net">${esc((r.remote || []).join("\n"))}</textarea>
        <div class="hint">Domains are resolved to IP addresses (and kept up to date from DNS traffic). *.domain also covers subdomains seen on this PC.</div></div>
      <div class="row3">
        <div class="field"><label>Protocol</label><select class="input" id="re-proto">${["any", "tcp", "udp"].map((p) => `<option ${p === (r.protocol || "any") ? "selected" : ""}>${p}</option>`).join("")}</select></div>
        <div class="field"><label>Remote ports</label><input class="input num" id="re-ports" value="${esc(r.ports || "")}" placeholder="e.g. 443 or 80,8000-8100"></div>
        <div class="field t-block"><label>Direction</label><select class="input" id="re-dir">${[["both", "In + out"], ["out", "Outgoing only"], ["in", "Incoming only"]].map(([v, l]) => `<option value="${v}" ${v === (r.direction || "both") ? "selected" : ""}>${l}</option>`).join("")}</select></div>
      </div>
    </fieldset>
    <fieldset class="t-throttle"><legend>Speed limit (upload)</legend>
      <div class="row2"><div class="field"><label>Max upload speed (kbit/s)</label><input class="input num" id="re-rate" type="number" min="8" value="${r.rate_kbps || 1000}"></div>
      <div class="field"><label>&nbsp;</label><div class="hint" style="padding-top:8px">1000 kbit/s = 1 Mbit/s ≈ 125 KB/s. Uses Windows QoS, which shapes outgoing traffic only.</div></div></div>
    </fieldset>
    <fieldset class="t-cap"><legend>Data limit</legend>
      <div class="row3"><div class="field"><label>Amount (MB)</label><input class="input num" id="re-mb" type="number" min="1" value="${cap.mb}"></div>
        <div class="field"><label>Per</label><select class="input" id="re-period">${["day", "month"].map((p) => `<option ${p === cap.period ? "selected" : ""}>${p}</option>`).join("")}</select></div>
        <div class="field"><label>Count</label><select class="input" id="re-metric">${[["total", "Down + up"], ["down", "Download"], ["up", "Upload"]].map(([v, l]) => `<option value="${v}" ${v === cap.metric ? "selected" : ""}>${l}</option>`).join("")}</select></div></div>
      <div class="row2"><div class="field"><label>When reached</label><select class="input" id="re-action">${[["block", "Block"], ["throttle", "Throttle upload"], ["alert", "Alert only"]].map(([v, l]) => `<option value="${v}" ${v === cap.action ? "selected" : ""}>${l}</option>`).join("")}</select></div>
        <div class="field"><label>Throttle to (kbit/s)</label><input class="input num" id="re-capkbps" type="number" min="8" value="${cap.throttle_kbps || 256}"></div></div>
      <div class="hint" style="margin-bottom:10px">Data limits use the scope above: app + remote/protocol filters choose what gets blocked or throttled; usage is counted for the whole app.</div>
    </fieldset>
    <fieldset><legend>When</legend>
      <div class="row2">
        <div class="field"><label>Start</label><input class="input" id="re-start" type="datetime-local" value="${r.starts_at ? toLocalInput(r.starts_at) : ""}"><div class="hint">Empty = now</div></div>
        <div class="field"><label>Allow again (rule ends)</label><input class="input" id="re-end" type="datetime-local" value="${r.expires_at ? toLocalInput(r.expires_at) : ""}">
          <div style="display:flex;gap:4px;margin-top:4px">${[[15, "+15m"], [60, "+1h"], [240, "+4h"], [1440, "+1d"]].map(([m, l]) => `<button type="button" class="btn sm ghost" data-plus="${m}">${l}</button>`).join("")}<button type="button" class="btn sm ghost" data-plus="0">Never</button></div></div>
      </div>
      <label style="display:flex;gap:8px;align-items:center;margin:4px 0 10px"><input type="checkbox" id="re-sch" ${r.schedule ? "checked" : ""}> Only active on a weekly schedule</label>
      <div id="re-schbox" class="row2" style="${r.schedule ? "" : "display:none"}">
        <div class="field"><label>Days</label><div class="days">${days.map((n, i) => `<label><input type="checkbox" value="${i}" ${sch.days.includes(i) ? "checked" : ""}><span>${n}</span></label>`).join("")}</div></div>
        <div class="row2"><div class="field"><label>From</label><input class="input num" id="re-from" type="time" value="${sch.start}"></div><div class="field"><label>To</label><input class="input num" id="re-to" type="time" value="${sch.end}"></div></div>
      </div>
    </fieldset>
    <div class="formerr" id="re-err"></div>
    </div><footer>${editing ? `<button class="btn danger" data-act="delRuleClose" data-id="${r.id}" style="margin-right:auto">Delete</button>` : ""}
      <button class="btn" data-act="close">Cancel</button><button class="btn primary" id="re-save">${editing ? "Save" : "Create rule"}</button></footer>`, {
    wide: true,
    onMount(m) {
      let t = type;
      const sync = () => {
        m.querySelectorAll("#re-type button").forEach((b) => b.classList.toggle("on", b.dataset.v === t));
        m.querySelectorAll(".t-block").forEach((e) => (e.style.display = t === "block" ? "" : "none"));
        m.querySelector(".t-throttle").style.display = t === "throttle" ? "" : "none";
        m.querySelector(".t-cap").style.display = t === "cap" ? "" : "none";
      };
      sync();
      m.querySelectorAll("#re-type button").forEach((b) => (b.onclick = () => { t = b.dataset.v; sync(); }));
      m.querySelector("#re-sch").onchange = (e) => (m.querySelector("#re-schbox").style.display = e.target.checked ? "" : "none");
      m.querySelectorAll("[data-plus]").forEach((b) => (b.onclick = () => {
        const mins = +b.dataset.plus;
        m.querySelector("#re-end").value = mins ? toLocalInput(Date.now() / 1000 + mins * 60) : "";
      }));
      m.querySelector("#re-save").onclick = async () => {
        const v = (id) => m.querySelector(id).value.trim();
        const dt = (id) => (v(id) ? new Date(v(id)).getTime() / 1000 : null);
        const appExe = v("#re-app");
        const known = apps.find((a) => lc(a.exe) === lc(appExe));
        const body = {
          type: t, name: v("#re-name"), app: appExe || null, app_name: known ? known.friendly : null,
          remote: v("#re-remote"), protocol: v("#re-proto"), ports: v("#re-ports"), direction: v("#re-dir"),
          starts_at: dt("#re-start"), expires_at: dt("#re-end"),
          schedule: m.querySelector("#re-sch").checked ? {
            days: [...m.querySelectorAll(".days input:checked")].map((x) => +x.value), start: v("#re-from"), end: v("#re-to"),
          } : null,
        };
        if (t === "throttle") body.rate_kbps = +v("#re-rate");
        if (t === "cap") body.cap = { mb: +v("#re-mb"), period: v("#re-period"), metric: v("#re-metric"), action: v("#re-action"), throttle_kbps: +v("#re-capkbps") };
        if (r.pause_all) body.pause_all = true;
        try {
          if (editing) await api("PATCH", `/api/rules/${r.id}`, body); else await api("POST", "/api/rules", body);
          closeModal(); toast(editing ? "Rule saved" : "Rule created"); poll(true);
        } catch (e) { m.querySelector("#re-err").textContent = e.message; }
      };
    },
  });
}
H.delRuleClose = (d) => { closeModal(); H.delRule(d); };

async function appDetail(key) {
  const a = appByKey(key); if (!a) return;
  let d;
  try { d = await api("GET", `/api/app?key=${encodeURIComponent(key)}`); } catch (e) { return toast(e.message, { err: true }); }
  const ar = appRules(key);
  modal(`<header>${avatar(a)}<h2>${esc(a.friendly)} <span class="faint" style="font-weight:400;font-size:13px">${esc(a.name)}</span></h2>
      ${ar.block || ar.pause ? `<button class="btn ok sm" data-act="allowApp" data-key="${esc(key)}">Allow</button>` : `<button class="btn danger sm" data-act="blockApp" data-key="${esc(key)}">Block</button>`}
      <button class="btn sm pause" data-act="pauseApp" data-key="${esc(key)}">Pause…</button>
      <button class="btn sm" data-act="newRule" data-prefill='${esc(JSON.stringify({ app: a.exe, type: "throttle" }))}'>Rule…</button></header>
    <div class="body">
      <div class="pro-grid" style="margin-bottom:14px"><div class="kv">
        <div>Path</div><div class="num" style="word-break:break-all">${esc(a.exe || "—")}</div>
        <div>Process IDs</div><div class="num">${esc(a.pids.join(", ") || "—")}</div>
        <div>User</div><div>${esc(a.user || "—")}</div>
        ${a.services.length ? `<div>Services</div><div>${esc(a.services.join(", "))}</div>` : ""}
        <div>Session</div><div class="num"><span class="down">↓ ${fmtB(a.down)}</span> · <span class="up">↑ ${fmtB(a.up)}</span></div>
        <div>Today</div><div class="num"><span class="down">↓ ${fmtB(a.today_down)}</span> · <span class="up">↑ ${fmtB(a.today_up)}</span></div>
        <div>This month</div><div class="num"><span class="down">↓ ${fmtB(a.month_down)}</span> · <span class="up">↑ ${fmtB(a.month_up)}</span></div>
      </div><div>${spark(d.hist, 300, 70)}<div class="faint" style="font-size:11.5px">Last 60 s — <span class="down">download</span> / <span class="up">upload</span></div></div></div>
      <h3 class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.6px">Endpoints (${d.endpoints.length})</h3>
      <div class="tablewrap" style="max-height:260px;margin-bottom:14px"><table class="t"><thead><tr><th>Host</th><th>IP</th><th>Ports</th><th class="r">↓</th><th class="r">↑</th><th>Last</th><th></th></tr></thead><tbody>
      ${d.endpoints.map((e) => `<tr><td>${esc(e.host || "—")}</td><td class="num">${esc(e.ip)}</td><td class="num">${esc(e.ports.join(", "))}</td><td class="r num down">${fmtB(e.down)}</td><td class="r num up">${fmtB(e.up)}</td><td class="faint">${ago(e.last)}</td>
        <td class="acts"><button class="btn sm" data-act="newRule" data-prefill='${esc(JSON.stringify({ app: a.exe, remote: [e.ip] }))}'>Block for app</button></td></tr>`).join("") || '<tr><td colspan="7" class="empty">No endpoints yet</td></tr>'}
      </tbody></table></div>
      <h3 class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.6px">Connections (${d.connections.length})</h3>
      <div class="tablewrap" style="max-height:240px"><table class="t"><thead><tr><th>Proto</th><th>Local</th><th>Remote</th><th>Host</th><th>State</th><th class="r">↓/s</th><th class="r">↑/s</th></tr></thead><tbody>
      ${d.connections.map((c) => `<tr><td>${c.proto.toUpperCase()}</td><td class="num">${c.lport}</td><td class="num">${esc(c.rip)}:${c.rport}</td><td>${esc(c.host || "")}</td><td class="faint">${esc(c.status)}</td><td class="r num down">${fmtR(c.rate_down)}</td><td class="r num up">${fmtR(c.rate_up)}</td></tr>`).join("") || '<tr><td colspan="7" class="empty">No open connections</td></tr>'}
      </tbody></table></div>
    </div><footer><button class="btn" data-act="close">Close</button></footer>`, { wide: true });
}

// ------------------------------------------------------------------ header + notices
function renderHeader() {
  const d = S.data;
  ["beginner", "pro"].forEach((m) => $("#mode-" + m).classList.toggle("on", S.mode === m));
  const pill = $("#status-pill");
  if (!d) return;
  const active = d.rules.filter((r) => r.status && (r.status.active)).length;
  const ld = d.lockdown || {};
  const waiting = (ld.pending || []).length;
  if (!d.paused && ld.mode && ld.mode !== "off") {
    pill.className = "pill " + (waiting ? "warn" : "ok");
    pill.textContent = (ld.mode === "ask" ? "Block all · ask me" : "Only allowed apps") + (waiting ? ` · ${waiting} waiting` : "");
  } else if (d.paused) { pill.className = "pill paused"; pill.textContent = d.paused.expires_at ? `Internet paused · ${left(d.paused.expires_at)}` : "Internet paused"; }
  else if (!d.admin) { pill.className = "pill warn"; pill.textContent = "Monitor only — not Administrator"; }
  else { pill.className = "pill ok"; pill.textContent = active ? `Protecting · ${active} rule${active > 1 ? "s" : ""} active` : "Watching · no blocks"; }
  let n = "";
  const up = d.update || {};
  if (up.busy && up.busy !== "checking") S.updating = true;
  if (S.failures > 2) n += S.updating ? `<div class="notice info">NetWarden is updating. It restarts by itself and opens a new window, so you can close this one.</div>`
    : `<div class="notice">Lost contact with NetWarden. Is the NetWarden window (console) still open? Retrying…</div>`;
  else if (up.busy && up.busy !== "checking") n += `<div class="notice info">Updating NetWarden to ${esc(up.latest)}: ${esc(up.busy)}… It restarts by itself in a moment.</div>`;
  else if (up.available && !S.updDismissed) n += `<div class="notice info">NetWarden ${esc(up.latest)} is available (you have ${esc(up.current)}).
    ${up.can_install ? '<button class="btn sm primary" data-act="updInstall" style="margin-left:8px">Install update</button>' : up.installed ? "" : " This copy isn't installed: run <b>git pull</b> to update it."}
    <button class="btn sm ghost" data-act="updDismiss">Later</button></div>`;
  if (d.sim) n += `<div class="notice info">Demo mode — the apps and traffic are simulated and nothing on your PC is changed. Start with <b>run.bat</b> on Windows for live monitoring.</div>`;
  if (!d.sim && !d.admin) n += `<div class="notice">NetWarden isn't running as Administrator, so it can watch but not block or limit. Close it and start it with <b>run.bat</b> (it asks for admin rights).</div>`;
  for (const w of (ld.warnings || [])) n += `<div class="notice">${esc(w)}${w.includes("turned off") ? ' <button class="btn sm" data-act="fwOn" style="margin-left:8px">Turn Windows Firewall on</button>' : ""}</div>`;
  if (!d.sim && !d.per_app_bytes) n += `<div class="notice">Per-app data counting is off — ${esc(d.sniffer_error || "the packet sniffer isn't running")}. You still see connections and total speed; data limits need this.</div>`;
  setHTML($("#notice"), n);
}
function setHTML(el, html) { if (el && el.__h !== html) { el.innerHTML = html; el.__h = html; } }

// ------------------------------------------------------------------ BEGINNER
function beginnerShell() {
  return `<div class="b-wrap">
    <div id="b-banner"></div>
    <div id="b-requests"></div>
    <section class="card"><h2>Protection</h2><p class="sub">Choose how strict NetWarden is. You can change this any time, also from the tray icon near the clock.</p><div id="b-modes"></div></section>
    <section class="card hidden" id="b-allowed-card"><h2>Allowed apps</h2><div style="display:flex;align-items:center;gap:10px;margin-bottom:12px"><p class="sub" style="flex:1;margin:0">These apps can connect while block-all is on.</p><button class="btn primary" data-act="addAllowed">Choose apps…</button></div><div id="b-allowed"></div></section>
    <section class="card hero">
      <div class="stat"><div class="label"><span class="dot down"></span>Downloading now</div><div class="value" id="b-down"></div></div>
      <div class="stat"><div class="label"><span class="dot up"></span>Uploading now</div><div class="value" id="b-up"></div></div>
      <div class="stat"><div class="label">Used today</div><div class="value" id="b-today"></div></div>
      <div class="chart-row"><canvas class="chart" id="chart"></canvas></div>
    </section>
    <section class="card pause-card" id="b-pause"></section>
    <section class="card"><h2>Apps using the internet</h2><p class="sub">Block an app, pause it for a while, or limit how much it can use. Changes apply right away.</p><div id="b-apps"></div></section>
    <div class="two">
      <section class="card"><h2>Your blocks &amp; limits</h2><p class="sub">Everything NetWarden is doing for you right now.</p><div id="b-rules"></div></section>
      <section class="card"><h2>What's been happening</h2><p class="sub">New apps going online, limits reached, things allowed again.</p><div id="b-feed" class="feed"></div></section>
    </div></div>`;
}
function splitVal(s) { const [v, u] = s.split(" "); return `${v}<small>${u}</small>`; }
function beginnerUpdate() {
  const d = S.data;
  const ld = LD();
  // permission requests (one row per app)
  const byApp = new Map();
  for (const p of ld.pending) { const k = lc(p.app); if (!byApp.has(k)) byApp.set(k, { ...p, n: 0, all: [] }); const g = byApp.get(k); g.n += p.count; g.all.push(p); }
  setHTML($("#b-requests"), ld.mode === "ask" && byApp.size ? `<section class="card req-card"><h2>${byApp.size} app${byApp.size > 1 ? "s want" : " wants"} to connect</h2>
    <p class="sub">They're blocked until you decide. Allow the ones you trust.</p><div class="applist">${[...byApp.values()].map((g) => `<div class="approw req">
      ${avatar({ name: g.app_name, friendly: g.app_name, exe: g.app })}<div style="min-width:0"><div class="name">${esc(g.app_name)}</div><div class="what">Tried ${esc((g.dests || []).slice(0, 2).join(", "))} · ${g.n} attempt${g.n > 1 ? "s" : ""}</div></div>
      <div></div><div></div><div class="acts"><button class="btn" data-act="reqLater" data-id="${g.all[0].id}">Later</button><button class="btn danger" data-act="reqApp" data-action="deny" data-app="${esc(g.app)}" data-name="${esc(g.app_name)}">Block</button><button class="btn ok" data-act="reqApp" data-action="allow" data-app="${esc(g.app)}" data-name="${esc(g.app_name)}">Allow</button></div></div>`).join("")}</div></section>` : "");
  setHTML($("#b-modes"), modeCards(false));
  const showAllowed = ld.mode !== "off";
  $("#b-allowed-card").classList.toggle("hidden", !showAllowed);
  if (showAllowed) {
    const rows = [];
    for (const g of ld.groups.filter((g) => g.enabled && g.id !== "essentials"))
      for (const a of g.apps) rows.push(`<div class="rulerow"><div class="icon ok">✓</div><div class="t"><b>${esc(a.name)}</b><div>Always allowed${g.id === "allowed" ? "" : ` · group “${esc(g.name)}”`}</div></div><button class="btn sm" data-act="grpRemoveApp" data-gid="${g.id}" data-exe="${esc(a.path)}">Remove</button></div>`);
    for (const x of ld.decisions.filter((x) => x.scope === "app")) {
      if (ld.mode === "allowlist" && x.action === "allow") continue;
      rows.push(`<div class="rulerow"><div class="icon ${x.action === "allow" ? "ok" : "block"}">${x.action === "allow" ? "✓" : "⛔"}</div><div class="t"><b>${esc(x.app_name)}</b><div>${x.action === "allow" ? "Allowed by you" : "Blocked by you"}${x.expires_at ? " · until " + when(x.expires_at) : ""}</div></div>
        ${x.action === "deny" ? `<button class="btn sm ok" data-act="allowLD" data-exe="${esc(x.app)}" data-name="${esc(x.app_name)}">Allow</button>` : ""}<button class="btn sm" data-act="decDel" data-id="${x.id}">${x.action === "allow" ? "Remove" : "Forget"}</button></div>`);
    }
    const ess = ld.groups.find((g) => g.id === "essentials");
    rows.push(`<div class="faint" style="font-size:12.5px;padding:6px 2px">${ess && ess.enabled ? "Windows essentials (DNS, updates, time…) are allowed too." : "⚠ Windows essentials are NOT allowed — Windows networking may break. Turn the group back on in Pro → Permissions."}</div>`);
    setHTML($("#b-allowed"), `<div class="rulelist">${rows.join("")}</div>`);
  }
  setHTML($("#b-banner"), d.paused ? `<div class="paused-banner"><div style="font-size:30px">⏸</div><div><div class="big">The internet is paused</div>
      <div class="muted">${d.paused.expires_at ? `It comes back on by itself at ${when(d.paused.expires_at)}.` : "It stays off until you turn it back on."}</div></div>
      ${d.paused.expires_at ? `<div class="count">${left(d.paused.expires_at)}</div>` : '<div class="spacer"></div>'}
      <button class="btn lg ok" data-act="resumeAll">Turn internet back on</button></div>` : "");
  setHTML($("#b-down"), splitVal(fmtR(d.total.rate_down)));
  setHTML($("#b-up"), splitVal(fmtR(d.total.rate_up)));
  setHTML($("#b-today"), splitVal(fmtB(d.today.down + d.today.up)));
  drawChart($("#chart"), d.history);
  setHTML($("#b-pause"), d.paused ? `<div class="txt"><h2>Pause is on</h2><p class="sub" style="margin:0">Want more time? Pick a new length — it replaces the current pause.</p></div>
      <div class="choices">${[[15, "15 min"], [60, "1 hour"]].map(([m, l]) => `<button class="btn pause" data-act="pauseAll" data-min="${m}">${l}</button>`).join("")}<button class="btn pause" data-act="pauseAll">Until I resume</button></div>`
    : `<div class="txt"><h2>Take a break from the internet</h2><p class="sub" style="margin:0">Pauses every app on this PC, then turns the internet back on automatically.</p></div>
      <div class="choices">${[[5, "5 min"], [15, "15 min"], [60, "1 hour"]].map(([m, l]) => `<button class="btn pause" data-act="pauseAll" data-min="${m}">⏸ ${l}</button>`).join("")}<button class="btn pause" data-act="pauseAll">Until I resume</button></div>`);

  // apps
  const apps = d.apps;
  const withRules = (a) => { const r = appRules(a.key); return r.block || r.pause || r.throttle || r.cap || ["blocked", "pending", "denied"].includes(a.perm); };
  const shown = apps.filter((a) => S.showIdle || a.active || withRules(a));
  const hidden = apps.length - shown.length;
  const maxRate = Math.max(1, ...apps.map((a) => a.rate_down + a.rate_up));
  const rows = shown.map((a) => {
    const r = appRules(a.key);
    const chips = [];
    let what = a.rate_down + a.rate_up > 1024 ? (a.rate_down >= a.rate_up ? "Downloading" : "Uploading") : a.active ? "Connected, quiet" : "Not active";
    if (r.block) { chips.push('<span class="chip blocked">Blocked</span>'); what = "Can't use the internet"; }
    if (r.pause) { chips.push(`<span class="chip paused">Paused · ${left(r.pause.expires_at)}</span>`); what = `Allowed again at ${when(r.pause.expires_at)}`; }
    if (r.throttle) chips.push(`<span class="chip limited">Upload ≤ ${fmtKbps(r.throttle.rate_kbps)}</span>`);
    if (r.cap) {
      const st = r.cap.status || {};
      const pct = st.limit ? Math.min(100, Math.round((st.used / st.limit) * 100)) : 0;
      chips.push(`<span class="chip ${st.state === "tripped" ? "blocked" : "cap"}">${st.state === "tripped" ? "Daily limit reached" : `Daily limit ${pct}%`}</span>`);
    }
    const blocked = r.block || r.pause;
    if (a.perm) chips.unshift(permChip(a.perm));
    if (a.critical) chips.push('<span class="chip idle" title="Part of Windows itself — blocking it can break your internet">Windows</span>');
    const ldBlocked = ["blocked", "pending", "denied"].includes(a.perm);
    if (ldBlocked) what = "Blocked by block-all mode";
    const w = Math.round(((a.rate_down + a.rate_up) / maxRate) * 100);
    return `<div class="approw">${avatar(a)}
      <div style="min-width:0"><div class="name">${esc(a.friendly)}</div><div class="what">${esc(what)} ${chips.join(" ")}</div></div>
      <div class="speed">${blocked ? '<span class="faint">—</span>' : `<span class="down">↓ ${fmtR(a.rate_down)}</span> &nbsp;<span class="up">↑ ${fmtR(a.rate_up)}</span><div class="bar"><i style="width:${w}%"></i></div>`}</div>
      <div class="today">${fmtB(a.today_down + a.today_up)}<div class="faint" style="font-size:11px">today</div></div>
      <div class="acts">${ldBlocked && !blocked ? `<button class="btn ok" data-act="allowLD" data-exe="${esc(a.exe)}" data-name="${esc(a.friendly)}">Allow</button>` : ""}${blocked ? `<button class="btn ok" data-act="allowApp" data-key="${esc(a.key)}">Allow</button>`
        : `<button class="btn pause" data-act="pauseApp" data-key="${esc(a.key)}">Pause</button><button class="btn danger" data-act="blockApp" data-key="${esc(a.key)}">Block</button>`}
        <button class="btn" data-act="limitApp" data-key="${esc(a.key)}">Limit</button></div></div>`;
  }).join("");
  setHTML($("#b-apps"), `<div class="applist">${rows || '<div class="empty">No apps are using the internet right now.</div>'}</div>
    ${hidden || S.showIdle ? `<div style="text-align:center;margin-top:8px"><button class="btn ghost" data-act="showIdle">${S.showIdle ? "Hide quiet apps" : `Show ${hidden} quiet app${hidden > 1 ? "s" : ""}`}</button></div>` : ""}`);

  const rules = d.rules.map((r) => {
    const p = plainRule(r);
    return `<div class="rulerow"><div class="icon ${p.icon}">${p.ic}</div><div class="t"><b>${esc(p.t)}</b><div>${esc(p.d)}</div></div>
      <button class="btn sm" data-act="delRule" data-id="${r.id}">${r.pause_all ? "Resume" : r.type === "block" ? "Allow" : "Remove"}</button></div>`;
  }).join("");
  setHTML($("#b-rules"), rules ? `<div class="rulelist">${rules}</div>` : '<div class="empty">Nothing blocked or limited. Use the buttons next to an app to start.</div>');
  const feed = d.events.filter((e) => ["alert", "new_app", "allow", "rule", "warn", "error"].includes(e.kind)).slice(0, 9);
  setHTML($("#b-feed"), feed.map((e) => `<div class="ev ${e.kind}"><time>${clock(e.t)}</time><span>${esc(e.msg)}</span></div>`).join("") || '<div class="empty">Quiet so far.</div>');
}

// ------------------------------------------------------------------ PRO
const TABS = [["overview", "Overview"], ["perms", "Permissions"], ["apps", "Apps"], ["conns", "Connections"], ["eps", "Endpoints"], ["rules", "Rules"], ["dns", "DNS"], ["log", "Activity"], ["settings", "Settings"]];
function proShell() {
  const tb = {
    overview: `<div class="toolbar"><button class="btn pause" data-act="pauseMenu">⏸ Pause internet…</button><button class="btn primary" data-act="newRule">+ New rule</button><div class="spacer"></div><span class="faint" id="p-uptime"></span></div>`,
    apps: `<div class="toolbar"><input class="input" id="f-apps" placeholder="Filter apps, paths, PIDs, services…" style="width:320px" value="${esc(S.filter.apps)}"><div class="spacer"></div><span class="faint" id="p-count"></span></div>`,
    conns: `<div class="toolbar"><input class="input" id="f-conns" placeholder="Filter app, IP, host, port…" style="width:300px" value="${esc(S.filter.conns)}">
      <select class="input" id="f-proto"><option value="">All protocols</option><option value="tcp">TCP</option><option value="udp">UDP</option></select>
      <select class="input" id="f-cstate"><option value="">All states</option><option value="ESTABLISHED">Established</option><option value="active">Moving data</option><option value="other">Closing / waiting</option></select>
      <label class="faint" style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="f-freeze"> Freeze</label><div class="spacer"></div><span class="faint" id="p-count"></span></div>`,
    eps: `<div class="toolbar"><input class="input" id="f-eps" placeholder="Filter host, IP, app…" style="width:320px" value="${esc(S.filter.eps)}"><div class="spacer"></div><span class="faint" id="p-count"></span></div>`,
    rules: `<div class="toolbar"><button class="btn primary" data-act="newRule">+ New rule</button><button class="btn pause" data-act="pauseMenu">⏸ Pause internet…</button><div class="spacer"></div><button class="btn danger" data-act="cleanup">Remove all rules</button></div>`,
    dns: `<div class="toolbar"><input class="input" id="f-dns" placeholder="Filter domains / IPs…" style="width:320px" value="${esc(S.filter.dns)}"><div class="spacer"></div><span class="faint">Learned from DNS answers seen on the network</span></div>`,
    log: `<div class="toolbar"><input class="input" id="f-log" placeholder="Filter activity…" style="width:320px" value="${esc(S.filter.log)}"></div>`,
    settings: "",
    perms: "",
  }[S.tab];
  return `<nav class="tabs" id="p-tabs"></nav>${tb}<div id="p-body"></div>`;
}
function bindProInputs() {
  for (const k of ["apps", "conns", "eps", "dns", "log"]) {
    const el = $("#f-" + k);
    if (el) el.oninput = () => { S.filter[k] = el.value; render(true); };
  }
  const p = $("#f-proto"); if (p) { p.value = S.filter.proto; p.onchange = () => { S.filter.proto = p.value; render(true); }; }
  const c = $("#f-cstate"); if (c) { c.value = S.filter.cstate; c.onchange = () => { S.filter.cstate = c.value; render(true); }; }
  const f = $("#f-freeze"); if (f) { f.checked = S.freeze; f.onchange = () => { S.freeze = f.checked; }; }
}
function th(table, key, label, cls = "") {
  const [k, dir] = S.sort[table];
  return `<th class="${cls}" data-act="sort" data-table="${table}" data-key="${key}">${label}${k === key ? ` <span class="arr">${dir < 0 ? "▾" : "▴"}</span>` : ""}</th>`;
}
function sortRows(rows, table, getters) {
  const [k, dir] = S.sort[table];
  const g = getters[k] || ((r) => r[k]);
  return rows.slice().sort((a, b) => { const x = g(a), y = g(b); return (x > y ? 1 : x < y ? -1 : 0) * dir; });
}
const match = (q, ...fields) => !q || fields.some((f) => lc(f).includes(lc(q)));
function stateBadge(st) { return `<span class="state ${esc(st.state)}" title="${esc(st.detail || "")}">${esc(st.state)}</span>`; }

function proUpdate() {
  const d = S.data;
  const counts = { perms: (d.lockdown?.pending || []).length || undefined, apps: d.apps.length, conns: (d.connections || []).length, eps: (d.endpoints || []).length, rules: d.rules.length, dns: (d.dns || []).length };
  setHTML($("#p-tabs"), TABS.map(([k, l]) => `<button data-act="tab" data-tab="${k}" class="${S.tab === k ? "on" : ""}">${l}${counts[k] !== undefined ? `<span class="n">${counts[k]}</span>` : ""}</button>`).join(""));
  const body = $("#p-body");
  const fn = { perms: proPerms, overview: proOverview, apps: proApps, conns: proConns, eps: proEps, rules: proRules, dns: proDns, log: proLog, settings: proSettings }[S.tab];
  fn(body, d);
}

function proOverview(body, d) {
  if (!body.__shell) {
    body.innerHTML = `<div class="tiles" id="o-tiles"></div>
      <div class="pro-grid"><div class="card" style="padding:14px 16px"><h3>Throughput — last 5 minutes</h3><canvas class="chart" id="chart" style="height:170px"></canvas></div>
      <div class="card" style="padding:14px 16px"><h3>Daily usage — 30 days</h3><div id="o-days"></div></div></div>
      <div class="card" style="padding:14px 16px;margin-top:16px"><h3>Top apps right now</h3><div id="o-top"></div></div>`;
    body.__shell = true;
  }
  const tile = (k, v, s, cls = "") => `<div class="tile"><div class="k">${k}</div><div class="v ${cls}">${v}</div>${s ? `<div class="s">${s}</div>` : ""}</div>`;
  const activeRules = d.rules.filter((r) => r.status?.active).length;
  setHTML($("#o-tiles"), [
    tile("Download now", fmtR(d.total.rate_down), "", "down"), tile("Upload now", fmtR(d.total.rate_up), "", "up"),
    tile("Session", `${fmtB(d.total.down)}`, `↑ ${fmtB(d.total.up)} sent`), tile("Today", fmtB(d.today.down + d.today.up), `↓ ${fmtB(d.today.down)} · ↑ ${fmtB(d.today.up)}`),
    tile("This month", fmtB(d.month.down + d.month.up), `↓ ${fmtB(d.month.down)} · ↑ ${fmtB(d.month.up)}`),
    tile("Active apps", d.counts.apps_active, `${d.apps.length} seen`), tile("TCP connections", d.counts.connections, "established"),
    tile("Endpoints", d.counts.endpoints, "active in last 30 s"),
    tile("Rules", `${activeRules}/${d.rules.length}`, `${d.applied ?? 0} firewall/QoS entries`),
    tile("Engine", d.sim ? "Demo" : d.admin ? "Live" : "Monitor", `${d.per_app_bytes ? "sniffer on" : "sniffer off"} · ${d.dropper ? "hard pause on" : "admin " + (d.admin ? "yes" : "no")}`),
  ].join(""));
  setHTML($("#p-uptime"), `Running ${Math.floor(d.uptime / 3600)}h ${Math.floor((d.uptime % 3600) / 60)}m`);
  drawChart($("#chart"), d.history);
  const days = d.days || [];
  const mx = Math.max(1, ...days.map(([, v]) => v[0] + v[1]));
  setHTML($("#o-days"), days.length ? `<div class="daybars">${days.map(([k, v]) => `<div class="d" data-tip="${k}: ↓ ${fmtB(v[1])} ↑ ${fmtB(v[0])}"><i class="u" style="height:${(v[0] / mx) * 100}px"></i><i style="height:${(v[1] / mx) * 100}px"></i></div>`).join("")}</div>
    <div class="faint" style="font-size:11.5px;margin-top:4px">Hover a bar for details · <span class="down">download</span> / <span class="up">upload</span></div>` : '<div class="empty">Collecting…</div>');
  const top = d.apps.slice(0, 8);
  setHTML($("#o-top"), `<table class="t"><thead><tr><th>App</th><th class="r">↓/s</th><th class="r">↑/s</th><th class="r">Today</th><th class="r">Conns</th><th>Trend</th></tr></thead><tbody>${top.map((a) =>
    `<tr data-act="appDetail" data-key="${esc(a.key)}" style="cursor:pointer"><td>${avatar(a, "mini-av")}${esc(a.friendly)}</td><td class="r num down">${fmtR(a.rate_down)}</td><td class="r num up">${fmtR(a.rate_up)}</td><td class="r num">${fmtB(a.today_down + a.today_up)}</td><td class="r num">${a.conns}</td><td>${spark(a.hist)}</td></tr>`).join("")}</tbody></table>`);
}

function proPerms(body, d) {
  const ld = LD();
  const pend = ld.pending;
  const apps = knownApps();
  const dl = `<datalist id="known-apps">${apps.map((a) => `<option value="${esc(a.exe)}">${esc(a.name)}</option>`).join("")}</datalist>`;
  const reqRows = pend.map((p) => `<tr><td>${avatar({ name: p.app_name, friendly: p.app_name, exe: p.app }, "mini-av")}<b>${esc(p.app_name)}</b><div class="path num">${esc(p.app)}</div></td>
    <td class="num">${esc(p.ip)}</td><td>${esc(p.host || "—")}</td><td class="num">${p.proto.toUpperCase()} ${p.port}</td><td class="r num">${p.count}</td><td class="faint">${ago(p.first)}</td>
    <td class="acts"><span class="faint" style="font-size:11.5px">Allow</span><button class="btn sm ok" data-act="reqAnswer" data-id="${p.id}" data-action="allow" data-scope="address">Address</button>${p.host ? `<button class="btn sm ok" data-act="reqAnswer" data-id="${p.id}" data-action="allow" data-scope="domain">Domain</button>` : ""}<button class="btn sm ok" data-act="reqAnswer" data-id="${p.id}" data-action="allow" data-scope="app">App</button>
      <span class="faint" style="font-size:11.5px;margin-left:8px">Block</span><button class="btn sm danger" data-act="reqAnswer" data-id="${p.id}" data-action="deny" data-scope="address">Address</button><button class="btn sm danger" data-act="reqAnswer" data-id="${p.id}" data-action="deny" data-scope="app">App</button><button class="btn sm ghost" data-act="reqLater" data-id="${p.id}">Later</button></td></tr>`).join("");
  const groups = ld.groups.map((g) => `<div class="card grp" style="padding:14px 16px">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px"><label class="switch"><input type="checkbox" data-act="grpToggle" data-gid="${g.id}" ${g.enabled ? "checked" : ""}><span></span></label>
      <b style="flex:1">${esc(g.name)}</b><span class="faint">${g.apps.length} app${g.apps.length === 1 ? "" : "s"}</span>${g.builtin ? "" : `<button class="btn sm ghost" data-act="grpDel" data-gid="${g.id}">Delete</button>`}</div>
    ${g.note ? `<div class="faint" style="font-size:12px;margin-bottom:8px">${esc(g.note)}</div>` : ""}
    <div class="gapps">${g.apps.map((a) => `<span class="gapp" title="${esc(a.path)}">${esc(a.name)}<button data-act="grpRemoveApp" data-gid="${g.id}" data-exe="${esc(a.path)}" title="Remove">×</button></span>`).join("") || '<span class="faint">No apps yet</span>'}</div>
    <div style="display:flex;gap:6px;margin-top:10px"><input class="input num" id="ga-${g.id}" list="known-apps" placeholder="Pick a seen app or paste a full .exe path" style="flex:1"><button class="btn sm" data-act="grpAddApp" data-gid="${g.id}">Add</button></div></div>`).join("");
  const decRows = ld.decisions.slice().sort((a, b) => b.created_at - a.created_at).map((x) => `<tr><td><b>${esc(x.app_name)}</b><div class="path num">${esc(x.app)}</div></td>
    <td>${x.scope === "app" ? "Whole app" : x.scope === "domain" ? "Domain" : "Address"}</td><td class="num">${esc(x.remote || "everywhere")}</td>
    <td>${x.action === "allow" ? '<span class="chip okc">allow</span>' : '<span class="chip blocked">block</span>'}${ld.mode === "allowlist" && x.action === "allow" ? ' <span class="faint" title="Only groups count in this mode">(inactive in allow-list mode)</span>' : ""}</td>
    <td class="faint">${x.expires_at ? "until " + when(x.expires_at) : "always"}</td><td class="faint">${ago(x.created_at)}</td><td class="acts"><button class="btn sm" data-act="decDel" data-id="${x.id}">Delete</button></td></tr>`).join("");
  const VERD = { unknown: "asked", denied: "blocked", allowed: "allowed (rule pending)", noise: "broadcast / local" };
  const atRows = (ld.attempts || []).slice(0, 150).map((a) => `<tr><td class="num faint">${clock(a.t, true)}</td><td>${esc(a.app_name || "?")}</td>
    <td class="num">${esc(a.ip)}</td><td>${esc(a.host || "")}</td><td class="num">${a.proto.toUpperCase()} ${a.port}</td><td class="r num">${a.count || 1}</td><td class="faint">${VERD[a.verdict] || a.verdict}</td>
    <td class="acts">${a.verdict !== "noise" && a.app ? `<button class="btn sm ok" data-act="decAdd" data-exe="${esc(a.app)}" data-name="${esc(a.app_name)}" data-remote="${esc(a.ip)}" data-scope="address">Allow address</button><button class="btn sm ok" data-act="allowLD" data-exe="${esc(a.app)}" data-name="${esc(a.app_name)}">Allow app</button>` : ""}</td></tr>`).join("");
  if (!body.__shell) {
    body.innerHTML = `<div id="pm-dl"></div><div class="card" style="padding:14px 16px;margin-bottom:16px"><h3>Protection mode</h3><div id="pm-mode"></div></div>
      <div id="pm-req"></div>
      <h3 class="sect">App groups <span class="faint">turned-on groups are always allowed</span></h3><div class="grp-grid"><div id="pm-groups" style="display:contents"></div>
        <div class="card grp" style="padding:14px 16px;display:grid;align-content:center;gap:8px"><b>New group</b><div class="faint" style="font-size:12px">e.g. “Work”, “Games”. Turn a group off to block all of its apps at once in block-all mode.</div><div style="display:flex;gap:6px"><input class="input" id="g-new" placeholder="Group name" style="flex:1"><button class="btn sm primary" data-act="grpNew">Create</button></div></div></div>
      <h3 class="sect">Your answers <span class="faint" id="pm-dec-n"></span></h3><div class="tablewrap" style="margin-bottom:18px;max-height:340px" id="pm-dec"></div>
      <h3 class="sect">Blocked connection attempts <span class="faint">reported by Windows</span></h3><div class="tablewrap" style="max-height:420px" id="pm-att"></div>`;
    body.__shell = true;
  }
  setHTML($("#pm-dl"), dl);
  setHTML($("#pm-mode"), modeCards(true) + `<div class="faint" style="font-size:12.5px;margin-top:10px">${ld.mode === "off" ? "Block-all is off." : `Firewall default for outgoing traffic: <b>${ld.policy_ok ? "Block ✓" : "switching…"}</b>. Pro mode asks <b>per address</b>; Beginner mode asks per app. Each answer becomes a Windows Firewall allow/block rule.`}</div>`);
  setHTML($("#pm-req"), ld.mode === "ask" ? `<h3 class="sect">Waiting for your answer <span class="faint">${pend.length}</span></h3>
    <div class="tablewrap" style="margin-bottom:18px;max-height:360px"><table class="t"><thead><tr><th>App</th><th>Address</th><th>Host</th><th>Port</th><th class="r">Tries</th><th>Since</th><th></th></tr></thead><tbody>${reqRows || '<tr><td colspan="7" class="empty">Nothing waiting. New requests also pop up near the clock.</td></tr>'}</tbody></table></div>` : "");
  setHTML($("#pm-groups"), groups);
  setHTML($("#pm-dec-n"), String(ld.decisions.length));
  setHTML($("#pm-dec"), `<table class="t"><thead><tr><th>App</th><th>Applies to</th><th>Target</th><th>Decision</th><th>Duration</th><th>Added</th><th></th></tr></thead><tbody>${decRows || '<tr><td colspan="7" class="empty">No answers yet.</td></tr>'}</tbody></table>`);
  setHTML($("#pm-att"), `<table class="t"><thead><tr><th>Time</th><th>App</th><th>Address</th><th>Host</th><th>Port</th><th class="r">Count</th><th>Result</th><th></th></tr></thead><tbody>${atRows || `<tr><td colspan="8" class="empty">${ld.mode === "off" ? "Turn on a block-all mode to see blocked attempts." : "No blocked attempts yet."}</td></tr>`}</tbody></table>`);
}
H.decAdd = (d) => act(api("POST", "/api/lockdown/decision", { app: d.exe, app_name: d.name, scope: d.scope, remote: d.remote, action: "allow" }), `Allowed ${d.name} → ${d.remote}`);

function appChips(key) {
  const r = appRules(key), c = [];
  if (r.block) c.push('<span class="chip blocked">blocked</span>');
  if (r.pause) c.push(`<span class="chip paused">paused ${left(r.pause.expires_at)}</span>`);
  if (r.throttle) c.push(`<span class="chip limited">≤ ${fmtKbps(r.throttle.rate_kbps)}</span>`);
  if (r.cap) c.push(`<span class="chip ${r.cap.status?.state === "tripped" ? "blocked" : "cap"}">cap ${r.cap.status?.limit ? Math.round((r.cap.status.used / r.cap.status.limit) * 100) : 0}%</span>`);
  if (r.custom) c.push(`<span class="chip idle">${r.custom} custom</span>`);
  return c.join(" ");
}
function proApps(body, d) {
  const q = S.filter.apps;
  let rows = d.apps.filter((a) => match(q, a.friendly, a.name, a.exe, a.pids.join(" "), a.services.join(" ")));
  rows = sortRows(rows, "apps", { rate: (a) => a.rate_down + a.rate_up, today: (a) => a.today_down + a.today_up, name: (a) => lc(a.friendly) });
  setHTML($("#p-count"), `${rows.length} apps`);
  setHTML(body, `<div class="tablewrap"><table class="t"><thead><tr>${th("apps", "name", "App")}<th>PIDs</th>${th("apps", "rate_down", "↓/s", "r")}${th("apps", "rate_up", "↑/s", "r")}
    ${th("apps", "down", "Session ↓ / ↑", "r")}${th("apps", "today", "Today", "r")}${th("apps", "conns", "Conns", "r")}${th("apps", "endpoints", "Hosts", "r")}<th>Last 40 s</th><th>Rules</th><th></th></tr></thead><tbody>
    ${rows.map((a) => {
      const r = appRules(a.key), blocked = r.block || r.pause;
      return `<tr><td>${avatar(a, "mini-av")}<span style="font-weight:600">${esc(a.friendly)}</span> <span class="faint">${esc(a.name)}</span><div class="path num" title="${esc(a.exe || "")}">${esc(a.exe || "")}</div></td>
      <td class="num faint">${esc(a.pids.slice(0, 4).join(", "))}${a.pids.length > 4 ? "…" : ""}</td>
      <td class="r num down">${fmtR(a.rate_down)}</td><td class="r num up">${fmtR(a.rate_up)}</td><td class="r num">${fmtB(a.down)} <span class="faint">/</span> ${fmtB(a.up)}</td>
      <td class="r num">${fmtB(a.today_down + a.today_up)}</td><td class="r num">${a.conns}</td><td class="r num">${a.endpoints}</td><td>${spark(a.hist)}</td><td>${permChip(a.perm)} ${appChips(a.key)}</td>
      <td class="acts"><button class="btn sm" data-act="appDetail" data-key="${esc(a.key)}">Details</button>${blocked ? `<button class="btn sm ok" data-act="allowApp" data-key="${esc(a.key)}">Allow</button>` : `<button class="btn sm danger" data-act="blockApp" data-key="${esc(a.key)}">Block</button><button class="btn sm pause" data-act="pauseApp" data-key="${esc(a.key)}">Pause</button>`}
      <button class="btn sm" data-act="newRule" data-prefill='${esc(JSON.stringify({ app: a.exe, type: "throttle" }))}'>Rule…</button></td></tr>`;
    }).join("") || '<tr><td colspan="11" class="empty">No apps match</td></tr>'}</tbody></table></div>`);
}

function proConns(body, d) {
  if (S.freeze && body.__h) return;
  const q = S.filter.conns;
  let rows = (d.connections || []).filter((c) => match(q, c.friendly, c.exe, c.rip, c.host, String(c.rport), String(c.lport), String(c.pid), c.status)
    && (!S.filter.proto || c.proto === S.filter.proto)
    && (!S.filter.cstate || (S.filter.cstate === "active" ? c.rate_down + c.rate_up > 0 : S.filter.cstate === "ESTABLISHED" ? c.status === "ESTABLISHED" : !["ESTABLISHED", "ACTIVE"].includes(c.status))));
  rows = sortRows(rows, "conns", { rate: (c) => c.rate_down + c.rate_up, total: (c) => c.down + c.up, app: (c) => lc(c.friendly), host: (c) => lc(c.host || c.rip) });
  setHTML($("#p-count"), `${rows.length} connections`);
  setHTML(body, `<div class="tablewrap"><table class="t"><thead><tr><th>Proto</th>${th("conns", "app", "App")}<th>Local port</th>${th("conns", "host", "Remote")}<th>Host</th>${th("conns", "status", "State")}
    ${th("conns", "rate_down", "↓/s", "r")}${th("conns", "rate_up", "↑/s", "r")}${th("conns", "total", "Total ↓ / ↑", "r")}<th></th></tr></thead><tbody>
    ${rows.map((c) => `<tr><td>${c.proto.toUpperCase()}${c.v6 ? ' <span class="faint">v6</span>' : ""}</td><td>${esc(c.friendly)} <span class="faint num">${c.pid || ""}</span></td>
      <td class="num faint">${c.lport}</td><td class="num">${esc(c.rip)}:${c.rport}</td><td>${esc(c.host || "")}</td><td class="faint">${esc(c.status)}</td>
      <td class="r num down">${fmtR(c.rate_down)}</td><td class="r num up">${fmtR(c.rate_up)}</td><td class="r num">${fmtB(c.down)} <span class="faint">/</span> ${fmtB(c.up)}</td>
      <td class="acts">${c.proto === "tcp" && !c.v6 && c.status === "ESTABLISHED" ? `<button class="btn sm" data-act="kill" data-lip="${esc(c.lip)}" data-lport="${c.lport}" data-rip="${esc(c.rip)}" data-rport="${c.rport}" title="Reset this TCP connection">Kill</button>` : ""}
        <button class="btn sm danger" data-act="blockIp" data-ip="${esc(c.rip)}" data-exe="${esc(c.exe || "")}" data-name="${esc(c.friendly)}">Block IP</button>${c.host ? `<button class="btn sm danger" data-act="blockHost" data-host="${esc(c.host)}" data-exe="${esc(c.exe || "")}" data-name="${esc(c.friendly)}">Block host</button>` : ""}
        <button class="btn sm" data-act="newRule" data-prefill='${esc(JSON.stringify({ app: c.exe, remote: [c.host || c.rip], protocol: c.proto, ports: String(c.rport) }))}'>Rule…</button></td></tr>`).join("")
      || '<tr><td colspan="10" class="empty">No connections match</td></tr>'}</tbody></table></div>`);
}

function proEps(body, d) {
  const q = S.filter.eps;
  let rows = (d.endpoints || []).filter((e) => match(q, e.ip, e.host, e.apps.join(" "), e.ports.join(" ")));
  rows = sortRows(rows, "eps", { rate: (e) => e.rate_down + e.rate_up, total: (e) => e.down + e.up, host: (e) => lc(e.host || e.ip) });
  setHTML($("#p-count"), `${rows.length} endpoints`);
  setHTML(body, `<div class="tablewrap"><table class="t"><thead><tr>${th("eps", "host", "Host")}<th>IP</th><th>Apps</th><th>Ports</th>
    ${th("eps", "rate_down", "↓/s", "r")}${th("eps", "rate_up", "↑/s", "r")}${th("eps", "down", "↓ total", "r")}${th("eps", "up", "↑ total", "r")}${th("eps", "last", "Last seen")}<th></th></tr></thead><tbody>
    ${rows.map((e) => `<tr><td>${e.active ? '<span class="dot down" style="margin-right:6px"></span>' : '<span class="dot" style="margin-right:6px;background:var(--line-2)"></span>'}${esc(e.host || "—")}</td><td class="num">${esc(e.ip)}</td>
      <td class="wrap" style="max-width:240px">${esc(e.apps.join(", "))}</td><td class="num faint">${esc(e.protos.join("/").toUpperCase())} ${esc(e.ports.join(", "))}</td>
      <td class="r num down">${fmtR(e.rate_down)}</td><td class="r num up">${fmtR(e.rate_up)}</td><td class="r num">${fmtB(e.down)}</td><td class="r num">${fmtB(e.up)}</td><td class="faint">${ago(e.last)}</td>
      <td class="acts"><button class="btn sm danger" data-act="blockIp" data-ip="${esc(e.ip)}">Block IP</button>${e.host ? `<button class="btn sm danger" data-act="blockHost" data-host="${esc(e.host)}">Block host</button>` : ""}
      <button class="btn sm" data-act="newRule" data-prefill='${esc(JSON.stringify({ type: "throttle", remote: [e.host || e.ip] }))}'>Rule…</button></td></tr>`).join("")
      || '<tr><td colspan="10" class="empty">No endpoints match</td></tr>'}</tbody></table></div>`);
}

function timing(r) {
  const p = [];
  if (r.starts_at) p.push(`from ${when(r.starts_at)}`);
  if (r.expires_at) p.push(`until ${when(r.expires_at)} (${left(r.expires_at)})`);
  if (r.schedule) p.push(`${["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].filter((_, i) => r.schedule.days.includes(i)).join(",")} ${r.schedule.start}–${r.schedule.end}`);
  return p.join(" · ") || "always";
}
function proRules(body, d) {
  const rows = sortRows(d.rules, "rules", { state: (r) => r.status?.state || "", name: (r) => lc(r.name) });
  const detail = (r) => r.type === "throttle" ? `≤ ${fmtKbps(r.rate_kbps)} upload` : r.type === "cap" ? `${r.cap.mb} MB/${r.cap.period} (${r.cap.metric}) → ${r.cap.action}${r.cap.action === "throttle" ? " " + fmtKbps(r.cap.throttle_kbps) : ""}` : r.pause_all ? "everything" : r.direction;
  setHTML(body, `<div class="tablewrap"><table class="t"><thead><tr><th>On</th>${th("rules", "type", "Type")}${th("rules", "name", "Name")}<th>App</th><th>Remote</th><th>Proto / ports</th><th>Action</th><th>When</th>${th("rules", "state", "Status")}<th></th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td><label class="switch"><input type="checkbox" ${r.enabled ? "checked" : ""} data-act="toggleRule" data-id="${r.id}"><span></span></label></td>
      <td>${esc(r.pause_all ? "pause" : r.type)}</td><td style="font-weight:600" class="wrap">${esc(r.name)}</td><td title="${esc(r.app || "")}">${esc(r.app ? appName(r) : "All")}</td>
      <td class="num wrap" style="max-width:220px">${esc((r.remote || []).join(", ") || "any")}</td><td class="num">${esc(r.protocol.toUpperCase())}${r.ports ? " " + esc(r.ports) : ""}</td>
      <td>${esc(detail(r))}</td><td class="faint wrap">${esc(timing(r))}</td><td>${stateBadge(r.status || {})}<div class="faint" style="font-size:11.5px;max-width:260px;white-space:normal">${esc(r.status?.detail || "")}</div></td>
      <td class="acts"><button class="btn sm" data-act="editRule" data-id="${r.id}">Edit</button><button class="btn sm danger" data-act="delRule" data-id="${r.id}">Delete</button></td></tr>`).join("")
      || '<tr><td colspan="10" class="empty">No rules yet. Create one, or use Block / Pause on the Apps, Connections and Endpoints tabs.</td></tr>'}</tbody></table></div>`);
}
// toggles are checkboxes: handle on change, not click (so the switch state is right)
document.addEventListener("change", (e) => {
  const el = e.target;
  if (el.dataset && el.dataset.act === "toggleRule") act(api("PATCH", `/api/rules/${el.dataset.id}`, { enabled: el.checked }), el.checked ? "Rule on" : "Rule off");
  if (el.dataset && el.dataset.act === "grpToggle") act(api("PATCH", `/api/lockdown/group/${el.dataset.gid}`, { enabled: el.checked }), el.checked ? "Group allowed" : "Group blocked");
  if (el.dataset && el.dataset.act === "setting") act(api("POST", "/api/settings", { [el.dataset.key]: el.checked }), "Saved");
});
H.toggleRule = () => {}; H.setting = () => {}; // handled by the change listener above

function proDns(body, d) {
  const q = S.filter.dns;
  const rows = (d.dns || []).filter((x) => match(q, x.host, x.ips.join(" ")));
  setHTML(body, `<div class="tablewrap"><table class="t"><thead><tr><th>Time</th><th>Domain</th><th>Answers</th><th></th></tr></thead><tbody>
    ${rows.map((x) => `<tr><td class="num faint">${clock(x.t, true)}</td><td>${esc(x.host)}</td><td class="num wrap">${esc(x.ips.join(", "))}</td>
      <td class="acts"><button class="btn sm danger" data-act="blockHost" data-host="${esc(x.host)}">Block domain</button></td></tr>`).join("")
      || `<tr><td colspan="4" class="empty">${d.per_app_bytes ? "No DNS answers seen yet." : "DNS logging needs the packet sniffer (WinDivert)."}</td></tr>`}</tbody></table></div>`);
}
function proLog(body, d) {
  const q = S.filter.log;
  const rows = d.events.filter((e) => match(q, e.msg, e.kind));
  setHTML(body, `<div class="card" style="padding:14px 18px"><div class="feed">${rows.map((e) => `<div class="ev ${e.kind}"><time>${clock(e.t, true)}</time><span class="faint" style="width:64px;flex:none">${esc(e.kind)}</span><span>${esc(e.msg)}</span></div>`).join("") || '<div class="empty">Nothing yet</div>'}</div></div>`);
}
function proSettings(body, d) {
  const s = d.settings;
  const row = (key, t, sub) => `<div class="settings-row"><div class="t"><b>${t}</b><div>${sub}</div></div><label class="switch"><input type="checkbox" data-act="setting" data-key="${key}" ${s[key] ? "checked" : ""}><span></span></label></div>`;
  setHTML(body, `<div class="pro-grid"><div class="card">
    <h2 style="margin-bottom:6px">Behaviour</h2>
    ${row("kill_on_block", "Cut open connections when a block starts", "Resets matching TCP connections so a block works immediately instead of on the next connection.")}
    ${row("instant_pause", "Hard pause", "Pause internet also drops packets in the kernel (WinDivert), stopping streams and calls that are already running.")}
    ${row("keep_rules_on_exit", "Keep blocks when NetWarden closes", "Off: closing NetWarden lifts every block (safe default). On: firewall blocks stay until NetWarden is opened again. Timers and data limits only run while NetWarden is open.")}
    ${row("resolve_hostnames", "Look up host names", "Reverse-DNS lookups for addresses not seen in DNS traffic.")}
    ${row("notify_new_apps", "Report new apps", "Add an activity entry when an app starts using the network for the first time.")}
    <div class="settings-row"><div class="t"><b>Reset usage counters</b><div>Sets today's and this month's data counts back to zero (data limits restart).</div></div><button class="btn" data-act="resetUsage">Reset</button></div>
    <div class="settings-row"><div class="t"><b>Remove all rules</b><div>Emergency undo: deletes every NetWarden rule and its firewall / QoS entries.</div></div><button class="btn danger" data-act="cleanup">Remove all</button></div>
    <div class="settings-row" style="border:0"><div class="t"><b>Quit NetWarden</b><div>Stops monitoring.</div></div><button class="btn danger" data-act="quit">Quit</button></div>
    </div><div style="display:grid;gap:16px;align-content:start"><div class="card"><h2 style="margin-bottom:10px">Updates</h2>${updateCard(d)}</div>
    <div class="card"><h2 style="margin-bottom:10px">Engine</h2><div class="kv">
      <div>Mode</div><div>${d.sim ? "Demo (simulated)" : "Live"}</div>
      <div>Administrator</div><div>${d.admin ? "Yes" : "No — monitor only"}</div>
      <div>Packet sniffer</div><div>${d.per_app_bytes ? "Running (WinDivert)" : esc(d.sniffer_error || "Off")}</div>
      <div>Hard pause</div><div>${d.dropper ? "Engaged" : d.dropper_error ? "Error: " + esc(d.dropper_error) : "Ready"}</div>
      <div>Firewall/QoS entries</div><div class="num">${d.applied ?? 0}</div>
      <div>Unattributed</div><div class="num">↓ ${fmtB(d.unattributed?.down)} · ↑ ${fmtB(d.unattributed?.up)}</div>
      <div>Uptime</div><div class="num">${Math.floor(d.uptime / 60)} min</div>
    </div><p class="faint" style="font-size:12px;margin-top:14px">Blocks use Windows Defender Firewall rules named <span class="num">NetWarden_*</span>. Upload limits use Windows QoS policies. If anything ever gets stuck, run <span class="num">cleanup.bat</span>.</p></div></div></div>`);
}

function updateCard(d) {
  const u = d.update || {};
  const status = d.sim ? "Not checked in demo mode"
    : u.busy ? (u.busy === "checking" ? "Checking…" : `Updating: ${esc(u.busy)}…`)
    : u.error ? `<span class="up">${esc(u.error)}</span>`
    : u.available ? `<b style="color:var(--ok)">Version ${esc(u.latest)} is available</b>`
    : u.latest ? "You have the latest version" : "Not checked yet";
  const btn = u.can_install ? '<button class="btn primary" data-act="updInstall">Install update</button>'
    : `<button class="btn" data-act="updCheck" ${d.sim || u.busy ? "disabled" : ""}>Check now</button>`;
  return `<div class="kv">
      <div>Installed version</div><div class="num">${esc(d.version || u.current || "?")}</div>
      <div>Latest on GitHub</div><div class="num">${esc(u.latest || "—")}</div>
      <div>Status</div><div>${status}</div>
      <div>Last checked</div><div>${u.checked_at ? ago(u.checked_at) : "—"}</div>
    </div>
    <div class="settings-row" style="border:0;padding-left:0"><div class="t"><b>Check automatically</b><div>Looks for a new version at start-up and twice a day. Nothing installs without your click.</div></div><label class="switch"><input type="checkbox" data-act="setting" data-key="auto_update_check" ${d.settings.auto_update_check ? "checked" : ""}><span></span></label></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">${btn}${u.can_install ? '<button class="btn" data-act="updCheck">Check again</button>' : ""}</div>
    ${u.installed === false && !d.sim ? '<p class="faint" style="font-size:12px;margin-top:10px">This copy runs from a folder, not the installed one. Update it with <span class="num">git pull</span>, or run <span class="num">Install NetWarden.bat</span> to install.</p>' : ""}`;
}

// ------------------------------------------------------------------ render loop
function render(force) {
  if (!S.data) return;
  if (!S.mode) S.mode = S.data.settings.ui_mode === "pro" ? "pro" : "beginner";
  const st = S.data.settings.theme || "classic";
  if (st !== S.theme && !(S.themeLocked && Date.now() - S.themeLocked < 3000)) applyTheme(st);
  renderHeader();
  const key = S.mode + ":" + (S.mode === "pro" ? S.tab : "");
  const app = $("#app");
  if (S.shellKey !== key) {
    app.innerHTML = S.mode === "pro" ? proShell() : beginnerShell();
    app.classList.toggle("pro", S.mode === "pro");
    S.shellKey = key;
    if (S.mode === "pro") bindProInputs();
    force = true;
  }
  if (S.pointerDown && !force) return; // don't swap buttons out from under a click
  if (S.mode === "pro") proUpdate(); else beginnerUpdate();
}

let pollTimer = null, inflight = false;
async function poll(now) {
  if (S.stopped) return;
  if (now) { clearTimeout(pollTimer); }
  if (inflight) { if (now) setTimeout(() => poll(true), 150); return; }
  inflight = true;
  try {
    const full = (S.mode || "") === "pro" ? 1 : 0;
    S.data = await api("GET", `/api/state?full=${full}`);
    S.failures = 0;
    render();
  } catch (e) {
    S.failures++;
    if (S.failures > 2) renderHeader();
    if (String(e.message).includes("token")) {
      $("#app").innerHTML = '<div class="empty" style="margin-top:12vh"><h2>Session expired</h2><p>Open NetWarden again from <b>run.bat</b>.</p></div>';
      inflight = false; return;
    }
  }
  inflight = false;
  clearTimeout(pollTimer);
  // Minimized / hidden window: poll slowly so NetWarden stays light in the background.
  pollTimer = setTimeout(poll, document.hidden ? 5000 : 1000);
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(true); });
window.addEventListener("unhandledrejection", (e) => { e.preventDefault(); });
window.addEventListener("resize", () => { const c = $("#chart"); if (c && S.data) drawChart(c, S.data.history); });
poll();
