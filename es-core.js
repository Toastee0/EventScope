// es-core.js — EventScope v5 — State, constants, utility functions
'use strict';

// ── CONSTANTS ──────────────────────────────────────────────────────────────────

const SESSION_COLORS = ['#DC551F','#5ddba8','#f0a830','#4ab8dc','#a78bfa','#f472b6','#e8703f','#ff3a3a'];

const LT_NAMES = {2:'Interactive',3:'Network',4:'Batch',5:'Service',7:'Unlock',8:'NetCleartext',9:'NewCred',10:'RDP',11:'CachedInteract'};

const LW = {critical:5,high:4,medium:3,low:2,informational:1};

// ── STATE OBJECT ───────────────────────────────────────────────────────────────

const S = {
  rows: [],
  filtered: null,         // post-filter cache (replaces filteredRows)
  sessions: [],
  sessionCurrent: 0,
  pivot: null,            // T-0 timestamp (epoch ms)
  pivotWindow: 3600,      // seconds either side of pivot
  tz: 0,                  // display TZ offset in minutes
  tags: {},               // rowId → [tag strings]
  ignoreEids: new Set(),
  prefs: {},              // loaded preferences
  eidDescs: {},           // eid → friendly description
  colConfig: [],          // column order/visibility
  hostnameGroups: {},
  // v4 operational fields:
  colIndex: {},
  columns: [],
  eventIdCounts: {},
  computerCounts: {},
  channelCounts: {},
  levelCounts: { critical:0, high:0, medium:0, low:0, informational:0 },
  ruleTitleCounts: {},
  ruleIdMap: {},
  sourceCounts: {},
  timeMin: Infinity,
  timeMax: -Infinity,
  format: null,
  filters: {},
  bucketPref: {},
  focusEid: null,
  _seqClusters: null,
  nav: { ctx: null, idx: null, clusterIdx: null, evtIdx: null }
};

// ── CSV PARSING ────────────────────────────────────────────────────────────────

function parseCSVLine(l) {
  const r = [];
  let c = '', q = false;
  for (let i = 0; i < l.length; i++) {
    const ch = l[i];
    if (q) {
      if (ch === '"') {
        if (i + 1 < l.length && l[i+1] === '"') { c += '"'; i++; }
        else q = false;
      } else c += ch;
    } else {
      if (ch === '"') q = true;
      else if (ch === ',') { r.push(c); c = ''; }
      else c += ch;
    }
  }
  r.push(c);
  return r;
}

function parseTS(s) {
  if (!s) return NaN;
  s = s.trim();
  if (/^\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}/.test(s)) {
    let n = s.replace(/\s+(\d{2}:\d{2}:\d{2})/, 'T$1');
    n = n.replace(/\s+([+-]\d{2}:\d{2})/, '$1');
    const d = new Date(n);
    return isNaN(d.getTime()) ? NaN : d.getTime();
  }
  return NaN;
}

function parseDet(d) {
  if (!d) return {};
  const p = {};
  for (const part of d.split('¦')) {
    const t = part.trim(), ci = t.indexOf(':');
    if (ci > 0) {
      const k = t.substring(0, ci).trim(), v = t.substring(ci+1).trim();
      if (k) p[k] = v;
    }
  }
  return p;
}

function normLvl(l) {
  if (!l) return 'informational';
  const s = l.trim().toLowerCase();
  if (s === 'crit' || s === 'critical' || s === '1') return 'critical';
  if (s === 'high' || s === 'error' || s === '2') return 'high';
  if (s === 'med' || s === 'medium' || s === 'warning' || s === 'warn' || s === '3') return 'medium';
  if (s === 'low' || s === 'verbose' || s === '5') return 'low';
  if (s === 'info' || s === 'information' || s === '0' || s === '4' || s === 'logalways') return 'informational';
  return 'informational';
}

// Safe min/max over large arrays — Math.min/max(...arr) blows the call stack past ~125k items
function arrMin(arr) { let m = Infinity;  for (let i = 0; i < arr.length; i++) if (arr[i] < m) m = arr[i]; return m; }
function arrMax(arr) { let m = -Infinity; for (let i = 0; i < arr.length; i++) if (arr[i] > m) m = arr[i]; return m; }
function tsMin(rows) { let m = Infinity;  for (let i = 0; i < rows.length; i++) if (rows[i].ts < m) m = rows[i].ts; return m; }
function tsMax(rows) { let m = -Infinity; for (let i = 0; i < rows.length; i++) if (rows[i].ts > m) m = rows[i].ts; return m; }

// ── STATISTICAL UTILITIES ──────────────────────────────────────────────────────

function cStats(v) {
  const n = v.length;
  if (!n) return {mean:0,std:0,median:0,q1:0,q3:0,iqr:0};
  const s = [...v].sort((a,b) => a-b);
  const sum = s.reduce((a,b) => a+b, 0);
  const m = sum / n;
  const va = s.reduce((a,x) => a + (x-m)**2, 0) / n;
  return {
    mean: m, std: Math.sqrt(va),
    median: s[Math.floor(n/2)],
    q1: s[Math.floor(n*.25)],
    q3: s[Math.floor(n*.75)],
    iqr: s[Math.floor(n*.75)] - s[Math.floor(n*.25)]
  };
}

function dBursts(rows, wMs) {
  if (!rows.length) return [];
  const ts = rows.map(r => r.ts).filter(t => !isNaN(t)).sort((a,b) => a-b);
  if (!ts.length) return [];
  const tMin = ts[0], tMax = ts[ts.length-1];
  const bc = new Array(Math.ceil((tMax-tMin)/wMs)+1).fill(0);
  for (const t of ts) bc[Math.floor((t-tMin)/wMs)]++;
  const st = cStats(bc), th = st.mean + 3*st.std, res = [];
  for (let i = 0; i < bc.length; i++)
    if (bc[i] > th && bc[i] > 5)
      res.push({start:new Date(tMin+i*wMs), end:new Date(tMin+(i+1)*wMs), count:bc[i], zscore:st.std>0?(bc[i]-st.mean)/st.std:0, baseline:st.mean});
  return res.sort((a,b) => b.zscore-a.zscore).slice(0,50);
}

function dFO(cm) {
  const e = Object.entries(cm);
  if (!e.length) return [];
  const c = e.map(x => x[1]), st = cStats(c);
  const lb = st.q1 - 1.5*st.iqr, ub = st.q3 + 1.5*st.iqr, r = [];
  for (const [k, cnt] of e) {
    const z = st.std > 0 ? (cnt - st.mean) / st.std : 0;
    let t = null;
    if (cnt < lb && cnt <= 3) t = 'rare';
    else if (cnt > ub && st.iqr > 0) t = 'high';
    else if (z > 3) t = 'high';
    if (t) r.push({key:k, count:cnt, zscore:z, type:t, mean:st.mean, std:st.std});
  }
  return r.sort((a,b) => Math.abs(b.zscore) - Math.abs(a.zscore));
}

// ── TIMELINE BUCKET UTILITIES ──────────────────────────────────────────────────

function aBMs(tMin, tMax) {
  const s = tMax - tMin;
  if (s < 3600000)   return 60000;
  if (s < 86400000)  return 600000;
  if (s < 604800000) return 3600000;
  return 86400000;
}

function gBMs(p, tMin, tMax) {
  switch (p) {
    case 'minute': return 60000;
    case 'hour':   return 3600000;
    case 'day':    return 86400000;
    default:       return aBMs(tMin, tMax);
  }
}

function bTL(rows, bMs) {
  const ts = rows.map(r => r.ts).filter(t => !isNaN(t));
  if (!ts.length) return {labels:[], values:[], tMin:0};
  const tMin = Math.min(...ts), tMax = Math.max(...ts);
  const c = Math.ceil((tMax-tMin)/bMs)+1, v = new Array(c).fill(0);
  for (const t of ts) v[Math.floor((t-tMin)/bMs)]++;
  const l = [];
  for (let i = 0; i < c; i++) l.push(new Date(tMin+i*bMs));
  return {labels:l, values:v, tMin};
}

function bTLSev(rows, bMs) {
  const v = rows.filter(r => !isNaN(r.ts));
  if (!v.length) return {labels:[], series:{}, tMin:0};
  const tMin = Math.min(...v.map(r => r.ts)), tMax = Math.max(...v.map(r => r.ts));
  const c = Math.ceil((tMax-tMin)/bMs)+1;
  const se = {critical:new Array(c).fill(0), high:new Array(c).fill(0), medium:new Array(c).fill(0), low:new Array(c).fill(0), informational:new Array(c).fill(0)};
  for (const r of v) {
    const i = Math.floor((r.ts-tMin)/bMs);
    if (se[r.lvl]) se[r.lvl][i]++;
  }
  const l = [];
  for (let i = 0; i < c; i++) l.push(new Date(tMin+i*bMs));
  return {labels:l, series:se, tMin};
}

// ── FORMAT UTILITIES ───────────────────────────────────────────────────────────

function fDS(d) {
  return String(d.getUTCMonth()+1).padStart(2,'0') + '-' +
         String(d.getUTCDate()).padStart(2,'0') + ' ' +
         String(d.getUTCHours()).padStart(2,'0') + ':' +
         String(d.getUTCMinutes()).padStart(2,'0');
}

function fDF(d) {
  return d.toISOString().replace('T',' ').replace(/\.\d+Z$/, ' UTC');
}

function fDMs(d) {
  return d.toISOString().replace('T',' ').replace('Z',' UTC');
}

function fDTz(ms) {
  const off = S.tz;
  const d = new Date(ms + off * 60000);
  const h = Math.abs(off / 60 | 0), sign = off >= 0 ? '+' : '-';
  const tzStr = off === 0 ? 'UTC' : `UTC${sign}${h}`;
  return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' ' + tzStr);
}

function fDelta(ms) {
  if (ms < 1000)      return ms.toFixed(0) + 'ms';
  if (ms < 60000)     return (ms/1000).toFixed(1) + 's';
  if (ms < 3600000)   return (ms/60000).toFixed(1) + 'm';
  if (ms < 86400000)  return (ms/3600000).toFixed(1) + 'h';
  return (ms/86400000).toFixed(1) + 'd';
}

// ── HTML / DISPLAY UTILITIES ───────────────────────────────────────────────────

function eH(s) {
  return s ? s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;') : '';
}

function lB(l) {
  const c = {critical:'badge-critical', high:'badge-danger', medium:'badge-warn', low:'badge-info', informational:'badge-ok'};
  return `<span class="badge ${c[l]||'badge-ok'}">${l}</span>`;
}

function lC(l) {
  return {critical:'#ff3a3a', high:'#DC551F', medium:'#f0a830', low:'#4ab8dc', informational:'#5ddba8'}[l] || '#6e7f90';
}

function eL(eid) {
  return `<a class="eid-link" onclick="focusEid('${eH(eid)}')">${eH(eid)}</a>`;
}

function mFT(h, r) {
  return `<table class="data-table"><thead><tr>${h.map(x=>`<th>${x}</th>`).join('')}</tr></thead><tbody>${r.map(x=>`<tr>${x.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}

// ── IP ANONYMISATION ───────────────────────────────────────────────────────────
// Salt is generated once per page load via CSPRNG — never stored, never disclosed.
// Same IP always maps to the same token within a session; reload = new mapping.
// Output ranges are RFC 5737 documentation addresses (can never be real hosts):
//   Internal IPs  → 203.0.113.x  (TEST-NET-3)
//   External IPs  → 198.51.100.x (TEST-NET-2)
//   IPv6          → 2001:db8::x  (RFC 3849)

const _anonSalt = crypto.getRandomValues(new Uint32Array(1))[0];
const _anonIPCache = new Map();  // original → token
const _anonIPUsed  = new Set();  // tokens already assigned (collision guard)

function _ipHash(ip) {
  let h = _anonSalt;
  for (let i = 0; i < ip.length; i++)
    h = Math.imul(h ^ ip.charCodeAt(i), 0x9e3779b9) >>> 0;
  return h;
}

const _reInternal = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
const _reIPv4     = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
const _reIPv6     = /\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;

function anonIP(ip) {
  if (_anonIPCache.has(ip)) return _anonIPCache.get(ip);
  const isV6       = ip.includes(':');
  const isInternal = !isV6 && _reInternal.test(ip);
  const prefix     = isV6 ? null : (isInternal ? '203.0.113' : '198.51.100');
  let token;
  if (isV6) {
    const n = (_ipHash(ip) % 65534) + 1;
    token = `2001:db8::${n.toString(16)}`;
  } else {
    let slot = (_ipHash(ip) % 253) + 1;
    token = `${prefix}.${slot}`;
    while (_anonIPUsed.has(token)) { slot = (slot % 253) + 1; token = `${prefix}.${slot}`; }
  }
  _anonIPUsed.add(token);
  _anonIPCache.set(ip, token);
  return token;
}

// Replace all IPs in a string with anonymised tokens
function anonIPs(str) {
  if (!str) return str;
  return str
    .replace(_reIPv6, m => anonIP(m))
    .replace(_reIPv4, m => anonIP(m));
}

// ── TOAST NOTIFICATION ─────────────────────────────────────────────────────────

function showToast(msg) {
  const el = document.getElementById('copyToast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 2200);
}

// ── TOOLTIP ────────────────────────────────────────────────────────────────────

const ttEl = () => document.getElementById('tooltip');

function sT(x, y, h) {
  const el = ttEl();
  el.innerHTML = h;
  el.style.display = 'block';
  let tx = x + 14, ty = y - 10;
  if (tx + el.offsetWidth > window.innerWidth - 10) tx = x - el.offsetWidth - 10;
  if (ty + el.offsetHeight > window.innerHeight - 10) ty = y - el.offsetHeight;
  el.style.left = tx + 'px';
  el.style.top  = ty + 'px';
}

function hT() {
  ttEl().style.display = 'none';
}

function aCT(el) {
  el.addEventListener('mousemove', e => {
    const cd = el._chartData;
    if (!cd || cd.type !== 'bar') { hT(); return; }
    const r = el.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    if (mx < cd.padL || mx > cd.padL + cd.chartW || my < cd.padT || my > cd.padT + cd.chartH) { hT(); return; }
    const i = Math.floor((mx - cd.padL) / cd.chartW * cd.values.length);
    if (i >= 0 && i < cd.values.length) {
      const l = cd.labels[i] instanceof Date ? fDF(cd.labels[i]) : cd.labels[i];
      sT(e.clientX, e.clientY, `<div style="color:var(--white)">${l}</div><div>Count: <strong style="color:var(--orange)">${cd.values[i].toLocaleString()}</strong></div>`);
    }
  });
  el.addEventListener('mouseleave', hT);
}
