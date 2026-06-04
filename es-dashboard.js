// es-dashboard.js -- EventScope v5 -- Host Profile (landing page)
// Pulls host identity, account profile, network exposure, device inventory
// and activity histograms from the already-ingested rows so an analyst
// can orient themselves in under 10 seconds after loading a CSV.
'use strict';

// ── EXTRACTION HELPERS ────────────────────────────────────────────────────────

// Look for OS version strings anywhere in det (EID 6009, 12, etc.)
// Returns { version, product, buildLine } or null.
function _extractOSLine(rows) {
  // Find first 6009 (System EventLog source, "OS version at boot")
  // Format: "6.3.9600 ¦ Service Pack ¦ ..." or "10.0 ¦ 19045 ¦ ..."
  for (const r of rows) {
    if (String(r.eid) === '6009') {
      const p = parseDet(r.det);
      const parts = Object.values(p).filter(Boolean);
      if (parts.length) return { raw: parts.slice(0, 4).join(' · '), ts: r.ts };
    }
  }
  // Fallback: EID 12 (Microsoft-Windows-Kernel-General "OS started")
  for (const r of rows) {
    if (String(r.eid) === '12' && /kernel-general/i.test(r.rid || '')) {
      const p = parseDet(r.det);
      if (p.MajorVersion || p.BuildVersion) {
        return { raw: `${p.MajorVersion || '?'}.${p.MinorVersion || '0'} build ${p.BuildVersion || '?'}`, ts: r.ts };
      }
    }
  }
  // Fallback: look for OS version in 4688 (process create) NewProcessName paths
  // or in any event's Payload XML OsVersion / ProductName fields
  for (const r of rows) {
    if (!r.extra) continue;
    const ovMatch = r.extra.match(/<Data\s+Name="(?:OsVersion|ProductName)"[^>]*>([^<]+)<\/Data>/i);
    if (ovMatch && ovMatch[1].trim()) {
      return { raw: ovMatch[1].trim(), ts: r.ts };
    }
  }
  return null;
}

function _extractBootEvents(rows) {
  // 6005 = event log started (boot), 6006 = event log stopped (shutdown),
  // 12 = kernel general start, 13 = kernel general stop, 1074 = clean shutdown
  let boots = 0, shutdowns = 0, lastBoot = null, lastShut = null;
  for (const r of rows) {
    const eid = String(r.eid);
    if (eid === '6005' || eid === '12') { boots++; if (!lastBoot || r.ts > lastBoot) lastBoot = r.ts; }
    else if (eid === '6006' || eid === '13' || eid === '1074') { shutdowns++; if (!lastShut || r.ts > lastShut) lastShut = r.ts; }
  }
  return { boots, shutdowns, lastBoot, lastShut };
}

function _extractAccounts(rows) {
  // Aggregate logon activity per user (4624 success, 4625 fail, 4648 explicit)
  // Stores firstFi/lastFi (indices into the filtered-rows array) so a click
  // can jump to the originating event via openDP().
  const users = new Map();
  for (let fi = 0; fi < rows.length; fi++) {
    const r = rows[fi];
    const eid = String(r.eid);
    if (eid !== '4624' && eid !== '4625' && eid !== '4648') continue;
    const p = parseDet(r.det);
    let u = (p.TargetUserName || p.TgtUser || p.UserName || '').trim();
    if (!u || u === '-' || u.endsWith('$')) continue;
    const lo = u.toLowerCase();
    if (LAT_SKIP && LAT_SKIP.has(lo)) continue;
    if (!users.has(lo)) users.set(lo, {
      name: u, successes:0, failures:0, explicit:0,
      firstTs: Infinity, lastTs: -Infinity,
      firstFi: fi, lastFi: fi,
      ips: new Set(), types: new Set(), domains: new Set()
    });
    const e = users.get(lo);
    if (eid === '4624') e.successes++;
    else if (eid === '4625') e.failures++;
    else if (eid === '4648') e.explicit++;
    if (!isNaN(r.ts)) {
      if (r.ts < e.firstTs) { e.firstTs = r.ts; e.firstFi = fi; }
      if (r.ts > e.lastTs)  { e.lastTs  = r.ts; e.lastFi  = fi; }
    }
    const ip = p.IpAddress || p.SrcIP || p.RemoteHost;
    if (ip && ip !== '-') e.ips.add(ip);
    const lt = p.LogonType || p.LgTp || p.Type;
    if (lt && lt !== '-') e.types.add(lt);
    const dom = p.TargetDomainName;
    if (dom && dom !== '-') e.domains.add(dom);
  }
  return [...users.values()].sort((a, b) => (b.successes + b.failures) - (a.successes + a.failures));
}

// EID 4672 -- Special privileges assigned to new logon. Hayabusa drops the
// PrivilegeList field, so fall back to scanning the raw det/extra strings
// for "Se*Privilege" tokens. Both formats stash them somewhere.
const _PRIV_RX = /\bSe[A-Z][A-Za-z]*Privilege\b/g;

function _extractPrivileged(rows) {
  const users = new Map();   // lowercase user -> { name, count, privs:Set, firstTs, lastTs, firstFi, ... }
  for (let fi = 0; fi < rows.length; fi++) {
    const r = rows[fi];
    if (String(r.eid) !== '4672') continue;
    const p = parseDet(r.det);
    let u = (p.SubjectUserName || p.TgtUser || p.TargetUserName || p.UserName || '').trim();
    if (!u || u === '-' || u.endsWith('$')) continue;
    const lo = u.toLowerCase();
    if (LAT_SKIP && LAT_SKIP.has(lo)) continue;
    if (!users.has(lo)) users.set(lo, {
      name: u, count: 0, privs: new Set(),
      firstTs: Infinity, lastTs: -Infinity,
      firstFi: fi, domain: p.SubjectDomainName || ''
    });
    const e = users.get(lo);
    e.count++;
    if (!isNaN(r.ts)) {
      if (r.ts < e.firstTs) { e.firstTs = r.ts; e.firstFi = fi; }
      if (r.ts > e.lastTs)  { e.lastTs  = r.ts; }
    }
    // Privileges: try parsed PrivilegeList first, then regex over det+extra
    const direct = p.PrivilegeList || p.privilegeList || '';
    if (direct) {
      direct.split(/[\s,;]+/).forEach(t => { if (/^Se[A-Z][A-Za-z]*Privilege$/.test(t)) e.privs.add(t); });
    }
    const hay = (r.det || '') + ' ' + (r.extra || '');
    let m;
    _PRIV_RX.lastIndex = 0;
    while ((m = _PRIV_RX.exec(hay)) !== null) e.privs.add(m[0]);
  }
  return [...users.values()].sort((a, b) => b.count - a.count);
}

// Per-channel log span — separate first/last per Windows event channel so
// "Log Span" doesn't lie when Security rolled at 30 days but Application
// has years of garbage. Returns sorted array.
function _extractChannelSpans(rows) {
  const map = new Map();
  for (const r of rows) {
    if (!r.chan || isNaN(r.ts)) continue;
    if (!map.has(r.chan)) map.set(r.chan, { chan: r.chan, first: r.ts, last: r.ts, count: 0 });
    const e = map.get(r.chan);
    if (r.ts < e.first) e.first = r.ts;
    if (r.ts > e.last)  e.last  = r.ts;
    e.count++;
  }
  return [...map.values()].sort((a, b) => b.count - a.count);
}

// Pull a clean IPv4 out of any string the events throw at us. Handles
// "::ffff:1.2.3.4", "1.2.3.4:50123", "[::1]" wrappers, etc.
function _dashCleanIP(s) {
  if (!s || s === '-') return '';
  let v = String(s).trim().toLowerCase();
  if (v.startsWith('[') && v.endsWith(']')) v = v.slice(1, -1);
  v = v.replace(/^::ffff:/, '').replace(/^(?:0+:){5}ffff:/, '');
  const v4 = v.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return v4 ? v4[1] : v;
}

function _extractNetwork(rows) {
  // Distinct hostnames (from r.comp) + distinct source/peer IPs seen in
  // logon/share/Sysmon/WFP/RDP events.
  const hosts = new Set();
  const srcIps = new Set();
  const dstIps = new Set();
  const domains = new Set();
  for (const r of rows) {
    if (r.comp) hosts.add(r.comp);
    const p = parseDet(r.det);
    // Inbound source IP candidates -- includes ClientIP/RemoteHost from
    // RdpCoreTS EID 131 (which arrive as "1.2.3.4:port")
    const sIp = p.SrcIP || p.IpAddress || p.ClientAddress
             || p.SourceAddress || p.SourceIp
             || p.ClientIP || p.RemoteHost;
    const dIp = p.TgtIP || p.DestAddress || p.DestinationIp;
    const sClean = _dashCleanIP(sIp);
    const dClean = _dashCleanIP(dIp);
    if (sClean) srcIps.add(sClean);
    if (dClean) dstIps.add(dClean);
    const d = p.TargetDomainName || p.SubjectDomainName;
    if (d && d !== '-' && !d.endsWith('$')) domains.add(d);
  }
  return { hosts, srcIps, dstIps, domains };
}

// Collect every (hostname, ip) pair observable in the loaded data, with rows
// kept for IPs that never had a hostname attached. Reuses _buildPeers() so
// inbound/outbound classification and hostname extraction stays consistent
// with the Remote Hosts tab. Local adapter IPs from netconfig are folded in
// under the primary host when only one computer is loaded.
function _extractHostIpPairs() {
  const out = [];
  if (typeof _buildPeers !== 'function') return out;
  const { inMap, outMap } = _buildPeers();

  // Merge inbound + outbound so each IP lists every hostname seen against it
  const merged = new Map(); // ip -> { hostnames:Set, hitsIn, hitsOut, first, last }
  const fold = (map, key) => {
    for (const [ip, p] of map) {
      if (!merged.has(ip)) merged.set(ip, {
        hostnames: new Set(), hitsIn: 0, hitsOut: 0,
        first: Infinity, last: -Infinity
      });
      const m = merged.get(ip);
      p.remoteHosts.forEach(h => m.hostnames.add(h));
      m[key] += p.count;
      if (p.first < m.first) m.first = p.first;
      if (p.last  > m.last)  m.last  = p.last;
    }
  };
  fold(inMap,  'hitsIn');
  fold(outMap, 'hitsOut');

  for (const [ip, m] of merged) {
    const hits = m.hitsIn + m.hitsOut;
    const dir  = m.hitsIn && m.hitsOut ? 'both' : (m.hitsIn ? 'in' : 'out');
    if (m.hostnames.size === 0) {
      out.push({ hostname: '', ip, dir, hits, first: m.first, last: m.last });
    } else {
      for (const h of [...m.hostnames].sort()) {
        out.push({ hostname: h, ip, dir, hits, first: m.first, last: m.last });
      }
    }
  }

  // Local host(s) from S.computerCounts, paired with netconfig adapter IPs
  // when the case contains evidence from a single machine.
  const locals = Object.keys(S.computerCounts || {}).filter(Boolean);
  const adapterIPs = [];
  if (locals.length === 1 && S.netconfig && Array.isArray(S.netconfig.adapters)) {
    for (const a of S.netconfig.adapters) {
      if (a && a.ip && /^\d+\.\d+\.\d+\.\d+$/.test(a.ip)) adapterIPs.push(a.ip);
    }
  }
  const localPairs = [];
  if (locals.length === 1 && adapterIPs.length) {
    for (const ip of adapterIPs) localPairs.push({
      hostname: locals[0], ip, dir: 'local', hits: 0, first: Infinity, last: -Infinity
    });
  } else if (locals.length) {
    for (const h of locals) localPairs.push({
      hostname: h, ip: '', dir: 'local', hits: 0, first: Infinity, last: -Infinity
    });
  }

  // Sort peer rows: named first, then by hits desc, then hostname/IP
  out.sort((a, b) => {
    const ah = a.hostname ? 0 : 1, bh = b.hostname ? 0 : 1;
    if (ah !== bh) return ah - bh;
    if (b.hits !== a.hits) return b.hits - a.hits;
    if (a.hostname !== b.hostname) return a.hostname.localeCompare(b.hostname);
    return a.ip.localeCompare(b.ip);
  });

  return [...localPairs, ...out];
}

// NTFS EID 142 "Volume attached" events carry VolumeName (drive letter),
// IsBootVolume, VolumeGuid, and a free-space range sampled at attach time.
// Aggregate per volume so the Dashboard can show what disks were seen.
function _extractDisks(rows) {
  const vols = new Map();
  for (let fi = 0; fi < rows.length; fi++) {
    const r = rows[fi];
    if (String(r.eid) !== '142') continue;
    if (!/ntfs/i.test(r.chan || '') && !/ntfs/i.test(r.rid || '')) continue;
    const p  = parseDet(r.det);
    const pe = (typeof parseEvtxPayload === 'function' ? parseEvtxPayload(r.extra) : null) || {};
    const name = String(p.VolumeName || pe.VolumeName || '').trim();
    if (!name) continue;
    if (!vols.has(name)) vols.set(name, {
      name, guid: '', boot: false,
      lowFree: Infinity, highFree: -Infinity,
      first: Infinity, last: -Infinity,
      count: 0, firstFi: fi
    });
    const v = vols.get(name);
    v.count++;
    if (!isNaN(r.ts)) {
      if (r.ts < v.first) { v.first = r.ts; v.firstFi = fi; }
      if (r.ts > v.last)  v.last  = r.ts;
    }
    const bootRaw = (p.IsBootVolume || pe.IsBootVolume || '').toLowerCase();
    if (bootRaw === 'true') v.boot = true;
    const guid = (p.VolumeGuid || pe.VolumeGuid || '').trim();
    if (guid && !v.guid) v.guid = guid;
    const lo = Number(p.LowestFreeSpaceInBytes  || pe.LowestFreeSpaceInBytes);
    const hi = Number(p.HighestFreeSpaceInBytes || pe.HighestFreeSpaceInBytes);
    if (isFinite(lo) && lo < v.lowFree)  v.lowFree  = lo;
    if (isFinite(hi) && hi > v.highFree) v.highFree = hi;
  }
  return [...vols.values()].sort((a, b) =>
    (b.boot?1:0) - (a.boot?1:0) || a.name.localeCompare(b.name)
  );
}

function _extractUSBDevices(rows) {
  // Look for USB\VID_xxxx&PID_xxxx patterns anywhere in the det or extra field.
  // Also check EID 6416 DeviceId, and Microsoft-Windows-UserPnp events.
  const devs = new Map();    // VID_PID key -> { vid, pid, desc, first, last, count, source }
  const rx = /USB(?:STOR)?[\\#]VID[_-]?([0-9A-Fa-f]{4})[&_]PID[_-]?([0-9A-Fa-f]{4})(?:[\\#&]([^\s¦"<>]+))?/g;
  for (const r of rows) {
    const hay = (r.det || '') + ' ' + (r.extra || '');
    let m;
    rx.lastIndex = 0;
    while ((m = rx.exec(hay)) !== null) {
      const key = `${m[1]}:${m[2]}`.toUpperCase();
      if (!devs.has(key)) devs.set(key, {
        vid: m[1].toUpperCase(), pid: m[2].toUpperCase(),
        desc: '', first: r.ts, last: r.ts, count: 0,
        eids: new Set()
      });
      const d = devs.get(key);
      d.count++;
      d.eids.add(String(r.eid));
      if (!isNaN(r.ts)) {
        if (r.ts < d.first) d.first = r.ts;
        if (r.ts > d.last)  d.last  = r.ts;
      }
      // Try to capture a friendly description from 6416 or nearby fields
      if (!d.desc) {
        const p = parseDet(r.det);
        const cand = p.DeviceDescription || p.DeviceDescrip || p.FriendlyName || p.Model;
        if (cand && cand !== '-') d.desc = cand;
      }
    }
  }
  return [...devs.values()].sort((a, b) => b.count - a.count);
}

// ── RENDER ────────────────────────────────────────────────────────────────────

function rDashboard() {
  const rows = getFR();
  if (!rows.length) {
    document.getElementById('dashboardContent').innerHTML =
      '<div style="padding:40px;text-align:center;color:var(--text-dim);font-family:var(--mono);font-size:12px">No data loaded.</div>';
    document.getElementById('headerStats').innerHTML = '';
    return;
  }

  // Header stats bar — always-visible summary across all tabs. Previously
  // set only by the Overview tab (now retired); Dashboard owns it.
  {
    const tot = rows.length;
    const uC  = new Set(rows.map(r => r.comp)).size;
    const lc  = {critical:0, high:0, medium:0, low:0, informational:0};
    rows.forEach(r => { if (lc[r.lvl] != null) lc[r.lvl]++; });
    document.getElementById('headerStats').innerHTML =
      `<span class="header-stat"><strong>${tot.toLocaleString()}</strong> det</span>
       <span class="header-stat"><span class="sev-pip sev-critical"></span><strong>${lc.critical}</strong></span>
       <span class="header-stat"><span class="sev-pip sev-high"></span><strong>${lc.high}</strong></span>
       <span class="header-stat"><span class="sev-pip sev-medium"></span><strong>${lc.medium}</strong></span>
       <span class="header-stat"><strong>${uC}</strong> hosts</span>`;
  }

  // ── Identity & OS ────────────────────────────────────────────────────────
  const hostCounts = S.computerCounts || {};
  const topHosts   = Object.entries(hostCounts).sort((a,b) => b[1]-a[1]).slice(0, 5);
  const primaryHost = topHosts[0]?.[0] || '—';
  const net        = _extractNetwork(rows);
  const osLine     = _extractOSLine(rows);
  const boots      = _extractBootEvents(rows);
  const tMin       = S.timeMin, tMax = S.timeMax;
  const spanFirst  = isFinite(tMin) ? fDTz(tMin) : '—';
  const spanLast   = isFinite(tMax) ? fDTz(tMax) : '—';
  const spanDelta  = isFinite(tMin) && isFinite(tMax) ? fDelta(tMax - tMin) : '';
  // Filter out junk domain entries
  const realDomains = [...net.domains].filter(d => d && d !== '-' && d !== 'NT AUTHORITY' && d !== 'Window Manager' && d !== 'Font Driver Host' && !d.endsWith('$'));
  const topDomain  = realDomains.sort()[0] || '—';

  // ── Accounts ─────────────────────────────────────────────────────────────
  const users = _extractAccounts(rows);

  // ── USB ──────────────────────────────────────────────────────────────────
  const usb = _extractUSBDevices(rows);

  // ── Histogram: events per day ────────────────────────────────────────────
  const byDay = new Map();
  for (const r of rows) {
    if (isNaN(r.ts)) continue;
    const d = new Date(r.ts);
    const k = d.getUTCFullYear() + '-' + String(d.getUTCMonth()+1).padStart(2,'0') + '-' + String(d.getUTCDate()).padStart(2,'0');
    byDay.set(k, (byDay.get(k) || 0) + 1);
  }
  const days   = [...byDay.keys()].sort();
  const counts = days.map(k => byDay.get(k));

  // ── Level breakdown ──────────────────────────────────────────────────────
  const lc = { critical:0, high:0, medium:0, low:0, informational:0 };
  for (const r of rows) if (lc.hasOwnProperty(r.lvl)) lc[r.lvl]++;

  // ── Top 10 EIDs ──────────────────────────────────────────────────────────
  const ec = {};
  for (const r of rows) ec[r.eid] = (ec[r.eid]||0) + 1;
  const topEids = Object.entries(ec).sort((a,b) => b[1]-a[1]).slice(0, 10);

  // ── Channel spans (for the Log Span breakdown) ───────────────────────────
  const chanSpans = _extractChannelSpans(rows);

  // ── Host ↔ IP pairs ──────────────────────────────────────────────────────
  const hostIpPairs = _extractHostIpPairs();
  const hostIpNoName = hostIpPairs.filter(p => p.ip && !p.hostname).length;

  // ── Disks / NTFS volumes ─────────────────────────────────────────────────
  const disks = _extractDisks(rows);

  // ── Privileged logons (4672) ─────────────────────────────────────────────
  const priv = _extractPrivileged(rows);

  // ── BUILD DOM ────────────────────────────────────────────────────────────

  const card = (label, value, sub, borderColor) =>
    `<div class="card"${borderColor?` style="border-left:3px solid ${borderColor}"`:''}>
      <div class="card-label">${label}</div>
      <div class="card-value" style="font-size:${String(value).length > 16 ? '15px' : '22px'}">${value}</div>
      ${sub ? `<div class="card-sub">${sub}</div>` : ''}
    </div>`;

  const identityCards =
    card('Primary Host', eH(primaryHost),
         Object.keys(hostCounts).length > 1 ? `+${Object.keys(hostCounts).length-1} others` : '1 host') +
    card('Operating System', osLine ? eH(osLine.raw) : '<span style="color:var(--text-dim)">unknown</span>',
         osLine ? 'from EID 6009 / 12' : 'no boot record in logs') +
    card('Domain / Workgroup', eH(topDomain),
         realDomains.length > 1 ? `${realDomains.length} distinct` : '') +
    card('Total Span', spanDelta || '—',
         `${eH(spanFirst)} &rarr; ${eH(spanLast)}`, 'var(--orange)') +
    card('Boots / Shutdowns', `${boots.boots} / ${boots.shutdowns}`,
         boots.lastBoot ? 'last boot ' + fDTz(boots.lastBoot) : '');

  // Accounts table -- show ALL accounts, click jumps to first-seen event
  const userRows = users.map(u => {
    const totalLogon = u.successes + u.failures;
    const failPct = totalLogon > 0 ? (u.failures / totalLogon * 100).toFixed(0) : '0';
    const navAttr = isFinite(u.firstTs)
      ? `style="cursor:pointer" data-nav-idx="${u.firstFi}" onclick="openDP(${u.firstFi},'dashboard')" title="Jump to first-seen event for ${eH(u.name)}"`
      : 'style="cursor:default"';
    return `<tr ${navAttr}>
      <td style="font-weight:600">${eH(u.name)}</td>
      <td style="font-family:var(--mono);font-size:11px">${[...u.domains].slice(0,2).join(', ') || '—'}</td>
      <td style="text-align:right;font-family:var(--mono);color:var(--success)">${u.successes}</td>
      <td style="text-align:right;font-family:var(--mono);color:${u.failures>0?'var(--high)':'var(--text-dim)'}">${u.failures}</td>
      <td style="text-align:right;font-family:var(--mono);font-size:11px;color:var(--text-dim)">${u.failures>0?failPct+'%':'—'}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${[...u.types].slice(0,3).map(t => fmtLT(t)).join(', ')}</td>
      <td style="text-align:right;font-family:var(--mono);font-size:11px;color:var(--text-dim)">${u.ips.size}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--orange)">${isFinite(u.firstTs)?fDTz(u.firstTs):'—'}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${isFinite(u.lastTs)?fDTz(u.lastTs):'—'}</td>
    </tr>`;
  }).join('');

  const usersSection = users.length
    ? `<table class="data-table"><thead><tr>
        <th>Account</th><th>Domain(s)</th>
        <th style="text-align:right">Success</th>
        <th style="text-align:right">Fail</th>
        <th style="text-align:right">Fail%</th>
        <th>Logon Types</th>
        <th style="text-align:right">Src IPs</th>
        <th>First Seen</th>
        <th>Last Seen</th>
      </tr></thead><tbody>${userRows}</tbody></table>`
    : '<div style="padding:16px;color:var(--text-dim);font-family:var(--mono);font-size:12px">No 4624/4625/4648 logon events in current filter.</div>';

  // Network section
  const netSection =
    `<div class="two-col">
      ${card('Known Hosts',    net.hosts.size.toLocaleString(),    topHosts.slice(0,3).map(([h]) => eH(h)).join(', '))}
      ${card('Source Peer IPs', net.srcIps.size.toLocaleString(),  'inbound (logon, SMB, RPC)')}
      ${card('Destination Peer IPs', net.dstIps.size.toLocaleString(), 'outbound (WFP, Sysmon NetConnect)')}
      ${card('Domains',        net.domains.size.toLocaleString(),  [...net.domains].slice(0,3).join(', '))}
    </div>`;

  // USB table
  const usbRows = usb.slice(0, 15).map(d => {
    return `<tr>
      <td style="font-family:var(--mono);font-weight:600;color:var(--orange)">VID_${d.vid}</td>
      <td style="font-family:var(--mono);color:var(--info)">PID_${d.pid}</td>
      <td>${eH(d.desc) || '<span style="color:var(--text-dim)">—</span>'}</td>
      <td style="text-align:right;font-family:var(--mono)">${d.count}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${[...d.eids].sort().slice(0,4).join(', ')}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${isFinite(d.first)?fDTz(d.first):'—'}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${isFinite(d.last)?fDTz(d.last):'—'}</td>
    </tr>`;
  }).join('');

  const usbSection = usb.length
    ? `<table class="data-table"><thead><tr>
        <th>Vendor</th><th>Product</th><th>Description</th>
        <th style="text-align:right">Sightings</th>
        <th>Event IDs</th>
        <th>First Seen</th><th>Last Seen</th>
      </tr></thead><tbody>${usbRows}</tbody></table>
      ${usb.length > 15 ? `<div style="padding:8px;font-family:var(--mono);font-size:11px;color:var(--text-dim);text-align:center">\u2026 ${usb.length-15} more devices</div>` : ''}`
    : '<div style="padding:16px;color:var(--text-dim);font-family:var(--mono);font-size:12px">No USB VID/PID patterns found in event details. Enable Microsoft-Windows-DriverFrameworks-UserMode/Operational or Security EID 6416 for full device telemetry.</div>';

  // Top EIDs list -- includes friendly description from win-security-eids.json
  const topEidRows = topEids.map(([eid, count]) => {
    const pct = (count / rows.length * 100).toFixed(1);
    const barW = Math.max(2, (count / topEids[0][1]) * 100);
    const desc = getEidDesc(eid) || '';
    return `<div style="display:grid;grid-template-columns:70px 1fr 70px 95px;align-items:center;gap:10px;padding:5px 0;border-bottom:1px solid var(--border)" title="${eH(desc)}">
      <div style="font-family:var(--mono);font-size:11px">${eL(eid)}</div>
      <div style="font-size:11px;color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${eH(desc) || '<span style="color:var(--text-dim);font-style:italic">no description</span>'}</div>
      <div style="height:10px;background:var(--surface2);border-radius:2px;overflow:hidden"><div style="width:${barW}%;height:100%;background:var(--orange);opacity:0.7"></div></div>
      <div style="font-family:var(--mono);font-size:11px;text-align:right;color:var(--text-dim)">${count.toLocaleString()} (${pct}%)</div>
    </div>`;
  }).join('');

  // Privileged logons table (4672)
  // Highlight the dangerous ones a separate colour: SeDebug, SeImpersonate,
  // SeAssignPrimaryToken, SeTcb, SeBackup, SeRestore, SeLoadDriver, SeTakeOwnership
  const _DANGER_PRIVS = new Set([
    'SeDebugPrivilege','SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege',
    'SeTcbPrivilege','SeBackupPrivilege','SeRestorePrivilege',
    'SeLoadDriverPrivilege','SeTakeOwnershipPrivilege','SeCreateTokenPrivilege',
    'SeRelabelPrivilege'
  ]);
  const fmtPriv = name => {
    const isDanger = _DANGER_PRIVS.has(name);
    const short   = name.replace(/^Se/, '').replace(/Privilege$/, '');
    return `<span style="font-family:var(--mono);font-size:10px;padding:1px 5px;border-radius:2px;margin:0 2px 2px 0;display:inline-block;background:${isDanger?'var(--critical-dim)':'var(--surface3)'};color:${isDanger?'var(--high)':'var(--text-dim)'};font-weight:${isDanger?'600':'400'}">${eH(short)}</span>`;
  };
  const privRows = priv.map(u => {
    const dangerCount = [...u.privs].filter(p => _DANGER_PRIVS.has(p)).length;
    const privBadges  = [...u.privs].sort().map(fmtPriv).join('');
    return `<tr style="cursor:pointer" data-nav-idx="${u.firstFi}" onclick="openDP(${u.firstFi},'dashboard')" title="Jump to first 4672 for ${eH(u.name)}">
      <td style="font-weight:600">${eH(u.name)}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${eH(u.domain) || '\u2014'}</td>
      <td style="text-align:right;font-family:var(--mono)">${u.count.toLocaleString()}</td>
      <td style="text-align:right;font-family:var(--mono);font-size:11px"><span style="color:${dangerCount>0?'var(--high)':'var(--text-dim)'};font-weight:${dangerCount>0?'600':'400'}">${dangerCount}</span><span style="color:var(--text-dim)"> / ${u.privs.size}</span></td>
      <td style="line-height:1.8;max-width:560px">${privBadges}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--orange)">${isFinite(u.firstTs)?fDTz(u.firstTs):'\u2014'}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${isFinite(u.lastTs)?fDTz(u.lastTs):'\u2014'}</td>
    </tr>`;
  }).join('');
  const privSection = priv.length
    ? `<table class="data-table"><thead><tr>
        <th>Account</th>
        <th>Domain</th>
        <th style="text-align:right">4672 hits</th>
        <th style="text-align:right" title="Privileges flagged as high-risk / many privileges">Risk / Total</th>
        <th>Privileges</th>
        <th>First Seen</th>
        <th>Last Seen</th>
      </tr></thead><tbody>${privRows}</tbody></table>`
    : '<div style="padding:16px;color:var(--text-dim);font-family:var(--mono);font-size:12px">No EID 4672 (Special privileges assigned to new logon) events in current filter.</div>';

  // Channel-span breakdown table
  const chanSpanRows = chanSpans.map(c => {
    const span = c.last - c.first;
    return `<tr>
      <td style="font-family:var(--mono);font-size:11px">${eH(c.chan)}</td>
      <td style="text-align:right;font-family:var(--mono);font-size:11px">${c.count.toLocaleString()}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim);white-space:nowrap">${fDTz(c.first)}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim);white-space:nowrap">${fDTz(c.last)}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--orange);white-space:nowrap">${span > 0 ? fDelta(span) : '\u2014'}</td>
    </tr>`;
  }).join('');
  const chanSpanSection = chanSpans.length
    ? `<table class="data-table"><thead><tr>
        <th>Channel</th>
        <th style="text-align:right">Events</th>
        <th>First Event</th>
        <th>Last Event</th>
        <th>Span</th>
      </tr></thead><tbody>${chanSpanRows}</tbody></table>`
    : '<div style="padding:16px;color:var(--text-dim);font-family:var(--mono);font-size:12px">No channel data.</div>';

  // Host ↔ IP pair table — every observed hostname/IP pairing, plus IPs that
  // never had a hostname attached. Copy button emits tab-separated text.
  const _dirTag = d => {
    if (d === 'local') return '<span style="font-size:9px;background:var(--surface3);color:var(--text);padding:1px 5px;border-radius:2px;font-weight:600">LOCAL</span>';
    if (d === 'both')  return '<span style="font-size:9px;background:var(--orange-dim);color:var(--orange);padding:1px 5px;border-radius:2px;font-weight:600">IN+OUT</span>';
    if (d === 'in')    return '<span style="font-size:9px;background:var(--surface3);color:var(--text-dim);padding:1px 5px;border-radius:2px">IN</span>';
    if (d === 'out')   return '<span style="font-size:9px;background:var(--surface3);color:var(--text-dim);padding:1px 5px;border-radius:2px">OUT</span>';
    return '';
  };
  const hostIpRows = hostIpPairs.map(p => `<tr>
    <td style="font-family:var(--mono);font-weight:${p.hostname?'600':'400'};color:${p.hostname?'var(--text)':'var(--text-dim)'}">${p.hostname ? eH(p.hostname) : '<span style="font-style:italic">— no hostname —</span>'}</td>
    <td style="font-family:var(--mono);color:${p.ip?'var(--orange)':'var(--text-dim)'}">${p.ip ? eH(p.ip) : '—'}</td>
    <td>${_dirTag(p.dir)}</td>
    <td style="text-align:right;font-family:var(--mono);font-size:11px;color:var(--text-dim)">${p.hits ? p.hits.toLocaleString() : '—'}</td>
  </tr>`).join('');
  const hostIpSection = hostIpPairs.length
    ? `<table class="data-table"><thead><tr>
        <th>Hostname</th><th>IP</th><th>Direction</th><th style="text-align:right">Hits</th>
      </tr></thead><tbody>${hostIpRows}</tbody></table>`
    : '<div style="padding:16px;color:var(--text-dim);font-family:var(--mono);font-size:12px">No host/IP pairs observed in current filter.</div>';

  // Disk/volume table — one row per distinct volume seen in NTFS EID 142.
  // Free-space columns show the range observed across attach events, not a
  // live figure. Click jumps to the first 142 for that volume.
  const diskRows = disks.map(v => {
    const nav = isFinite(v.first)
      ? `style="cursor:pointer" data-nav-idx="${v.firstFi}" onclick="openDP(${v.firstFi},'dashboard')" title="Jump to first EID 142 for ${eH(v.name)}"`
      : 'style="cursor:default"';
    const bootCell = v.boot
      ? '<span style="font-size:9px;background:var(--orange-dim);color:var(--orange);padding:1px 5px;border-radius:2px;font-weight:600">BOOT</span>'
      : '<span style="color:var(--text-dim)">—</span>';
    const loStr = isFinite(v.lowFree)  ? fmtBytes(v.lowFree)  : '—';
    const hiStr = isFinite(v.highFree) ? fmtBytes(v.highFree) : '—';
    return `<tr ${nav}>
      <td style="font-family:var(--mono);font-weight:600;color:var(--orange)">${eH(v.name)}</td>
      <td>${bootCell}</td>
      <td style="text-align:right;font-family:var(--mono);font-size:11px">${loStr}</td>
      <td style="text-align:right;font-family:var(--mono);font-size:11px">${hiStr}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text-dim);word-break:break-all">${eH(v.guid) || '—'}</td>
      <td style="text-align:right;font-family:var(--mono)">${v.count.toLocaleString()}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--orange);white-space:nowrap">${isFinite(v.first)?fDTz(v.first):'—'}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim);white-space:nowrap">${isFinite(v.last)?fDTz(v.last):'—'}</td>
    </tr>`;
  }).join('');
  const diskSection = disks.length
    ? `<table class="data-table"><thead><tr>
        <th>Volume</th><th>Boot</th>
        <th style="text-align:right">Lowest Free</th>
        <th style="text-align:right">Highest Free</th>
        <th>Volume GUID</th>
        <th style="text-align:right">Attach Events</th>
        <th>First Seen</th><th>Last Seen</th>
      </tr></thead><tbody>${diskRows}</tbody></table>`
    : '<div style="padding:16px;color:var(--text-dim);font-family:var(--mono);font-size:12px">No Microsoft-Windows-Ntfs/Operational EID 142 events in current filter. Enable that channel to capture volume attach metadata.</div>';

  document.getElementById('dashboardContent').innerHTML = `
    <div style="margin-bottom:18px;font-family:var(--mono);font-size:11px;color:var(--text-dim)">
      Snapshot of the loaded evidence. Numbers respect the current filter bar.
    </div>

    <div class="chart-box" style="margin-bottom:14px">
      <div class="chart-header"><span class="chart-title">Host Identity</span></div>
      <div class="card-grid">${identityCards}</div>
    </div>

    <div class="two-col">
      <div class="chart-box">
        <div class="chart-header"><span class="chart-title">Activity Histogram &mdash; events per UTC day</span></div>
        <canvas class="chart-canvas" id="dashHistCanvas" style="height:180px"></canvas>
      </div>
      <div class="chart-box">
        <div class="chart-header"><span class="chart-title">Top 10 Event IDs</span></div>
        <div style="padding:8px 0">${topEidRows}</div>
      </div>
    </div>

    <div class="chart-box" style="margin-bottom:14px">
      <div class="chart-header"><span class="chart-title">Privileged Logons &mdash; admin sessions and what they got</span>
        <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim);margin-left:auto">EID 4672 &mdash; SeDebug / SeImpersonate / SeAssignPrimaryToken etc.</span>
      </div>
      <div class="data-table-wrap">${privSection}</div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:14px">
      <div class="chart-box" style="margin-bottom:0">
        <div class="chart-header">
          <span class="chart-title">Log Span by Channel</span>
        </div>
        <div class="data-table-wrap">${chanSpanSection}</div>
      </div>
      <div class="chart-box" style="margin-bottom:0">
        <div class="chart-header"><span class="chart-title">User Accounts</span>
          <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim);margin-left:auto">4624 / 4625 / 4648</span>
        </div>
        <div class="data-table-wrap">${usersSection}</div>
      </div>
      <div class="chart-box" style="margin-bottom:0">
        <div class="chart-header"><span class="chart-title">Network</span>
          <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim);margin-left:auto">as seen in logs</span>
        </div>
        ${netSection}
      </div>
    </div>

    <div class="chart-box" style="margin-bottom:14px">
      <div class="chart-header"><span class="chart-title">Host &harr; IP Pairs</span>
        <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim);margin-left:auto">${hostIpPairs.length.toLocaleString()} pair${hostIpPairs.length===1?'':'s'}${hostIpNoName?` &middot; ${hostIpNoName} IP${hostIpNoName===1?'':'s'} without hostname`:''}</span>
        <button class="copy-btn" onclick="copyHostIpPairs()" style="margin-left:10px" title="Copy hostname&lt;TAB&gt;ip, one per line — IPs without a hostname copy with a leading tab so the IP column stays aligned">Copy</button>
      </div>
      <div class="data-table-wrap">${hostIpSection}</div>
    </div>

    <div class="chart-box" style="margin-bottom:14px">
      <div class="chart-header"><span class="chart-title">Disks / NTFS Volumes</span>
        <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim);margin-left:auto">Microsoft-Windows-Ntfs/Operational EID 142 &mdash; volume attach metadata</span>
      </div>
      <div class="data-table-wrap">${diskSection}</div>
    </div>

    <div class="chart-box" style="margin-bottom:14px">
      <div class="chart-header"><span class="chart-title">USB Devices Observed</span>
        <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim);margin-left:auto">VID/PID patterns from event details &amp; payload</span>
      </div>
      <div class="data-table-wrap">${usbSection}</div>
    </div>
  `;

  // Draw histogram
  const cvs = document.getElementById('dashHistCanvas');
  if (cvs && days.length) drawBC(cvs, days, counts);
}

// Copy all host/IP pairs as tab-separated text. IPs without a hostname keep
// a leading tab so a clipboard paste into Excel / netmap.html still aligns
// the IP column. Pairs are deduplicated on (hostname, ip).
function copyHostIpPairs() {
  const pairs = _extractHostIpPairs();
  if (!pairs.length) { showToast('No host/IP pairs to copy'); return; }
  const seen = new Set();
  const lines = [];
  for (const p of pairs) {
    const key = p.hostname.toLowerCase() + '\t' + p.ip.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    lines.push(`${p.hostname}\t${p.ip}`);
  }
  navigator.clipboard.writeText(lines.join('\n')).then(
    () => showToast(`Copied ${lines.length} host/IP pair${lines.length===1?'':'s'}`),
    () => showToast('Clipboard copy failed')
  );
}
