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
    return;
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

  document.getElementById('dashboardContent').innerHTML = `
    <div style="margin-bottom:18px;font-family:var(--mono);font-size:11px;color:var(--text-dim)">
      Snapshot of the loaded evidence. Numbers respect the current filter bar.
    </div>

    <div class="chart-box" style="margin-bottom:14px">
      <div class="chart-header"><span class="chart-title">Host Identity</span></div>
      <div class="card-grid">${identityCards}</div>
    </div>

    <div class="chart-box" style="margin-bottom:14px">
      <div class="chart-header">
        <span class="chart-title">Log Span by Channel</span>
        <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim);margin-left:auto">each channel rolls independently</span>
      </div>
      <div style="display:flex;gap:18px;align-items:flex-start">
        <div class="data-table-wrap" style="flex:0 1 auto;max-width:fit-content">${chanSpanSection}</div>
        <div style="flex:1;min-width:200px" id="dashChanExtra"></div>
      </div>
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
      <div class="chart-header"><span class="chart-title">User Accounts &mdash; by logon activity</span>
        <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim);margin-left:auto">extracted from 4624 / 4625 / 4648</span>
      </div>
      <div class="data-table-wrap">${usersSection}</div>
    </div>

    <div class="chart-box" style="margin-bottom:14px">
      <div class="chart-header"><span class="chart-title">Privileged Logons &mdash; admin sessions and what they got</span>
        <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim);margin-left:auto">EID 4672 &mdash; SeDebug / SeImpersonate / SeAssignPrimaryToken etc. highlighted as high-risk</span>
      </div>
      <div class="data-table-wrap">${privSection}</div>
    </div>

    <div class="chart-box" style="margin-bottom:14px">
      <div class="chart-header"><span class="chart-title">Network &mdash; as seen in logs</span>
        <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim);margin-left:auto">source IPs in auth/share events, dest IPs in WFP/Sysmon</span>
      </div>
      ${netSection}
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
