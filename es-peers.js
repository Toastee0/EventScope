// es-peers.js -- EventScope v5 -- Remote Hosts (IP contact map)
// "Who touched me" (inbound) and "Who did I touch" (outbound) based on IPs
// extracted from event Details. Handles both Hayabusa aliases and raw Windows
// field names.
'use strict';

// ── EID CLASSIFICATION ────────────────────────────────────────────────────────
// dir:'in'  -- remote initiated, IP is the peer in srcFields
// dir:'out' -- local initiated, IP is the peer in dstFields
// dir:'wfp' -- 5156/5157, use Direction field; both src/dst meaningful
// dir:'sysmon' -- Sysmon 3, use Initiated field

const PEER_EID_MAP = {
  // ── Inbound: authentication / logons ────────────────────────────────────────
  '4624': { dir:'in',  src:['SrcIP','IpAddress'],          label:'Logon Success'      },
  '4625': { dir:'in',  src:['SrcIP','IpAddress'],          label:'Logon Failure'      },
  '4648': { dir:'in',  src:['SrcIP','IpAddress'],          label:'Explicit Creds'     },
  '4768': { dir:'in',  src:['SrcIP','IpAddress'],          label:'Kerberos TGT'       },
  '4769': { dir:'in',  src:['SrcIP','IpAddress'],          label:'Kerberos Service'   },
  '4771': { dir:'in',  src:['SrcIP','IpAddress'],          label:'Kerberos PreAuth Fail' },
  '4778': { dir:'in',  src:['SrcIP','ClientAddress'],      label:'Session Reconnect'  },
  '4779': { dir:'in',  src:['SrcIP','ClientAddress'],      label:'Session Disconnect' },
  '4825': { dir:'in',  src:['SrcIP','ClientAddress'],      label:'RDP Denied'         },
  // RemoteDesktopServices-RdpCoreTS/Operational. ClientIP arrives as
  // "1.2.3.4:50123" -- _normIP() extracts the v4 substring automatically.
  '131':  { dir:'in',  src:['ClientIP','RemoteHost'],      label:'RDP Connection',   chan:'RdpCoreTS' },
  // ── Inbound: share access ───────────────────────────────────────────────────
  '5140': { dir:'in',  src:['SrcIP','IpAddress'],          label:'Share Access'       },
  '5145': { dir:'in',  src:['SrcIP','IpAddress'],          label:'Share Detail'       },
  // ── Inbound: SMBServer Audit (channel: Microsoft-Windows-SMBServer/Audit) ──
  '551':  { dir:'in',  src:['ClientName','RemoteHost','ClientIp'], label:'SMB Logon Rejected', chan:'SMBServer' },
  '1006': { dir:'in',  src:['ClientName','RemoteHost','ClientIp'], label:'SMB Auth Failure',   chan:'SMBServer' },
  // ── Bidirectional: WFP (Windows Filtering Platform) ────────────────────────
  '5156': { dir:'wfp', src:['SrcIP','SourceAddress'], dst:['TgtIP','DestAddress'],
            dirField:'Direction', label:'WFP Allow' },
  '5157': { dir:'wfp', src:['SrcIP','SourceAddress'], dst:['TgtIP','DestAddress'],
            dirField:'Direction', label:'WFP Block' },
  // ── Bidirectional: Sysmon ──────────────────────────────────────────────────
  '3':    { dir:'sysmon', src:['SrcIP','SourceIp'], dst:['TgtIP','DestinationIp'],
            dirField:'Initiated', label:'Sysmon NetConnect',
            chan:'Sysmon' },
};

// WFP Direction values: %%14592 = Inbound, %%14593 = Outbound
function _wfpDir(d) {
  if (!d) return null;
  if (d.indexOf('14592') !== -1 || /inbound/i.test(d))  return 'in';
  if (d.indexOf('14593') !== -1 || /outbound/i.test(d)) return 'out';
  return null;
}

function _isUselessIP(ip) {
  if (!ip) return true;
  const s = _normIP(ip);
  if (!s || s === '-' || s === '::' || s === '::1' || s === '0.0.0.0') return true;
  if (s.startsWith('127.')) return true;
  if (s.startsWith('fe80:')) return true;       // link-local IPv6
  if (s.startsWith('169.254.')) return true;    // APIPA
  return false;
}

// Normalise an IP value pulled from event details so RFC1918 checks work.
// Handles: brackets [::1], zone ids %eth0, CIDR /24, ports :445,
// IPv4-mapped IPv6 in collapsed (::ffff:1.2.3.4) and expanded
// (0:0:0:0:0:ffff:1.2.3.4 / 0000:...) forms, and any wrapper text by
// extracting the first embedded IPv4 substring as a final fallback.
function _normIP(ip) {
  if (!ip) return '';
  let s = ip.trim().toLowerCase();
  // Strip surrounding brackets ([::1] -> ::1)
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  // Strip zone id (fe80::1%eth0 -> fe80::1)
  const pct = s.indexOf('%');
  if (pct !== -1) s = s.slice(0, pct);
  // Strip CIDR mask (192.168.1.0/24 -> 192.168.1.0)
  const slash = s.indexOf('/');
  if (slash !== -1) s = s.slice(0, slash);
  // Strip IPv4-mapped IPv6 prefix variants
  s = s.replace(/^::ffff:/, '');
  s = s.replace(/^(?:0+:){5}ffff:/, '');
  // If there's any IPv4 substring anywhere, prefer that.
  // Catches "1.2.3.4:445", "1.2.3.4 (foo)", "ipv4:1.2.3.4", etc.
  const v4 = s.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  if (v4) return v4[1];
  return s;
}

function _isPrivateIP(ip) {
  const s = _normIP(ip);
  if (!s) return false;
  if (/^10\./.test(s)) return true;
  if (/^192\.168\./.test(s)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(s)) return true;
  if (/^fc/i.test(s) || /^fd/i.test(s)) return true;  // ULA IPv6
  return false;
}

// 172.16.0.0/12 is RFC1918 but in DFIR casework almost always appears
// as a VPN concentrator range rather than on-LAN traffic. Flagged with
// a "?" because it's a heuristic, not a confirmation.
function _isLikelyVPN(ip) {
  const s = _normIP(ip);
  return /^172\.(1[6-9]|2\d|3[01])\./.test(s);
}

function _firstField(p, names) {
  for (const n of names) {
    const v = (p[n] || '').trim();
    if (v && v !== '-') return v;
  }
  return '';
}

function _getUser(p) {
  return _firstField(p, [
    'TgtUser','TargetUserName','SrcUser','SubjectUserName',
    'UserName','AccountName','User'
  ]);
}

// Extract a remote hostname from event details. Different EIDs use different
// keys; ClientName is sometimes the same as the IP, so filter that case out.
function _getSrcHost(p) {
  const v = _firstField(p, [
    'SrcComp','WorkstationName','ClientName','Workstation',
    'SourceHostname','RemoteHost','Source Workstation'
  ]);
  if (!v) return '';
  // ClientName fields occasionally hold the IP itself; ignore those
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) return '';
  return v.replace(/\\$/, '');   // strip trailing slash NetBIOS artefact
}

function _getDstHost(p) {
  const v = _firstField(p, [
    'DestinationHostname','TgtComp','TargetServerName','TgtSvr','TargetInfo'
  ]);
  if (!v) return '';
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) return '';
  return v;
}

// Friendly LogonType names. Hayabusa often pre-decodes ("3 - NETWORK")
// so we extract any leading number and re-format consistently.
const _LOGON_TYPES = {
  '0':  'System',
  '2':  'Interactive',
  '3':  'Network',
  '4':  'Batch',
  '5':  'Service',
  '7':  'Unlock',
  '8':  'NetworkCleartext',
  '9':  'NewCredentials',
  '10': 'RemoteInteractive',
  '11': 'CachedInteractive',
  '12': 'CachedRemoteInteractive',
  '13': 'CachedUnlock',
};
function _decodeLogonType(v) {
  if (!v) return '';
  const m = String(v).match(/(\d+)/);
  if (!m) return v;
  const n = m[1];
  return _LOGON_TYPES[n] ? `${n}-${_LOGON_TYPES[n]}` : v;
}

// Impersonation level codes from Security 4624. Some sources emit the
// numeric code, others emit "%%1833" style placeholders, others a name.
const _IMP_LEVELS = {
  '0':      'Anonymous',
  '1':      'Identification',
  '2':      'Impersonation',
  '3':      'Delegation',
  '%%1832': 'Identification',
  '%%1833': 'Impersonation',
  '%%1840': 'Delegation',
  '%%1841': 'Anonymous',
};
function _decodeImpLevel(v) {
  if (!v) return '';
  return _IMP_LEVELS[v] || v;
}

// Pull a port number off an "ip:port" or "[ipv6]:port" string. Returns
// '' when no recognisable port is present. _normIP strips it for the IP
// side; this is the complement so we can keep both halves.
function _extractPort(s) {
  if (!s) return '';
  const v = String(s).trim();
  // [::1]:443 -> 443
  const bracket = v.match(/^\[[^\]]+\]:(\d{1,5})$/);
  if (bracket) return bracket[1];
  // 1.2.3.4:50123 -- only treat trailing digits as a port if exactly
  // one colon is present (so we don't mis-parse pure IPv6 like 2001::1)
  if ((v.match(/:/g) || []).length === 1) {
    const m = v.match(/:(\d{1,5})$/);
    if (m) return m[1];
  }
  return '';
}

// ── STATE ─────────────────────────────────────────────────────────────────────

let _peersExpanded = null;        // 'in:1.2.3.4' or 'out:5.6.7.8'
let _peersIncludePrivate = true;
let _peersOnlyFails      = false;

// ── BUILD ─────────────────────────────────────────────────────────────────────

function _buildPeers() {
  const inMap = new Map();    // ip -> {ip, count, fail, eids:Set, users:Set, comps:Set, first, last, indices:[]}
  const outMap = new Map();
  const all = getFR();

  const ensure = (m, ip) => {
    if (!m.has(ip)) m.set(ip, {
      ip, count:0, fail:0,
      eids: new Set(), users: new Set(), comps: new Set(),
      remoteHosts: new Set(),
      logonTypes:    new Set(),    // 2/3/10/etc -- decoded for display
      logonProcs:    new Set(),    // NtLmSsp, Kerberos, Advapi, ...
      authPackages:  new Set(),    // NTLM, Kerberos, Negotiate
      lmPackages:    new Set(),    // NTLM V1, NTLM V2, LM
      impLevels:     new Set(),    // Impersonation level
      ports:         new Set(),    // remote-side port numbers (string form)
      first: Infinity, last: -Infinity, indices: []
    });
    return m.get(ip);
  };

  const record = (m, ipRaw, r, fi, dirHint) => {
    if (_isUselessIP(ipRaw)) return;
    const ip = _normIP(ipRaw);
    if (!_peersIncludePrivate && _isPrivateIP(ip)) return;
    const isFail = String(r.eid) === '4625' || String(r.eid) === '4771'
                || String(r.eid) === '4776' || String(r.eid) === '551'
                || String(r.eid) === '5157' || String(r.eid) === '4825';
    if (_peersOnlyFails && !isFail) return;
    const e = ensure(m, ip);
    e.count++;
    if (isFail) e.fail++;
    e.eids.add(String(r.eid));
    if (r.comp) e.comps.add(r.comp);
    const det = parseDet(r.det);
    const u = _getUser(det);
    if (u) e.users.add(u);
    // Capture the remote hostname seen in this event (from WorkstationName,
    // SrcComp, ClientName, etc.) -- only meaningful for inbound peers
    const rh = (dirHint === 'in') ? _getSrcHost(det) : _getDstHost(det);
    if (rh && rh.toLowerCase() !== ip.toLowerCase()) e.remoteHosts.add(rh);
    // Logon mechanics (4624/4625/4648 carry these; harmless if absent)
    const lt = _firstField(det, ['LogonType','Type']);
    if (lt) e.logonTypes.add(_decodeLogonType(lt));
    const lp = _firstField(det, ['LogonProcessName','LogonProcess']);
    if (lp) e.logonProcs.add(lp);
    const ap = _firstField(det, ['AuthenticationPackageName','AuthPkg']);
    if (ap) e.authPackages.add(ap);
    const lm = _firstField(det, ['LmPackageName']);
    if (lm) e.lmPackages.add(lm);
    const im = _firstField(det, ['ImpersonationLevel']);
    if (im) e.impLevels.add(_decodeImpLevel(im));
    // Port capture -- two sources:
    //  (a) embedded in the IP field itself, e.g. EID 131 ClientIP "1.2.3.4:50123"
    //  (b) a separate Port field on the event (Sysmon 3, WFP 5156/5157)
    // For inbound peers we want the remote source port; for outbound the
    // destination port we touched.
    const embeddedPort = _extractPort(ipRaw);
    if (embeddedPort) e.ports.add(embeddedPort);
    const portField = (dirHint === 'in')
      ? _firstField(det, ['SrcPort','SourcePort','ClientPort'])
      : _firstField(det, ['TgtPort','DestPort','DestinationPort']);
    if (portField && /^\d{1,5}$/.test(portField)) e.ports.add(portField);
    if (!isNaN(r.ts)) {
      if (r.ts < e.first) e.first = r.ts;
      if (r.ts > e.last)  e.last  = r.ts;
    }
    if (e.indices.length < 200) e.indices.push(fi);
  };

  for (let fi = 0; fi < all.length; fi++) {
    const r = all[fi];
    const eid = String(r.eid);
    const cfg = PEER_EID_MAP[eid];
    if (!cfg) continue;
    const p = parseDet(r.det);

    if (cfg.dir === 'in') {
      const ip = _firstField(p, cfg.src);
      record(inMap, ip, r, fi, 'in');
    } else if (cfg.dir === 'out') {
      const ip = _firstField(p, cfg.dst || cfg.src);
      record(outMap, ip, r, fi, 'out');
    } else if (cfg.dir === 'wfp') {
      const dir = _wfpDir(p[cfg.dirField] || '');
      if (dir === 'in')  record(inMap,  _firstField(p, cfg.src), r, fi, 'in');
      else if (dir === 'out') record(outMap, _firstField(p, cfg.dst), r, fi, 'out');
      else { // unknown direction -- record both
        record(inMap,  _firstField(p, cfg.src), r, fi, 'in');
        record(outMap, _firstField(p, cfg.dst), r, fi, 'out');
      }
    } else if (cfg.dir === 'sysmon') {
      const initiated = (p[cfg.dirField] || '').toLowerCase();
      if (initiated === 'true')       record(outMap, _firstField(p, cfg.dst), r, fi, 'out');
      else if (initiated === 'false') record(inMap,  _firstField(p, cfg.src), r, fi, 'in');
      else { record(outMap, _firstField(p, cfg.dst), r, fi, 'out'); }
    }
  }

  return { inMap, outMap };
}

// ── RENDER ────────────────────────────────────────────────────────────────────

function rPeers() {
  const { inMap, outMap } = _buildPeers();

  // Wire control state from DOM (in case user toggled checkboxes)
  const incPriv = document.getElementById('peersIncPriv');
  const onlyFail = document.getElementById('peersOnlyFails');
  if (incPriv)  incPriv.checked  = _peersIncludePrivate;
  if (onlyFail) onlyFail.checked = _peersOnlyFails;

  document.getElementById('peersInWrap').innerHTML  = _renderPeerTable(inMap,  'in');
  document.getElementById('peersOutWrap').innerHTML = _renderPeerTable(outMap, 'out');

  document.getElementById('peersStats').textContent =
    `${inMap.size} inbound peer${inMap.size===1?'':'s'} \u2022 ${outMap.size} outbound peer${outMap.size===1?'':'s'}`;
}

function togglePeersFilter(which, el) {
  if (which === 'priv') _peersIncludePrivate = el.checked;
  if (which === 'fail') _peersOnlyFails      = el.checked;
  _peersExpanded = null;
  rPeers();
}

function _renderPeerTable(map, direction) {
  if (!map.size) {
    return `<div style="padding:24px;text-align:center;color:var(--text-dim);font-family:var(--mono);font-size:12px">No ${direction==='in'?'inbound':'outbound'} IP traffic detected in current filter.</div>`;
  }

  const dirLabel = direction === 'in' ? 'Source IP' : 'Destination IP';
  const peers = [...map.values()].sort((a,b) => b.count - a.count);

  const rows = peers.map(p => {
    const id        = direction + ':' + p.ip;
    const isOpen    = _peersExpanded === id;
    const arrow     = isOpen ? '&#9660;' : '&#9658;';
    const failBadge = p.fail > 0
      ? `<span style="color:var(--high);font-weight:600">${p.fail}</span><span style="color:var(--text-dim)"> / ${p.count}</span>`
      : `<span>${p.count.toLocaleString()}</span>`;
    const isVPN    = _isLikelyVPN(p.ip);
    const isPriv   = _isPrivateIP(p.ip);
    const ipStyle  = isVPN  ? 'color:var(--warn);font-weight:600;'
                   : isPriv ? 'color:var(--text);'
                            : 'color:var(--orange);font-weight:600;';
    const badge    = isVPN
      ? ' <span style="font-size:9px;background:var(--warn-dim);color:var(--warn);padding:1px 4px;border-radius:2px;font-weight:600" title="172.16.0.0/12 is typically a VPN concentrator range in DFIR casework">VPN?</span>'
      : (isPriv ? ''
                : ' <span style="font-size:9px;background:var(--orange-dim);color:var(--orange);padding:1px 4px;border-radius:2px;font-weight:600">PUBLIC</span>');
    const eidList = [...p.eids].sort().slice(0, 6).map(e => eL(e)).join(', ')
                  + (p.eids.size > 6 ? ' \u2026' : '');
    const userList = [...p.users].slice(0, 3).join(', ')
                   + (p.users.size > 3 ? ` +${p.users.size-3}` : '');
    const hostList = [...p.remoteHosts].slice(0, 2).join(', ')
                   + (p.remoteHosts.size > 2 ? ` +${p.remoteHosts.size-2}` : '');
    const portsSorted = [...p.ports].sort((a,b) => Number(a) - Number(b));
    const portList    = portsSorted.slice(0, 4).join(', ')
                      + (portsSorted.length > 4 ? ` +${portsSorted.length-4}` : '');
    const ltList   = [...p.logonTypes].sort().join(', ');
    const procList = [...p.logonProcs].sort().join(', ');
    const authList = [...p.authPackages].sort().join(', ');
    const lmList   = [...p.lmPackages].sort().join(', ');
    const impList  = [...p.impLevels].sort().join(', ');
    const span = (p.last - p.first) > 0 ? fDelta(p.last - p.first) : '\u2014';

    // Logon mechanics tooltip — only meaningful for inbound peers (4624/4625/4648)
    const mechTip = direction === 'in' ? eH([
      procList ? 'LogonProcess: ' + procList : '',
      authList ? 'AuthPackage: '  + authList : '',
      lmList   ? 'LmPackage: '    + lmList   : '',
      impList  ? 'Impersonation: '+ impList  : '',
    ].filter(Boolean).join(' \u2022 ')) : '';
    const mechCell = direction === 'in'
      ? `<td style="font-family:var(--mono);font-size:11px;color:var(--text-dim);max-width:170px;overflow:hidden;text-overflow:ellipsis" title="${mechTip}">${eH(ltList) || '\u2014'}</td>`
      : `<td style="color:var(--text-dim)">\u2014</td>`;

    const portsTitle = portsSorted.length
      ? `${portsSorted.length} distinct port${portsSorted.length===1?'':'s'}: ${portsSorted.join(', ')}`
      : '';
    const portsCell = portsSorted.length
      ? `<td style="font-family:var(--mono);font-size:11px;color:var(--text-dim);max-width:140px;overflow:hidden;text-overflow:ellipsis" title="${eH(portsTitle)}">${eH(portList)}</td>`
      : `<td style="color:var(--text-dim)">\u2014</td>`;

    let summary = `<tr class="peer-summary-row${isOpen?' peer-row-open':''}" style="cursor:pointer" onclick="togglePeerExpand('${eH(id)}')">
      <td style="width:18px;color:var(--text-dim);font-size:10px;padding-right:0">${arrow}</td>
      <td style="font-family:var(--mono);${ipStyle}">${eH(p.ip)}${badge}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--info);max-width:170px;overflow:hidden;text-overflow:ellipsis" title="${eH([...p.remoteHosts].join(', '))}">${eH(hostList) || '<span style="color:var(--text-dim)">\u2014</span>'}</td>
      ${portsCell}
      <td style="text-align:right;font-family:var(--mono)">${failBadge}</td>
      ${mechCell}
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${!isFinite(p.first)?'\u2014':fDTz(p.first)}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${!isFinite(p.last)?'\u2014':fDTz(p.last)}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${span}</td>
      <td style="font-family:var(--mono);font-size:11px">${eidList}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim);max-width:160px;overflow:hidden;text-overflow:ellipsis">${eH(userList) || '\u2014'}</td>
    </tr>`;

    if (isOpen) {
      const sample = p.indices.slice(0, 60);
      const evtRows = sample.map(fi => {
        const r = getFR()[fi];
        if (!r) return '';
        const det = parseDet(r.det);
        const u   = _getUser(det) || '\u2014';
        const rh  = (direction === 'in' ? _getSrcHost(det) : _getDstHost(det)) || '\u2014';
        return `<tr style="cursor:pointer" data-nav-idx="${fi}" onclick="event.stopPropagation();openDP(${fi},'peers')">
          <td colspan="2"></td>
          <td style="font-family:var(--mono);font-size:11px">${!isNaN(r.ts)?fDTz(r.ts):'N/A'}</td>
          <td>${lB(r.lvl)}</td>
          <td>${eL(r.eid)}</td>
          <td style="font-family:var(--mono);font-size:11px;color:var(--info)">${eH(rh)}</td>
          <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)" colspan="2">${eH(u)}</td>
        </tr>`;
      }).join('');
      const more = p.indices.length > 60
        ? `<tr><td colspan="11" style="text-align:center;font-family:var(--mono);font-size:11px;color:var(--text-dim);padding:6px">\u2026 ${(p.indices.length-60).toLocaleString()} more (truncated)</td></tr>`
        : '';
      summary += `<tr class="peer-expand-row"><td colspan="11" style="padding:0;background:var(--surface2);border-top:2px solid var(--orange);border-bottom:1px solid var(--border)">
        <table class="data-table" style="margin:0;border:none">
          <thead><tr style="background:var(--surface3)"><th colspan="2"></th><th>Time</th><th>Lvl</th><th>EID</th><th>Hostname</th><th colspan="2">Account</th></tr></thead>
          <tbody>${evtRows}${more}</tbody>
        </table>
      </td></tr>`;
    }
    return summary;
  }).join('');

  const portHeader = direction === 'in' ? 'Src Ports' : 'Dst Ports';
  return `<table class="data-table"><thead><tr>
    <th style="width:18px"></th>
    <th>${dirLabel}</th>
    <th>Hostname</th>
    <th title="${direction==='in'?'Remote (source) ports observed':'Destination ports touched'}">${portHeader}</th>
    <th style="text-align:right">Hits / Fails</th>
    <th title="LogonType (hover for LogonProcess / AuthPackage / LmPackage / Impersonation)">Logon</th>
    <th>First Seen</th>
    <th>Last Seen</th>
    <th>Span</th>
    <th>Event IDs</th>
    <th>Accounts</th>
  </tr></thead><tbody>${rows}</tbody></table>`;
}

function togglePeerExpand(id) {
  _peersExpanded = (_peersExpanded === id) ? null : id;
  rPeers();
  if (_peersExpanded) {
    requestAnimationFrame(() => {
      const row = document.querySelector('.peer-row-open');
      if (row) row.scrollIntoView({block:'nearest', behavior:'smooth'});
    });
  }
}

// ── CSV EXPORT ────────────────────────────────────────────────────────────────

const PEER_CSV_COLS = [
  'Direction','RemoteIP','RemoteHostnames','RemotePorts','Classification','Hits','Failures',
  'LogonTypes','LogonProcesses','AuthPackages','LmPackages','ImpersonationLevels',
  'FirstSeen_UTC','LastSeen_UTC','Span',
  'EventIDs','Accounts','Computers'
];

function _csvCell(v) {
  const s = (v == null) ? '' : String(v);
  if (s.indexOf('"') !== -1 || s.indexOf(',') !== -1 || s.indexOf('\n') !== -1) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function _peerToCsvRow(p, direction) {
  const fmt = ts => isFinite(ts) ? new Date(ts).toISOString().replace('T',' ').replace(/\..+$/, '') : '';
  const cls = _isLikelyVPN(p.ip) ? 'VPN?'
            : _isPrivateIP(p.ip) ? 'Private'
                                 : 'Public';
  return [
    direction === 'in' ? 'Inbound' : 'Outbound',
    p.ip,
    [...p.remoteHosts].sort().join('; '),
    [...p.ports].sort((a,b) => Number(a)-Number(b)).join('; '),
    cls,
    p.count,
    p.fail,
    [...p.logonTypes].sort().join('; '),
    [...p.logonProcs].sort().join('; '),
    [...p.authPackages].sort().join('; '),
    [...p.lmPackages].sort().join('; '),
    [...p.impLevels].sort().join('; '),
    fmt(p.first),
    fmt(p.last),
    (p.last - p.first) > 0 ? fDelta(p.last - p.first) : '',
    [...p.eids].sort().join('; '),
    [...p.users].sort().join('; '),
    [...p.comps].sort().join('; '),
  ].map(_csvCell).join(',');
}

function buildPeersCsv() {
  const { inMap, outMap } = _buildPeers();
  const lines = [PEER_CSV_COLS.map(_csvCell).join(',')];
  // Inbound first (sorted by hits desc), then outbound
  [...inMap.values()].sort((a,b) => b.count - a.count).forEach(p => lines.push(_peerToCsvRow(p, 'in')));
  [...outMap.values()].sort((a,b) => b.count - a.count).forEach(p => lines.push(_peerToCsvRow(p, 'out')));
  return lines.join('\r\n');
}

function copyPeersCsv() {
  const csv = buildPeersCsv();
  if (!csv) { showToast('No peer data to export'); return; }
  navigator.clipboard.writeText(csv).then(
    () => showToast('Remote hosts CSV copied to clipboard'),
    () => showToast('Clipboard copy failed')
  );
}

function downloadPeersCsv() {
  const csv = buildPeersCsv();
  if (!csv) { showToast('No peer data to export'); return; }
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  const stamp = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
  a.href     = url;
  a.download = `remote-hosts-${stamp}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('Remote hosts CSV downloaded');
}
