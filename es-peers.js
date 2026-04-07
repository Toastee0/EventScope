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
  const s = ip.trim().toLowerCase();
  if (!s || s === '-' || s === '::' || s === '::1' || s === '0.0.0.0') return true;
  if (s.startsWith('127.')) return true;
  if (s.startsWith('fe80:')) return true;       // link-local IPv6
  if (s.startsWith('169.254.')) return true;    // APIPA
  // Filter out NetBIOS-style names by checking if it has any digit-dot or hex-colon pattern
  // (allow plain hostnames through too — useful for ClientName field)
  return false;
}

function _isPrivateIP(ip) {
  if (!ip) return false;
  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if (/^fc/i.test(ip) || /^fd/i.test(ip)) return true;  // ULA IPv6
  return false;
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
      first: Infinity, last: -Infinity, indices: []
    });
    return m.get(ip);
  };

  const record = (m, ip, r, fi) => {
    if (_isUselessIP(ip)) return;
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
    const u = _getUser(parseDet(r.det));
    if (u) e.users.add(u);
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
      record(inMap, ip, r, fi);
    } else if (cfg.dir === 'out') {
      const ip = _firstField(p, cfg.dst || cfg.src);
      record(outMap, ip, r, fi);
    } else if (cfg.dir === 'wfp') {
      const dir = _wfpDir(p[cfg.dirField] || '');
      if (dir === 'in')  record(inMap,  _firstField(p, cfg.src), r, fi);
      else if (dir === 'out') record(outMap, _firstField(p, cfg.dst), r, fi);
      else { // unknown direction -- record both
        record(inMap,  _firstField(p, cfg.src), r, fi);
        record(outMap, _firstField(p, cfg.dst), r, fi);
      }
    } else if (cfg.dir === 'sysmon') {
      const initiated = (p[cfg.dirField] || '').toLowerCase();
      if (initiated === 'true')       record(outMap, _firstField(p, cfg.dst), r, fi);
      else if (initiated === 'false') record(inMap,  _firstField(p, cfg.src), r, fi);
      else { record(outMap, _firstField(p, cfg.dst), r, fi); }
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

  const rows = peers.map((p, ri) => {
    const id        = direction + ':' + p.ip;
    const isOpen    = _peersExpanded === id;
    const arrow     = isOpen ? '&#9660;' : '&#9658;';
    const failBadge = p.fail > 0
      ? `<span style="color:var(--high);font-weight:600">${p.fail}</span><span style="color:var(--text-dim)"> / ${p.count}</span>`
      : `<span>${p.count.toLocaleString()}</span>`;
    const ipStyle = _isPrivateIP(p.ip)
      ? 'color:var(--text);'
      : 'color:var(--orange);font-weight:600;';
    const eidList = [...p.eids].sort().slice(0, 6).map(e => eL(e)).join(', ')
                  + (p.eids.size > 6 ? ' \u2026' : '');
    const userList = [...p.users].slice(0, 3).join(', ')
                   + (p.users.size > 3 ? ` +${p.users.size-3}` : '');
    const span = (p.last - p.first) > 0 ? fDelta(p.last - p.first) : '\u2014';

    let summary = `<tr class="peer-summary-row${isOpen?' peer-row-open':''}" style="cursor:pointer" onclick="togglePeerExpand('${eH(id)}')">
      <td style="width:18px;color:var(--text-dim);font-size:10px;padding-right:0">${arrow}</td>
      <td style="font-family:var(--mono);${ipStyle}">${eH(p.ip)}${_isPrivateIP(p.ip)?'':' <span style="font-size:9px;background:var(--orange-dim);color:var(--orange);padding:1px 4px;border-radius:2px;font-weight:600">PUBLIC</span>'}</td>
      <td style="text-align:right;font-family:var(--mono)">${failBadge}</td>
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
        return `<tr style="cursor:pointer" data-nav-idx="${fi}" onclick="event.stopPropagation();openDP(${fi},'peers')">
          <td colspan="2"></td>
          <td style="font-family:var(--mono);font-size:11px">${!isNaN(r.ts)?fDTz(r.ts):'N/A'}</td>
          <td>${lB(r.lvl)}</td>
          <td>${eL(r.eid)}</td>
          <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${eH(r.comp)}</td>
          <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)" colspan="2">${eH(u)}</td>
        </tr>`;
      }).join('');
      const more = p.indices.length > 60
        ? `<tr><td colspan="8" style="text-align:center;font-family:var(--mono);font-size:11px;color:var(--text-dim);padding:6px">\u2026 ${(p.indices.length-60).toLocaleString()} more (truncated)</td></tr>`
        : '';
      summary += `<tr class="peer-expand-row"><td colspan="8" style="padding:0;background:var(--surface2);border-top:2px solid var(--orange);border-bottom:1px solid var(--border)">
        <table class="data-table" style="margin:0;border:none">
          <thead><tr style="background:var(--surface3)"><th colspan="2"></th><th>Time</th><th>Lvl</th><th>EID</th><th>Computer</th><th colspan="2">Account</th></tr></thead>
          <tbody>${evtRows}${more}</tbody>
        </table>
      </td></tr>`;
    }
    return summary;
  }).join('');

  return `<table class="data-table"><thead><tr>
    <th style="width:18px"></th>
    <th>${dirLabel}</th>
    <th style="text-align:right">Hits / Fails</th>
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
