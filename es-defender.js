// es-defender.js — EventScope v6 — Windows Defender tab
// Combines Defender EVTX operational log events + MPLog parsed artifacts
// into a single unified Defender activity timeline.
'use strict';

// ── DEFENDER EVTX EID CLASSIFICATION ──────────────────────────────────────────

const DEFENDER_EIDS = {
  // Detections
  '1006': { cat: 'detection',  sev: 'high',   label: 'Malware detected' },
  '1007': { cat: 'detection',  sev: 'high',   label: 'Action taken on malware' },
  '1008': { cat: 'detection',  sev: 'critical', label: 'Action on malware FAILED' },
  '1009': { cat: 'detection',  sev: 'medium', label: 'Item restored from quarantine' },
  '1010': { cat: 'detection',  sev: 'high',   label: 'Failed to remove from quarantine' },
  '1116': { cat: 'detection',  sev: 'high',   label: 'Detected malware or unwanted software' },
  '1117': { cat: 'detection',  sev: 'high',   label: 'Performed action on malware' },
  '1118': { cat: 'detection',  sev: 'critical', label: 'Action on malware FAILED' },
  '1119': { cat: 'detection',  sev: 'critical', label: 'Critical error taking action' },
  // Scans
  '1000': { cat: 'scan',      sev: 'info',   label: 'Scan started' },
  '1001': { cat: 'scan',      sev: 'info',   label: 'Scan finished' },
  '1002': { cat: 'scan',      sev: 'medium', label: 'Scan cancelled' },
  '1005': { cat: 'scan',      sev: 'high',   label: 'Scan failed' },
  // Real-time protection
  '5000': { cat: 'rtp',       sev: 'info',   label: 'Real-time protection enabled' },
  '5001': { cat: 'rtp',       sev: 'high',   label: 'Real-time protection DISABLED' },
  '5004': { cat: 'rtp',       sev: 'medium', label: 'RTP config changed' },
  '5007': { cat: 'config',    sev: 'medium', label: 'Config changed' },
  '5008': { cat: 'config',    sev: 'high',   label: 'Unexpected error' },
  '5010': { cat: 'rtp',       sev: 'medium', label: 'Scanning for malware disabled' },
  '5012': { cat: 'rtp',       sev: 'medium', label: 'Scanning for viruses disabled' },
  '3002': { cat: 'rtp',       sev: 'high',   label: 'Real-time protection FAILED' },
  // Updates
  '2000': { cat: 'update',    sev: 'info',   label: 'Definitions updated' },
  '2001': { cat: 'update',    sev: 'high',   label: 'Definition update FAILED' },
  '2002': { cat: 'update',    sev: 'info',   label: 'Engine updated' },
  '2003': { cat: 'update',    sev: 'high',   label: 'Engine update FAILED' },
  '2004': { cat: 'update',    sev: 'medium', label: 'Reverting to last known good definitions' },
  '2010': { cat: 'update',    sev: 'info',   label: 'Using definitions from backup' },
  // Submissions
  '1013': { cat: 'submit',    sev: 'info',   label: 'Sample submitted to Microsoft' },
  '2050': { cat: 'submit',    sev: 'info',   label: 'Submission upload completed' },
  // Exclusions
  '5007': { cat: 'config',    sev: 'medium', label: 'Config changed (possible exclusion add)' },
};

const DEFENDER_CHAN = /windows defender|antimalware/i;

// Category metadata
const DEF_CATS = {
  detection: { label: 'Detections',     color: 'var(--high)',    icon: '\u26A0' },
  scan:      { label: 'Scans',          color: 'var(--info)',    icon: '\u2699' },
  rtp:       { label: 'Real-Time Protection', color: 'var(--orange)', icon: '\u2691' },
  config:    { label: 'Configuration',  color: 'var(--text-dim)', icon: '\u2263' },
  update:    { label: 'Updates',        color: 'var(--success)', icon: '\u2191' },
  submit:    { label: 'Submissions',    color: 'var(--info)',    icon: '\u2197' },
  mplog:     { label: 'MPLog Events',   color: 'var(--orange)',  icon: '\u25B6' },
};

// ── EXTRACT DEFENDER EVENTS FROM EVTX ─────────────────────────────────────────

function _extractDefenderEvtx(rows) {
  const events = [];
  for (let fi = 0; fi < rows.length; fi++) {
    const r = rows[fi];
    if (!DEFENDER_CHAN.test(r.chan || '') && !DEFENDER_CHAN.test(r.rid || '')) continue;
    const eid = String(r.eid);
    const def = DEFENDER_EIDS[eid];
    const p = parseDet(r.det);

    // Extract key fields
    const threatName = p['Threat Name'] || p.ThreatName || p.Name || '';
    const path = p.Path || p['FWLink'] || p.path || '';
    const action = p.Action || p['Action Name'] || '';
    const processName = p['Process Name'] || p.ProcessName || '';
    const user = p['Detection User'] || p.User || p.Domain || '';
    const severity = p['Severity Name'] || p.Severity || (def ? def.sev : 'info');

    events.push({
      fi, ts: r.ts, eid, comp: r.comp,
      source: 'evtx',
      cat: def ? def.cat : 'config',
      label: def ? def.label : (r.rule || 'Defender event ' + eid),
      sev: severity,
      threatName,
      path: path || processName,
      action,
      user,
      rule: r.rule,
      det: r.det,
    });
  }
  return events;
}

// ── EXTRACT MPLOG EVENTS FROM S.artifacts ─────────────────────────────────────

function _extractMPLogEvents() {
  const events = [];
  if (!S.artifacts) return events;

  for (const art of S.artifacts) {
    if (art.type !== 'mplog' || !art.events) continue;
    for (const evt of art.events) {
      const ts = evt.timestamp ? new Date(evt.timestamp).getTime() : NaN;

      // Map mplog type → category + label + key fields
      let cat = 'mplog', label = evt.type, threatName = '', path = '', action = '', sev = 'info';

      switch (evt.type) {
        case 'detection_add':
        case 'detection_event':
          cat = 'detection'; sev = 'high';
          label = evt.type === 'detection_add' ? 'Detection added' : 'Detection event';
          path = evt.command_line || '';
          break;
        case 'threat_cmdline':
          cat = 'detection'; sev = 'high'; label = 'Threat command line';
          path = evt.command_line || '';
          break;
        case 'threat_action':
          cat = 'detection'; sev = 'high'; label = 'Threat action: ' + (evt.action || '');
          threatName = evt.threat_name || '';
          path = evt.path || '';
          action = evt.result || '';
          break;
        case 'blocked_file':
          cat = 'detection'; sev = 'medium'; label = 'File blocked';
          path = evt.full_path || '';
          action = 'Process: ' + (evt.process_name || '');
          break;
        case 'unsuccessful_scan':
          cat = 'scan'; sev = 'low'; label = 'Scan unsuccessful';
          path = evt.full_path || '';
          action = 'Reason: ' + (evt.reason || '');
          break;
        case 'resource_scan':
          cat = 'scan'; sev = evt.threat_name ? 'high' : 'info';
          label = evt.threat_name ? 'Scan found: ' + evt.threat_name : 'Resource scan';
          threatName = evt.threat_name || '';
          path = evt.resource_path || '';
          break;
        case 'lowfi':
          cat = 'detection'; sev = 'medium'; label = 'Low-fi detection';
          path = evt.command_line || '';
          break;
        case 'original_filename':
          cat = 'detection'; sev = 'medium'; label = 'Original filename mismatch';
          path = evt.full_path || '';
          action = 'Original: ' + (evt.original_filename || '');
          break;
        case 'exclusion':
          cat = 'config'; sev = 'medium'; label = 'Exclusion configured';
          path = evt.path_drive || evt.path_device || '';
          break;
        case 'bm_telemetry':
          cat = 'detection'; sev = 'medium'; label = 'Behavior monitoring';
          path = evt.image_path || '';
          action = evt.telemetry_name || evt.operations || '';
          break;
        case 'ems':
          cat = 'scan'; sev = 'info'; label = 'Engine memory scan';
          path = evt.process || '';
          action = 'PID: ' + (evt.pid || '');
          break;
        case 'process_image':
          cat = 'scan'; sev = 'info'; label = 'Process scan performance';
          path = evt.process_image_name || '';
          action = 'Impact: ' + (evt.estimated_impact || '');
          break;
        case 'rtp_perf':
          cat = 'rtp'; sev = 'info'; label = 'RTP performance snapshot';
          action = 'Exclusions: ' + (evt.process_exclusions || []).length + ' proc, '
                 + (evt.path_exclusions || []).length + ' path, '
                 + (evt.extension_exclusions || []).length + ' ext';
          break;
        case 'dlp':
          cat = 'submit'; sev = 'medium'; label = 'DLP notification';
          path = evt.source || '';
          action = evt.action_type + ' (' + evt.enforcement_level + ')';
          break;
      }

      events.push({
        fi: -1, ts, eid: '', comp: '',
        source: 'mplog',
        cat, label, sev,
        threatName, path, action,
        user: evt.user_sid || '', rule: '', det: '',
      });
    }
  }
  return events;
}

// ── RENDER ────────────────────────────────────────────────────────────────────

let _defFilterCat = '';
let _defFilterSev = '';

function rDefender() {
  const el = document.getElementById('defenderContent');
  if (!el) return;

  const rows = getFR();
  const evtxEvents = _extractDefenderEvtx(rows);
  const mplogEvents = _extractMPLogEvents();
  const all = [...evtxEvents, ...mplogEvents].sort((a, b) => (b.ts || 0) - (a.ts || 0));

  // Apply filters
  let filtered = all;
  if (_defFilterCat) filtered = filtered.filter(e => e.cat === _defFilterCat);
  if (_defFilterSev) filtered = filtered.filter(e => e.sev === _defFilterSev);

  // Summary counts by category
  const catCounts = {};
  for (const e of all) catCounts[e.cat] = (catCounts[e.cat] || 0) + 1;

  // Severity counts
  const sevCounts = {};
  for (const e of all) sevCounts[e.sev] = (sevCounts[e.sev] || 0) + 1;

  // Detection summary — unique threat names
  const threats = new Map();
  for (const e of all) {
    if (e.threatName && e.cat === 'detection') {
      if (!threats.has(e.threatName)) threats.set(e.threatName, { name: e.threatName, count: 0, firstTs: e.ts, lastTs: e.ts, paths: new Set() });
      const t = threats.get(e.threatName);
      t.count++;
      if (e.ts < t.firstTs) t.firstTs = e.ts;
      if (e.ts > t.lastTs) t.lastTs = e.ts;
      if (e.path) t.paths.add(e.path);
    }
  }

  // RTP status — find most recent enable/disable
  const rtpEvents = all.filter(e => e.cat === 'rtp').sort((a, b) => (b.ts || 0) - (a.ts || 0));
  const rtpStatus = rtpEvents[0];
  const rtpBadge = rtpStatus
    ? (rtpStatus.label.includes('DISABLED') || rtpStatus.label.includes('FAILED')
      ? `<span style="color:var(--high);font-weight:700">\u26A0 ${eH(rtpStatus.label)}</span> at ${fDTz(rtpStatus.ts)}`
      : `<span style="color:var(--success)">\u2713 ${eH(rtpStatus.label)}</span> at ${fDTz(rtpStatus.ts)}`)
    : '<span style="color:var(--text-dim)">No RTP events</span>';

  // Category filter buttons
  const catBtns = Object.entries(DEF_CATS).map(([key, meta]) => {
    const cnt = catCounts[key] || 0;
    if (!cnt) return '';
    const active = _defFilterCat === key;
    return `<button class="copy-btn${active?' active':''}" style="${active?'border-color:'+meta.color+';color:'+meta.color:''}" onclick="_defFilterCat=_defFilterCat==='${key}'?'':'${key}';rDefender()">
      ${meta.icon} ${meta.label} (${cnt})
    </button>`;
  }).filter(Boolean).join('');

  // Threat table
  const threatRows = [...threats.values()].sort((a, b) => b.count - a.count);
  const threatSection = threatRows.length ? `
    <div style="margin-bottom:14px">
      <div style="font-family:var(--mono);font-size:12px;font-weight:600;color:var(--high);margin-bottom:8px">\u26A0 Threats Detected (${threatRows.length} unique)</div>
      <div class="data-table-wrap"><table class="data-table"><thead><tr>
        <th>Threat Name</th><th>Hits</th><th>First Seen</th><th>Last Seen</th><th>Paths / Processes</th>
      </tr></thead><tbody>${threatRows.map(t => `<tr>
        <td style="font-weight:600;color:var(--high)">${eH(t.name)}</td>
        <td style="font-family:var(--mono)">${t.count}</td>
        <td style="font-family:var(--mono);font-size:11px;white-space:nowrap">${isFinite(t.firstTs)?fDTz(t.firstTs):'\u2014'}</td>
        <td style="font-family:var(--mono);font-size:11px;white-space:nowrap">${isFinite(t.lastTs)?fDTz(t.lastTs):'\u2014'}</td>
        <td style="font-size:11px;max-width:400px;overflow:hidden;text-overflow:ellipsis" title="${eH([...t.paths].join('\n'))}">${eH([...t.paths].slice(0,3).join(', '))}</td>
      </tr>`).join('')}</tbody></table></div>
    </div>` : '';

  // Event timeline
  const display = filtered.slice(0, 1000);
  const evtRows = display.map(e => {
    const sevColor = e.sev === 'critical' ? 'var(--crit)' : e.sev === 'high' ? 'var(--high)' : e.sev === 'medium' ? 'var(--med)' : 'var(--text-dim)';
    const catMeta = DEF_CATS[e.cat] || DEF_CATS.mplog;
    const clickAttr = e.fi >= 0 ? `style="cursor:pointer" onclick="openDP(${e.fi},'defender')"` : '';
    return `<tr ${clickAttr}>
      <td style="font-family:var(--mono);font-size:11px;white-space:nowrap">${isFinite(e.ts)?fDTz(e.ts):'\u2014'}</td>
      <td><span style="color:${sevColor};font-weight:600;font-size:11px">${eH(e.sev)}</span></td>
      <td><span style="color:${catMeta.color};font-size:11px">${catMeta.icon} ${eH(catMeta.label)}</span></td>
      <td style="font-size:12px">${eH(e.label)}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--high);max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${eH(e.threatName)}">${eH(e.threatName || '\u2014')}</td>
      <td style="font-family:var(--mono);font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis" title="${eH(e.path)}">${eH(e.path ? e.path.split(/[/\\]/).pop() : '\u2014')}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${eH(e.action || '\u2014')}</td>
      <td style="font-size:10px;color:var(--text-dim)">${e.source}</td>
    </tr>`;
  }).join('');

  el.innerHTML = `
    <div class="chart-box">
      <div class="chart-header">
        <span class="chart-title">Windows Defender</span>
        <span style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">
          ${all.length} events (${evtxEvents.length} EVTX + ${mplogEvents.length} MPLog)
        </span>
      </div>

      <div style="display:flex;gap:16px;margin-bottom:14px;align-items:center;flex-wrap:wrap">
        <div style="font-family:var(--mono);font-size:11px">RTP Status: ${rtpBadge}</div>
        <div style="margin-left:auto;display:flex;gap:4px;flex-wrap:wrap">${catBtns}</div>
      </div>

      ${threatSection}

      <div style="margin-bottom:8px;font-family:var(--mono);font-size:11px;color:var(--text-dim)">
        ${_defFilterCat || _defFilterSev ? `Filtered: ${filtered.length} of ${all.length} events` : `Showing ${Math.min(1000, filtered.length).toLocaleString()} of ${filtered.length.toLocaleString()}`}
        ${_defFilterCat ? ` \u2022 <button class="copy-btn" onclick="_defFilterCat='';_defFilterSev='';rDefender()" style="font-size:10px;padding:1px 6px">\u2715 Clear filter</button>` : ''}
      </div>

      ${display.length ? `
        <div class="data-table-wrap">
          <table class="data-table"><thead><tr>
            <th>Timestamp</th><th>Severity</th><th>Category</th><th>Event</th><th>Threat</th><th>File / Process</th><th>Action / Detail</th><th>Source</th>
          </tr></thead><tbody>${evtRows}</tbody></table>
        </div>
      ` : '<div style="padding:40px;text-align:center;color:var(--text-dim);font-family:var(--mono);font-size:12px">No Defender events found. Load Defender EVTX channel or MPLog files.</div>'}
    </div>`;
}
