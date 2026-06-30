// es-rdp.js — EventScope v5 — RDP Session Reconstruction
// Correlates TerminalServices, Security, RdpCoreTS, and RDPClient EIDs
// into complete RDP session lifecycles per JPCERT mstsc artifact reference.
'use strict';

// ── RDP EVENT CLASSIFICATION ──────────────────────────────────────────────────

const RDP_EIDS = {
  // Destination (target) events
  '261':  { side: 'dest', phase: 'listener',   chan: /RemoteConnectionManager|^RDS-RCM$/i, label: 'Listener: connection received' },
  '1149': { side: 'dest', phase: 'auth',       chan: /RemoteConnectionManager|^RDS-RCM$/i, label: 'User authenticated successfully' },
  '4624': { side: 'dest', phase: 'logon',      chan: /^Sec$|Security/i,               label: 'Logon success', ltFilter: '10' },
  '4625': { side: 'dest', phase: 'logon_fail', chan: /^Sec$|Security/i,               label: 'Logon failure', ltFilter: '10' },
  '4648': { side: 'both', phase: 'explicit',   chan: /^Sec$|Security/i,               label: 'Explicit credential use' },
  '4672': { side: 'dest', phase: 'privs',      chan: /^Sec$|Security/i,               label: 'Special privileges assigned' },
  '21':   { side: 'dest', phase: 'session',    chan: /LocalSessionManager|^RDS-LSM$/i,    label: 'Session logon succeeded' },
  '22':   { side: 'dest', phase: 'shell',      chan: /LocalSessionManager|^RDS-LSM$/i,    label: 'Shell start notification' },
  '24':   { side: 'dest', phase: 'disconnect', chan: /LocalSessionManager|^RDS-LSM$/i,    label: 'Session disconnected' },
  '25':   { side: 'dest', phase: 'reconnect',  chan: /LocalSessionManager|^RDS-LSM$/i,    label: 'Session reconnected' },
  '4779': { side: 'dest', phase: 'disconnect', chan: /^Sec$|Security/i,               label: 'Session disconnected' },
  '4778': { side: 'dest', phase: 'reconnect',  chan: /^Sec$|Security/i,               label: 'Session reconnected' },
  '131':  { side: 'dest', phase: 'client_ip',  chan: /RdpCoreTS|^RDP-CoreTS$/i, label: 'Client IP captured' },
  '5156': { side: 'both', phase: 'network',    chan: /^Sec$|Security/i,               label: 'WFP connection (port 3389)' },
  // Source (client) events
  '1024': { side: 'src',  phase: 'connect',    chan: /RDPClient|^RDP-Cli$/i,              label: 'RDP connecting to host' },
  '1025': { side: 'src',  phase: 'connected',  chan: /RDPClient|^RDP-Cli$/i,              label: 'RDP connection established' },
  '1026': { side: 'src',  phase: 'src_disconnect', chan: /RDPClient|^RDP-Cli$/i,          label: 'RDP disconnected' },
  '1029': { side: 'src',  phase: 'src_auth',   chan: /RDPClient|^RDP-Cli$/i,              label: 'User auth (hash)' },
  '1105': { side: 'src',  phase: 'src_disconnect', chan: /RDPClient|^RDP-Cli$/i,          label: 'Multi-transport disconnected' },
};

// Phases that indicate RDP-specific process activity on destination
const RDP_PROCS = new Set(['rdpclip.exe','tstheme.exe','rdpinit.exe','rdpshell.exe']);

// ── EVENT EXTRACTION ──────────────────────────────────────────────────────────

function _extractRDPEvents(rows) {
  const events = [];

  for (let fi = 0; fi < rows.length; fi++) {
    const r = rows[fi];
    const eid = String(r.eid);
    const def = RDP_EIDS[eid];

    if (def) {
      // Channel filter: must match expected channel pattern.
      // Each pattern accepts both the full EvtxECmd channel name and the
      // Hayabusa abbreviation (e.g. Security→Sec, LocalSessionManager→RDS-LSM).
      if (def.chan && !def.chan.test(r.chan || '')) continue;

      const p = parseDet(r.det);

      // For 4624/4625: only LT10 (RemoteInteractive) is RDP
      if (def.ltFilter) {
        const lt = p.LogonType || p.LgTp || p.Type || '';
        const ltNum = String(lt).match(/(\d+)/);
        if (!ltNum || ltNum[1] !== def.ltFilter) continue;
      }

      // For 5156: only port 3389
      if (eid === '5156') {
        const sp = p.SourcePort || p.SrcPort || '';
        const dp = p.DestPort || p.DestinationPort || '';
        if (sp !== '3389' && dp !== '3389') continue;
      }

      const srcIP = p.IpAddress || p.SrcIP || p.ClientAddress || p.SourceAddress
                 || p['Source Network Address'] || p.ClientIP || p.RemoteHost || '';
      const user  = p.TargetUserName || p.TgtUser || p.User || p.AccountName || p.UserName || '';
      const domain = p.TargetDomainName || p.AccountDomain || '';
      const sessionName = p.SessionName || '';
      const clientName = p.ClientName || p.WorkstationName || p.SrcComp || '';

      // Clean IP: strip port suffix, ::ffff: prefix
      let cleanIP = srcIP.replace(/:\d+$/, '').replace(/^::ffff:/, '').trim();
      // Strip "(IP)" from EvtxECmd RemoteHost
      cleanIP = cleanIP.replace(/\s*\(\d{1,3}(\.\d{1,3}){3}\)$/, '').trim();
      // If what remains looks like a hostname, try to extract IP from original
      if (cleanIP && !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(cleanIP)) {
        const ipMatch = srcIP.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        if (ipMatch) {
          if (!clientName) { /* use cleanIP as client name below */ }
          cleanIP = ipMatch[1];
        }
      }

      events.push({
        fi, ts: r.ts, eid, comp: r.comp, chan: r.chan,
        phase: def.phase, side: def.side, label: def.label,
        srcIP: cleanIP,
        user: user && user !== '-' ? user : '',
        domain: domain && domain !== '-' ? domain : '',
        clientName: clientName && clientName !== '-' ? clientName : '',
        sessionName,
        rule: r.rule || '',
        lvl: r.lvl,
        det: r.det,
        privs: p.PrivilegeList || '',
        authPkg: p.AuthenticationPackageName || p.AuthPkg || '',
        logonProcess: p.LogonProcessName || '',
      });
    }

    // Also catch RDP-related process creation (rdpclip, TSTheme)
    if (eid === '4688' || eid === '1') {
      const p = parseDet(r.det);
      const proc = (p.NewProcessName || p.Image || p.Process || '').toLowerCase();
      const procName = proc.split(/[/\\]/).pop();
      if (RDP_PROCS.has(procName)) {
        events.push({
          fi, ts: r.ts, eid, comp: r.comp, chan: r.chan,
          phase: 'activity', side: 'dest', label: 'RDP process: ' + procName,
          srcIP: '', user: p.SubjectUserName || p.User || '', domain: '',
          clientName: '', sessionName: '', rule: r.rule || '', lvl: r.lvl,
          det: r.det, privs: '', authPkg: '', logonProcess: '',
        });
      }
    }
  }

  events.sort((a, b) => a.ts - b.ts);
  return events;
}

// ── SESSION RECONSTRUCTION ────────────────────────────────────────────────────
// Correlate events into sessions by: source IP + user + time proximity

function _buildRDPSessions(events) {
  const sessions = [];
  const SESSION_GAP = 5 * 60 * 1000; // 5 min gap = new session

  // Group destination events by (srcIP + user) — these form the session backbone
  const groups = new Map();
  for (const evt of events) {
    if (!evt.srcIP && evt.phase !== 'activity') continue;
    // Build a correlation key
    const userKey = (evt.user || '').toLowerCase().replace(/\$$/,'');
    const ipKey = evt.srcIP || 'no-ip';
    const key = ipKey + '|' + userKey;

    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(evt);
  }

  // For each group, split into sessions by time gaps
  for (const [key, evts] of groups) {
    evts.sort((a, b) => a.ts - b.ts);
    let session = null;

    for (const evt of evts) {
      if (!session || (evt.ts - session.lastTs) > SESSION_GAP) {
        // Start new session
        if (session) sessions.push(session);
        session = {
          srcIP: evt.srcIP,
          user: evt.user,
          domain: evt.domain,
          clientName: evt.clientName,
          comp: evt.comp,
          firstTs: evt.ts,
          lastTs: evt.ts,
          events: [],
          phases: new Set(),
          authPkg: '',
          logonProcess: '',
          privs: '',
          sessionName: '',
          logonSuccess: false,
          logonFail: false,
          disconnected: false,
          reconnected: false,
          reconnects: 0,
        };
      }

      session.lastTs = evt.ts;
      session.events.push(evt);
      session.phases.add(evt.phase);

      // Capture session details from key events
      if (evt.user && !session.user) session.user = evt.user;
      if (evt.domain && !session.domain) session.domain = evt.domain;
      if (evt.clientName && !session.clientName) session.clientName = evt.clientName;
      if (evt.sessionName && !session.sessionName) session.sessionName = evt.sessionName;
      if (evt.authPkg && !session.authPkg) session.authPkg = evt.authPkg;
      if (evt.logonProcess && !session.logonProcess) session.logonProcess = evt.logonProcess;
      if (evt.privs && !session.privs) session.privs = evt.privs;
      if (evt.phase === 'logon') session.logonSuccess = true;
      if (evt.phase === 'logon_fail') session.logonFail = true;
      if (evt.phase === 'disconnect') session.disconnected = true;
      if (evt.phase === 'reconnect') { session.reconnected = true; session.reconnects++; }
    }
    if (session) sessions.push(session);
  }

  sessions.sort((a, b) => b.firstTs - a.firstTs); // newest first
  return sessions;
}

// ── RENDER ────────────────────────────────────────────────────────────────────

let _rdpExpanded = null;

function rRDP() {
  const el = document.getElementById('rdpContent');
  if (!el) return;

  const rows = getFR();
  const events = _extractRDPEvents(rows);
  const sessions = _buildRDPSessions(events);

  // Stats
  const totalSessions = sessions.length;
  const uniqueIPs = new Set(sessions.map(s => s.srcIP).filter(Boolean));
  const uniqueUsers = new Set(sessions.map(s => s.user).filter(Boolean));
  const failedSessions = sessions.filter(s => s.logonFail && !s.logonSuccess);
  const reconnectedSessions = sessions.filter(s => s.reconnects > 0);

  // Phase legend
  const phaseBadge = (phase, label, color) =>
    `<span style="display:inline-block;padding:2px 8px;margin:1px 2px;border-radius:3px;font-size:10px;font-family:var(--mono);background:${color};color:var(--white)">${label}</span>`;

  const phaseColors = {
    listener: '#2d5a8a', auth: '#1a7a5a', logon: '#1a8a2a',
    logon_fail: '#8a1a1a', privs: '#8a5a1a', session: '#2a7a4a',
    shell: '#3a6a5a', disconnect: '#6a3a3a', reconnect: '#5a5a1a',
    client_ip: '#4a4a6a', activity: '#3a5a6a', network: '#4a5a4a',
    connect: '#2a5a7a', connected: '#1a6a5a', src_disconnect: '#5a3a4a',
    src_auth: '#3a6a3a', explicit: '#6a4a1a',
  };

  // Session rows
  const sessionRows = sessions.map((s, i) => {
    const duration = s.lastTs - s.firstTs;
    const isOpen = _rdpExpanded === i;
    const arrow = isOpen ? '\u25BC' : '\u25B6';

    // Status badge
    let status;
    if (s.logonFail && !s.logonSuccess) {
      status = '<span style="color:var(--high);font-weight:700">\u2717 Failed</span>';
    } else if (s.logonSuccess && s.disconnected) {
      status = '<span style="color:var(--success)">\u2713 Complete</span>';
    } else if (s.logonSuccess) {
      status = '<span style="color:var(--success)">\u2713 Active</span>';
    } else {
      status = '<span style="color:var(--text-dim)">Partial</span>';
    }

    const reconnBadge = s.reconnects > 0
      ? ` <span style="font-size:9px;background:var(--warn-dim, rgba(200,160,30,.2));color:var(--warn, #c8a01e);padding:1px 5px;border-radius:2px;font-weight:600">${s.reconnects} reconnect${s.reconnects>1?'s':''}</span>`
      : '';

    const privBadge = s.privs
      ? ' <span style="font-size:9px;background:var(--orange-dim);color:var(--orange);padding:1px 5px;border-radius:2px;font-weight:600">PRIV</span>'
      : '';

    const phaseIcons = [...s.phases].map(ph => {
      const c = phaseColors[ph] || '#555';
      return `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${c};margin:0 1px" title="${ph}"></span>`;
    }).join('');

    let detail = '';
    if (isOpen) {
      const evtRows = s.events.map(evt => {
        const bgColor = phaseColors[evt.phase] || '#333';
        return `<tr onclick="openDP(${evt.fi},'rdp')" style="cursor:pointer">
          <td style="font-family:var(--mono);font-size:11px;white-space:nowrap">${fDTz(evt.ts)}</td>
          <td><span style="display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-family:var(--mono);background:${bgColor};color:var(--white)">${eH(evt.phase)}</span></td>
          <td style="font-family:var(--mono);font-size:11px">${eH(evt.eid)}</td>
          <td style="font-size:11px;color:var(--text-dim);max-width:200px;overflow:hidden;text-overflow:ellipsis">${eH(evt.chan)}</td>
          <td style="font-size:11px;max-width:350px;overflow:hidden;text-overflow:ellipsis" title="${eH(evt.label)}">${eH(evt.label)}</td>
          <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${eH(evt.user || '')}</td>
          <td style="font-family:var(--mono);font-size:11px;color:var(--orange)">${eH(evt.srcIP || '')}</td>
        </tr>`;
      }).join('');

      detail = `<tr class="inline-expansion"><td colspan="11" style="padding:0;background:var(--surface2);border-top:2px solid var(--orange);border-bottom:2px solid var(--border-bright)">
        <div style="padding:12px 16px">
          <div style="font-family:var(--mono);font-size:12px;font-weight:600;color:var(--orange);margin-bottom:8px">
            Session Detail \u2014 ${s.events.length} events \u2014 ${eH(s.srcIP)} \u2192 ${eH(s.comp)}
          </div>
          ${s.authPkg ? `<div style="font-family:var(--mono);font-size:11px;color:var(--text-dim);margin-bottom:4px">Auth: ${eH(s.authPkg)}${s.logonProcess ? ' / ' + eH(s.logonProcess) : ''}</div>` : ''}
          ${s.privs ? `<div style="font-family:var(--mono);font-size:11px;color:var(--orange);margin-bottom:4px">Privileges: ${eH(s.privs.substring(0, 200))}</div>` : ''}
          <table class="data-table"><thead><tr>
            <th>Timestamp</th><th>Phase</th><th>EID</th><th>Channel</th><th>Description</th><th>User</th><th>IP</th>
          </tr></thead><tbody>${evtRows}</tbody></table>
        </div>
      </td></tr>`;
    }

    return `<tr style="cursor:pointer" onclick="toggleRDPSession(${i})">
      <td style="width:18px;color:var(--text-dim);font-size:10px">${arrow}</td>
      <td style="font-family:var(--mono);font-size:11px;white-space:nowrap">${fDTz(s.firstTs)}</td>
      <td>${status}${reconnBadge}${privBadge}</td>
      <td style="font-family:var(--mono);font-size:11px;font-weight:600;color:var(--white)">${eH(s.user || '\u2014')}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${eH(s.domain || '')}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--orange)">${eH(s.srcIP || '\u2014')}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--info)">${eH(s.clientName || '\u2014')}</td>
      <td style="font-family:var(--mono);font-size:11px">${eH(s.comp || '\u2014')}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${duration > 0 ? fDelta(duration) : '\u2014'}</td>
      <td style="font-size:11px">${phaseIcons}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${s.events.length}</td>
    </tr>${detail}`;
  }).join('');

  el.innerHTML = `
    <div class="chart-box">
      <div class="chart-header">
        <span class="chart-title">RDP Sessions</span>
        <span style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">
          ${totalSessions} session${totalSessions===1?'':'s'}
          \u2022 ${uniqueIPs.size} source IP${uniqueIPs.size===1?'':'s'}
          \u2022 ${uniqueUsers.size} user${uniqueUsers.size===1?'':'s'}
          ${failedSessions.length ? '\u2022 <span style="color:var(--high)">' + failedSessions.length + ' failed</span>' : ''}
          ${reconnectedSessions.length ? '\u2022 <span style="color:var(--warn,#c8a01e)">' + reconnectedSessions.length + ' with reconnects</span>' : ''}
        </span>
      </div>

      <div style="font-size:11px;font-family:var(--mono);color:var(--text-dim);margin-bottom:12px;line-height:1.8;padding:0 4px">
        RDP lifecycle reconstructed from Security (4624/4625/4648/4672/4778/4779/5156),
        TerminalServices-LocalSessionManager (21/22/24/25), RemoteConnectionManager (261/1149),
        RdpCoreTS (131), and RDPClient (1024/1025/1026/1029). Click a session to expand.
      </div>

      ${sessions.length ? `
        <div class="data-table-wrap">
          <table class="data-table"><thead><tr>
            <th style="width:18px"></th>
            <th>First Event</th>
            <th>Status</th>
            <th>User</th>
            <th>Domain</th>
            <th>Source IP</th>
            <th>Client Name</th>
            <th>Dest Host</th>
            <th>Duration</th>
            <th title="Lifecycle phases observed">Phases</th>
            <th>Events</th>
          </tr></thead><tbody>${sessionRows}</tbody></table>
        </div>
      ` : `
        <div style="padding:40px;text-align:center;color:var(--text-dim);font-family:var(--mono);font-size:12px">
          No RDP activity detected in current filter.<br>
          Looking for: EIDs 4624(LT10), 4625(LT10), 4778, 4779, 131, 21, 24, 25, 261, 1149, 1024-1029
        </div>
      `}
    </div>`;
}

function toggleRDPSession(idx) {
  _rdpExpanded = (_rdpExpanded === idx) ? null : idx;
  rRDP();
  if (_rdpExpanded !== null) {
    requestAnimationFrame(() => {
      const row = document.querySelector('#panel-rdp .inline-expansion');
      if (row) row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
  }
}
