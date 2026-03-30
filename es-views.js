// es-views.js — EventScope v5 — Tab render functions, inline row expansion
'use strict';

// ── INLINE ROW EXPANSION ───────────────────────────────────────────────────────

let _lastExpandedIdx = null;
let _lastExpandedCtx = null;
let _detailRowIndex  = null;

function buildDetailHTML(r) {
  const isEvtx = S.format === 'evtxecmd';
  const p = parseDet(r.det);
  const pl = Object.entries(p).map(([k,v]) =>
    `<span class="detail-key">${eH(k)}</span>: <span class="detail-val">${eH(v)}</span>`
  ).join('\n');
  const srcField = isEvtx && r.src
    ? `<div class="detail-field"><span class="detail-key">Source File</span>: <span class="detail-val" style="word-break:break-all;white-space:normal">${eH(r.src)}</span></div>`
    : '';
  const ruleSection = `<div class="detail-section"><div class="detail-section-title">${isEvtx?'Event Description':'Rule'}</div><div class="detail-field"><span class="detail-key">${isEvtx?'Description':'Rule Title'}</span>: <span class="detail-val">${eH(r.rule)}</span></div><div class="detail-field"><span class="detail-key">${isEvtx?'Provider':'Rule ID'}</span>: <span class="detail-val">${eH(r.rid)}</span></div></div>`;
  const extraTitle = isEvtx ? 'Raw Payload (JSON)' : 'Extra Field Info';
  return `<div class="detail-inline">
    <div>
      <div class="detail-section"><div class="detail-section-title">Event Metadata</div>
        <div class="detail-field"><span class="detail-key">Timestamp</span>: <span class="detail-val">${!isNaN(r.ts)?fDTz(r.ts):'N/A'}</span></div>
        <div class="detail-field"><span class="detail-key">Event ID</span>: <span class="detail-val">${eL(r.eid)}</span></div>
        <div class="detail-field"><span class="detail-key">Level</span>: ${lB(r.lvl)}</div>
        <div class="detail-field"><span class="detail-key">Computer</span>: <span class="detail-val">${eH(r.comp)}</span></div>
        <div class="detail-field"><span class="detail-key">Channel</span>: <span class="detail-val">${eH(r.chan)}</span></div>
        <div class="detail-field"><span class="detail-key">Record ID</span>: <span class="detail-val">${eH(r.rec)}</span></div>
        ${srcField}
      </div>
      ${ruleSection}
    </div>
    <div>
      <div class="detail-section"><div class="detail-section-title">Payload (Details)</div>
        <div class="detail-payload-block">${pl||'<span style="color:var(--text-dim)">No parsed details</span>'}</div>
      </div>
      ${r.extra && r.extra !== '-' ? `<div class="detail-section"><div class="detail-section-title">${extraTitle}</div><div class="detail-payload-block">${eH(r.extra)}</div></div>` : ''}
    </div>
    <div class="detail-inline-full">
      <div class="detail-section"><div class="detail-section-title">Raw Details String</div>
        <div class="detail-payload-block" style="font-size:10px;color:var(--text-dim)">${eH(r.det)}</div>
      </div>
      <div style="margin-top:8px;display:flex;gap:8px">
        <button class="copy-btn" onclick="copyDetailEvent()">Copy Event</button>
      </div>
    </div>
  </div>`;
}

function openDP(i, navCtx) {
  _detailRowIndex = i;

  // Find target row BEFORE any DOM changes — needed to anchor position
  const tr = document.querySelector(`tr[data-nav-idx="${i}"]`);
  const anchorTop = tr ? tr.getBoundingClientRect().top : null;

  // Close existing expansion, restoring the previously-selected row's position
  const existing = document.querySelector('.inline-expansion');
  if (existing) {
    const oldTr = document.querySelector('tr.row-selected');
    const oldTop = oldTr ? oldTr.getBoundingClientRect().top : null;
    existing.remove();
    if (oldTr && oldTop !== null) {
      const delta = oldTr.getBoundingClientRect().top - oldTop;
      if (Math.abs(delta) > 1) window.scrollBy(0, delta);
    }
  }
  document.querySelectorAll('.row-selected').forEach(el => el.classList.remove('row-selected'));

  // Toggle: same row clicked again — just close
  if (_lastExpandedIdx === i && _lastExpandedCtx === navCtx) {
    _lastExpandedIdx = null;
    _lastExpandedCtx = null;
    S.nav.idx = null;
    return;
  }

  _lastExpandedIdx = i;
  _lastExpandedCtx = navCtx;
  S.nav.idx = i;
  if (navCtx) S.nav.ctx = navCtx;

  const r = getFR()[i];
  if (!r) return;

  if (!tr) { highlightNavRow(); showNavHint(); return; }

  tr.classList.add('row-selected');
  const colCount = tr.cells.length || 7;

  const expansion = document.createElement('tr');
  expansion.className = 'inline-expansion';
  const td = document.createElement('td');
  td.colSpan = colCount;
  td.className = 'inline-expansion-cell';
  td.innerHTML = buildDetailHTML(r);
  expansion.appendChild(td);
  tr.parentNode.insertBefore(expansion, tr.nextSibling);

  // Restore the clicked row to its original viewport position — no jump
  if (anchorTop !== null) {
    const delta = tr.getBoundingClientRect().top - anchorTop;
    if (Math.abs(delta) > 1) window.scrollBy(0, delta);
  }

  showNavHint();
}

// ── NAV HINT & KEYBOARD NAV ───────────────────────────────────────────────────

function showNavHint() {
  const el = document.getElementById('navHint');
  el.classList.add('visible');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('visible'), 4000);
}

function highlightNavRow() {
  document.querySelectorAll('.nav-selected').forEach(el => el.classList.remove('nav-selected'));
  const n = S.nav;
  if (n.ctx === 'raw' && n.idx != null) {
    const tr = document.querySelector(`#rawTableWrap tr[data-nav-idx="${n.idx}"]`);
    if (tr) { tr.classList.add('nav-selected'); tr.scrollIntoView({block:'nearest',behavior:'smooth'}); }
  } else if (n.ctx === 'sequence' && n.clusterIdx != null && n.evtIdx != null) {
    const el = document.querySelector(`.seq-event-line[data-cluster="${n.clusterIdx}"][data-evt="${n.evtIdx}"]`);
    if (el) { el.classList.add('nav-selected'); el.scrollIntoView({block:'nearest',behavior:'smooth'}); }
  }
}

function navMove(delta) {
  const n = S.nav;
  const hasExpansion = !!document.querySelector('.inline-expansion');
  if (!hasExpansion) return false;
  if (n.ctx === 'raw') {
    const rows = getFR(), maxShow = Math.min(2000, rows.length);
    const next = (n.idx || 0) + delta;
    if (next < 0 || next >= maxShow) return true;
    n.idx = next; openDP(next, 'raw'); return true;
  }
  if (n.ctx === 'sequence' && S._seqClusters) {
    const cluster = S._seqClusters[n.clusterIdx];
    if (!cluster) return false;
    const nextEvt = (n.evtIdx || 0) + delta;
    if (nextEvt < 0 || nextEvt >= cluster.events.length) return true;
    n.evtIdx = nextEvt;
    const ev = cluster.events[nextEvt];
    const ri = getFR().indexOf(ev);
    if (ri >= 0) { n.idx = ri; openDP(ri, 'sequence'); }
    return true;
  }
  if (n.ctx === 'periodic') {
    const next = (n.idx || 0) + delta;
    if (next < 0 || next >= _periodicResults.length) return true;
    openPeriodicDetail(next);
    return true;
  }
  if (n.ctx === 'eidfocus' && S.focusEid) {
    const ar = getFR().filter(r => r.eid === S.focusEid).slice(-100).reverse();
    const curRow = getFR()[n.idx];
    let di = ar.indexOf(curRow);
    if (di === -1) di = 0;
    const nextDi = di + delta;
    if (nextDi < 0 || nextDi >= ar.length) return true;
    const tr = ar[nextDi];
    const ri = getFR().indexOf(tr);
    if (ri >= 0) openDP(ri, 'eidfocus');
    return true;
  }
  return false;
}

function navCluster(delta) {
  const n = S.nav;
  if (n.ctx !== 'sequence' || !S._seqClusters) return false;
  const nextCi = (n.clusterIdx || 0) + delta;
  if (nextCi < 0 || nextCi >= S._seqClusters.length) return false;
  const cluster = S._seqClusters[nextCi];
  if (!cluster || !cluster.events.length) return false;
  n.clusterIdx = nextCi; n.evtIdx = 0;
  const ev = cluster.events[0];
  const ri = getFR().indexOf(ev);
  if (ri >= 0) { n.idx = ri; openDP(ri, 'sequence'); }
  return true;
}

// ── EID FOCUS ──────────────────────────────────────────────────────────────────

function focusEid(eid) {
  S.focusEid = eid;
  document.getElementById('tabEidFocus').style.display = '';
  document.getElementById('tabEidFocus').textContent = 'EID ' + eid;
  switchTab('eidfocus');
}

function renderEF() {
  const eid = S.focusEid;
  if (!eid) return;
  document.getElementById('eidFocusTitle').textContent = 'EID ' + eid;
  const ar = getFR().filter(r => r.eid === eid);
  const el = document.getElementById('eidFocusContent');
  const lc = {critical:0,high:0,medium:0,low:0,informational:0};
  const rules = {}, comps = {};
  ar.forEach(r => { lc[r.lvl]++; rules[r.rule]=(rules[r.rule]||0)+1; comps[r.comp]=(comps[r.comp]||0)+1; });
  const tR = Object.entries(rules).sort((a,b) => b[1]-a[1]).slice(0,10);
  const vt = ar.filter(r => !isNaN(r.ts));
  const tMin = vt.length ? new Date(Math.min(...vt.map(r => r.ts))) : null;
  const tMax = vt.length ? new Date(Math.max(...vt.map(r => r.ts))) : null;
  el.innerHTML = `<div class="card-grid">
    <div class="card"><div class="card-label">Total Hits</div><div class="card-value">${ar.length.toLocaleString()}</div></div>
    <div class="card"><div class="card-label">Severity</div><div class="card-sub" style="margin-top:6px"><span class="sev-pip sev-critical"></span>${lc.critical} crit <span class="sev-pip sev-high"></span>${lc.high} high <span class="sev-pip sev-medium"></span>${lc.medium} med <span class="sev-pip sev-low"></span>${lc.low} low</div></div>
    <div class="card"><div class="card-label">Computers</div><div class="card-value">${Object.keys(comps).length}</div><div class="card-sub">${Object.entries(comps).sort((a,b)=>b[1]-a[1]).slice(0,3).map(([c,n])=>c+' ('+n+')').join(', ')}</div></div>
    <div class="card"><div class="card-label">Time Range</div><div class="card-value" style="font-size:13px">${tMin?fDF(tMin):'N/A'}</div><div class="card-sub">${tMax?'to '+fDF(tMax):''}</div></div>
  </div>
  <div class="chart-box"><div class="chart-header"><span class="chart-title">EID ${eid} Timeline</span></div><canvas class="chart-canvas" id="canvasEidFocus" style="height:250px"></canvas></div>
  <div class="chart-box"><div class="chart-header"><span class="chart-title">Associated Rules</span></div><div class="data-table-wrap" style="max-height:300px"><table class="data-table"><thead><tr><th>Rule Title</th><th>Count</th></tr></thead><tbody>${tR.map(([r,c])=>`<tr><td style="white-space:normal;max-width:400px">${eH(r)}</td><td>${c}</td></tr>`).join('')}</tbody></table></div></div>
  <div class="chart-box"><div class="chart-header"><span class="chart-title">Recent Events (last 100)</span></div><div class="data-table-wrap" style="max-height:400px"><table class="data-table"><thead><tr><th>Timestamp</th><th>Level</th><th>Rule</th><th>Computer</th></tr></thead><tbody>${ar.slice(-100).reverse().map((r,i)=>`<tr style="cursor:pointer" data-nav-idx="${i}" onclick="openEFD(${i},'${eid}')"><td>${!isNaN(r.ts)?fDTz(r.ts):'N/A'}</td><td>${lB(r.lvl)}</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis" title="${eH(r.rule)}">${eH(r.rule)}</td><td>${r.comp}</td></tr>`).join('')}</tbody></table></div></div>`;
  if (vt.length) {
    const mn = Math.min(...vt.map(r => r.ts)), mx = Math.max(...vt.map(r => r.ts));
    const bMs = aBMs(mn, mx), tl = bTL(vt, bMs);
    setTimeout(() => {
      drawBC(document.getElementById('canvasEidFocus'), tl.labels, tl.values);
      aCT(document.getElementById('canvasEidFocus'));
    }, 50);
  }
}

function openEFD(di, eid) {
  const ar = getFR().filter(r => r.eid === eid).slice(-100).reverse();
  const tr = ar[di];
  if (!tr) return;
  const ri = getFR().indexOf(tr);
  if (ri >= 0) openDP(ri, 'eidfocus');
}

// ── SEQUENCE ANALYSIS ──────────────────────────────────────────────────────────

function runSeq() {
  const es = document.getElementById('seqEidInput').value.trim();
  const ws = parseInt(document.getElementById('seqWindowInput').value) || 60;
  if (!es) {
    document.getElementById('seqResults').innerHTML = '<div class="anomaly-item info"><div class="anomaly-title">Enter Event IDs above</div></div>';
    return;
  }
  const tEids = new Set(es.split(',').map(s => s.trim()).filter(Boolean));
  const wMs = ws * 1000;
  const rows = getFR().filter(r => tEids.has(r.eid) && !isNaN(r.ts)).sort((a,b) => a.ts-b.ts);
  if (!rows.length) {
    document.getElementById('seqResults').innerHTML = '<div class="anomaly-item info"><div class="anomaly-title">No matching events</div></div>';
    document.getElementById('seqSummary').innerHTML = '';
    return;
  }
  const clusters = [];
  let cc = [rows[0]];
  for (let i = 1; i < rows.length; i++) {
    if (rows[i].ts - cc[cc.length-1].ts <= wMs) cc.push(rows[i]);
    else { if (cc.length >= 2) clusters.push([...cc]); cc = [rows[i]]; }
  }
  if (cc.length >= 2) clusters.push(cc);

  const cd = clusters.map(ev => {
    const dl = [];
    for (let i = 1; i < ev.length; i++) dl.push(ev[i].ts - ev[i-1].ts);
    const span = ev[ev.length-1].ts - ev[0].ts;
    const avg = dl.length ? dl.reduce((a,b) => a+b, 0) / dl.length : 0;
    const ue = new Set(ev.map(e => e.eid)).size;
    let beh = 'human';
    if (avg < 500) beh = 'scripted';
    else if (avg < 5000) beh = 'fast';
    return {events:ev, deltas:dl, totalSpan:span, avgDelta:avg, maxDelta:Math.max(...dl,0), minDelta:Math.min(...dl,Infinity), uniqueEids:ue, behavior:beh};
  });

  const sc = cd.filter(c => c.behavior==='scripted').length;
  const fc = cd.filter(c => c.behavior==='fast').length;
  const hc = cd.filter(c => c.behavior==='human').length;
  const aD = cd.map(c => c.avgDelta), as = cStats(aD);
  document.getElementById('seqSummary').innerHTML = `<div class="card-grid" style="margin-bottom:16px">
    <div class="card"><div class="card-label">Clusters</div><div class="card-value">${clusters.length}</div><div class="card-sub">${rows.length} events in ${ws}s window</div></div>
    <div class="card" style="border-left:3px solid var(--critical)"><div class="card-label">Scripted (&lt;500ms)</div><div class="card-value" style="color:var(--critical)">${sc}</div></div>
    <div class="card" style="border-left:3px solid var(--warn)"><div class="card-label">Fast (500ms–5s)</div><div class="card-value" style="color:var(--warn)">${fc}</div></div>
    <div class="card" style="border-left:3px solid var(--success)"><div class="card-label">Human (&gt;5s)</div><div class="card-value" style="color:var(--success)">${hc}</div></div>
    <div class="card"><div class="card-label">Mean Inter-Event</div><div class="card-value" style="font-size:18px">${fDelta(as.mean)}</div><div class="card-sub">σ = ${fDelta(as.std)}</div></div>
  </div>`;

  cd.sort((a,b) => a.events[0].ts - b.events[0].ts);
  document.getElementById('seqResults').innerHTML = cd.slice(0,200).map((c,ci) =>
    `<div class="seq-cluster ${c.behavior}">
      <div class="seq-cluster-header">
        <div>${c.behavior==='scripted'?'<span class="badge badge-critical">SCRIPTED</span>':c.behavior==='fast'?'<span class="badge badge-warn">FAST</span>':'<span class="badge badge-ok">HUMAN</span>'} ${c.events.length} events, ${c.uniqueEids} unique EIDs</div>
        <div style="display:flex;align-items:center;gap:8px">
          <div class="seq-cluster-timing" style="color:${lC(c.behavior==='scripted'?'critical':c.behavior==='fast'?'medium':'informational')}">avg ${fDelta(c.avgDelta)} span ${fDelta(c.totalSpan)}</div>
          <button class="copy-btn" onclick="copyCluster(${ci})">Copy</button>
        </div>
      </div>
      ${c.events.map((ev,i) => `<div class="seq-event-line" data-cluster="${ci}" data-evt="${i}" onclick="openSD(${ci},${i})"><span class="seq-delta">${i>0?'+'+fDelta(c.deltas[i-1]):'—'}</span><span class="seq-ts">${fDTz(ev.ts)}</span><span class="seq-eid-tag">EID ${ev.eid}</span><span class="seq-rule">${eH(ev.rule)}</span></div>`).join('')}
    </div>`
  ).join('');
  S._seqClusters = cd;
}

function openSD(ci, ei) {
  const c = S._seqClusters?.[ci];
  if (!c) return;
  const ev = c.events[ei];
  if (!ev) return;
  S.nav.clusterIdx = ci;
  S.nav.evtIdx = ei;
  const ri = getFR().indexOf(ev);
  if (ri >= 0) openDP(ri, 'sequence');
}

// ── TAB RENDER FUNCTIONS ───────────────────────────────────────────────────────

function rOV() {
  const rows = getFR(), tot = rows.length;
  const uR = new Set(rows.map(r => r.rule)).size;
  const uC = new Set(rows.map(r => r.comp)).size;
  const vt = rows.filter(r => !isNaN(r.ts));
  const tMin = vt.length ? new Date(Math.min(...vt.map(r=>r.ts))) : null;
  const tMax = vt.length ? new Date(Math.max(...vt.map(r=>r.ts))) : null;
  const lc = {critical:0,high:0,medium:0,low:0,informational:0};
  rows.forEach(r => lc[r.lvl]++);

  document.getElementById('overviewCards').innerHTML =
    `<div class="card"><div class="card-label">Total Detections</div><div class="card-value">${tot.toLocaleString()}</div></div>
     <div class="card" style="border-left:3px solid var(--critical)"><div class="card-label">Critical / High</div><div class="card-value" style="color:var(--orange)">${(lc.critical+lc.high).toLocaleString()}</div><div class="card-sub"><span class="sev-pip sev-critical"></span>${lc.critical} crit <span class="sev-pip sev-high"></span>${lc.high} high</div></div>
     <div class="card" style="border-left:3px solid var(--medium)"><div class="card-label">Medium / Low</div><div class="card-value" style="color:var(--warn)">${(lc.medium+lc.low).toLocaleString()}</div><div class="card-sub"><span class="sev-pip sev-medium"></span>${lc.medium} med <span class="sev-pip sev-low"></span>${lc.low} low</div></div>
     <div class="card"><div class="card-label">Unique Rules</div><div class="card-value">${uR.toLocaleString()}</div></div>
     <div class="card"><div class="card-label">Computers</div><div class="card-value">${uC.toLocaleString()}</div></div>
     <div class="card"><div class="card-label">Time Range</div><div class="card-value" style="font-size:14px">${tMin?fDF(tMin):'N/A'}</div><div class="card-sub">${tMax?'to '+fDF(tMax):''}</div></div>`;

  document.getElementById('headerStats').innerHTML =
    `<span class="header-stat"><strong>${tot.toLocaleString()}</strong> det</span>
     <span class="header-stat"><span class="sev-pip sev-critical"></span><strong>${lc.critical}</strong></span>
     <span class="header-stat"><span class="sev-pip sev-high"></span><strong>${lc.high}</strong></span>
     <span class="header-stat"><span class="sev-pip sev-medium"></span><strong>${lc.medium}</strong></span>
     <span class="header-stat"><strong>${uC}</strong> hosts</span>`;

  const tsR = rows.filter(r => !isNaN(r.ts));
  const bMs = gBMs(S.bucketPref['timelineAll'], S.timeMin, S.timeMax);
  const tl = bTL(tsR, bMs);
  drawBC(document.getElementById('canvasTimelineAll'), tl.labels, tl.values);
  aCT(document.getElementById('canvasTimelineAll'));

  const sl = ['critical','high','medium','low','informational'];
  drawHBC(document.getElementById('canvasSeverity'), sl, sl.map(l => lc[l]||0), sl.map(l => lC(l)));

  const ec = {};
  rows.forEach(r => ec[r.eid] = (ec[r.eid]||0)+1);
  const es = Object.entries(ec).sort((a,b) => b[1]-a[1]).slice(0,20);
  drawHBC(document.getElementById('canvasTopEvents'), es.map(s=>'EID '+s[0]), es.map(s=>s[1]));

  const cc = {};
  rows.forEach(r => { if (r.chan) cc[r.chan] = (cc[r.chan]||0)+1; });
  const cs = Object.entries(cc).sort((a,b) => b[1]-a[1]).slice(0,15);
  drawHBC(document.getElementById('canvasChannels'), cs.map(s=>s[0]), cs.map(s=>s[1]));
}

function rTL() {
  const rows = getFR().filter(r => !isNaN(r.ts));
  const tMin = rows.length ? Math.min(...rows.map(r=>r.ts)) : S.timeMin;
  const tMax = rows.length ? Math.max(...rows.map(r=>r.ts)) : S.timeMax;
  const bMs = gBMs(S.bucketPref['timelineFiltered'], tMin, tMax);
  const tl = bTL(rows, bMs);
  drawBC(document.getElementById('canvasTimelineFiltered'), tl.labels, tl.values);
  aCT(document.getElementById('canvasTimelineFiltered'));
  const sv = bTLSev(rows, bMs);
  drawSBC(document.getElementById('canvasSevTimeline'), sv.labels, sv.series);
  const bu = dBursts(rows, bMs);
  document.getElementById('burstList').innerHTML = bu.length
    ? bu.map(b => {
        const startMs = b.start.getTime(), endMs = b.end.getTime();
        return `<div class="anomaly-item ${b.zscore>6?'':'warn'}" style="cursor:pointer" title="Click to jump to first event in this burst" onclick="jumpToBurst(${startMs},${endMs})">
          <div class="anomaly-title"><span class="badge ${b.zscore>6?'badge-danger':'badge-warn'}">${b.zscore.toFixed(1)}σ</span> ${b.count.toLocaleString()} det <span style="font-size:10px;color:var(--text-dim);font-weight:400;margin-left:8px">▶ jump to raw</span></div>
          <div class="anomaly-detail">${fDF(b.start)} → ${fDF(b.end)}<br>Baseline: ${b.baseline.toFixed(1)}/window</div>
        </div>`;
      }).join('')
    : '<div class="anomaly-item info"><div class="anomaly-title">No bursts detected</div></div>';
}

function rRU() {
  const rows = getFR(), ra = {};
  rows.forEach(r => {
    if (!r.rule) return;
    if (!ra[r.rule]) ra[r.rule] = {rule:r.rule, rid:r.rid, lvl:r.lvl, count:0, eids:new Set(), chans:new Set(), comps:new Set()};
    ra[r.rule].count++;
    if (r.eid)  ra[r.rule].eids.add(r.eid);
    if (r.chan)  ra[r.rule].chans.add(r.chan);
    if (r.comp)  ra[r.rule].comps.add(r.comp);
    if (LW[r.lvl] > LW[ra[r.rule].lvl]) ra[r.rule].lvl = r.lvl;
  });
  const s = Object.values(ra).sort((a,b) => {
    const w = (LW[b.lvl]||0) - (LW[a.lvl]||0);
    return w !== 0 ? w : b.count - a.count;
  });
  document.getElementById('ruleTable').innerHTML =
    `<table class="data-table"><thead><tr><th>Level</th><th>Rule Title</th><th>Count</th><th>Event IDs</th><th>Channels</th><th>Computers</th><th>Rule ID</th></tr></thead><tbody>${
      s.map(r => `<tr><td>${lB(r.lvl)}</td><td style="white-space:normal;max-width:350px">${eH(r.rule)}</td><td>${r.count.toLocaleString()}</td><td>${[...r.eids].slice(0,5).map(e=>eL(e)).join(', ')}${r.eids.size>5?' …':''}</td><td>${[...r.chans].slice(0,2).join(', ')}${r.chans.size>2?' …':''}</td><td>${[...r.comps].slice(0,3).join(', ')}${r.comps.size>3?' …':''}</td><td style="font-size:10px;color:var(--text-dim)" title="${eH(r.rid)}">${r.rid.substring(0,8)}…</td></tr>`)
      .join('')
    }</tbody></table>`;
}

function rFR() {
  const rows = getFR();
  const ec = {};
  rows.forEach(r => ec[r.eid] = (ec[r.eid]||0)+1);
  const es = Object.entries(ec).sort((a,b) => b[1]-a[1]);
  const est = cStats(es.map(e => e[1]));
  const eo = new Set(dFO(ec).map(o => o.key));
  document.getElementById('freqEventTable').innerHTML = mFT(['Event ID','Count','Pct','Z-Score','Flag'],
    es.map(([eid,c]) => {
      const z = est.std > 0 ? (c-est.mean)/est.std : 0;
      return [eL(eid), c.toLocaleString(), ((c/rows.length)*100).toFixed(2)+'%', z.toFixed(2),
        eo.has(eid) ? (z>0 ? '<span class="badge badge-danger">HIGH</span>' : '<span class="badge badge-warn">RARE</span>') : '<span class="badge badge-ok">OK</span>'];
    }));
  const cc = {};
  rows.forEach(r => { if (r.chan) cc[r.chan] = (cc[r.chan]||0)+1; });
  document.getElementById('freqChannelTable').innerHTML = mFT(['Channel','Count','Pct'],
    Object.entries(cc).sort((a,b) => b[1]-a[1]).map(([c,n]) => [c, n.toLocaleString(), ((n/rows.length)*100).toFixed(2)+'%']));
  const mc = {};
  rows.forEach(r => { if (r.comp) mc[r.comp] = (mc[r.comp]||0)+1; });
  document.getElementById('freqComputerTable').innerHTML = mFT(['Computer','Count','Pct'],
    Object.entries(mc).sort((a,b) => b[1]-a[1]).map(([c,n]) => [c, n.toLocaleString(), ((n/rows.length)*100).toFixed(2)+'%']));
  const todSel = document.getElementById('todComputer');
  const todCur = todSel.value;
  todSel.innerHTML = '<option value="">All Computers</option>';
  Object.keys(mc).sort().forEach(c => todSel.innerHTML += `<option value="${eH(c)}"${c===todCur?' selected':''}>${eH(c)}</option>`);
  renderTOD();
}

function rAN() {
  const rows = getFR(), an = [];
  const rs = {};
  rows.forEach(r => {
    if (!r.rule) return;
    if (!rs[r.rule]) rs[r.rule] = {lvl:r.lvl, count:0, rid:r.rid};
    rs[r.rule].count++;
    if (LW[r.lvl] > LW[rs[r.rule].lvl]) rs[r.rule].lvl = r.lvl;
  });
  for (const [rule,d] of Object.entries(rs)) {
    if (d.lvl === 'critical') an.push({severity:'critical', title:'Critical: '+eH(rule), detail:'Count: '+d.count+' | Rule: '+d.rid});
    else if (d.lvl === 'high') an.push({severity:'danger', title:'High: '+eH(rule), detail:'Count: '+d.count+' | Rule: '+d.rid});
  }
  const ec = {};
  rows.forEach(r => ec[r.eid] = (ec[r.eid]||0)+1);
  for (const o of dFO(ec).slice(0,15))
    an.push({severity:o.type==='high'?'warn':'info', title:(o.type==='high'?'Frequent':'Rare')+' EID '+o.key, detail:'Count: '+o.count+' | Z: '+o.zscore.toFixed(2)});
  const tr = rows.filter(r => !isNaN(r.ts));
  if (tr.length > 1) {
    const mn = Math.min(...tr.map(r=>r.ts)), mx = Math.max(...tr.map(r=>r.ts));
    for (const b of dBursts(tr, aBMs(mn,mx)).slice(0,10))
      an.push({severity:b.zscore>6?'critical':'warn', title:'Burst: '+b.count+' det ('+b.zscore.toFixed(1)+'σ)', detail:fDF(b.start)+' → '+fDF(b.end)});
  }
  const so = {critical:0,danger:1,warn:2,info:3};
  an.sort((a,b) => (so[a.severity]||9) - (so[b.severity]||9));
  const cn = {critical:an.filter(a=>a.severity==='critical').length, danger:an.filter(a=>a.severity==='danger').length, warn:an.filter(a=>a.severity==='warn').length, info:an.filter(a=>a.severity==='info').length};
  document.getElementById('anomalyCards').innerHTML =
    `<div class="card" style="border-left:3px solid var(--critical)"><div class="card-label">Critical</div><div class="card-value" style="color:var(--critical)">${cn.critical}</div></div>
     <div class="card" style="border-left:3px solid var(--orange)"><div class="card-label">High</div><div class="card-value" style="color:var(--orange)">${cn.danger}</div></div>
     <div class="card" style="border-left:3px solid var(--warn)"><div class="card-label">Warnings</div><div class="card-value" style="color:var(--warn)">${cn.warn}</div></div>
     <div class="card" style="border-left:3px solid var(--low)"><div class="card-label">Info</div><div class="card-value" style="color:var(--low)">${cn.info}</div></div>`;
  document.getElementById('anomalyList').innerHTML = an.length
    ? an.map(a => `<div class="anomaly-item ${a.severity}"><div class="anomaly-title">${a.title}</div><div class="anomaly-detail">${a.detail}</div></div>`).join('')
    : '<div class="anomaly-item info"><div class="anomaly-title">No anomalies</div></div>';
}

let _rawSelection = new Set();
let _lastCheckIdx = null;

function updateRawSelectionUI() {
  const btn = document.getElementById('copySelectedBtn');
  if (!btn) return;
  if (_rawSelection.size > 0) {
    btn.textContent = `Copy Selected (${_rawSelection.size})`;
    btn.style.display = '';
  } else {
    btn.style.display = 'none';
  }
  // Sync checkbox visuals
  document.querySelectorAll('#rawTableWrap .row-check').forEach(cb => {
    cb.checked = _rawSelection.has(Number(cb.dataset.idx));
  });
  const allCb = document.getElementById('rawSelectAll');
  if (allCb) {
    const total = Math.min(2000, getFR().length);
    allCb.checked = _rawSelection.size === total && total > 0;
    allCb.indeterminate = _rawSelection.size > 0 && _rawSelection.size < total;
  }
}

function onRawCheck(i, el, event) {
  if (event.shiftKey && _lastCheckIdx !== null) {
    const lo = Math.min(i, _lastCheckIdx), hi = Math.max(i, _lastCheckIdx);
    for (let j = lo; j <= hi; j++) {
      if (el.checked) _rawSelection.add(j); else _rawSelection.delete(j);
    }
  } else {
    if (el.checked) _rawSelection.add(i); else _rawSelection.delete(i);
  }
  _lastCheckIdx = i;
  updateRawSelectionUI();
}

function rawSelectAll(el) {
  _rawSelection.clear();
  if (el.checked) {
    const total = Math.min(2000, getFR().length);
    for (let i = 0; i < total; i++) _rawSelection.add(i);
  }
  updateRawSelectionUI();
}

function copySelectedRows() {
  const rows = getFR().slice(0, 2000);
  const selected = [..._rawSelection].sort((a,b) => a-b).map(i => rows[i]).filter(Boolean);
  copyRows(selected);
}

function rRW() {
  _rawSelection.clear();
  updateRawSelectionUI();
  const rows = getFR(), mx = 2000, sh = rows.slice(0, mx);
  document.getElementById('rawCount').textContent =
    `Showing ${Math.min(mx,rows.length).toLocaleString()} of ${rows.length.toLocaleString()}`;
  const isEvtx = S.format === 'evtxecmd';
  const hdr = `<th style="width:28px;padding:6px 8px"><input type="checkbox" id="rawSelectAll" onchange="rawSelectAll(this)" style="accent-color:var(--orange);cursor:pointer"></th><th>Timestamp</th><th>Level</th><th>EID</th><th>${isEvtx?'Description':'Rule Title'}</th><th>Computer</th><th>Channel</th><th>Record</th>${isEvtx?'<th>Source</th>':''}`;
  document.getElementById('rawTableWrap').innerHTML =
    `<table class="data-table"><thead><tr>${hdr}</tr></thead><tbody>${
      sh.map((r,i) => {
        const srcCell = isEvtx
          ? `<td style="max-width:160px;overflow:hidden;text-overflow:ellipsis" title="${eH(r.src||'')}">${eH((r.src||'').split(/[/\\]/).pop())}</td>`
          : '';
        return `<tr style="cursor:pointer" data-nav-idx="${i}" onclick="openDP(${i},'raw')">
          <td style="padding:6px 8px" onclick="event.stopPropagation()"><input type="checkbox" class="row-check" data-idx="${i}" style="accent-color:var(--orange);cursor:pointer" onchange="onRawCheck(${i},this,event)" onclick="event.stopPropagation()"></td>
          <td>${!isNaN(r.ts)?fDTz(r.ts):'N/A'}</td>
          <td>${lB(r.lvl)}</td>
          <td>${eL(r.eid)}</td>
          <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis" title="${eH(r.rule)}">${eH(r.rule)}</td>
          <td>${r.comp}</td>
          <td>${r.chan.length>25?r.chan.substring(0,23)+'…':r.chan}</td>
          <td>${r.rec}</td>
          ${srcCell}
        </tr>`;
      }).join('')
    }</tbody></table>`;
}

// ── PERIODICITY ────────────────────────────────────────────────────────────────

let _periodicResults = [];

function openPeriodicDetail(idx) {
  // Remove any expansion in periodic table
  const existing = document.querySelector('#periodicTable .inline-expansion');
  if (existing) {
    const wasIdx = Number(existing.dataset.forIdx);
    existing.remove();
    if (wasIdx === idx) { S.nav.idx = null; S.nav.ctx = null; return; }
  }
  document.querySelectorAll('#periodicTable tr.row-selected').forEach(el => el.classList.remove('row-selected'));

  const pr = _periodicResults[idx];
  if (!pr) return;

  S.nav.ctx = 'periodic';
  S.nav.idx = idx;

  const tr = document.querySelector(`#periodicTable tr[data-nav-idx="${idx}"]`);
  if (!tr) return;
  tr.classList.add('row-selected');
  const anchorTop = tr.getBoundingClientRect().top;

  // Get recent events for this EID
  const evts = getFR().filter(r => r.eid === pr.eid && !isNaN(r.ts))
    .sort((a,b) => b.ts - a.ts).slice(0, 20);
  const desc = S.eidDescs[pr.eid] ? `<span style="color:var(--text-dim);font-size:11px"> — ${eH(S.eidDescs[pr.eid])}</span>` : '';
  const evtRows = evts.map(r =>
    `<div style="font-family:var(--mono);font-size:11px;padding:3px 0;border-bottom:1px solid var(--border);display:flex;gap:12px;cursor:pointer" onclick="jumpToRaw(${getFR().indexOf(r)})">
      <span style="color:var(--stone);min-width:190px">${fDTz(r.ts)}</span>
      <span>${lB(r.lvl)}</span>
      <span style="color:var(--text-dim);overflow:hidden;text-overflow:ellipsis">${eH(r.rule||r.comp)}</span>
    </div>`
  ).join('');

  const expansion = document.createElement('tr');
  expansion.className = 'inline-expansion';
  expansion.dataset.forIdx = idx;
  const td = document.createElement('td');
  td.colSpan = tr.cells.length;
  td.className = 'inline-expansion-cell';
  td.innerHTML = `<div style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--orange);margin-bottom:10px">EID ${pr.eid}${desc}</div>
    <div style="display:flex;gap:24px;margin-bottom:12px;font-family:var(--mono);font-size:12px">
      <span><span style="color:var(--text-dim)">Median interval:</span> <strong>${fDelta(pr.median)}</strong></span>
      <span><span style="color:var(--text-dim)">CV:</span> <strong style="color:${pr.periodic?'var(--success)':'var(--text-dim)'}">${pr.cv.toFixed(3)}</strong></span>
      <span><span style="color:var(--text-dim)">Count:</span> <strong>${pr.count.toLocaleString()}</strong></span>
    </div>
    <div style="color:var(--text-dim);font-family:var(--mono);font-size:11px;margin-bottom:6px">Recent events (click to open in Raw Data):</div>
    ${evtRows || '<div style="color:var(--text-dim);font-family:var(--mono);font-size:11px">No events in current filter</div>'}`;
  expansion.appendChild(td);
  tr.parentNode.insertBefore(expansion, tr.nextSibling);

  const delta = tr.getBoundingClientRect().top - anchorTop;
  if (Math.abs(delta) > 1) window.scrollBy(0, delta);
  showNavHint();
}

function jumpToRaw(i) {
  switchTab('raw');
  setTimeout(() => openDP(i, 'raw'), 50);
}

function jumpToBurst(startMs, endMs) {
  // Find index of first event in burst window
  const rows = getFR();
  const i = rows.findIndex(r => !isNaN(r.ts) && r.ts >= startMs && r.ts <= endMs);
  if (i < 0) return;
  switchTab('raw');
  // Scroll raw table to that row and open its detail
  setTimeout(() => {
    const tr = document.querySelector(`#rawTableWrap tr[data-nav-idx="${i}"]`);
    if (tr) tr.scrollIntoView({ block: 'center', behavior: 'smooth' });
    openDP(i, 'raw');
  }, 50);
}

const PERIODIC_REFS = [
  {label:'15min',ms:15*60000},{label:'30min',ms:30*60000},{label:'1h',ms:3600000},
  {label:'2h',ms:7200000},{label:'4h',ms:4*3600000},{label:'6h',ms:6*3600000},
  {label:'8h',ms:8*3600000},{label:'12h',ms:12*3600000},{label:'24h',ms:86400000},
];

function classifyPeriod(medianMs) {
  let best = null, bestDiff = Infinity;
  for (const ref of PERIODIC_REFS) {
    const diff = Math.abs(medianMs - ref.ms) / ref.ms;
    if (diff < 0.15 && diff < bestDiff) { best = ref; bestDiff = diff; }
  }
  return best ? best.label : null;
}

function rPeriodic() {
  const minEv = parseInt(document.getElementById('periodicMinEvents')?.value) || 10;
  const maxCV = parseFloat(document.getElementById('periodicMaxCV')?.value)   || 0.4;
  const rows  = getFR().filter(r => !isNaN(r.ts));
  const byEid = new Map();
  for (const r of rows) { if (!byEid.has(r.eid)) byEid.set(r.eid,[]); byEid.get(r.eid).push(r.ts); }
  const results = [];
  for (const [eid,ts] of byEid) {
    if (ts.length < minEv) continue;
    ts.sort((a,b) => a-b);
    const intervals = [];
    for (let i = 1; i < ts.length; i++) intervals.push(ts[i]-ts[i-1]);
    const st = cStats(intervals);
    if (st.median === 0) continue;
    const cv = st.std / st.median;
    const label = classifyPeriod(st.median);
    results.push({eid, count:ts.length, median:st.median, std:st.std, cv, periodic:cv<=maxCV, periodLabel:label, first:ts[0], last:ts[ts.length-1]});
  }
  results.sort((a,b) => a.cv-b.cv);
  _periodicResults = results;
  const periodicCount = results.filter(r => r.periodic).length;
  document.getElementById('periodicCards').innerHTML = `
    <div class="card"><div class="card-label">EIDs Analyzed</div><div class="card-value">${results.length.toLocaleString()}</div></div>
    <div class="card" style="border-left:3px solid var(--success)"><div class="card-label">Periodic (CV ≤ ${maxCV})</div><div class="card-value" style="color:var(--success)">${periodicCount}</div></div>
    <div class="card"><div class="card-label">Irregular</div><div class="card-value">${(results.length-periodicCount).toLocaleString()}</div></div>`;
  if (!results.length) {
    document.getElementById('periodicTable').innerHTML = '<div style="padding:20px;color:var(--text-dim);font-family:var(--mono)">No EIDs with enough events to analyze.</div>';
    return;
  }
  document.getElementById('periodicTable').innerHTML =
    `<table class="data-table"><thead><tr><th>Event ID</th><th>Count</th><th>Median Interval</th><th>Std Dev</th><th>CV</th><th>Matches</th><th>Classification</th></tr></thead><tbody>${
      results.slice(0,200).map((r,i) => `<tr style="cursor:pointer" data-nav-idx="${i}" onclick="openPeriodicDetail(${i})">
        <td>${eL(r.eid)}${S.eidDescs[r.eid]?`<br><span style="color:var(--text-dim);font-size:10px">${eH(S.eidDescs[r.eid])}</span>`:''}</td>
        <td>${r.count.toLocaleString()}</td>
        <td style="font-family:var(--mono);font-size:11px">${fDelta(r.median)}</td>
        <td style="font-family:var(--mono);font-size:11px">${fDelta(r.std)}</td>
        <td style="font-family:var(--mono);font-size:12px;color:${r.periodic?'var(--success)':'var(--text-dim)'}">${r.cv.toFixed(3)}</td>
        <td style="font-family:var(--mono);font-size:11px;color:var(--orange)">${r.periodLabel||'—'}</td>
        <td>${r.periodic?'<span class="badge badge-ok">PERIODIC</span>':'<span class="badge">IRREGULAR</span>'}</td>
      </tr>`).join('')
    }</tbody></table>`;
}

// ── GAP ANALYSIS ───────────────────────────────────────────────────────────────

let _gapResults = [];

function popGapCompFilter() {
  const sel = document.getElementById('gapCompFilter');
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = '<option value="">All Computers</option>';
  Object.keys(S.computerCounts).sort().forEach(c =>
    sel.innerHTML += `<option value="${eH(c)}"${c===cur?' selected':''}>${eH(c)}</option>`
  );
}

function runGapAnalysis() {
  const minMs   = (parseFloat(document.getElementById('gapMinutes')?.value) || 15) * 60000;
  const sigTh   = parseFloat(document.getElementById('gapSigma')?.value) || 3;
  const compFilt = document.getElementById('gapCompFilter')?.value || '';
  let rows = getFR().filter(r => !isNaN(r.ts));
  if (compFilt) rows = rows.filter(r => r.comp === compFilt);
  const byComp = new Map();
  for (const r of rows) { if (!byComp.has(r.comp)) byComp.set(r.comp,[]); byComp.get(r.comp).push(r); }
  const gaps = [];
  for (const [comp,crows] of byComp) {
    const sorted = [...crows].sort((a,b) => a.ts-b.ts);
    const ts = sorted.map(r => r.ts);
    if (ts.length < 4) continue;
    const intervals = [];
    for (let i = 1; i < ts.length; i++) intervals.push(ts[i]-ts[i-1]);
    const st = cStats(intervals);
    const statTh = st.mean + sigTh*st.std;
    for (let i = 1; i < ts.length; i++) {
      const gap = ts[i]-ts[i-1];
      if (gap >= minMs && gap >= statTh) {
        const before = sorted[i-1], after = sorted[i];
        gaps.push({comp, start:ts[i-1], end:ts[i], duration:gap, zscore:st.std>0?(gap-st.mean)/st.std:0, baseline:st.mean, baselineStr:fDelta(st.mean), beforeRule:before.rule, beforeEid:before.eid, afterRule:after.rule, afterEid:after.eid});
      }
    }
  }
  gaps.sort((a,b) => b.duration-a.duration);
  _gapResults = gaps;
  renderGapResults(gaps);
}

function renderGapResults(gaps) {
  const longest = gaps[0];
  const hostCounts = {};
  gaps.forEach(g => hostCounts[g.comp] = (hostCounts[g.comp]||0)+1);
  const topHost = Object.entries(hostCounts).sort((a,b) => b[1]-a[1])[0];
  document.getElementById('gapCards').innerHTML = `
    <div class="card" style="border-left:3px solid var(--warn)"><div class="card-label">Gaps Found</div><div class="card-value" style="color:var(--warn)">${gaps.length.toLocaleString()}</div></div>
    <div class="card"><div class="card-label">Hosts Analyzed</div><div class="card-value">${new Set(gaps.map(g=>g.comp)).size}</div></div>
    <div class="card" style="border-left:3px solid var(--orange)"><div class="card-label">Longest Gap</div><div class="card-value" style="font-size:16px">${longest?fDelta(longest.duration):'N/A'}</div><div class="card-sub">${longest?longest.comp:''}</div></div>
    <div class="card"><div class="card-label">Most Gaps</div><div class="card-value" style="font-size:16px">${topHost?topHost[1]:'N/A'}</div><div class="card-sub">${topHost?topHost[0]:''}</div></div>`;

  const wrap = document.getElementById('gapChartWrap');
  const topList = document.getElementById('gapTopList');
  if (!gaps.length) {
    wrap.innerHTML = '';
    topList.innerHTML = '<div style="padding:20px;color:var(--text-dim);font-family:var(--mono)">No gaps found. Try reducing the minimum gap or σ threshold.</div>';
    return;
  }

  // Build canvas gap chart
  const hosts = [...new Set(gaps.map(g => g.comp))].sort();
  const allRows = getFR().filter(r => !isNaN(r.ts));
  const tMin = allRows.length ? Math.min(...allRows.map(r=>r.ts)) : gaps[0].start;
  const tMax = allRows.length ? Math.max(...allRows.map(r=>r.ts)) : gaps[gaps.length-1].end;
  const tSpan = tMax - tMin || 1;

  const PAD_L = 160, PAD_R = 24, PAD_T = 32, PAD_B = 28;
  const ROW_H = 32;
  const totalH = PAD_T + hosts.length * ROW_H + PAD_B;
  const dpr = window.devicePixelRatio || 1;
  const cw = Math.max(800, (wrap.clientWidth || window.innerWidth - 80));

  wrap.innerHTML = `<canvas id="gapCanvas" style="display:block"></canvas>`;
  const cvs = document.getElementById('gapCanvas');
  cvs.width  = cw * dpr;
  cvs.height = totalH * dpr;
  cvs.style.width  = cw + 'px';
  cvs.style.height = totalH + 'px';
  const ctx = cvs.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, cw, totalH);

  const chartW = cw - PAD_L - PAD_R;
  function tX(ts) { return PAD_L + ((ts - tMin) / tSpan) * chartW; }

  // Time axis ticks
  ctx.fillStyle = '#6e7f90';
  ctx.font = '10px JetBrains Mono,monospace';
  ctx.textAlign = 'center';
  const tickCount = Math.min(8, Math.floor(chartW / 80));
  for (let i = 0; i <= tickCount; i++) {
    const ts = tMin + (tSpan / tickCount) * i;
    const x = tX(ts);
    ctx.fillStyle = '#1a3a55';
    ctx.fillRect(x, PAD_T - 8, 1, hosts.length * ROW_H + 8);
    ctx.fillStyle = '#6e7f90';
    ctx.fillText(fDS(new Date(ts)), x, PAD_T - 12);
  }

  hosts.forEach((comp, hi) => {
    const y  = PAD_T + hi * ROW_H;
    const cy = y + ROW_H / 2;

    // Host label
    ctx.fillStyle = '#6e7f90';
    ctx.font = '11px JetBrains Mono,monospace';
    ctx.textAlign = 'right';
    const lbl = comp.length > 22 ? comp.substring(0, 20) + '…' : comp;
    ctx.fillText(lbl, PAD_L - 8, cy + 4);

    // Baseline track
    ctx.strokeStyle = '#1a3a55';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(PAD_L, cy);
    ctx.lineTo(cw - PAD_R, cy);
    ctx.stroke();

    // Gap blocks
    for (const g of gaps.filter(g => g.comp === comp)) {
      const x1  = tX(g.start);
      const x2  = tX(g.end);
      const bW  = Math.max(3, x2 - x1);
      const col = g.zscore > 6 ? '#ff3a3a' : g.zscore > 3 ? '#DC551F' : '#f0a830';
      ctx.fillStyle = col;
      ctx.globalAlpha = 0.75;
      ctx.fillRect(x1, y + 5, bW, ROW_H - 10);
      ctx.globalAlpha = 1;
      if (bW > 36) {
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 10px JetBrains Mono,monospace';
        ctx.textAlign = 'center';
        ctx.fillText(fDelta(g.duration), x1 + bW / 2, cy + 4);
      }
    }
  });

  // Bottom time label
  ctx.fillStyle = '#6e7f90';
  ctx.font = '10px JetBrains Mono,monospace';
  ctx.textAlign = 'left';
  ctx.fillText(fDS(new Date(tMin)), PAD_L, totalH - 6);
  ctx.textAlign = 'right';
  ctx.fillText(fDS(new Date(tMax)), cw - PAD_R, totalH - 6);

  // Tooltip on hover
  cvs._gapData = { hosts, gaps, PAD_L, PAD_T, ROW_H, tMin, tSpan, chartW };
  cvs.onmousemove = e => {
    const d = cvs._gapData;
    const rect = cvs.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    const hi = Math.floor((my - d.PAD_T) / d.ROW_H);
    if (hi < 0 || hi >= d.hosts.length) { hT(); return; }
    const comp = d.hosts[hi];
    const ts = d.tMin + ((mx - d.PAD_L) / d.chartW) * d.tSpan;
    const hit = d.gaps.filter(g => g.comp === comp && ts >= g.start && ts <= g.end)[0];
    if (!hit) { hT(); return; }
    sT(e.clientX, e.clientY,
      `<strong style="color:var(--orange)">${eH(hit.comp)}</strong><br>` +
      `Duration: <strong>${fDelta(hit.duration)}</strong> (${hit.zscore.toFixed(1)}σ)<br>` +
      `${fDMs(new Date(hit.start))}<br>→ ${fDMs(new Date(hit.end))}<br>` +
      `Before: EID ${hit.beforeEid} ${eH(hit.beforeRule.substring(0,50))}<br>` +
      `After: EID ${hit.afterEid} ${eH(hit.afterRule.substring(0,50))}`);
  };
  cvs.onmouseleave = hT;

  // Top-10 list below chart
  topList.innerHTML = `<div style="margin-top:12px;font-family:var(--mono);font-size:11px;color:var(--text-dim)">Top gaps by duration:</div>` +
    gaps.slice(0,10).map(g =>
      `<div style="display:flex;gap:12px;align-items:center;padding:5px 0;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:11px">
        <span style="color:${g.zscore>6?'var(--critical)':g.zscore>3?'var(--orange)':'var(--warn)'};min-width:60px;font-weight:700">${fDelta(g.duration)}</span>
        <span style="color:var(--text-dim);min-width:70px">${g.zscore.toFixed(1)}σ</span>
        <span style="color:var(--white);min-width:160px">${eH(g.comp)}</span>
        <span style="color:var(--text-dim)">${fDMs(new Date(g.start))}</span>
        <span style="color:var(--text-dim)">→ ${fDMs(new Date(g.end))}</span>
      </div>`
    ).join('');
}

function rGaps() { popGapCompFilter(); runGapAnalysis(); }

// ── ARRIVALS ───────────────────────────────────────────────────────────────────

function rArrivals() {
  const rows = getFR().filter(r => !isNaN(r.ts));
  if (!rows.length) {
    document.getElementById('arrivalsTable').innerHTML = '<div style="padding:20px;color:var(--text-dim);font-family:var(--mono)">No data.</div>';
    return;
  }
  const allTs = rows.map(r => r.ts);
  const dsMin = Math.min(...allTs), dsMax = Math.max(...allTs), dsMid = (dsMin+dsMax)/2;
  const type     = document.getElementById('arrivalsType')?.value   || 'eid';
  const sort     = document.getElementById('arrivalsSort')?.value   || 'first';
  const lateOnly = document.getElementById('arrivalsLateBtn')?.classList.contains('active');
  const map = new Map();
  for (const r of rows) {
    let keys = [];
    if      (type === 'eid')      keys = [r.eid||''];
    else if (type === 'rule')     keys = [r.rule||''];
    else if (type === 'computer') keys = [r.comp||''];
    else if (type === 'account')  keys = [...extractAccounts(r)];
    for (const k of keys) {
      if (!k) continue;
      const e = map.get(k) || {first:Infinity, last:-Infinity, count:0};
      if (r.ts < e.first) e.first = r.ts;
      if (r.ts > e.last)  e.last  = r.ts;
      e.count++;
      map.set(k, e);
    }
  }
  let entries = [...map.entries()].filter(([k]) => k);
  if (lateOnly) entries = entries.filter(([,e]) => e.first > dsMid);
  if      (sort === 'first') entries.sort((a,b) => a[1].first-b[1].first);
  else if (sort === 'last')  entries.sort((a,b) => a[1].last -b[1].last);
  else                        entries.sort((a,b) => b[1].count-a[1].count);
  const lateCount = entries.filter(([,e]) => e.first > dsMid).length;
  const dsSpan = dsMax - dsMin || 1;
  document.getElementById('arrivalsCards').innerHTML = `
    <div class="card"><div class="card-label">Unique ${type==='eid'?'Event IDs':type==='rule'?'Rules':type==='computer'?'Computers':'Accounts'}</div><div class="card-value">${map.size.toLocaleString()}</div></div>
    <div class="card" style="border-left:3px solid var(--warn)"><div class="card-label">Late Arrivals</div><div class="card-value" style="color:var(--warn)">${lateCount.toLocaleString()}</div><div class="card-sub">First seen after dataset midpoint</div></div>
    <div class="card"><div class="card-label">Dataset Midpoint</div><div class="card-value" style="font-size:13px">${fDF(new Date(dsMid))}</div></div>`;
  function posBar(ts) {
    const pct = Math.round(((ts-dsMin)/dsSpan)*100);
    const isLate = ts > dsMid;
    return `<div style="width:80px;height:6px;border-radius:3px;background:var(--surface3);display:inline-block;vertical-align:middle;position:relative"><div style="position:absolute;left:0;top:0;height:100%;width:${pct}%;border-radius:3px;background:${isLate?'var(--warn)':'var(--orange)'}"></div></div>`;
  }
  const rows2 = entries.slice(0,500);
  const rows_html = rows2.map(([k,e]) => {
    const isLate = e.first > dsMid, span = e.last-e.first;
    const desc = (type === 'eid' && S.eidDescs[k]) ? `<br><span style="color:var(--text-dim);font-size:10px;font-weight:400">${eH(S.eidDescs[k])}</span>` : '';
    const kDisp = type === 'eid' ? `${eL(k)}${desc}` : eH(k);
    return `<tr${isLate?' style="color:var(--warn)"':''}>
      <td style="font-family:var(--mono);font-size:12px;max-width:300px;overflow:hidden">${kDisp}</td>
      <td style="font-family:var(--mono);font-size:11px">${fDTz(e.first)}</td>
      <td style="font-family:var(--mono);font-size:11px">${fDTz(e.last)}</td>
      <td style="font-family:var(--mono);font-size:12px">${e.count.toLocaleString()}</td>
      <td style="font-family:var(--mono);font-size:11px">${span>0?fDelta(span):'—'}</td>
      <td>${posBar(e.first)}</td>
    </tr>`;
  }).join('');
  document.getElementById('arrivalsTable').innerHTML =
    `<table class="data-table"><thead><tr><th>${type==='eid'?'Event ID':type==='rule'?'Rule':type==='computer'?'Computer':'Account'}</th><th>First Seen</th><th>Last Seen</th><th>Count</th><th>Span</th><th>Position in Dataset</th></tr></thead><tbody>${rows_html}</tbody></table>`;
}

// ── MULTI-SESSION & LATERAL ────────────────────────────────────────────────────

function renderSessionBar() {
  const bar = document.getElementById('sessionBar');
  document.getElementById('sessionChips').innerHTML = S.sessions.map(s =>
    `<span class="session-chip"><span class="session-chip-dot" style="background:${s.color}"></span><span title="${eH(s.label)}">${eH(s.label.length>30?s.label.substring(0,28)+'…':s.label)}</span><span style="color:var(--text-dim);margin-left:4px">(${s.count.toLocaleString()})</span></span>`
  ).join('');
  bar.style.display = '';
}

async function loadAdditionalSession(file) {
  const idx    = S.sessions.length;
  const label  = file.name.replace(/\.[^.]+$/, '');
  const color  = SESSION_COLORS[idx % SESSION_COLORS.length];
  const before = S.rows.length;
  S.sessionCurrent = idx;
  const c = await streamParse(file);
  if (!c) return;
  const newRows = S.rows.slice(before);
  const tMin = newRows.reduce((m,r) => !isNaN(r.ts) ? Math.min(m,r.ts) : m, Infinity);
  const tMax = newRows.reduce((m,r) => !isNaN(r.ts) ? Math.max(m,r.ts) : m, -Infinity);
  S.sessions.push({idx, label, color, format:S.format, count:newRows.length, timeMin:tMin, timeMax:tMax});
  if (tMin < S.timeMin) S.timeMin = tMin;
  if (tMax > S.timeMax) S.timeMax = tMax;
  renderSessionBar();
  popF();
  // Reset filter inputs
  const fEls = ['filterEventId','filterRuleTitle','filterComputer','filterChannel','filterSource','filterDetails','filterTimeStart','filterTimeEnd'];
  fEls.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    if (el.tagName === 'SELECT') el.selectedIndex = 0; else el.value = '';
  });
  document.querySelectorAll('#levelFilter input[type="checkbox"]').forEach(c => c.checked = true);
  S.filters = {};
  invF();
  const at = document.querySelector('.tab.active');
  if (at) switchTab(at.dataset.tab);
}

const LAT_SKIP = new Set(['','system','local service','network service','-','anonymous logon','null','dwm-1','dwm-2','dwm-3','umfd-0','umfd-1','umfd-2','umfd-3','window manager','font driver host','iis apppool']);

function extractAccounts(r) {
  const p = parseDet(r.det), out = new Set();
  for (const k of ['TargetUserName','SubjectUserName','AccountName','UserName','SamAccountName','RemoteUserName']) {
    let v = (p[k]||'').trim();
    if (!v || v === '-') continue;
    if (v.includes('\\')) v = v.split('\\').pop();
    if (v.includes('@'))  v = v.split('@')[0];
    v = v.trim();
    if (v.length >= 2 && !v.endsWith('$') && !LAT_SKIP.has(v.toLowerCase())) out.add(v);
  }
  return out;
}

function buildLateralGraph() {
  const accounts = new Map();
  for (const r of S.rows) {
    for (const acct of extractAccounts(r)) {
      if (!accounts.has(acct)) accounts.set(acct,[]);
      const p = parseDet(r.det);
      const lt    = p['LogonType'] || p['Logon Type'] || '';
      const srcIp = p['IpAddress'] || p['IPAddress'] || p['RemoteHost'] || p['WorkstationName'] || '';
      accounts.get(acct).push({ts:r.ts, comp:r.comp, eid:r.eid, sessionIdx:r.sessionIdx??0, logonType:lt, srcIp, lvl:r.lvl, rule:r.rule});
    }
  }
  for (const [,evts] of accounts) evts.sort((a,b) => a.ts-b.ts);
  const crossSession = new Set(), multiComp = new Set();
  for (const [acct,evts] of accounts) {
    const sess  = new Set(evts.map(e => e.sessionIdx));
    const comps = new Set(evts.map(e => e.comp));
    if (sess.size  > 1) crossSession.add(acct);
    if (comps.size > 1) multiComp.add(acct);
  }
  return {accounts, crossSession, multiComp};
}

function buildHops(evts) {
  const hops = [];
  for (const e of evts) {
    const last = hops[hops.length-1];
    if (last && last.comp === e.comp && last.sessionIdx === e.sessionIdx) {
      last.count++;
      last.tsLast = e.ts;
      if (e.logonType && !last.logonTypes.includes(e.logonType)) last.logonTypes.push(e.logonType);
    } else {
      hops.push({comp:e.comp, sessionIdx:e.sessionIdx, tsFirst:e.ts, tsLast:e.ts, count:1, logonTypes:e.logonType?[e.logonType]:[]});
    }
  }
  return hops;
}

function renderLatMatrix(g, tops) {
  if (!S.sessions.length) return;
  const el  = document.getElementById('latMatrix');
  const hdr = `<tr><th style="text-align:left">Account</th>${S.sessions.map(s=>`<th><span class="session-badge" style="background:${s.color}">S${s.idx+1}</span> ${eH(s.label.length>18?s.label.substring(0,16)+'…':s.label)}</th>`).join('')}</tr>`;
  const rowsHtml = tops.map(([acct,evts]) => {
    const isCross = g.crossSession.has(acct);
    const cells = S.sessions.map(s => {
      const se = evts.filter(e => e.sessionIdx === s.idx);
      if (!se.length) return `<td class="empty">—</td>`;
      const comps = [...new Set(se.map(e => e.comp))];
      return `<td class="hit" title="${eH(comps.join(', '))}">${se.length}<br><span style="font-size:9px;opacity:.7">${comps.length}sys</span></td>`;
    }).join('');
    return `<tr${isCross?' class="cross-acct"':''}><td class="acct-col">${eH(acct)}</td>${cells}</tr>`;
  }).join('');
  el.innerHTML = `<table class="lat-matrix-table"><thead>${hdr}</thead><tbody>${rowsHtml}</tbody></table>`;
}

function renderLateral() {
  const g = buildLateralGraph();
  const filterVal = (document.getElementById('latAccountFilter')||{}).value?.toLowerCase() || '';
  const legEl = document.getElementById('latSessionLegend');
  if (S.sessions.length === 0) {
    legEl.innerHTML = '<div class="anomaly-item info"><div class="anomaly-title">No sessions loaded yet.</div></div>';
    return;
  }
  legEl.innerHTML = `<div class="card-grid">${S.sessions.map(s =>
    `<div class="card" style="border-left:3px solid ${s.color}"><div class="card-label">Session ${s.idx+1}</div><div class="card-value" style="font-size:15px;color:${s.color};white-space:normal;word-break:break-all">${eH(s.label)}</div><div class="card-sub">${s.count.toLocaleString()} records · ${s.format==='evtxecmd'?'EvtxECmd':'Hayabusa'}</div><div class="card-sub" style="font-size:10px">${s.timeMin<Infinity?fDF(new Date(s.timeMin))+'&nbsp;→':''} ${s.timeMax>-Infinity?fDF(new Date(s.timeMax)):''}</div></div>`
  ).join('')}</div>`;
  const sorted = [...g.accounts.entries()].sort((a,b) => {
    const ax = g.crossSession.has(a[0]) ? 2 : g.multiComp.has(a[0]) ? 1 : 0;
    const bx = g.crossSession.has(b[0]) ? 2 : g.multiComp.has(b[0]) ? 1 : 0;
    return bx !== ax ? bx-ax : b[1].length-a[1].length;
  });
  const filtered = filterVal ? sorted.filter(([n]) => n.toLowerCase().includes(filterVal)) : sorted;
  const chains = filtered.slice(0,120).map(([acct,evts]) => {
    const hops = buildHops(evts);
    const isCross = g.crossSession.has(acct), isMulti = g.multiComp.has(acct);
    const flags = isCross ? '<span class="badge badge-warn">CROSS-SESSION</span> ' : isMulti ? '<span class="badge badge-info">MULTI-HOST</span> ' : '';
    const hopHtml = hops.map((h,i) => {
      const sess  = S.sessions[h.sessionIdx] || {color:'#6e7f90', idx:0};
      const lt    = h.logonTypes[0];
      const ltName = lt ? (' · '+(LT_NAMES[+lt]||'T'+lt)) : '';
      const prev  = hops[i-1];
      const xsess = prev && prev.sessionIdx !== h.sessionIdx;
      const arrow = i > 0 ? `<span class="lat-arrow${xsess?' xsess':''}">${xsess?' ⇒ ':' → '}</span>` : '';
      return `${arrow}<div class="lat-hop"><span class="lat-hop-comp" title="${eH(h.comp)}">${eH(h.comp.length>14?h.comp.substring(0,12)+'…':h.comp)}</span><span class="session-badge" style="background:${sess.color}">S${sess.idx+1}</span><span class="lat-hop-meta">${h.count}evt${ltName}</span></div>`;
    }).join('');
    const comps = new Set(evts.map(e => e.comp));
    return `<div class="lat-chain${isCross?' cross':''}"><div class="lat-chain-hdr"><span class="lat-chain-name">${eH(acct)}</span>${flags}<span style="font-family:var(--mono);font-size:10px;color:var(--text-dim)">${evts.length} events · ${comps.size} system${comps.size!==1?'s':''}</span></div><div class="lat-hops">${hopHtml}</div></div>`;
  }).join('');
  document.getElementById('latChains').innerHTML = chains ||
    '<div class="anomaly-item info"><div class="anomaly-title">No accounts extracted from loaded data</div><div class="anomaly-detail" style="font-family:var(--mono);font-size:11px">Accounts are extracted from Details fields: TargetUserName, SubjectUserName, UserName, AccountName. Ensure events like 4624, 4648, 4625, 5140 are present.</div></div>';
  if (g.crossSession.size > 0) {
    document.getElementById('latCrossSession').innerHTML = mFT(['Account','Sessions','Computers','Events'],
      [...g.crossSession].sort((a,b) => g.accounts.get(b).length-g.accounts.get(a).length).map(acct => {
        const evts  = g.accounts.get(acct);
        const sess  = [...new Set(evts.map(e => e.sessionIdx))].map(i => `<span class="session-badge" style="background:${(S.sessions[i]||{color:'#6e7f90'}).color}">S${i+1}</span>`).join(' ');
        const comps = new Set(evts.map(e => e.comp));
        return [eH(acct), sess, comps.size, evts.length];
      }));
  } else {
    document.getElementById('latCrossSession').innerHTML =
      `<div style="color:var(--text-dim);font-size:12px;padding:12px;font-family:var(--mono)">${S.sessions.length<2?'Use <strong>+ Add Session</strong> to load a second CSV. Accounts seen in both sessions will appear here.':'No accounts found spanning multiple sessions.'}</div>`;
  }
  renderLatMatrix(g, sorted.slice(0,30));
}

// ── TAB SWITCHER ───────────────────────────────────────────────────────────────

function switchTab(t) {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x.dataset.tab===t));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id==='panel-'+t));
  // Close any open inline expansion when switching tabs
  const existing = document.querySelector('.inline-expansion');
  if (existing) existing.remove();
  document.querySelectorAll('.row-selected').forEach(el => el.classList.remove('row-selected'));
  _lastExpandedIdx = null; _lastExpandedCtx = null;
  switch (t) {
    case 'overview':  rOV();          break;
    case 'timeline':  rTL();          break;
    case 'heatmap':   rHM();          break;
    case 'arrivals':  rArrivals();    break;
    case 'gaps':      rGaps();        break;
    case 'periodic':  rPeriodic();    break;
    case 'rules':     rRU();          break;
    case 'frequency': rFR();          break;
    case 'anomalies': rAN();          break;
    case 'raw':       rRW();          break;
    case 'eidfocus':  renderEF();     break;
    case 'lateral':   renderLateral();break;
  }
}
