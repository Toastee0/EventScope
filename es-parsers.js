// es-parsers.js — EventScope v5 — CSV ingestion, header-name field mapping
'use strict';

// ── STREAM PARSER ──────────────────────────────────────────────────────────────

async function streamParse(file) {
  const CS = 4 * 1024 * 1024;
  let off = 0, buf = '', hp = false, rc = 0, procFn = procRow;
  const pf = document.getElementById('progressFill');
  const pt = document.getElementById('progressText');
  document.getElementById('progressContainer').style.display = 'block';

  while (off < file.size) {
    buf += await file.slice(off, off + CS).text();
    off += CS;
    let sf = 0;
    while (true) {
      const nl = buf.indexOf('\n', sf);
      if (nl === -1) break;
      const cand = buf.substring(0, nl);
      let qc = 0;
      for (let i = 0; i < cand.length; i++) if (cand[i] === '"') qc++;
      if (qc % 2 !== 0) { sf = nl + 1; continue; }
      const rec = cand.replace(/\r$/, '');
      buf = buf.substring(nl + 1);
      sf = 0;
      if (!rec.trim()) continue;
      if (!hp) {
        S.colIndex = {};
        S.columns = parseCSVLine(rec);
        S.columns.forEach((c, i) => S.colIndex[c.trim().replace(/^"/, '').replace(/"$/, '')] = i);
        hp = true;
        if ('TimeCreated' in S.colIndex && 'EventId' in S.colIndex) {
          S.format = 'evtxecmd';
          procFn = procRowEvtxECmd;
        } else {
          S.format = 'hayabusa';
          procFn = procRow;
        }
        continue;
      }
      procFn(parseCSVLine(rec));
      rc++;
    }
    const fmt = S.format === 'evtxecmd' ? 'EvtxECmd' : 'Hayabusa';
    pf.style.width = Math.min(100, off / file.size * 100) + '%';
    pt.textContent = `Parsed ${rc.toLocaleString()} records [${fmt}] (${Math.round(Math.min(100, off / file.size * 100))}%)`;
    await new Promise(r => setTimeout(r, 0));
  }

  if (buf.trim() && hp) { procFn(parseCSVLine(buf.trim())); rc++; }
  pf.style.width = '100%';
  pt.textContent = `Complete: ${rc.toLocaleString()} records [${S.format === 'evtxecmd' ? 'EvtxECmd' : 'Hayabusa'}]`;
  return rc;
}

// ── HAYABUSA ROW PROCESSOR ─────────────────────────────────────────────────────

function procRow(f) {
  const ci = S.colIndex;
  const ts   = parseTS(f[ci['Timestamp']]);
  const rule = (f[ci['RuleTitle']]  || '').trim();
  const lvl  = normLvl(f[ci['Level']]);
  const comp = (f[ci['Computer']]   || '').trim();
  const chan  = (f[ci['Channel']]   || '').trim();
  const eid  = (f[ci['EventID']]    || '').trim();
  const rec  = (f[ci['RecordID']]   || '').trim();
  const det  = (f[ci['Details']]    || '').trim();
  const ext  = (f[ci['ExtraFieldInfo']] || '').trim();
  const rid  = (f[ci['RuleID']]     || '').trim();

  S.rows.push({ts,rule,lvl,comp,chan,eid,rec,det,extra:ext,rid,src:'',sessionIdx:S.sessionCurrent||0});
  S.eventIdCounts[eid] = (S.eventIdCounts[eid] || 0) + 1;
  if (comp) S.computerCounts[comp] = (S.computerCounts[comp] || 0) + 1;
  if (chan)  S.channelCounts[chan]  = (S.channelCounts[chan]  || 0) + 1;
  S.levelCounts[lvl] = (S.levelCounts[lvl] || 0) + 1;
  if (rule) {
    S.ruleTitleCounts[rule] = (S.ruleTitleCounts[rule] || 0) + 1;
    if (!S.ruleIdMap[rule]) S.ruleIdMap[rule] = {ruleId:rid, level:lvl, count:0, channel:chan, eventIds:new Set()};
    S.ruleIdMap[rule].count++;
    if (eid) S.ruleIdMap[rule].eventIds.add(eid);
  }
  if (!isNaN(ts)) { if (ts < S.timeMin) S.timeMin = ts; if (ts > S.timeMax) S.timeMax = ts; }
}

// ── EVTXECMD ROW PROCESSOR (Bug 2 fix: robust header-name mapping) ─────────────

function procRowEvtxECmd(f) {
  const ci = S.colIndex;

  // Helper: case-insensitive lookup with fallback alternatives
  function col(...names) {
    for (const name of names) {
      // Exact match first
      if (name in ci && ci[name] !== undefined) {
        const v = f[ci[name]];
        return v !== undefined ? v : '';
      }
      // Case-insensitive scan
      const lower = name.toLowerCase();
      for (const key of Object.keys(ci)) {
        if (key.toLowerCase() === lower) {
          const v = f[ci[key]];
          return v !== undefined ? v : '';
        }
      }
    }
    return '';
  }

  const ts       = parseTS(col('TimeCreated'));
  const rule     = col('MapDescription').trim();
  const lvl      = normLvl(col('Level'));
  const comp     = col('Computer').trim();
  const chan      = col('Channel').trim();
  const eid      = col('EventId', 'EventID').trim();
  const rec      = col('EventRecordId', 'RecordNumber', 'RecordID').trim();
  const provider = col('Provider').trim();
  const src      = col('SourceFile').trim();

  const parts = [];
  for (let i = 1; i <= 6; i++) {
    const v = col('PayloadData' + i).trim();
    if (v && v !== '-') parts.push(v);
  }

  const un   = col('UserName').trim();
  const rh   = col('RemoteHost').trim();
  const uid2 = col('UserId').trim();
  const ei   = col('ExecutableInfo').trim();
  if (un   && un   !== '-') parts.push('UserName: '        + un);
  if (rh   && rh   !== '-') parts.push('RemoteHost: '      + rh);
  if (uid2 && uid2 !== '-') parts.push('UserId: '          + uid2);
  if (ei   && ei   !== '-') parts.push('ExecutableInfo: '  + ei);

  const det = parts.join('\u00a6');
  const ext = col('Payload').trim();
  const rid = provider;

  // Log unmapped columns (once, for debugging) — only in first 5 rows
  if (S.rows.length < 5) {
    const knownCols = new Set(['TimeCreated','MapDescription','Level','Computer','Channel',
      'EventId','EventID','EventRecordId','RecordNumber','RecordID','Provider','SourceFile',
      'PayloadData1','PayloadData2','PayloadData3','PayloadData4','PayloadData5','PayloadData6',
      'UserName','RemoteHost','UserId','ExecutableInfo','Payload']);
    const unmapped = Object.keys(ci).filter(k => !knownCols.has(k) && !k.toLowerCase().startsWith('payloaddata'));
    if (unmapped.length) console.debug('[EvtxECmd] unmapped columns:', unmapped);
  }

  S.rows.push({ts,rule,lvl,comp,chan,eid,rec,det,extra:ext,rid,src,sessionIdx:S.sessionCurrent||0});
  S.eventIdCounts[eid] = (S.eventIdCounts[eid] || 0) + 1;
  if (comp) S.computerCounts[comp] = (S.computerCounts[comp] || 0) + 1;
  if (chan)  S.channelCounts[chan]  = (S.channelCounts[chan]  || 0) + 1;
  S.levelCounts[lvl] = (S.levelCounts[lvl] || 0) + 1;
  if (src) S.sourceCounts[src] = (S.sourceCounts[src] || 0) + 1;
  if (rule) {
    S.ruleTitleCounts[rule] = (S.ruleTitleCounts[rule] || 0) + 1;
    if (!S.ruleIdMap[rule]) S.ruleIdMap[rule] = {ruleId:rid, level:lvl, count:0, channel:chan, eventIds:new Set()};
    S.ruleIdMap[rule].count++;
    if (eid) S.ruleIdMap[rule].eventIds.add(eid);
  }
  if (!isNaN(ts)) { if (ts < S.timeMin) S.timeMin = ts; if (ts > S.timeMax) S.timeMax = ts; }
}

// ── POPULATE FILTER DROPDOWNS ──────────────────────────────────────────────────

function popF() {
  const cs = document.getElementById('filterComputer');
  cs.innerHTML = '<option value="">All Computers</option>';
  Object.keys(S.computerCounts).sort().forEach(c => {
    cs.innerHTML += `<option value="${eH(c)}">${c} (${S.computerCounts[c]})</option>`;
  });

  const ch = document.getElementById('filterChannel');
  ch.innerHTML = '<option value="">All Channels</option>';
  Object.entries(S.channelCounts).sort((a,b) => b[1]-a[1]).forEach(([c,n]) => {
    ch.innerHTML += `<option value="${eH(c)}">${c.length > 40 ? c.substring(0,38)+'…' : c} (${n})</option>`;
  });

  const sw = document.getElementById('filterSourceWrap');
  const sf = document.getElementById('filterSource');
  if (S.format === 'evtxecmd') {
    sf.innerHTML = '<option value="">All Sources</option>';
    Object.entries(S.sourceCounts).sort((a,b) => b[1]-a[1]).forEach(([s,n]) => {
      const fn = s.split(/[/\\]/).pop();
      sf.innerHTML += `<option value="${eH(s)}">${eH(fn)} (${n})</option>`;
    });
    sw.style.display = '';
  } else {
    sw.style.display = 'none';
  }
}
