// es-srum.js — EventScope v5 — SRUM Network Usage timeline + export
'use strict';

// ── TOOL CLASSIFICATION ───────────────────────────────────────────────────────

const SRUM_EXFIL = new Set([
  'winscp.exe','rclone.exe','megacmd.exe','megacmdserver.exe',
  'mega-cmd.exe','mega-cmd-server.exe',
  'robocopy.exe','xcopy.exe','xcp.exe',
  'curl.exe','wget.exe',
  '7z.exe','7za.exe','7zg.exe',
  'bitsadmin.exe','certutil.exe',
  'azcopy.exe','aws.exe','gsutil.exe',
  'ftp.exe','sftp.exe','pscp.exe','psftp.exe',
]);

const SRUM_RMM = new Set([
  'anydesk.exe','teamviewer.exe','teamviewerservice.exe',
  'mstsc.exe',
  'screenconnect.clientservice.exe',
  'atera_agent.exe','splashtop.exe','splashtopstreamer.exe',
  'logmein.exe','gotomypc.exe',
]);

// ── COLOUR PALETTE ────────────────────────────────────────────────────────────

const _SP = [
  '#4ab8dc','#5ddba8','#a78bfa','#f472b6','#34d399',
  '#60a5fa','#c084fc','#86efac','#67e8f9','#fbbf24',
  '#94a3b8','#38bdf8','#4ade80','#e879f9','#22d3ee','#fb7185',
];

function _srumColor(exe) {
  const lo = exe.toLowerCase();
  if (SRUM_EXFIL.has(lo)) return '#ff3a3a';
  if (SRUM_RMM.has(lo))   return '#DC551F';
  let h = 0;
  for (let i = 0; i < lo.length; i++) h = (Math.imul(h, 31) + lo.charCodeAt(i)) >>> 0;
  return _SP[h % _SP.length];
}

// ── UTILITIES ─────────────────────────────────────────────────────────────────

function normExe(raw) {
  if (!raw) return 'Unknown';
  // Strip \Device\HarddiskVolumeN\ prefix
  let s = raw.replace(/^\\device\\harddiskvolume\d+\\/i, '');
  // Full path — take filename only
  if (s.includes('\\') || s.includes('/')) {
    return s.replace(/\\/g, '/').split('/').pop();
  }
  // UWP package ID: "Claude_1.1.7714.0_x64__pzs8sxrjxfjjc" → "Claude"
  const uwp = s.match(/^([A-Za-z][A-Za-z0-9.]+?)_[\d.]+_/);
  if (uwp) return uwp[1];
  return s;
}

function fmtBytes(b) {
  if (!b || b <= 0) return '0 B';
  if (b < 1024)       return b.toLocaleString() + ' B';
  if (b < 1048576)    return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(2) + ' MB';
  return (b / 1073741824).toFixed(3) + ' GB';
}

function _utcLabel(ms) {
  const d = new Date(ms);
  return [
    d.getUTCFullYear(), '-',
    String(d.getUTCMonth()+1).padStart(2,'0'), '-',
    String(d.getUTCDate()).padStart(2,'0'), ' ',
    String(d.getUTCHours()).padStart(2,'0'), ':00 UTC',
  ].join('');
}

// ── MODULE STATE ──────────────────────────────────────────────────────────────

let _srumBlocks   = [];  // hit-test rects: [{x,y,w,h, bucketTs, exeShort}]
let _srumBuckets  = {};  // bucketTs(number) → { exeShort → {bytesSent,bytesRecv,rows[]} }
let _srumExeOrder = [];  // exeShort[] sorted by global total bytes desc
let _srumColors   = {};  // exeShort → css color

// ── PARSER ────────────────────────────────────────────────────────────────────

async function loadSrumFile(file) {
  const CS = 4 * 1024 * 1024;
  let off = 0, buf = '', hp = false, rc = 0, ci = {};
  const rows = [];
  const prog = document.getElementById('srumProgressText');
  document.getElementById('srumProgress').style.display = 'block';
  if (prog) prog.textContent = 'Loading…';

  while (off < file.size) {
    buf += (await file.slice(off, off + CS).text()).replace(/^\uFEFF/, '');
    off += CS;

    while (true) {
      const nl = buf.indexOf('\n');
      if (nl === -1) break;
      const rec = buf.substring(0, nl).replace(/\r$/, '').replace(/^\uFEFF/, '');
      buf = buf.substring(nl + 1);
      if (!rec.trim()) continue;

      if (!hp) {
        parseCSVLine(rec).forEach((h, i) => { ci[h.trim()] = i; });
        hp = true;
        const hasSent = 'BytesSent' in ci;
        const hasRecv = 'BytesRecvd' in ci || 'BytesReceived' in ci;
        const hasApp  = 'App' in ci || 'ExeInfo' in ci;
        if (!hasSent || !hasRecv || !hasApp) {
          if (prog) prog.textContent = 'Not a SRUM NetworkUsages CSV — expected BytesSent, BytesRecvd/BytesReceived, App/ExeInfo columns.';
          return;
        }
        continue;
      }

      const f = parseCSVLine(rec);
      const g = (...names) => {
        for (const n of names) if (n in ci) return (f[ci[n]] || '').trim();
        return '';
      };

      const ts = parseTS(g('TimeStamp', 'Timestamp'));
      if (isNaN(ts)) continue;

      const recv = parseInt(g('BytesRecvd', 'BytesReceived'), 10) || 0;
      const sent = parseInt(g('BytesSent'),                  10) || 0;
      if (recv === 0 && sent === 0) continue;

      // InterfaceLuid arrives in scientific notation from SrumECmd (e.g. 1.6894E+15)
      const luidRaw = g('InterfaceLuid');
      const ifType  = luidRaw ? String(Math.round(parseFloat(luidRaw))) : g('InterfaceType');

      const bucketTs = Math.floor(ts / 3600000) * 3600000;
      const exeRaw   = g('App', 'ExeInfo');
      rows.push({
        ts, bucketTs,
        exeRaw,
        exeShort:  normExe(exeRaw),
        exeDesc:   g('ExeInfoDescription'),
        userName:  g('User', 'UserName'),
        sid:       g('UserId', 'Sid'),
        sidType:   g('SidType'),
        bytesRecv: recv,
        bytesSent: sent,
        ifType,
        profile:   g('L2ProfileId', 'ProfileName'),
      });
      rc++;
    }

    if (prog) prog.textContent = `Parsed ${rc.toLocaleString()} records…`;
    await new Promise(r => setTimeout(r, 0));
  }

  document.getElementById('srumProgress').style.display = 'none';

  if (!rows.length) {
    if (prog) prog.textContent = 'No transfer rows found (all BytesSent + BytesReceived = 0).';
    return;
  }

  S.srum = {
    networkUsages: rows,
    timeMin: rows.reduce((m, r) => Math.min(m, r.bucketTs), Infinity),
    timeMax: rows.reduce((m, r) => Math.max(m, r.bucketTs), -Infinity),
    loaded:   true,
    fileName: file.name,
  };

  document.getElementById('srumDropzone').style.display = 'none';
  document.getElementById('srumContent').style.display  = '';
  const fn = document.getElementById('srumFileName');
  if (fn) fn.textContent = file.name + ' — ' + rc.toLocaleString() + ' transfer records';
  rSRUM();
}

// ── BUCKET BUILDER ────────────────────────────────────────────────────────────

function _buildSrumBuckets() {
  const filter = (document.getElementById('srumExeSearch')?.value || '').toLowerCase().trim();
  const buckets   = {};
  const exeTotals = {};

  for (const r of S.srum.networkUsages) {
    if (filter && !r.exeShort.toLowerCase().includes(filter) &&
                  !r.exeRaw.toLowerCase().includes(filter)) continue;

    if (!buckets[r.bucketTs]) buckets[r.bucketTs] = {};
    if (!buckets[r.bucketTs][r.exeShort]) {
      buckets[r.bucketTs][r.exeShort] = { bytesSent: 0, bytesRecv: 0, rows: [] };
    }
    buckets[r.bucketTs][r.exeShort].bytesSent += r.bytesSent;
    buckets[r.bucketTs][r.exeShort].bytesRecv += r.bytesRecv;
    buckets[r.bucketTs][r.exeShort].rows.push(r);

    const tot = r.bytesSent + r.bytesRecv;
    exeTotals[r.exeShort] = (exeTotals[r.exeShort] || 0) + tot;
  }

  _srumBuckets  = buckets;
  _srumExeOrder = Object.entries(exeTotals).sort((a, b) => b[1] - a[1]).map(e => e[0]);
  _srumColors   = {};
  _srumExeOrder.forEach(e => { _srumColors[e] = _srumColor(e); });
}

// ── MAIN RENDER ───────────────────────────────────────────────────────────────

function rSRUM() {
  if (!S.srum?.loaded) return;
  _buildSrumBuckets();
  _drawSrumCanvas();
  _buildSrumLegend();
  _buildSrumTotalsBar();
}

// ── CANVAS ────────────────────────────────────────────────────────────────────

function _drawSrumCanvas() {
  const canvas = document.getElementById('canvasSrum');
  if (!canvas) return;

  const { ctx, w, h } = sC(canvas);
  const pL = 72, pR = 20, pT = 20, pB = 55;
  const cW = w - pL - pR, cH = h - pT - pB;

  ctx.clearRect(0, 0, w, h);
  _srumBlocks = [];

  const bucketKeys = Object.keys(_srumBuckets).map(Number).sort((a, b) => a - b);
  if (!bucketKeys.length) {
    ctx.fillStyle = themeC('#6e7f90','#4a5a6a');
    ctx.font = '13px JetBrains Mono,monospace';
    ctx.textAlign = 'center';
    ctx.fillText('No data matches current filter', w / 2, h / 2);
    return;
  }

  // Max total bytes per bucket → Y scale
  let maxBucket = 1;
  for (const bk of bucketKeys) {
    let bt = 0;
    for (const app of Object.keys(_srumBuckets[bk])) {
      bt += _srumBuckets[bk][app].bytesSent + _srumBuckets[bk][app].bytesRecv;
    }
    if (bt > maxBucket) maxBucket = bt;
  }

  const logMax = Math.log1p(maxBucket);
  const tMin   = bucketKeys[0];
  const tRange = (bucketKeys[bucketKeys.length - 1] - tMin) || 3600000;
  // Bar width: distribute evenly across chart width, min 2px
  const bW = Math.max(2, Math.floor(cW / bucketKeys.length) - 1);

  // Y grid lines and labels
  ctx.font      = '10px JetBrains Mono,monospace';
  ctx.textAlign = 'right';
  for (const yl of [
    { v: 1024,         l: '1 KB'    },
    { v: 1048576,      l: '1 MB'    },
    { v: 10485760,     l: '10 MB'   },
    { v: 104857600,    l: '100 MB'  },
    { v: 1073741824,   l: '1 GB'    },
    { v: 10737418240,  l: '10 GB'   },
    { v: 107374182400, l: '100 GB'  },
  ].filter(yl => yl.v <= maxBucket * 1.5)) {
    const y = pT + cH - (Math.log1p(yl.v) / logMax) * cH;
    ctx.strokeStyle = themeC('rgba(26,58,85,0.55)','rgba(180,195,215,0.7)');
    ctx.lineWidth   = 1;
    ctx.setLineDash([3, 3]);
    ctx.beginPath(); ctx.moveTo(pL, y); ctx.lineTo(w - pR, y); ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = themeC('#6e7f90','#4a5a6a');
    ctx.fillText(yl.l, pL - 6, y + 3);
  }

  // Chart border
  ctx.strokeStyle = themeC('#1a3a55','rgba(180,195,215,0.8)');
  ctx.lineWidth   = 1;
  ctx.strokeRect(pL, pT, cW, cH);

  // Stacked bars
  for (const bk of bucketKeys) {
    const bucket = _srumBuckets[bk];
    const x = pL + ((bk - tMin) / tRange) * cW;

    // Total bytes this bucket
    let bucketTotal = 0;
    for (const app of Object.keys(bucket)) {
      bucketTotal += bucket[app].bytesSent + bucket[app].bytesRecv;
    }
    if (bucketTotal === 0) continue;

    // Total bar height = log of bucket total (log scale Y axis)
    const totalBarH = (Math.log1p(bucketTotal) / logMax) * cH;

    // Sort apps by bytes desc; biggest block at bottom
    const apps = Object.keys(bucket).sort((a, b) => {
      return (bucket[b].bytesSent + bucket[b].bytesRecv)
           - (bucket[a].bytesSent + bucket[a].bytesRecv);
    });

    let stackBottom = pT + cH;

    for (const exe of apps) {
      const appTotal = bucket[exe].bytesSent + bucket[exe].bytesRecv;
      // Proportional height within the total log-scaled bar
      const segH = (appTotal / bucketTotal) * totalBarH;
      if (segH < 0.5) continue;

      const segY = stackBottom - segH;
      ctx.fillStyle = _srumColors[exe] || '#4ab8dc';
      ctx.fillRect(x, segY, bW, segH);

      _srumBlocks.push({ x, y: segY, w: bW, h: segH, bucketTs: bk, exeShort: exe });

      stackBottom = segY;
      if (stackBottom <= pT) break;
    }
  }

  // X axis date labels
  ctx.fillStyle  = themeC('#6e7f90','#4a5a6a');
  ctx.font       = '10px JetBrains Mono,monospace';
  ctx.textAlign  = 'center';
  const rangeDays      = Math.ceil(tRange / 86400000);
  const labelEveryDays = rangeDays <= 7 ? 1 : rangeDays <= 31 ? 2 : rangeDays <= 90 ? 7 : 30;
  let prevDay = -1;
  for (const bk of bucketKeys) {
    const dayOff = Math.floor((bk - tMin) / 86400000);
    const dayNum = Math.floor(bk / 86400000);
    if (dayOff % labelEveryDays === 0 && dayNum !== prevDay) {
      prevDay = dayNum;
      const d = new Date(bk);
      const x = pL + ((bk - tMin) / tRange) * cW;
      ctx.fillText(`${d.getUTCMonth()+1}/${d.getUTCDate()}`, x, pT + cH + 16);
    }
  }

  // Replace click handler
  canvas.onclick = e => {
    const rect  = canvas.getBoundingClientRect();
    const scaleX = canvas.width  / rect.width;
    const scaleY = canvas.height / rect.height;
    const mx = (e.clientX - rect.left) * scaleX;
    const my = (e.clientY - rect.top)  * scaleY;
    // Iterate reversed so topmost-drawn segment (smallest) wins
    const hit = [..._srumBlocks].reverse().find(
      b => mx >= b.x && mx <= b.x + b.w && my >= b.y && my <= b.y + b.h
    );
    showSrumDetail(hit ? hit.bucketTs : null);
  };
}

// ── LEGEND ────────────────────────────────────────────────────────────────────

function _buildSrumLegend() {
  const el = document.getElementById('srumLegend');
  if (!el) return;

  el.innerHTML = _srumExeOrder.slice(0, 24).map(exe => {
    const col  = _srumColors[exe];
    const lo   = exe.toLowerCase();
    const flag = SRUM_EXFIL.has(lo)
      ? ' <span style="color:#ff3a3a;font-size:9px;font-weight:700">EXFIL</span>'
      : SRUM_RMM.has(lo)
      ? ' <span style="color:#DC551F;font-size:9px;font-weight:700">RMM</span>'
      : '';
    return `<span class="srum-leg">
      <span style="display:inline-block;width:9px;height:9px;background:${col};border-radius:2px;margin-right:5px;flex-shrink:0"></span>${eH(exe)}${flag}
    </span>`;
  }).join('');
}

// ── TOTALS SUMMARY BAR ────────────────────────────────────────────────────────

function _buildSrumTotalsBar() {
  const el = document.getElementById('srumTotals');
  if (!el) return;

  // Compute per-exe grand totals
  const exeTotals = {};
  for (const r of S.srum.networkUsages) {
    if (!exeTotals[r.exeShort]) exeTotals[r.exeShort] = { sent: 0, recv: 0 };
    exeTotals[r.exeShort].sent += r.bytesSent;
    exeTotals[r.exeShort].recv += r.bytesRecv;
  }

  const sorted = Object.entries(exeTotals)
    .map(([exe, t]) => ({ exe, total: t.sent + t.recv, sent: t.sent, recv: t.recv }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 20);

  const maxTotal = sorted[0]?.total || 1;

  el.innerHTML = sorted.map(({ exe, total, sent, recv }) => {
    const pct    = Math.round((total / maxTotal) * 100);
    const col    = _srumColors[exe] || '#4ab8dc';
    const lo     = exe.toLowerCase();
    const flag   = SRUM_EXFIL.has(lo)
      ? `<span class="badge badge-critical" style="font-size:9px;padding:1px 5px;margin-left:6px">EXFIL</span>`
      : SRUM_RMM.has(lo)
      ? `<span class="badge badge-danger" style="font-size:9px;padding:1px 5px;margin-left:6px">RMM</span>`
      : '';
    return `<div class="srum-total-row" onclick="_filterSrumTo('${eH(exe).replace(/'/g,"\\'")}')">
      <div class="srum-total-exe">
        <span style="display:inline-block;width:8px;height:8px;background:${col};border-radius:2px;margin-right:6px;flex-shrink:0"></span>
        <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis">${eH(exe)}</span>${flag}
      </div>
      <div class="srum-total-bar-wrap">
        <div class="srum-total-bar" style="width:${pct}%;background:${col};opacity:0.7"></div>
      </div>
      <div class="srum-total-nums">
        <span style="color:var(--warn)">&uarr;${fmtBytes(sent)}</span>
        <span style="color:var(--info)">&darr;${fmtBytes(recv)}</span>
        <span style="color:var(--text-dim)">${fmtBytes(total)}</span>
      </div>
    </div>`;
  }).join('');
}

function _filterSrumTo(exe) {
  const inp = document.getElementById('srumExeSearch');
  if (!inp) return;
  inp.value = exe;
  rSRUM();
}

// ── DETAIL PANE ───────────────────────────────────────────────────────────────

function showSrumDetail(bucketTs) {
  const el = document.getElementById('srumDetail');
  if (!el) return;
  if (bucketTs === null) { el.innerHTML = ''; return; }

  const bucket = _srumBuckets[bucketTs];
  if (!bucket) { el.innerHTML = ''; return; }

  const bucketStart = _utcLabel(bucketTs);
  const bucketEnd   = _utcLabel(bucketTs + 3600000);

  const rows = Object.entries(bucket)
    .map(([exe, data]) => ({ exe, data }))
    .sort((a, b) => (b.data.bytesSent + b.data.bytesRecv) - (a.data.bytesSent + a.data.bytesRecv));

  const totalSent = rows.reduce((s, r) => s + r.data.bytesSent, 0);
  const totalRecv = rows.reduce((s, r) => s + r.data.bytesRecv, 0);

  const accountsFor = data => {
    const seen = new Set();
    data.rows.forEach(r => {
      const k = r.userName || r.sid || r.sidType || 'Unknown';
      seen.add(k);
    });
    return [...seen].join(', ');
  };

  const ifFor = data => {
    const seen = new Set();
    data.rows.forEach(r => { if (r.ifType) seen.add(r.ifType.replace('IF_TYPE_', '')); });
    return [...seen].join(', ') || '—';
  };

  const profileFor = data => {
    const seen = new Set();
    data.rows.forEach(r => { if (r.profile) seen.add(r.profile); });
    return [...seen].join(', ') || '—';
  };

  const tableRows = rows.map(({ exe, data }) => {
    const col  = _srumColors[exe] || '#4ab8dc';
    const lo   = exe.toLowerCase();
    const flag = SRUM_EXFIL.has(lo)
      ? `<span class="badge badge-critical" style="font-size:9px;padding:1px 5px;margin-left:6px">EXFIL</span>`
      : SRUM_RMM.has(lo)
      ? `<span class="badge badge-danger" style="font-size:9px;padding:1px 5px;margin-left:6px">RMM</span>`
      : '';
    return `<tr>
      <td>
        <span style="display:inline-block;width:8px;height:8px;background:${col};border-radius:2px;margin-right:6px;vertical-align:middle"></span>
        ${eH(exe)}${flag}
      </td>
      <td style="color:var(--text-dim)">${eH(accountsFor(data))}</td>
      <td style="text-align:right;color:var(--warn);font-family:var(--mono)">${fmtBytes(data.bytesSent)}</td>
      <td style="text-align:right;color:var(--info);font-family:var(--mono)">${fmtBytes(data.bytesRecv)}</td>
      <td style="text-align:right;font-family:var(--mono)">${fmtBytes(data.bytesSent + data.bytesRecv)}</td>
      <td style="color:var(--text-dim)">${eH(ifFor(data))}</td>
      <td style="color:var(--text-dim)">${eH(profileFor(data))}</td>
    </tr>`;
  }).join('');

  el.innerHTML = `
    <div class="chart-box" style="margin-top:12px">
      <div class="chart-header">
        <span class="chart-title" style="font-size:13px;font-family:var(--mono)">${bucketStart} → +1h</span>
        <div class="chart-controls">
          <button class="chart-btn" onclick="downloadSrumCsv(${bucketTs})">Export Bucket</button>
          <button class="chart-btn" onclick="downloadSrumCsv()">Export All</button>
          <button class="chart-btn" onclick="showSrumDetail(null)" style="padding:4px 8px">✕</button>
        </div>
      </div>
      <div class="data-table-wrap">
        <table class="data-table">
          <thead><tr>
            <th>Application</th>
            <th>Account</th>
            <th style="text-align:right">Sent &uarr;</th>
            <th style="text-align:right">Received &darr;</th>
            <th style="text-align:right">Total</th>
            <th>Interface</th>
            <th>Network</th>
          </tr></thead>
          <tbody>${tableRows}</tbody>
          <tfoot><tr style="border-top:2px solid var(--border-bright)">
            <td colspan="2" style="font-family:var(--mono);font-size:11px;font-weight:600;color:var(--text-dim)">HOUR TOTAL</td>
            <td style="text-align:right;font-weight:700;color:var(--warn);font-family:var(--mono)">${fmtBytes(totalSent)}</td>
            <td style="text-align:right;font-weight:700;color:var(--info);font-family:var(--mono)">${fmtBytes(totalRecv)}</td>
            <td style="text-align:right;font-weight:700;font-family:var(--mono)">${fmtBytes(totalSent + totalRecv)}</td>
            <td colspan="2"></td>
          </tr></tfoot>
        </table>
      </div>
    </div>`;
}

// ── EXPORT ────────────────────────────────────────────────────────────────────

function downloadSrumCsv(filterBucketTs) {
  if (!S.srum?.loaded) return;

  const rows = S.srum.networkUsages.filter(r =>
    filterBucketTs === undefined || r.bucketTs === filterBucketTs
  ).sort((a, b) => a.bucketTs - b.bucketTs || (b.bytesSent + b.bytesRecv) - (a.bytesSent + a.bytesRecv));

  if (!rows.length) { showToast('No data to export'); return; }

  const flagFor = exe => {
    const lo = exe.toLowerCase();
    if (SRUM_EXFIL.has(lo)) return 'EXFIL_TOOL';
    if (SRUM_RMM.has(lo))   return 'RMM';
    return '';
  };

  const esc = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';

  const header = [
    'ExeName', 'FullExePath', 'ExeDescription',
    'BucketStart_UTC', 'BucketEnd_UTC',
    'Account', 'SID', 'SIDType',
    'BytesSent', 'BytesReceived', 'TotalBytes',
    'InterfaceType', 'ProfileName', 'Flag',
  ];

  const isoUTC = ms => new Date(ms).toISOString().replace('T', ' ').replace('.000Z', ' UTC');

  const lines = [header.map(esc).join(',')];
  for (const r of rows) {
    lines.push([
      r.exeShort,
      r.exeRaw,
      r.exeDesc,
      isoUTC(r.bucketTs),
      isoUTC(r.bucketTs + 3600000),
      r.userName,
      r.sid,
      r.sidType,
      r.bytesSent,
      r.bytesRecv,
      r.bytesSent + r.bytesRecv,
      r.ifType,
      r.profile,
      flagFor(r.exeShort),
    ].map(esc).join(','));
  }

  const blob = new Blob([lines.join('\r\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = filterBucketTs
    ? `srum-${new Date(filterBucketTs).toISOString().slice(0,13).replace('T','-')}h.csv`
    : 'srum-network-all.csv';
  a.click();
  URL.revokeObjectURL(a.href);
  showToast(`Exported ${rows.length} row${rows.length !== 1 ? 's' : ''}`);
}
