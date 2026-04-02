// es-charts.js — EventScope v5 — All canvas drawing
'use strict';

// ── CANVAS SETUP ───────────────────────────────────────────────────────────────

function sC(el) {
  const r = el.getBoundingClientRect(), d = window.devicePixelRatio || 1;
  el.width  = r.width  * d;
  el.height = r.height * d;
  const ctx = el.getContext('2d');
  ctx.scale(d, d);
  return {ctx, w:r.width, h:r.height};
}

// ── BAR CHART ──────────────────────────────────────────────────────────────────

function drawBC(el, labels, values, opt = {}) {
  const {ctx,w,h} = sC(el);
  const pL=60,pR=20,pT=20,pB=50,cW=w-pL-pR,cH=h-pT-pB;
  const logScale = opt.logScale || false;
  const xfm = v => logScale ? Math.log1p(v) : v;
  const mxRaw = Math.max(...values, 1);
  const mx = xfm(mxRaw);
  const bW = Math.max(1, (cW/values.length) - 1);
  ctx.clearRect(0,0,w,h);
  ctx.strokeStyle = '#1a3a55';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pT + (cH/4)*i;
    ctx.beginPath(); ctx.moveTo(pL,y); ctx.lineTo(w-pR,y); ctx.stroke();
    ctx.fillStyle = '#6e7f90';
    ctx.font = '11px JetBrains Mono,monospace';
    ctx.textAlign = 'right';
    const rawVal = logScale ? Math.round(Math.expm1(mx*(1-i/4))) : Math.round(mx*(1-i/4));
    ctx.fillText(rawVal.toLocaleString(), pL-8, y+4);
  }
  // dashed baseline indicator
  if (opt.baseline > 0) {
    const by = pT + cH - (xfm(opt.baseline)/mx)*cH;
    ctx.save();
    ctx.strokeStyle = 'rgba(110,127,144,0.45)';
    ctx.lineWidth = 1;
    ctx.setLineDash([4,3]);
    ctx.beginPath(); ctx.moveTo(pL,by); ctx.lineTo(w-pR,by); ctx.stroke();
    ctx.restore();
  }
  const bc = opt.baseColor || 'rgba(220,85,31,0.55)';
  const st = cStats(values), th = st.mean + 2.5*st.std;
  for (let i = 0; i < values.length; i++) {
    const x = pL + (i/values.length)*cW;
    const bH = (xfm(values[i])/mx)*cH;
    ctx.fillStyle = (values[i] > th && values[i] > 5) ? 'rgba(255,58,58,0.85)' : bc;
    ctx.fillRect(x, pT+cH-bH, bW, bH);
  }
  if (labels.length) {
    const step = Math.max(1, Math.floor(labels.length/8));
    ctx.fillStyle = '#6e7f90';
    ctx.font = '10px JetBrains Mono,monospace';
    ctx.textAlign = 'center';
    for (let i = 0; i < labels.length; i += step)
      ctx.fillText(labels[i] instanceof Date ? fDS(labels[i]) : String(labels[i]), pL+((i+.5)/values.length)*cW, h-pB+16);
  }
  el._chartData = {labels, values, padL:pL, padR:pR, padT:pT, padB:pB, chartW:cW, chartH:cH, barW:bW, type:'bar'};
}

// ── STACKED BAR CHART ──────────────────────────────────────────────────────────

function drawSBC(el, labels, sm) {
  const {ctx,w,h} = sC(el);
  const pL=60,pR=20,pT=10,pB=40,cW=w-pL-pR,cH=h-pT-pB;
  const lvls = ['informational','low','medium','high','critical'];
  const cols = {critical:'#ff3a3a',high:'#DC551F',medium:'#f0a830',low:'rgba(74,184,220,0.7)',informational:'rgba(93,219,168,0.5)'};
  const bc = labels.length;
  const tots = new Array(bc).fill(0);
  for (const l of lvls) for (let i = 0; i < bc; i++) tots[i] += (sm[l]?.[i] || 0);
  const mx = Math.max(...tots, 1);
  ctx.clearRect(0,0,w,h);
  ctx.strokeStyle = '#1a3a55';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pT + (cH/4)*i;
    ctx.beginPath(); ctx.moveTo(pL,y); ctx.lineTo(w-pR,y); ctx.stroke();
    ctx.fillStyle = '#6e7f90';
    ctx.font = '10px JetBrains Mono,monospace';
    ctx.textAlign = 'right';
    ctx.fillText(Math.round(mx*(1-i/4)).toLocaleString(), pL-8, y+4);
  }
  const bW = Math.max(1, (cW/bc) - 1);
  for (let i = 0; i < bc; i++) {
    let yo = 0;
    for (const l of lvls) {
      const v = sm[l]?.[i] || 0;
      if (!v) continue;
      const bH = (v/mx)*cH;
      ctx.fillStyle = cols[l];
      ctx.fillRect(pL+(i/bc)*cW, pT+cH-yo-bH, bW, bH);
      yo += bH;
    }
  }
  if (labels.length) {
    const step = Math.max(1, Math.floor(bc/8));
    ctx.fillStyle = '#6e7f90';
    ctx.font = '10px JetBrains Mono,monospace';
    ctx.textAlign = 'center';
    for (let i = 0; i < bc; i += step)
      ctx.fillText(fDS(labels[i]), pL+((i+.5)/bc)*cW, h-pB+14);
  }
}

// ── HORIZONTAL BAR CHART ───────────────────────────────────────────────────────

function drawHBC(el, labels, values, bc) {
  const {ctx,w,h} = sC(el);
  const pL=160,pR=60,pT=10,pB=10,cW=w-pL-pR,cH=h-pT-pB;
  const mx = Math.max(...values, 1);
  const bH = Math.max(2, (cH/labels.length) - 4);
  ctx.clearRect(0,0,w,h);
  const dc = ['#DC551F','#5ddba8','#f0a830','#4ab8dc','#a78bfa','#f472b6','#e8703f','#ff3a3a'];
  for (let i = 0; i < labels.length; i++) {
    const y = pT + (i/labels.length)*cH;
    const bw = (values[i]/mx)*cW;
    ctx.fillStyle = bc ? bc[i] : dc[i%dc.length];
    ctx.globalAlpha = 0.8;
    ctx.fillRect(pL, y, bw, bH);
    ctx.globalAlpha = 1;
    ctx.fillStyle = '#C8C2BD';
    ctx.font = '11px JetBrains Mono,monospace';
    ctx.textAlign = 'right';
    ctx.fillText(labels[i].length > 22 ? labels[i].substring(0,20)+'…' : labels[i], pL-8, y+bH/2+4);
    ctx.fillStyle = '#6e7f90';
    ctx.textAlign = 'left';
    ctx.fillText(values[i].toLocaleString(), pL+bw+6, y+bH/2+4);
  }
}

// ── HEATMAP COLORING ───────────────────────────────────────────────────────────

const HM_SEV_W = {critical:5, high:4, medium:3, low:2, informational:1};

const HM_GRAD = [
  [0,    [5,14,23,0]],
  [0.01, [9,55,95,0.2]],
  [0.08, [9,55,95,0.6]],
  [0.2,  [180,80,20,0.7]],
  [0.5,  [220,85,31,0.85]],
  [0.8,  [240,120,40,0.95]],
  [1.0,  [255,58,58,1]],
];

function hmColor(v, mx) {
  if (mx === 0 || v === 0) return 'rgba(5,14,23,1)';
  const t = Math.min(1, v/mx);
  let lo = HM_GRAD[0], hi = HM_GRAD[HM_GRAD.length-1];
  for (let i = 0; i < HM_GRAD.length-1; i++) {
    if (t >= HM_GRAD[i][0] && t <= HM_GRAD[i+1][0]) { lo = HM_GRAD[i]; hi = HM_GRAD[i+1]; break; }
  }
  const r2 = (hi[0]-lo[0]) === 0 ? 0 : (t-lo[0])/(hi[0]-lo[0]);
  const [r1a,g1a,b1a,a1a] = lo[1], [r2a,g2a,b2a,a2a] = hi[1];
  const ri = Math.round(r1a+(r2a-r1a)*r2);
  const gi = Math.round(g1a+(g2a-g1a)*r2);
  const bi = Math.round(b1a+(b2a-b1a)*r2);
  const ai = (a1a+(a2a-a1a)*r2).toFixed(2);
  return `rgba(${ri},${gi},${bi},${ai})`;
}

// ── HEATMAP RENDER ─────────────────────────────────────────────────────────────

let _hmWt = 'count';

function popHMFilter() {
  const sel = document.getElementById('hmComputerFilter');
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = '<option value="">All Computers</option>';
  Object.keys(S.computerCounts).sort().forEach(c =>
    sel.innerHTML += `<option value="${eH(c)}"${c===cur?' selected':''}>${eH(c)}</option>`
  );
}

function rHM() { popHMFilter(); _renderHeatmap(); }

function _renderHeatmap() {
  const compFilter = document.getElementById('hmComputerFilter')?.value || '';
  let rows = getFR().filter(r => !isNaN(r.ts));
  if (compFilter) rows = rows.filter(r => r.comp === compFilter);
  if (!rows.length) { document.getElementById('hmStats').textContent = 'No data for this filter.'; return; }

  const dayMap = new Map(), dayWeight = new Map();
  for (const r of rows) {
    const d = new Date(r.ts);
    const dk = d.getUTCFullYear() + '-' + String(d.getUTCMonth()+1).padStart(2,'0') + '-' + String(d.getUTCDate()).padStart(2,'0');
    const h = d.getUTCHours();
    if (!dayMap.has(dk)) { dayMap.set(dk, new Float64Array(24)); dayWeight.set(dk, new Float64Array(24)); }
    dayMap.get(dk)[h]++;
    dayWeight.get(dk)[h] += (HM_SEV_W[r.lvl] || 1);
  }

  const days = [...dayMap.keys()].sort();
  const useWeight = _hmWt === 'severity', dataMap = useWeight ? dayWeight : dayMap;
  let mx = 0;
  for (const arr of dataMap.values()) for (const v of arr) if (v > mx) mx = v;

  const CELL_W = Math.max(16, Math.floor((window.innerWidth-300)/24)), CELL_H = 22;
  const PAD_L=90, PAD_T=32, PAD_B=16, PAD_R=16;
  const cvs = document.getElementById('canvasHeatmap');
  const dpr = window.devicePixelRatio || 1;
  const cw = PAD_L + 24*CELL_W + PAD_R, ch = PAD_T + days.length*CELL_H + PAD_B;
  cvs.width = cw*dpr; cvs.height = ch*dpr;
  cvs.style.width = cw+'px'; cvs.style.height = ch+'px';
  const ctx = cvs.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0,0,cw,ch);
  ctx.fillStyle = '#6e7f90';
  ctx.font = '10px JetBrains Mono,monospace';
  ctx.textAlign = 'center';
  for (let h = 0; h < 24; h++)
    ctx.fillText(String(h).padStart(2,'0'), PAD_L+h*CELL_W+CELL_W/2, PAD_T-8);
  days.forEach((dk, di) => {
    const arr = dataMap.get(dk);
    ctx.fillStyle = '#6e7f90';
    ctx.font = '11px JetBrains Mono,monospace';
    ctx.textAlign = 'right';
    ctx.fillText(dk.slice(5), PAD_L-6, PAD_T+di*CELL_H+CELL_H/2+4);
    for (let h = 0; h < 24; h++) {
      const v = arr[h];
      ctx.fillStyle = hmColor(v, mx);
      ctx.fillRect(PAD_L+h*CELL_W+1, PAD_T+di*CELL_H+1, CELL_W-2, CELL_H-2);
    }
  });

  const peak = days.map(dk => {
    const a = dataMap.get(dk);
    let s = 0; for (const v of a) s += v;
    return {dk, sum:s};
  }).sort((a,b) => b.sum-a.sum)[0];
  document.getElementById('hmStats').innerHTML =
    `<strong>Days:</strong> ${days.length} &nbsp; <strong>Peak day (UTC):</strong> ${peak ? peak.dk+' ('+peak.sum.toFixed(useWeight?1:0)+(useWeight?' wt':' evt')+')' : ''} &nbsp; <strong>Max/cell:</strong> ${mx.toFixed(useWeight?1:0)}`;

  cvs.onclick = e => {
    const rect = cvs.getBoundingClientRect();
    const x = e.clientX-rect.left, y = e.clientY-rect.top;
    const col = Math.floor((x-PAD_L)/CELL_W), row = Math.floor((y-PAD_T)/CELL_H);
    if (col < 0 || col > 23 || row < 0 || row >= days.length) return;
    const dk = days[row];
    document.getElementById('filterTimeStart').value = dk;
    document.getElementById('filterTimeEnd').value   = dk;
    S.filters.timeStart = dk; S.filters.timeEnd = dk; invF();
    showToast(`Filtered to ${dk} — switching to Timeline`);
    switchTab('timeline');
  };
  cvs.onmousemove = e => {
    const rect = cvs.getBoundingClientRect();
    const x = e.clientX-rect.left, y = e.clientY-rect.top;
    const col = Math.floor((x-PAD_L)/CELL_W), row = Math.floor((y-PAD_T)/CELL_H);
    if (col < 0 || col > 23 || row < 0 || row >= days.length) { hT(); return; }
    const dk = days[row];
    const cnt = dayMap.get(dk)?.[col] || 0, wt = dayWeight.get(dk)?.[col] || 0;
    sT(e.clientX, e.clientY,
      `<strong>${dk}</strong> ${String(col).padStart(2,'0')}:00 UTC<br>Events: <strong style="color:var(--orange)">${cnt}</strong><br>Sev-weight: <strong style="color:var(--warn)">${wt.toFixed(1)}</strong>`);
  };
  cvs.onmouseleave = hT;
}

// ── TIME-OF-DAY ────────────────────────────────────────────────────────────────

function renderTOD() {
  const compF = document.getElementById('todComputer')?.value || '';
  let rows = getFR().filter(r => !isNaN(r.ts));
  if (compF) rows = rows.filter(r => r.comp === compF);
  if (!rows.length) return;
  const hc = new Array(24).fill(0);
  rows.forEach(r => hc[new Date(r.ts).getUTCHours()]++);
  let bestSum = 0, bestStart = 0;
  for (let s = 0; s < 24; s++) {
    let sum = 0;
    for (let i = 0; i < 8; i++) sum += hc[(s+i)%24];
    if (sum > bestSum) { bestSum = sum; bestStart = s; }
  }
  const peakHours = new Set();
  for (let i = 0; i < 8; i++) peakHours.add((bestStart+i)%24);
  const st = cStats(hc);
  const labels = Array.from({length:24}, (_,h) => String(h).padStart(2,'0'));
  const colors = hc.map((v,h) => {
    if (peakHours.has(h)) return 'rgba(220,85,31,0.65)';
    const z = st.std > 0 ? (v-st.mean)/st.std : 0;
    if (z > 2) return 'rgba(240,168,48,0.85)';
    return 'rgba(9,55,95,0.6)';
  });
  const cvs = document.getElementById('canvasTOD');
  const {ctx,w,h} = sC(cvs);
  const pL=40,pR=20,pT=20,pB=30,cW=w-pL-pR,cH=h-pT-pB;
  const mx = Math.max(...hc, 1);
  const bW = Math.max(2, (cW/24) - 2);
  ctx.clearRect(0,0,w,h);
  ctx.strokeStyle = '#1a3a55'; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pT+(cH/4)*i;
    ctx.beginPath(); ctx.moveTo(pL,y); ctx.lineTo(w-pR,y); ctx.stroke();
    ctx.fillStyle = '#6e7f90';
    ctx.font = '10px JetBrains Mono,monospace';
    ctx.textAlign = 'right';
    ctx.fillText(Math.round(mx*(1-i/4)).toLocaleString(), pL-6, y+4);
  }
  for (let h2 = 0; h2 < 24; h2++) {
    const x = pL+(h2/24)*cW, bH = (hc[h2]/mx)*cH;
    ctx.fillStyle = colors[h2];
    ctx.fillRect(x, pT+cH-bH, bW, bH);
    ctx.fillStyle = '#6e7f90';
    ctx.font = '9px JetBrains Mono,monospace';
    ctx.textAlign = 'center';
    ctx.fillText(labels[h2], x+bW/2, h-5);
  }
  const offPeak = [];
  for (let h2 = 0; h2 < 24; h2++) {
    if (!peakHours.has(h2) && hc[h2] > 0) {
      const z = st.std > 0 ? (hc[h2]-st.mean)/st.std : 0;
      if (z > 2) offPeak.push({h:h2, count:hc[h2], z});
    }
  }
  document.getElementById('todAfterHours').innerHTML = offPeak.length
    ? `<div class="anomaly-item warn"><div class="anomaly-title">Off-hours activity detected</div><div class="anomaly-detail">Peak window: ${String(bestStart).padStart(2,'0')}:00–${String((bestStart+8)%24).padStart(2,'0')}:00 UTC<br>${offPeak.map(o=>`Hour ${String(o.h).padStart(2,'0')}:00 — ${o.count.toLocaleString()} events (${o.z.toFixed(1)}σ)`).join('<br>')}</div></div>`
    : `<div class="anomaly-item info"><div class="anomaly-title">No significant off-hours activity</div><div class="anomaly-detail">Peak window: ${String(bestStart).padStart(2,'0')}:00–${String((bestStart+8)%24).padStart(2,'0')}:00 UTC</div></div>`;
}
