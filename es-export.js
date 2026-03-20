// es-export.js — EventScope v5 — Copy/column config system
'use strict';

// ── COPY COLUMN DEFINITIONS ────────────────────────────────────────────────────

const COPY_COLS_DEF = [
  {key:'ts',    label:'Timestamp',          on:true,  fmt:r => !isNaN(r.ts) ? fDMs(new Date(r.ts)) : ''},
  {key:'lvl',   label:'Level',              on:true,  fmt:r => r.lvl},
  {key:'eid',   label:'Event ID',           on:true,  fmt:r => r.eid},
  {key:'rule',  label:'Rule / Description', on:true,  fmt:r => r.rule},
  {key:'comp',  label:'Computer',           on:true,  fmt:r => r.comp},
  {key:'chan',  label:'Channel',            on:false, fmt:r => r.chan},
  {key:'rec',   label:'Record ID',          on:false, fmt:r => r.rec},
  {key:'det',   label:'Details',            on:true,  fmt:r => r.det},
  {key:'extra', label:'Extra / Payload',    on:false, fmt:r => r.extra},
  {key:'rid',   label:'Rule ID / Provider', on:false, fmt:r => r.rid},
  {key:'src',   label:'Source File',        on:false, fmt:r => r.src},
];

let _copyCfg = null;

function loadCopyCfg() {
  if (_copyCfg) return _copyCfg;
  try {
    const s = localStorage.getItem('eventscope_copy_cfg');
    if (s) { _copyCfg = JSON.parse(s); return _copyCfg; }
  } catch(e) {}
  _copyCfg = {cols: COPY_COLS_DEF.map(c => ({key:c.key, label:c.label, on:c.on})), delim:'tab'};
  return _copyCfg;
}

function saveCopyCfg() {
  try { localStorage.setItem('eventscope_copy_cfg', JSON.stringify(_copyCfg)); } catch(e) {}
}

function fmtCell(key, r) {
  const def = COPY_COLS_DEF.find(d => d.key === key);
  return def ? def.fmt(r) : '';
}

function esc_csv(v, delim) {
  const s = String(v ?? '');
  if (delim === ',' && (s.includes(',') || s.includes('"') || s.includes('\n')))
    return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

function rowsToText(rows) {
  const cfg    = loadCopyCfg();
  const active = cfg.cols.filter(c => c.on);
  if (!active.length) return '';
  const d = cfg.delim === 'comma' ? ',' : '\t';
  const lines = [active.map(c => c.label).join(d)];
  for (const r of rows) lines.push(active.map(c => esc_csv(fmtCell(c.key, r), d)).join(d));
  return lines.join('\r\n');
}

function copyRows(rows) {
  if (!rows || !rows.length) { showToast('No rows to copy'); return; }
  const text = rowsToText(rows);
  navigator.clipboard.writeText(text)
    .then(() => showToast(`Copied ${rows.length} row${rows.length!==1?'s':''}`))
    .catch(() => showToast('Clipboard write failed'));
}

function copyDetailEvent() {
  // Uses the _detailRowIndex set in es-views.js openDP
  if (typeof _detailRowIndex === 'undefined' || _detailRowIndex === null) return;
  const r = getFR()[_detailRowIndex];
  if (r) copyRows([r]);
}

function copyTableRows(ctx) {
  if (ctx === 'raw') {
    copyRows(getFR().slice(0, 2000));
    return;
  }
  if (ctx === 'rules') {
    const rows = getFR(), ra = {};
    rows.forEach(r => {
      if (!r.rule) return;
      if (!ra[r.rule]) ra[r.rule] = {ts:r.ts, lvl:r.lvl, eid:r.eid, rule:r.rule, comp:r.comp, chan:r.chan, rec:'', det:'', extra:'', rid:r.rid, src:''};
    });
    copyRows(Object.values(ra));
    return;
  }
}

function copyCluster(ci) {
  const c = S._seqClusters?.[ci];
  if (!c) return;
  copyRows(c.events);
}

// ── COLUMN CONFIG MODAL ────────────────────────────────────────────────────────

function openColCfg() {
  const cfg = loadCopyCfg();
  const container = document.getElementById('colCfgRows');
  function render() {
    container.innerHTML = cfg.cols.map((c,i) => `
      <div class="col-cfg-row" data-idx="${i}">
        <input class="col-cfg-check" type="checkbox" id="cc${i}" ${c.on?'checked':''} onchange="loadCopyCfg().cols[${i}].on=this.checked">
        <label class="col-cfg-lbl" for="cc${i}">${c.label}</label>
        <button class="col-cfg-mv" onclick="moveCfgCol(${i},-1)" ${i===0?'disabled':''}>&#9650;</button>
        <button class="col-cfg-mv" onclick="moveCfgCol(${i},1)"  ${i===cfg.cols.length-1?'disabled':''}>&#9660;</button>
      </div>`).join('');
  }
  render();
  window._cfgRender = render;
  document.querySelectorAll('.delim-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.delim === cfg.delim);
    b.onclick = () => {
      cfg.delim = b.dataset.delim;
      document.querySelectorAll('.delim-btn').forEach(x => x.classList.toggle('active', x.dataset.delim === cfg.delim));
    };
  });
  document.getElementById('colCfgOverlay').classList.add('open');
}

function moveCfgCol(i, dir) {
  const cfg = loadCopyCfg(), j = i + dir;
  if (j < 0 || j >= cfg.cols.length) return;
  [cfg.cols[i], cfg.cols[j]] = [cfg.cols[j], cfg.cols[i]];
  if (window._cfgRender) window._cfgRender();
}

// ── COLUMN CONFIG EVENT LISTENERS ─────────────────────────────────────────────

function initExport() {
  document.getElementById('colCfgSave').addEventListener('click', () => {
    saveCopyCfg();
    document.getElementById('colCfgOverlay').classList.remove('open');
  });
  document.getElementById('colCfgCancel').addEventListener('click', () => {
    _copyCfg = null; loadCopyCfg();
    document.getElementById('colCfgOverlay').classList.remove('open');
  });
  document.getElementById('colCfgOverlay').addEventListener('click', e => {
    if (e.target === document.getElementById('colCfgOverlay')) {
      _copyCfg = null; loadCopyCfg();
      document.getElementById('colCfgOverlay').classList.remove('open');
    }
  });
}
