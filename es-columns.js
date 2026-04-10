// es-columns.js — EventScope v5 — Column management: reorder, per-column filters, persist
'use strict';

// ── COLUMN DEFINITIONS ────────────────────────────────────────────────────────
// Single source of truth for table display + copy.  Order here = default order.

const RAW_COLS = [
  {key:'ts',   label:'Timestamp',    on:true,  w:195, fmt:r => !isNaN(r.ts) ? fDTz(r.ts) : 'N/A',  val:r => r.ts, sort:'num'},
  {key:'lvl',  label:'Level',        on:true,  w:90,  fmt:r => lB(r.lvl),                           val:r => r.lvl, sort:'lvl'},
  {key:'eid',  label:'EID',          on:true,  w:70,  fmt:r => eL(r.eid),                           val:r => r.eid, sort:'num'},
  {key:'rule', label:'Rule',         on:true,  w:300, fmt:r => eH(r.rule),                          val:r => r.rule, sort:'str'},
  {key:'comp', label:'Computer',     on:true,  w:150, fmt:r => eH(r.comp),                          val:r => r.comp, sort:'str'},
  {key:'chan', label:'Channel',       on:true,  w:160, fmt:r => eH(r.chan),                          val:r => r.chan, sort:'str'},
  {key:'rec',  label:'Record',       on:true,  w:80,  fmt:r => eH(r.rec),                           val:r => r.rec, sort:'num'},
  {key:'src',  label:'Source',       on:false, w:160, fmt:r => eH((r.src||'').split(/[\/\\]/).pop()), val:r => r.src, sort:'str'},
  {key:'det',  label:'Details',      on:false, w:400, fmt:r => eH((r.det||'').substring(0,120)),     val:r => r.det, sort:'str'},
  {key:'rid',  label:'Rule ID',      on:false, w:120, fmt:r => eH(r.rid),                           val:r => r.rid, sort:'str'},
];

// ── COLUMN STATE ──────────────────────────────────────────────────────────────

let _colState = null;     // [{key, on}] — order + visibility
let _colFilters = {};     // key → Set of allowed values (null = no filter)
let _colSortKey = 'ts';
let _colSortDir = 1;      // 1=asc, -1=desc

function _getColState() {
  if (_colState) return _colState;
  try {
    const s = localStorage.getItem('eventscope_col_state');
    if (s) {
      const parsed = JSON.parse(s);
      // Validate: all saved keys must exist in RAW_COLS
      const validKeys = new Set(RAW_COLS.map(c => c.key));
      const valid = parsed.filter(c => validKeys.has(c.key));
      // Add any new columns not in saved state
      const savedKeys = new Set(valid.map(c => c.key));
      for (const c of RAW_COLS) {
        if (!savedKeys.has(c.key)) valid.push({key:c.key, on:c.on});
      }
      _colState = valid;
      return _colState;
    }
  } catch(e) {}
  _colState = RAW_COLS.map(c => ({key:c.key, on:c.on}));
  return _colState;
}

function _saveColState() {
  try { localStorage.setItem('eventscope_col_state', JSON.stringify(_colState)); } catch(e) {}
}

function _colDef(key) {
  return RAW_COLS.find(c => c.key === key);
}

// Get visible columns in order
function _visCols() {
  return _getColState().filter(c => c.on).map(c => _colDef(c.key)).filter(Boolean);
}

// ── PER-COLUMN FILTERS ────────────────────────────────────────────────────────

function applyColFilters(rows) {
  const activeFilters = Object.entries(_colFilters).filter(([, v]) => v !== null && v !== undefined);
  if (!activeFilters.length) return rows;
  return rows.filter(r => {
    for (const [key, allowed] of activeFilters) {
      const def = _colDef(key);
      if (!def) continue;
      const v = String(def.val(r) ?? '');
      if (!allowed.has(v)) return false;
    }
    return true;
  });
}

function clearColFilter(key) {
  delete _colFilters[key];
  rRW();
}

function clearAllColFilters() {
  _colFilters = {};
  rRW();
}

// ── COLUMN HEADER DROPDOWN ────────────────────────────────────────────────────

let _activeColDropdown = null;

function _closeColDropdown() {
  if (_activeColDropdown) {
    _activeColDropdown.remove();
    _activeColDropdown = null;
  }
  document.removeEventListener('mousedown', _onDocClickDropdown);
}

function _onDocClickDropdown(e) {
  if (_activeColDropdown && !_activeColDropdown.contains(e.target)) {
    _closeColDropdown();
  }
}

function openColDropdown(key, thEl) {
  _closeColDropdown();

  const def = _colDef(key);
  if (!def) return;

  const allFR = getFR();
  // Collect unique values for this column
  const counts = new Map();
  for (const r of allFR) {
    const v = String(def.val(r) ?? '');
    counts.set(v, (counts.get(v) || 0) + 1);
  }

  // Sort: for numeric columns sort numerically, otherwise by count desc
  let entries = [...counts.entries()];
  if (def.sort === 'num') {
    entries.sort((a, b) => {
      const na = parseFloat(a[0]), nb = parseFloat(b[0]);
      if (!isNaN(na) && !isNaN(nb)) return na - nb;
      return a[0].localeCompare(b[0]);
    });
  } else if (def.sort === 'lvl') {
    const LO = {critical:0,high:1,medium:2,low:3,informational:4};
    entries.sort((a, b) => (LO[a[0]] ?? 99) - (LO[b[0]] ?? 99));
  } else {
    entries.sort((a, b) => b[1] - a[1]);
  }

  const currentFilter = _colFilters[key] || null;

  // Build dropdown
  const dd = document.createElement('div');
  dd.className = 'col-dropdown';
  dd.innerHTML = `
    <div class="col-dd-search-wrap">
      <input type="text" class="col-dd-search" placeholder="Search${def.sort==='num'?' or range (e.g. 21-25)':' values'}..." autofocus>
    </div>
    <div class="col-dd-actions">
      <button class="col-dd-btn" data-action="all">Select All</button>
      <button class="col-dd-btn" data-action="none">Select None</button>
      <button class="col-dd-btn" data-action="invert">Invert</button>
      ${currentFilter ? '<button class="col-dd-btn col-dd-clear" data-action="clear">Clear Filter</button>' : ''}
    </div>
    <div class="col-dd-list"></div>
    <div class="col-dd-footer">
      <span class="col-dd-count">${entries.length} unique values</span>
      <button class="col-dd-apply">Apply</button>
    </div>`;

  // Position below header
  const rect = thEl.getBoundingClientRect();
  dd.style.left = Math.max(0, rect.left) + 'px';
  dd.style.top  = rect.bottom + 'px';
  document.body.appendChild(dd);
  _activeColDropdown = dd;

  // If dropdown goes off-screen right, nudge it
  const ddRect = dd.getBoundingClientRect();
  if (ddRect.right > window.innerWidth - 10) {
    dd.style.left = Math.max(0, window.innerWidth - ddRect.width - 10) + 'px';
  }

  const listEl = dd.querySelector('.col-dd-list');
  const searchEl = dd.querySelector('.col-dd-search');
  const checkedSet = new Set(currentFilter ? currentFilter : entries.map(e => e[0]));
  let visibleEntries = entries;

  function renderList() {
    listEl.innerHTML = visibleEntries.map(([val, cnt]) => {
      const checked = checkedSet.has(val) ? 'checked' : '';
      const display = val === '' ? '<i>(empty)</i>' : eH(val.length > 60 ? val.substring(0, 58) + '\u2026' : val);
      return `<label class="col-dd-item">
        <input type="checkbox" ${checked} data-val="${eH(val)}">
        <span class="col-dd-val">${display}</span>
        <span class="col-dd-cnt">${cnt.toLocaleString()}</span>
      </label>`;
    }).join('');

    // Wire checkboxes
    listEl.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', () => {
        if (cb.checked) checkedSet.add(cb.dataset.val);
        else checkedSet.delete(cb.dataset.val);
      });
    });
  }

  renderList();

  // Search / range filter
  searchEl.addEventListener('input', () => {
    const q = searchEl.value.trim();
    if (!q) {
      visibleEntries = entries;
    } else if (def.sort === 'num' && /^\d+\s*-\s*\d+$/.test(q)) {
      // Range filter: "21-25"
      const [lo, hi] = q.split('-').map(s => parseInt(s.trim(), 10));
      visibleEntries = entries.filter(([v]) => {
        const n = parseInt(v, 10);
        return !isNaN(n) && n >= lo && n <= hi;
      });
    } else {
      const ql = q.toLowerCase();
      visibleEntries = entries.filter(([v]) => v.toLowerCase().includes(ql));
    }
    renderList();
  });

  // Action buttons
  dd.querySelectorAll('.col-dd-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const action = btn.dataset.action;
      if (action === 'all')    visibleEntries.forEach(([v]) => checkedSet.add(v));
      if (action === 'none')   visibleEntries.forEach(([v]) => checkedSet.delete(v));
      if (action === 'invert') visibleEntries.forEach(([v]) => checkedSet.has(v) ? checkedSet.delete(v) : checkedSet.add(v));
      if (action === 'clear')  { clearColFilter(key); _closeColDropdown(); return; }
      renderList();
    });
  });

  // Apply
  dd.querySelector('.col-dd-apply').addEventListener('click', () => {
    if (checkedSet.size === entries.length) {
      delete _colFilters[key]; // All selected = no filter
    } else {
      _colFilters[key] = new Set(checkedSet);
    }
    _closeColDropdown();
    rRW();
  });

  // Close on outside click (after a tick to avoid the current click)
  setTimeout(() => document.addEventListener('mousedown', _onDocClickDropdown), 0);
  searchEl.focus();
}

// ── COLUMN SORT ───────────────────────────────────────────────────────────────

function setColSort(key) {
  if (_colSortKey === key) {
    _colSortDir *= -1;
  } else {
    _colSortKey = key;
    _colSortDir = 1;
  }
  rRW();
}

function sortRows(rows) {
  const def = _colDef(_colSortKey);
  if (!def) return rows;
  const sorted = [...rows];
  const dir = _colSortDir;
  if (def.sort === 'num') {
    sorted.sort((a, b) => {
      const va = parseFloat(def.val(a)) || 0, vb = parseFloat(def.val(b)) || 0;
      return (va - vb) * dir;
    });
  } else if (def.sort === 'lvl') {
    const LO = {critical:0,high:1,medium:2,low:3,informational:4};
    sorted.sort((a, b) => ((LO[def.val(a)]??99) - (LO[def.val(b)]??99)) * dir);
  } else {
    sorted.sort((a, b) => {
      const va = String(def.val(a) ?? '').toLowerCase();
      const vb = String(def.val(b) ?? '').toLowerCase();
      return va < vb ? -dir : va > vb ? dir : 0;
    });
  }
  return sorted;
}

// ── DRAG REORDER ──────────────────────────────────────────────────────────────

let _dragColKey = null;

function onColDragStart(e, key) {
  _dragColKey = key;
  e.dataTransfer.effectAllowed = 'move';
  e.target.classList.add('col-dragging');
}

function onColDragOver(e) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
}

function onColDragEnter(e) {
  const th = e.target.closest('th');
  if (th) th.classList.add('col-drag-over');
}

function onColDragLeave(e) {
  const th = e.target.closest('th');
  if (th) th.classList.remove('col-drag-over');
}

function onColDrop(e, targetKey) {
  e.preventDefault();
  const th = e.target.closest('th');
  if (th) th.classList.remove('col-drag-over');
  if (!_dragColKey || _dragColKey === targetKey) return;

  const state = _getColState();
  const srcIdx = state.findIndex(c => c.key === _dragColKey);
  const tgtIdx = state.findIndex(c => c.key === targetKey);
  if (srcIdx < 0 || tgtIdx < 0) return;

  const [moved] = state.splice(srcIdx, 1);
  state.splice(tgtIdx, 0, moved);
  _saveColState();
  rRW();
}

function onColDragEnd(e) {
  _dragColKey = null;
  e.target.classList.remove('col-dragging');
  document.querySelectorAll('.col-drag-over').forEach(el => el.classList.remove('col-drag-over'));
}

// ── TABLE HEADER BUILDER ──────────────────────────────────────────────────────

function buildRawHeader() {
  const cols = _visCols();
  const checkTh = '<th style="width:28px;padding:6px 8px"><input type="checkbox" id="rawSelectAll" onchange="rawSelectAll(this)" style="accent-color:var(--orange);cursor:pointer"></th>';

  const ths = cols.map(c => {
    const sortIcon = _colSortKey === c.key
      ? (_colSortDir === 1 ? ' \u25B4' : ' \u25BE')
      : '';
    const filterIcon = _colFilters[c.key] ? ' <span class="col-filter-dot">\u25CF</span>' : '';
    return `<th draggable="true"
      data-col="${c.key}"
      ondragstart="onColDragStart(event,'${c.key}')"
      ondragover="onColDragOver(event)"
      ondragenter="onColDragEnter(event)"
      ondragleave="onColDragLeave(event)"
      ondrop="onColDrop(event,'${c.key}')"
      ondragend="onColDragEnd(event)"
      style="max-width:${c.w}px;cursor:grab"
    ><span class="col-hdr-sort" onclick="setColSort('${c.key}')">${eH(c.label)}${sortIcon}</span>${filterIcon}<span class="col-hdr-filter" onclick="event.stopPropagation();openColDropdown('${c.key}',this.closest('th'))" title="Filter ${c.label}">\u25BC</span></th>`;
  });

  return checkTh + ths.join('');
}

function buildRawRow(r, fi, idx) {
  const cols = _visCols();
  const checkTd = `<td style="padding:6px 8px" onclick="event.stopPropagation()"><input type="checkbox" class="row-check" data-idx="${idx}" style="accent-color:var(--orange);cursor:pointer" onchange="onRawCheck(${idx},this,event)" onclick="event.stopPropagation()"></td>`;
  const tds = cols.map(c => {
    const style = c.key === 'rule' || c.key === 'det' || c.key === 'src'
      ? `max-width:${c.w}px;overflow:hidden;text-overflow:ellipsis`
      : '';
    const title = c.key === 'rule' ? `title="${eH(r.rule)}"` : c.key === 'src' ? `title="${eH(r.src||'')}"` : '';
    return `<td ${title} ${style ? `style="${style}"` : ''}>${c.fmt(r)}</td>`;
  }).join('');
  return `<tr style="cursor:pointer" data-nav-idx="${fi}" onclick="openDP(${fi},'raw')">${checkTd}${tds}</tr>`;
}

// ── AUTO-ENABLE SOURCE COLUMN FOR EVTXECMD ────────────────────────────────────

function autoEnableEvtxCols() {
  if (S.format === 'evtxecmd') {
    const state = _getColState();
    const src = state.find(c => c.key === 'src');
    if (src && !src.on) { src.on = true; _saveColState(); }
  }
}
