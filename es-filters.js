// es-filters.js — EventScope v5 — Filter logic
'use strict';

// ── TIME FILTER PARSING ────────────────────────────────────────────────────────
// Time inputs accept ISO-ish strings without zone info. Treat them as UTC so
// the on-screen UTC display matches the filter exactly. Minute precision.
function _parseFilterTime(s, isEnd) {
  if (!s) return NaN;
  s = s.trim().replace(' ', 'T');
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
    // bare date -> end of day for the end input, start of day for start
    s += isEnd ? 'T23:59:59' : 'T00:00:00';
  } else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(s)) {
    // datetime-local picker output (no seconds) -> tail with :59 for end
    s += isEnd ? ':59' : ':00';
  }
  // Force UTC
  if (!/[zZ]|[+-]\d{2}:?\d{2}$/.test(s)) s += 'Z';
  return new Date(s).getTime();
}

// ── LEVEL CHECKBOX HELPERS ─────────────────────────────────────────────────────

function getSelectedLevels() {
  const checks = document.querySelectorAll('#levelFilter input[type="checkbox"]');
  const s = new Set();
  checks.forEach(c => { if (c.checked) s.add(c.value); });
  return s;
}

// ── FILTER CACHE ───────────────────────────────────────────────────────────────

function getFR() {
  if (S.filtered !== null) return S.filtered;
  const f = S.filters;
  let r = S.rows;

  if (f.eventId) {
    const ids = f.eventId.split(',').map(s => s.trim()).filter(Boolean);
    if (ids.length) r = r.filter(x => ids.includes(x.eid));
  }
  if (f.ruleTitle) {
    const s = f.ruleTitle.toLowerCase();
    r = r.filter(x => x.rule.toLowerCase().includes(s));
  }
  // Bug 1 fix: level filter uses checkbox set
  const selectedLevels = getSelectedLevels();
  if (selectedLevels.size < 5) {
    r = r.filter(x => selectedLevels.has(x.lvl));
  }
  if (f.computer)  r = r.filter(x => x.comp === f.computer);
  if (f.channel)   r = r.filter(x => x.chan === f.channel);
  if (f.source)    r = r.filter(x => x.src === f.source);
  if (f.details) {
    const s = f.details.toLowerCase();
    r = r.filter(x => x.det.toLowerCase().includes(s));
  }
  if (f.timeStart) {
    // Parse as UTC. Accepts:
    //  YYYY-MM-DDTHH:MM   (datetime-local picker)
    //  YYYY-MM-DD HH:MM   (manual)
    //  YYYY-MM-DD         (date only -> 00:00 UTC)
    const t = _parseFilterTime(f.timeStart, false);
    if (!isNaN(t)) r = r.filter(x => x.ts >= t);
  }
  if (f.timeEnd) {
    // End is inclusive: a bare date becomes 23:59:59 UTC, a HH:MM becomes :59
    const t = _parseFilterTime(f.timeEnd, true);
    if (!isNaN(t)) r = r.filter(x => x.ts <= t);
  }

  S.filtered = r;
  return r;
}

function invF() {
  S.filtered = null;
}

// ── READ FILTER STATE FROM DOM ─────────────────────────────────────────────────
// Bug 1: no longer reads filterLevel (it's checkboxes that directly invalidate)

function readF() {
  S.filters = {
    eventId:   document.getElementById('filterEventId').value.trim(),
    ruleTitle: document.getElementById('filterRuleTitle').value.trim(),
    computer:  document.getElementById('filterComputer').value,
    channel:   document.getElementById('filterChannel').value,
    source:    document.getElementById('filterSource')?.value || '',
    details:   document.getElementById('filterDetails').value.trim(),
    timeStart: document.getElementById('filterTimeStart').value.trim(),
    timeEnd:   document.getElementById('filterTimeEnd').value.trim(),
  };
  invF();
  const at = document.querySelector('.tab.active');
  if (at) switchTab(at.dataset.tab);
}

// ── DEBOUNCE ───────────────────────────────────────────────────────────────────

function deb(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// ── FILTER BAR INIT ────────────────────────────────────────────────────────────

function initFilterBar() {
  // Filter input IDs (no filterLevel — it's checkboxes now)
  const fEls = ['filterEventId','filterRuleTitle','filterComputer','filterChannel','filterSource','filterDetails','filterTimeStart','filterTimeEnd'];

  fEls.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('change', readF);
    el.addEventListener('input', deb(readF, 400));
  });

  // Level checkboxes invalidate and re-render
  document.querySelectorAll('#levelFilter input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', () => {
      invF();
      const at = document.querySelector('.tab.active');
      if (at) switchTab(at.dataset.tab);
    });
  });

  // Reset button
  document.getElementById('filterReset').addEventListener('click', () => {
    fEls.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      if (el.tagName === 'SELECT') el.selectedIndex = 0;
      else el.value = '';
    });
    // Reset checkboxes to all-checked
    document.querySelectorAll('#levelFilter input[type="checkbox"]').forEach(c => c.checked = true);
    readF();
  });

  // Collapse toggle
  document.getElementById('filterToggle').addEventListener('click', function() {
    const content = document.getElementById('filterBarContent');
    const collapsed = content.classList.toggle('collapsed');
    this.classList.toggle('active', !collapsed);
    this.textContent = collapsed ? '▶ Filters' : '☰ Filters';
  });
}
