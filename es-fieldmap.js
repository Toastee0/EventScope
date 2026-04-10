// es-fieldmap.js — EventScope v5 — Semantic field mapping system
// Lets analysts map raw event fields to semantic roles per Channel::EID.
// Replaces hardcoded field name lookups with a resolver that learns.
'use strict';

// ── SEMANTIC ROLE VOCABULARY (v1) ─────────────────────────────────────────────

const FIELD_ROLES = [
  'time','srcip','destip','srcport','destport','srchost','desthost',
  'srcuser','destuser','subjectuser','process','parentprocess',
  'processid','commandline','filepath','filehash','logontype',
  'sessionid','result','direction','protocol','ignore'
];

// Human-friendly labels
const ROLE_LABELS = {
  time:'Timestamp', srcip:'Source IP', destip:'Dest IP',
  srcport:'Source Port', destport:'Dest Port',
  srchost:'Source Host', desthost:'Dest Host',
  srcuser:'Source User', destuser:'Dest User', subjectuser:'Subject User',
  process:'Process', parentprocess:'Parent Process',
  processid:'Process ID', commandline:'Command Line',
  filepath:'File Path', filehash:'File Hash',
  logontype:'Logon Type', sessionid:'Session ID',
  result:'Result', direction:'Direction', protocol:'Protocol',
  ignore:'Ignore'
};

function isValidRole(r) {
  return FIELD_ROLES.includes(r) || (typeof r === 'string' && r.startsWith('custom:'));
}

// ── STORAGE ───────────────────────────────────────────────────────────────────

const FM_KEY = 'eventscope.fieldmap.v1';
const FM_EXPORT_HASH_KEY = 'eventscope.fieldmap.lastExportHash';

function _loadFieldMappings() {
  if (S._fieldMappings) return S._fieldMappings;
  try {
    const s = localStorage.getItem(FM_KEY);
    if (s) { S._fieldMappings = JSON.parse(s); return S._fieldMappings; }
  } catch(e) {}
  S._fieldMappings = {};
  return S._fieldMappings;
}

function _saveFieldMappings() {
  try { localStorage.setItem(FM_KEY, JSON.stringify(S._fieldMappings || {})); } catch(e) {}
}

// Build the mapping key for a row
function _mapKey(row) {
  const ch = row.chan || '';
  const eid = String(row.eid || '');
  if (ch) return ch + '::' + eid;
  const prov = row.rid || '';
  return prov ? prov + '::' + eid : '::' + eid;
}

// ── DEFAULT MAPPING PACK ──────────────────────────────────────────────────────

let _defaultPack = null;

async function loadDefaultPack() {
  try {
    const resp = await fetch('es-data/default-fieldmap.json');
    _defaultPack = await resp.json();
  } catch(e) {
    _defaultPack = {};
  }
  // Merge defaults under user mappings (user wins)
  const user = _loadFieldMappings();
  for (const [key, mapping] of Object.entries(_defaultPack)) {
    if (!user[key]) {
      user[key] = mapping;
    }
  }
  S._fieldMappings = user;
}

// ── RESOLVER ──────────────────────────────────────────────────────────────────

// Cache for parsed extra/det fields — keyed by row reference
const _fieldCache = new WeakMap();

function _getAllFields(row) {
  if (_fieldCache.has(row)) return _fieldCache.get(row);
  const fields = {};

  // 1. parseDet fields (from det)
  if (row.det) {
    const p = parseDet(row.det);
    Object.assign(fields, p);
  }

  // 2. Extra/Payload XML fields
  if (row.extra) {
    const re = /<Data\s+Name="([^"]+)"[^>]*>([^<]*)<\/Data>/gi;
    let m;
    while ((m = re.exec(row.extra)) !== null) {
      const k = m[1], v = m[2].trim();
      if (v && v !== '-' && !fields[k]) fields[k] = v;
    }
    // Also try ExtraFieldInfo key:value pairs (Hayabusa)
    if (!row.extra.startsWith('<')) {
      for (const part of row.extra.split('\u00a6')) {
        const ci = part.indexOf(':');
        if (ci > 0) {
          const k = part.substring(0, ci).trim();
          const v = part.substring(ci + 1).trim();
          if (k && v && !fields[k]) fields[k] = v;
        }
      }
    }
  }

  _fieldCache.set(row, fields);
  return fields;
}

// Resolve a semantic role for a given row.
// Returns the field value or null if no mapping or field not found.
function getMappedField(row, role) {
  const key = _mapKey(row);
  const mappings = _loadFieldMappings();
  const mapping = mappings[key];
  if (!mapping || !mapping.fields) return null;

  for (const [rawField, mappedRole] of Object.entries(mapping.fields)) {
    if (mappedRole === role) {
      const fields = _getAllFields(row);
      const v = fields[rawField];
      if (v && v !== '-') return v;
    }
  }
  return null;
}

// Get all mapped fields for a row as {role: value} pairs
function getMappedFields(row) {
  const key = _mapKey(row);
  const mappings = _loadFieldMappings();
  const mapping = mappings[key];
  if (!mapping || !mapping.fields) return {};

  const fields = _getAllFields(row);
  const result = {};
  for (const [rawField, role] of Object.entries(mapping.fields)) {
    if (role === 'ignore') continue;
    const v = fields[rawField];
    if (v && v !== '-') result[role] = v;
  }
  return result;
}

// ── FIELD DISCOVERY ───────────────────────────────────────────────────────────
// Scan sample rows for a given Channel::EID and discover all available fields
// with sample values.

function discoverFields(channelEid, maxSamples) {
  maxSamples = maxSamples || 50;
  const rows = (S.rows || []).filter(r => _mapKey(r) === channelEid);
  const samples = rows.slice(0, maxSamples);

  // Collect all field names → [sample values]
  const fieldSamples = new Map();
  for (const row of samples) {
    const fields = _getAllFields(row);
    for (const [k, v] of Object.entries(fields)) {
      if (!fieldSamples.has(k)) fieldSamples.set(k, []);
      const arr = fieldSamples.get(k);
      if (arr.length < 3 && v && v !== '-' && !arr.includes(v)) arr.push(v);
    }
  }

  return fieldSamples; // Map<fieldName, string[]>
}

// ── SAVE / UPDATE MAPPING ─────────────────────────────────────────────────────

function saveMapping(channelEid, fieldsObj, notes) {
  const mappings = _loadFieldMappings();
  const now = new Date().toISOString();
  const existing = mappings[channelEid];
  mappings[channelEid] = {
    added_utc: existing ? existing.added_utc : now,
    updated_utc: now,
    notes: notes || '',
    fields: fieldsObj
  };
  _saveFieldMappings();
}

function deleteMapping(channelEid) {
  const mappings = _loadFieldMappings();
  delete mappings[channelEid];
  _saveFieldMappings();
}

// ── UNMAPPED EVENT DETECTION ──────────────────────────────────────────────────

function getUnmappedEvents() {
  const mappings = _loadFieldMappings();
  const counts = new Map(); // channelEid → {count, sampleRule, chan, eid}
  for (const row of (S.rows || [])) {
    const key = _mapKey(row);
    if (mappings[key]) continue;
    if (!counts.has(key)) {
      counts.set(key, {key, chan: row.chan, eid: row.eid, count: 0, sampleRule: row.rule || row.comp || ''});
    }
    const e = counts.get(key);
    e.count++;
    if (!e.sampleRule && (row.rule || row.comp)) e.sampleRule = row.rule || row.comp;
  }
  return [...counts.values()].sort((a, b) => b.count - a.count);
}

// ── EXPORT ────────────────────────────────────────────────────────────────────

// Sanitization regex patterns — block export if notes contain evidence data
const _SANITIZE_PATTERNS = [
  { name: 'IPv4 address', re: /\b\d{1,3}(\.\d{1,3}){3}\b/ },
  { name: 'UNC path',     re: /\\\\[^\\]+\\/ },
  { name: 'SID',          re: /S-1-[0-9-]+/ },
  { name: 'Email',        re: /[^\s]+@[^\s]+\.[^\s]+/ },
];

function sanitizeCheck(mappings) {
  const violations = [];
  for (const [key, mapping] of Object.entries(mappings)) {
    if (!mapping.notes) continue;
    for (const pat of _SANITIZE_PATTERNS) {
      if (pat.re.test(mapping.notes)) {
        violations.push({ key, pattern: pat.name, text: mapping.notes });
      }
    }
  }
  return violations;
}

function buildExport(analystInitials) {
  const mappings = _loadFieldMappings();
  // Strip to only field names + roles + notes (no sample values, no counts)
  const clean = {};
  for (const [key, mapping] of Object.entries(mappings)) {
    clean[key] = {
      added_utc: mapping.added_utc,
      updated_utc: mapping.updated_utc,
      notes: mapping.notes || '',
      fields: { ...mapping.fields }
    };
  }

  return {
    schema: 'eventscope-fieldmap/v1',
    exported_utc: new Date().toISOString(),
    exported_by: analystInitials || '',
    mappings: clean
  };
}

async function exportFieldMappings(analystInitials) {
  const mappings = _loadFieldMappings();
  const violations = sanitizeCheck(mappings);
  if (violations.length) {
    return { ok: false, violations };
  }

  const payload = buildExport(analystInitials);
  const json = JSON.stringify(payload, null, 2);

  // Compute hash for filename
  const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(json));
  const hashArr = new Uint8Array(hashBuf);
  const hashHex = Array.from(hashArr.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('');
  const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const filename = `eventscope-fieldmap-${dateStr}-${hashHex}.json`;

  // Store export hash for diff tracking
  try { localStorage.setItem(FM_EXPORT_HASH_KEY, hashHex); } catch(e) {}

  return { ok: true, json, filename, payload, count: Object.keys(payload.mappings).length };
}

function downloadExport(json, filename) {
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── IMPORT ────────────────────────────────────────────────────────────────────

function parseImport(jsonString) {
  const data = JSON.parse(jsonString);
  if (!data.schema) return { ok: false, error: 'Missing schema field' };
  if (!data.schema.startsWith('eventscope-fieldmap/v')) return { ok: false, error: 'Unknown schema: ' + data.schema };

  const ver = parseInt(data.schema.split('/v')[1], 10);
  if (ver > 1) return { ok: false, error: 'Schema version ' + ver + ' is newer than supported (v1). Update EventScope.' };

  const incoming = data.mappings || {};
  const existing = _loadFieldMappings();

  const added = [], identical = [], conflicts = [];
  for (const [key, mapping] of Object.entries(incoming)) {
    if (!existing[key]) {
      added.push({ key, mapping });
    } else {
      // Compare field assignments
      const same = JSON.stringify(existing[key].fields) === JSON.stringify(mapping.fields);
      if (same) {
        identical.push(key);
      } else {
        conflicts.push({ key, existing: existing[key], incoming: mapping });
      }
    }
  }

  return { ok: true, data, added, identical, conflicts };
}

function applyImport(added, resolvedConflicts) {
  const mappings = _loadFieldMappings();
  for (const { key, mapping } of added) {
    mappings[key] = mapping;
  }
  for (const { key, mapping } of (resolvedConflicts || [])) {
    mappings[key] = mapping;
  }
  S._fieldMappings = mappings;
  _saveFieldMappings();
}

// ── DIFF (since last export) ──────────────────────────────────────────────────

function getExportDiff() {
  const mappings = _loadFieldMappings();
  const total = Object.keys(mappings).length;
  const lastHash = localStorage.getItem(FM_EXPORT_HASH_KEY) || null;
  // We track new/changed via updated_utc comparison if we stored a last export date
  // For now: report total and whether last export hash exists
  return { total, hasExported: !!lastHash, lastHash };
}

// ── ROUND-TRIP VERIFICATION ───────────────────────────────────────────────────

async function verifyRoundTrip() {
  const result = await exportFieldMappings('');
  if (!result.ok) return { ok: false, error: 'Export failed: sanitization violations' };

  const reimported = parseImport(result.json);
  if (!reimported.ok) return { ok: false, error: 'Re-import failed: ' + reimported.error };

  const live = _loadFieldMappings();
  const imported = reimported.data.mappings;

  // Deep compare
  const liveKeys = Object.keys(live).sort();
  const importKeys = Object.keys(imported).sort();

  if (liveKeys.length !== importKeys.length) {
    return { ok: false, error: `Key count mismatch: live=${liveKeys.length}, reimported=${importKeys.length}` };
  }

  for (const key of liveKeys) {
    if (!imported[key]) return { ok: false, error: `Missing key after round-trip: ${key}` };
    if (JSON.stringify(live[key].fields) !== JSON.stringify(imported[key].fields)) {
      return { ok: false, error: `Field mismatch for ${key}` };
    }
  }

  return { ok: true, count: liveKeys.length };
}

// ── CUSTOM ROLE DISCOVERY ─────────────────────────────────────────────────────

function getCustomRoles() {
  const mappings = _loadFieldMappings();
  const customs = new Set();
  for (const mapping of Object.values(mappings)) {
    if (!mapping.fields) continue;
    for (const role of Object.values(mapping.fields)) {
      if (typeof role === 'string' && role.startsWith('custom:')) customs.add(role);
    }
  }
  return [...customs].sort();
}

// ── DEVELOPER TAB RENDERING ───────────────────────────────────────────────────

function rDeveloper() {
  const el = document.getElementById('developerContent');
  if (!el) return;

  const mappings = _loadFieldMappings();
  const unmapped = getUnmappedEvents();
  const mapped = Object.entries(mappings).sort((a, b) => (b[1].updated_utc || '').localeCompare(a[1].updated_utc || ''));
  const customs = getCustomRoles();
  const diff = getExportDiff();

  el.innerHTML = `
    <div class="chart-box">
      <div class="chart-header">
        <span class="chart-title">Developer &mdash; Field Mapping</span>
        <span style="font-family:var(--mono);font-size:11px;color:var(--text-dim)">${diff.total} mappings total</span>
        <div style="display:flex;gap:6px;margin-left:auto;align-items:center">
          <button class="copy-btn" onclick="openExportPreview()">Export Mappings</button>
          <button class="copy-btn" onclick="triggerImport()">Import</button>
          <button class="copy-btn" onclick="runRoundTrip()">Verify Round Trip</button>
          <input type="file" id="fieldmapImportInput" accept=".json" style="display:none">
        </div>
      </div>

      <!-- UNMAPPED EVENTS -->
      <div style="margin-bottom:24px">
        <div style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--orange);margin-bottom:8px;padding:0 8px">
          Unmapped Events (${unmapped.length})
        </div>
        ${unmapped.length ? `
          <div class="data-table-wrap" style="max-height:350px;overflow-y:auto">
            <table class="data-table"><thead><tr>
              <th>Channel</th><th>EID</th><th>Count</th><th>Sample Rule/Description</th><th></th>
            </tr></thead><tbody>
              ${unmapped.slice(0, 200).map(u => `<tr>
                <td style="font-size:11px">${eH(u.chan)}</td>
                <td>${eH(u.eid)}</td>
                <td>${u.count.toLocaleString()}</td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;font-size:11px">${eH(u.sampleRule)}</td>
                <td><button class="copy-btn" onclick="openFieldPicker('${eH(u.key)}')">Map Fields</button></td>
              </tr>`).join('')}
            </tbody></table>
          </div>
        ` : '<div style="padding:16px;color:var(--text-dim);font-family:var(--mono);font-size:12px">All Channel::EID combinations in the dataset have mappings.</div>'}
      </div>

      <!-- EXISTING MAPPINGS -->
      <div style="margin-bottom:24px">
        <div style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--white);margin-bottom:8px;padding:0 8px">
          Existing Mappings (${mapped.length})
        </div>
        ${mapped.length ? `
          <div class="data-table-wrap" style="max-height:400px;overflow-y:auto">
            <table class="data-table"><thead><tr>
              <th>Channel::EID</th><th>Fields</th><th>Notes</th><th>Updated</th><th></th>
            </tr></thead><tbody>
              ${mapped.map(([key, m]) => {
                const fieldCount = Object.keys(m.fields || {}).length;
                const roles = [...new Set(Object.values(m.fields || {}))].join(', ');
                return `<tr>
                  <td style="font-size:11px;white-space:nowrap">${eH(key)}</td>
                  <td style="font-size:11px" title="${eH(roles)}">${fieldCount} fields</td>
                  <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;font-size:11px">${eH(m.notes || '')}</td>
                  <td style="font-size:10px;color:var(--text-dim);white-space:nowrap">${m.updated_utc ? m.updated_utc.substring(0,10) : ''}</td>
                  <td style="white-space:nowrap">
                    <button class="copy-btn" onclick="openFieldPicker('${eH(key)}')">Edit</button>
                    <button class="copy-btn" onclick="if(confirm('Delete mapping for ${eH(key)}?')){deleteMapping('${eH(key)}');rDeveloper()}" style="color:var(--critical)">Del</button>
                  </td>
                </tr>`;
              }).join('')}
            </tbody></table>
          </div>
        ` : '<div style="padding:16px;color:var(--text-dim);font-family:var(--mono);font-size:12px">No mappings yet. Click "Map Fields" on an unmapped event above.</div>'}
      </div>

      <!-- CUSTOM ROLE PROMOTION CANDIDATES -->
      ${customs.length ? `
        <div>
          <div style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--text-dim);margin-bottom:8px;padding:0 8px">
            Promotion Candidates &mdash; Custom Roles (${customs.length})
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;padding:0 8px">
            ${customs.map(c => `<span style="font-family:var(--mono);font-size:11px;padding:3px 8px;border:1px solid var(--border);border-radius:4px;color:var(--orange)">${eH(c)}</span>`).join('')}
          </div>
        </div>
      ` : ''}
    </div>`;

  // Wire import file input
  const importInput = document.getElementById('fieldmapImportInput');
  if (importInput) {
    importInput.addEventListener('change', async () => {
      if (!importInput.files.length) return;
      const text = await importInput.files[0].text();
      importInput.value = '';
      handleImport(text);
    });
  }
}

// ── FIELD PICKER MODAL ────────────────────────────────────────────────────────

let _fieldPickerKey = null;

function openFieldPicker(channelEid) {
  _fieldPickerKey = channelEid;
  const mappings = _loadFieldMappings();
  const existing = mappings[channelEid];

  document.getElementById('fieldPickerTitle').textContent = 'Map Fields — ' + channelEid;
  const parts = channelEid.split('::');
  document.getElementById('fieldPickerSub').textContent = `Channel: ${parts[0] || '(none)'}  |  EID: ${parts[1] || '?'}`;
  document.getElementById('fieldPickerNotes').value = existing ? (existing.notes || '') : '';

  const fieldSamples = discoverFields(channelEid, 50);
  const existingFields = existing ? (existing.fields || {}) : {};

  const roleOptions = FIELD_ROLES.map(r =>
    `<option value="${r}">${ROLE_LABELS[r] || r}</option>`
  ).join('') + '<option value="">— unmapped —</option>';

  const body = document.getElementById('fieldPickerBody');
  body.innerHTML = `<table class="data-table"><thead><tr>
    <th>Raw Field</th><th>Sample Values</th><th>Semantic Role</th>
  </tr></thead><tbody>
    ${[...fieldSamples.entries()].map(([field, samples]) => {
      const currentRole = existingFields[field] || '';
      const isCustom = currentRole.startsWith('custom:');
      return `<tr>
        <td style="font-weight:600;white-space:nowrap;font-size:12px">${eH(field)}</td>
        <td style="max-width:350px;overflow:hidden;text-overflow:ellipsis;font-size:11px;color:var(--text-dim)" title="${eH(samples.join(' | '))}">${eH(samples.map(s => s.length > 80 ? s.substring(0,78)+'\u2026' : s).join(' | '))}</td>
        <td>
          <select class="field-role-sel" data-field="${eH(field)}" style="font-family:var(--mono);font-size:11px;padding:3px 6px;background:var(--surface2);border:1px solid var(--border);border-radius:3px;color:var(--text)">
            <option value="">— unmapped —</option>
            ${FIELD_ROLES.map(r =>
              `<option value="${r}" ${currentRole === r ? 'selected' : ''}>${ROLE_LABELS[r] || r}</option>`
            ).join('')}
            ${isCustom ? `<option value="${eH(currentRole)}" selected>${eH(currentRole)}</option>` : ''}
            <option value="__custom__">custom:...</option>
          </select>
        </td>
      </tr>`;
    }).join('')}
  </tbody></table>`;

  // Wire custom role prompt
  body.querySelectorAll('.field-role-sel').forEach(sel => {
    sel.addEventListener('change', () => {
      if (sel.value === '__custom__') {
        const name = prompt('Enter custom role name (e.g. custom:servicename):');
        if (name && name.startsWith('custom:')) {
          const opt = document.createElement('option');
          opt.value = name; opt.textContent = name; opt.selected = true;
          sel.insertBefore(opt, sel.querySelector('[value="__custom__"]'));
        } else {
          sel.value = '';
          if (name) showToast('Custom roles must start with "custom:"');
        }
      }
    });
  });

  document.getElementById('fieldPickerOverlay').classList.add('open');
}

function closeFieldPicker() {
  document.getElementById('fieldPickerOverlay').classList.remove('open');
  _fieldPickerKey = null;
}

function saveFieldPicker() {
  if (!_fieldPickerKey) return;
  const body = document.getElementById('fieldPickerBody');
  const notes = (document.getElementById('fieldPickerNotes').value || '').trim();
  const fields = {};
  body.querySelectorAll('.field-role-sel').forEach(sel => {
    const role = sel.value;
    if (role && role !== '__custom__') {
      fields[sel.dataset.field] = role;
    }
  });
  saveMapping(_fieldPickerKey, fields, notes);
  closeFieldPicker();
  rDeveloper();
  showToast('Mapping saved for ' + _fieldPickerKey);
}

// ── EXPORT PREVIEW ────────────────────────────────────────────────────────────

async function openExportPreview() {
  const initials = (document.getElementById('exportInitials')?.value || '').trim();
  const result = await exportFieldMappings(initials);

  const warnings = document.getElementById('exportPreviewWarnings');
  const jsonEl = document.getElementById('exportPreviewJson');
  const confirmBtn = document.getElementById('exportConfirmBtn');

  if (!result.ok) {
    jsonEl.textContent = '';
    warnings.innerHTML = `<div style="color:var(--critical);font-family:var(--mono);font-size:12px;padding:8px">
      <strong>Export blocked — evidence data detected in notes:</strong><br>
      ${result.violations.map(v => `• ${eH(v.key)}: ${eH(v.pattern)} found`).join('<br>')}
    </div>`;
    confirmBtn.disabled = true;
    confirmBtn.style.opacity = '0.3';
  } else {
    jsonEl.textContent = result.json;
    warnings.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:var(--success);padding:4px 0">${result.count} mappings ready for export. Filename: ${eH(result.filename)}</div>`;
    confirmBtn.disabled = false;
    confirmBtn.style.opacity = '1';
    confirmBtn.onclick = () => {
      downloadExport(result.json, result.filename);
      closeExportPreview();
      showToast('Exported ' + result.count + ' mappings');
    };
  }

  document.getElementById('exportPreviewOverlay').classList.add('open');
}

function closeExportPreview() {
  document.getElementById('exportPreviewOverlay').classList.remove('open');
}

// ── IMPORT ────────────────────────────────────────────────────────────────────

function triggerImport() {
  document.getElementById('fieldmapImportInput').click();
}

let _importPending = null;

function handleImport(jsonText) {
  let result;
  try {
    result = parseImport(jsonText);
  } catch(e) {
    showToast('Import failed: ' + e.message);
    return;
  }
  if (!result.ok) {
    showToast('Import failed: ' + result.error);
    return;
  }

  if (result.conflicts.length) {
    _importPending = result;
    showImportConflicts(result);
  } else {
    applyImport(result.added, []);
    rDeveloper();
    showToast(`Imported ${result.added.length} new mapping(s), ${result.identical.length} identical`);
  }
}

function showImportConflicts(result) {
  const body = document.getElementById('importConflictBody');
  body.innerHTML = `
    <div style="padding:8px 20px;font-family:var(--mono);font-size:11px;color:var(--text-dim)">
      ${result.added.length} new, ${result.identical.length} identical, ${result.conflicts.length} conflict(s)
    </div>
    <table class="data-table"><thead><tr>
      <th>Channel::EID</th><th>Keep</th><th>Current Fields</th><th>Incoming Fields</th>
    </tr></thead><tbody>
      ${result.conflicts.map((c, i) => `<tr>
        <td style="font-size:11px">${eH(c.key)}</td>
        <td>
          <select class="conflict-sel" data-idx="${i}" style="font-family:var(--mono);font-size:11px;padding:3px;background:var(--surface2);border:1px solid var(--border);border-radius:3px;color:var(--text)">
            <option value="existing" selected>Keep Current</option>
            <option value="incoming">Use Incoming</option>
          </select>
        </td>
        <td style="font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${eH(Object.entries(c.existing.fields||{}).map(([k,v])=>k+'='+v).join(', '))}</td>
        <td style="font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${eH(Object.entries(c.incoming.fields||{}).map(([k,v])=>k+'='+v).join(', '))}</td>
      </tr>`).join('')}
    </tbody></table>`;
  document.getElementById('importConflictOverlay').classList.add('open');
}

function closeImportConflict() {
  document.getElementById('importConflictOverlay').classList.remove('open');
  _importPending = null;
}

function applyImportResolutions() {
  if (!_importPending) return;
  const resolved = [];
  document.querySelectorAll('.conflict-sel').forEach(sel => {
    const idx = parseInt(sel.dataset.idx, 10);
    const conflict = _importPending.conflicts[idx];
    if (sel.value === 'incoming') {
      resolved.push({ key: conflict.key, mapping: conflict.incoming });
    }
  });
  applyImport(_importPending.added, resolved);
  closeImportConflict();
  rDeveloper();
  showToast(`Import complete: ${_importPending.added.length} added, ${resolved.length} overwritten`);
  _importPending = null;
}

// ── ROUND-TRIP TEST ───────────────────────────────────────────────────────────

async function runRoundTrip() {
  const result = await verifyRoundTrip();
  if (result.ok) {
    showToast('Round-trip verified OK — ' + result.count + ' mappings');
  } else {
    showToast('Round-trip FAILED: ' + result.error);
  }
}
