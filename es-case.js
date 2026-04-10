// es-case.js — EventScope v5 — Case Folder management
// Handles opening a case folder (webkitdirectory), reading/writing case.json,
// auto-loading files per manifest, and companion-file detection.
'use strict';

// ── CASE STATE ────────────────────────────────────────────────────────────────

// Populated when user opens a folder via webkitdirectory input.
// Maps relative filename → File object for every file in the selected folder.
let _caseFiles = null;   // Map<string, File> | null
let _caseMeta  = null;   // Parsed case.json contents | null
let _caseFolderName = '';
let _caseLoading = false; // true while manifest-driven load is in progress

// ── OPEN CASE FOLDER ──────────────────────────────────────────────────────────

async function openCaseFolder(fileList) {
  // Build a map of relative-filename → File from the webkitdirectory result.
  // webkitRelativePath looks like "FolderName/file.csv"
  _caseFiles = new Map();
  _caseFolderName = '';
  _caseMeta = null;

  for (const f of fileList) {
    const rel = f.webkitRelativePath || f.name;
    // Strip the top-level folder prefix to get the filename
    const parts = rel.split('/');
    if (parts.length > 1 && !_caseFolderName) _caseFolderName = parts[0];
    const key = parts.length > 1 ? parts.slice(1).join('/') : parts[0];
    _caseFiles.set(key, f);
  }

  // Look for case.json
  const caseFile = _caseFiles.get('case.json') || _caseFiles.get('Case.json');
  if (caseFile) {
    try {
      const text = await caseFile.text();
      _caseMeta = JSON.parse(text);
      await _loadFromManifest();
      return;
    } catch (e) {
      showToast('case.json parse error: ' + e.message);
    }
  }

  // No case.json — scan for CSVs and show the case setup panel
  _showCaseSetup();
}

// ── LOAD FROM MANIFEST ────────────────────────────────────────────────────────

async function _loadFromManifest() {
  if (!_caseMeta || !_caseMeta.machines || !_caseMeta.machines.length) {
    showToast('case.json has no machines defined');
    return;
  }

  // Gather all files in order: machine 0 first file, machine 0 second file, etc.
  const loadQueue = [];
  for (const machine of _caseMeta.machines) {
    for (const fname of (machine.files || [])) {
      const file = _caseFiles.get(fname);
      if (file) {
        loadQueue.push({ file, hostname: machine.hostname || '', machineIdx: machine.index });
      } else {
        showToast('Missing file: ' + fname);
      }
    }
  }

  if (!loadQueue.length) {
    showToast('No matching files found in case folder');
    return;
  }

  _caseLoading = true;

  // Load first file as primary
  await loadF(loadQueue[0].file);

  // Load remaining as additional sessions
  for (let i = 1; i < loadQueue.length; i++) {
    await loadAdditionalSession(loadQueue[i].file);
  }

  _caseLoading = false;
  showToast('Case loaded: ' + (_caseMeta.caseName || _caseFolderName) + ' — ' + loadQueue.length + ' file(s)');
}

// ── CASE SETUP PANEL (no case.json found) ─────────────────────────────────────

function _showCaseSetup() {
  // Find all CSV/TSV files
  const csvFiles = [];
  for (const [name, file] of _caseFiles) {
    if (/\.(csv|tsv|txt)$/i.test(name)) csvFiles.push({ name, file });
  }

  if (!csvFiles.length) {
    showToast('No CSV files found in folder');
    return;
  }

  csvFiles.sort((a, b) => a.name.localeCompare(b.name));

  const overlay = document.getElementById('caseSetupOverlay');
  const body = document.getElementById('caseSetupBody');
  const nameInput = document.getElementById('caseNameInput');
  nameInput.value = _caseFolderName || '';

  body.innerHTML = csvFiles.map((f, i) => {
    return `<div class="case-file-row" data-idx="${i}">
      <label class="case-file-check">
        <input type="checkbox" checked data-file="${eH(f.name)}">
        <span class="case-file-name">${eH(f.name)}</span>
        <span class="case-file-size">${(f.file.size / 1024 / 1024).toFixed(1)} MB</span>
      </label>
      <input type="text" class="case-host-input" placeholder="hostname (auto-detect)" data-file="${eH(f.name)}">
    </div>`;
  }).join('');

  overlay.style.display = 'flex';
}

function closeCaseSetup() {
  document.getElementById('caseSetupOverlay').style.display = 'none';
}

async function applyCaseSetup() {
  const overlay = document.getElementById('caseSetupOverlay');
  const caseName = (document.getElementById('caseNameInput').value || '').trim() || _caseFolderName || 'Untitled';
  const checks = overlay.querySelectorAll('input[type="checkbox"]:checked');

  if (!checks.length) {
    showToast('No files selected');
    return;
  }

  // Gather selected files in DOM order
  const selected = [];
  for (const cb of checks) {
    const fname = cb.dataset.file;
    const hostInput = overlay.querySelector(`.case-host-input[data-file="${fname}"]`);
    const hostname = hostInput ? hostInput.value.trim() : '';
    const file = _caseFiles.get(fname);
    if (file) selected.push({ name: fname, file, hostname });
  }

  overlay.style.display = 'none';
  _caseLoading = true;

  // Load first file as primary
  await loadF(selected[0].file);

  // Load rest as additional sessions
  for (let i = 1; i < selected.length; i++) {
    await loadAdditionalSession(selected[i].file);
  }

  _caseLoading = false;
  // Build case metadata for later save
  _caseMeta = _buildCaseMeta(caseName);
  showToast('Loaded ' + selected.length + ' file(s) from ' + caseName);
}

// ── COMPANION FILE DETECTION ──────────────────────────────────────────────────
// After a single-file load via the case folder, check if there are other CSVs
// in the folder that look like they belong to the same host and offer to load.

function checkCompanionFiles() {
  if (_caseLoading) return;
  if (!_caseFiles || _caseFiles.size === 0) return;
  if (!S.sessions.length) return;

  const loaded = new Set();
  // Collect filenames that are already loaded (match by filename suffix)
  for (const sess of S.sessions) {
    if (sess.label) loaded.add(sess.label);
  }

  const companions = [];
  for (const [name] of _caseFiles) {
    if (!/\.(csv|tsv|txt)$/i.test(name)) continue;
    const label = name.replace(/\.[^.]+$/, '');
    if (loaded.has(label)) continue;
    companions.push(name);
  }

  if (!companions.length) return;

  // Show a toast-like prompt for companion files
  _showCompanionOffer(companions);
}

function _showCompanionOffer(files) {
  const bar = document.getElementById('companionBar');
  if (!bar) return;

  bar.innerHTML = `<span style="margin-right:10px">Other files in case folder:</span>` +
    files.map((f, i) => `<button class="companion-btn" data-companion="${eH(f)}">${eH(f)}</button>`).join('') +
    `<button class="companion-btn companion-load-all" data-companion-all>Load all</button>` +
    `<button class="companion-dismiss" onclick="dismissCompanions()" title="Dismiss">\u2715</button>`;
  bar.querySelectorAll('[data-companion]').forEach(btn =>
    btn.addEventListener('click', () => loadCompanion(btn.dataset.companion))
  );
  bar.querySelector('[data-companion-all]').addEventListener('click', loadAllCompanions);
  bar.style.display = 'flex';
}

async function loadCompanion(fname) {
  const file = _caseFiles ? _caseFiles.get(fname) : null;
  if (!file) { showToast('File not found: ' + fname); return; }
  await loadAdditionalSession(file);
  // Remove this button
  const bar = document.getElementById('companionBar');
  if (bar) {
    const btn = bar.querySelector(`[data-companion="${CSS.escape(fname)}"]`);
    if (btn) btn.remove();
    // If no more companion buttons, hide bar
    if (!bar.querySelector('.companion-btn:not(.companion-load-all)')) bar.style.display = 'none';
  }
}

async function loadAllCompanions() {
  if (!_caseFiles) return;
  const loaded = new Set();
  for (const sess of S.sessions) {
    if (sess.label) loaded.add(sess.label);
  }
  for (const [name, file] of _caseFiles) {
    if (!/\.(csv|tsv|txt)$/i.test(name)) continue;
    const label = name.replace(/\.[^.]+$/, '');
    if (loaded.has(label)) continue;
    await loadAdditionalSession(file);
  }
  dismissCompanions();
}

function dismissCompanions() {
  const bar = document.getElementById('companionBar');
  if (bar) bar.style.display = 'none';
}

// ── SAVE CASE ─────────────────────────────────────────────────────────────────

function _buildCaseMeta(caseName) {
  // Group sessions by primaryHost → machine
  const machines = [];
  const hostMap = new Map();
  for (const sess of S.sessions) {
    const host = sess.primaryHost || sess.label;
    if (!hostMap.has(host)) {
      hostMap.set(host, { index: machines.length, hostname: host, files: [] });
      machines.push(hostMap.get(host));
    }
    const m = hostMap.get(host);
    // Try to find original filename — label is filename without extension
    const fname = sess.label + '.csv';
    if (!m.files.includes(fname)) m.files.push(fname);
  }
  return { caseName: caseName || _caseFolderName || 'Untitled', machines };
}

function saveCaseJson() {
  const meta = _caseMeta || _buildCaseMeta(_caseFolderName);
  const json = JSON.stringify(meta, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'case.json';
  a.click();
  URL.revokeObjectURL(url);
  showToast('case.json downloaded — place it in your case folder');
}
