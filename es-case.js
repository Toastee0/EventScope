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

// Extensions worth indexing — everything else is ignored during folder scan
const _CASE_EXTS = /\.(csv|tsv|txt|json|jsonl|log|xml)$/i;
// Paths to always skip even if extension matches (massive dirs, no forensic value)
const _CASE_SKIP = /[/\\](Windows[/\\]WinSxS|Windows[/\\]assembly|Windows[/\\]servicing|Windows[/\\]Installer|Windows[/\\]SoftwareDistribution|\$Recycle\.Bin|System Volume Information)[/\\]/i;

async function openCaseFolder(fileList) {
  // Build a map of relative-filename → File from the webkitdirectory result.
  // Only index files with forensically useful extensions to avoid choking on
  // full filesystem mirrors with hundreds of thousands of files.
  _caseFiles = new Map();
  _caseFolderName = '';
  _caseMeta = null;
  let skipped = 0;

  for (const f of fileList) {
    const rel = f.webkitRelativePath || f.name;
    const parts = rel.split('/');
    if (parts.length > 1 && !_caseFolderName) _caseFolderName = parts[0];
    const key = parts.length > 1 ? parts.slice(1).join('/') : parts[0];

    // Always index case.json
    if (/^case\.json$/i.test(key.split('/').pop())) {
      _caseFiles.set(key, f);
      continue;
    }

    // Skip files in known junk directories
    if (_CASE_SKIP.test(key)) { skipped++; continue; }

    // Only index files with useful extensions
    if (!_CASE_EXTS.test(key)) { skipped++; continue; }

    // Skip very deeply nested files (>8 levels deep = likely OS noise)
    if (key.split('/').length > 8) { skipped++; continue; }

    _caseFiles.set(key, f);
  }

  if (skipped > 0) {
    console.debug(`[case] indexed ${_caseFiles.size} files, skipped ${skipped.toLocaleString()} irrelevant files`);
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

  const progContainer = document.getElementById('progressContainer');
  const progFill = document.getElementById('progressFill');
  const progText = document.getElementById('progressText');
  if (progContainer) progContainer.style.display = '';
  if (progFill) progFill.style.width = '0%';
  const total = loadQueue.length;

  // Load first file as primary
  if (progText) progText.textContent = `Loading ${loadQueue[0].file.name} (1/${total})...`;
  await loadF(loadQueue[0].file);
  if (progFill) progFill.style.width = (1 / total * 100) + '%';

  // Load remaining as additional sessions
  for (let i = 1; i < loadQueue.length; i++) {
    await new Promise(r => setTimeout(r, 0)); // yield to UI
    if (progText) progText.textContent = `Loading ${loadQueue[i].file.name} (${i+1}/${total})...`;
    await loadAdditionalSession(loadQueue[i].file);
    if (progFill) progFill.style.width = ((i+1) / total * 100) + '%';
  }

  if (progContainer) progContainer.style.display = 'none';

  _caseLoading = false;
  showToast('Case loaded: ' + (_caseMeta.caseName || _caseFolderName) + ' — ' + total + ' file(s)');
}

// ── ARTIFACT REGISTRY ─────────────────────────────────────────────────────────
// Known artifact path patterns from Cypfer triage output + standard tool CSVs.
// Each entry: regex on relative path → { category, label, parser, priority }
// Priority: lower = load first. Parser: how to ingest (evtx/hayabusa handled by
// streamParse; others will be custom parsers or text loaders).

const ARTIFACT_PATTERNS = [
  // ── Event Logs (primary) ──
  { rx: /Hayabusa[^/]*\.csv$/i,                        cat: 'events',     label: 'Hayabusa timeline',      parser: 'hayabusa',    pri: 1, auto: true },
  { rx: /_EVTX_[^/]*\.csv$/i,                          cat: 'events',     label: 'EvtxECmd all-events',    parser: 'evtxecmd',    pri: 2, auto: true },

  // ── Script Execution ──
  { rx: /ConsoleHost_history\.txt$/i,                   cat: 'scripts',    label: 'PowerShell history',     parser: 'console_history', pri: 10, auto: true },
  { rx: /PSScriptBlocks\//i,                            cat: 'scripts',    label: 'PS ScriptBlock (Takajo)', parser: 'scriptblock',   pri: 11, auto: true },
  { rx: /Hayabusa-extract-base64\.csv$/i,               cat: 'scripts',    label: 'Base64 extraction',      parser: 'csv_generic',   pri: 12, auto: true },

  // ── Execution Evidence ──
  { rx: /Shimcache[^/]*\.csv$/i,                        cat: 'execution',  label: 'Shimcache / AppCompat',  parser: 'csv_generic',   pri: 20, auto: true },
  { rx: /Amcache[^/]*\.csv$/i,                          cat: 'execution',  label: 'Amcache',                parser: 'csv_generic',   pri: 21, auto: true },

  // ── Network ──
  { rx: /network-adapters\.csv$/i,                      cat: 'network',    label: 'Network adapters',       parser: 'netconfig',     pri: 30, auto: true },
  { rx: /network-profiles\.csv$/i,                      cat: 'network',    label: 'Network profiles',       parser: 'netconfig',     pri: 31, auto: true },
  { rx: /SrumECmd[^/]*NetworkUsages?\.csv$/i,           cat: 'network',    label: 'SRUM network usage',     parser: 'srum',          pri: 32, auto: true },
  { rx: /SrumECmd[^/]*\.csv$/i,                         cat: 'network',    label: 'SRUM data',              parser: 'srum',          pri: 33, auto: false },

  // ── Registry ──
  { rx: /\.rr3\.txt$/i,                                 cat: 'registry',   label: 'RegRipper output',       parser: 'text_artifact', pri: 40, auto: false },
  { rx: /\.recmd\.csv$/i,                               cat: 'registry',   label: 'RECmd CSV',              parser: 'csv_generic',   pri: 41, auto: false },
  { rx: /\.sbecmd\.csv$/i,                              cat: 'registry',   label: 'ShellBags',              parser: 'csv_generic',   pri: 42, auto: false },
  { rx: /services\.rr3\.csv$/i,                         cat: 'registry',   label: 'Services (RegRipper)',   parser: 'csv_generic',   pri: 43, auto: true },

  // ── File System ──
  { rx: /MFTECmd[^/]*MFT[^/]*\.csv$/i,                 cat: 'filesystem', label: 'MFT parsed',             parser: 'csv_generic',   pri: 50, auto: false },
  { rx: /MFTECmd[^/]*J[^/]*\.csv$/i,                   cat: 'filesystem', label: 'USN Journal',            parser: 'csv_generic',   pri: 51, auto: false },

  // ── Endpoint Protection ──
  { rx: /MPLog[^/]*\.log$/i,                            cat: 'protection', label: 'Defender MPLog (raw)',   parser: 'mplog',         pri: 59, auto: true },
  { rx: /MPDlpLog[^/]*\.log$/i,                         cat: 'protection', label: 'Defender DLP Log (raw)', parser: 'mplog',         pri: 59, auto: true },
  { rx: /Windows Defender[/\\]Support[/\\]MPLog/i,      cat: 'protection', label: 'Defender MPLog (image)', parser: 'mplog',         pri: 59, auto: true },
  { rx: /Windows Defender[/\\]Support[/\\]MPDlpLog/i,   cat: 'protection', label: 'Defender DLP (image)',   parser: 'mplog',         pri: 59, auto: true },
  { rx: /MPLog[^/]*\.csv$/i,                            cat: 'protection', label: 'Defender MPLog (CSV)',   parser: 'csv_generic',   pri: 60, auto: true },

  // ── Hayabusa extras ──
  { rx: /Hayabusa-logon-summary/i,                      cat: 'events',     label: 'Hayabusa logon summary', parser: 'csv_generic',   pri: 70, auto: false },
  { rx: /Hayabusa-computer-metrics\.csv$/i,             cat: 'events',     label: 'Hayabusa host metrics',  parser: 'csv_generic',   pri: 71, auto: false },

  // ── Chainsaw ──
  { rx: /chainsaw[^/]*\.csv$/i,                         cat: 'events',     label: 'Chainsaw detections',    parser: 'csv_generic',   pri: 72, auto: false },

  // ── Other ──
  { rx: /SumECmd[^/]*\.csv$/i,                          cat: 'other',      label: 'SUM (User Access)',      parser: 'csv_generic',   pri: 80, auto: false },
  { rx: /WMI-PersistenceFinder\.txt$/i,                 cat: 'other',      label: 'WMI Persistence',        parser: 'text_artifact', pri: 81, auto: true },
];

// Category display metadata
const ARTIFACT_CATS = {
  events:     { label: 'Event Logs',          icon: '\u26A1', color: 'var(--orange)' },
  scripts:    { label: 'Script Execution',    icon: '\u25B6', color: 'var(--high)' },
  execution:  { label: 'Execution Evidence',  icon: '\u2699', color: 'var(--med)' },
  network:    { label: 'Network',             icon: '\u21C4', color: 'var(--info)' },
  registry:   { label: 'Registry',            icon: '\u2263', color: 'var(--low)' },
  filesystem: { label: 'File System',         icon: '\u2637', color: 'var(--text-dim)' },
  protection: { label: 'Endpoint Protection', icon: '\u2691', color: 'var(--success)' },
  other:      { label: 'Other Artifacts',     icon: '\u2022', color: 'var(--text-dim)' },
  unknown:    { label: 'Unrecognized Files',  icon: '?',      color: 'var(--text-dim)' },
};

// Scan case files and classify each one
function _discoverArtifacts() {
  const found = [];
  const matched = new Set();

  for (const [path, file] of _caseFiles) {
    let hit = null;
    for (const pat of ARTIFACT_PATTERNS) {
      if (pat.rx.test(path)) {
        hit = pat;
        break;
      }
    }
    if (hit) {
      found.push({ path, file, cat: hit.cat, label: hit.label, parser: hit.parser, pri: hit.pri, auto: hit.auto });
      matched.add(path);
    } else if (/\.(csv|tsv|txt|json|jsonl|log)$/i.test(path)) {
      found.push({ path, file, cat: 'unknown', label: path.split('/').pop(), parser: 'csv_generic', pri: 99, auto: false });
    }
  }

  found.sort((a, b) => a.pri - b.pri || a.path.localeCompare(b.path));
  return found;
}

// ── CASE SETUP PANEL (no case.json found) ─────────────────────────────────────

function _showCaseSetup() {
  const artifacts = _discoverArtifacts();

  if (!artifacts.length) {
    showToast('No recognizable artifact files found in folder');
    return;
  }

  const overlay = document.getElementById('caseSetupOverlay');
  const body = document.getElementById('caseSetupBody');
  const nameInput = document.getElementById('caseNameInput');
  nameInput.value = _caseFolderName || '';

  // Group by category
  const groups = new Map();
  for (const a of artifacts) {
    if (!groups.has(a.cat)) groups.set(a.cat, []);
    groups.get(a.cat).push(a);
  }

  // Render grouped artifact list
  const catOrder = ['events','scripts','execution','network','registry','filesystem','protection','other','unknown'];
  body.innerHTML = catOrder.filter(c => groups.has(c)).map(cat => {
    const items = groups.get(cat);
    const meta = ARTIFACT_CATS[cat] || ARTIFACT_CATS.unknown;
    const autoCount = items.filter(a => a.auto).length;
    return `<div style="margin-bottom:4px">
      <div style="padding:8px 12px;background:var(--surface2);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px">
        <span style="font-size:14px">${meta.icon}</span>
        <span style="font-family:var(--mono);font-size:12px;font-weight:600;color:${meta.color}">${meta.label}</span>
        <span style="font-family:var(--mono);font-size:10px;color:var(--text-dim)">${items.length} file${items.length===1?'':'s'}${autoCount ? ', '+autoCount+' auto-selected' : ''}</span>
      </div>
      ${items.map(a => `<div class="case-file-row">
        <label class="case-file-check">
          <input type="checkbox" ${a.auto?'checked':''} data-file="${eH(a.path)}" data-parser="${a.parser}">
          <span class="case-file-name" title="${eH(a.path)}">${eH(a.label)}</span>
          <span style="font-family:var(--mono);font-size:10px;color:var(--text-dim);max-width:300px;overflow:hidden;text-overflow:ellipsis" title="${eH(a.path)}">${eH(a.path)}</span>
          <span class="case-file-size">${(a.file.size / 1024 / 1024).toFixed(1)} MB</span>
        </label>
      </div>`).join('')}
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

  // Gather selected files in DOM order, grouped by parser type
  const evtFiles = [];   // hayabusa/evtxecmd → streamParse
  const auxFiles = [];   // everything else → auxiliary loaders
  for (const cb of checks) {
    const fname = cb.dataset.file;
    const parser = cb.dataset.parser || 'csv_generic';
    const file = _caseFiles.get(fname);
    if (!file) continue;
    if (parser === 'hayabusa' || parser === 'evtxecmd') {
      evtFiles.push({ name: fname, file, parser });
    } else {
      auxFiles.push({ name: fname, file, parser });
    }
  }

  overlay.style.display = 'none';
  _caseLoading = true;

  const allFiles = [...evtFiles.map(f => ({...f, isEvt: true})), ...auxFiles.map(f => ({...f, isEvt: false}))];
  const total = allFiles.length;

  // Show progress bar
  const progContainer = document.getElementById('progressContainer');
  const progFill = document.getElementById('progressFill');
  const progText = document.getElementById('progressText');
  if (progContainer) progContainer.style.display = '';
  if (progFill) progFill.style.width = '0%';

  // Load event log CSVs first (primary ingest pipeline)
  let loaded = 0;
  if (evtFiles.length) {
    if (progText) progText.textContent = `Loading ${evtFiles[0].name.split('/').pop()}...`;
    await loadF(evtFiles[0].file);
    loaded++;
    if (progFill) progFill.style.width = (loaded / total * 100) + '%';
    for (let i = 1; i < evtFiles.length; i++) {
      await new Promise(r => setTimeout(r, 0)); // yield to UI
      if (progText) progText.textContent = `Loading ${evtFiles[i].name.split('/').pop()} (${loaded+1}/${total})...`;
      await loadAdditionalSession(evtFiles[i].file);
      loaded++;
      if (progFill) progFill.style.width = (loaded / total * 100) + '%';
    }
  }

  // Load auxiliary artifacts via their specific loaders
  for (const aux of auxFiles) {
    await new Promise(r => setTimeout(r, 0)); // yield to UI
    loaded++;
    if (progText) progText.textContent = `Loading ${aux.name.split('/').pop()} (${loaded}/${total})...`;
    if (progFill) progFill.style.width = (loaded / total * 100) + '%';
    await _loadAuxArtifact(aux);
  }

  if (progContainer) progContainer.style.display = 'none';

  _caseLoading = false;
  const totalLoaded = total;
  // Build case metadata for later save
  _caseMeta = _buildCaseMeta(caseName);
  showToast('Loaded ' + totalLoaded + ' artifact(s) from ' + caseName);
}

// ── AUXILIARY ARTIFACT LOADERS ────────────────────────────────────────────────
// Each parser type gets a handler. For now, netconfig and srum use existing
// loaders; console_history gets a new text parser; csv_generic and text_artifact
// are stored as supplemental data for the Developer tab / future views.

// Supplemental artifacts store — non-event data loaded from triage
if (!S.artifacts) S.artifacts = [];

async function _loadAuxArtifact(aux) {
  try {
    switch (aux.parser) {
      case 'netconfig':
        if (typeof loadNetconfigFile === 'function') await loadNetconfigFile(aux.file);
        break;
      case 'srum':
        if (typeof loadSrumFile === 'function') await loadSrumFile(aux.file);
        break;
      case 'mplog':
        if (typeof loadMPLogFile === 'function') await loadMPLogFile(aux.file);
        break;
      case 'console_history':
        await _loadConsoleHistory(aux);
        break;
      case 'scriptblock':
        await _loadTextArtifact(aux, 'scripts');
        break;
      case 'text_artifact':
        await _loadTextArtifact(aux, 'text');
        break;
      case 'csv_generic':
        await _loadGenericCsv(aux);
        break;
      default:
        console.debug('[case] no loader for parser:', aux.parser, aux.name);
    }
  } catch (e) {
    console.warn('[case] failed to load', aux.name, e);
  }
}

// Parse ConsoleHost_history.txt — each line is a command, no timestamps.
// Extract the username from the filename pattern: <user>.ConsoleHost_history.txt
async function _loadConsoleHistory(aux) {
  const text = await aux.file.text();
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (!lines.length) return;

  // Extract username from filename
  const fname = aux.name.split('/').pop();
  const user = fname.replace(/\.?ConsoleHost_history\.txt$/i, '') || 'unknown';

  S.artifacts.push({
    type: 'console_history',
    user,
    file: fname,
    lines,
    count: lines.length
  });
  showToast('Loaded ' + lines.length + ' PS commands for ' + user);
}

async function _loadTextArtifact(aux, subtype) {
  const text = await aux.file.text();
  const fname = aux.name.split('/').pop();
  S.artifacts.push({
    type: subtype || 'text',
    file: fname,
    path: aux.name,
    content: text,
    size: aux.file.size
  });
}

async function _loadGenericCsv(aux) {
  const text = await aux.file.text();
  const fname = aux.name.split('/').pop();
  // Parse header + first N rows for preview
  const lines = text.split(/\r?\n/);
  const header = lines[0] ? lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, '')) : [];
  const rowCount = lines.filter(l => l.trim()).length - 1;

  S.artifacts.push({
    type: 'csv',
    file: fname,
    path: aux.name,
    header,
    rowCount,
    rawText: text,
    size: aux.file.size
  });
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
