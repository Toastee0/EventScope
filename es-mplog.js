// es-mplog.js — EventScope v5 — Windows Defender MPLog/DLP parser
// Pure JS port of github.com/Toastee0/mplog_parser
// Parses raw MPLog-*.log and MPDlpLog-*.log files in-browser.
'use strict';

// ── TIMESTAMP REGEX (shared across parsers) ───────────────────────────────────
const _TS = '([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]+Z)';

// FILETIME → ISO string
const _EPOCH_FT = 116444736000000000;
function _ftToISO(ft) {
  const us = (ft - _EPOCH_FT) / 10;
  return new Date(us / 1000).toISOString();
}

// Key:Value block parser (for BM telemetry, resource scan, threat actions)
function _parseBlock(text) {
  const o = {};
  for (const m of text.matchAll(/^([\w -]+):(.+)$/gm)) {
    o[m[1].trim()] = m[2].trim();
  }
  return o;
}

// ── INDIVIDUAL PARSERS ────────────────────────────────────────────────────────

function _parseMiniFilterBlocked(logs) {
  const rx = new RegExp(_TS + '.*\\[Mini-filter\\] Blocked file: (.+) Process: (.+), Status: (.+), State: (.+), ScanRequest (.+), FileId: (.+), Reason: (.+), IoStatusBlockForNewFile: (.+), DesiredAccess:(.+), FileAttributes:(.+), ScanAttributes:(.+), AccessStateFlags:(.+), BackingFileInfo: (.+)', 'g');
  const out = [];
  for (const m of logs.matchAll(rx)) {
    out.push({ timestamp: m[1], type: 'blocked_file', full_path: m[2], process_name: m[3], status: m[4], state: m[5], scan_request: m[6], file_id: m[7], reason: m[8], io_status: m[9], desired_access: m[10], file_attributes: m[11], scan_attributes: m[12], access_state_flags: m[13], backing_file_info: m[14] });
  }
  return out;
}

function _parseMiniFilterUnsuccessful(logs) {
  const rx = new RegExp(_TS + '.*\\[Mini-filter\\] Unsuccessful scan status: (.+) Process: (.+), Status: (.+), State: (.+), ScanRequest (.+), FileId: (.+), Reason: (.+), IoStatusBlockForNewFile: (.+), DesiredAccess:(.+), FileAttributes:(.+), ScanAttributes:(.+), AccessStateFlags:(.+), BackingFileInfo: (.+)', 'g');
  const out = [];
  for (const m of logs.matchAll(rx)) {
    out.push({ timestamp: m[1], type: 'unsuccessful_scan', full_path: m[2], process_name: m[3], status: m[4], state: m[5], scan_request: m[6], file_id: m[7], reason: m[8], io_status: m[9], desired_access: m[10], file_attributes: m[11], scan_attributes: m[12], access_state_flags: m[13], backing_file_info: m[14] });
  }
  return out;
}

function _parseExclusions(logs) {
  const rx = new RegExp(_TS + ' \\[Exclusion\\] (.+) -> (.+)', 'g');
  const out = [];
  for (const m of logs.matchAll(rx)) {
    out.push({ timestamp: m[1], type: 'exclusion', path_drive: m[2], path_device: m[3] });
  }
  return out;
}

function _parseLowfi(logs) {
  const rx = new RegExp(_TS + '.*lowfi: (.+)', 'gi');
  const out = [];
  for (const m of logs.matchAll(rx)) {
    out.push({ timestamp: m[1], type: 'lowfi', command_line: m[2] });
  }
  return out;
}

function _parseDetectionAdd(logs) {
  const rx = new RegExp(_TS + '.*(DETECTION_ADD(?:#2)?) (.*)', 'g');
  const out = [];
  for (const m of logs.matchAll(rx)) {
    out.push({ timestamp: m[1], type: 'detection_add', subtype: m[2], command_line: m[3] });
  }
  return out;
}

function _parseThreatCommandLine(logs) {
  const rx = new RegExp(_TS + '.*threat: (.+)', 'gi');
  const out = [];
  for (const m of logs.matchAll(rx)) {
    out.push({ timestamp: m[1], type: 'threat_cmdline', command_line: m[2] });
  }
  return out;
}

function _parseDetectionEvent(logs) {
  const rx = new RegExp(_TS + '.*DETECTIONEVENT MPSOURCE_SYSTEM (.*)', 'g');
  const out = [];
  for (const m of logs.matchAll(rx)) {
    out.push({ timestamp: m[1], type: 'detection_event', command_line: m[2] });
  }
  return out;
}

function _parseOriginalFilename(logs) {
  const rx = new RegExp(_TS + '.*original file name "(.*)" for "(.*)", hr=(\\w*)', 'gi');
  const out = [];
  for (const m of logs.matchAll(rx)) {
    out.push({ timestamp: m[1], type: 'original_filename', original_filename: m[2], full_path: m[3], hr: m[4] });
  }
  return out;
}

function _parseEMS(logs) {
  const rx = new RegExp(_TS + '.*process: (\\w*) pid: (\\d*), sigseq: (\\w*), sendMemoryScanReport: (\\d*), source: (\\d*)', 'gi');
  const out = [];
  for (const m of logs.matchAll(rx)) {
    out.push({ timestamp: m[1], type: 'ems', process: m[2], pid: m[3], sigseq: m[4], send_memory_scan_report: m[5], source: m[6] });
  }
  return out;
}

function _parseProcessImageName(logs) {
  const rx = new RegExp(_TS + ' ProcessImageName: (.*), Pid: (\\d*), TotalTime: (\\d*), Count: (\\d*), MaxTime: (\\d*), MaxTimeFile: (.*), EstimatedImpact: (.*)', 'g');
  const out = [];
  for (const m of logs.matchAll(rx)) {
    out.push({ timestamp: m[1], type: 'process_image', process_image_name: m[2], pid: m[3], total_time: m[4], count: m[5], max_time: m[6], max_time_file: m[7], estimated_impact: m[8] });
  }
  return out;
}

function _parseBMTelemetry(logs) {
  const rx = /BEGIN BM telemetry(?:.*\n)+?END BM telemetry/g;
  const out = [];
  for (const block of logs.matchAll(rx)) {
    const raw = _parseBlock(block[0]);
    let ts = '';
    try { ts = _ftToISO(parseInt(raw.ProcessCreationTime || '0', 10)); } catch(e) {}
    out.push({
      timestamp: ts, type: 'bm_telemetry',
      guid: raw.GUID || '', process_creation_time: raw.ProcessCreationTime || '',
      signature_id: raw.SignatureID || '', signature_sha1: raw.SigSha || '',
      pid: raw.ProcessID || '', session_id: raw.SessionID || '',
      creation_time: raw.CreationTime || '', image_path: raw.ImagePath || '',
      taint_info: raw['Taint Info'] || '', operations: raw.Operations || '',
      telemetry_name: raw.TelemetryName || '', target_filename: raw.TargetFileName || ''
    });
  }
  return out;
}

function _parseResourceScan(logs) {
  const rx = /Begin Resource Scan(?:.*\n)+?End Scan/g;
  const out = [];
  for (const block of logs.matchAll(rx)) {
    const raw = _parseBlock(block[0]);
    out.push({
      timestamp: raw['Start Time'] || '', type: 'resource_scan',
      scan_id: raw['Scan ID'] || '', scan_source: raw['Scan Source'] || '',
      start_time: raw['Start Time'] || '', end_time: raw['End Time'] || '',
      resource_schema: raw['Resource Schema'] || '', resource_path: raw['Resource Path'] || '',
      result_count: raw['Result Count'] || '', threat_name: raw['Threat Name'] || '',
      id: raw.ID || '', severity: raw.Severity || '',
      number_of_resources: raw['Number of Resources'] || '',
      sigseq: raw['Extended Info - SigSeq'] || '', sigsha: raw['Extended Info - SigSha'] || ''
    });
  }
  return out;
}

function _parseThreatActions(logs) {
  const rx = /Beginning threat actions(?:.*\n)+?Finished threat actions/g;
  const out = [];
  for (const block of logs.matchAll(rx)) {
    const raw = _parseBlock(block[0]);
    out.push({
      timestamp: raw['Start time'] || '', type: 'threat_action',
      threat_name: raw['Threat Name'] || '', threat_id: raw['Threat ID'] || '',
      action: raw.Action || '', path: raw.Path || '',
      schema: raw.Schema || '', result: raw.Result || '',
      threat_result: raw['Threat result'] || '',
      threat_status_flags: raw['Threat status flags'] || '',
      effective_removal_policy: raw['Threat Effective RemovalPolicy'] || ''
    });
  }
  return out;
}

function _parseRTPPerf(logs) {
  const rx = /\*{28}RTP Perf Log\*{27}(?:.*\n)+?\*{26}END RTP Perf Log\*{25}/g;
  const out = [];
  for (const block of logs.matchAll(rx)) {
    const inner = /RTP Start:(.*)\nLast Perf:(.*)\nFirst RTP Scan:(.*)\nPlugin States:(.*)\n/s;
    const m = block[0].match(inner);
    const procEx = [...block[0].matchAll(/Process Exclusions:\n((?:\s+.*\n)*)/g)].map(x => x[1].trim().split(/\n/).map(l => l.trim()).filter(Boolean));
    const pathEx = [...block[0].matchAll(/Path Exclusions:\n((?:\s+.*\n)*)/g)].map(x => x[1].trim().split(/\n/).map(l => l.trim()).filter(Boolean));
    const extEx  = [...block[0].matchAll(/Ext Exclusions:\n((?:\s+.*\n)*)/g)].map(x => x[1].trim().split(/\n/).map(l => l.trim()).filter(Boolean));
    out.push({
      type: 'rtp_perf',
      rtp_start: m ? m[1].trim() : '', last_perf: m ? m[2].trim() : '',
      first_rtp_scan: m ? m[3].trim() : '', plugin_states: m ? m[4].trim() : '',
      process_exclusions: procEx.flat(), path_exclusions: pathEx.flat(), extension_exclusions: extEx.flat()
    });
  }
  return out;
}

function _parseDLP(logs) {
  const rx = new RegExp(_TS + ' \\[DLP\\] DLP Notification:\\n\\tPolicy Version: \\|?(.+),\\n\\tRule Id: \\|?(.+),\\n\\tEnforcement Level: (.+),\\n\\tAction Type: (.+),\\n\\tProcess Name: (.+),\\n\\tProcess ID: (.+),\\n\\tUser SID: (.+),\\n\\tSource: \\|?(.+),\\n\\tTarget: (.+),\\n\\tSession ID: (.+),\\n\\tAudit Reason: (.+),\\n\\tFilterElapsedMs: (.+),\\n\\tEventElapsedMs: (.+),\\n\\tSenseElapsedMs: (.+),\\n\\tToastElapsedMs: (.+),\\n\\tTotalMs: (.+),\\n\\tToastType: (.+)', 'g');
  const out = [];
  for (const m of logs.matchAll(rx)) {
    out.push({
      timestamp: m[1], type: 'dlp',
      policy_version: m[2].trim(), rule_id: m[3].trim(),
      enforcement_level: m[4].trim(), action_type: m[5].trim(),
      process_name: m[6].trim(), process_id: m[7].trim(),
      user_sid: m[8].trim(), source: m[9].trim(), target: m[10].trim(),
      session_id: m[11].trim(), audit_reason: m[12].trim(),
      filter_elapsed_ms: m[13].trim(), event_elapsed_ms: m[14].trim(),
      sense_elapsed_ms: m[15].trim(), toast_elapsed_ms: m[16].trim(),
      total_ms: m[17].trim(), toast_type: m[18].trim()
    });
  }
  return out;
}

// ── MAIN ENTRY POINT ──────────────────────────────────────────────────────────

function parseMPLog(text) {
  // Normalize line endings
  const logs = text.replace(/\r\n/g, '\n');

  const results = [
    ..._parseMiniFilterBlocked(logs),
    ..._parseMiniFilterUnsuccessful(logs),
    ..._parseExclusions(logs),
    ..._parseLowfi(logs),
    ..._parseDetectionAdd(logs),
    ..._parseThreatCommandLine(logs),
    ..._parseDetectionEvent(logs),
    ..._parseOriginalFilename(logs),
    ..._parseEMS(logs),
    ..._parseProcessImageName(logs),
    ..._parseBMTelemetry(logs),
    ..._parseResourceScan(logs),
    ..._parseThreatActions(logs),
    ..._parseRTPPerf(logs),
    ..._parseDLP(logs),
  ];

  // Sort by timestamp
  results.sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
  return results;
}

// ── FILE LOADER (for case folder integration) ─────────────────────────────────

async function loadMPLogFile(file) {
  let text;
  try {
    // MPLog files are typically UTF-16
    text = await file.text();
  } catch(e) {
    console.warn('[mplog] failed to read', file.name, e);
    return;
  }

  const results = parseMPLog(text);
  if (!results.length) return;

  // Store in S.artifacts
  if (!S.artifacts) S.artifacts = [];
  S.artifacts.push({
    type: 'mplog',
    file: file.name,
    events: results,
    count: results.length,
    // Summary counts by type
    summary: results.reduce((acc, r) => { acc[r.type] = (acc[r.type] || 0) + 1; return acc; }, {})
  });

  showToast('Parsed ' + results.length + ' Defender events from ' + file.name);
}
