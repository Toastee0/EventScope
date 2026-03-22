# EventScope — AI Development Context

## What this project is
EventScope is a browser-based DFIR (Digital Forensics & Incident Response) event log analysis tool. It ingests CSV output from Hayabusa and EvtxECmd (Zimmerman Tools) and provides a rich tab-based analysis UI for Windows security event logs. It is designed for air-gapped forensic workstations.

**The four questions every feature must answer:**
1. When did they get in?
2. What did they look at?
3. What did they take and how much?
4. What else did they access?

**Design philosophy:** Speed multiplier for analyst intuition. No autotagging. Ever. Data is evidence.

## Target environment
- Samsung G9 49" ultrawide (5120×1440)
- Windows 11, UTC+0
- Air-gapped — no internet access
- Opened as a local file in browser (file:// protocol)

## Architecture constraints — NON-NEGOTIABLE
- No npm, no bundler, no build step
- No external dependencies (no CDN, no libraries)
- Vanilla JavaScript only — no frameworks
- No network requests of any kind (the only exception: `fetch('es-data/win-security-eids.json')` which is a local file)
- Single deployable unit: index.html + es-*.js + es-data/ — everything must work offline
- Streaming CSV parser: 4MB chunks, yields to event loop via setTimeout(r, 0) between chunks

## File structure
```
index.html              Shell, layout, tab skeleton, CSS (no external styles)
es-core.js              State object S, constants, low-level utilities
es-parsers.js           CSV ingestion, format detection, row processors
es-filters.js           Filter logic, filter cache, DOM reads
es-charts.js            Canvas 2D chart drawing (all charts)
es-views.js             All tab render functions + inline row expansion
es-dedup.js             PLACEHOLDER — Phase 7 (dedup & outlier detection)
es-export.js            Copy-to-clipboard system, column config modal
es-prefs.js             PLACEHOLDER — Phase 5 (preferences load/save)
es-data/
  win-security-eids.json    Windows Security Event ID reference data
archive/                Old monolithic v4 backups (do not touch)
EventScope.html         v4 monolithic predecessor (reference only)
```

Script loading order in index.html (end of body):
es-core.js → es-parsers.js → es-filters.js → es-charts.js → es-views.js → es-dedup.js → es-export.js → es-prefs.js → inline init script

## Internal data model
Every ingested row is normalized to:
```js
{ ts, rule, lvl, comp, chan, eid, rec, det, extra, rid, src, sessionIdx }
```
- `ts` — epoch milliseconds (UTC always; timezone is display-only)
- `lvl` — canonical: 'critical' | 'high' | 'medium' | 'low' | 'informational'
- `det` — raw Details string (¦-delimited key:value pairs)
- `sessionIdx` — which loaded session this row belongs to

## Global state object S (es-core.js)
```js
S = {
  rows[],               // all ingested rows
  filtered,             // cached filtered rows (null = needs rebuild)
  sessions[],           // session metadata
  sessionCurrent,       // active session index
  pivot,                // T-0 pivot timestamp
  pivotWindow,          // window around pivot
  tz,                   // display timezone offset
  tags{},               // event tag overlay (never touches source data)
  ignoreEids(Set),      // suppressed EIDs (filter-only)
  prefs{},              // user preferences
  eidDescs{},           // loaded from win-security-eids.json
  colConfig[],          // column visibility/order config
  hostnameGroups{},     // FQDN vs short name merging
  colIndex{},           // header name → column index map
  columns[],            // parsed header names
  eventIdCounts{}, computerCounts{}, channelCounts{},
  levelCounts{}, ruleTitleCounts{}, ruleIdMap{}, sourceCounts{},
  timeMin, timeMax,     // epoch ms bounds of loaded data
  format,               // 'hayabusa' | 'evtxecmd'
  filters{},            // current filter state
  bucketPref{},         // timeline bucket size preferences
  focusEid,             // EID Focus tab target
  _seqClusters,         // sequence analysis clusters
  nav{ctx, idx, clusterIdx, evtIdx}  // keyboard navigation state
}
```

## Coding conventions
- Global state: always `S`
- Short utility names: `eH` (event handler), `lB` (label), `fDF` (format date), `getFR` (get filtered rows)
- Render functions prefixed `r`: `rOV` (render Overview), `rTL` (render Timeline)
- Complex analytical functions use full names: `runSeq`, `buildLateralGraph`
- Canvas functions: `drawBC` (bar chart), `drawHBC` (horizontal bar chart), `drawSBC` (stacked bar chart)
- HiDPI canvas: always use `sC(el)` helper which applies `devicePixelRatio`
- Filter cache: always call `invF()` to invalidate before re-render, never set `S.filtered` directly

## Three-band timing model
Inter-event interval classification (used in Sequence tab):
- **Scripted** < 500ms — OS internals, automated scripts
- **Fast** 500ms–5s — automated tooling with network latency (THE ANOMALY BAND)
- **Human** > 5s — keyboard operator

The Fast band is the primary anomaly detection zone. Highlight it.

## UI design rules
- Wide scrollable table is the primary view
- Charts/summary ABOVE the table
- Detail panel expands full-width BELOW selected row (not a side panel, not a modal)
- Filter bar collapses to reclaim horizontal space
- No modals. No slide-ins. No popups (except the column config overlay)
- All severity colors from CSS variables: `--crit`, `--high`, `--med`, `--low`, `--info`
- Theme: dark navy `--bg: #050e17`, accent `--orange: #DC551F`
- Font: JetBrains Mono / Fira Code / SF Mono (monospace stack)

## Evidence integrity invariants — NEVER violate
- Source data (`S.rows`) is NEVER modified after ingestion
- Timezone is DISPLAY ONLY — epoch ms is always UTC internally
- Tags are a SEPARATE overlay — never written into row data
- Export = copy of filtered data + annotations appended (source untouched)
- Dedup = view-only grouping (source untouched)
- Ignore list = filter only (source untouched)

## Current status
**Phase 1 — COMPLETE:** Clipboard copy, heatmap calendar, arrivals tracker, gap analysis, time-of-day profiling, periodicity detection.

**Phase 2 — IN PROGRESS:** Network graph (lateral movement), temporal swim lanes, credential spread matrix, source IP correlation.

**Phase 3 — PLANNED:** Bookmarking/annotation, session save/load, narrative timeline export, IOC extraction.

**Phase 4 — PLANNED:** Additional input formats (Velociraptor JSONL, Chainsaw, raw EVTX via WASM).

**Phase 5 — DEFERRED:** Local LLM (Ollama), process baselining, YARA/Sigma visualization.

**es-dedup.js** — 3-line placeholder, Phase 7
**es-prefs.js** — 5-line placeholder, Phase 5

## Known bugs (from v4, check if fixed in v5)
1. Level filter — should be checkbox group (Critical/High/Medium/Low/Informational), not single select — **appears fixed in es-filters.js** (uses getSelectedLevels() with checkbox Set)
2. EvtxECmd field mapping — must detect columns by header name only, never by index — **appears fixed in es-parsers.js** (uses S.colIndex[headerName])

## Key upcoming features (priority order from EVENTSCOPE_V5_TODO.md)
1. Column management (hide/reorder/sort, persisted)
2. Hostname multi-select (merge FQDN vs short name)
3. Vertical Density Timeline — 4 zoom levels, bars extend rightward, severity tints
4. Central Pivot T-0 — user-settable, propagates to all views
5. Event Tagging System — MITRE ATT&CK presets + free-form, overlay only
6. Export IR Report CSV — tagged events by tactic + static reference sheets
7. Ignore List — EID suppression with toggle
8. Dual File Load — Hayabusa + EvtxECmd simultaneously, merge by dedup key
9. Deduplicated Payload Groups — group by EID+Description, outlier flag
10. MFT Timestamps MACB — millisecond clustering, directory blast detection

## What NOT to do
- Do not add any npm packages, bundlers, or build tools
- Do not add any CDN script tags
- Do not add any fetch() calls to external URLs
- Do not use localStorage for anything evidence-related (prefs only, and only with explicit user save action)
- Do not add frameworks (React, Vue, etc.)
- Do not add side panels or modals (except the existing column config overlay)
- Do not autotag or auto-annotate evidence rows
