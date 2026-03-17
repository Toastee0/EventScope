# EventScope — Development Plan

**Author:** Adrian Neill  
**Repo:** `https://github.com/Toastee0/EventScope` (private)  
**Status:** Active development — single-file browser tool for DFIR event log analysis  
**Last updated:** 2026-03-17  
**Phase 1 complete.** Phase 2 in progress.

---

## Design Philosophy

EventScope is two things: a **best-in-class event viewer** and a **pattern visualization instrument**.

**Viewer first.** Before any statistical analysis or correlation, the tool must be the best way to read individual events and groups of events. Click anything — an event, a cluster, an EID — and the detail panel shows a clean, parsed, human-readable breakdown of exactly what that event contains. The analyst lives in the detail panel. If viewing and extracting individual records isn't fast, clear, and frictionless, nothing else matters.

**Pattern visualization second.** The tool makes the **shape** of event log data visible. The analyst decides what the shapes mean. It does not infer intent, label events as malicious, or make detection calls. It surfaces statistical facts — timing, frequency, distribution, correlation — and lets the analyst interpret them in context.

This distinction matters because legitimate software can look suspicious. A backup tool's initialization sequence can resemble an exploit. A service account doing its job can generate event chains identical to lateral movement. The analyst needs to see the patterns clearly enough to make that call themselves.

### The Three-Band Timing Model

The sequence cluster analysis revealed a natural separation in inter-event timing:

| Band | Threshold | What lives here |
|------|-----------|-----------------|
| **Scripted** | < 500ms | OS internals, service accounts, kernel operations — local machine talking to itself |
| **Fast** | 500ms – 5s | The anomaly band — automated tooling with real-world network latency |
| **Human** | > 5s | Someone at a keyboard making decisions |

The "fast" band surfaces anomalies. Legitimate OS operations are faster (sub-500ms, no network hops). Human activity is slower (reading, deciding, clicking). Anything in between is automated-but-not-local, which is where attack tooling (Mimikatz, PsExec, WMI lateral movement, automated RDP) naturally lands due to network round-trips, credential negotiation, and service startup. The tool doesn't judge what's in the band — it shows what's there and lets the analyst eliminate known fast-band residents (monitoring agents, backup tools, deployment scripts) to find what shouldn't be there.

### What EventScope Is Not

- Not a SIEM. No alerting, no rules engine, no real-time ingestion.
- Not a replacement for Axiom, X-Ways, or Velociraptor. Those tools parse artifacts and recover evidence. EventScope visualizes exported event data.
- Not SusFilter. The allowlist-driven anomaly triage concept is parked until deeper case experience informs what it actually needs to be.
- Not an LLM wrapper. If LLM integration ever comes, it generates summaries, not judgments.

---

## Architecture

### Constraints (non-negotiable)

- **Single HTML file.** No build step, no bundler, no server, no dependencies. Open the file in a browser and it works. This is a tool for analysts who may be working in restricted environments where they can't install software.
- **Absolute network isolation.** EventScope must never make a network request of any kind. No fetch calls, no XHR, no CDN loads, no font imports, no analytics, no telemetry, no WebSocket connections, no image loads from external URLs. The tool handles forensic evidence — case data must never leave the analyst's machine, even accidentally. This is not a preference, it is a hard security requirement. The file must function identically air-gapped on a forensic workstation with no network interface. Any proposed feature that requires network access is rejected.
- **Vanilla JavaScript only.** No frameworks, no libraries, no npm. Canvas 2D API for charts. DOM manipulation for tables. This keeps the file self-contained and auditable.
- **Streaming parser.** Must handle multi-GB CSV exports without blocking the UI or running out of memory. Current implementation reads 4 MB chunks and yields to the event loop between chunks.

### Internal Data Model

All ingested data normalizes to a common row schema regardless of source format:

```
{
  ts:    Number    // Unix epoch ms
  rule:  String    // RuleTitle (Hayabusa) or MapDescription (EvtxECmd)
  lvl:   String    // normalized: critical | high | medium | low | informational
  comp:  String    // Computer hostname
  chan:   String    // Event log channel
  eid:   String    // Event ID
  rec:   String    // Record ID
  det:   String    // Details field (¦-delimited key-value pairs)
  extra: String    // ExtraFieldInfo (Hayabusa) or Payload (EvtxECmd)
  rid:   String    // RuleID (Hayabusa) or Provider (EvtxECmd)
  src:   String    // SourceFile (EvtxECmd only)
  sessionIdx: Number  // which loaded file this row came from
}
```

### Multi-Session Design

Each loaded CSV file is a "session" with an index, color, label, format tag, and row count. All rows carry their `sessionIdx` so any analysis feature can distinguish or merge sessions. The lateral movement tab uses this to identify accounts that appear across multiple sessions (hosts), which is a direct indicator of credential reuse across the network.

---

## Current Feature Set (v1)

### Input Formats
- [x] Hayabusa `csv-timeline` (auto-detected)
- [x] EvtxECmd (Zimmerman Tools) CSV (auto-detected)
- [x] Multi-session loading with `+ Add Session`

### Analysis Tabs
- [x] **Overview** — summary cards, detection timeline, severity distribution, top EIDs, top channels
- [x] **Timeline** — filtered timeline, severity stacked heatmap, 3σ burst detection
- [x] **Heatmap** — hour × day activity grid, count or severity-weighted, click-to-filter, per-computer mode
- [x] **Arrivals** — first-seen/last-seen tracker for EIDs, rules, computers, accounts; late-arrival highlighting
- [x] **Gaps** — per-host silence detection with configurable absolute + σ thresholds
- [x] **Periodic** — CV-based periodicity detection per EID; maps to known periods (15min–24h)
- [x] **Rules** — rule table sorted by severity × count, associated EIDs and hosts
- [x] **Sequence** — temporal cluster analysis with scripted/fast/human classification, presets for common logon chains
- [x] **Frequency** — EID, channel, computer distribution with IQR + Z-score outlier flagging; time-of-day profile
- [x] **Anomalies** — unified list of critical/high rules, frequency outliers, burst windows
- [x] **Raw Data** — filtered record table, clickable rows open detail panel
- [x] **Lateral Movement** — account movement chains, cross-session correlation, account × session matrix
- [x] **EID Focus** — click any EID anywhere to drill into dedicated timeline, rule associations, recent events

### Interactive Features
- [x] Clickable EID links throughout all tabs
- [x] Slide-out detail panel with parsed payload (¦-delimited Details → key-value display)
- [x] Global filter bar (EID, rule, level, computer, channel, source, details substring, time range)
- [x] Bucket size controls on timeline charts (auto/1m/1h/1d)
- [x] Canvas tooltips on all bar charts
- [x] **Copy to Clipboard as CSV/TSV** — column config modal (persisted in localStorage), delimiter toggle, copy buttons on detail panel / raw table / rules table / sequence clusters
- [x] Toast notification on copy

---

## Development Roadmap

### Phase 1 — Viewer Enhancement + Temporal Pattern Visualization ✅ COMPLETE

**Goal:** Strengthen the core viewer with frictionless data extraction, then add temporal visualizations for spotting pattern breaks across days of logs.

#### 1.1 Copy to Clipboard as CSV ✅
*Priority: CRITICAL — this is the bridge between viewing and reporting.*

The analyst finds a 4-event logon cluster in the sequence tab, or a set of flagged events in the raw table. They need to paste those events into Excel, a report template, or a case management tool. Right now they'd have to manually transcribe or screenshot. This feature makes extraction instant.

- **Configurable column order.** A settings panel (or modal) where the analyst defines which columns to include and in what order. Different report formats need different column layouts — one report template might want `Timestamp, EID, Computer, Rule, Details` while a client summary wants `Timestamp, EID, Level, Description`. Save the column configuration in localStorage so it persists across sessions.
- **Copy single event.** Button in the detail side panel: "Copy as CSV". Copies the current event as a single CSV row (headers + data) using the configured column order.
- **Copy event group.** Button on sequence clusters: "Copy Cluster". Copies all events in the cluster as CSV (header row + N data rows). Same for any selected/filtered set of events in the raw data tab.
- **Copy from any table.** A subtle copy button in the header of every data table (raw data, rules, frequency, EID focus events). Copies visible rows as CSV in the configured column order.
- **Tab-delimited option.** Toggle between comma-delimited (CSV) and tab-delimited (TSV). Tab-delimited pastes directly into Excel cells without an import step.
- **Uses `navigator.clipboard.writeText()` only.** No Blob downloads, no file creation. Pure clipboard write. Works air-gapped. No network involvement.

Implementation: `copyRows(rows)` reads the column config from localStorage, formats rows as TSV or CSV, and writes to clipboard via `navigator.clipboard.writeText()`. Toast confirms "Copied N rows". Column config modal persists selection and order to localStorage.

#### 1.2 Activity Heatmap Calendar ✅
*Priority: HIGH — the single most impactful visualization for scrolling through days of logs.*

- Hour × day grid (columns = hours 0–23, rows = days)
- Cell color = event density, severity-weighted (a single critical at 3am should glow even if total count is low)
- Click a cell to filter the timeline to that hour
- Supports the merged multi-session dataset
- Optional per-computer heatmap mode to compare host activity profiles

**Implemented.** Canvas 2D rendering, HiDPI support, color gradient from dark → cyan → orange → critical-red. Click cell filters timeline to that day. Count and severity-weight modes. Per-computer dropdown.

#### 1.3 First-Seen / Last-Seen Tracker ✅
*Priority: HIGH — low effort, high analytical value.*

- For every unique EID, account (extracted from Details), computer, and rule: record the timestamp of first and last occurrence in the dataset
- "New Arrivals" view: a timeline of when novel artifacts first appeared, sorted chronologically
- Anything that first appears in the second half of the dataset is inherently more interesting (new tool deployed, new account created, new host communicating)
- Display as a simple sortable table with sparkline-style timeline indicators

**Implemented.** Arrivals tab. Tracks EIDs, rules, computers, accounts. Dataset-position bar per row. Late-arrival highlighting (orange). Sortable by first/last/count. Late-only filter toggle.

#### 1.4 Gap Analysis ✅
*Priority: HIGH — unique insight, cheap to compute.*

- Identify time windows where expected activity stops
- For each computer, compute the average inter-event interval, then flag gaps that exceed 3σ or a configurable absolute threshold
- Display gaps as a table: computer, gap start, gap end, duration, what was happening before/after
- A domain controller going silent for 40 minutes mid-workday is significant regardless of what caused it

**Implemented.** Gaps tab. Configurable min gap (minutes) and σ threshold. Per-host statistical baseline (mean + Nσ). Shows before/after event context (EID + rule). Per-computer filter. Z-score displayed per gap.

#### 1.5 Time-of-Day Profiling ✅
*Priority: MEDIUM — catches temporal anomalies without making judgment calls.*

- Per-computer, build a 24-hour activity histogram (what hours of the day does this host normally generate events?)
- Overlay the current dataset's events on top of the profile
- Highlight events that fall outside the host's typical active hours
- A workstation that normally generates events 9–17 EST logging RDP connections at 03:00 UTC — the analyst sees it immediately

**Implemented.** Integrated into Frequency tab. 24-hour bar chart per computer (UTC hours). Peak 8-hour window detection. Off-hours anomaly flagging (Z > 2 outside peak window) with inline anomaly item.

#### 1.6 Periodicity Detection ✅
*Priority: MEDIUM — powerful but more complex to implement well.*

- Autocorrelation on per-EID event frequency to detect recurring patterns (scheduled tasks, heartbeats, backup cycles)
- Display as a period table: "EID 4624 has a 24h cycle", "EID 7036 has an 8h cycle"
- The presence of periodicity means the events are expected. The *break* in periodicity is the signal — if a daily backup stopped firing, that's worth knowing.
- Probably defer this to Phase 2 unless implementation turns out to be straightforward

**Implemented.** Periodic tab. Median inter-event interval + coefficient of variation (σ/median) per EID. Classifies as Periodic (CV ≤ threshold) or Irregular. Maps to known periods: 15min, 30min, 1h, 2h, 4h, 6h, 8h, 12h, 24h (±15% tolerance). Configurable min events and CV threshold.

---

### Phase 2 — Multi-Host Correlation Visualization

**Goal:** When multiple sessions are loaded, show how accounts and activity flow between hosts over time.

#### 2.1 Network Graph
*Priority: HIGH — transforms the lateral movement tab from a table into a spatial map. **In progress.***

- Nodes = computers, edges = logon relationships (account X authenticated from A to B)
- Edge weight = event count, edge color = logon type
- Force-directed layout so tightly-connected clusters group naturally
- Click a node to filter all tabs to that host
- Click an edge to see accounts, timing, and event details
- Anomalous connections (single-use edges, edges to hosts not in the normal cluster) stand out visually

#### 2.2 Temporal Swim Lanes
*Priority: MEDIUM — the "watch the attacker walk across the network" view.*

- Horizontal lanes, one per host, time flows left to right
- Events appear as dots/marks in each lane
- When an account appears on Host A and then Host B within a time window, draw a connecting arc between the lanes
- Color arcs by account
- Multi-hop lateral movement chains become visually obvious as diagonal cascading arcs

#### 2.3 Credential Spread Matrix Enhancement
*Priority: MEDIUM — builds on existing lateral movement matrix.*

- Add temporal dimension: when did this account *first* touch this host?
- Highlight first-time access events vs. recurring access
- Sort by "breadth" — accounts that touched the most hosts float to the top
- Cross-reference with logon type: an account using Type 3 (network) on 15 hosts in an hour is different from one using Type 10 (RDP) on 2 hosts over a week

#### 2.4 Source IP Correlation
*Priority: LOW — useful but depends on event richness.*

- For events with source IP fields (4624 IpAddress, 5140 ClientAddress, etc.), build IP → host mapping
- Flag IPs that authenticated to multiple hosts
- Cross-reference with the computer list to distinguish known internal hosts from unknown sources
- Useful when available, but many event exports won't have IP data

---

### Phase 3 — Analyst Workflow

**Goal:** Make EventScope practical for sustained case work — bookmarking, saving, exporting.

#### 3.1 Bookmarking and Annotation
*Priority: HIGH — this makes the tool usable for real casework.*

- Click any event or cluster to add an analyst note
- Color-coded tags (analyst-defined, not severity — categories like "initial access", "persistence", "benign", "needs review")
- Persist bookmarks in localStorage (survives page reload within the same browser)
- Bookmarked events highlighted across all tabs

#### 3.2 Session Save / Load
*Priority: HIGH — enables continuity and collaboration.*

- Serialize all loaded rows, session metadata, bookmarks, annotations, and current filter state to a single JSON file
- Load a saved session to restore the exact analysis state
- Enables: pausing work overnight, sharing annotated analysis with colleagues, building a library of analyzed cases

#### 3.3 Narrative Timeline Export
*Priority: MEDIUM — the bridge between analysis and reporting.*

- One-click export of filtered/bookmarked events as a Markdown or standalone HTML document
- Include embedded SVG charts (timeline, heatmap, severity) and annotated event tables
- Sequence clusters with timing annotations included
- Goal: generate something close to a "findings" section that the analyst can edit into a final report
- Not replacing report writing — giving the analyst a structured first draft

#### 3.4 IOC List Extraction
*Priority: LOW — convenience feature.*

- Pull all unique values from loaded data: IP addresses, hostnames, account names, file paths, service names
- Export as CSV or flat text
- No judgment about whether they're indicators — just a deduplicated extraction of observed values

---

### Phase 4 — Additional Input Formats

**Goal:** Accept whatever the analyst's pipeline produces. Build these as cases demand, not preemptively.

| Format | Trigger to build |
|--------|-----------------|
| Velociraptor JSONL | When VQL artifact output needs visualization |
| Chainsaw CSV/JSON | When encountered in a case |
| Raw EVTX (WASM parser) | When direct evtx parsing without external tools is needed |
| JSON blob paste | When reading someone else's report and wanting to add IOC timestamps |

Each new format maps to the same internal schema. All analysis features work regardless of source.

---

### Phase 5 — Deferred / Conditional

Features that might be valuable but should only be built when real case experience proves they're needed.

| Feature | Condition |
|---------|-----------|
| Local LLM integration (Ollama) | Only when visualization layer is solid and the analyst workflow is proven. Strictly generative (summarize, don't judge). |
| Process execution baselining | Only if EID 4688/Sysmon data is commonly present in cases. This is SusFilter territory. |
| YARA/Sigma rule visualization | Only if there's a need to map loaded events against rule sets interactively. |
| Real-time ingestion | Only if live monitoring becomes a use case (currently EventScope is post-incident). |

---

## Coding Conventions

### File Structure
Single HTML file. CSS in a `<style>` block. JavaScript in a single `<script>` block at the end of body. No external files, no modules, no imports.

### Variable Naming
- Global state lives in `S` (the state object)
- Short function names for frequently-called utilities: `eH` (escapeHtml), `lB` (levelBadge), `fDF` (formatDateFull), `getFR` (getFilteredRows)
- Render functions prefixed with `r`: `rOV` (renderOverview), `rTL` (renderTimeline)
- Full descriptive names for complex analytical functions: `runSeq`, `buildLateralGraph`, `buildHops`

### Canvas Charts
All charts use the 2D Canvas API directly. No charting library. Helper functions: `drawBC` (bar chart), `drawHBC` (horizontal bar chart), `drawSBC` (stacked bar chart). HiDPI support via `devicePixelRatio` scaling. Chart data stored on `el._chartData` for tooltip hit detection.

### Adding a New Tab
1. Add a `<div class="tab">` in the tabs bar
2. Add a `<div class="panel" id="panel-{name}">` in the dashboard
3. Add a render function
4. Add a case to `switchTab()`
5. Wire any interactive elements in the event binding section at the bottom of the script

### Adding a New Input Format
1. Add header detection logic in `streamParse()` (check for format-specific column names)
2. Write a `procRow{Format}` function that maps the format's columns to the common schema
3. Set `S.format` for any format-specific UI adjustments (e.g., EvtxECmd shows Source File column)

---

## Testing Notes

EventScope has no automated test suite. Testing is manual against real case data.

**Test files to maintain:**
- A small Hayabusa CSV with known event patterns (logon chains, bursts, time gaps)
- A small EvtxECmd CSV from the same source data for format parity testing
- A multi-host pair (2+ CSVs from different hosts in the same incident) for lateral movement testing

**Regression checklist for any code change:**
- [ ] Drop a Hayabusa CSV — all tabs render without console errors
- [ ] Drop an EvtxECmd CSV — format auto-detected, Source column appears
- [ ] Add a second session — session bar appears, lateral movement tab populates
- [ ] Sequence presets fire and clusters display in chronological order
- [ ] Click an EID link — EID Focus tab opens with timeline and events
- [ ] Click a raw data row — detail panel slides out with parsed payload
- [ ] Filter by time range — all tabs respect the filter
- [ ] Large file (100k+ rows) — streaming parser doesn't freeze the UI

---

## License

MIT
