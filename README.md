# EventScope

A single-file, zero-dependency browser tool for analyzing Windows event log output from [Hayabusa](https://github.com/Yamato-Security/hayabusa) and [EvtxECmd](https://github.com/EricZimmerman/evtx) (Zimmerman Tools). Everything runs locally — no server, no install, no data leaves your machine.

![EventScope](https://img.shields.io/badge/format-single%20HTML-blue) ![License](https://img.shields.io/badge/license-MIT-green)

---

## Supported Input Formats

EventScope auto-detects the CSV format from the header row.

### Format A — Hayabusa `csv-timeline`
```
evtx_dump / hayabusa csv-timeline --RFC-3339 -f output.csv
```
Expected columns: `Timestamp, RuleTitle, Level, Computer, Channel, EventID, RecordID, Details, ExtraFieldInfo, RuleID`

### Format B — EvtxECmd (Zimmerman Tools)
```
EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv "C:\output" --csvf "evtx-all.csv"
```
Expected columns: `TimeCreated, EventId, Level, Provider, Channel, Computer, MapDescription, PayloadData1–6, UserName, RemoteHost, UserId, ExecutableInfo, SourceFile, Payload, ...`

---

## Features

### Multi-Session Loading
Load multiple CSV files in the same browser session. Each file is tagged with a color-coded session label (`S1`, `S2`, ...). All analysis tabs work across the merged dataset simultaneously.

Use **`+ Add Session`** in the session bar to load additional CSV files after the first.

### Analysis Tabs

| Tab | Description |
|-----|-------------|
| **Overview** | Summary cards, detection timeline, severity distribution, top Event IDs, top channels |
| **Timeline** | Filtered timeline with burst detection and severity heatmap |
| **Rules** | Rule/description table sorted by severity then count, with Event IDs and system coverage |
| **Sequence** | Temporal cluster analysis — groups events by Event ID within a time window and classifies behavior as Scripted (<500ms), Fast (500ms–5s), or Human (>5s) |
| **Frequency** | Event ID, Channel, and Computer distribution tables with Z-score outlier flagging |
| **Anomalies** | Unified anomaly list: critical/high rules, statistical outlier EIDs, burst windows |
| **Raw Data** | Filtered record table with click-through detail panel; shows Source File column for EvtxECmd data |
| **Lateral Movement** | Cross-session account correlation (see below) |

### Lateral Movement Analysis

When two or more sessions are loaded, the **Lateral Movement** tab extracts user accounts from event Details fields (`TargetUserName`, `SubjectUserName`, `UserName`, `AccountName`, etc.) and builds:

- **Account Movement Chains** — hop-by-hop visualization of which systems each account touched, in timestamp order. Cross-session hops are highlighted with `⇒` (amber). Logon types are labeled (Interactive, Network, RDP, NewCred, etc.).
- **Cross-Session Accounts** — accounts observed in 2+ loaded sessions, ranked by event count. These are high-value lateral movement indicators.
- **Account × Session Matrix** — top 30 accounts as rows, sessions as columns, showing event counts and system counts per cell.

### Filters
- Event ID (comma-separated list)
- Rule / Description title (substring)
- Severity level
- Computer
- Channel
- Source File (EvtxECmd only)
- Details field (substring)
- Time range (start / end date)

### EID Focus
Click any Event ID link anywhere in the tool to open a dedicated drill-down view: timeline, rule associations, per-computer breakdown, and recent events.

---

## Usage

1. Open `eventscope-hayabusa.html` in a modern browser (Chrome/Edge/Firefox)
2. Drag and drop a Hayabusa or EvtxECmd CSV onto the drop zone, or click to browse
3. Use **`+ Add Session`** in the top bar to load additional CSVs from other hosts or time ranges
4. Navigate tabs to explore; use the filter bar to narrow results

No build step. No dependencies. No internet required after opening the file.

---

## Sequence Analysis Presets

| Preset | Event IDs | Window |
|--------|-----------|--------|
| Logon/Logoff cycle | 4624, 4672, 4634, 4647 | 60s |
| Explicit credential logon | 4624, 4672, 4648 | 30s |
| Process create/exit | 4688, 4689 | 10s |
| Scheduled task lifecycle | 4698, 4699, 4700, 4701, 4702 | 60s |
| Service install | 7045, 7036, 4697 | 30s |
| Account creation | 4720, 4722, 4732, 4724 | 120s |

---

## Architecture

Single self-contained HTML file. All logic is vanilla JavaScript with no external dependencies.

- **CSV streaming parser** — reads files in 4 MB chunks, handles quoted fields and multi-line edge cases, streams arbitrarily large files without blocking the UI
- **In-RAM store** — parsed rows stored as plain objects in `S.rows[]`, tagged with `sessionIdx` for multi-session correlation
- **Canvas charts** — bar charts, stacked severity charts, and horizontal bar charts drawn directly via 2D Canvas API with HiDPI support
- **Lateral graph** — pure in-memory adjacency built at render time from `S.rows`, no external graph library needed

---

## License

MIT
