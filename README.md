# EventScope

A single-file, zero-dependency browser tool for analyzing Windows event log output from [Hayabusa](https://github.com/Yamato-Security/hayabusa) and [EvtxECmd](https://github.com/EricZimmerman/evtx) (Zimmerman Tools). Everything runs locally — no server, no install, no data leaves your machine.

![EventScope](https://img.shields.io/badge/format-single%20HTML-blue) ![License](https://img.shields.io/badge/license-MIT-green)

---

## Supported Input Formats

EventScope auto-detects the CSV format from the header row.

### Format A — Hayabusa `csv-timeline`
```
hayabusa csv-timeline --RFC-3339 -f output.csv
```
Expected columns: `Timestamp, RuleTitle, Level, Computer, Channel, EventID, RecordID, Details, ExtraFieldInfo, RuleID`

### Format B — EvtxECmd (Zimmerman Tools)
```
EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv "C:\output" --csvf "evtx-all.csv"
```
Expected columns: `TimeCreated, EventId, Level, Provider, Channel, Computer, MapDescription, PayloadData1–6, UserName, RemoteHost, UserId, ExecutableInfo, SourceFile, Payload, ...`

---

## Usage

1. Open `eventscope-hayabusa.html` in a modern browser (Chrome, Edge, or Firefox)
2. Drag and drop a Hayabusa or EvtxECmd CSV onto the drop zone, or click to browse
3. Use **`+ Add Session`** in the top bar to load additional CSVs from other hosts or time ranges
4. Navigate tabs to explore; use the filter bar to narrow results

No build step. No dependencies. No internet required after opening the file.

---

## Analysis Tabs

### Core Viewer

| Tab | What it shows |
|-----|---------------|
| **Overview** | Summary cards, detection timeline, severity distribution, top Event IDs, top channels |
| **Timeline** | Filtered timeline, severity stacked heatmap, 3σ burst detection |
| **Rules** | Rule/description table sorted by severity × count — Event IDs, channels, system coverage |
| **Sequence** | Temporal cluster analysis with Scripted / Fast / Human classification (see below) |
| **Frequency** | EID, Channel, and Computer distribution with Z-score outlier flagging, and time-of-day profile |
| **Anomalies** | Unified list: critical/high rules, frequency outliers, burst windows |
| **Raw Data** | Full filtered record table — click any row to open the detail panel |
| **Lateral Movement** | Account movement chains, cross-session correlation, account × session matrix |
| **EID Focus** | Click any Event ID anywhere to drill into its dedicated timeline and event list |

### Temporal Pattern Tabs

| Tab | What it shows |
|-----|---------------|
| **Heatmap** | Hour × day activity grid. Color intensity = event density or severity weight. Click a cell to filter the timeline to that day. |
| **Arrivals** | First-seen / last-seen tracker for Event IDs, rules, computers, or accounts. Items first appearing after the dataset midpoint are highlighted — new arrivals in an investigation are inherently more interesting. |
| **Gaps** | Per-host silence detection. Flags time windows where a host went quiet beyond its statistical baseline (mean + Nσ). A domain controller going silent for 40 minutes mid-workday stands out immediately. |
| **Periodic** | Periodicity detection per Event ID. Uses median inter-event interval and coefficient of variation to classify EIDs as Periodic or Irregular, and maps them to known periods (15min, 1h, 24h, etc.). Breaks in periodicity — a backup that stopped firing — are the real signal. |

---

## Sequence Analysis

The Sequence tab groups matching Event IDs into temporal clusters and classifies each cluster's timing:

| Band | Threshold | What lives here |
|------|-----------|-----------------|
| **Scripted** | < 500ms | OS internals, service accounts, kernel operations |
| **Fast** | 500ms – 5s | The anomaly band — automated tooling with real-world network latency |
| **Human** | > 5s | Someone at a keyboard making decisions |

Legitimate OS operations are faster (sub-500ms, no network hops). Human activity is slower. Anything in the Fast band is automated-but-not-local — where attack tooling (Mimikatz, PsExec, WMI lateral movement) lands due to network round-trips, credential negotiation, and service startup.

### Presets

| Preset | Event IDs | Window |
|--------|-----------|--------|
| Logon/Logoff cycle | 4624, 4672, 4634, 4647 | 60s |
| Explicit credential logon | 4624, 4672, 4648 | 30s |
| Process create/exit | 4688, 4689 | 10s |
| Scheduled task lifecycle | 4698, 4699, 4700, 4701, 4702 | 60s |
| Service install | 7045, 7036, 4697 | 30s |
| Account creation | 4720, 4722, 4732, 4724 | 120s |

---

## Lateral Movement Analysis

When two or more sessions are loaded:

- **Account Movement Chains** — hop-by-hop view of which systems each account touched, in timestamp order. Cross-session hops are marked `⇒` (amber). Logon types labeled (Interactive, Network, RDP, NewCred, etc.).
- **Cross-Session Accounts** — accounts seen in 2+ sessions, ranked by event count. High-value lateral movement indicators.
- **Account × Session Matrix** — top 30 accounts as rows, sessions as columns, event counts and system counts per cell.

Accounts are extracted from event Details fields: `TargetUserName`, `SubjectUserName`, `UserName`, `AccountName`, `RemoteUserName`.

---

## Copy to Clipboard

Every data surface has a **Copy** button that exports to TSV (pastes directly into Excel) or CSV. A column configuration modal (accessible from any Copy button) lets you choose and reorder which fields are included. Configuration is saved to `localStorage` and persists across sessions.

| Location | What gets copied |
|----------|-----------------|
| Detail panel | The currently-open event (header + 1 row) |
| Raw Data table | All visible filtered rows (up to 2,000) |
| Rules table | One row per unique rule |
| Sequence clusters | All events in the cluster |

---

## Filters

Active across all tabs:

- Event ID (comma-separated)
- Rule / Description (substring)
- Severity level
- Computer
- Channel
- Source File (EvtxECmd only)
- Details field (substring)
- Time range (start / end date)

---

## Architecture

Single self-contained HTML file (~1,150 lines). All logic is vanilla JavaScript with no external dependencies — no npm, no bundler, no CDN.

- **Streaming parser** — reads files in 4 MB chunks, yields to the event loop between chunks, handles multi-GB exports without blocking the UI
- **In-RAM store** — parsed rows as plain objects in `S.rows[]`, tagged with `sessionIdx` for multi-session correlation
- **Canvas charts** — all charts drawn directly via Canvas 2D API with HiDPI (`devicePixelRatio`) support; force-directed network graph uses a Verlet-integrated spring/repulsion physics simulation for natural cluster layout
- **Zero network access** — suitable for air-gapped forensic workstations; the file functions identically with no network interface
- **Lateral graph** — pure in-memory adjacency built at render time from `S.rows`, no external graph library needed

---

## License

MIT
