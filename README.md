# EventScope

A browser-based DFIR tool for analysing Windows event log data from [Hayabusa](https://github.com/Yamato-Security/hayabusa) and [EvtxECmd](https://github.com/EricZimmerman/evtx), and network transfer history from [SrumECmd](https://github.com/EricZimmerman/Srum) (Zimmerman Tools). Everything runs locally — no server, no install, no data leaves your machine.

Designed for air-gapped forensic workstations. Built for the Samsung G9 49" ultrawide.

---

## Supported Input Formats

### Hayabusa `csv-timeline`
```
hayabusa csv-timeline --RFC-3339 -f output.csv
```
Expected columns: `Timestamp, RuleTitle, Level, Computer, Channel, EventID, RecordID, Details, ExtraFieldInfo, RuleID`

### EvtxECmd (Zimmerman Tools)
```
EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv "C:\output" --csvf evtx-all.csv
```
Expected columns: `TimeCreated, EventId, Level, Provider, Channel, Computer, MapDescription, PayloadData1–6, UserName, RemoteHost, UserId, ExecutableInfo, SourceFile, Payload`

Auto-detected from the CSV header row. No manual format selection required.

### SrumECmd — Network Usage (SRUM tab only)
```
SrumECmd.exe -f "C:\Windows\System32\sru\SRUDB.dat" --csv C:\output\
```
Load the `*_NetworkUsages_Output.csv` file via the **SRUM** tab.

---

## Usage

1. Open `index.html` in a modern browser (Chrome, Edge, or Firefox)
2. Drag and drop a Hayabusa or EvtxECmd CSV onto the drop zone, or click to browse
3. Use **`+ Add Session`** to load additional CSVs from other hosts or time ranges
4. Navigate tabs to explore; collapse the filter bar to reclaim horizontal space

No build step. No dependencies. No internet required.

---

## Analysis Tabs

### Event Log Tabs (Hayabusa / EvtxECmd)

| Tab | What it shows |
|-----|---------------|
| **Dashboard** | Landing view — host identity, OS line, boot events, network summary, header stats (total detections, severity counts, host count) |
| **Histograms** | Filtered detection timeline with log-scale toggle, dynamic canvas height, 3σ burst detection with inline spike context panels |
| **Heatmap** | Hour × day activity grid — color intensity = event density or severity weight; click a cell to filter to that day |
| **Arrivals** | First-seen / last-seen per EID, rule, computer, or account — items first seen after the dataset midpoint are highlighted |
| **Gaps** | Per-host silence detection — flags windows where a host went quiet beyond its statistical baseline (mean + Nσ) |
| **Periodic** | Periodicity detection per EID — classifies as Periodic or Irregular, maps to known intervals (15m, 1h, 24h), flags breaks |
| **Rules** | Rule/description table sorted by severity × count — Event IDs, channels, coverage |
| **Sequence** | Temporal cluster analysis with Scripted / Fast / Human band classification |
| **Frequency** | EID, Channel, and Computer distribution with Z-score outlier flagging and time-of-day profile |
| **Anomalies** | Unified list of critical/high rules, frequency outliers, and burst windows |
| **Raw Data** | Full filtered record table — click any row to open the inline detail panel |
| **Logons** | Dedicated 4624/4625 view with per-event field extraction and CSV export |
| **Lateral Movement** | Account movement chains, cross-session correlation, account × session matrix |
| **EID Focus** | Click any Event ID anywhere to drill into its dedicated timeline and event list |

### SRUM Tab

| Feature | Detail |
|---------|--------|
| **Timeline canvas** | Stacked log-scale bar chart — X = time (hourly buckets), block height = total bytes transferred, colors = application |
| **Click detail** | Click any bar segment — inline breakdown of sent/received per app, per account, per interface for that hour |
| **Totals table** | Grand total bytes sent/received per application, sorted by volume, with inline bar |
| **Tool flagging** | Known exfil tools highlighted red; RMM/remote access tools highlighted orange throughout |
| **App filter** | Text filter on exe name narrows both the timeline canvas and the totals table |
| **Export** | Download per-bucket or full-dataset CSV: ExeName, FullExePath, BucketStart/End UTC, Account, SID, BytesSent, BytesReceived, TotalBytes, InterfaceType, Flag |

---

## Sequence Analysis

Groups matching Event IDs into temporal clusters and classifies timing:

| Band | Threshold | What lives here |
|------|-----------|-----------------|
| **Scripted** | < 500ms | OS internals, service accounts, kernel operations |
| **Fast** | 500ms – 5s | The anomaly band — automated tooling with real-world network latency |
| **Human** | > 5s | Someone at a keyboard making decisions |

Attack tooling (Mimikatz, PsExec, WMI lateral movement) lands in the **Fast** band — automated but with network round-trips.

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

## Histogram Spike Tools

When the Histograms tab detects a burst (3σ above baseline):

- **Spike context panel** — expand inline (no tab switch): rule breakdown by count + first-40-event sequence with relative timestamps (T+0, T+1m30s…)
- **Copy Pattern** — exports structured text (rule breakdown + sequence) with IPs anonymised via RFC 5737 documentation addresses; safe to paste to AI for rule writing without exposing raw evidence
- **Log scale toggle** — auto-enables when spike/mean ratio exceeds 20×; baseline mean shown as dashed line; canvas height scales dynamically

---

## Lateral Movement Analysis

When two or more sessions are loaded:

- **Account Movement Chains** — hop-by-hop view of which systems each account touched in timestamp order; cross-session hops marked `⇒`
- **Cross-Session Accounts** — accounts seen in 2+ sessions, ranked by event count
- **Account × Session Matrix** — top 30 accounts × sessions, event counts per cell

Accounts extracted from: `TargetUserName`, `SubjectUserName`, `UserName`, `AccountName`, `RemoteUserName`.

---

## NetMap — Network Diagram

Standalone companion tool at `netmap.html` — opens in any browser, no EventScope session required. Paste asset data (netstat, arp, hayabusa src/dst, anything messy) and it builds a clean SVG diagram: nodes grouped by /24 VLAN, infra nodes pulled to the top as trunks, public IPs called out.

- **Add line / Remove line** — click two nodes to insert or strip an `A => B` pairing in the textbox, then auto-reparse
- **Group drag** — shift+click to multi-select, shift+drag the canvas to lasso, drag any selected node to move the whole group
- **Auto-reparse** — 500ms after the last textbox edit; the Parse button is still there for immediate
- **Export** — SVG or JSON

From EventScope's **Remote Hosts** tab, click **Copy for NetMap** to build a seed text from the current peer data (inbound / outbound / netconfig adapters) and paste into netmap's textbox. Clipboard handoff only — no URL passing, no message bus.

---

## Copy / Export

| Location | Output |
|----------|--------|
| Detail panel | Single event — header + row |
| Raw Data table | All filtered rows (up to 2,000) |
| Rules table | One row per unique rule |
| Sequence clusters | All events in the cluster |
| Logons tab | 4624/4625 CSV with all logon fields extracted |
| SRUM tab | Network transfer CSV — per-app per-hour |
| Timeline spikes | Structured pattern text (IPs anonymised) |

Column configuration modal (accessible from any Copy button) lets you choose and reorder fields. Saved to `localStorage`.

---

## Filters

Active across all event log tabs:

- Event ID (comma-separated)
- Rule / Description (substring)
- Severity level (checkboxes)
- Computer
- Channel
- Source File (EvtxECmd only)
- Details field (substring)
- Time range (start / end date)

---

## Architecture

Modular vanilla JavaScript — no npm, no bundler, no CDN, no external dependencies.

```
index.html          Shell, layout, tab skeleton, all CSS
es-core.js          State object S, constants, utilities, IP anonymisation
es-parsers.js       CSV ingestion — Hayabusa and EvtxECmd format detection
es-filters.js       Filter logic and filter cache
es-charts.js        Canvas 2D charts — bar, stacked bar, horizontal bar, heatmap
es-views.js         All tab render functions, inline row expansion, spike context
es-srum.js          SRUM network usage parser, timeline canvas, export
es-export.js        Clipboard copy, logon CSV export, column config modal
es-dedup.js         Placeholder — Phase 7
es-prefs.js         Placeholder — Phase 5
es-data/
  win-security-eids.json    Windows Security Event ID reference
```

- **Streaming parser** — 4 MB chunks, yields to event loop between chunks; handles multi-GB exports without blocking
- **In-RAM store** — parsed rows as plain objects in `S.rows[]`, tagged with `sessionIdx` for multi-session correlation
- **Canvas charts** — all charts via Canvas 2D API with HiDPI (`devicePixelRatio`) support
- **Evidence integrity** — `S.rows` is never modified after ingestion; timezone is display-only; tags are a separate overlay

---

## License

MIT
