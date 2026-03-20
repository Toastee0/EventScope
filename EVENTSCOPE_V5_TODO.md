# EventScope v5 — Design & Feature Handoff
**Author:** Adrian Neill  
**Date:** 2026-03-18  
**Status:** Planning complete — hand to coding agent  
**Repo:** toastee0 / EventScope

---

## The Four Questions

Every feature exists to answer one of these:

1. **When did they get in?**
2. **What did they look at?**
3. **What did they take and how much?**
4. **What else did they access?**

---

## Design Philosophy

EventScope is a **speed multiplier for analyst intuition** — not an automated detection engine.

The analyst brings the pattern recognition. EventScope removes the mechanical friction of finding the data.

Each view is a different lens on the same data. No single view catches everything. A skilled analyst cycling through views at different time scales — hours, minutes, seconds — builds the narrative fast.

**No autotagging. Ever. The data is evidence.**

---

## Target Environment

- **Primary display:** Samsung G9 49" 5120×1440 32:9 curved ultrawide
- **Secondary:** Laptop display
- **OS:** Windows 11, UTC+0 workstation
- **Source files:** May originate from systems in other timezones
- **Deployment:** Air-gapped — no internet, no CDN, no external dependencies

---

## Display Philosophy — CORRECTED

**Horizontal space = reading full row content without truncation**  
**Vertical scroll = primary navigation — time flows downward**

The analyst reads the timeline like a document, scrolling through the narrative. Motion pattern recognition fires on shapes and outliers while scrolling. This is how the WMI attack chain was found — scrolling through grouped headers, pattern recognition identifying the anomalous entries.

**Layout model:**
- Primary view is a **wide scrollable table**
- Summary charts and panels sit **above** the table — context before detail
- Detail panel opens as a **full-width expansion below the selected row** — not a side panel stealing horizontal space
- Filter bar collapses/hides when not needed — return horizontal space to the table
- No modal overlays
- No slide-ins that consume screen real estate
- Full payload/Details field visible without truncation — the G9 width handles it

---

## v5 First Task: Refactor

**Refactor before any new features. This is non-negotiable.**

v4 is 1479 lines in a single HTML file. v5 will be significantly larger. Single-file architecture will not scale and makes collaborative development with a coding agent unreliable.

v4 also contains features that are not useful — the refactor is a clean slate, not a preservation exercise. Review v4 critically before splitting.

### Module Structure

```
EventScope/
├── index.html              -- shell, layout structure, tab skeleton only
├── es-core.js              -- state object, constants, utility functions
├── es-parsers.js           -- all CSV ingestion and field mapping
├── es-filters.js           -- filter logic, column hide/reorder/sort
├── es-charts.js            -- all canvas drawing, density, heatmap, TOD
├── es-views.js             -- tab render functions
├── es-dedup.js             -- payload outlier detection, grouping logic
├── es-export.js            -- tagging system, IR report CSV export
├── es-prefs.js             -- preferences file load/save
└── es-data/
    └── win-security-eids.json  -- default Windows Security EID descriptions
```

All local files. HTML loads JS via `<script src="">` tags. Air gap safe.

### Refactor is complete when:
- All v4 features that are being kept work identically
- Each file has a single clear responsibility
- State management via `S` object is clean and consistent
- No regressions

### Then fix the two existing bugs before adding anything new.

---

## Bugs to Fix (Post-Refactor, Pre-New Features)

### [ ] Level filter — multi-select checkboxes
- Replace single `filterLevel` `<select>` with checkbox group
- Options: Critical / High / Medium / Low / Informational
- Default: all checked
- No presets needed for 5 items
- Filter logic: `selectedSet.has(r.lvl)` instead of equality check

### [ ] EvtxECmd field mapping
- Current parser maps columns by position — breaks when EvtxECmd version or export options change
- Fix: detect columns by header name only, never by index
- Map to internal schema explicitly by name
- Log unmapped columns to console
- Expose column mapping UI if auto-detection fails
- Most impactful bug — bad field mapping silently corrupts lateral movement analysis and detail panel

---

## Table — First Class Citizen

The table is the primary view. It must be excellent.

### [ ] Column Management
- **Hide columns** — analyst configures visible columns per session, persisted in preferences
- **Reorder columns** — drag to reorder, persisted
- **Sort by column** — click header, ascending/descending toggle, stable sort
- **Full content visible** — no truncation, especially on Details/payload field
- No horizontal scroll within the table — use the G9 width

### [ ] Hostname Multi-Select
- Computer/hostname filter becomes multi-select checkboxes — same pattern as level filter
- Analyst checks multiple hostnames for the same physical machine (renamed, domain-joined, etc.)
- They merge into a single unified view
- Checkbox state persists in preferences
- Also handles: same host appearing as FQDN vs short name across different tool outputs

---

## Vertical Density Timeline — Zoom-Linked View

The core visualization innovation of v5.

### [ ] Implementation

Time flows **downward**. The analyst scrolls through the narrative.

**Zoom levels — linked to table view:**

| Level | Behaviour |
|-------|-----------|
| 1 | Full row detail — normal table |
| 2 | Compressed rows — timestamp + level + description only |
| 3 | Density bars — fixed row height, bar extends **rightward** proportional to event count in time bucket |
| 4 | Grouped buckets — larger time slices, bar width = group count |

**The signal:** As the analyst scrolls, the right edge of the bars is what they read. Normal operation = ragged but consistent right edge. Attack sequence = right edge suddenly extends. The shape is the signal.

**Implementation details:**
- Bar extends rightward from a fixed timestamp column
- Severity color on bars — critical/high events tint the bar red regardless of width
- Click any bar at any zoom level = expand to show that time bucket's individual events
- Zoom controls: per-minute / per-hour / per-day / per-week buckets
- Anti-forensic chaff detection: unnaturally regular bar widths (low CV) = machine-generated flooding, itself a finding

---

## New Features

### [ ] Central Pivot Date/Time
- User-settable T-0 reference timestamp for the investigation
- Visual marker on ALL views and charts
- Relative time labels throughout — T-0, T+1h, T-24h, T+1w
- **Detection sensitivity boundary:**
  - Within configurable window of pivot: anomaly scoring elevated, noise filters relax
  - Outside pivot window: normal noise suppression applies
- Natural pivot = accessed timestamp on the initial malware = detonation time
- Set once, propagates everywhere
- Persisted in preferences per-case

---

### [ ] Event Tagging System
- Manually tag any event — single or multi-select
- **No autotagging. Ever.** Analyst judgment only. Data is evidence.
- Preset tags = MITRE ATT&CK tactics:
  - Initial Access / Execution / Persistence / Privilege Escalation
  - Defense Evasion / Credential Access / Discovery / Lateral Movement
  - Collection / Exfiltration / Impact
- Free-form custom tags also supported
- Tags are a separate overlay — source data is never touched
- Tags persist in preferences/session file
- Visual indicator on tagged rows in all views

---

### [ ] Export — IR Report CSV

Analyst builds the report by tagging as they investigate. Export produces the Excel-ready output. The report writes itself during triage.

**Structure:**
- Tagged events sorted by MITRE tactic — tag names become sheet names in Excel
- Each exported row: full original event data (unchanged) + file hashes where present + analyst tag + timestamp + source artifact
- **Static reference sheets** populated from loaded artifact data:
  - **System Profile** — OS install date, hostname, domain, last boot, timezone, user accounts, installed software
  - **Network Map** — adapters, IPs, DNS servers, mapped drives, remote connections, RMM endpoints (ScreenConnect URLs + source IPs, AnyDesk IDs, PuTTY hosts)
  - **Files of Interest** — analyst-flagged entries with full path, all four MACB timestamps, hashes
- Evidence integrity: raw data fields never altered in export

---

### [ ] Ignore List
- Mark an EID as ignored — filtered from all views
- Persisted in preferences
- Easy toggle to temporarily re-enable
- **WMI channel note:** Do NOT default-suppress WMI. Attackers deliberately flood WMI logs as anti-forensic chaff. Suppressing WMI plays into their hands. Instead use the Deduplicated Payload Groups view.
- Exception: EID 5861 (permanent WMI subscription = persistence) is always promoted regardless of any suppression setting

---

### [ ] Preferences File
- JSON file, same folder as EventScope HTML files
- Air gap safe — browser sandbox means manual save/load button workflow, cannot auto-write to disk
- Stores: ignore list, column config, tag definitions, TZ offset, per-channel suppression, hostname groupings, pivot date per session
- Load on startup if present, explicit Save button in UI

---

### [ ] Importable Event Description Lists
- Load CSV/JSON mapping EID → friendly name/description
- Enriches UI display — never modifies source data
- Ship default Windows Security EID reference list (`es-data/win-security-eids.json`)
- User can load custom lists: Sysmon, application-specific event logs

---

### [ ] Timezone Handling
- TZ adjustment = display only, always — raw timestamps never modified
- All internal storage and comparison in UTC epoch milliseconds
- User-settable TZ offset per session or per loaded file
- Source files may be from non-UTC systems; workstation is UTC+0

---

### [ ] Timeline Spike Navigation
- Click any spike on any density chart = navigate to table view
- Scroll and focus to **first event at the beginning of that time bucket**
- Not just a filter — actual row positioning
- Workflow: see anomalous spike → click → land at first event of burst → arrow key down through the sequence

---

### [ ] Sequence Analysis — Window Parameter Clarification
The window parameter is currently labelled ambiguously. It means:

**Maximum gap in seconds between consecutive events to be considered part of the same cluster.**

The cluster duration is not bounded — it grows as long as consecutive events stay within the window of each other.

UI should explain this clearly. Suggested guidance per use case:
- Scripted/automated activity: 5–30 seconds
- Human operator: 60–300 seconds
- Slow deliberate activity: 300–900 seconds

---

### [ ] Dual File Load — Hayabusa + EvtxECmd
- Load both CSVs in the same session simultaneously
- Hayabusa = detection layer (severity, rule, SIGMA matches)
- EvtxECmd = raw density layer (every event, no filtering)
- Dedup key: Timestamp + EventID + Computer + RecordID
- Merge: Hayabusa wins for severity/rule fields, EvtxECmd wins for raw payload
- Events only in EvtxECmd = severity "none" — visible in density charts, not cluttering detection views unless explicitly included
- Gaps between detections inside a density spike = undetected attacker activity — this is the finding

---

### [ ] Deduplicated Payload Groups View

**The WMI problem:** 500 events, same EID, same description. 499 have identical payloads. 1 has a different payload. That 1 is the attacker hiding in the storm of legitimate WMI noise — potentially deliberate anti-forensic chaff added by the attacker to bury their activity.

**The insight:** The deduplicated description list collapses the noise. The malicious calls stand out because they are semantically different. The payload of each unique description entry is the evidence — it must be fully preserved and displayed.

**Implementation:**
- Group by EID + Description/RuleTitle
- Within each group, compare payload/Details field contents
- Show unique payload variants with count per variant
- Sort groups by total count descending — noise at top, rare entries at bottom
- **Outlier flag:** any payload appearing in < configurable threshold % of group = automatically flagged
- Single occurrence in group of 500 = near-certain signal
- Expandable groups — collapsed by default showing count, expand to see all payload variants
- **Critical:** payload is fully preserved, not truncated — the payload IS the finding

**Known hostile WMI classes to highlight:**
- `Win32_ShadowCopy` DELETE — ransomware prep
- `AntiVirusProduct` — AV enumeration/kill attempt
- `Win32_NetworkAdapterConfiguration` — network recon
- `RSoPLoggingModeProvider` — policy audit evasion
- `Win32_GroupUser` + domain admin group — privilege validation

---

### [ ] WMI Operation Sequence Summarizer
- Extract WMI class/method from event Details field within a time window
- Display as an ordered list: what was queried, in sequence, top to bottom
- The analyst reads the list and the kill chain narrative is self-evident
- Flag known hostile class names inline
- Example sequence found in the wild:
  1. RSoPLoggingModeProvider — blind the policy audit trail
  2. Win32_NetworkAdapterConfiguration — map the environment
  3. Win32_GroupUser (Domain Admins) — validate privilege level
  4. AntiVirusProduct + disable method — remove defensive capability

---

### [ ] MFT Timestamps — MACB as First-Class Fields

All four MACB timestamps must be immediately visible when an analyst selects a file:
- **M**odified
- **A**ccessed ← detonation time for malware
- **C**hanged ($MFT entry modified)
- **B**orn (created)

**Directory blast pattern detection:**
- When malware executes, the parent directory MFT entry and sibling files get their MFT Changed timestamp updated in the same millisecond window
- Detect: abnormal clustering of MFT Changed timestamps within the same directory path at millisecond resolution
- Flag as candidate execution event even with no corresponding process creation event
- **Tamper resistance:** directory-level MFT ripple persists even if individual file timestamps are stomped — the cluster is the evidence

---

### [ ] New Input Formats

#### RECmd Registry CSV
- RECmd batch output from EZ Tools triage
- Field mapping: KeyPath → source, ValueName → field, ValueData → payload, LastWriteTime → timestamp
- Dedup key: KeyPath + ValueName + ValueData + Computer
- **High-value registry paths to highlight in UI:**
  - `HKCU\Software\SimonTatham\PuTTY\SshHostKeys` — SSH hosts ever connected to
  - `HKCU\Software\SimonTatham\PuTTY\Sessions` — saved sessions with hostname/port/user
  - `HKCU\Software\Microsoft\Terminal Server Client\Servers` — RDP destination history
  - WinSCP stored sessions
  - Mapped network drives MRU
  - RunMRU — network UNC paths via Run dialog
  - Typed paths (Explorer UNC history) from NTUser.dat
  - Mount points
  - AnyDesk, Atera, ScreenConnect install/config keys

#### SrumECmd CSV
- SRUM = System Resource Usage Monitor — Windows keeps 30–60 day rolling history
- Per-application: bytes sent, bytes received, CPU time, timestamps of activity
- **Primary use: exfiltration volume quantification** — the byte count that goes in the report
- Known exfil tool highlight list: WinSCP, MegaCMD, rclone, robocopy, curl, wget, 7zip, AnyDesk, TeamViewer
- Cross-reference active timestamps against pivot point
- Bytes sent per application = answer to "what did they take and how much"

#### Chainsaw CSV
- Detection source alongside Hayabusa
- Per-artifact CSV outputs: lateral_movement, persistence, credential_access, rdp_events, service_installation, powershell, sigma, account_tampering, defense_evasion, antivirus, applocker, log_tampering, login_attacks
- Each file has different column schema — parser must handle per-type

#### Forensic Timeliner Unified CSV
- Reference: https://github.com/acquiredsecurity/forensic-timeliner (CC BY-NC 4.0)
- Schema: `DateTime, TimestampInfo, ArtifactName, Tool, Description, DataDetails, DataPath, FileExtension, EventId, User, Computer, FileSize, IPAddress, SHA1, Count, EvidencePath`
- Covers EZ Tools, Axiom, Hayabusa, Chainsaw, Nirsoft, browser history in one unified timeline
- Enables density analysis across ALL artifact types simultaneously — MFT, Registry, Prefetch, Event Logs, Browser history together

---

### [ ] ScreenConnect Guest Invite Forensics

Attack pattern: TA gains initial access → generates guest invite from installed ScreenConnect instance → connects IN via guest invite from their own infrastructure → guest connection logs **source IP of incoming connection**

That source IP is the TA's VPN exit node at minimum — most actionable single data point in the timeline.

- Guest invite creation event: timestamp + account that created it
- Guest connection event: timestamp + **source IP prominently displayed as first-class column**
- Flag custom ScreenConnect domains (non-.screenconnect.com) as critical — indicates attacker-controlled infrastructure
- Cross-reference source IP against 4624 Security log for same subnet
- Source IP field never buried in Details — promoted to visible table column

---

### [ ] Application Timeline View — Swimlane

Per-application lifecycle visualization:

- **Install event** — Amcache/AppCompatCache first-seen timestamp
- **Update events** — subsequent version changes
- **Execution events** — Prefetch, UserAssist, AppCompatCache hits
- **SRUM overlay** — bytes sent/received as bar height/opacity on the same time axis

Multiple apps stacked as selectable rows sharing a common time axis. Shows correlation: rclone installs → executes → SRUM shows 40GB sent → all within the same 2-hour window.

**Selection UI:**
- Searchable app list from all loaded sources
- Checkbox to add app to swimlane
- Drag to reorder rows
- Toggle SRUM overlay per row

---

### [ ] Quick Chart Dashboard — IR Overview

Summary charts for rapid case orientation at the start of an investigation:

- Application install history — Amcache/AppCompatCache first-seen timeline
- Service install history — EID 7045 timeline
- Account creation history — EID 4720/4722 timeline
- IP addresses seen — all unique remote IPs across all sources, first/last seen, frequency
- SRUM application network usage — bytes sent/received per executable, top 20

---

### [ ] Sequence Tab — Enhanced Lateral Movement Presets

Based on Stroz Friedberg Velociraptor LMDA (Kostya Ilioukevitch & Phalgun Kulkarni). Reference file: `Custom.Windows.LateralMovement.yaml`

| Preset | EID Sequence | Window |
|--------|-------------|--------|
| RDP inbound | 1149 → 131 → 21/24/25 | 120s |
| RDP outbound | 1024/1102 | 60s |
| Explicit credential use | 4648 → 4672 → 4624 | 60s |
| Share access chain | 4624 → 5140 → 5145 | 120s |
| Credential validation | 4776 → 4624/4625 | 30s |
| WinRM inbound | 91 → 4624 | 60s |
| WinRM outbound | 6 | — |
| PsExec | 7045 | — |
| Pre-ransomware WMI prep | WMI burst: RSoP + adapter enum + group check + AV kill | 300s |

---

## Evidence Integrity Rules — Non-Negotiable

These are not guidelines. They are invariants.

- Source data is **never modified** under any circumstances
- TZ adjustment = display transformation only, never stored back
- Tags = separate overlay stored in preferences, never written to source data
- Export = copy of source data with analyst annotations appended as additional columns
- Dedup = view operation only — both records retained in memory
- Ignored EIDs = filter operation only — data retained, never deleted
- The analyst is the chain of custody — the tool is a window, not an editor

---

## Input Format Reference

| Format | Source Tool | Primary Timestamp Field | Notes |
|--------|------------|------------------------|-------|
| Hayabusa CSV | Hayabusa | Timestamp | Detection layer — severity + rules |
| EvtxECmd CSV | EZ Tools | TimeCreated | Raw event layer — all events |
| RECmd CSV | EZ Tools | LastWriteTime | Registry artifact layer |
| SrumECmd CSV | EZ Tools | Timestamp | Exfil quantification layer |
| Chainsaw CSV | Chainsaw | Timestamp (varies) | Detection layer — per artifact type |
| Forensic Timeliner CSV | forensic-timeliner | DateTime | Unified all-source layer |

**Parser rule:** All parsers detect columns by header name only — never by position index.

---

## Reference Material

| Resource | Purpose |
|----------|---------|
| `Custom.Windows.LateralMovement.yaml` | Lateral movement EID vocabulary — sequence presets |
| https://github.com/acquiredsecurity/forensic-timeliner | Unified schema reference, dedup logic, supported artifact list |
| MITRE ATT&CK | Tactic taxonomy for tag preset structure |
| EventScope v4 `index.html` | Current feature baseline — review critically, not preserved wholesale |

---

## Out of Scope for v5

- Automated detection / alerting — EventScope does not decide what is suspicious
- Network connectivity of any kind — air gap is a hard requirement
- Any modification of source data for any reason
- Autotagging

---

*Planning session: 2026-03-17 / 2026-03-18*  
*Participants: Adrian Neill, 17 raccoons (Gerald, Deborah, Steve, and others), one unnamed raccoon whose pointer arithmetic remains under review*  
*No code written this session*  
*Hand to coding agent — start with refactor*
