# EventScope Universal Module Architecture

## Overview

This document defines the target architecture for EventScope's modular, multi-format pipeline. The goal is a format-agnostic core that any forensic CSV format can plug into via a standardised module interface — without touching core rendering, filtering, or export logic.

---

## 1. Pipeline Model

```
Acquire → Extract → Preprocess → Visualize
```

| Stage | Responsibility | Owner |
|---|---|---|
| **Acquire** | File selection, drag-drop, streaming read | `es-core.js` |
| **Extract** | Raw CSV parsing, column index mapping | `es-core.js` (streaming CSV parser) |
| **Preprocess** | Format-specific normalisation → standardised row object | Module (`normalizeRow`) |
| **Visualize** | Timeline, table, heatmap, filters, tabs, export | `es-core.js` + module views |

### The Preprocessor as Contract Boundary

The `normalizeRow` function is the **only** place where format-specific knowledge lives. Everything downstream — filtering, timeline rendering, heatmap, export — operates on normalised row objects whose shape is defined by the module's `schema[]`. This boundary must be respected: no format-specific field names should leak into core rendering code.

---

## 2. Core Framework (Format-Agnostic)

These components are owned by the core and must work with any module without modification:

| Component | Description |
|---|---|
| **Streaming CSV parser** | Handles large files via chunk-based reads; emits rows one at a time to avoid blocking the main thread |
| **Timeline** | Renders a zoomable event-density timeline against the normalised `timestamp` field |
| **Raw table** | Paginated, sortable table driven by `schema[].displayDefault` and column visibility prefs |
| **Filter bar** | Renders filter controls contributed by `filterFields[]`; applies AND logic across all active filters |
| **Heatmap** | Day × hour heatmap of event density; uses the normalised `timestamp` field |
| **Export** | CSV/JSON export of the current filtered row set using normalised field keys |
| **Timezone bar** | Global TZ offset selector; applied to all timestamp rendering |
| **Session management** | Save/restore filter state, column config, and active module per session |
| **Column config** | Per-module column visibility and order preferences, persisted to localStorage |

---

## 3. Module Interface Specification

Every module **must** export an object conforming to this interface. The module registry will reject anything that doesn't satisfy the required fields.

### 3.1 Required Fields

#### `id` — `string`
Unique identifier for this module. Used as a key in the registry and in localStorage keys.

```js
id: 'eventlog'
```

#### `label` — `string`
Human-readable display name shown in the UI (header bar, error panel).

```js
label: 'Windows Event Log (Hayabusa / EvtxECmd)'
```

#### `requiredHeaders[]` — `string[]`
**Exact CSV column names that the preprocessor for this format must produce.** This array is the authoritative specification for anyone writing a preprocessor or exporter that feeds EventScope. Detection uses this list as a strict subset match against the actual CSV headers.

```js
requiredHeaders: ['Datetime', 'Channel', 'EventID', 'Level', 'Computer', 'Provider', 'Details']
```

> **Note for preprocessor authors:** Your output CSV must contain every column listed in `requiredHeaders` with exactly these names (case-sensitive). Additional columns are permitted.

#### `schema[]` — `FieldDef[]`
Ordered list of field definitions that describe the normalised row shape. Each entry:

```ts
interface FieldDef {
  key: string;              // key on the normalised row object
  label: string;            // column header shown in the UI
  type: 'timestamp'         // parsed to Date; used by timeline/heatmap
       | 'string'           // plain text
       | 'enum'             // finite set of values; filter renders as multi-select
       | 'ip'               // IP address; enables geo/subnet filter helpers
       | 'integer';         // numeric; enables range filters
  filterable: boolean;      // whether the filter bar includes this field
  displayDefault: boolean;  // whether this column is visible by default in the table
}
```

Example entry:

```js
{ key: 'level',    label: 'Level',    type: 'enum',      filterable: true,  displayDefault: true  }
{ key: 'datetime', label: 'Datetime', type: 'timestamp', filterable: false, displayDefault: true  }
{ key: 'eventId',  label: 'Event ID', type: 'integer',   filterable: true,  displayDefault: true  }
{ key: 'details',  label: 'Details',  type: 'string',    filterable: false, displayDefault: false }
```

#### `normalizeRow(rawFields, colIndex)` → `object`
Pure function. Takes the raw split field array from the CSV parser and the column-name-to-index map, and returns a normalised row object whose keys match `schema[].key`.

```js
normalizeRow(rawFields, colIndex) {
  return {
    datetime: rawFields[colIndex['Datetime']] ?? '',
    channel:  rawFields[colIndex['Channel']]  ?? '',
    eventId:  parseInt(rawFields[colIndex['EventID']], 10) || 0,
    level:    rawFields[colIndex['Level']]    ?? '',
    computer: rawFields[colIndex['Computer']] ?? '',
    provider: rawFields[colIndex['Provider']] ?? '',
    details:  rawFields[colIndex['Details']]  ?? '',
  };
}
```

**Contract:** Must be a pure function with no side effects. Must never throw — use `?? ''` or `|| 0` fallbacks.

#### `colorFn(row)` → `string`
Returns a CSS color string for the row based on severity or level. Used by the timeline and the table row highlight. Return `''` for no highlight.

```js
colorFn(row) {
  switch (row.level) {
    case 'crit':  return '#ff4444';
    case 'high':  return '#ff8800';
    case 'med':   return '#ffcc00';
    case 'low':   return '#4488ff';
    default:      return '';
  }
}
```

#### `tabs[]` — `TabDef[]`
Module-specific tabs rendered in the analysis panel alongside the core tabs (Timeline, Table, Heatmap).

```ts
interface TabDef {
  id: string;                          // unique tab identifier
  label: string;                       // tab button label
  render(container: HTMLElement): void; // called when tab becomes active; draws into container
}
```

The core manages tab activation state. `render` will be called each time the tab is shown and must handle re-renders gracefully (clear `container.innerHTML` first).

#### `filterFields[]` — `FilterDef[]`
Filter controls this module contributes to the filter bar. The core renders these in order after its own built-in controls.

```ts
interface FilterDef {
  key: string;       // must match a schema[].key
  label: string;     // filter label
  type: 'text'       // free-text substring match
      | 'select'     // multi-select from enum values
      | 'range';     // min/max for integer/timestamp fields
}
```

---

## 4. Core Module Registry (`es-core.js`)

The registry lives on the global `S` (state) object and is populated at startup by each module file's self-registration call.

### State Properties

```js
S.modules       // Array<ModuleDef> — all registered modules in registration order
S.activeModule  // ModuleDef | null — the module currently in use, set by detectModule()
```

### Functions (defined in `es-module-api.js`, exposed on `S`)

#### `registerModule(mod)`
Validates `mod` against the required interface fields and pushes it onto `S.modules`. Throws a descriptive error if any required field is missing — this surfaces misconfigured modules at load time rather than silently at parse time.

```js
function registerModule(mod) {
  const required = ['id', 'label', 'requiredHeaders', 'schema', 'normalizeRow', 'colorFn', 'tabs', 'filterFields'];
  for (const field of required) {
    if (mod[field] === undefined) throw new Error(`Module missing required field: ${field}`);
  }
  S.modules.push(mod);
}
```

#### `detectModule(headers)`
Given the array of header strings from the uploaded CSV, returns the first module whose `requiredHeaders` are all present in `headers` (strict subset match, case-sensitive). Sets `S.activeModule` and returns the module, or `null` if no match.

```js
function detectModule(headers) {
  const headerSet = new Set(headers);
  for (const mod of S.modules) {
    if (mod.requiredHeaders.every(h => headerSet.has(h))) {
      S.activeModule = mod;
      return mod;
    }
  }
  S.activeModule = null;
  return null;
}
```

#### `strictDetect(headers)` (helper)
Same logic as `detectModule` but returns a diagnostics object for display in the error panel when no module matches:

```js
{
  matched: false,
  actualHeaders: string[],
  candidates: [
    {
      moduleId: string,
      moduleLabel: string,
      requiredHeaders: string[],
      missing: string[],   // headers in requiredHeaders not found in the file
      extra: string[]      // headers in the file not in requiredHeaders (informational)
    }
  ]
}
```

The error panel renders `missing` headers in red for each candidate module, giving the user (or preprocessor author) exact guidance on what the file is lacking.

---

## 5. Module Detection — Strict Header Matching

Detection is **strict subset matching only**. A module matches if and only if every entry in `requiredHeaders` is present in the file's actual headers.

### Rules

- Matching is **case-sensitive** — `EventID` ≠ `eventid`
- Extra columns in the file are ignored (modules may use them via `normalizeRow` but are not required to)
- If more than one module matches (ambiguous headers), the first registered module wins — order modules from most specific to least specific in `index.html`
- There is no fuzzy matching, no column-name aliasing, and no fallback guessing

### Error Panel on Unknown Format

When `detectModule` returns `null`, the UI shows a structured error panel:

```
Unknown file format.

Your file headers:
  Datetime, Channel, EventID, Level, Computer, Provider, Details, ExtraCol

Available modules:
  ✗ Windows Event Log (Hayabusa / EvtxECmd)
      Required: Datetime, Channel, EventID, Level, Computer, Provider, Details
      Missing:  (none — this should have matched, check case)

  ✗ MFT (MFTECmd)
      Required: FileName, ParentPath, Created0x10, LastModified0x10, Extension, FileSize, IsDirectory
      Missing:  FileName, ParentPath, Created0x10, LastModified0x10, Extension, FileSize, IsDirectory
```

This panel tells the user exactly which preprocessor to run and what output columns are expected.

---

## 6. File Structure

### New Files

| File | Purpose |
|---|---|
| `es-module-api.js` | Module registry (`S.modules`, `registerModule`, `detectModule`, `strictDetect`) |
| `es-mod-eventlog.js` | Event log module definition: `requiredHeaders`, `schema`, `normalizeRow`, `colorFn`, `filterFields` |
| `es-mod-eventlog-views.js` | Event log specific tabs: EID Focus, Lateral Movement, Sequence |
| `es-mod-mft.js` | MFT module definition (MFTECmd output): same interface |
| `es-mod-mft-views.js` | MFT specific tabs |

### Future Modules (pattern)

Each new format gets exactly two files:
- `es-mod-{id}.js` — module definition (data contract)
- `es-mod-{id}-views.js` — module-specific tabs and visualisations

### Existing Files (unchanged role)

| File | Role after migration |
|---|---|
| `es-core.js` | State init, streaming CSV parser, core UI bootstrap |
| `es-parsers.js` | Shared parsing utilities (date normalisation, IP parsing, etc.) — format-agnostic helpers only |
| `es-filters.js` | Filter bar rendering and filter logic — driven by `filterFields[]` from active module |
| `es-charts.js` | Timeline and heatmap rendering — uses normalised `timestamp` field |
| `es-views.js` | Core tab rendering (Timeline, Table, Heatmap) — format-agnostic |
| `es-dedup.js` | Deduplication logic — operates on normalised rows |
| `es-export.js` | CSV/JSON export — operates on normalised rows |
| `es-prefs.js` | Column config and session persistence |

---

## 7. Migration Strategy

The migration from the current monolithic structure to the module architecture must not break existing event log functionality at any step.

### Step 1 — Introduce `es-module-api.js`
Create the file with `registerModule`, `detectModule`, and `strictDetect`. At this stage, the event log detection logic in `es-parsers.js` is left in place as a fallback. No behaviour change yet.

### Step 2 — Extract event log module definition
Create `es-mod-eventlog.js` with the event log's `id`, `label`, `requiredHeaders`, `schema`, `colorFn`, and `filterFields` ported from the existing constants and logic in `es-parsers.js`. The `normalizeRow` implementation is extracted from the current row-parsing code.

Call `registerModule(EventLogModule)` at the bottom of the file.

### Step 3 — Wire `detectModule` into the file load path
In the file-load handler (currently in `es-core.js` or `es-parsers.js`), replace the existing format detection with `detectModule(headers)`. The error panel should now use `strictDetect` output.

### Step 4 — Extract event log views
Create `es-mod-eventlog-views.js` with the EID Focus, Lateral Movement, and Sequence tabs extracted from `es-views.js`. Attach them to the event log module's `tabs[]`. Core views file should only contain format-agnostic tabs after this step.

### Step 5 — Clean up `es-parsers.js`
Remove format-specific constants (level maps, known EID lists, etc.) that have been moved into the module files. `es-parsers.js` should contain only shared utilities.

### Step 6 — Implement MFT module
Once the event log migration is stable and tested, implement `es-mod-mft.js` + `es-mod-mft-views.js` following the same pattern.

### Validation at each step
After each step: load a Hayabusa CSV and verify the full feature set (timeline, heatmap, all tabs, filters, export, dedup, column config) works identically to the pre-migration baseline.

---

## 8. Developer Workflow — Adding a New Module

To add support for a new forensic CSV format:

### 1. Define `requiredHeaders` and `schema`

Examine the output format of the tool (MFTECmd, Chainsaw, RECmd, etc.) and identify the minimum set of columns that unambiguously identify this format. These become `requiredHeaders`.

Map each relevant column to a `schema` entry with an appropriate `type`. Be conservative with `type: 'enum'` — only use it when the value space is small and known in advance.

### 2. Implement `es-mod-{id}.js`

```js
// es-mod-mft.js
const MftModule = {
  id: 'mft',
  label: 'MFT (MFTECmd)',
  requiredHeaders: ['FileName', 'ParentPath', 'Created0x10', 'LastModified0x10', 'Extension', 'FileSize', 'IsDirectory'],
  schema: [
    { key: 'fileName',         label: 'File Name',       type: 'string',    filterable: true,  displayDefault: true  },
    { key: 'parentPath',       label: 'Parent Path',     type: 'string',    filterable: true,  displayDefault: true  },
    { key: 'created',          label: 'Created',         type: 'timestamp', filterable: false, displayDefault: true  },
    { key: 'lastModified',     label: 'Last Modified',   type: 'timestamp', filterable: false, displayDefault: true  },
    { key: 'extension',        label: 'Extension',       type: 'enum',      filterable: true,  displayDefault: true  },
    { key: 'fileSize',         label: 'File Size',       type: 'integer',   filterable: false, displayDefault: true  },
    { key: 'isDirectory',      label: 'Is Directory',    type: 'enum',      filterable: true,  displayDefault: false },
  ],
  normalizeRow(rawFields, colIndex) {
    return {
      fileName:     rawFields[colIndex['FileName']]         ?? '',
      parentPath:   rawFields[colIndex['ParentPath']]       ?? '',
      created:      rawFields[colIndex['Created0x10']]      ?? '',
      lastModified: rawFields[colIndex['LastModified0x10']] ?? '',
      extension:    rawFields[colIndex['Extension']]        ?? '',
      fileSize:     parseInt(rawFields[colIndex['FileSize']], 10) || 0,
      isDirectory:  rawFields[colIndex['IsDirectory']]      ?? '',
    };
  },
  colorFn(row) {
    // No severity colouring for MFT; return empty for no highlight
    return '';
  },
  filterFields: [
    { key: 'extension',  label: 'Extension',     type: 'select' },
    { key: 'fileName',   label: 'File Name',     type: 'text'   },
    { key: 'parentPath', label: 'Parent Path',   type: 'text'   },
  ],
  tabs: [], // populated by es-mod-mft-views.js
};

registerModule(MftModule);
```

### 3. Implement `es-mod-{id}-views.js`

Add tab definitions to the module's `tabs[]` array after the module is registered. Tabs can be pushed in the views file:

```js
// es-mod-mft-views.js
MftModule.tabs.push(
  {
    id: 'mft-timeline',
    label: 'File Timeline',
    render(container) {
      container.innerHTML = '';
      // render MFT-specific visualisation using S.filteredRows
    }
  },
  {
    id: 'mft-extensions',
    label: 'Extensions',
    render(container) {
      container.innerHTML = '';
      // render extension frequency chart
    }
  }
);
```

### 4. Add script tags to `index.html`

Add the new module files in the correct load order (see Section 9):

```html
<script src="es-mod-mft.js"></script>
<script src="es-mod-mft-views.js"></script>
```

That's it. No changes to core files required.

---

## 9. Script Loading Order

Scripts must be loaded in this exact order. Dependencies flow strictly downward — no file should reference a symbol defined in a later file.

```html
<!-- Core state and CSV parser -->
<script src="es-core.js"></script>

<!-- Module registry (registerModule, detectModule, strictDetect) -->
<script src="es-module-api.js"></script>

<!-- Module definitions — each calls registerModule() at load time -->
<script src="es-mod-eventlog.js"></script>
<script src="es-mod-eventlog-views.js"></script>
<script src="es-mod-mft.js"></script>
<script src="es-mod-mft-views.js"></script>
<!-- future: <script src="es-mod-{id}.js"></script> -->
<!-- future: <script src="es-mod-{id}-views.js"></script> -->

<!-- Shared parsing utilities (date normalisation, IP parsing, etc.) -->
<script src="es-parsers.js"></script>

<!-- Filter bar — reads S.activeModule.filterFields -->
<script src="es-filters.js"></script>

<!-- Chart rendering — timeline, heatmap -->
<script src="es-charts.js"></script>

<!-- Core tab rendering — Table, Timeline, Heatmap -->
<script src="es-views.js"></script>

<!-- Deduplication logic -->
<script src="es-dedup.js"></script>

<!-- Export logic -->
<script src="es-export.js"></script>

<!-- Column config and session preferences -->
<script src="es-prefs.js"></script>

<!-- Inline init — wires file input, triggers initial state -->
<script>
  // S is ready; all modules registered; call init()
</script>
```

### Dependency Notes

- `es-module-api.js` must load before any module file because modules call `registerModule` at load time
- View files (`es-mod-{id}-views.js`) must load after their corresponding module file because they mutate `tabs[]` on the module object
- `es-filters.js`, `es-views.js`, `es-charts.js` must load after all module files so they can safely read `S.activeModule` on first render
- The inline init block runs last, after all symbols are defined

---

## Appendix: Interface Checklist for Module Authors

Use this checklist when implementing a new module to verify compliance before adding script tags to `index.html`:

- [ ] `id` is a lowercase string with no spaces, unique across all modules
- [ ] `label` is a descriptive human-readable string
- [ ] `requiredHeaders` contains at least 3 columns that together uniquely identify this format
- [ ] Every entry in `schema` has `key`, `label`, `type`, `filterable`, and `displayDefault`
- [ ] `normalizeRow` returns an object with a key for every `schema` entry
- [ ] `normalizeRow` never throws — all field accesses use `?? ''` or `|| 0` fallbacks
- [ ] `colorFn` returns a CSS color string or `''` — never `undefined`
- [ ] Every tab in `tabs[]` clears `container.innerHTML` at the start of `render`
- [ ] Every entry in `filterFields` has a `key` that matches a `schema[].key`
- [ ] `registerModule(MyModule)` is the last line of `es-mod-{id}.js`
- [ ] Script tags are added to `index.html` in the correct order
