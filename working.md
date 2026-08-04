# DefenderAtlas — How It Works

This document explains, end to end, what DefenderAtlas does and exactly how it
works: the two pipelines (collection and analysis), every CLI command, every
module, the data flow, and the on-disk artifacts.

---

## 1. What DefenderAtlas Is

DefenderAtlas is a Python 3.12+ framework for **reverse-engineering how
Microsoft Defender scans files**. The core idea:

1. **Collect** real scans: run Defender against a file while a Sysinternals
   **ProcMon** trace records every file read Defender makes.
2. **Filter** the trace down to *Defender's* reads of *that file*.
3. **Map** each read to a PE structure (DOS header, import table, `.text`, …).
4. **Analyze** the result: how many times each byte range is read, in what
   order, and which structural phases the scan goes through.

The output is per-sample **experiments** (JSON + filtered CSV) plus aggregate
statistics, intended to reveal detection logic and evasion opportunities.

Two important facts about the current state:

- **The Collector (`collect`) is fully implemented and Windows-specific.**
- **Several engines are stubs**: `capture`, `visualize` and `report` are
  placeholders, and the non-PE `analyzers` raise `NotImplementedError` in
  `analyze()`. The analysis library (parser, statistics, mapping, timeline,
  phase detection) is real and tested.

---

## 2. High-Level Architecture

```
┌─────────────────────────── COLLECTION PIPELINE ───────────────────────────┐
│                                                                           │
│  dataset/  ──► enumerate_samples()  ──►  per sample:                      │
│    sample.exe            (SHA-256, size, category)                        │
│    lib.dll                                                               │
│    driver.sys                                                             │
│                                    │                                      │
│                                    ▼                                      │
│  1. ExperimentDirectory allocates experiments/000001/                     │
│  2. ProcmonController.start(pml)  ── elevated scheduled task OR direct    │
│  3. wait_until_ready()  (PML file appears)                                │
│  4. AttachmentTrigger.run(sample)  ── trigger_worker.exe reproduces       │
│     IAttachmentExecute::Save download scan                                │
│  5. sleep(trigger_timeout_ms)  (let Defender finish)                      │
│  6. ProcmonController.stop()     (/Terminate)                             │
│  7. ProcmonController.export_csv()  (PML → CSV via /OpenLog /SaveAs)      │
│  8. ProcmonFilter.filter_csv()  ── Defender-only rows → filtered.csv      │
│  9. write metadata.json / manifest.json / trigger.json                    │
│                                                                           │
│  Result per sample: experiments/000001/{sample.exe,capture.pml,           │
│     capture.csv, filtered.csv, metadata.json, manifest.json, trigger.json}│
└───────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────── ANALYSIS PIPELINE ─────────────────────────────┐
│                                                                           │
│  filtered.csv  ──► parse_procmon_csv()  ──► ReadEvent stream              │
│                      │                                                   │
│                      ├─► compute_statistics()       ──► Statistics        │
│                      │                                                   │
│                      ├─► map_events(pe, events)     ──► MappedReadEvent   │
│                      │     (PE regions via pefile + binary search)        │
│                      │         │                                          │
│                      │         ├─► compute_region_statistics() ──► per-   │
│                      │         │    region read counts / bytes / pct      │
│                      │         │                                          │
│                      │         └─► build_timeline() ──► TimelineResult    │
│                      │                 │                                  │
│                      │                 └─► PhaseDetector.detect() ──►     │
│                      │                      phases + confidence           │
│                      └─► (future) Analyzer.analyze() ──► AnalysisResult   │
└───────────────────────────────────────────────────────────────────────────┘
```

Entry point is the Typer CLI `defenderatlas` (defined in
`src/defenderatlas/cli/app.py`, wired in `pyproject.toml` as
`defenderatlas = "defenderatlas.cli.app:app"`).

---

## 3. Installation

```bash
pip install -e .          # runtime (typer, rich, pydantic, pefile)
pip install -e ".[dev]"   # + ruff, black, mypy, pytest, pre-commit
```

Runtime dependencies (`pyproject.toml`):

| Package   | Purpose                            |
|-----------|------------------------------------|
| `typer`   | CLI framework                      |
| `rich`    | Terminal tables / panels           |
| `pydantic`| All data models (strict validation)|
| `pefile`  | Parsing PE files for region mapping|

---

## 4. CLI Reference

Global option: `-V, --verbose` (debug logging).

| Command | Purpose | Status |
|---|---|---|
| `defenderatlas version` | Print version | Working |
| `defenderatlas install` | Register the elevated ProcMon scheduled task(s) | Working |
| `defenderatlas uninstall` | Remove those scheduled tasks | Working |
| `defenderatlas analyze <trace.csv>` | Statistics over a ProcMon CSV | Working |
| `defenderatlas collect <dataset>` | Full capture pipeline for a dataset | Working |
| `defenderatlas capture <file>` | Capture engine | Placeholder |
| `defenderatlas visualize <data>` | Charts | Placeholder |
| `defenderatlas report <data>` | Reports | Placeholder |

> Note: there is **no** `--version` flag; use `defenderatlas version`
> (the README's `defenderatlas --version` is stale).

### 4.1 `defenderatlas analyze <trace.csv>`

Parses the CSV, keeps only read operations, and prints:

```
Statistics Summary
  Total Reads        total read events
  Unique Offsets     distinct offsets touched
  Repeated Reads     reads of an already-touched offset
  Bytes Read         sum of lengths
  Read Amplification bytes_read / file_size  (N/A without file size)
  Processing Time    parse vs compute split
```

Errors: missing/invalid headers → exit 1 with a format panel; no read events →
warning "No read events found"; unreadable rows are skipped (logged).

### 4.2 `defenderatlas install / uninstall`

Creates/removes the **three** Windows scheduled tasks that run ProcMon
elevated (see §5.3). Options: `--procmon <exe>` (auto-detect when omitted,
honours `DEFENDERATLAS_PROCMON`) and `--task-name` (default
`DefenderAtlas ProcMon`).

### 4.3 `defenderatlas collect <dataset>`

The main capture command. Full option list:

| Option | Default | Meaning |
|---|---|---|
| `-o, --output` | `experiments` | Experiment root dir |
| `--working-directory` | `~/Downloads` | Where triggered copies are placed |
| `--procmon` | auto-detect | Procmon64.exe path |
| `--trigger-worker` | auto-detect | trigger_worker.exe path |
| `--source-url` | `https://example.com/download` | Origin URL recorded in trigger.json |
| `--profile` | `minimal` | `minimal` \| `extended` \| `full` |
| `--completion-strategy` | `timeout` | Only `timeout` implemented |
| `--trigger-timeout` (ms) | 8000 | Sleep after triggering |
| `--worker-timeout` (ms) | 30000 | Worker subprocess timeout |
| `--procmon-ready-timeout` (ms) | 15000 | Wait for PML to appear |
| `--procmon-stop-timeout` (ms) | 15000 | Wait for ProcMon to exit |
| `--procmon-export-timeout` (ms) | 120000 | PML→CSV export timeout |
| `--procmon-launch-method` | `auto` | `auto` \| `process` \| `task` |
| `--scheduled-task-name` | `DefenderAtlas ProcMon` | Task used when not elevated |

---

## 5. The Collection Pipeline (module by module)

### 5.1 `capture/dataset.py` — sample discovery

- `SUPPORTED_SUFFIXES = {".exe", ".dll", ".sys"}`.
- `enumerate_samples(root)` walks the tree recursively (`rglob`), and for each
  matching file computes `size`, `sha256` (streamed, 1 MiB chunks), a
  `relative_path` (POSIX-style), and a `category` (the first path segment, or
  `""`). Unreadable files are counted as **skipped**, never fatal.
- Returns `(samples_sorted, skipped_count)`.

### 5.2 `capture/experiment.py` — experiment directories

- `ExperimentDirectory` allocates `experiments/<id>` where `id = max existing
  numeric dir + 1`, zero-padded to **6 digits** (`000001`, `000002`, …). IDs are
  never reused.
- Each experiment dir has fixed file paths:

| File | Property | Content |
|---|---|---|
| `sample.exe` | `sample_path` | Copy of the sample (stored under this name) |
| `capture.pml` | `pml_path` | Raw ProcMon capture |
| `capture.csv` | `csv_path` | PML exported to CSV |
| `filtered.csv` | `filtered_csv_path` | Defender-only rows |
| `metadata.json` | `metadata_path` | Experiment descriptor |
| `manifest.json` | `manifest_path` | Artifact index |
| `trigger.json` | `trigger_info_path` | Reproduction record |

### 5.3 `capture/taskscheduler.py` — elevation without UAC

**Why:** ProcMon loads a kernel driver, so every invocation (capture,
`/Terminate`, `/OpenLog`) must run **elevated**. Launching Procmon64.exe
directly from an unelevated process pops a UAC prompt on every capture.

**Solution:** three Windows scheduled tasks registered **once** (via
`defenderatlas install`, run as admin) with *Run with highest privileges*:

| Task | Runs | Purpose |
|---|---|---|
| `<task_name>` | `launch_procmon.cmd` | capture: `/Quiet /BackingFile <pml>` |
| `<task_name> Stop` | `launch_procmon_stop.cmd` | terminate: `/Terminate` |
| `<task_name> Export` | `launch_procmon_export.cmd` | export: `/OpenLog /SaveAs` |

Because a scheduled task can't take per-launch arguments, each task runs a
small **launcher script** in `%LOCALAPPDATA%\DefenderAtlas`:

- `launch_procmon.cmd` reads the target PML path from `pml_path.txt`.
- `launch_procmon_export.cmd` reads `pml_path` + `csv_path` from
  `export_args.txt`.

The Collector writes those arg files and calls `Start-ScheduledTask`, which
works from an unelevated process for a task registered to the current user.

Key functions: `task_exists`, `install_procmon_task` (registers all three),
`uninstall_procmon_task`, `launch_procmon_task`, `terminate_procmon_task`,
`export_procmon_task`, `is_task_running`. All PowerShell via `_run_ps`
(cmdlets: `Get-ScheduledTask`, `Register-ScheduledTask`,
`Unregister-ScheduledTask`, `Start-ScheduledTask`,
`Get-ScheduledTaskInfo`).

### 5.4 `capture/procmon.py` — ProcMon lifecycle controller

`ProcmonController` owns one capture session. Public API:

- `start(pml_path)` — decides launch path (see below), unlinks any old PML.
- `wait_until_ready(timeout)` — polls until the PML file exists (a running
  capture creates it), with liveness checks (task state or process exit).
- `stop(timeout)` — runs `/AcceptEula /Terminate`, waits for the process to
  exit, force-kills as a fallback.
- `export_csv(pml, csv, timeout)` — runs `/AcceptEula /OpenLog <pml>
  /SaveAs <csv>`, fails if the CSV is missing/empty.
- `is_running()`, `find_procmon()`, `_is_elevated()`.

**Elevation decision** (`_is_elevated`):
- Non-Windows → treated as elevated (`True`).
- Windows → `ctypes.windll.shell32.IsUserAnAdmin()`.

**Launch method** (`--procmon-launch-method`):

| Method | Elevated process | Unelevated process |
|---|---|---|
| `auto` / `process` | direct `Popen` | scheduled task (if installed), else refuse |
| `task` | scheduled task, fall back to direct | scheduled task (if installed), else refuse |

The refusal is deliberate: launching ProcMon unelevated makes it self-relaunch
forever and never produce a backing file, so it is never attempted.

`find_procmon()` looks at `DEFENDERATLAS_PROCMON`, then fixed candidates
(`C:\ProcessMonitor\Procmon64.exe`, …), then `PATH`.

### 5.5 `capture/trigger.py` — reproducing the download scan

- The scan Defender performs on *downloaded* attachments is reproduced by
  `trigger_worker.exe` calling **`IAttachmentExecute::Save()`** out of process
  (crash-isolation: a shell background-thread crash kills only the worker).
- `AttachmentTrigger.run(local_path)` invokes
  `trigger_worker.exe <path> <source_url>` with `worker_timeout`, and returns a
  `TriggerResult(success, message)`.
- `find_trigger_worker()` looks at `DEFENDERATLAS_TRIGGER_WORKER`, then
  `collector/trigger_worker.exe` (repo-relative), then `PATH`.

### 5.6 `capture/collector.py` — orchestrator

`Collector(config).run()`:

1. `enumerate_samples(dataset_root)`.
2. For each sample, `collect_sample()`:
   - Allocate `ExperimentDirectory`, `shutil.copy2` the sample in as
     `sample.exe`.
   - Create a **working copy** in
     `working_directory/defenderatlas_<experiment_id>` (the trigger target),
     then run the pipeline:
     1. `ProcmonController.start(experiment.pml_path)`
     2. `wait_until_ready(procmon_ready_timeout)` — if not ready, warns and
        continues (so a failed capture still records an experiment)
     3. `trigger.run(working_copy)` — the scan reproduction
     4. `_wait_for_completion()` — `sleep(trigger_timeout_ms)`
     5. `procmon.stop(stop_timeout)`
     6. `procmon.export_csv(...)` → `capture.csv`
     7. If exported: `ProcmonFilter.filter_csv(capture.csv, filtered.csv)`
   - Write `metadata.json`, `manifest.json`, `trigger.json`.
   - Clean up the working-copy directory (always, even on failure).
3. Return `CollectionSummary(processed, successful, failed, skipped,
   elapsed_seconds, experiment_root)`.

Design rule: **a failure in any step never aborts the run** — the experiment is
recorded as `"failed"` and collection continues with the next sample.

### 5.7 `capture/filter.py` — Defender-only filtering

`ProcmonFilter(profile, sample_filename)` keeps a CSV row when **all** hold:

1. `Process Name` == `msmpeng.exe` (case-insensitive);
2. the sample's original file name appears in `Path`;
3. the operation is in the profile's operation set.

Operation sets:

| Profile  | Operations |
|---|---|
| `minimal` | CreateFile, ReadFile |
| `extended` | CreateFile, ReadFile, QueryInformationFile, QueryStandardInformationFile, CloseFile |
| `full` | all |

`filter_csv()` streams row-by-row, writing only matching rows to
`filtered.csv` (BOM preserved). Unknown profiles fall back to `minimal`.

### 5.8 `capture/metadata.py` — JSON artifacts

- `build_metadata(...)` → `metadata.json`: experiment id, sample name &
  relative path, SHA-256, size, trigger type, completion strategy, collector
  version, procmon profile, category, UTC timestamp, `result` (`success` |
  `failed`).
- `build_manifest(...)` → `manifest.json`: id, `status` (`completed` |
  `failed`), sample, and the capture artifact file names.
- `build_trigger_info(...)` → `trigger.json`: trigger type, source URL,
  working copy name, strategy, profile, collector version.

---

## 6. The Analysis Pipeline (module by module)

### 6.1 `models/core.py` — Pydantic v2 data models

| Model | Fields | Notes |
|---|---|---|
| `ReadEvent` | timestamp, process_name, process_id, operation, path, offset, length, result | One file read |
| `Statistics` | total_reads, unique_offsets, repeated_reads, bytes_read, read_amplification | Aggregate |
| `ScanPhase` | id, name, description, start_offset, end_offset (validated `end ≥ start`) | Phase label |
| `Finding` | title, severity, description, evidence | Severity: low/medium/high/critical |
| `AnalysisResult` | file_type, findings, phases, statistics | Top-level |

### 6.2 `parsers/procmon.py` — streaming CSV parser

- `parse_procmon_csv(source, *, skip_errors=True)` is a **generator** (constant
  memory). Accepts a path or an open text stream.
- Keeps only operations in `{ReadFile, IRP_MJ_READ, FastIORead}`.
- Requires headers `Time of Day, Process Name, PID, Operation, Path, Result,
  Detail` (else `HeaderError`).
- Extracts `Offset:` / `Length:` from the `Detail` column via regex (hex `0x…`
  or decimal, thousands-commas allowed).
- Timestamps: `HH:MM:SS.fffffff` — 7-digit fractions are truncated to 6
  (`datetime.strptime` limit).
- Malformed rows: skipped with a warning by default; raise `RowError` if
  `skip_errors=False`.
- Error taxonomy: `CSVFormatError`, `HeaderError`, `RowError`,
  `TimestampParseError`, `OffsetParseError`, `LengthParseError` (all in
  `parsers/errors.py`, subclass `ParserError`).

### 6.3 `statistics/compute.py` — global statistics

One O(n) pass: totals, a `set` of seen offsets (unique / repeated), and
`read_amplification = bytes_read / file_size` (0.0 when no file size given).
A value of `1.0` = every byte read once; `6.0` = file effectively read six
times (multi-pass scanning).

### 6.4 `mapping/pe_mapper.py` — PE structure mapping

`map_events(pe_path, events)` maps each `ReadEvent` to every `PERegion`
whose inclusive `[start, end]` intersects the read's `[offset, offset+len-1]`.

- Parses the PE once with `pefile`.
- Builds regions for: **DOS Header** (0..63), **DOS Stub**, **NT Headers**,
  **File Header**, **Optional Header**, **Section Table**, each **section**
  (named by its section name, e.g. `.text`), each populated **data directory**
  (Import, Export, Resource, Relocation, TLS, Debug, Certificate, Bound
  Import, Delay Import, IAT, COM Descriptor), and the **Overlay** (appended
  data after the last section — common payload-hiding location).
- Data-directory `VirtualAddress` values are RVAs, converted to file offsets
  via the section table (`_rva_to_file_offset`). The **Certificate Table** is
  special: its `VirtualAddress` is already a raw file offset.
- Lookup uses a **sorted regions list + binary search** (`bisect`) — O(log m +
  k) per event.
- Errors: `InvalidPEError` (not a PE / parse failure), `TruncatedPEError`
  (regions can't be built), `FileNotFoundError`.

### 6.5 `mapping/models.py` — region models

- `PERegion`: name, start_offset, end_offset (inclusive), description;
  `overlaps(offset, length)` tests intersection.
- `MappedReadEvent`: wraps the original `ReadEvent` + `matched_regions`
  (empty = unmapped read, e.g. padding).

### 6.6 `timeline/timeline_builder.py` — chronological reconstruction

- `build_timeline(mapped_events)` expands each event into one `TimelineEntry`
  per matched region (`"Unmapped"` if none), then sorts by
  `(timestamp, original_order)` — stable, preserving input order for equal
  timestamps and the simultaneity of cross-region reads.
- `TimelineResult` helpers: `timeline_by_region()`,
  `regions_in_order()`, `first/last_region_accessed()`,
  `most_frequently_visited_regions(n)`; carries `start_time`, `end_time`,
  `duration`.

### 6.7 `statistics/region_statistics.py` — per-region stats

`compute_region_statistics(mapped_events)` accumulates per region: `read_count`,
`unique_offsets`, `bytes_read`, plus percentages of aggregate reads/bytes.
Cross-region reads are counted in **every** touched region, so percentages may
sum to > 100% (intentional). Result sorted by `bytes_read` desc; helpers
`top_regions_by_reads(n)`, `top_regions_by_bytes(n)`.

### 6.8 `phases/phase_detector.py` — rule-based scan phases

- `PhaseRule`: `name`, `description`, `required_regions` (set, must all
  appear), `minimum_reads`, `optional_regions` (ordered list; when present,
  must appear in that order).
- `PhaseDetector.detect(timeline)`:
  - For each rule, collects all unclaimed entries whose region is relevant.
  - A `Phase` is created spanning first→last collected entry, with evidence.
  - Rules claim timestamps so later rules only see unclaimed entries.
  - **Confidence** = weighted mean of:
    - `rule_match` (40%) — fraction of rules matched;
    - `phase_coverage` (40%) — fraction of unique timestamps covered;
    - `phase_count_bonus` (20%) — `1 / (1 + len(phases))`.
- Other methods: `timeline_to_phases` (naive consecutive-run grouping),
  `matched_rules`, `unmatched_rules`, `phase_summary`.

### 6.9 `analyzers/` — file-type analyzers

- `Analyzer` ABC: `supports(path)` (fast magic sniff) + `analyze(path)` →
  `AnalysisResult`.
- `PEAnalyzer` — `supports()` checks `MZ`; `analyze()` returns a placeholder
  `AnalysisResult` (empty findings/phases, zeroed statistics).
- `PDFAnalyzer` (`%PDF`), `ZIPAnalyzer` (`PK\x03\x04`), `PNGAnalyzer`,
  `OfficeAnalyzer` — `supports()` works; `analyze()` raises
  `NotImplementedError`.

---

## 7. Data Flow — A Complete Example

Run:

```bash
defenderatlas collect samples/ -o experiments --trigger-timeout 8000
```

For each `samples/*.exe`:

1. `enumerate_samples` → `Sample(path, size, sha256, relative_path, category)`.
2. `ExperimentDirectory` → `experiments/000001/`.
3. Copy sample → `experiments/000001/sample.exe`.
4. Copy sample → `~/Downloads/defenderatlas_000001/<name>` (trigger target).
5. `ProcmonController.start(capture.pml)`:
   - elevated → direct launch; not elevated + task installed → task launch.
6. `wait_until_ready`: when `capture.pml` appears, Defender is being traced.
7. `trigger_worker.exe <working_copy> <source_url>` reproduces the attachment
   download → Defender scans the file → reads recorded by ProcMon.
8. `sleep(8s)`.
9. `/Terminate` stops the capture; ProcMon exits.
10. `/OpenLog capture.pml /SaveAs capture.csv` exports the trace.
11. `ProcmonFilter` keeps only `MsMpEng.exe` reads of `<filename>` →
    `filtered.csv`.
12. `metadata.json` (`result: success`), `manifest.json`
    (`status: completed`), `trigger.json` written.

Then analysis:

```bash
defenderatlas analyze experiments/000001/filtered.csv
```

`parse_procmon_csv` → `ReadEvent`s → `compute_statistics` → summary table.
For deeper analysis, the library API:

```python
from defenderatlas.parsers import parse_procmon_csv
from defenderatlas.statistics import compute_statistics, compute_region_statistics
from defenderatlas.mapping import map_events
from defenderatlas.timeline import build_timeline
from defenderatlas.phases import PhaseDetector, PhaseRule

events   = list(parse_procmon_csv("filtered.csv"))
stats    = compute_statistics(events)
mapped   = list(map_events("sample.exe", events))
regions  = compute_region_statistics(mapped)
timeline = build_timeline(mapped)
result   = PhaseDetector(rules).detect(timeline)
```

---

## 8. Configuration & Environment Variables

| Variable | Used by | Purpose |
|---|---|---|
| `DEFENDERATLAS_PROCMON` | `find_procmon` | Procmon64.exe path override |
| `DEFENDERATLAS_TRIGGER_WORKER` | `find_trigger_worker` | trigger_worker.exe path override |
| `LOCALAPPDATA` | taskscheduler `_launcher_dir` | Where launcher scripts + arg files live |

All capture timing knobs live on `CollectorConfig`
(`capture/collector.py:40`) with sensible Windows defaults; the CLI exposes
each as a `--*` flag (see §4.3).

---

## 9. Project Layout

```
src/defenderatlas/
├── __init__.py            # __version__ = "0.1.0"
├── analyzers/             # PEAnalyzer (+ PDF/ZIP/PNG/Office stubs)
├── capture/               # THE Collector
│   ├── collector.py       #   orchestrator
│   ├── dataset.py         #   sample discovery
│   ├── experiment.py      #   experiment dirs
│   ├── filter.py          #   Defender-only CSV filter
│   ├── metadata.py        #   JSON artifacts
│   ├── procmon.py         #   ProcMon lifecycle controller
│   ├── taskscheduler.py   #   elevated scheduled-task launcher
│   └── trigger.py         #   IAttachmentExecute reproduction
├── cli/
│   ├── app.py             # Typer app, all commands
│   └── _logging.py        # logging setup
├── detectors/             # (empty stub)
├── mapping/               # PE structure mapping
│   ├── errors.py, models.py, pe_mapper.py
├── models/core.py         # Pydantic models
├── parsers/               # errors.py, procmon.py (CSV parser)
├── phases/phase_detector.py
├── reports/               # (empty stub)
├── reverse/               # (empty stub)
├── statistics/            # compute.py, region_statistics.py
├── timeline/timeline_builder.py
├── utils/                 # (empty stub)
└── visualization/         # (empty stub)
```

Top-level dirs: `tests/` (471 tests, pytest), `docs/`, `datasets/`,
`collector/` (trigger_worker.exe), plus `analyzeers/` (sic, unused),
`baits/`, `CSVs/`, `reports/`, `trigger/`, `vishualizations/`.

---

## 10. Development Workflow

```bash
pip install -e ".[dev]"

ruff check src/ tests/          # lint (E,W,F,I,N,UP,B,A,C4,SIM,TCH,RUF)
ruff format --check src/ tests/ # format (line-length 88)
black --check src/ tests/       # black also enforces format
mypy src/                       # strict type checking
pytest                          # 471 tests, coverage enabled via addopts
```

CI (`.github/workflows/ci.yml`) runs the lint job on Python 3.12
(ruff check, ruff format, black, mypy) and the test job on Python 3.12 & 3.13.

### Testing notes (important)

- Tests use **fake ProcMon / trigger-worker scripts** (`tests/_fakes.py`) and a
  `fake_script_factory` fixture that writes `.cmd` (Windows) or shebang
  (POSIX) launchers.
- The collector/procmon lifecycle tests assume an **elevated process or a
  non-Windows host** (`_is_elevated()` returns `True` on POSIX). On an
  unelevated Windows machine the Collector routes through the real scheduled
  tasks, so run the suite elevated (`Start-Process ... -Verb RunAs`) or on the
  Linux CI runner.
- The Collector also leaves state via the scheduled-task path:
  `Stop-ScheduledTask` / `taskkill /F /IM Procmon64.exe` (elevated) clean up
  after interrupted runs.

---

## 11. Known Stubs & Future Work

- `capture`, `visualize`, `report` CLI commands are placeholders.
- `analyzer` `analyze()` for PDF/ZIP/PNG/Office raises `NotImplementedError`;
  `PEAnalyzer.analyze()` returns an empty placeholder result.
- `detectors/`, `reports/`, `reverse/`, `utils/`, `visualization/` are empty
  packages.
- `completion_strategy` only supports `"timeout"`.
- The phase detector's docstring describes a future gap-splitting feature.
