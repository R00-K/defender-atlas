# DefenderAtlas Collector

A permanent, extensible collection engine for DefenderAtlas. The Collector
reproduces Microsoft Defender's "new download" scan for every PE file in a
dataset, captures the resulting process/file/registry activity, and stores each
run as a self-contained experiment.

## Overview

For each sample the Collector:

1. allocates a new experiment directory under `experiments/0000NN/`
2. applies the configured ProcMon filter profile (`.pmc`) and derives a dynamic
   path filter from the sample's file name
3. copies the sample into the experiment directory and into the working
   directory (the "Downloads" location) under its original file name
4. starts ProcMon capturing to `capture.pml`
5. triggers the download event on the working copy
6. waits until the scan is considered finished (completion strategy)
7. stops ProcMon and exports the raw `capture.csv`
8. filters `capture.csv` down to `filtered.csv` using the profile and the
   dynamic path filter
9. runs the configured Analyzer on `filtered.csv` to produce `report.md`
10. writes `metadata.json`, `manifest.json` and `trigger.json` describing the
    experiment

A failure in any step never aborts the run: the Collector logs the problem,
records a `"failed"` experiment and continues with the next sample.

## Architecture

```
                    defenderatlas_collector.exe
                  ┌──────────────────────────────┐
   config.json ──▶│ main.cpp                     │
                  │   config.json ──▶ Config     │
                  │                              │
                   │   Collector                  │
                   │     ├─ DatasetEnumerator     │  sample discovery
                   │     ├─ ProcmonController     │  PML capture / CSV export
                   │     ├─ ProcmonFilter         │  profile + path filtering
                   │     ├─ Analyzer              │  report generation
                   │     ├─ ITrigger             │  download-event reproduction
                   │     └─ ICompletionStrategy   │  "scan finished" decision
                  └──────────────────────────────┘
                          │ spawns per experiment
                          ▼
                  ┌──────────────────────────────┐
                  │ trigger_worker.exe           │
                  │   IAttachmentExecute::Save() │
                  └──────────────────────────────┘
```

The Collector depends only on the `ITrigger` and `ICompletionStrategy`
abstractions, never on concrete trigger/strategy implementations.

## Trigger execution model

The actual download reproduction is `IAttachmentExecute`:

```
CoInitializeEx
CoCreateInstance(CLSID_AttachmentServices, ...)
SetLocalPath(file)
SetSource(url)
Save()
```

It is the verbatim refactor of the experimentally verified
`trigger/trigger_test.cpp`. The trigger runs **out of process**, in
`trigger_worker.exe`:

- `SubprocessTrigger` (the Collector's `ITrigger`) spawns one worker per
  experiment, waits for it, and reports the outcome.
- The worker performs exactly one `Save()` and exits immediately.

This process lifecycle is deliberate. `IAttachmentExecute::Save()` schedules
shell32 background threads (recycle-bin/shell-hook work) that can crash the
hosting process at a non-deterministic point *after* `Save()` returns — observed
reliably on the DefenderAtlas test environment. A crash there would otherwise
kill the whole collection run, violating the "never terminate on one failed
sample" guarantee. Isolating the trigger in a short-lived worker means:

- the process lifecycle matches the verified trigger, and
- any shell crash kills only the worker; the Collector records the experiment
  as failed and continues.

## Configuration

All runtime values are loaded from `config.json` (see `config.cpp` for defaults):

| key | purpose |
| --- | --- |
| `procmon_path` | path to Procmon64.exe |
| `dataset_root` | sample tree to enumerate |
| `experiment_root` | per-experiment output directory root |
| `working_directory` | where triggered samples are placed |
| `trigger_timeout_ms` | how long the completion strategy waits after a trigger |
| `trigger_worker_timeout_ms` | max wait for `trigger_worker.exe` to finish |
| `source_url` | URL reported as the download origin |
| `trigger_worker_path` | path to `trigger_worker.exe` |
| `procmon_ready_timeout_ms` | max wait for ProcMon readiness |
| `procmon_stop_timeout_ms` | max wait for ProcMon shutdown |
| `procmon_export_timeout_ms` | max wait for PML → CSV export |
| `procmon_filter_profile` | `minimal`, `extended` or `full` |
| `completion_strategy` | `timeout` (implemented) or `procmon_activity` (stub) |
| `analyzer_path` | path to the Analyzer executable (empty = auto-generated report) |
| `analyzer_timeout_ms` | max wait for the Analyzer to finish |

Relative paths are resolved against the directory containing `config.json`.

If no config file exists, a default template is written and the process exits.

## ProcMon filter profiles

The `procmon_filter_profile` key selects how activity is narrowed down before
it is handed to the Analyzer:

- `minimal` — only `MsMpEng.exe` doing `CreateFile` / `ReadFile` (default)
- `extended` — adds `QueryInformationFile` / `QueryStandardInformationFile` /
  `CloseFile`
- `full` — all `MsMpEng.exe` operations, no operation filtering

The profile is written to `procmon_filter.pmc` (ProcMon XML filter format) in
each experiment, and the same rule set is applied to the exported `capture.csv`
to produce `filtered.csv`. The path condition is generated per experiment from
the sample's file name (e.g. `disk.sys`), so it never needs manual editing.

## Analyzer

After `filtered.csv` is produced, the Collector runs the executable named by
`analyzer_path` with the filtered CSV path and the report path as arguments.
The Analyzer writes a markdown report to `report.md`. If no Analyzer is
configured (empty path), the Collector generates a fallback report itself and
records `"analysis": "skipped"` in `metadata.json`; a failing or timed-out
Analyzer also falls back and records `"failed"`.

## Experiment lifecycle

Each experiment is a directory `experiments/0000NN/` containing:

- `sample.exe` — the sample copy that was triggered
- `capture.pml` — raw ProcMon trace (only with a working ProcMon)
- `capture.csv` — raw exported trace (never overwritten)
- `filtered.csv` — profile + path filtered trace, the Analyzer input
- `procmon_filter.pmc` — the applied ProcMon filter rules
- `report.md` — Analyzer output
- `metadata.json` — experiment descriptor
- `manifest.json` — artifact inventory for the experiment
- `trigger.json` — reproduction record (trigger, source URL, strategy, profile)

`metadata.json` records the sample identity (SHA-256, size), the trigger and
completion strategy used, the filter profile, signature/category, the analysis
outcome (`"completed"`/`"skipped"`/`"failed"`), a UTC timestamp and the result
(`"success"`/`"failed"`). The Collector version is recorded as `1.1`.

Experiment IDs auto-increment; existing experiments are never overwritten.

## Building

```
powershell -ExecutionPolicy Bypass -File collector\build.ps1
```

Produces `defenderatlas_collector.exe` and `trigger_worker.exe`. Requires MinGW
g++ (C++17). Links ole32, wintrust, crypt32 and bcrypt.

## Running

```
defenderatlas_collector.exe [path\to\config.json]
```

Without an argument, `config.json` in the current directory is used. Point
`trigger_worker_path` at the built worker (defaults to `trigger_worker.exe`
next to the config).

## Extension points

- `ITrigger` — new download-event reproductions (BrowserTrigger,
  ShellExecuteTrigger, SmartScreenTrigger, ExplorerTrigger, CloudTrigger, ...).
  The Collector's trigger runs in-process only if the implementation is safe;
  otherwise wrap it in a worker subprocess like `SubprocessTrigger`.
- `ICompletionStrategy` — alternative "scan finished" decisions (e.g. based on
  Defender event log activity instead of a fixed timeout).
- `ProcmonController` — future capture backends (ETW, Sysmon) can replace the
  ProcMon lifecycle behind the same experiment-directory contract.
