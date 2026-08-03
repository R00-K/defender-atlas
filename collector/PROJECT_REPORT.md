# DefenderAtlas Collector — Project Status Report

_Prepared for continuation of work (handoff document)._

## 1. Objective

Build **DefenderAtlas Collector v1.1**: a permanent, extensible collection engine
for the DefenderAtlas project. It automatically reproduces Microsoft Defender's
"new download" scan (the pattern Defender shows after a browser downloads an
untrusted PE) for every PE file in a dataset, captures the resulting
process/file/registry activity with Sysinternals ProcMon, and stores each run
as a self-contained, metadata-tagged experiment. It must **never terminate the
whole run because a single sample failed**.

v1.1 adds: ProcMon filter profiles, per-experiment dynamic path filters,
a raw + filtered CSV output pair, automatic Analyzer integration
(`report.md`), extended metadata, per-experiment `manifest.json` /
`trigger.json`, pluggable completion strategies, and improved logging.

## 2. Location & Toolchain

- Project root: `\\VBoxSvr\000\DefenderAtlas`
- Collector source: `\\VBoxSvr\000\DefenderAtlas\collector\`
- Compiler: MinGW g++ 15.2.0 (`C:\ProgramData\mingw64\mingw64\bin\g++.exe`), C++17
- Build: `build.ps1` (must be run with `powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1`)
- Output binaries: `defenderatlas_collector.exe`, `trigger_worker.exe`
- Compile flags: `-std=c++17 -O2 -Wall -Wextra -DUNICODE -D_UNICODE -municode`
- Link libs: `-lole32 -lwintrust -lcrypt32 -lbcrypt`
- `attachment_trigger.cpp` defines `INITGUID` so `CLSID_AttachmentServices` resolves
- The collector binary does NOT link the COM trigger code; only `trigger_worker.exe` does

## 3. Architecture

```
                defenderatlas_collector.exe
              ┌──────────────────────────────┐
 config.json ─▶ main.cpp                     │
              │   config.json ──▶ Config     │
              │                              │
              │   Collector                  │
              │     ├─ DatasetEnumerator     │  sample discovery
              │     ├─ ProcmonController     │  PML capture / CSV export
              │     ├─ ProcmonFilter         │  profile + dynamic path filter
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

Design rules that were enforced (unchanged from v1):
- The Collector depends only on the `ITrigger` and `ICompletionStrategy`
  abstractions — never on concrete implementations.
- The trigger COM sequence is a **verbatim refactor** of the experimentally
  verified `trigger/trigger_test.cpp` — no redesign.
- No `system()`; process launching uses `CreateProcessW`.
- No hardcoded `Sleep` in the Collector — "wait until scan done" is delegated
  to the pluggable completion strategy.
- Everything runtime-relevant is config-driven (no hardcoded paths in code).
- v1.1 classes are documented, modern C++17, no duplicated code, backward
  compatible with the v1 config/behavior.

### Per-sample pipeline (Collector::CollectSample)
1. Allocate experiment dir `experiments/0000NN/`
2. Apply the configured filter profile: write `procmon_filter.pmc` and derive a
   dynamic path filter from the sample's file name
3. Copy sample into experiment dir (`sample.exe`) and into the working
   directory as `working_directory/defenderatlas_<id>/<original filename>`
   (the original name is used so the path filter matches Defender activity)
4. Start ProcMon capturing to `capture.pml`
5. Wait until ProcMon is ready (skipped if it failed to start)
6. Trigger the download event on the working copy
7. Wait for the completion strategy
8. Stop ProcMon; export raw `capture.csv`
9. Filter `capture.csv` → `filtered.csv` using the profile + dynamic path filter
10. Run the Analyzer on `filtered.csv` → `report.md` (fallback report if no
    Analyzer configured or it fails/times out)
11. Write `metadata.json`, `manifest.json`, `trigger.json`
12. Any failure → log, record experiment `"failed"`, continue to next sample;
    the working-copy directory is cleaned up afterward

### Experiment output (`experiments/0000NN/`)
- `sample.exe` — copy of the triggered file
- `capture.pml` — raw ProcMon trace
- `capture.csv` — raw exported trace (never overwritten)
- `filtered.csv` — profile + path filtered trace; the Analyzer input
- `procmon_filter.pmc` — the applied ProcMon filter rules (XML)
- `report.md` — Analyzer output (or auto-generated fallback)
- `metadata.json` — experiment descriptor
- `manifest.json` — artifact inventory (pml/csv/filtered + report)
- `trigger.json` — reproduction record
- Experiment IDs auto-increment; existing experiments are never overwritten.

### metadata.json schema
`experiment_id`, `sample`, `relative_path`, `sha256`, `size`, `trigger`,
`completion_strategy`, `collector_version` (`"1.1"`), `procmon_profile`,
`signed`, `category`, `analysis` (`"completed"`/`"skipped"`/`"failed"`),
`timestamp`, `result` (`"success"`/`"failed"`).

## 4. Source Files

| file | role |
| --- | --- |
| `main.cpp` | entry point; loads config (writes default template if missing); wires Collector + SubprocessTrigger + completion strategy (config-driven); logs strategy/profile/analyzer |
| `collector.h/.cpp` | the collection engine, per-sample pipeline (filter → capture → export → filtered.csv → analyzer → metadata/manifest/trigger.json), failure tolerance |
| `itrigger.h` | `ITrigger` abstraction + `TriggerResult{success, message}` |
| `subprocess_trigger.h/.cpp` | `ITrigger` impl that spawns `trigger_worker.exe` per call, waits with timeout, captures stdout; uses shared `run_process` helper |
| `attachment_trigger.h/.cpp` | verbatim `IAttachmentExecute` refactor (used only by the worker) |
| `trigger_worker.cpp` | worker `main`: one Save + immediate exit |
| `istrategy.h`, `timeout_strategy.h/.cpp` | `ICompletionStrategy` + fixed-timeout implementation (kept exactly as v1) |
| `procmon_activity_strategy.h/.cpp` | **v1.1 stub** `ICompletionStrategy` (returns not-implemented/false); Collector can switch via config |
| `procmon_filter.h/.cpp` | **v1.1** profile model (minimal/extended/full), `Matches()` (process/operation/path), `.pmc` XML writer, CSV filter (`filter_csv` → `CsvFilterStats`) with quoted-field parsing |
| `procmon.h/.cpp` | `ProcmonController`; CreateProcess with `/AcceptEula /Quiet /Minimized /BackingFile <pml>` then `/OpenLog <pml> /SaveAs <csv>`; failure-tolerant |
| `dataset.h/.cpp` | dataset tree enumeration, relative paths, category derivation, skips unhashable samples with a warning |
| `experiment.h/.cpp` | experiment directory lifecycle, ID allocation, artifact paths |
| `metadata.h/.cpp` | metadata.json/manifest.json/trigger.json build/serialize; `kCollectorVersion` |
| `config.h/.cpp` | config model + JSON load/save; relative paths resolved against config dir |
| `json.h/.cpp` | minimal JSON parser/serializer |
| `log.h/.cpp` | thread-safe leveled logging (console + optional file), ISO8601 UTC |
| `util.h/.cpp` | SHA-256 (bcrypt), signature verification, UTF-8↔UTF-16, RAII ComInitializer/ComPtr/UniqueHandle, file/path helpers, **v1.1** shared `run_process` (args vector, timeout, output capture) |
| `config.json` | default config template (includes all v1.1 keys) |
| `build.ps1` | builds both executables; collector source list includes `procmon_filter.cpp` and `procmon_activity_strategy.cpp` |
| `README.md` | architecture + usage doc (updated for v1.1) |

## 5. Configuration Keys

| key | purpose |
| --- | --- |
| `procmon_path` | path to Procmon64.exe |
| `dataset_root` | sample tree to enumerate |
| `experiment_root` | per-experiment output root |
| `working_directory` | where triggered samples are placed |
| `trigger_timeout_ms` | completion strategy wait after a trigger (default 8000) |
| `trigger_worker_timeout_ms` | max wait for trigger_worker.exe (default 30000) |
| `source_url` | URL reported to `SetSource` (default `https://example.com/download`) |
| `trigger_worker_path` | path to trigger_worker.exe (default `trigger_worker.exe`) |
| `procmon_ready_timeout_ms` | max wait for ProcMon readiness (default 15000) |
| `procmon_stop_timeout_ms` | max wait for ProcMon shutdown (default 15000) |
| `procmon_export_timeout_ms` | max wait for PML→CSV (default 120000) |
| `procmon_filter_profile` | **v1.1** `minimal` / `extended` / `full` (default `minimal`; unknown → minimal) |
| `completion_strategy` | **v1.1** `timeout` (implemented) or `procmon_activity` (stub; default `timeout`) |
| `analyzer_path` | **v1.1** Analyzer executable (default `defenderatlas_analyzer.exe`; empty = auto-generated fallback report) |
| `analyzer_timeout_ms` | **v1.1** max wait for the Analyzer (default 60000) |

Relative paths are resolved against the directory containing `config.json`.

### Filter profiles
- `minimal` — `MsMpEng.exe` doing `CreateFile` / `ReadFile` only
- `extended` — minimal + `QueryInformationFile` / `QueryStandardInformationFile` / `CloseFile`
- `full` — all `MsMpEng.exe` operations, no operation filtering

The process name is matched case-insensitively; the dynamic path condition is
"Path contains <sample original file name>" (e.g. `disk.sys`), generated per
experiment — never hardcoded.

### Analyzer contract
Invoked as `run_process(analyzer_path, {filtered.csv, report.md}, analyzer_timeout_ms)`.
Exit 0 → `"analysis": "completed"`; timeout/nonzero → fallback report +
`"failed"`; empty/unset path → fallback report + `"skipped"`. The fallback
report records sample, SHA-256, profile, path filter, raw/filtered row counts.

## 6. The Bug That Was Found & Fixed

### Symptom
The Collector crashed deterministically on the **second** sample's trigger:
log stopped after `[INFO] Triggering sample (attachment): signed/tiny/find.exe`.
Exit codes varied: `-1073741819` (`0xC0000005` ACCESS_VIOLATION) and
`-1073740791` (`0xC0000409` STACK_BUFFER_OVERRUN). Reproduced 3/3 runs.

### Investigation
- Built a `-O0 -g` debug binary and ran under `gdb`. Backtrace showed the crash
  was **not in our code**:
  ```
  ShellHookProc (shell32.dll)
  SHEmptyRecycleBinW (shell32.dll)
  ... via Windows.Storage!ILCloneFirst ...
  ntdll worker thread
  ```
  A **background thread** spawned by the shell crashed with `0xC0000409`.
- Minimal reproductions:
  - Two sequential `Save()` calls in one process + 300 ms sleep → crash.
  - **One** `Save()` + 5 s sleep → `Save()` returned success, process crashed
    during the sleep (the background thread dies after the fact).
  - One `Save()` + **immediate exit** → 5/5 clean runs (this matches the
    originally verified `trigger_test.exe` lifecycle).

### Root cause
`IAttachmentExecute::Save()` schedules shell32 background work (recycle-bin /
shell-hook path, `ShellHookProc` → `SHEmptyRecycleBinW`). On the test
environment that background thread **crashes the whole process at a
non-deterministic point after Save() returns**. It cannot be guarded with
try/catch or SEH because it runs on an OS-owned thread pool thread, not ours.
An in-process trigger therefore violates the "never terminate the run" rule.

### Fix — worker-subprocess trigger
- `trigger_worker.exe`: performs exactly **one** Save and exits immediately
  (the exact process lifecycle that was verified to work). Protocol: exit code
  0 = success, 1 = trigger failed, 2 = bad args; the human-readable result
  message is printed to stdout.
- `SubprocessTrigger` (`subprocess_trigger.cpp`): the Collector's `ITrigger`
  impl. It builds the command line, creates an anonymous pipe for stdout,
  `CreateProcessW` the worker, `WaitForSingleObject` up to
  `trigger_worker_timeout_ms` (on timeout: `TerminateProcess`, record failure),
  reads stdout, and returns `TriggerResult` (message = worker stdout; failure
  detail includes the worker exit code).
- The Collector binary no longer links `attachment_trigger.cpp`; the COM
  machinery lives only in the worker.
- `trigger_timeout_ms` (completion strategy) was decoupled from the worker wait
  via the new `trigger_worker_timeout_ms` key, because a slow Defender /
  SmartScreen cloud check on an unsigned file can make one worker take seconds.

### Why this is correct
- Matches the experimentally verified deployment (one Save per short-lived
  process).
- Crash isolation: if shell32 kills the worker, only the worker dies; the
  Collector records `"failed"` and continues.

## 7. Verification Results

Test harness (local temp): `C:\Users\cruiz\AppData\Local\Temp\opencode\da_test\`
- `test_config.json` — intentionally invalid ProcMon path
  (`C:\nonexistent\Procmon64.exe`) so capture steps fail gracefully;
  `trigger_timeout_ms=5000`, `trigger_worker_timeout_ms=15000`,
  `completion_strategy=timeout`, `procmon_filter_profile=minimal`,
  `analyzer_path=""` (fallback report path)
- `full_test_config.json` — points `procmon_path` at a **fake ProcMon**
  (`fake_procmon.exe`) and `analyzer_path` at a fake analyzer
  (`fake_analyzer.exe`) for end-to-end validation without real ProcMon
- 3-sample dataset `ds\`:
  - `drivers/disk.sys` (101,856 B, catalog-signed → `signed=yes`)
  - `signed/tiny/find.exe` (17,920 B, catalog-signed → `signed=yes`)
  - `unsigned/hello/hello_tiny.exe` (signed=no)

Signature detection (embedded Authenticode + Windows catalog fallback via
mscat.h `CryptCATAdmin*` + `WTD_CHOICE_CATALOG`) verified on all three.

### v1 (worker-subprocess fix)
- All 3 triggers succeeded through the worker, worker wall-times 0.3–1.2 s each.
- No crash; Collector survived all experiments; correct `metadata.json`;
  working-copy dirs cleaned up.
- Crash-isolation proof: swapped in a worker that dereferences a null pointer.
  Collector logged `trigger worker exited with code 3221225477`
  (`0xC0000005`) for every sample and completed all 3 experiments.

### v1.1 (new pipeline)
- **End-to-end run with fake ProcMon + fake analyzer**: 2 of 3 experiments
  succeeded end-to-end; the 3rd (`hello_tiny.exe`) failed legitimately on the
  trigger (`Save failed: 0x80004005`, Defender/SmartScreen rejecting the
  unsigned file) and the Collector continued.
- Artifacts verified per experiment: `capture.pml`, raw `capture.csv`,
  `filtered.csv` (correctly narrowed to `MsMpEng.exe` + CreateFile/ReadFile +
  the sample's file name), valid `procmon_filter.pmc`, analyzer-written
  `report.md`, and metadata/manifest/trigger.json with all v1.1 fields
  (`collector_version: "1.1"`, `procmon_profile`, `signed`, `category`,
  `analysis: "completed"`).
- **Filter unit tests pass** (minimal/extended/full profiles, case-insensitive
  matching, unknown profile → minimal, CSV row filtering counts):
  minimal keeps only CreateFile/ReadFile; extended adds QueryInformationFile
  and CloseFile; full keeps every operation.
- **Degraded run** (no ProcMon, no analyzer): all 3 samples processed,
  fallback `report.md` auto-generated, `"analysis": "skipped"`, `"result":
  "failed"`, run completed without crash.

### Environment caveats observed
- Windows Defender real-time protection quarantined the unsigned
  `hello_tiny.exe` dataset copy after repeated trigger attempts; recreate from
  source when that happens.
- A freshly created/copied unsigned PE can be briefly held by Defender's scan,
  so sample discovery may log `Cannot hash sample, skipping` for a few seconds;
  re-running after the scan settles hashes it fine. `sha256_file` itself is
  correct (matches PowerShell SHA-256).

## 8. Known Remaining Items

1. **Real ProcMon end-to-end not yet validated** — testing used a fake ProcMon.
   Point `procmon_path` at Sysinternals Procmon64.exe and verify one full
   experiment produces a real `capture.pml` + `capture.csv` + `filtered.csv`.
2. **`procmon_activity` completion strategy is a stub** — currently logs
   "not implemented" and returns false. Implement based on Defender activity
   (event log / MpEng processes) when needed.
3. **Environment caveat** — the shell32 background-thread crash is specific to
   the test VM; the worker architecture makes the Collector safe regardless.
4. **Defender scan confirmation** — a final end-to-end confirmation of scan
   activity during a real collection run (with real ProcMon + real analyzer) is
   still advisable.
5. **Analyzer** — the reference `defenderatlas_analyzer.exe` is a stub
   (`fake_analyzer.cpp`); the real analyzer (report generation, statistics) is
   future work.
