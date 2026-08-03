# DefenderAtlas — Architecture Audit Report

**Date:** 2026-07-22
**Scope:** Full codebase review of all implemented source, tests, and configuration
**Method:** Static code inspection of every file in the repository

---

## 1. Project Overview

DefenderAtlas is a Python framework for analyzing Microsoft Defender's file scanning behavior. It is in **pre-alpha** (v0.1.0), classified under `Development Status :: 2 - Pre-Alpha`.

**Primary purpose:** Provide structured tooling to parse ProcMon CSV telemetry, model scanning events as typed data objects, and analyze how Defender reads files at the I/O level.

**What it can solve today:**

- Parse ProcMon CSV exports into validated `ReadEvent` objects
- Identify file types via magic-byte detection (PE, ZIP, PNG, PDF, Office)
- Provide a typed data model layer for scan events, phases, findings, and statistics
- Offer a CLI scaffold with version, analyze, capture, visualize, and report commands
- Enforce code quality via strict linting, type checking, and test coverage

**What it cannot do today:**

- Actually analyze file scanning behavior (analyzers return placeholders or raise `NotImplementedError`)
- Capture ProcMon/ETW events
- Generate reports or visualizations
- Detect Defender-specific patterns

---

## 2. Directory Structure Analysis

```
DefenderAtlas/
├── src/defenderatlas/           # Main package (src layout)
│   ├── __init__.py              # Version string
│   ├── analyzers/               # File type analyzers (IMPLEMENTED)
│   │   ├── __init__.py          # Re-exports all analyzers
│   │   ├── base.py              # Abstract Analyzer ABC
│   │   ├── pe.py                # PEAnalyzer (placeholder)
│   │   ├── zip.py               # ZIPAnalyzer (NotImplementedError)
│   │   ├── png.py               # PNGAnalyzer (NotImplementedError)
│   │   ├── pdf.py               # PDFAnalyzer (NotImplementedError)
│   │   └── office.py            # OfficeAnalyzer (NotImplementedError)
│   ├── capture/                 # ProcMon/ETW capture (EMPTY STUB)
│   │   └── __init__.py
│   ├── cli/                     # CLI entry points (IMPLEMENTED)
│   │   ├── __init__.py
│   │   ├── _logging.py          # Rich-based logging setup
│   │   └── app.py               # Typer CLI with 5 commands
│   ├── detectors/               # Pattern detection (EMPTY STUB)
│   │   └── __init__.py
│   ├── mapping/                 # File format mapping (EMPTY STUB)
│   │   └── __init__.py
│   ├── models/                  # Data models (IMPLEMENTED)
│   │   ├── __init__.py          # Re-exports all models
│   │   └── core.py              # 6 Pydantic v2 models
│   ├── parsers/                 # File format parsers (IMPLEMENTED)
│   │   ├── __init__.py          # Re-exports parser + errors
│   │   ├── errors.py            # 7 custom exception classes
│   │   └── procmon.py           # Streaming ProcMon CSV parser
│   ├── reports/                 # Report generation (EMPTY STUB)
│   │   └── __init__.py
│   ├── reverse/                 # Reverse engineering (EMPTY STUB)
│   │   └── __init__.py
│   ├── statistics/              # Statistical analysis (EMPTY STUB)
│   │   └── __init__.py
│   ├── utils/                   # Shared utilities (EMPTY STUB)
│   │   └── __init__.py
│   └── visualization/           # Visualization (EMPTY STUB)
│       └── __init__.py
├── tests/                       # Test suite
│   ├── __init__.py
│   ├── test_analyzers.py        # 39 tests
│   ├── test_cli.py              # 22 tests
│   ├── test_models.py           # 57 tests
│   └── test_parsers.py          # 41 tests
├── analyzeers/                  # Legacy scripts (misspelled name)
│   ├── PE/                      # Standalone PE analysis scripts
│   │   ├── pe_scan_analysis.py  # 868-line PE scanning report generator
│   │   └── analyze.py           # Cross-file ProcMon CSV analyzer
│   └── ZIP/                     # Standalone ZIP analysis scripts
│       ├── zipMap.py            # ZIP structure mapper
│       ├── cx.zip               # Sample ZIP archive
│       └── cx_regions.csv       # Pre-generated region map
├── baits/                       # Scan target files
├── CSVs/                        # ProcMon CSV exports (3 files)
├── reports/                     # Generated analysis reports
├── datasets/                    # Empty
├── docs/                        # Prompt/design docs
├── vishualizations/             # Visualization assets (misspelled)
├── .github/workflows/ci.yml     # GitHub Actions CI
├── .pre-commit-config.yaml      # Pre-commit hooks
├── pyproject.toml               # Project configuration
├── README.md
├── CONTRIBUTING.md
├── PROGRESS.md
├── ANALYSIS_REPORT.md
└── LICENSE
```

### Folder Status Summary

| Folder | Status | Description |
|--------|--------|-------------|
| `src/defenderatlas/analyzers/` | **Implemented** | Abstract base + 5 concrete analyzers |
| `src/defenderatlas/cli/` | **Implemented** | CLI with 5 commands (4 are placeholders) |
| `src/defenderatlas/models/` | **Implemented** | 6 Pydantic v2 data models |
| `src/defenderatlas/parsers/` | **Implemented** | Streaming ProcMon CSV parser |
| `src/defenderatlas/capture/` | **Empty stub** | Docstring-only `__init__.py` |
| `src/defenderatlas/detectors/` | **Empty stub** | Docstring-only `__init__.py` |
| `src/defenderatlas/mapping/` | **Empty stub** | Docstring-only `__init__.py` |
| `src/defenderatlas/reports/` | **Empty stub** | Docstring-only `__init__.py` |
| `src/defenderatlas/reverse/` | **Empty stub** | Docstring-only `__init__.py` |
| `src/defenderatlas/statistics/` | **Empty stub** | Docstring-only `__init__.py` |
| `src/defenderatlas/utils/` | **Empty stub** | Docstring-only `__init__.py` |
| `src/defenderatlas/visualization/` | **Empty stub** | Docstring-only `__init__.py` |
| `analyzeers/` | **Legacy** | Standalone scripts outside the package |

---

## 3. Dependency Analysis

### Runtime Dependencies

| Dependency | Version | Used By | Purpose |
|-----------|---------|---------|---------|
| `typer` | >=0.12.0 | `cli/app.py` | CLI framework with argument parsing, help generation, and Rich integration |
| `rich` | >=13.0.0 | `cli/app.py`, `cli/_logging.py` | Terminal formatting: panels, colored output, rich tracebacks in logs |
| `pydantic` | >=2.0.0 | `models/core.py` | Data validation, serialization, JSON schema for all data models |

### Development Dependencies

| Dependency | Version | Purpose |
|-----------|---------|---------|
| `ruff` | >=0.5.0 | Linter (pycodestyle, pyflakes, isort, bugbear, etc.) |
| `black` | >=24.0.0 | Code formatter |
| `mypy` | >=1.10.0 | Static type checker (strict mode) |
| `pytest` | >=8.0.0 | Test framework |
| `pytest-cov` | >=5.0.0 | Coverage reporting |
| `pre-commit` | >=3.7.0 | Git hook framework |

### Build Tools

| Tool | Purpose |
|------|---------|
| `hatchling` | PEP 517 build backend (lightweight, modern) |

---

## 4. Implemented Components

### 4.1 CLI Module

| | |
|---|---|
| **Location** | `src/defenderatlas/cli/app.py` (269 lines) |
| **Helper** | `src/defenderatlas/cli/_logging.py` (43 lines) |
| **Purpose** | Command-line interface for DefenderAtlas |
| **Status** | Scaffolded — commands parse arguments but print placeholder output |
| **Dependencies** | `typer`, `rich`, `defenderatlas.__version__`, `defenderatlas.cli._logging` |
| **Used By** | Entry point: `defenderatlas` console script |

**Commands implemented:**

| Command | Arguments | Options | Status |
|---------|-----------|---------|--------|
| `version` | — | — | Functional |
| `analyze <file>` | `file` (exists, readable) | `--output-dir`, `--format` | Placeholder |
| `capture <file>` | `file` (exists, readable) | `--output-dir`, `--duration` | Placeholder |
| `visualize <source>` | `source` (exists, readable) | `--output-dir` | Placeholder |
| `report <source>` | `source` (exists, readable) | `--output-dir`, `--format` | Placeholder |

**Key implementation details:**

- Global `--verbose` / `-V` flag initializes logging via `setup_logging()`
- Error handling wraps exceptions in Rich `Panel` with red border, exits with code 1
- Output directories created automatically via `_resolve_output_dir()`
- Logging goes to stderr (stdout stays clean for piping)
- `no_args_is_help=True` shows help when run without subcommands

### 4.2 Logging Module

| | |
|---|---|
| **Location** | `src/defenderatlas/cli/_logging.py` (43 lines) |
| **Purpose** | Configure Rich-based logging for CLI |
| **Status** | Fully implemented |
| **Dependencies** | `rich.console.Console`, `rich.logging.RichHandler` |
| **Used By** | `cli/app.py` |

**Implementation:**

- `setup_logging(verbose=False)` — configures root logger with `RichHandler`
- `get_logger(name)` — returns namespaced logger
- Verbose mode sets DEBUG level; default is INFO
- Removes pre-existing handlers to prevent double-printing
- Handler outputs to stderr

### 4.3 Models Module

| | |
|---|---|
| **Location** | `src/defenderatlas/models/core.py` (200 lines) |
| **Purpose** | Pydantic v2 data models for all analysis objects |
| **Status** | Fully implemented |
| **Dependencies** | `pydantic` |
| **Used By** | `parsers/procmon.py`, `analyzers/*.py`, tests |

**Models implemented:**

| Model | Purpose | Key Fields | Validation |
|-------|---------|------------|------------|
| `Severity` | StrEnum for finding severity | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | String enum validation |
| `ReadEvent` | Single file read operation | `timestamp`, `process_name`, `process_id`, `operation`, `path`, `offset`, `length`, `result` | `gt=0`, `ge=0`, `min_length=1` |
| `ScanPhase` | Phase of Defender's scan | `id`, `name`, `description`, `start_offset`, `end_offset` | `end_offset >= start_offset` (cross-field) |
| `Finding` | Security finding | `title`, `severity`, `description`, `evidence` | `min_length=1`, default `evidence=[]` |
| `Statistics` | Aggregate read stats | `total_reads`, `unique_offsets`, `repeated_reads`, `bytes_read`, `read_amplification` | `ge=0`, `ge=0.0` |
| `AnalysisResult` | Top-level container | `file_type`, `findings`, `phases`, `statistics` | `min_length=1`, nested validation |

**Key implementation details:**

- All models use `from __future__ import annotations` for forward references
- `ScanPhase` uses `@model_validator(mode="after")` for cross-field validation
- All models support `model_dump()`, `model_dump_json()`, `model_validate()`, `model_validate_json()`
- JSON serialization preserves enum values as strings (via `StrEnum`)
- `Statistics.read_amplification` is `float` with `ge=0.0` constraint

### 4.4 Parsers Module

| | |
|---|---|
| **Location** | `src/defenderatlas/parsers/procmon.py` (297 lines) |
| **Exceptions** | `src/defenderatlas/parsers/errors.py` (52 lines) |
| **Purpose** | Streaming ProcMon CSV parser |
| **Status** | Fully implemented |
| **Dependencies** | `defenderatlas.models.core.ReadEvent`, `defenderatlas.parsers.errors` |
| **Used By** | Tests, future CLI integration |

**Public API:**

```python
parse_procmon_csv(source, *, skip_errors=True) -> Iterator[ReadEvent]
```

- Accepts `str`, `Path`, or `IO[str]`
- Streams `ReadEvent` objects (constant memory)
- `skip_errors=True`: bad rows logged and skipped
- `skip_errors=False`: raises `RowError` on first bad row

**Exception hierarchy:**

```
ParserError (base)
├── CSVFormatError          # File unreadable or empty
│   └── HeaderError        # Missing required headers
└── RowError                # Single row parse failure
    ├── TimestampParseError # Bad timestamp
    ├── OffsetParseError    # Bad/missing offset
    └── LengthParseError    # Bad/missing length
```

**Key implementation details:**

- Filters to `ReadFile`, `IRP_MJ_READ`, `FastIORead` operations only
- Handles UTF-8 BOM (ProcMon exports with BOM)
- Timestamp truncation: ProcMon 7-digit fractions → Python 6-digit limit
- Detail column regex: `Offset:\s*(0x\w+|\d[\d,]*)` and `Length:\s*(0x\w+|\d[\d,]*)`
- Hex and decimal parsing with comma stripping
- `RowError` carries `line_number` and `raw` for traceability

### 4.5 Analyzers Module

| | |
|---|---|
| **Location** | `src/defenderatlas/analyzers/` (6 files, ~300 lines total) |
| **Purpose** | File type identification and analysis |
| **Status** | Architecture implemented; only PEAnalyzer has placeholder analysis |
| **Dependencies** | `defenderatlas.models.core.AnalysisResult` |
| **Used By** | Tests |

**Architecture:**

| Analyzer | `supports()` | `analyze()` | Magic Bytes |
|----------|-------------|-------------|-------------|
| `PEAnalyzer` | Checks for `MZ` | Returns empty `AnalysisResult` | `b"MZ"` (2 bytes) |
| `ZIPAnalyzer` | Checks for `PK\x03\x04` | Raises `NotImplementedError` | `b"PK\x03\x04"` (4 bytes) |
| `PNGAnalyzer` | Checks for `\x89PNG\r\n\x1a\n` | Raises `NotImplementedError` | 8 bytes |
| `PDFAnalyzer` | Checks for `%PDF` | Raises `NotImplementedError` | `b"%PDF"` (4 bytes) |
| `OfficeAnalyzer` | Checks for `\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1` | Raises `NotImplementedError` | 8 bytes |

**Abstract interface (`Analyzer`):**

```python
class Analyzer(ABC):
    @abstractmethod
    def supports(self, file_path: Path) -> bool: ...

    @abstractmethod
    def analyze(self, file_path: Path) -> AnalysisResult: ...
```

**Key implementation details:**

- Magic-byte detection (no extension dependency)
- All analyzers handle `OSError` gracefully in `supports()` (returns `False`)
- All analyzers check `file_path.exists()` before raising `NotImplementedError`
- Lazy imports in `PEAnalyzer.analyze()` to avoid circular dependencies
- `TYPE_CHECKING` guard for runtime imports (satisfies ruff TC001/TC003)

---

## 5. Data Model Flow

### Model Relationships

```
AnalysisResult
├── file_type: str
├── findings: list[Finding]
│   ├── title: str
│   ├── severity: Severity (StrEnum)
│   ├── description: str
│   └── evidence: list[str]
├── phases: list[ScanPhase]
│   ├── id: int (gt=0)
│   ├── name: str
│   ├── description: str
│   ├── start_offset: int (ge=0)
│   └── end_offset: int (ge=0, >= start_offset)
└── statistics: Statistics
    ├── total_reads: int (ge=0)
    ├── unique_offsets: int (ge=0)
    ├── repeated_reads: int (ge=0)
    ├── bytes_read: int (ge=0)
    └── read_amplification: float (ge=0.0)

ReadEvent (standalone, used by parser)
├── timestamp: datetime
├── process_name: str (min_length=1)
├── process_id: int (gt=0)
├── operation: str (min_length=1)
├── path: str (min_length=1)
├── offset: int (ge=0)
├── length: int (gt=0)
└── result: str (min_length=1)
```

### Data Flow Diagram

```
ProcMon CSV (file)
       │
       ▼
parse_procmon_csv()
       │
       ▼
ReadEvent (streaming iterator)
       │
       ▼
[Future: Statistics computation]
       │
       ▼
AnalysisResult
       │
       ├── findings: list[Finding]
       ├── phases: list[ScanPhase]
       └── statistics: Statistics
```

**Note:** Currently `ReadEvent` objects are produced by the parser but not consumed by any analysis pipeline. The `AnalysisResult` is only constructed by `PEAnalyzer.analyze()` as an empty placeholder. No code currently connects `ReadEvent` → `Statistics` → `AnalysisResult`.

---

## 6. Current Runtime Workflow

### What happens when a user runs DefenderAtlas

```
User runs: defenderatlas analyze myfile.exe
                    │
                    ▼
┌─────────────────────────────────────────────┐
│ CLI Entry Point (cli/app.py:44)             │
│ console_scripts: defenderatlas = app:app     │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│ Typer App callback (cli/app.py:59)          │
│ - setup_logging(verbose=False)              │
│ - ctx.invoked_subcommand = "analyze"        │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│ analyze() command (cli/app.py:87)           │
│ - Validates file exists (Typer argument)    │
│ - _resolve_output_dir(None) → Path(...)     │
│ - Prints Rich Panel with file info          │
│ - log.info("Analyzing %s ...")              │
│ - log.warning("... placeholder only")       │
│ - Prints "Analysis complete. (placeholder)" │
└─────────────────────────────────────────────┘

Exit code: 0
No analysis actually performed.
```

### What happens when ProcMon CSV is parsed programmatically

```
from defenderatlas.parsers import parse_procmon_csv

events = parse_procmon_csv("Logfile.csv")
       │
       ▼
┌─────────────────────────────────────────────┐
│ open("Logfile.csv", encoding="utf-8-sig")   │
│ Strip BOM if present                        │
│ csv.DictReader(fh)                          │
│ Validate required headers                   │
│ Check missing headers → HeaderError         │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│ For each row:                               │
│ - Filter: operation not in _READ_OPS? skip  │
│ - Parse timestamp → _parse_timestamp()      │
│ - Extract PID, process_name, path, result   │
│ - Validate non-empty fields                 │
│ - Parse Detail → _parse_detail()            │
│   - Regex extract Offset: and Length:       │
│   - Parse hex or decimal                    │
│ - _build_read_event() → ReadEvent           │
│ - yield ReadEvent                           │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
        Iterator[ReadEvent] (streaming)
```

---

## 7. ProcMon Parser Workflow

### CSV Loading

1. **File path input:** Opens with `utf-8-sig` encoding (handles BOM automatically)
2. **Stream input:** Reads first character; if BOM, consumes it; if not, seeks back
3. **DictReader:** Parses CSV with header detection
4. **Header validation:** Checks 7 required columns exist: `Time of Day`, `Process Name`, `PID`, `Operation`, `Path`, `Result`, `Detail`

### Row Parsing

For each row in the CSV:

1. **Operation filter:** Only `ReadFile`, `IRP_MJ_READ`, `FastIORead` are processed; all others silently skipped
2. **Timestamp parsing:** `_parse_timestamp()` handles 7-digit fractional seconds (truncates to 6)
3. **Field extraction:** `process_name`, `PID`, `Path`, `Result` stripped of whitespace
4. **Validation:** Empty `process_name`, `path`, or `result` raises `RowError`
5. **PID parsing:** `int()` conversion, raises `RowError` on failure
6. **Detail parsing:** `_parse_detail()` extracts offset and length via regex
7. **Event construction:** `_build_read_event()` creates validated `ReadEvent`

### Error Handling

| Scenario | `skip_errors=True` | `skip_errors=False` |
|----------|-------------------|---------------------|
| Bad timestamp | Log warning, skip row | Raise `TimestampParseError` |
| Invalid PID | Log warning, skip row | Raise `RowError` |
| Missing offset | Log warning, skip row | Raise `OffsetParseError` |
| Missing length | Log warning, skip row | Raise `LengthParseError` |
| Empty fields | Log warning, skip row | Raise `RowError` |
| File not found | Raise `CSVFormatError` | Raise `CSVFormatError` |
| Empty CSV | Raise `CSVFormatError` | Raise `CSVFormatError` |
| Missing headers | Raise `HeaderError` | Raise `HeaderError` |

### Flow Diagram

```
CSV File/Stream
       │
       ▼
  ┌─────────────────┐
  │ Open & strip BOM │
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ Validate headers │──── Missing? → HeaderError
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ For each row:    │
  │                  │
  │ Operation in     │──── No → skip
  │ _READ_OPS?       │
  │                  │
  │ Yes ↓            │
  │                  │
  │ Parse timestamp  │──── Fail → TimestampParseError
  │ Extract PID      │──── Fail → RowError
  │ Validate fields  │──── Fail → RowError
  │ Parse Detail     │──── Fail → OffsetParseError / LengthParseError
  │                  │
  │ Build ReadEvent  │
  │ yield event      │
  └─────────────────┘
```

---

## 8. CLI Workflow

### Command Registration

```
app = typer.Typer(name="defenderatlas", ...)

@app.callback(invoke_without_command=True)
def main(ctx, verbose=False):
    setup_logging(verbose=verbose)

@app.command() def version()
@app.command() def analyze(file, output_dir, fmt)
@app.command() def capture(file, output_dir, duration)
@app.command() def visualize(source, output_dir)
@app.command() def report(source, output_dir, fmt)
```

### Argument Parsing Flow

```
User: defenderatlas -V analyze myfile.exe -o ./out -f json
                    │
                    ▼
  ┌─────────────────────────────────┐
  │ Typer parses global options     │
  │ -V → verbose=True               │
  └────────┬────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────┐
  │ main() callback executes        │
  │ setup_logging(verbose=True)     │
  │ → Root logger set to DEBUG     │
  └────────┬────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────┐
  │ Typer routes to analyze()       │
  │ file = Path("myfile.exe")       │
  │ output_dir = "./out"            │
  │ fmt = "json"                    │
  └────────┬────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────┐
  │ analyze() body executes         │
  │ _resolve_output_dir("./out")    │
  │ → Path("./out"), mkdir created │
  │ Print Rich Panel                │
  │ Print placeholder message      │
  └─────────────────────────────────┘
```

### Error Handling Flow

```
Any command
     │
     ▼
  try: ... except Exception as exc:
     │
     ▼
  _handle_error(exc)
     │
     ├── error_console.print(Panel(..., border_style="red"))
     ├── log.debug("Traceback:", exc_info=True)
     └── raise typer.Exit(code=1)
```

---

## 9. Test Coverage Analysis

### Test Suite Summary

| Test File | Tests | Module Covered | Lines |
|-----------|-------|----------------|-------|
| `test_models.py` | 57 | `models/core.py` | 418 |
| `test_parsers.py` | 41 | `parsers/procmon.py`, `parsers/errors.py` | 321 |
| `test_analyzers.py` | 39 | `analyzers/*.py` | 322 |
| `test_cli.py` | 22 | `cli/app.py`, `cli/_logging.py` | 202 |
| **Total** | **159** | | **1,263** |

### Coverage by Module

| Module | Stmts | Coverage | Notes |
|--------|-------|----------|-------|
| `analyzers/base.py` | 8 | 100% | ABC enforcement tested |
| `analyzers/pe.py` | 22 | 100% | Both `supports()` and `analyze()` paths covered |
| `analyzers/zip.py` | 16 | 100% | `NotImplementedError` path tested |
| `analyzers/png.py` | 16 | 100% | `NotImplementedError` path tested |
| `analyzers/pdf.py` | 16 | 100% | `NotImplementedError` path tested |
| `analyzers/office.py` | 16 | 100% | `NotImplementedError` path tested |
| `models/core.py` | 47 | 100% | All validation rules tested |
| `parsers/procmon.py` | 100 | 100% | All code paths including error branches |
| `parsers/errors.py` | 13 | 100% | Exception hierarchy tested |
| `cli/_logging.py` | 17 | 100% | Tested via CLI verbose flag |
| `cli/app.py` | 70 | 82% | All commands tested; error handler partially covered |

### Test Categories

**Model tests (57):**
- Construction validation (required fields, constraints)
- Boundary testing (zero, negative, large values)
- Serialization roundtrips (dict and JSON)
- Cross-field validation (`ScanPhase.end_offset >= start_offset`)
- Enum validation (`Severity` levels)

**Parser tests (41):**
- Hex and decimal parsing
- Timestamp parsing (6-digit, 7-digit, invalid)
- Detail column extraction (hex, decimal, comma-separated)
- Streaming behavior (single row, multiple rows, non-read operations)
- Error handling (skip_errors=True/False)
- File I/O (file path, nonexistent file, BOM handling)
- Operation filtering (ReadFile, IRP_MJ_READ, FastIORead)

**Analyzer tests (39):**
- ABC enforcement (cannot instantiate, must implement both methods)
- `supports()` for each analyzer (correct magic bytes, false positives, empty files, nonexistent files)
- `analyze()` behavior (PE returns result, others raise NotImplementedError)
- Polymorphic dispatch (iterate analyzers, match by `supports()`)
- Subclass/instance checks

**CLI tests (22):**
- Version output
- Help text (root, each command)
- Command execution (valid files, output directory creation)
- Error cases (nonexistent files)
- Logging (verbose flag)

### Missing Tests

- No integration tests connecting parser → analyzer → result
- No tests for the `analyzeers/` legacy scripts
- No tests for error handler `_handle_error()` panel output
- No tests for logging output content (only that verbose flag is accepted)
- No tests for `parse_procmon_csv()` with actual ProcMon CSV files from `CSVs/`

---

## 10. Current Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Layer                             │
│  ┌──────────┐  ┌─────────┐  ┌──────────┐  ┌────────────┐  │
│  │ version  │  │ analyze │  │ capture  │  │ visualize  │  │
│  └──────────┘  └────┬────┘  └──────────┘  └────────────┘  │
│                     │          (all placeholders)           │
│  ┌──────────────────┴─────────────────────────────────┐    │
│  │              _logging.py (Rich handler)             │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────┴───────────────────────────────┐
│                     Models Layer                             │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌───────────┐  │
│  │ReadEvent │  │ScanPhase  │  │ Finding  │  │Statistics │  │
│  └──────────┘  └───────────┘  └──────────┘  └───────────┘  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              AnalysisResult (top-level)               │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────┴───────────────────────────────┐
│                    Parser Layer                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         parse_procmon_csv() → Iterator[ReadEvent]    │   │
│  │         (streaming, error-tolerant)                   │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  ParserError hierarchy (7 exception classes)          │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────┴───────────────────────────────┐
│                   Analyzer Layer                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Analyzer (ABC) — supports() + analyze()             │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │PEAnalyzer│  │ZIPAnalyzer│ │PNGAnalyzer│ │PDFAnalyzer│   │
│  │(placeholder)│ │(stub)   │  │(stub)    │  │(stub)    │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│  ┌──────────────┐                                          │
│  │OfficeAnalyzer│                                          │
│  │(stub)        │                                          │
│  └──────────────┘                                          │
└─────────────────────────────────────────────────────────────┘

Disconnected (not wired into pipeline):
  - capture/      (empty)
  - detectors/    (empty)
  - mapping/      (empty)
  - reports/      (empty)
  - reverse/      (empty)
  - statistics/   (empty)
  - utils/        (empty)
  - visualization/(empty)
```

---

## 11. What Is NOT Implemented Yet

| Component | Exists | Partially Exists | Missing |
|-----------|--------|-----------------|---------|
| **CLI commands** | `version` works | `analyze`, `capture`, `visualize`, `report` are placeholders | Actual analysis logic in commands |
| **Capture (ProcMon/ETW)** | Empty `capture/__init__.py` | — | ProcMon automation, ETW session management, CSV export |
| **Detectors** | Empty `detectors/__init__.py` | — | Defender pattern detection logic |
| **Mapping** | Empty `mapping/__init__.py` | — | File format structure mapping (PE sections, ZIP regions, PDF objects) |
| **Reports** | Empty `reports/__init__.py` | — | HTML/Markdown/JSON report generation |
| **Reverse Engineering** | Empty `reverse/__init__.py` | — | Disassembly, import analysis, string extraction |
| **Statistics** | Empty `statistics/__init__.py` | — | ReadEvent → Statistics computation (offset analysis, amplification) |
| **Utilities** | Empty `utils/__init__.py` | — | Shared helpers (hex formatting, file hashing, etc.) |
| **Visualization** | Empty `visualization/__init__.py` | — | Chart/graph generation from analysis data |
| **PE Analyzer** | `supports()` works | `analyze()` returns empty result | PE structure parsing, section mapping, scan phase detection |
| **ZIP Analyzer** | `supports()` works | `analyze()` raises `NotImplementedError` | ZIP structure analysis, nested archive handling |
| **PNG Analyzer** | `supports()` works | `analyze()` raises `NotImplementedError` | PNG chunk analysis |
| **PDF Analyzer** | `supports()` works | `analyze()` raises `NotImplementedError` | PDF object parsing |
| **Office Analyzer** | `supports()` works | `analyze()` raises `NotImplementedError` | OLE2 structure parsing |
| **Pipeline integration** | — | — | No code connects parser → analyzer → result |

---

## 12. Current Capabilities

DefenderAtlas can do the following **right now**:

- Install as a Python package via `pip install -e .`
- Run CLI commands: `defenderatlas version`, `--help`, `analyze`, `capture`, `visualize`, `report`
- Parse ProcMon CSV files into validated `ReadEvent` objects via `parse_procmon_csv()`
- Handle malformed CSV rows gracefully (skip or raise)
- Support hex, decimal, and comma-separated offset/length values
- Handle UTF-8 BOM in ProcMon exports
- Filter to read-only operations (`ReadFile`, `IRP_MJ_READ`, `FastIORead`)
- Construct typed `AnalysisResult` objects with nested models
- Serialize/deserialize all models to/from JSON and dict
- Identify file types via magic-byte detection (PE, ZIP, PNG, PDF, Office)
- Validate all data at construction time via Pydantic constraints
- Run 159 tests with 100% coverage on parser and analyzer modules
- Enforce code quality via ruff, black, mypy (strict), and pre-commit hooks
- Run CI on GitHub Actions (Python 3.12/3.13)

---

## 13. Current Limitations

### Architectural Limitations

1. **No pipeline integration** — `ReadEvent` objects from the parser are never consumed by any analysis code. The parser and analyzers are disconnected.
2. **CLI commands are hollow** — All commands except `version` print placeholder messages. No actual analysis occurs.
3. **No Statistics computation** — `Statistics` model exists but no code computes it from `ReadEvent` data.
4. **No ScanPhase detection** — `ScanPhase` model exists but no code identifies phases from events.

### Missing Modules

5. **8 empty modules** — `capture/`, `detectors/`, `mapping/`, `reports/`, `reverse/`, `statistics/`, `utils/`, `visualization/` are all docstring-only stubs.
6. **No PE structure parsing** — Despite `pe_scan_analysis.py` existing in `analyzeers/`, no PE parsing logic is in the package.

### Technical Debt

7. **`analyzeers/` directory** — Misspelled name, contains standalone scripts with hardcoded paths (`/home/godwin/Desktop/...`), reimplements CSV parsing instead of using the package parser.
8. **`vishualizations/` directory** — Misspelled name (should be `visualizations/`).
9. **No `py.typed` marker** — Package lacks PEP 561 marker for type checking consumers.
10. **No integration tests** — Only unit tests exist; no tests verify end-to-end workflows.

### Future Bottlenecks

11. **`pe_scan_analysis.py` has 868 lines** of hardcoded PE section definitions and report generation that would need significant refactoring to integrate into the package.
12. **No configuration system** — All parameters (file paths, PE sections, thresholds) are hardcoded.

---

## 14. Recommended Next Milestone

### Priority: Connect the Pipeline

The most impactful next step is wiring the existing components together into a functional analysis pipeline.

**Why:**

- The parser produces `ReadEvent` objects that are currently unused
- The `Statistics` model exists but is never computed
- The CLI `analyze` command is a placeholder
- This would make DefenderAtlas actually functional for its core use case

**Dependencies:**

- `parsers/procmon.py` (already implemented)
- `models/core.py` (already implemented)
- `statistics/` (empty — needs implementation)

**Expected output:**

1. **`statistics/compute.py`** — Function that takes `Iterator[ReadEvent]` and computes `Statistics` (total_reads, unique_offsets, repeated_reads, bytes_read, read_amplification)
2. **Wire CLI `analyze` command** — Accept a ProcMon CSV, parse it, compute statistics, return `AnalysisResult`
3. **Integration test** — End-to-end test using real CSV data from `CSVs/`

**Roadmap:**

```
Phase 1: Statistics Engine (this milestone)
├── statistics/compute.py — Compute Statistics from ReadEvent stream
├── Wire CLI analyze command — CSV → parse → statistics → result
└── Integration tests — End-to-end with real CSV data

Phase 2: PE Analyzer
├── mapping/pe_sections.py — Parse PE headers, map sections
├── analyzers/pe.py — Implement real analysis
└── detectors/pe_patterns.py — Detect scan phases

Phase 3: Reports & Visualization
├── reports/markdown.py — Generate Markdown reports
├── visualization/charts.py — Generate scan coverage charts
└── CLI report/visualize commands — Wire to generators

Phase 4: Capture Automation
├── capture/procmon.py — Automate ProcMon start/stop/export
├── capture/etw.py — ETW session management
└── CLI capture command — Wire to capture engine
```

---

## 15. Executive Summary

### What Has Been Built

DefenderAtlas has a **solid foundation** with 4 fully implemented modules:

- **Models:** 6 Pydantic v2 data models with strict validation, serialization, and JSON schema support
- **Parser:** Streaming ProcMon CSV parser with error handling, BOM support, and typed output
- **Analyzers:** Abstract base class with 5 concrete implementations (magic-byte detection working, analysis stubs)
- **CLI:** Typer + Rich framework with 5 commands, logging, and error handling

### What Works

- `defenderatlas version` — displays version
- `parse_procmon_csv()` — parses real ProcMon CSVs into `ReadEvent` objects
- `PEAnalyzer.supports()` / `ZIPAnalyzer.supports()` / etc. — identifies file types
- 159 tests, all passing, with 100% coverage on core modules
- Strict linting (ruff), formatting (black), and type checking (mypy)
- CI pipeline on GitHub Actions

### What Does Not Exist

- Any actual file analysis logic (analyzers return empty results or raise errors)
- ProcMon/ETW capture automation
- Report or visualization generation
- Statistics computation from parsed events
- Pipeline integration connecting parser → analysis → output
- PE structure parsing (despite legacy scripts in `analyzeers/`)

### Current Maturity Level

**Pre-alpha (v0.1.0)** — The architecture and data models are well-designed and tested, but the framework cannot yet perform its primary function (analyzing Defender scanning behavior). It is a well-engineered skeleton awaiting implementation.

### Readiness for Research Usage

**Not ready.** A researcher would need to:

1. Manually run ProcMon and export CSV
2. Use the standalone scripts in `analyzeers/` (which have hardcoded paths and no tests)
3. Or write custom Python code using `parse_procmon_csv()` and manually construct `AnalysisResult` objects

The package is useful as a **library** for parsing ProcMon CSVs and constructing typed models, but not as an end-to-end analysis tool.
