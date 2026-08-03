# Folder Analysis Report — DefenderAtlas

---

## 1. Identification

**Project Name:** DefenderAtlas (aka `defender-atlas`)
**Repository:** https://github.com/R00-K/defender-atlas
**Type:** Security Research Project / Anti-Virus Reverse Engineering Analysis Toolkit

**What it is:** A Microsoft Defender behavior analysis research project that captures and analyzes ProcMon (Process Monitor) CSV telemetry to reverse-engineer how Microsoft Defender's scanner (`MsMpEng.exe`) reads and navigates files during real-time protection scans. The project documents Defender's scanning strategy for PE executables, ZIP archives, and PNG images at the I/O level.

**Reasoning:** The README states: *"Mapping Microsoft Defender's file-navigation and scanning behavior through ProcMon telemetry and file-format structure analysis."* All scripts parse ProcMon CSV exports, map read offsets to file format structures, and produce reports. The `baits/` folder contains files used as scan targets (not malware authoring — they are bait files placed to trigger Defender scans).

---

## 2. Purpose

The project's goals are:

1. Capture Defender's file read behavior using ProcMon
2. Map those reads to known file format structures (PE sections, ZIP regions)
3. Quantify coverage, chunk sizes, scan phases, and read amplification
4. Document Defender's internal scanning strategy (multi-pass, structure-aware probing, Authenticode checking, chunk-based I/O patterns)
5. Compare scanning behavior across file types (PE vs ZIP vs PNG)

This is **defensive security research** aimed at understanding AV engine internals — useful for understanding detection gaps, optimizing evasion research, or improving detection engineering.

---

## 3. Technology Stack

### Languages

- **Python 3** — All analysis scripts (3 files)
- **Markdown** — Reports (1 file)
- **CSV** — ProcMon log data (3 files)

### Python Standard Library Usage

- `csv`, `re`, `io`, `json`, `statistics`, `collections`, `struct`, `os`, `sys`

### Python Third-Party Dependencies

- `tabulate` — Used in `analyzeers/PE/analyze.py` for formatted table output

### Tools/Platforms Referenced

- **ProcMon (Process Monitor)** — Windows Sysinternals tool used to capture file I/O
- **PEStudio** — Referenced in PE section definitions (for section extraction)
- **Microsoft Defender (MsMpEng.exe)** — The target being analyzed

### Build System

None. No `setup.py`, `requirements.txt`, `pyproject.toml`, `Makefile`, or package manager files exist.

---

## 4. Directory Structure

```
DefenderAtlas/
├── README.md                          # Project description (2 lines)
├── ANALYSIS_REPORT.md                 # This file
│
├── analyzeers/                        # Analysis scripts (note: misspelled "analyzers")
│   ├── PE/                            # PE executable analysis
│   │   ├── pe_scan_analysis.py        # Main PE scanning strategy analysis (868 lines)
│   │   └── analyze.py                 # Cross-file ProcMon CSV analyzer (437 lines)
│   └── ZIP/                           # ZIP archive analysis
│       ├── zipMap.py                  # ZIP structure mapper (228 lines)
│       ├── cx.zip                     # Sample ZIP archive (24 MB, contains APK+extracted contents)
│       └── cx_regions.csv             # Pre-generated region map of cx.zip (4,077 regions)
│
├── baits/                             # Scan target files ("bait" files for Defender)
│   ├── AdobeReader.exe                # PE64 executable (2.6 MB, 20 sections) — primary PE target
│   ├── test.bin                       # PE64 executable renamed to .bin (2.6 MB)
│   ├── adobe.zip                      # ZIP archive (526 KB)
│   ├── me.zip                         # ZIP archive (25 MB)
│   ├── cx.png                         # Actually a ZIP archive mislabeled (24 MB)
│   ├── me.png                         # PNG image (686 KB, 800x800 RGB)
│   └── hello.exe                      # ASCII text file (6 bytes)
│
├── CSVs/                              # ProcMon CSV exports (raw telemetry data)
│   ├── LogfileMalwareexe.CSV          # ProcMon trace: MsMpEng.exe scanning AdobeReader.exe (111 rows)
│   ├── Logfilezip.CSV                 # ProcMon trace: MsMpEng.exe scanning cx.zip (841 rows)
│   └── LogfileZipPNG.CSV             # ProcMon trace: SearchProtocolHost.exe reading me.png (9 rows)
│
├── reports/                           # Generated analysis reports
│   ├── PE_SCAN_REPORT.txt             # PE section scanning analysis (508 lines)
│   └── ZIP_SCAN_REPORT.md            # ZIP archive scanning analysis (576 lines)
│
└── vishualizations/                   # Visualization assets (note: misspelled "visualizations")
    └── flow.png                       # Scan flow diagram (1024x1536 PNG)
```

---

## 5. Architecture

### Component Diagram

```
                    ┌─────────────────┐
                    │  Windows Host    │
                    │  (User: cruiz)   │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────▼────┐   ┌────▼────┐   ┌────▼────┐
         │ProcMon  │   │ MsMpEng │   │ Bait    │
         │Capture  │──▶│ .exe    │──▶│ Files   │
         │(I/O log)│   │(Defender│   │(targets)│
         └────┬────┘   │ scanner)│   └─────────┘
              │        └─────────┘
              ▼
     ┌────────────────┐
     │  CSV Export     │    (Logfile*.CSV)
     └────────┬───────┘
              │
    ┌─────────┼──────────┐
    │         │          │
┌───▼───┐ ┌──▼────┐ ┌───▼────┐
│PE     │ │PE     │ │ZIP     │
│pe_scan│ │analyze│ │zipMap  │
│_anal..│ │.py    │ │.py     │
└───┬───┘ └──┬────┘ └───┬────┘
    │        │          │
    ▼        ▼          ▼
┌────────────────────────────┐
│  Analysis Reports          │
│  (PE_SCAN_REPORT.txt)      │
│  (ZIP_SCAN_REPORT.md)      │
│  (console output)          │
└────────────────────────────┘
```

### Data Flow

```
Bait files on disk
    ↓
Defender (MsMpEng.exe) triggers real-time scan on file access
    ↓
ProcMon captures ReadFile I/O events → CSV export
    ↓
Python scripts parse CSV, map offsets to format structures
    ↓
Reports: coverage analysis, chunk sizes, scan phases, strategy
```

---

## 6. Execution Flow

### PE Analysis (`pe_scan_analysis.py`)

```
Input:  ProcMon CSV (LogfileMalwareexe.CSV)
  ↓
Parse CSV → filter ReadFile events from MsMpEng.exe
  ↓
Extract offset, length, timestamp from Detail field
  ↓
Map each offset to PE section (hardcoded PE_SECTIONS dict)
  ↓
Calculate per-section coverage (byte-level)
  ↓
Merge overlapping reads → contiguous ranges
  ↓
Detect patterns: sequential score, chunk distribution, phases
  ↓
Generate report with 13 sections (tables, visualizations, Q&A)
  ↓
Output: PE_SCAN_REPORT.txt
```

### Cross-File Analyzer (`analyze.py`)

```
Input:  3 CSVs (EXE, ZIP, PNG)
  ↓
Parse each → filter by MsMpEng.exe
  ↓
Analyze: read count, chunk sizes, sequential score, alignment
  ↓
Print individual reports + cross-file comparison table
  ↓
Output: Console (tabulate-formatted tables)
```

### ZIP Structure Mapper (`zipMap.py`)

```
Input:  ZIP file path (CLI argument)
  ↓
Read raw bytes → find EOCD signature (PK\x05\x06)
  ↓
Parse EOCD → locate Central Directory
  ↓
Iterate zipfile.infolist() → map local headers + data regions
  ↓
Export region table (CSV) with start/end offsets
  ↓
Output: {name}_regions.csv + console region table
```

---

## 7. Important Files

### Priority 1 — Primary Analysis Scripts

| File | Why |
|------|-----|
| `analyzeers/PE/pe_scan_analysis.py` | **Core of the project.** 868-line Python script that performs the most detailed analysis — PE section mapping, coverage calculation, multi-phase scan reconstruction, strategy determination. Contains hardcoded PE section definitions. Main research output generator. |
| `reports/ZIP_SCAN_REPORT.md` | **Most comprehensive research output.** 576-line detailed analysis of Defender's ZIP scanning behavior including the 512 KB cycle pattern discovery, phase reconstruction, and PE vs ZIP comparison. |
| `reports/PE_SCAN_REPORT.txt` | **PE scan analysis output.** 508-line report documenting Defender's 8-phase scanning strategy for PE executables, covering all 110 ReadFile events. |

### Priority 2 — Supporting Analysis

| File | Why |
|------|-----|
| `analyzeers/PE/analyze.py` | Cross-file comparison analyzer. Uses `tabulate` for formatted output. Analyzes EXE, ZIP, and PNG traces comparatively. |
| `analyzeers/ZIP/zipMap.py` | ZIP structure mapper. Standalone tool to generate byte-level region maps of ZIP archives. |
| `CSVs/Logfilezip.CSV` | **Raw data** — 840-row ProcMon capture of Defender scanning a 24 MB ZIP containing a nested APK. |
| `CSVs/LogfileMalwareexe.CSV` | **Raw data** — 110-row ProcMon capture of Defender scanning a PE executable. |

### Priority 3 — Supporting Files

| File | Why |
|------|-----|
| `CSVs/LogfileZipPNG.CSV` | Minimal 9-row trace — PNG scan was by SearchProtocolHost.exe (not Defender). |
| `analyzeers/ZIP/cx.zip` | 24 MB sample ZIP archive containing a nested Android APK + extracted contents. Used as scan target. |
| `analyzeers/ZIP/cx_regions.csv` | Pre-generated 4,077-region structure map of cx.zip. |
| `baits/*` | Bait/trigger files placed for Defender to scan. Not analysis targets themselves. |
| `vishualizations/flow.png` | Flow diagram visualization of scan pipeline. |

---

## 8. Security Analysis

### Research Context (Not Malicious)

This project is **legitimate security research** analyzing AV engine internals. The `baits/` folder contains files intentionally placed to trigger Defender scans — they are research stimuli, not malware payloads.

### Findings Documented

#### Defender Scanning Strategy for PE Executables

1. **Authenticode-first:** Second read event always targets the signature/footer region (offset 2,637,824 for a 2.6 MB PE) — indicates signature verification is highest priority
2. **Multi-engine architecture:** At least 3 independent scan engines evidenced by 3 identical full-file passes + 2 interleaved passes
3. **6.1x read amplification:** 2.6 MB file results in ~16 MB total disk reads
4. **Offset 0 re-read 7 times:** Each engine independently validates magic bytes
5. **Hybrid strategy:** Structure-aware probing + bulk sequential scanning + fine-grained page-level probing
6. **PE header parsed:** DOS header, e_lfanew, PE signature, File Header, Optional Header, all 16 Data Directories, Section Table
7. **All PE sections covered:** .text (code), .data, .rdata, .pdata, .xdata, .idata, .CRT, .tls, .rsrc, .reloc

#### Defender Scanning Strategy for ZIP Archives

1. **Header + EOCD probe first:** Reads offset 0 then jumps to the end for Central Directory
2. **1.02x read amplification** — much more efficient than PE (single pass)
3. **512 KB cycle pattern:** 7x64KB + 1x60KB + 1x4KB = 524,288 bytes per cycle
4. **Full extraction scanning:** Reads ALL file data including nested archives
5. **Zone.Identifier check** as final scan step (NTFS alternate data stream)
6. **Central Directory as index:** CD region (268 KB) read 116 times during file enumeration
7. **Dual-pass nested APK scanning:** Nested cx/base.apk scanned twice (as ZIP entry and as extracted contents)

### Observations Relevant to Security

- **Bait file naming deception:** `hello.exe` is a 6-byte ASCII text file; `test.bin` is actually a PE64 executable; `cx.png` is actually a ZIP archive — these appear designed to test Defender's file-type detection vs extension-based detection
- **Hardcoded file paths in scripts:** Reference `C:\Users\cruiz\Downloads\` — Windows paths from the researcher's machine
- **External CSV path references:** `pe_scan_analysis.py:842` references `/home/godwin/Desktop/000/malware/win10/opncode/LogfileMalwareexe.CSV` — outside this repo
- **No obfuscation, no network code, no persistence, no exploitation code** — purely analytical

### MITRE ATT&CK Relevance

The documented Defender behaviors map to these defensive techniques:

| Technique | Description |
|-----------|-------------|
| T1059.001 | PowerShell/Script-based scanning (AMSI integration) |
| T1105 | Ingress Tool Transfer (Zone.Identifier check) |
| T1027 | Obfuscated Files (Defender's entropy-based analysis) |
| T1027.002 | Software Packing (nested archive detection) |
| T1562.001 | Disable or Modify Tools (anti-tamper via Authenticode priority) |

---

## 9. Dependencies

### Runtime

- Python 3.x
- `tabulate` pip package (only for `analyzeers/PE/analyze.py`)

### Data Requirements

- ProcMon CSV exports (provided in `CSVs/`)
- Sample files for scanning (provided in `baits/` and `analyzeers/ZIP/`)
- Windows 10+ host with Microsoft Defender real-time protection active

### Risk Assessment

**Low risk.** Scripts are read-only analyzers. No network calls, no system modifications, no dangerous APIs. The `tabulate` dependency is a well-known, safe formatting library.

---

## 10. Development Status

### Completed

- PE section scanning strategy analysis (comprehensive, 13-section report)
- ZIP archive scanning strategy analysis (comprehensive, 15-section report with 512 KB cycle pattern discovery)
- Cross-file comparison framework (EXE vs ZIP vs PNG)
- ZIP structure mapping tool (`zipMap.py`)
- ProcMon CSV parsing pipeline
- Per-section byte-level coverage calculation
- Scan phase reconstruction with ASCII visualizations

### Partially Implemented

- PNG analysis — trace captured but only 9 rows from SearchProtocolHost.exe (not Defender)
- Cross-file comparison in `analyze.py` — structure exists but PNG data is insufficient
- Pattern detection — `detect_patterns()` function exists but could be expanded

### Missing

- `requirements.txt` — No dependency specification
- Configuration files — All parameters hardcoded (file paths, PE section definitions)
- Tests — No unit or integration tests
- CLI argument handling — `pe_scan_analysis.py` and `analyze.py` have hardcoded paths
- Automated ProcMon capture workflow
- Additional file format support (PDF, Office documents, etc.)
- Visualization generation scripts (only static PNG exists)
- Proper error handling for malformed CSVs

### TODO/FIXME (Inferred)

- Fix typo: `analyzeers` → `analyzers`
- Fix typo: `vishualizations` → `visualizations`
- Add `requirements.txt` with `tabulate` dependency
- Make file paths configurable via CLI arguments or config file
- Add PNG/image file analysis when proper Defender traces are captured
- Extract PE section definitions from PEStudio automatically
- Add timing analysis when ProcMon timestamps are available
- Support for WriteFile and CloseFile event analysis

---

## 11. Recommendations for Further Review

### For ChatGPT/Security Researchers

1. **Read `reports/ZIP_SCAN_REPORT.md` first** — It is the most comprehensive and self-contained research output, covering the 512 KB cycle pattern discovery and PE vs ZIP comparison
2. **Read `reports/PE_SCAN_REPORT.txt` second** — Documents the 8-phase PE scanning strategy with detailed evidence
3. **Review `analyzeers/PE/pe_scan_analysis.py`** — The most sophisticated script; understand the PE section definitions and coverage calculation logic
4. **Examine the bait files** — The deliberate extension/content mismatches (`.bin` = PE, `.png` = ZIP, `.exe` = text) suggest testing Defender's file-type identification bypass
5. **Note the external path references** — Scripts reference `/home/godwin/Desktop/000/malware/` suggesting a larger malware analysis workspace

### Key Research Questions to Investigate

- What Defender components correspond to each scan phase? (MpEngine, AMSI, Cloud reputation)
- Can scan phases be skipped or reduced by file type or trust status?
- How does the 61,440-byte boundary read relate to Windows page alignment?
- Does Defender decompress ZIP entries in-memory or scan compressed bytes directly?
- How do scan patterns change for detected (malicious) vs clean files?
- What is the maximum nesting depth for archive scanning?

---

*Report generated: 2026-07-22*
*Analysis method: Static file inspection of all files in DefenderAtlas directory*
*No files were modified, deleted, or created during this analysis (except this report)*
