# DefenderAtlas Research Dataset Report

Generated: 2026-07-27T03:04:29Z
Generator: DefenderAtlas Dataset Generator

## Summary

| Metric | Count |
|--------|-------|
| Total Samples | 51 |
| Signed Executables | 22 |
| Unsigned Executables | 14 |
| Windows Drivers | 15 |
| Total Dataset Size | 72.38 MB |

## Size Distribution

| Category | Range | Count |
|----------|-------|-------|
| Tiny | < 100 KB | 27 |
| Small | 100 KB - 500 KB | 8 |
| Medium | 500 KB - 2 MB | 7 |
| Large | 2 MB - 10 MB | 7 |
| Huge | > 10 MB | 2 |

## Unsigned Executables (14 samples)

Compiled with MinGW GCC g++.exe (x86_64-posix-seh-rev0, Built by MinGW-Builds project) 15.2.0 (x64, static linking)

| ID | Category | File | Size | Description |
|----|----------|------|------|-------------|
| unsigned_hello_001 | hello | hello_tiny.exe | 81.3 KB | Minimal Hello World |
| unsigned_hello_002 | hello | hello_small.exe | 82.5 KB | Small Hello World with strings |
| unsigned_hello_003 | hello | hello_medium.exe | 85.2 KB | Medium Hello World with math |
| unsigned_hello_004 | hello | hello_large.exe | 87.6 KB | Large Hello World with matrices |
| unsigned_hello_005 | hello | hello_huge.exe | 90.3 KB | Huge Hello World - 50K arrays |
| unsigned_imports_001 | imports | imports_many.exe | 94.3 KB | Many Windows API imports |
| unsigned_arrays_001 | arrays | arrays_large.exe | 86.0 KB | Large global arrays |
| unsigned_data_001 | data | data_embedded.exe | 86.0 KB | Embedded resource-like data |
| unsigned_functions_001 | functions | functions_many.exe | 96.0 KB | 65+ distinct functions |
| unsigned_switches_001 | switches | switches_large.exe | 88.5 KB | Large switch statements |
| unsigned_recursion_001 | recursion | recursion_algo.exe | 86.9 KB | Recursive algorithms |
| unsigned_fileio_001 | fileio | fileio_basic.exe | 59.7 KB | Basic file I/O |
| unsigned_network_001 | network | network_imports.exe | 86.6 KB | Network API imports |
| unsigned_threads_001 | threads | threads_create.exe | 84.9 KB | Thread creation |

### Categories

- **hello** (5): Minimal to large Hello World programs spanning tiny to medium sizes
- **imports** (1): Heavy Windows API imports (ws2_32, crypt32, wintrust, shell32, etc.)
- **arrays** (1): Large static global arrays (.data/.bss section inflation)
- **data** (1): Embedded HTML, JSON, XML, CSV, and binary data
- **functions** (1): 65+ distinct functions for complex code analysis
- **switches** (1): Complex control flow with 20+ case switches
- **recursion** (1): Quicksort, merge sort, ackermann, collatz
- **fileio** (1): File read/write operations
- **network** (1): Network API imports (no actual networking)
- **threads** (1): Multi-threaded with synchronization primitives

## Signed Executables (22 samples)

All verified with Authenticode signature (Valid)

### Tiny (< 100 KB) - 7 samples

| File | Size | Signature |
|------|------|-----------|
| calc.exe | 27 KB | Valid |
| ping.exe | 22 KB | Valid |
| ipconfig.exe | 35 KB | Valid |
| find.exe | 17.5 KB | Valid |
| fc.exe | 25.5 KB | Valid |
| whoami.exe | 72 KB | Valid |
| wscadminui.exe | 9 KB | Valid |

### Small (100 - 500 KB) - 6 samples

| File | Size | Signature |
|------|------|-----------|
| notepad.exe | 196 KB | Valid |
| tasklist.exe | 104 KB | Valid |
| net.exe | 58.5 KB | Valid |
| taskkill.exe | 99 KB | Valid |
| RuntimeBroker.exe | 100.5 KB | Valid |
| cmd.exe | 283 KB | Valid |

### Medium (500 KB - 2 MB) - 3 samples

| File | Size | Signature |
|------|------|-----------|
| mspaint.exe | 916.5 KB | Valid |
| Narrator.exe | 521.5 KB | Valid |
| systemreset.exe | 510 KB | Valid |

### Large (2 - 10 MB) - 4 samples

| File | Size | Signature |
|------|------|-----------|
| smartscreen.exe | 2.3 MB | Valid |
| WinSAT.exe | 2.7 MB | Valid |
| explorer.exe | 5.1 MB | Valid |
| sppsvc.exe | 4.5 MB | Valid |

### Huge (> 10 MB) - 2 samples

| File | Size | Signature |
|------|------|-----------|
| ntoskrnl.exe | 10.4 MB | Valid |
| OneDriveSetup.exe | 30.1 MB | Valid |

## Windows Drivers (15 samples)

| Driver | Size | Signature |
|--------|------|-----------|
| disk.sys | 99.5 KB | Valid |
| kbdclass.sys | 69.8 KB | Valid |
| mouclass.sys | 66 KB | Valid |
| WdBoot.sys | 45.6 KB | Valid |
| WdNisDrv.sys | 52.9 KB | Valid |
| fileinfo.sys | 92.5 KB | Valid |
| fltmgr.sys | 419.9 KB | Valid |
| WdFilter.sys | 341.9 KB | Valid |
| acpi.sys | 793.4 KB | Valid |
| cng.sys | 730 KB | Valid |
| storport.sys | 709.4 KB | Valid |
| ndis.sys | 1446.9 KB | Valid |
| tcpip.sys | 2923.4 KB | Valid |
| ntfs.sys | 2779.9 KB | Valid |
| dxgkrnl.sys | 3728.9 KB | Valid |

## Architecture

- Unsigned: x64 (MinGW GCC g++.exe (x86_64-posix-seh-rev0, Built by MinGW-Builds project) 15.2.0)
- Signed: Official Windows binaries (x64)
- Drivers: x64 Windows kernel-mode drivers

## Research Coverage

This dataset provides comprehensive coverage for studying Microsoft Defender's file scanning behavior:

- **51 total samples** across 3 major categories
- **5 size categories** from <100KB to >30MB
- **10 unsigned categories** covering different PE characteristics
- **22 signed Windows binaries** spanning common system tools to kernel components
- **15 kernel drivers** across storage, networking, input, and system subsystems
- **All SHA256 hashes** generated for reproducibility
- **All Authenticode signatures** verified as Valid

## Future Automation

This dataset is designed for use with the DefenderAtlas analysis pipeline:

`
defenderatlas experiment datasets/
`

Expected workflow:
1. Read manifest.json
2. Launch ProcMon
3. Capture Defender activity
4. Export CSV
5. Run DefenderAtlas analysis
6. Generate timeline
7. Detect phases
8. Generate findings
9. Generate HTML report
10. Update manifest.json

All manifests include reserved esearch fields for future automation outputs:

`json
"research": {
    "procmon_trace": null,
    "analysis_report": null,
    "timeline": null,
    "phase_detection": null,
    "findings": [],
    "rule_matches": [],
    "confidence": null,
    "notes": ""
}
`

## Quality Assurance

- All 22 signed executables copied and verified
- All 15 drivers copied and verified
- All 14 unsigned executables compiled and verified
- SHA256 hashes generated for all 51 samples
- Manifests generated for all 16 directories
- Master index references all 51 samples
- All Authenticode signatures verified as Valid
- Missing categories: None

---
*Generated by DefenderAtlas Dataset Generator*
*Timestamp: 2026-07-27T03:04:29Z*
*Compiler: MinGW GCC g++.exe (x86_64-posix-seh-rev0, Built by MinGW-Builds project) 15.2.0*
