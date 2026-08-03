# DefenderAtlas Trigger Comparison Report

## Executive Summary

**IAttachmentExecute partially reproduces browser Defender scanning, but with significant gaps for large binaries.**

The emulated trigger (`SetLocalPath → SetSource → Save`) produces **identical read patterns** for small-to-medium PE files (mspaint, network_imports, threads_create), matching the browser download scan exactly in offset sequence, read sizes, total bytes, and repeated regions.

However, for **large files** (sppsvc, ~4.7 MB), the emulated trigger only executes the first phase of scanning and **misses the entire second-phase sequential re-scan** that the browser download performs. The first 15 reads are identical; the remaining 28 reads are absent.

Zone.Identifier handling also differs: the browser scan sometimes reads the ADS multiple times (threads: 3 reads), while the emulated trigger reads it once.

## Sample Results

| Sample | Similarity | Verdict |
|--------|-----------|---------|
| `mspaint` | 100/100 | **Identical** - exact read-level match |
| `network_imports` | 95/100 | **Identical read pattern**; Zone.Identifier ADS created by emulated but not by actual browser |
| `threads` | 90/100 | **Identical read pattern**; Zone.Identifier read count differs (actual: 3, emulated: 1) |
| `sppsvc` | 55/100 | **First phase identical**; second-phase sequential re-scan missing in emulated |

## Detailed Analysis

### 1. mspaint (small signed PE, ~938 KB)

**ReadFile metrics:**

| Metric | Actual | Emulated |
|--------|--------|----------|
| Total reads | 53 | 53 |
| Unique offsets | 44 | 44 |
| Repeated offsets | 9 | 9 |
| Total bytes read | 2,979,840 | 2,979,840 |
| Read amplification | ~3.17x | ~3.17x |

**Phase structure (identical in both):**
- **Phase 1** (reads 1-29): Security scan — PE header at offset 0, then scattered reads at certificate table (933,888), `.rsrc` sections, import regions, and section headers.
- **Phase 2** (read 30): Large sequential scan — `12,288 + 512,000` covering `.text`.
- **Phase 3** (reads 31-34): Large reads spanning `524,288` through `+414,208` covering `.data`/`.rdata`.
- **Phase 4** (reads 35-37): Re-reads of offset 0, 4,096, 524,288.
- **Phase 5** (reads 38-53): Full 4K sequential scan from offset 0 through 65,536, then 458,752 bulk read, final re-reads of 524,288 and 0.

**Offset sequence:** EXACT match across all 53 reads.
**Length sequence:** EXACT match.
**Repeated offsets:** Identical repeats at {0: 4, 4096: 3, 8192: 2, 12288: 2, 524288: 3}.

**Differences:** None. The scan behavior is byte-for-byte identical.

---

### 2. network_imports (small unsigned PE)

**ReadFile metrics:**

| Metric | Actual | Emulated |
|--------|--------|----------|
| Total reads | 10 | 10 |
| Unique offsets | 10 | 10 |
| Repeated offsets | 0 | 0 |
| Total bytes read | 124,154 | 124,154 |

**Phase structure:**
- **Phase 1** (reads 1-6): PE header at 0, then security data at 81,920, scattered section reads at 32,768, 36,864, 45,056, 28,672, 4,096.
- **Phase 2** (reads 7-10): Remaining section reads at 40,960, 8,192, then bulk sequential read `12,288 + 76,413`.

**Offset sequence:** EXACT match across all 10 reads.

**Zone.Identifier difference:**
- Actual: `CreateFile` on `:Zone.Identifier` → **NAME NOT FOUND** (browser download still in `.crdownload` temp state).
- Emulated: `CreateFile` + `ReadFile` on `:Zone.Identifier` → **SUCCESS**, reads 229 bytes. IAttachmentExecute creates the ADS.

This is a behavioral difference in how the Zone.Identifier ADS is present at scan time, not in the PE scan itself.

---

### 3. threads / thread_create (small unsigned PE)

**ReadFile metrics:**

| Metric | Actual | Emulated |
|--------|--------|----------|
| Total reads | 10 | 10 |
| Unique offsets | 10 | 10 |
| Repeated offsets | 0 | 0 |
| Total bytes read | 116,444 | 116,444 |

**Phase structure:**
- **Phase 1** (reads 1-6): PE header at 0, security at 81,920, section reads at 36,864, 49,152, 28,672, 4,096.
- **Phase 2** (reads 7-10): Section reads at 40,960, 45,056, 8,192, then bulk `12,288 + 74,606`.

**Offset sequence:** EXACT match across all 10 reads.

**Zone.Identifier difference:**
- Actual: Reads `:Zone.Identifier` **3 times** (offset 0, length 236 each).
- Emulated: Reads `:Zone.Identifier` **1 time** (offset 0, length 236).

The actual browser scan re-verifies the zone identifier multiple times. The emulated scan checks it once.

---

### 4. sppsvc (large signed PE, ~4.7 MB) — CRITICAL MISMATCH

**ReadFile metrics:**

| Metric | Actual | Emulated |
|--------|--------|----------|
| Total reads | **43** | **16** |
| Unique offsets | **32** | **15** |
| Repeated offsets | **11** | **1** |
| Total bytes read | **9,362,784** | **4,742,496** |
| Read amplification | **~2.0x** | **~1.02x** |

**First phase (identical — reads 1-15):**

| # | Offset | Length | Purpose |
|---|--------|--------|---------|
| 1 | 0 | 4,096 | PE header + DOS header |
| 2 | 4,661,248 | 7,968 | Certificate table (end of file) |
| 3 | 4,616,192 | 4,096 | Security directory |
| 4 | 4,620,288 | 48,928 | Certificate content |
| 5 | 4,575,232 | 4,096 | Security/attribute region |
| 6 | 4,579,328 | 4,096 | Security/attribute region |
| 7 | 4,096 | 520,192 | `.text` section |
| 8 | 524,288 | 524,288 | `.data` section |
| 9 | 1,048,576 | 524,288 | `.rdata` section |
| 10 | 1,572,864 | 524,288 | `.reloc` / additional sections |
| 11 | 2,097,152 | 524,288 | Section data |
| 12 | 2,621,440 | 524,288 | Section data |
| 13 | 3,145,728 | 524,288 | Section data |
| 14 | 3,670,016 | 524,288 | Section data |
| 15 | 4,194,304 | 474,912 | Final section data to end |

These 15 reads are **identical** in both actual and emulated. This is the standard Defender security scan: read PE header, verify certificates, scan all sections in 512 KB chunks.

**Second phase (actual ONLY — reads 16-43):**

After the first scan, the actual browser download triggers a **second, sequential re-scan** of the entire file:

| # | Offset | Length | Pattern |
|---|--------|--------|---------|
| 16 | 0 | 4,096 | Re-read header |
| 17-42 | 4,096 → 4,460,544 | varies | 262,144 + 258,048 alternating blocks |
| 43 | 0 | 4,096 | Final header check |

This second phase reads the entire file from start to end in a sequential pattern using alternating 256 KB chunks. The emulated scan does NOT perform this second pass — it stops after read 15 with only one extra re-read of offset 0 (read 16).

**Interpretation:** The browser download triggers additional scanning that IAttachmentExecute does not. This could be:
- A separate scanner component (e.g., real-time protection vs. download scan)
- A size-dependent policy where files above a threshold receive deeper inspection
- Different scan context (browser process vs. direct file write)

---

## Phase Detection Comparison

| Sample | Actual Phases | Emulated Phases | Match |
|--------|--------------|-----------------|-------|
| mspaint | 5 phases (scattered scan, bulk .text, bulk .data, re-reads, sequential scan) | 5 phases (identical) | **Full** |
| network_imports | 2 phases (scattered scan, bulk read) | 2 phases (identical) | **Full** |
| threads | 2 phases (scattered scan, bulk read) | 2 phases (identical) | **Full** |
| sppsvc | 2 phases (scattered security scan, full sequential re-scan) | 1 phase (scattered security scan only) | **Partial — Phase 2 missing** |

---

## Similarity Scores

| Sample | Score | Basis |
|--------|-------|-------|
| **mspaint** | **100** | All 53 reads match exactly in offset, length, and order. Zone.Identifier absent in both. |
| **network_imports** | **95** | All 10 reads match. 5-point deduction: ADS zone handling differs (emulated creates Zone.Identifier, actual does not). |
| **threads** | **90** | All 10 reads match. 10-point deduction: Zone.Identifier read count differs (3 vs 1). |
| **sppsvc** | **55** | First 15 reads match. 45-point deduction: Second-phase sequential re-scan (28 reads, 4.6 MB) entirely missing. |

---

## Final Hypothesis

**IAttachmentExecute is a valid replacement trigger for small-to-medium PE files but is insufficient for large binaries.**

For files under ~1 MB, the emulated IAttachmentExecute trigger produces Defender scan traces that are **byte-for-byte identical** to real browser downloads. This covers the common case of small malware samples.

For larger files (≥~4.7 MB based on this evidence), the browser download triggers a **two-phase scan** — an initial security analysis followed by a full sequential re-scan — while IAttachmentExecute only triggers the first phase. This means automated collection via IAttachmentExecute will miss phase detection data, scan duration, and total I/O patterns for large binaries.

The Zone.Identifier discrepancy (ADS created vs. absent, read count variation) is minor and does not affect the PE scan trace quality.

### Recommended Experiments

1. **Size threshold test**: Scan binaries of varying sizes (100 KB, 500 KB, 1 MB, 2 MB, 3 MB, 4 MB) to determine the exact threshold where the second-phase scan is triggered.

2. **Signed vs. unsigned**: Test whether signing status affects phase count (sppsvc is signed; test with unsigned large binary to isolate size vs. signing as the cause).

3. **Multiple emulated triggers**: Compare IAttachmentExecute against other trigger methods (e.g., URLMon, WinINet download, direct `WriteFile` + zone identifier) to see if any reproduce the second phase.

4. **Browser-specific behavior**: Compare Chrome vs. Edge download scans — the second phase may be specific to one browser's download manager.

5. **Concurrent scan analysis**: Determine whether the second phase is a separate MpEngine scan invocation (different scan ID/context) or a continuation within the same scan.
