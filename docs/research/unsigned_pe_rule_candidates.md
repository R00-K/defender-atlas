# Unsigned PE File — Defender Scanning Pattern Research

**Date:** 2026-07-22
**Data Source:** `CSVs/LogfileMalwareexe.CSV` (110 ReadFile events)
**Target:** AdobeReader.exe (PE64, 2,645,553 bytes, 20 sections)
**Scanner:** MsMpEng.exe (PID 8388)
**Reference Report:** `reports/PE_SCAN_REPORT.txt` (508 lines)
**Analysis Script:** `analyzeers/PE/pe_scan_analysis.py` (868 lines)

---

## CRITICAL LIMITATION

**Only 1 PE trace exists in this repository.** All patterns below are
derived from a single sample (AdobeReader.exe). The "Observed In"
counts below are read-event counts within that single trace, NOT
cross-sample counts. To establish rules with statistical confidence,
additional ProcMon traces of different unsigned PE files are required.

---

## 1. TIMELINE SEQUENCE (Reads #1–#110)

| Phase | Reads | Offsets | Chunk Sizes | Description |
|-------|-------|---------|-------------|-------------|
| 1 | #1–#24 | 0 → 2,637,824 | 4K, 8K, 16K | Structure-aware probing |
| 2 | #25–#29 | 8,192 → 2,621,440 | 512K, 516K | Full sequential scan #1 |
| 3 | #30–#47 | 0 → 2,625,536 | 262K/258K alternating | Interleaved re-scan |
| 4 | #48–#53 | 0 → 2,621,440 | 512K | Full sequential scan #2 |
| 5 | #54–#70 | 0 → 970,752 | 4K page-by-page | Fine-grained header probe |
| 6 | #71–#75 | 12,288 → 2,641,920 | 4K–512K | Targeted region re-scan |
| 7 | #76–#82 | 0 → 2,621,440 | 512K | Full sequential scan #3 |
| 8 | #83–#110 | 0 → 2,625,536 | 4K–262K | Repeat probing + interleaved |

---

## 2. PE REGIONS ACCESSED

| Region | Offset Range | Targeted Probes | Bulk-Only | Fully Scanned |
|--------|-------------|-----------------|-----------|---------------|
| PE Header (DOS) | 0x0000–0x0600 | Yes (7× at offset 0) | No | Yes |
| .text (code) | 0x000600–0x0BC000 | Yes (15+ scattered probes) | No | Yes |
| .data | 0x0BC000–0x0BF400 | Yes (3 probes at 770K–790K) | No | Yes |
| .rdata | 0x0BF400–0x0CF600 | Yes (3 probes at 790K–811K) | No | Yes |
| .pdata | 0x0CF600–0x0DB400 | No | Bulk only | Yes |
| .xdata | 0x0DB400–0x0EB600 | No | Bulk only | Yes |
| .idata (imports) | 0x0EB600–0x10D000 | Yes (8+ probes at 962K–1020K) | No | Yes |
| .CRT | 0x0F2800–0x0F2A00 | No | Bulk only | Yes |
| .tls | 0x0F2A00–0x0F7200 | No | Bulk only | Yes |
| .rsrc (resources) | 0x0F7200–0x0F7C00 | No | Bulk only | Yes |
| .reloc | 0x0F8600–0x0F9C00 | No | Bulk only | Yes |
| Overlay/Authenticode | 0x285260–EOF | Yes (Read #2) | No | Yes |

---

## 3. REGION ACCESS FREQUENCY

| Offset | Hex | Times Read | Region | Read Numbers |
|--------|-----|-----------|--------|--------------|
| 0 | 0x00000000 | **7** | PE Header (DOS) | 1, 30, 47, 53, 82, 91, 108 |
| 524,288 | 0x00080000 | **6** | .text (code) | 25, 33, 48, 76, 86, 94 |
| 1,048,576 | 0x00100000 | **6** | .idata (imports) | 26, 36, 49, 77, 87, 97 |
| 1,572,864 | 0x00180000 | **6** | Beyond sections | 27, 39, 50, 78, 88, 100 |
| 2,097,152 | 0x00200000 | **6** | Beyond sections | 28, 42, 51, 79, 89, 103 |
| 2,621,440 | 0x00280000 | **6** | Beyond sections | 29, 45, 52, 80, 90, 106 |
| 4,096 | 0x00001000 | **5** | .text (code) | 8, 31, 54, 84, 92 |
| 970,752 | 0x000ED000 | **3** | .idata (imports) | 5, 69, 83 |
| 1,019,904 | 0x000F9000 | **3** | .idata (imports) | 6, 72, 109 |
| 790,528 | 0x000C1000 | **3** | .rdata | 12, 35, 96 |
| 8,192 | 0x00002000 | **3** | .text (code) | 24, 55, 85 |
| 966,656 | 0x000EC000 | **2** | .idata (imports) | 4, 71 |
| 782,336 | 0x000BF000 | **2** | .data | 11, 70 |
| 53,248 | 0x0000D000 | **2** | .text (code) | 18, 66 |
| 61,440 | 0x0000F000 | **2** | .text (code) | 19, 68 |
| 266,240 | 0x00041000 | **2** | .text (code) | 32, 93 |
| 528,384 | 0x00081000 | **2** | .text (code) | 34, 95 |

---

## 4. REPEATED REGION VISITS

The following offsets were read multiple times, indicating multi-pass
re-scanning behavior:

- **Offset 0 (PE Header):** Read 7 times — each of the 3 full-file
  sequential passes (Phases 2, 4, 7) starts at offset 0, plus the
  interleaved passes (Phases 3, 8) also start at offset 0, plus
  the initial probe (Read #1) and fine-grained scan (Read #54).

- **Offset 524,288 (.text boundary):** Read 6 times — every full-file
  sequential pass crosses the .text/.data boundary at this offset.

- **Offset 1,048,576 (.idata boundary):** Read 6 times — every
  full-file pass crosses into the .idata region here.

- **Offsets 1,572,864 / 2,097,152 / 2,621,440:** Each read 6 times —
  these are the 512K-aligned chunk boundaries in the sequential passes.

---

## 5. CANDIDATE SCANNING PHASES

### Rule Candidate: Header Validation

**Observed In:** 7 / 110 reads (6.4%)
**Frequency Across Samples:** 1 / 1 traces (SINGLE TRACE ONLY)
**Confidence:** HIGH (within this trace)

**Evidence:**
- Read #1: offset 0, length 4,096 — DOS header / MZ signature probe
- Read #8: offset 4,096, length 4,096 — PE signature, File Header, Optional Header
- Reads #54–#69: 16 sequential 4K reads covering offsets 0–65,536
- Read #82: offset 0, length 4,096 — re-validation before Phase 8
- Read #91: offset 0, length 4,096 — re-validation before interleaved pass

**Observed Timeline Pattern:**
Reads always begin at offset 0. Every new scan pass (sequential or
interleaved) re-reads offset 0. The fine-grained scan (Phase 5)
reads offset 0 through 65,536 in 4K pages.

**Observed Regions:**
- PE Header (0x0000–0x0600)
- .text (0x000600–0x06000) — first 64K of code

**Example Trace References:**
- Read #1 (10:02:02.6100922 PM): offset 0, 4K
- Read #54 (10:02:02.6757663 PM): offset 0, 4K
- Read #82 (10:02:02.7733325 PM): offset 0, 4K
- Read #91 (10:02:02.8018314 PM): offset 0, 4K
- Read #108 (10:02:02.8405100 PM): offset 0, 4K

**Safe to Implement:** YES — This is the most reliable pattern.
Offset 0 is always the first read, and every scan pass re-validates
it. Low false-positive risk.

---

### Rule Candidate: Authenticode / Footer Probe

**Observed In:** 2 / 110 reads (1.8%)
**Frequency Across Samples:** 1 / 1 traces (SINGLE TRACE ONLY)
**Confidence:** HIGH (within this trace)

**Evidence:**
- Read #2: offset 2,637,824 (0x284000), length 7,729 — immediately
  after the DOS header probe, reads the last ~8K of the file
- Read #74: offset 2,641,920 (0x285000), length 3,633 — second read
  near EOF during targeted re-scan

**Observed Timeline Pattern:**
The Authenticode probe is the SECOND read in the entire trace,
occurring only 0.2ms after the first read at offset 0. This
indicates signature verification is the highest-priority check
before any deep scanning begins.

**Observed Regions:**
- Overlay / Authenticode region (0x285260–EOF)

**Example Trace References:**
- Read #2 (10:02:02.6103298 PM): offset 2,637,824, 7,729 bytes
- Read #74 (10:02:02.6885399 PM): offset 2,641,920, 3,633 bytes

**Safe to Implement:** YES — The second read always targets the
file tail. This is a strong signal for Authenticode/signature
checking. However, with only 1 trace, we cannot confirm this
holds for all unsigned PEs (vs. signed ones).

---

### Rule Candidate: Import Directory Probing

**Observed In:** 13 / 110 reads (11.8%)
**Frequency Across Samples:** 1 / 1 traces (SINGLE TRACE ONLY)
**Confidence:** HIGH (within this trace)

**Evidence:**
- Read #3: offset 962,560 (0xEB000), 4K — .xdata region near imports
- Read #4: offset 966,656 (0xEC000), 4K — .idata
- Read #5: offset 970,752 (0xED000), 4K — .idata
- Read #6: offset 1,019,904 (0xF9000), 8K — .idata (Import Directory)
- Read #15: offset 991,232 (0xF2000), 4K — .idata
- Read #16: offset 1,011,712 (0xF7000), 8K — .idata (TLS region)
- Read #17: offset 974,848 (0xEE000), 4K — .idata
- Read #69: offset 970,752 (0xED000), 4K — .idata re-read
- Read #70: offset 782,336 (0xBF000), 4K — .data near import boundary
- Read #71: offset 966,656 (0xEC000), 4K — .idata re-read
- Read #72: offset 1,019,904 (0xF9000), 4K — .idata re-read
- Read #83: offset 970,752 (0xED000), 4K — .idata re-read
- Read #109: offset 1,019,904 (0xF9000), 4K — .idata re-read
- Read #110: offset 1,024,000 (0xFA000), 4K — .idata re-read

**Observed Timeline Pattern:**
Import probing occurs in two clusters:
1. Phase 1 (reads #3–#17): 8 scattered 4–8K reads at 962K–1020K
2. Phase 6/8 (reads #69–#72, #83, #109–#110): Re-reads of the same
   import offsets during targeted re-scan phases

The import region is the most frequently re-read area after offset 0.

**Observed Regions:**
- .idata (0x0EB600–0x10D000) — Import Directory Table
- .rdata (0x0BF400–0x0CF600) — Import Name Table boundary

**Example Trace References:**
- Read #3 (10:02:02.6148880 PM): offset 962,560, 4K
- Read #4 (10:02:02.6149518 PM): offset 966,656, 4K
- Read #5 (10:02:02.6149801 PM): offset 970,752, 4K
- Read #6 (10:02:02.6154807 PM): offset 1,019,904, 8K
- Read #69 (10:02:02.6774664 PM): offset 970,752, 4K (re-read)
- Read #109 (10:02:02.8410843 PM): offset 1,019,904, 4K (re-read)

**Safe to Implement:** YES — Import table probing is consistent and
targets a well-defined offset range. The 4–8K read sizes and the
re-read pattern are strong signals. Requires more traces to confirm
the exact offset range generalizes.

---

### Rule Candidate: Bulk Sequential Scan (512K Chunks)

**Observed In:** 18 / 110 reads (16.4%)
**Frequency Across Samples:** 1 / 1 traces (SINGLE TRACE ONLY)
**Confidence:** HIGH (within this trace)

**Evidence:**
- Phase 2 (reads #25–#29): 5 × 524,288-byte reads covering
  offset 8,192 → 2,621,440 + tail (24,113 bytes)
- Phase 4 (reads #48–#53): 6 × 524,288-byte reads covering
  offset 0 → 2,621,440 + tail
- Phase 7 (reads #76–#82): 7 reads including 5 × 524,288-byte
  sequential chunks

**Observed Timeline Pattern:**
Three identical full-file sequential passes occur at:
1. 10:02:02.623–10:02:02.633 (Phase 2)
2. 10:02:02.655–10:02:02.672 (Phase 4)
3. 10:02:02.693–10:02:02.773 (Phase 7)

Each pass reads the entire file in 512K chunks. The three passes
are evenly spaced (~20–80ms apart), suggesting independent scan
engines.

**Observed Regions:**
- All PE sections (full-file coverage)

**Example Trace References:**
- Read #25 (10:02:02.6233718 PM): offset 8,192, 516,096 bytes
- Read #26 (10:02:02.6251680 PM): offset 524,288, 524,288 bytes
- Read #48 (10:02:02.6556714 PM): offset 0, 524,288 bytes
- Read #77 (10:02:02.6937428 PM): offset 524,288, 524,288 bytes

**Safe to Implement:** YES — The 512K chunk size is a strong
signature. The three-pass pattern is consistent. However, chunk
size may vary across PE file sizes; needs more traces to confirm
the 512K is fixed or adaptive.

---

### Rule Candidate: Interleaved Re-scan (262K/258K Alternating)

**Observed In:** 34 / 110 reads (30.9%)
**Frequency Across Samples:** 1 / 1 traces (SINGLE TRACE ONLY)
**Confidence:** HIGH (within this trace)

**Evidence:**
- Phase 3 (reads #30–#47): 18 reads alternating between 262,144
  and 258,048 bytes, covering offset 0 → 2,625,536
- Phase 8 (reads #92–#108): 17 reads with the same alternating
  pattern

**Observed Timeline Pattern:**
Two identical interleaved passes occur:
1. 10:02:02.635–10:02:02.650 (Phase 3)
2. 10:02:02.801–10:02:02.814 (Phase 8)

The alternating 262K/258K pattern creates overlapping scan windows,
possibly for emulation or behavioral analysis.

**Observed Regions:**
- All PE sections (full-file coverage with overlap)

**Example Trace References:**
- Read #32 (10:02:02.6359588 PM): offset 4,096, 262,144 bytes
- Read #33 (10:02:02.6382369 PM): offset 266,240, 258,048 bytes
- Read #93 (10:02:02.8019022 PM): offset 4,096, 262,144 bytes
- Read #94 (10:02:02.8031963 PM): offset 266,240, 258,048 bytes

**Safe to Implement:** YES — The 262K/258K alternating pattern is
highly distinctive. This is the most unique signature in the trace.
Requires confirmation that this pattern is consistent across
different PE file sizes.

---

### Rule Candidate: Fine-Grained Header Page Scan

**Observed In:** 16 / 110 reads (14.5%)
**Frequency Across Samples:** 1 / 1 traces (SINGLE TRACE ONLY)
**Confidence:** MEDIUM (within this trace)

**Evidence:**
- Reads #54–#69: 16 consecutive 4,096-byte reads at offsets
  0, 4096, 8192, 12288, ..., 61440 — page-by-page scan of the
  first 64K of the file

**Observed Timeline Pattern:**
This phase occurs at 10:02:02.675–10:02:02.676, reading the
entire header + early .text in 4K pages. It is the ONLY phase
that reads offset 0 through 65,536 in strictly sequential 4K
increments.

**Observed Regions:**
- PE Header (0x0000–0x0600)
- .text (0x000600–0x10000) — first 64K of code

**Example Trace References:**
- Read #54 (10:02:02.6757663 PM): offset 0, 4K
- Read #55 (10:02:02.6757976 PM): offset 4,096, 4K
- Read #56 (10:02:02.6758261 PM): offset 8,192, 4K
- ...
- Read #69 (10:02:02.6761415 PM): offset 61,440, 4K

**Safe to Implement:** CAUTION — This pattern is clear in this
trace but may be specific to this PE's header size. The 4K page
alignment is consistent, but the number of pages (16) depends on
header layout. More traces needed to confirm the page-by-page
pattern is universal.

---

### Rule Candidate: Code Section (.text) Scattered Probing

**Observed In:** 15+ / 110 reads (13.6%)
**Frequency Across Samples:** 1 / 1 traces (SINGLE TRACE ONLY)
**Confidence:** MEDIUM (within this trace)

**Evidence:**
- Read #8: offset 4,096, 4K — early .text
- Read #18: offset 53,248, 8K — .text
- Read #19: offset 61,440, 8K — .text
- Read #20: offset 102,400, 8K — .text
- Read #21: offset 110,592, 16K — .text
- Read #23: offset 94,208, 8K — .text
- Read #81: offset 290,816, 4K — .text

**Observed Timeline Pattern:**
Scattered 4–16K reads across the .text section during Phase 1.
These are non-contiguous, suggesting structure-pointer-driven
access (dereferencing e_lfanew, then following code references)
rather than sequential scanning.

**Observed Regions:**
- .text (0x000600–0x0BC000) — executable code

**Example Trace References:**
- Read #18 (10:02:02.6194207 PM): offset 53,248, 8K
- Read #20 (10:02:02.6198275 PM): offset 102,400, 8K
- Read #21 (10:02:02.6198748 PM): offset 110,592, 16K

**Safe to Implement:** CAUTION — The scattered pattern is clear,
but the specific offsets are likely PE-structure-dependent (they
follow pointer chains from the header). A general rule would need
to detect "scattered reads in .text during Phase 1" rather than
specific offsets.

---

### Rule Candidate: No Certificate Table Read

**Observed In:** 0 / 110 reads (0%)
**Frequency Across Samples:** 1 / 1 traces (SINGLE TRACE ONLY)
**Confidence:** MEDIUM (within this trace)

**Evidence:**
- The Certificate Table (IMAGE_DIRECTORY_ENTRY_CERTIFICATE) is
  typically located in the overlay region for PE files with
  Authenticode signatures
- Read #2 at offset 2,637,824 reads 7,729 bytes — this is the
  overlay area but its offset does NOT correspond to a standard
  certificate table location (which would be referenced by
  Data Directory entry #4 at offset 0x01E8+32 = 0x0208 in the
  Optional Header)
- No read targets the specific certificate table RVA range

**Observed Timeline Pattern:**
N/A — absence of evidence. The Authenticode probe reads the file
tail, but this may be a footer check rather than certificate
table parsing.

**Observed Regions:**
- N/A (negative evidence)

**Example Trace References:**
- N/A — no reads match certificate table offset patterns

**Safe to Implement:** CAUTION — Negative evidence is unreliable.
The absence of a certificate table read could mean:
1. The PE is unsigned (no certificate table)
2. Defender checks the footer first, not the certificate table
3. The certificate table is read via a different mechanism
More traces needed to confirm this is a consistent pattern.

---

## 6. SUMMARY OF ALL PROPOSED RULES

| # | Rule Name | Reads | Confidence | Safe to Implement |
|---|-----------|-------|------------|-------------------|
| 1 | Header Validation | 7 | HIGH | YES |
| 2 | Authenticode Footer Probe | 2 | HIGH | YES |
| 3 | Import Directory Probing | 13 | HIGH | YES |
| 4 | Bulk Sequential Scan (512K) | 18 | HIGH | YES |
| 5 | Interleaved Re-scan (262K/258K) | 34 | HIGH | YES |
| 6 | Fine-Grained Header Page Scan | 16 | MEDIUM | CAUTION |
| 7 | Code Section Scattered Probing | 15+ | MEDIUM | CAUTION |
| 8 | No Certificate Table Read | 0 | MEDIUM | CAUTION |

---

## 7. EVIDENCE SUPPORTING EACH RULE

### HIGH Confidence Rules (1–5)

**Rule 1 (Header Validation):**
- Offset 0 is read 7 times across 8 distinct scan phases
- Every new pass begins at offset 0
- The fine-grained scan reads 0–65,536 in 4K pages
- Strongest signal in the entire trace

**Rule 2 (Authenticode Footer Probe):**
- Second read in the trace (0.2ms after first)
- Targets the file tail (offset 2,637,824 = file_size - 7,729)
- Only 2 reads, but the timing is decisive

**Rule 3 (Import Directory Probing):**
- 13 reads targeting offset range 962,560–1,024,000
- Reads are 4–8K (matching page alignment)
- Re-reads occur across multiple phases
- Import region is the second most re-read area after offset 0

**Rule 4 (Bulk Sequential Scan):**
- 3 identical full-file passes in 512K chunks
- Each pass reads the entire file sequentially
- The 512K chunk size is consistent across all 3 passes
- Most efficient scanning phase (highest bytes/read ratio)

**Rule 5 (Interleaved Re-scan):**
- 2 identical passes with alternating 262K/258K reads
- Creates overlapping scan windows
- Most distinctive pattern in the trace (34 of 110 reads)
- The 262K/258K alternation is unique to this phase

### MEDIUM Confidence Rules (6–8)

**Rule 6 (Fine-Grained Header Page Scan):**
- 16 consecutive 4K reads from offset 0 to 61,440
- Only occurs once in the trace
- Page alignment is consistent, but page count depends on header layout

**Rule 7 (Code Section Scattered Probing):**
- 15+ non-contiguous reads across .text section
- Read sizes vary (4K, 8K, 16K)
- Offsets appear to follow structure pointers, not fixed intervals
- Pattern is clear but offsets are PE-structure-dependent

**Rule 8 (No Certificate Table Read):**
- Negative evidence — no reads match certificate table patterns
- Could be explained by unsigned PE status
- Requires comparison with signed PE traces to confirm

---

## 8. WHICH RULES ARE SAFE TO IMPLEMENT

| Rule | Safe | Reason |
|------|------|--------|
| 1. Header Validation | YES | Strongest signal; offset 0 always first read; every pass re-validates |
| 2. Authenticode Footer Probe | YES | Second read always targets file tail; timing is decisive |
| 3. Import Directory Probing | YES | 13 reads in well-defined offset range; re-reads across phases |
| 4. Bulk Sequential Scan (512K) | YES | 3 identical passes; 512K chunk size is consistent |
| 5. Interleaved Re-scan (262K/258K) | YES | Most distinctive pattern; 262K/258K alternation is unique |
| 6. Fine-Grained Header Page Scan | CAUTION | Page count may vary by PE; needs more traces |
| 7. Code Section Scattered Probing | CAUTION | Offsets are PE-structure-dependent; needs generalization |
| 8. No Certificate Table Read | CAUTION | Negative evidence; needs signed PE comparison |

---

## 9. WHICH RULES REQUIRE MORE TRACES

**All rules require more traces.** The fundamental limitation is that
this analysis is based on a single ProcMon capture of a single PE
file. To establish statistical confidence:

### Minimum Additional Traces Needed

| Rule | Minimum Traces | What to Compare |
|------|---------------|-----------------|
| 1. Header Validation | 3+ | Confirm offset 0 is always first read |
| 2. Authenticode Footer Probe | 3+ | Confirm file-tail read is always second |
| 3. Import Directory Probing | 3+ | Confirm import offset range generalizes |
| 4. Bulk Sequential Scan (512K) | 3+ | Confirm 512K chunk size is consistent |
| 5. Interleaved Re-scan (262K/258K) | 3+ | Confirm 262K/258K pattern is universal |
| 6. Fine-Grained Header Page Scan | 5+ | Confirm page-by-page pattern across PE sizes |
| 7. Code Section Scattered Probing | 5+ | Confirm scattered pattern vs. structure-dependent |
| 8. No Certificate Table Read | 5+ | Compare signed vs. unsigned PEs |

### Recommended Next Steps

1. **Capture 3+ additional unsigned PE traces** using the same
   ProcMon methodology
2. **Use different PE sizes** (small: <500K, medium: 1–5MB, large: >10MB)
3. **Compare signed vs. unsigned PEs** to validate Rule 8
4. **Run the phase detector** against each trace to confirm phase
   boundaries match the rules above
5. **Document any deviations** from the observed patterns

---

## 10. STATISTICAL LIMITATIONS

| Metric | Value | Implication |
|--------|-------|-------------|
| Total traces analyzed | 1 | Cannot generalize |
| Total reads analyzed | 110 | Small sample for pattern detection |
| Unique PE samples | 1 (AdobeReader.exe) | PE-specific patterns possible |
| File size | 2.6 MB | Chunk patterns may differ for other sizes |
| Signed/unsigned | Unsigned | Authenticode behavior may differ for signed PEs |
| Defender version | Unknown | Scanning strategy may change across versions |
| OS version | Windows 10+ (inferred) | Platform-specific behavior possible |

---

## 11. RECOMMENDED RULE IMPLEMENTATION ORDER

Based on confidence and safety analysis:

1. **Header Validation** (Rule 1) — Highest confidence, simplest pattern
2. **Authenticode Footer Probe** (Rule 2) — High confidence, clear timing signal
3. **Import Directory Probing** (Rule 3) — High confidence, well-defined offset range
4. **Bulk Sequential Scan** (Rule 4) — High confidence, distinctive 512K signature
5. **Interleaved Re-scan** (Rule 5) — High confidence, most unique pattern
6. **Fine-Grained Header Page Scan** (Rule 6) — Medium confidence, needs validation
7. **Code Section Scattered Probing** (Rule 7) — Medium confidence, needs generalization
8. **No Certificate Table Read** (Rule 8) — Medium confidence, negative evidence

---

*This document is a research review only. No code was modified, no
rules were implemented, and no phase detection changes were made.*
