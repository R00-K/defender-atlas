# Microsoft Defender PE File Scanning Strategy — Final Research Report

**DefenderAtlas · 30 ProcMon experiments · MsMpEng.exe on-access scanner**

## Abstract

This study characterises how Microsoft Defender's on-access scanner (MsMpEng.exe)
reads Portable Executable (PE) files.  30 ProcMon captures were filtered to
Defender's own `ReadFile` operations against a single sample each, and every read
was mapped to the corresponding PE structure (headers, sections, data directories,
overlay).  Samples span 9,216 to 30,870,320 bytes and include signed Microsoft
system binaries, a signed third-party installer family, and unsigned experimental
executables.  We find that Defender performs a **complete, structure-aware,
multi-pass scan**: an invariant 4 KiB header prologue, an early end-of-file probe,
a metadata walk, a linear body sweep in aligned power-of-two chunks, and — for
large files — repeated re-streaming and a closing header re-read.  Byte coverage
is 100% in every experiment; cost scales super-linearly with file size because the
scanner *re-reads* rather than reads once.

## 1. Methodology

### 1.1 Capture

Each experiment places a sample on disk and triggers Defender's on-access scan
(attachment-trigger profile).  Sysinternals ProcMon records all file I/O; the trace
is filtered to `MsMpEng.exe` operations against the target path
(``filtered.csv``).

### 1.2 I/O-layer model

ProcMon reports each read twice: a **FAST IO DISALLOWED** event (fast-I/O path
declines) followed by a **SUCCESS** event (IRP read that transferred bytes).  Both
share the offset; the fast-I/O *requested* length can exceed the *transferred*
length at EOF.  All statistics in this report use **SUCCESS** events
(actual bytes transferred).  Fast-I/O attempts are reported separately.

### 1.3 Analysis

The existing DefenderAtlas library is used directly: `parse_procmon_csv` for
parsing, `compute_statistics` for aggregates, `map_events`/`compute_region_statistics`
for PE structure mapping, `build_timeline` for chronological reconstruction and the
rule-based `PhaseDetector` for scan-phase labelling.  Additional derived metrics
(read-size distributions, 4 KiB block coverage, offset entropy, forward-pass
detection, time-gap segmentation, similarity clustering) are computed on top.

### 1.4 Limitations

* ProcMon timestamps are wall-clock; durations include scheduler noise.
* The dataset mixes provenance and size; size effects are confounded with binary
  layout (sections, resources, certificates, overlay).
* I/O traces reveal *what* is read, not *why*; phase semantics are inferred.
* n = 30; statistical power is limited.

## 2. Observed behaviours

### 2.1 The prologue is invariant

Every scan starts with `offset 0, length 4096` and touches the header chain
(DOS Header → DOS Stub → NT Headers → File Header → Optional Header → Section
Table → first section) in identical first-access order across all 30 scans.

### 2.2 The whole file is always read

Byte coverage is 100.0% in all 30 experiments (zero variance).  For files below
500 KB the scan is a single linear pass with amplification ≈ 1.0–1.4x and no
repeated offsets.

### 2.3 Large files are re-read

Files ≥ 500 KB undergo multiple forward passes (up to 5) with repeated offsets
(up to 37% of reads), amplification up to 6.0x, and dedicated streaming of the
overlay and resource regions.  Read amplification, passes, repeated reads and
duration are all strongly correlated with file size (r = 0.57–0.67) and near-
perfectly correlated with each other (r ≥ 0.85).

### 2.4 Chunking is aligned and power-of-two

Reads start on 4 KiB alignment.  Chunk sizes occupy discrete bands (4 KiB, 8 KiB,
32–64 KiB, 128–256 KiB, 512 KiB); the largest request is 512 KiB.  The body sweep
is a contiguous chain of 512 KiB chunks ending in one partial chunk that lands
exactly on EOF.

### 2.5 The scan is bracketed by header/footer accesses

A large subset of scans probe the file footer as their second read (all 14 files
with an overlay), and 8 of 30 scans end with a re-read of offset 0 (length 4096).
Reads extending past EOF are clamped by the I/O layer, revealing that the streaming
pass is a blind aligned sweep.

## 3. Repeated patterns

1. Invariant first read (0, 4096) — 30/30.
2. Invariant header-chain access order — 30/30.
3. 100% byte coverage — 30/30.
4. 4 KiB-aligned starts and power-of-two chunk sizes — 30/30.
5. 2–4 KiB and 4–8 KiB chunk families used in every scan.
6. Small files read once; large files re-read (23 two-pass, 6 five-pass, 1 one-pass).
7. Header/import/IAT/.text/.data touched in every scan.

## 4. Likely Defender strategy (hypothesis, evidence-based)

**Hypothesis H1 — structure-first parsing.**  Defender parses the PE header chain
before anything else (invariant prologue), then walks the section table and data
directories (imports, IAT, resources) before streaming the body.  *Evidence:*
identical prologue; import/IAT read in all scans; metadata reads precede body
streaming in the timeline.

**Hypothesis H2 — signature/authenticode envelope.**  The early footer probe and
final header re-read bracket the scan.  *Evidence:* footer probed as read #2 in
files with overlay/certificates; 8 scans end with an offset-0 re-read; reads
extend to exactly EOF.

**Hypothesis H3 — multiple independent scan components.**  Large files are streamed
several times with different chunk sizes and region focus (overlay stream at
128–512 KiB, resource sweep at 32–64 KiB).  *Evidence:* 5-pass structure, discrete
chunk families correlated with region, near-perfect correlation of passes with
bytes read.

**Hypothesis H4 — linear scanning is a fingerprinting primitive.**  The aligned,
contiguous, power-of-two streaming pattern is a stable Defender signature visible
at the filesystem layer.  *Evidence:* no intermediate chunk sizes; starts always
4 KiB-aligned; final chunk lands on EOF.

These are hypotheses: file reads alone cannot confirm the detection logic that
motivates each access.

## 5. Open questions / future experiments

1. **Controlled size sweep** — same binary re-signed/padded at 100 KB–100 MB to
   isolate the size effect from provenance.
2. **Overlay/authenticode ablations** — add/remove a certificate table and
   overlay on identical binaries to confirm the footer-probe/header-re-read
   hypotheses.
3. **Chunk-size instrumentation** — verify whether 512 KiB is a hard cap
   (memory-pool bound) or a policy.
4. **Determinism runs** — repeat the same experiment multiple times to measure
   intra-sample variance in read order.
5. **Other engines** — compare against Defender's MPEngine on-demand scan
   (`MpCmdRun`) and other AV products.

## 6. Conclusion

Defender scans PE files with a deterministic, structure-aware strategy: parse the
headers, probe the footer, walk the metadata, stream the whole body in aligned
power-of-two chunks, and re-read large files multiple times — finishing, in many
cases, with a final header verification.  The behaviour is consistent enough
across 30 heterogeneous binaries to be treated as a reliable model of the
engine's on-access cost profile and a usable filesystem-I/O fingerprint.

---
*Data products: statistics.csv, region_statistics.csv, timeline_summary.csv,
phase_summary.csv, region_aggregate.csv, common_offsets.csv, chunk_sizes.csv,
anomalies.csv · Figures: figures/, heatmaps/, charts/ · All values reproducible
from pipeline_results.json.*
