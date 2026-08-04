# Interesting Findings

## 1. Every scan opens with an identical 4 KiB header read

The very first read in **all 30** scans is `offset 0, length 4096`.  A single
transfer captures the DOS header, DOS stub, NT signature, file/optional headers and
the start of the section table.  This is the cheapest possible structure-recognition
probe and it is byte-for-byte invariant across the dataset.

## 2. The whole file is always read — exactly once for small files

Byte coverage is 100% in all 30 experiments, and small files (< 500 KB) are read
with amplification ≈ 1.0–1.4x and zero repeated offsets.  Defender never reads a
*subset* of a file and never short-circuits a small clean file after the header.

## 3. Large files are re-streamed, not just read once

Files ≥ 500 KB show repeated reads of the same offsets (up to 37% of reads) and
up to 5 forward passes.  The 6 most-read experiments (ntoskrnl + the four sublime
runs) account for 8 of the 30
scans and dominate the total bytes transferred.

## 4. An early footer probe, then a final header re-read

* 20/30 scans read the last few percent of the file as their **second**
  read — before the body is scanned.
* 6 scans (experiments 01, 07, 08, 10, 11, 12) **end** with a re-read
  of offset 0.

The scan is *bracketed* by header/footer accesses: an opening header parse, an
early end-of-file probe, and (often) a closing header re-read.  This bracketing is
consistent with a signature/authenticode verification envelope.

## 5. Read chunks are powers of two on 4 KiB alignment

Every read starts at a 4 KiB-aligned offset.  Chunk sizes fall into discrete bands
(4 KiB, 8 KiB, 32–64 KiB, 128–256 KiB, 512 KiB) with *no* intermediate sizes — the
scanner issues aligned, power-of-two requests.  The largest request in the dataset
is exactly 512 KiB.

## 6. Overlay and resource data receive the most bytes

The **Overlay** region (appended data after the last section) absorbs
496,515,685
bytes across the 14 files that carry one — more than any single section.  Appended
data is a primary scan target.

## 7. Import metadata is always probed

**Import Directory** and **IAT Directory** are read in all 30 experiments, and
`Import Directory` reads are overwhelmingly the most frequent *directory* reads.
Import analysis is a universal step of the scan, consistent with import-based
detection heuristics.

## 8. The prologue is deterministic, the body is layout-driven

The first 7 region accesses are identical in all 30 scans.  After the header chain,
the sequence is dictated by the binary's section layout.  Defender's scan *strategy*
is deterministic even though the concrete offset sequence is file-specific.

## 9. Fast-I/O requests reveal requested vs transferred lengths

For reads that cross EOF, the fast-I/O request length (e.g. 8,192) exceeds the
transferred length (e.g. 4,547).  This confirms Defender requests aligned full
chunks and lets the I/O layer clamp to the file end — evidence that the streaming
pass is a blind aligned sweep rather than a size-aware reader.

## 10. 4 KiB alignment is a reliable Defender signature

Across the whole dataset there are essentially no reads starting on non-4 KiB
offsets except targeted section/directory probes.  A filesystem-visible read
signature of "aligned power-of-two chunks, header-first, EOF-probed, whole-file" is
a plausible detector for Defender's presence.
