# Pattern Analysis — How Defender Scans a PE File

This document answers a fixed set of behavioural questions directly from the data.

## Does Defender always begin reading near offset 0?

**Yes — 30/30 experiments.**  The very first read is always `offset 0, length 4096`,
which covers the DOS Header, DOS Stub, NT Headers (signature + File Header +
Optional Header) and the start of the section table in a single 4 KiB transfer.
The first **seven** region accesses are identical across all 30 scans
(DOS Header → DOS Stub → NT Headers → File Header → Optional Header → Section
Table → first section).  This is the header-parsing prologue.

## Does Defender probe the file footer early?

**Yes.**  In **20/30** experiments the *second* read targets the trailing
4–10% of the file (e.g. OneDriveSetup.exe reads offset 30,863,360 of a 30,870,320-byte
file as read #2).  The footer is probed before the linear body scan begins.  This is
consistent with reading the Authenticode certificate table / security directory and
checking file length before committing to a full scan.

## Does it always revisit the same offsets?

No.  Re-visiting is strongly size-dependent:

* Files < 500 KB: **zero repeated offsets** (repeated-read fraction ~0%).
* Files ≥ 500 KB: repeated offsets account for up to **37%** of reads
  (median 24%); offsets in the overlay, `.rsrc`/Resource Directory and
  section-table ranges are the most re-read.

A global repeated-offset rate of **35.2%** of all
reads target an offset already read earlier in the same scan.

## Does Defender perform multiple passes?

Yes, for large files.  The forward-pass detector finds:

* 1 pass — 1 experiment (wscadminui.exe, 9,216 B)
* 2 passes — 23 experiments
* 5 passes — 6 experiments (ntoskrnl.exe, sublimeBase.exe and the three
  sublime_mod variants)

The 5-pass scans consist of: (1) header/footer probe, (2) targeted metadata reads,
(3–5) repeated sequential sweeps over the body with different chunk sizes
(256–512 KiB and 128–256 KiB for the overlay streaming pass, 32–64 KiB for the
resource-section sweep).

## Does it switch between sequential and random reads?

Yes, in a structured way.  The sequential score (fraction of consecutive reads that
are byte-contiguous) averages **0.49** but
ranges from 0.0 (pure random access, e.g. sublimeBase.exe resource scan) to 1.0
(small files read in one contiguous sweep).  The access pattern is:

1. **Random access** — targeted header/section/import reads (small 4–8 KiB chunks at
   arbitrary offsets) during the metadata phase.
2. **Sequential streaming** — large 128–512 KiB contiguous sweeps through the body.

Sequentiality *increases* with file size (r = 0.65): bigger files spend a larger
fraction of their reads in the linear streaming phase.

## Are there fixed-size read chunks?  Does chunk size change during scanning?

Yes, and yes.  The chunk-size bands and how often each band is used:

| Band | Total reads | % experiments using |
|---|---|---|
| <=512B | 12 | 13 |
| 513B-1K | 3 | 3 |
| 1-2K | 2 | 3 |
| 2-4K | 1,007 | 100 |
| 4-8K | 354 | 100 |
| 8-16K | 53 | 47 |
| 16-32K | 69 | 17 |
| 32-64K | 1,076 | 27 |
| 64-128K | 9 | 23 |
| 128-256K | 645 | 40 |
| 256-512K | 553 | 47 |
| 512K-1M | 0 | 0 |
| >1M | 0 | 0 |

Reads are 4 KiB-aligned start offsets in every experiment.  The mode read size is
**4,096 bytes**; large streaming reads reach **524,288 bytes (512 KiB)**.  Chunk size
is *phase-dependent*: metadata/header reads use 4–8 KiB, section reads use 8–64 KiB,
and body/overlay streaming uses 128–512 KiB.  No read in the entire dataset exceeds
512 KiB.

## Does scan behaviour change based on file size?

Yes — this is the single strongest pattern in the dataset:

* File size correlates with amplification (r = 0.57), number of passes (r = 0.57),
  repeated reads (r = 0.67), sequential score (r = 0.65) and duration (r = 0.67).
* Files < 500 KB: one linear pass, amplification ≈ 1.0–1.5x, zero repeated offsets,
  no explicit footer probe.
* Files ≥ 500 KB: multi-pass scans with dedicated overlay/resource sweeps and a
  final header re-read.

## Can scan phases be identified automatically?

Yes.  The rule-based PhaseDetector labels each scan into 2–6 phases.  Across the
dataset the detected phases, in order of frequency:

| Phase | Experiments |
|---|---|
| Header Inspection | 30 |
| Directory Parsing | 30 |
| Overlay Inspection | 14 |
| Code Scanning | 26 |
| Resource Parsing | 25 |
| Certificate Verification | 0 |
| Relocation Processing | 6 |

## Which offsets are almost always read?

The 10 regions accessed in **every** experiment are:

* **DOS Header, DOS Stub, NT Headers, File Header, Optional Header,
  Section Table** (the header chain), and **.text, .data, Import Directory,
  IAT Directory**.

`.rdata` is read in 29/30, `.rsrc`/Resource Directory in 26/30, `.reloc` in 26/30,
`.pdata` in 24/30, Debug Directory in 22/30, TLS Directory in 17/30.

## Which offsets are almost never read?

Regions that are structurally absent from the sample are of course never read.
Among regions that exist, the least-read are late structural extras such as
`Bound Import Directory`, `Delay Import Directory`, `COM Descriptor Directory` and
`Export Directory` (only exported binaries, e.g. ntoskrnl.exe, touch `.edata`).
No experiment read a region that did not exist in its own sample; there were no
"phantom" reads.

## Where do scans terminate?

* Small files: the scan ends inside the body — the final read is the last chunk of
  the single linear sweep.
* Large files (8 of 30): the scan **ends with a re-read of offset 0, length 4096** —
  a final header verification (experiments 01, 07, 08, 10, 11, 12).
* The linear sweep itself always terminates with a **partial final chunk** that ends
  exactly at EOF (e.g. OneDriveSetup.exe reads 461,616 bytes to end at 30,870,320;
  WinSAT.exe reads 189,952 bytes to end at 2,811,392).

## Does Defender perform footer reads?

Yes.  **Every** experiment reads into the final 4 KiB block of the file (100% byte
coverage includes the last byte).  20/30 perform an *early* footer probe as
read #2; the rest reach EOF at the end of the linear sweep.  Reads extending past
EOF occur when a request is clamped to the file size (see anomalies.md).

## Does it perform sparse reads?

Yes — but only as *starts*.  While 100% of bytes are covered, only
**37.7%** of 4 KiB blocks contain a
read *start*.  Large chunks cover many bytes per read, so the read-start footprint is
sparse while the byte footprint is complete.  The tail of the file (last few blocks)
is a hotspot for read starts (footer/overlay probes).

## Does it perform complete linear scans?

Yes.  Byte coverage is 100% in **30/30**
experiments.  For large files the body is read in perfectly contiguous 512 KiB chunks
(with each chunk starting exactly where the previous one ended); the streaming pass
is a textbook linear scan.

## Summary of the Defender scan model

**Observed facts** (in every experiment):

1. Read 1 is always `offset 0, length 4096`.
2. The header chain is the first 7 regions touched.
3. The entire file is read at least once.
4. Reads start on 4 KiB alignment; chunk sizes are powers-of-two bands.
5. Small files: one linear pass.  Large files: multi-pass with a footer probe and a
   final header re-read.

**Hypotheses** (consistent with the data, not directly observable from I/O):

* The early footer probe and the final offset-0 re-read suggest a signature /
  Authenticode verification step that needs the security directory (footer) and a
  hash of the header block.
* The repeated resource/overlay sweeps suggest separate scanner components (e.g.
  emulation, signature matching, static heuristics) each stream the file
  independently.
