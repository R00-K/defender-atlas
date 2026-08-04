# Timeline Analysis — Reconstructing the Scan

## Reconstructed canonical timeline

All 30 scans follow the same skeletal timeline (timing is wall-clock from the first to last SUCCESS read; relative ordering is what matters):

| Step | Region(s) | Evidence |
|---|---|---|
| 1. Header prologue | DOS Header … Section Table | Read #1 = offset 0, length 4096 in 30/30 scans |
| 2. Footer probe | Overlay / Certificate Table / EOF | Read #2 targets the last ~2–10% of the file in 14/30 scans (all files with an overlay) |
| 3. Metadata walk | Section table, directories, imports, IAT | 4–8 KiB reads at section/data-directory offsets |
| 4. Linear body sweep | .text … EOF | Contiguous 128–512 KiB chunks, one partial final chunk to EOF |
| 5. Secondary sweeps (large files only) | overlay, .rsrc | 32–64 KiB resource sweep; additional 128–512 KiB streams |
| 6. Verification re-read (8/30) | DOS Header | final read = offset 0, length 4096 |

## First-access order of the header chain (all experiments)

| Rank | Region | Experiments |
|---|---|---|
| 1 | DOS Header | 30/30 |
| 2 | DOS Stub | 30/30 |
| 3 | NT Headers | 30/30 |
| 4 | File Header | 30/30 |
| 5 | Optional Header | 30/30 |
| 6 | Section Table | 30/30 |
| 7 | .text | 29/30 |
| 8 | Overlay | 14/30 |
| 9 | .data | 9/30 |
| 10 | .pdata | 7/30 |

## Temporal stages (gap-based segmentation)

Splitting each scan at time gaps > 10x the median inter-event gap yields between 1 and 24 stages.  Large-file scans show more stages; the stages map onto the canonical steps above.  The three sublimeBase runs show the most granular staging (8–24 stages), reflecting their interleaved multi-sweep structure.

## Repeated verification

The scanner re-reads structural metadata rather than trusting the OS file cache: repeated reads at the same offsets account for 35.2% of all reads globally, and the final offset-0 re-read in 8 experiments is a clear end-of-scan verification step.

## Determinism

**A deterministic sequence exists for the prologue.**  The first 7 region accesses are identical in all 30 scans, and the first read is invariant (0, 4096).  The full read sequence after the prologue is *not* fixed across files — it follows each file's layout — but the *strategy* (probe header, probe footer, walk metadata, stream body) is invariant.

## Hypotheses about scan stages

* The **footer probe** and **final header re-read** bracket the scan and are consistent with an Authenticode/signature verification that needs the security directory (footer) and a hash of the header block.* The **secondary resource/overlay sweeps** are consistent with separate detection components (e.g. heuristic + emulation + signature) each streaming the file independently.
* These are I/O-level hypotheses; they cannot be confirmed from file reads alone.