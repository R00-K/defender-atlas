# Anomaly Detection

13 anomalies were flagged automatically.

## Rule summary

* **z-score outliers** (|z| ≥ 2.5) on amplification, duration, bytes read, total
  reads, offset entropy and repeated reads.
* **IQR outliers** (1.5 × IQR) on amplification, repeated reads, duration.
* **Offset anomalies**: reads that extend beyond the end of the file.
* **Missing phases**: scans lacking the typical Header Inspection / Directory
  Parsing phases.
* **Degenerate captures**: ≤ 2 SUCCESS reads.
* **Unaligned reads**: > 30% of reads starting off 4 KiB alignment.

## Flagged anomalies

| Exp | Sample | Type | Metric | Value | Reason |
|---|---|---|---|---|---|
| 02 | ntoskrnl.exe | IQR outlier | repeated reads | 174.0 | repeated reads outside 1.5x IQR range [-22.88,38.12] |
| 02 | ntoskrnl.exe | IQR outlier | duration | 0.476 | duration outside 1.5x IQR range [-0.17,0.32] |
| 03 | sublimeBase.exe | IQR outlier | repeated reads | 260.0 | repeated reads outside 1.5x IQR range [-22.88,38.12] |
| 03 | sublimeBase.exe | IQR outlier | duration | 2.537 | duration outside 1.5x IQR range [-0.17,0.32] |
| 03 | sublimeBase.exe | z-score outlier | duration | 2.537 | duration (2.54) is +2.66 sigma from dataset mean |
| 04 | sublime_mod1.exe | IQR outlier | repeated reads | 260.0 | repeated reads outside 1.5x IQR range [-22.88,38.12] |
| 04 | sublime_mod1.exe | IQR outlier | duration | 2.377 | duration outside 1.5x IQR range [-0.17,0.32] |
| 05 | sublime_mod2.exe | IQR outlier | repeated reads | 260.0 | repeated reads outside 1.5x IQR range [-22.88,38.12] |
| 05 | sublime_mod2.exe | IQR outlier | duration | 2.343 | duration outside 1.5x IQR range [-0.17,0.32] |
| 06 | sublime_mod3.exe | IQR outlier | repeated reads | 260.0 | repeated reads outside 1.5x IQR range [-22.88,38.12] |
| 06 | sublime_mod3.exe | IQR outlier | duration | 2.476 | duration outside 1.5x IQR range [-0.17,0.32] |
| 06 | sublime_mod3.exe | z-score outlier | duration | 2.476 | duration (2.48) is +2.58 sigma from dataset mean |
| 26 | wscadminui.exe | degenerate capture | total reads | 2 | only 2 or fewer SUCCESS reads; scan may have been truncated |

## Explanations

* **EOF-clamped reads**: when Defender requests a chunk that crosses the end of
  the file, the IRP layer returns the remaining bytes; the requested length
  (fast-I/O event) is larger than the transferred length.  This is normal
  streaming behaviour, not corruption.
* **Missing phases**: the 2 smallest files (wscadminui.exe, calc.exe) complete the
  whole scan in so few reads that the phase detector does not find a distinct
  Directory Parsing phase.
* **Degenerate capture (wscadminui.exe)**: a 9,216-byte file is read with just 2
  reads — this is expected for a tiny binary, but flagged because the capture is
  at the noise floor and could hide a truncated scan.
* **Amplification outliers**: ntoskrnl.exe (5.06x) and the sublime family (6.01x)
  are the only scans re-reading large portions of the file; their overlay-heavy
  layout and large size drive the amplification.
* **Unaligned reads**: any scan flagged is dominated by reads that start in the
  middle of a 4 KiB block — these are targeted metadata reads at section/data
  directory offsets rather than streaming reads.

## Outlier experiments

The **sublimeBase.exe family (exp 03–06)** is the largest outlier group: it has the
highest read count, amplification, duration and entropy in the dataset, and the
interleaved multi-sweep structure.  **ntoskrnl.exe (exp 02)** is a second outlier
with 33 sections and a 5-pass scan.  All remaining experiments are comparatively
homogeneous.
